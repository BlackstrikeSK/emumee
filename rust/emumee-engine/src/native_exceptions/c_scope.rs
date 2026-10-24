//! Deferred C language-handler scans. Filters execute as ordinary guest code;
//! the registered guest wrapper runs before delegation (including any GS check).
use super::*;
use emumee_core::x64_exception::scope::{Action, Scan};

struct Request {
    pc: u64,
    sp: u64,
    arguments: [u64; 4],
    event: Option<usize>,
    frame: [u8; 40],
}
struct Resume {
    request: Request,
    value: u64,
}
#[derive(Default)]
pub(super) struct State {
    pending: Option<Request>,
    resume: Option<Resume>,
    busy: bool,
    pub(super) requests: u64,
    pub(super) filters: u64,
    pub(super) terminations: u64,
}
pub(crate) fn queued(engine: &Unicorn<Trace>) -> bool {
    engine.get_data().native_exceptions.scope.pending.is_some()
}
pub(crate) fn queue(engine: &mut Unicorn<Trace>, arguments: &[u64]) -> Result<u64> {
    let args: [u64; 4] = arguments
        .try_into()
        .map_err(|_| anyhow::anyhow!("C handler argument count"))?;
    let state = &engine.get_data().native_exceptions;
    ensure!(
        state.active && state.handler_arguments == Some(args),
        "C handler is outside its registered native dispatch frame"
    );
    ensure!(
        state.owner
            == Some((
                crate::threads::current_id(engine),
                engine.get_data().cpu.processor,
                crate::threads::thread_address(engine)
            )),
        "C handler dispatch owner changed"
    );
    ensure!(
        !state.scope.busy && state.scope.pending.is_none() && state.scope.resume.is_none(),
        "Nested C language-handler request is not yet supported"
    );
    let pc = uc(engine.pc_read())?;
    let sp = uc(engine.reg_read(R::RSP))?;
    ensure!(sp % 16 == 8, "Misaligned C handler call stack");
    let mut frame = [0; 40];
    read(engine, sp, &mut frame)?;
    let event = engine.get_data().apis.next_event_index();
    let state = &mut engine.get_data_mut().native_exceptions.scope;
    ensure!(state.requests < 256, "C language-handler request bound");
    state.requests += 1;
    state.pending = Some(Request {
        pc,
        sp,
        arguments: args,
        event,
        frame,
    });
    Ok(0)
}
pub(crate) fn transition(
    engine: &mut Unicorn<Trace>,
    horizon: &ExecutionHorizon,
) -> Result<Option<Outcome>> {
    let request = engine
        .get_data_mut()
        .native_exceptions
        .scope
        .pending
        .take()
        .context("No pending C handler")?;
    engine.get_data_mut().native_exceptions.scope.busy = true;
    let result = scan(engine, request, horizon);
    engine.get_data_mut().native_exceptions.scope.busy = false;
    result
}
fn scan(
    engine: &mut Unicorn<Trace>,
    request: Request,
    horizon: &ExecutionHorizon,
) -> Result<Option<Outcome>> {
    let [exception, frame, context, dispatcher] = request.arguments;
    let mut bytes = [0; 152];
    read(engine, exception, &mut bytes)?;
    let record = ExceptionRecord::from_bytes(&bytes)?;
    ensure!(
        record.code != 0xe06d7363,
        "C++ exception-object destruction is not yet integrated with C dispatch"
    );
    let mut bytes = [0; 80];
    read(engine, dispatcher, &mut bytes)?;
    let d = DispatcherContext::from_bytes(&bytes)?;
    ensure!(
        d.establisher_frame == frame,
        "C handler frame differs from dispatcher"
    );
    let (image, _) = image(engine, d.control_pc)?;
    ensure!(
        image.base == d.image_base,
        "C handler image differs from loaded mapping"
    );
    let scopes = unwind::c_scopes(&mut memory(engine), &image, d.handler_data)?;
    let mut scan = Scan::new(
        image.base,
        d.control_pc,
        d.target_ip,
        record.flags,
        record.code,
        scopes,
        d.scope_index,
    )?;
    let pointers = request
        .sp
        .checked_sub(0x40)
        .context("Filter argument stack underflow")?
        & !15;
    let mut pointer_bytes = [0; 16];
    pointer_bytes[..8].copy_from_slice(&exception.to_le_bytes());
    pointer_bytes[8..].copy_from_slice(&context.to_le_bytes());
    crate::cpu::write(engine, pointers, &pointer_bytes)?;
    let call_sp = (pointers
        .checked_sub(0x100)
        .context("Filter stack underflow")?
        & !15)
        - 0x28;
    let stack = owned_stack(engine, request.sp)?;
    ensure!(call_sp >= stack.low + 0x1000, "C handler stack overflow");
    let mut reply = None;
    for _ in 0..8193 {
        match scan.step(reply.take())? {
            Action::Filter { address, .. } => {
                engine.get_data_mut().native_exceptions.scope.filters += 1;
                let outcome = invoke(
                    engine,
                    address,
                    &[pointers, frame],
                    call_sp,
                    engine.get_data().return_marker + SCOPE_RETURN,
                    horizon,
                )?;
                if !outcome.returned {
                    return Ok(Some(outcome));
                }
                reply = Some(outcome.value.context("Filter return absent")? as u32 as i32);
            }
            action @ (Action::ContinueExecution | Action::ContinueSearch) => {
                let value = u64::from(action == Action::ContinueSearch);
                engine.get_data_mut().native_exceptions.scope.resume =
                    Some(Resume { request, value });
                return Ok(None);
            }
            Action::Unwind { target, .. } => {
                ensure!(
                    engine.get_data().native_exceptions.unwind.is_none(),
                    "An unwind is already pending"
                );
                let mut start = capture(engine)?.registers();
                start.rip = u64::from_le_bytes(request.frame[..8].try_into().unwrap());
                start.integer[4] = request
                    .sp
                    .checked_add(8)
                    .context("Unwind caller stack overflow")?;
                require(engine, target, 1, P::EXECUTE)?;
                // C reads ExceptionCode again AFTER invoking the filter.
                // Keep actual guest edits to the exception payload/flags.
                let mut live = [0; 152];
                read(engine, exception, &mut live)?;
                let live = ExceptionRecord::from_bytes(&live)?;
                ensure!(
                    live.code != 0xe06d7363,
                    "C++ exception-object destruction is not yet integrated with C dispatch"
                );
                let return_value = live.code as u64;
                engine.get_data_mut().native_exceptions.unwind = Some(unwind_phase::Request {
                    record: live,
                    start,
                    target_frame: frame,
                    target_ip: target,
                    return_value,
                    event: request.event,
                });
                return Ok(Some(Outcome {
                    returned: false,
                    value: None,
                    error: None,
                }));
            }
            Action::Finally {
                address,
                next_scope,
            } => {
                crate::cpu::write(engine, dispatcher + 72, &next_scope.to_le_bytes())?;
                engine.get_data_mut().native_exceptions.scope.terminations += 1;
                let outcome = invoke(
                    engine,
                    address,
                    &[1, frame],
                    call_sp,
                    engine.get_data().return_marker + SCOPE_RETURN,
                    horizon,
                )?;
                if !outcome.returned {
                    return Ok(Some(outcome));
                }
            }
        }
    }
    bail!("C scope action bound exceeded")
}
pub(crate) fn resume_api(engine: &mut Unicorn<Trace>, pc: u64) -> Result<bool> {
    let Some(resume) = engine.get_data_mut().native_exceptions.scope.resume.take() else {
        return Ok(false);
    };
    ensure!(
        resume.request.pc == pc && uc(engine.reg_read(R::RSP))? == resume.request.sp,
        "C handler API resumed at a different frame"
    );
    let mut frame = [0; 40];
    read(engine, resume.request.sp, &mut frame)?;
    ensure!(
        frame == resume.request.frame,
        "C handler API caller frame was modified"
    );
    uc(engine.reg_write(R::RAX, resume.value))?;
    if let Some(index) = resume.request.event {
        let event = engine
            .get_data_mut()
            .apis
            .events
            .get_mut(index)
            .context("C handler API event missing")?;
        ensure!(
            event.pending && event.api_gate_pc == pc,
            "C handler API event identity changed"
        );
        event.pending = false;
        event.result = Some(resume.value);
        event.effect = Some("returned_from_c_language_handler");
    }
    Ok(true)
}
