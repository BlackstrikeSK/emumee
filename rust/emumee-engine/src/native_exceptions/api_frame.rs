//! Owned modeled-API exception bodies, never aliases for signed kernel code.
//! The actual API caller stack supplies ordinary search/unwind continuations.
use super::*;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Kind {
    Breakpoint,
    Prompt,
}
#[derive(Clone, Debug, Serialize)]
pub struct Evidence {
    pub kind: Kind,
    pub gate: u64,
    pub fault_site: u64,
    pub stack_pointer: u64,
    pub initial_return_address: u64,
    pub delivered: bool,
    pub thread_id: u64,
    pub processor: u32,
    pub current_thread: u64,
}
#[derive(Clone)]
pub(super) struct Frame {
    pub(super) evidence: Evidence,
    event: Option<usize>,
    index: usize,
}
fn owner(engine: &Unicorn<Trace>) -> (u64, u32, u64) {
    (
        crate::threads::current_id(engine),
        engine.get_data().cpu.processor,
        crate::threads::thread_address(engine),
    )
}
fn validate_owner(engine: &Unicorn<Trace>, frame: &Frame) -> Result<()> {
    let e = &frame.evidence;
    ensure!(
        owner(engine) == (e.thread_id, e.processor, e.current_thread),
        "Modeled API exception frame owner changed"
    );
    Ok(())
}
pub(crate) fn queue(engine: &mut Unicorn<Trace>, kind: Kind) -> Result<u64> {
    ensure!(
        engine.get_data().architecture == Architecture::X64,
        "Modeled API exception dispatch requires AMD64"
    );
    ensure!(
        !engine.get_data().machine.boot_debug(),
        "Debug-enabled boot transport state is not modeled"
    );
    let state = &engine.get_data().native_exceptions;
    ensure!(
        !state.active && state.pending.is_none() && state.api_frame.is_none(),
        "Nested modeled API exception is not yet supported"
    );
    ensure!(
        state.api_exceptions.len() < 256,
        "Modeled API exception evidence bound"
    );
    let gate = uc(engine.pc_read())?;
    ensure!(
        crate::api::debug_gate_kind(engine, gate) == Some(kind),
        "Exception source is not its admitted API gate"
    );
    let sp = uc(engine.reg_read(R::RSP))?;
    let stack = owned_stack(engine, sp)?;
    ensure!(
        sp % 16 == 8 && sp.checked_add(8).is_some_and(|end| end <= stack.high),
        "Invalid modeled API caller stack"
    );
    let mut value = [0; 8];
    read(engine, sp, &mut value)?;
    let ret = u64::from_le_bytes(value);
    let site = gate.checked_add(8).context("API fault site overflow")?;
    let mut code = [0; 2];
    read(engine, site, &mut code)?;
    ensure!(code == [0xcc, 0xc3], "Modeled API fault body was modified");
    require(engine, site, 2, P::EXECUTE)?;
    let (thread, processor, current) = owner(engine);
    let evidence = Evidence {
        kind,
        gate,
        fault_site: site,
        stack_pointer: sp,
        initial_return_address: ret,
        delivered: false,
        thread_id: thread,
        processor,
        current_thread: current,
    };
    let event = engine.get_data().apis.next_event_index();
    let state = &mut engine.get_data_mut().native_exceptions;
    let index = state.api_exceptions.len();
    state.api_exceptions.push(evidence.clone());
    state.api_frame = Some(Frame {
        evidence,
        event,
        index,
    });
    state.raised += 1;
    state.pending = Some(ExceptionRecord {
        code: 0x80000003,
        flags: 0,
        nested_record: 0,
        address: site + u64::from(kind == Kind::Prompt),
        parameters: vec![if kind == Kind::Prompt { 2 } else { 0 }],
    });
    Ok(0)
}
pub(super) fn deliver(engine: &mut Unicorn<Trace>) -> Result<()> {
    let Some(mut frame) = engine.get_data().native_exceptions.api_frame.clone() else {
        return Ok(());
    };
    if frame.evidence.delivered {
        return Ok(());
    }
    validate_owner(engine, &frame)?;
    ensure!(
        uc(engine.pc_read())? == frame.evidence.gate
            && uc(engine.reg_read(R::RSP))? == frame.evidence.stack_pointer,
        "Modeled API exception delivery left its caller frame"
    );
    uc(engine.reg_write(R::RIP, frame.evidence.fault_site))?;
    if frame.evidence.kind == Kind::Prompt {
        uc(engine.reg_write(R::RAX, 2))?;
    }
    if let Some(index) = frame.event {
        let event = engine
            .get_data_mut()
            .apis
            .events
            .get_mut(index)
            .context("API exception event missing")?;
        ensure!(
            event.pending && event.api_gate_pc == frame.evidence.gate,
            "API exception event identity changed"
        );
        event.pending = false;
        event.result = None;
        event.effect = Some("raised_native_exception");
    }
    frame.evidence.delivered = true;
    engine.get_data_mut().native_exceptions.api_exceptions[frame.index] = frame.evidence.clone();
    engine.get_data_mut().native_exceptions.api_frame = Some(frame);
    Ok(())
}
pub(crate) fn is_instruction(engine: &Unicorn<Trace>, pc: u64) -> bool {
    engine
        .get_data()
        .native_exceptions
        .api_frame
        .as_ref()
        .is_some_and(|f| {
            f.evidence.delivered
                && (f.evidence.fault_site..=f.evidence.fault_site + 1).contains(&pc)
        })
}
pub(crate) fn before_instruction(engine: &mut Unicorn<Trace>, pc: u64) -> Result<()> {
    if engine.get_data().native_exceptions.api_frame.is_none() {
        return Ok(());
    }
    if is_instruction(engine, pc) {
        let frame = engine
            .get_data()
            .native_exceptions
            .api_frame
            .as_ref()
            .unwrap();
        validate_owner(engine, frame)?;
        ensure!(
            uc(engine.reg_read(R::RSP))? == frame.evidence.stack_pointer,
            "Unsupported modeled API context stack pivot"
        );
    } else if !engine.get_data().native_exceptions.active
        && engine.get_data().native_exceptions.pending.is_none()
    {
        engine.get_data_mut().native_exceptions.api_frame = None;
    }
    Ok(())
}
pub(super) fn caller(
    engine: &Unicorn<Trace>,
    context: &Context,
    stack: Stack,
) -> Result<Option<Context>> {
    if !is_instruction(engine, context.rip) {
        return Ok(None);
    }
    let frame = engine
        .get_data()
        .native_exceptions
        .api_frame
        .as_ref()
        .unwrap();
    validate_owner(engine, frame)?;
    ensure!(
        context.integer[4] == frame.evidence.stack_pointer,
        "Modeled API unwind stack identity changed"
    );
    ensure!(
        context.integer[4] >= stack.low
            && context.integer[4]
                .checked_add(8)
                .is_some_and(|end| end <= stack.high),
        "Modeled API unwind left the owned stack"
    );
    let mut value = [0; 8];
    read(engine, context.integer[4], &mut value)?;
    let mut caller = context.clone();
    caller.rip = u64::from_le_bytes(value);
    caller.integer[4] += 8;
    Ok(Some(caller))
}
