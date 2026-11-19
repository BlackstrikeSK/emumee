//! Owned user-mode vectored and x86 registration-chain exception dispatch.
//! Handlers run on the selected guest CPU, without a recursive host run frame.
use super::*;
use crate::api::{self, crt_startup, user_threads};
use std::collections::BTreeMap;

const RETURN: u64 = 0xb00;
mod eh4;
#[derive(Clone, Copy)]
pub(crate) enum Call {
    Add(bool),
    Remove(bool),
    Filter,
    Raise,
    Eh4,
}
#[derive(Clone, Copy)]
enum Kind {
    Vectored,
    Registration(u64),
    Filter,
    Continue,
}
#[derive(Clone, Copy)]
struct Handler {
    address: u64,
    kind: Kind,
}
struct Frame {
    exception: ExceptionRecord,
    saved: unicorn_engine::Context,
    before: Vec<u8>,
    record: u64,
    context: u64,
    pointers: u64,
    sp: u64,
    handlers: Vec<Handler>,
    next: usize,
    checked: Option<crt_startup::initializers::CheckedCall>,
    continuing: bool,
    final_filter: bool,
    event: Option<usize>,
}
struct Software {
    pc: u64,
    sp: u64,
    event: Option<usize>,
}
#[derive(Default)]
pub(super) struct State {
    vectored: Vec<(u64, u64, bool)>,
    filter: u64,
    next_handle: u64,
    frames: BTreeMap<u64, Vec<Frame>>,
    action: bool,
    bypass: bool,
    software: Option<Software>,
    eh4: eh4::State,
}
pub(super) fn active(engine: &Unicorn<Trace>) -> bool {
    eh4::active(engine) || engine
        .get_data()
        .native_exceptions
        .user
        .frames
        .values()
        .any(|v| !v.is_empty())
}
pub(super) fn queued(engine: &Unicorn<Trace>) -> bool {
    engine.get_data().native_exceptions.user.action || eh4::queued(engine)
}
pub(crate) fn invoke(engine: &mut Unicorn<Trace>, call: Call, args: &[u64]) -> Result<u64> {
    ensure!(
        engine.get_data().apis.user_bootstrap.is_some(),
        "User exception API requires a user process"
    );
    match call {
        Call::Eh4 => eh4::queue(engine, args),
        Call::Add(continuation) => {
            if api::require_without_timer_guard(engine, args[1], 1, P::EXECUTE).is_err() {
                engine.get_data_mut().apis.last_error = 998;
                return Ok(0);
            }
            let state = &mut engine.get_data_mut().native_exceptions.user;
            if state.vectored.len() >= 128 {
                return Ok(0);
            }
            let Some(next) = state
                .next_handle
                .checked_add(4)
                .filter(|next| *next < 0x01000000)
            else {
                return Ok(0);
            };
            state.next_handle = next;
            let handle = 0x6c000000 + next;
            if args[0] as u32 != 0 {
                state.vectored.insert(0, (handle, args[1], continuation));
            } else {
                state.vectored.push((handle, args[1], continuation));
            }
            Ok(handle)
        }
        Call::Remove(continuation) => {
            let state = &mut engine.get_data_mut().native_exceptions.user;
            let Some(index) = state
                .vectored
                .iter()
                .position(|(h, _, c)| *h == args[0] && *c == continuation)
            else {
                return Ok(0);
            };
            state.vectored.remove(index);
            Ok(1)
        }
        Call::Raise => {
            let flags = args[1] as u32;
            let count = args[2] as u32;
            ensure!(
                flags & !1 == 0 && count <= 15,
                "Invalid bounded RaiseException flags/argument count"
            );
            ensure!(
                engine.get_data().native_exceptions.pending.is_none()
                    && engine.get_data().native_exceptions.user.software.is_none(),
                "Software exception already queued"
            );
            let wide = engine.get_data().architecture == Architecture::X64;
            let width = if wide { 8 } else { 4 };
            let sp = uc(engine.reg_read(if wide { R::RSP } else { R::ESP }))?;
            let mut raw = [0; 8];
            raw[..width].copy_from_slice(&read_bytes(engine, sp, width as u64)?);
            let pc = u64::from_le_bytes(raw);
            api::require_without_timer_guard(engine, pc, 1, P::EXECUTE)?;
            let arguments = if count == 0 {
                vec![]
            } else {
                read_bytes(engine, args[3], u64::from(count) * width as u64)?
            };
            let parameters = arguments
                .chunks_exact(width)
                .map(|chunk| {
                    let mut value = [0; 8];
                    value[..width].copy_from_slice(chunk);
                    u64::from_le_bytes(value)
                })
                .collect();
            let event = engine.get_data().apis.next_event_index();
            let state = &mut engine.get_data_mut().native_exceptions;
            state.user.software = Some(Software {
                pc,
                sp: sp + if wide { 8 } else { 20 },
                event,
            });
            state.pending = Some(ExceptionRecord {
                code: args[0] as u32,
                flags,
                nested_record: 0,
                address: pc,
                parameters,
            });
            state.raised += 1;
            uc(engine.emu_stop())?;
            Ok(0)
        }
        Call::Filter => {
            if args[0] != 0 {
                api::require_without_timer_guard(engine, args[0], 1, P::EXECUTE)?;
            }
            Ok(std::mem::replace(
                &mut engine.get_data_mut().native_exceptions.user.filter,
                args[0],
            ))
        }
    }
}
pub(crate) fn queue_fault(
    engine: &mut Unicorn<Trace>,
    code: u32,
    address: u64,
    parameters: Vec<u64>,
) -> bool {
    if engine.get_data().apis.user_bootstrap.is_none() || engine.get_data().native_exceptions.active
    {
        return false;
    }
    let state = &mut engine.get_data_mut().native_exceptions;
    if state.pending.is_some() {
        return false;
    }
    state.raised += 1;
    state.pending = Some(ExceptionRecord {
        code,
        flags: 0,
        nested_record: 0,
        address,
        parameters,
    });
    let _ = engine.emu_stop();
    true
}
pub(super) fn install(engine: &mut Unicorn<Trace>) -> Result<()> {
    if engine.get_data().apis.user_bootstrap.is_none() {
        return Ok(());
    }
    if engine.get_data().architecture == Architecture::X86 {
        uc(engine.add_intr_hook(|engine, number| {
            let result = (|| -> Result<()> {
                let pc = uc(engine.pc_read())?;
                let (code, address, parameters) = match number {
                    3 => {
                        let address = pc.checked_sub(1).context("Breakpoint underflow")?;
                        ensure!(
                            read_bytes(engine, address, 1)? == [0xcc],
                            "Unsupported x86 breakpoint encoding"
                        );
                        uc(engine.reg_write(R::EIP, address))?;
                        (0x80000003, address, vec![0])
                    }
                    0 => (0xc0000094, pc, vec![]),
                    6 => (0xc000001d, pc, vec![]),
                    _ => bail!("Unsupported x86 user interrupt {number}"),
                };
                ensure!(
                    queue_fault(engine, code, address, parameters),
                    "User exception queue is occupied"
                );
                Ok(())
            })();
            if let Err(error) = result {
                engine.get_data_mut().cpu.fault = Some(format!("{error:#}"));
            }
            let _ = engine.emu_stop();
        }))?;
    }
    uc(engine.add_insn_invalid_hook(|engine| {
        if let Ok(pc) = engine.pc_read() {
            queue_fault(engine, 0xc000001d, pc, vec![]);
        }
        false
    }))?;
    Ok(())
}
pub(super) fn begin(engine: &mut Unicorn<Trace>, exception: ExceptionRecord) -> Result<bool> {
    if let Some(software) = engine.get_data_mut().native_exceptions.user.software.take() {
        let wide = engine.get_data().architecture == Architecture::X64;
        uc(engine.reg_write(if wide { R::RIP } else { R::EIP }, software.pc))?;
        uc(engine.reg_write(if wide { R::RSP } else { R::ESP }, software.sp))?;
        if let Some(index) = software.event
            && let Some(event) = engine.get_data_mut().apis.events.get_mut(index)
        {
            event.pending = false;
            event.result = Some(0);
            event.effect = Some("software_exception_dispatched");
        }
    }
    if std::mem::take(&mut engine.get_data_mut().native_exceptions.user.bypass) {
        return Ok(false);
    }
    begin_stage(engine, exception, 0)
}
pub(super) fn after_native(
    engine: &mut Unicorn<Trace>,
    exception: ExceptionRecord,
    unhandled: bool,
) -> Result<bool> {
    begin_stage(engine, exception, if unhandled { 1 } else { 2 })
}
fn begin_stage(
    engine: &mut Unicorn<Trace>,
    mut exception: ExceptionRecord,
    stage: u8,
) -> Result<bool> {
    if engine.get_data().apis.user_bootstrap.is_none() {
        return Ok(false);
    }
    let wide = engine.get_data().architecture == Architecture::X64;
    let state = &engine.get_data().native_exceptions.user;
    if (stage == 0 && wide && state.vectored.iter().all(|(_, _, c)| *c))
        || (stage == 1 && state.filter == 0)
        || (stage == 2 && state.vectored.iter().all(|(_, _, c)| !*c))
    {
        return Ok(false);
    }
    ensure!(
        state.frames.values().map(Vec::len).sum::<usize>() < 16,
        "User exception nesting bound exceeded"
    );
    let mut handlers = state
        .vectored
        .iter()
        .filter(|(_, _, c)| stage != 1 && *c == (stage == 2))
        .map(|(_, address, _)| Handler {
            address: *address,
            kind: if stage == 2 {
                Kind::Continue
            } else {
                Kind::Vectored
            },
        })
        .collect::<Vec<_>>();
    let filter = state.filter;
    let id = user_threads::current_id(engine);
    if let Some(parent) = state.frames.get(&id).and_then(|f| f.last()) {
        exception.nested_record = parent.record;
    }
    let sp = uc(engine.reg_read(if wide { R::RSP } else { R::ESP }))?;
    let (low, high) = user_threads::stack_bounds(engine)?;
    ensure!(
        sp >= low && sp < high,
        "User exception left its owned stack"
    );
    if !wide && stage == 0 {
        let teb = api::user_bootstrap::active_teb(engine).context("User exception TEB missing")?;
        let mut node = u32::from_le_bytes(read_bytes(engine, teb, 4)?.try_into().unwrap()) as u64;
        let mut visited = BTreeSet::new();
        while node != 0 && node != u32::MAX as u64 {
            ensure!(
                visited.len() < 128 && visited.insert(node),
                "x86 exception registration chain cycle/bound"
            );
            ensure!(
                node >= low && node.checked_add(8).is_some_and(|end| end <= high) && node & 3 == 0,
                "x86 exception registration left the owned stack"
            );
            let entry = read_bytes(engine, node, 8)?;
            let next = u32::from_le_bytes(entry[..4].try_into().unwrap()) as u64;
            let address = u32::from_le_bytes(entry[4..].try_into().unwrap()) as u64;
            api::require_without_timer_guard(engine, address, 1, P::EXECUTE)?;
            handlers.push(Handler {
                address,
                kind: Kind::Registration(node),
            });
            node = next;
        }
    }
    if filter != 0 && (stage == 1 || (!wide && stage == 0)) {
        handlers.push(Handler {
            address: filter,
            kind: Kind::Filter,
        });
    }
    let anchor = sp
        .checked_sub(0x900)
        .context("User exception stack underflow")?
        & !15;
    ensure!(anchor >= low + 0x1000, "User exception stack exhausted");
    let record = anchor;
    let context = anchor + 0xa0;
    let pointers = anchor + 0x600;
    let before = user_threads::capture_context(engine)?;
    let raw = if wide {
        exception.bytes()?.to_vec()
    } else {
        let mut raw = vec![0; 80];
        for (index, value) in [
            exception.code,
            exception.flags,
            exception.nested_record as u32,
            exception.address as u32,
            exception.parameters.len() as u32,
        ]
        .into_iter()
        .enumerate()
        {
            raw[index * 4..index * 4 + 4].copy_from_slice(&value.to_le_bytes());
        }
        for (i, value) in exception.parameters.iter().enumerate() {
            raw[20 + i * 4..24 + i * 4].copy_from_slice(&(*value as u32).to_le_bytes());
        }
        raw
    };
    api::require_without_timer_guard(engine, anchor, 0x610, P::RW)?;
    crate::cpu::write(engine, record, &raw)?;
    crate::cpu::write(engine, context, &before)?;
    let width = if wide { 8 } else { 4 };
    crate::cpu::write(engine, pointers, &record.to_le_bytes()[..width])?;
    crate::cpu::write(
        engine,
        pointers + width as u64,
        &context.to_le_bytes()[..width],
    )?;
    let frame = Frame {
        exception,
        saved: uc(engine.context_init())?,
        before,
        record,
        context,
        pointers,
        sp: anchor - 0x100,
        handlers,
        next: 0,
        checked: None,
        continuing: stage == 2,
        final_filter: stage == 1,
        event: None,
    };
    let state = &mut engine.get_data_mut().native_exceptions.user;
    state.frames.entry(id).or_default().push(frame);
    state.action = true;
    Ok(true)
}
pub(crate) fn before_instruction(engine: &mut Unicorn<Trace>, pc: u64) -> bool {
    if eh4::before_instruction(engine, pc) {
        return true;
    }
    let id = user_threads::current_id(engine);
    if pc == engine.get_data().return_marker + RETURN
        && engine
            .get_data()
            .native_exceptions
            .user
            .frames
            .get(&id)
            .and_then(|v| v.last())
            .is_some_and(|f| f.checked.is_some())
    {
        engine.get_data_mut().native_exceptions.user.action = true;
        true
    } else {
        false
    }
}
pub(super) fn transition(engine: &mut Unicorn<Trace>) -> Result<Option<Outcome>> {
    if eh4::queued(engine) {
        return eh4::transition(engine);
    }
    let id = user_threads::current_id(engine);
    engine.get_data_mut().native_exceptions.user.action = false;
    let mut frame = engine
        .get_data_mut()
        .native_exceptions
        .user
        .frames
        .get_mut(&id)
        .and_then(Vec::pop)
        .context("User exception continuation missing")?;
    if let Some(checked) = frame.checked.take() {
        checked.validate(engine)?;
        let disposition = uc(engine.reg_read(R::EAX))? as u32;
        uc(engine.context_restore(&frame.saved))?;
        if let Some(event) = frame.event.take() {
            engine.get_data_mut().native_exceptions.events[event].disposition = Some(disposition);
        }
        let kind = frame.handlers[frame.next - 1].kind;
        if matches!(kind, Kind::Filter) && disposition == 1 {
            api::user_lifecycle::request_exit(engine, frame.exception.code, true)?;
            return Ok(Some(Outcome {
                returned: false,
                value: None,
                error: None,
            }));
        }
        let resume = match kind {
            Kind::Vectored | Kind::Filter => disposition == u32::MAX,
            Kind::Registration(_) => disposition == 0,
            Kind::Continue => false,
        };
        if resume {
            ensure!(
                frame.exception.flags & 1 == 0,
                "Noncontinuable user exception cannot resume"
            );
            frame.handlers = engine
                .get_data()
                .native_exceptions
                .user
                .vectored
                .iter()
                .filter(|(_, _, c)| *c)
                .map(|(_, address, _)| Handler {
                    address: *address,
                    kind: Kind::Continue,
                })
                .collect();
            frame.next = 0;
            frame.continuing = true;
        } else {
            ensure!(
                matches!(kind, Kind::Continue)
                    || disposition
                        == if matches!(kind, Kind::Registration(_)) {
                            1
                        } else {
                            0
                        },
                "Unsupported user exception handler disposition {disposition:#x}"
            );
        }
    }
    if let Some(handler) = frame.handlers.get(frame.next).copied() {
        ensure!(
            engine.get_data().native_exceptions.events.len() < 256,
            "User exception event bound exceeded"
        );
        let event = engine.get_data().native_exceptions.events.len();
        engine.get_data_mut().native_exceptions.events.push(Event {
            phase: "user-handler",
            flags: frame.exception.flags,
            code: frame.exception.code,
            exception_address: frame.exception.address,
            control_pc: frame.exception.address,
            establisher: if let Kind::Registration(node) = handler.kind {
                node
            } else {
                0
            },
            handler: handler.address,
            disposition: None,
            parameters: frame.exception.parameters.clone(),
        });
        let arguments = if let Kind::Registration(node) = handler.kind {
            vec![frame.record, node, frame.context, 0]
        } else {
            vec![frame.pointers]
        };
        frame.checked = Some(crt_startup::initializers::begin_checked_call(
            engine,
            handler.address,
            frame.sp,
            &arguments,
            matches!(handler.kind, Kind::Registration(_)),
            engine.get_data().return_marker + RETURN,
        )?);
        frame.next += 1;
        frame.event = Some(event);
        engine
            .get_data_mut()
            .native_exceptions
            .user
            .frames
            .entry(id)
            .or_default()
            .push(frame);
        return Ok(None);
    }
    uc(engine.context_restore(&frame.saved))?;
    if frame.continuing {
        let after = read_bytes(engine, frame.context, frame.before.len() as u64)?;
        user_threads::restore_context(engine, &frame.before, &after)?;
        engine.get_data_mut().native_memory_fault = None;
        Ok(None)
    } else if engine.get_data().architecture == Architecture::X64 && !frame.final_filter {
        let state = &mut engine.get_data_mut().native_exceptions;
        state.user.bypass = true;
        state.pending = Some(frame.exception);
        Ok(None)
    } else {
        engine.get_data_mut().guest_failure_code = Some(frame.exception.code);
        Ok(Some(Outcome {
            returned: false,
            value: None,
            error: Some(format!(
                "Unhandled user exception {:#010x}{}",
                frame.exception.code,
                fault_suffix(engine)
            )),
        }))
    }
}
pub(crate) fn cancel(engine: &mut Unicorn<Trace>, id: u64) {
    eh4::cancel(engine, id);
    engine
        .get_data_mut()
        .native_exceptions
        .user
        .frames
        .remove(&id);
}

fn read_bytes(engine: &Unicorn<Trace>, address: u64, size: u64) -> Result<Vec<u8>> {
    api::require_without_timer_guard(engine, address, size, P::READ)?;
    let mut bytes = vec![0; size as usize];
    uc(engine.mem_read(address, &mut bytes))?;
    Ok(bytes)
}

pub(super) fn fault_suffix(engine: &Unicorn<Trace>) -> String {
    engine
        .get_data()
        .native_memory_fault
        .as_ref()
        .map_or(String::new(), |fault| {
            let suffix = if engine
                .get_data()
                .apis
                .memory
                .region(fault.address)
                .is_some()
            {
                "PROT"
            } else {
                "UNMAPPED"
            };
            format!(
                " ({}_{suffix})",
                if fault.access == "execute" {
                    "FETCH"
                } else if fault.access == "write" {
                    "WRITE"
                } else {
                    "READ"
                }
            )
        })
}

pub(super) fn summary(engine: &Unicorn<Trace>) -> (usize, usize, bool) {
    let state = &engine.get_data().native_exceptions.user;
    (
        state.vectored.len(),
        state.frames.values().map(Vec::len).sum(),
        state.filter != 0,
    )
}
