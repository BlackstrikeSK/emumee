//! Owned FLS/APC continuations using checked guest calls and the shared horizon.
use super::*;
use crate::threads::{ExecutionHorizon, Outcome};
use anyhow::Context as _;

struct Pending {
    pc: u64,
    sp: u64,
    frame: Vec<u8>,
    calls: Vec<(u64, u64)>,
    event: Option<usize>,
    complete: bool,
    context: Option<unicorn_engine::Context>,
    checked: Option<crt_startup::initializers::CheckedCall>,
    next: usize,
    retirement: Option<(u32, usize)>,
    apc_wait: Option<user_threads::Pending>,
}
#[derive(Default)]
pub(crate) struct State {
    pending: BTreeMap<u64, Vec<Pending>>,
    action: bool,
    pub(super) calls: usize,
}
fn sp_register(arch: Architecture) -> RegisterX86 {
    if arch == Architecture::X64 {
        RegisterX86::RSP
    } else {
        RegisterX86::ESP
    }
}
pub(crate) fn queued(engine: &Unicorn<Trace>) -> bool {
    engine.get_data().apis.user_callbacks.action
}
pub(crate) fn queue(engine: &mut Unicorn<Trace>, calls: Vec<(u64, u64)>) -> Result<u64> {
    ensure!(
        engine
            .get_data()
            .apis
            .user_callbacks
            .pending
            .values()
            .map(Vec::len)
            .sum::<usize>()
            < 16,
        "FLS callback nesting bound exceeded"
    );
    let arch = engine.get_data().architecture;
    let sp = uc(engine.reg_read(sp_register(arch)))?;
    let pending = Pending {
        pc: uc(engine.pc_read())?,
        sp,
        frame: read(engine, sp, if arch == Architecture::X64 { 40 } else { 8 })?,
        calls,
        event: engine.get_data().apis.next_event_index(),
        complete: false,
        context: None,
        checked: None,
        next: 0,
        retirement: None,
        apc_wait: None,
    };
    let id = user_threads::current_id(engine);
    let state = &mut engine.get_data_mut().apis.user_callbacks;
    state.pending.entry(id).or_default().push(pending);
    state.action = true;
    Ok(0)
}
pub(crate) fn queue_apcs(engine: &mut Unicorn<Trace>, calls: Vec<(u64, u64)>) -> Result<()> {
    ensure!(
        engine
            .get_data()
            .apis
            .user_callbacks
            .pending
            .values()
            .map(Vec::len)
            .sum::<usize>()
            < 16,
        "User callback nesting bound exceeded"
    );
    let sp = uc(engine.reg_read(sp_register(engine.get_data().architecture)))?;
    let pending = Pending {
        pc: uc(engine.pc_read())?,
        sp,
        frame: Vec::new(),
        calls,
        event: None,
        complete: false,
        context: None,
        checked: None,
        next: 0,
        retirement: None,
        apc_wait: Some(user_threads::detach_apc_wait(engine)?),
    };
    let id = user_threads::current_id(engine);
    let state = &mut engine.get_data_mut().apis.user_callbacks;
    state.pending.entry(id).or_default().push(pending);
    state.action = true;
    Ok(())
}
/// Begin normal thread retirement without keeping a host execution frame alive.
/// The scheduler owns the eventual exit and keeps the thread unsignaled meanwhile.
pub(crate) fn retire(engine: &mut Unicorn<Trace>, id: u64, code: u32, sp: u64) -> Result<bool> {
    let calls = user_runtime::take_fls(engine, None, Some(id));
    if calls.is_empty() {
        return Ok(false);
    }
    cancel(engine, id, "aborted_by_thread_exit");
    let pending = Pending {
        pc: uc(engine.pc_read())?,
        sp,
        frame: Vec::new(),
        calls,
        event: None,
        complete: false,
        context: None,
        checked: None,
        next: 0,
        retirement: Some((code, 1)),
        apc_wait: None,
    };
    let state = &mut engine.get_data_mut().apis.user_callbacks;
    state.pending.entry(id).or_default().push(pending);
    state.action = true;
    Ok(true)
}
/// A submitted-user FLS callback is an owned continuation, so blocking it
/// never leaves a Rust guest-execution frame parked on the host stack.
pub(crate) fn before_instruction(engine: &mut Unicorn<Trace>, pc: u64) -> bool {
    let id = user_threads::current_id(engine);
    if pc == engine.get_data().return_marker + 0xa00
        && engine
            .get_data()
            .apis
            .user_callbacks
            .pending
            .get(&id)
            .and_then(|p| p.last())
            .is_some_and(|p| p.checked.is_some())
    {
        engine.get_data_mut().apis.user_callbacks.action = true;
        return true;
    }
    false
}
pub(crate) fn transition(
    engine: &mut Unicorn<Trace>,
    _horizon: &ExecutionHorizon,
) -> Result<Option<Outcome>> {
    let id = user_threads::current_id(engine);
    engine.get_data_mut().apis.user_callbacks.action = false;
    let mut pending = engine
        .get_data_mut()
        .apis
        .user_callbacks
        .pending
        .get_mut(&id)
        .and_then(Vec::pop)
        .context("FLS caller absent")?;
    let result = (|| -> Result<()> {
        if let Some(checked) = pending.checked.take() {
            let valid = checked.validate(engine);
            uc(engine.context_restore(
                pending
                    .context
                    .as_ref()
                    .context("FLS saved caller absent")?,
            ))?;
            valid?;
        }
        if pending.context.is_none() {
            pending.context = Some(uc(engine.context_init())?);
        }
        if pending.next == pending.calls.len()
            && let Some((_, pass)) = pending.retirement.as_mut()
        {
            let calls = user_runtime::take_fls(engine, None, Some(id));
            ensure!(
                calls.is_empty() || *pass < 4,
                "FLS destructors repeatedly repopulated retiring thread slots"
            );
            if !calls.is_empty() {
                *pass += 1;
                pending.calls = calls;
                pending.next = 0;
            }
        }
        if let Some((target, value)) = pending.calls.get(pending.next).copied() {
            ensure!(
                engine.get_data().apis.user_callbacks.calls < 4096,
                "FLS destructor call quota exceeded"
            );
            engine.get_data_mut().apis.user_callbacks.calls += 1;
            let marker = engine.get_data().return_marker + 0xa00;
            pending.checked = Some(crt_startup::initializers::begin_checked_call(
                engine,
                target,
                pending.sp,
                &[value],
                false,
                marker,
            )?);
            pending.next += 1;
        } else {
            pending.complete = true;
        }
        Ok(())
    })();
    if result.is_ok() && pending.complete && pending.apc_wait.is_some() {
        user_threads::restore_apc_wait(engine, pending.apc_wait.take().unwrap())?;
    } else if result.is_ok()
        && pending.complete
        && let Some((code, _)) = pending.retirement
    {
        user_threads::retirement_complete(engine, id, code);
    } else {
        engine
            .get_data_mut()
            .apis
            .user_callbacks
            .pending
            .entry(id)
            .or_default()
            .push(pending);
    }
    result.map(|()| None)
}
pub(crate) fn resume_api(engine: &mut Unicorn<Trace>, pc: u64) -> Result<bool> {
    let id = user_threads::current_id(engine);
    let Some(pending) = engine
        .get_data()
        .apis
        .user_callbacks
        .pending
        .get(&id)
        .and_then(|p| p.last())
        .filter(|p| p.complete)
    else {
        return Ok(false);
    };
    ensure!(
        pc == pending.pc
            && uc(engine.reg_read(sp_register(engine.get_data().architecture)))? == pending.sp
            && read(engine, pending.sp, pending.frame.len() as u64)? == pending.frame,
        "FLS caller frame changed"
    );
    let event = pending.event;
    uc(engine.reg_write(
        if engine.get_data().architecture == Architecture::X64 {
            RegisterX86::RAX
        } else {
            RegisterX86::EAX
        },
        1,
    ))?;
    if let Some(index) = event
        && let Some(event) = engine.get_data_mut().apis.events.get_mut(index)
    {
        event.pending = false;
        event.result = Some(1);
        event.effect = Some("fls_destructors_returned");
    }
    engine
        .get_data_mut()
        .apis
        .user_callbacks
        .pending
        .get_mut(&id)
        .unwrap()
        .pop();
    Ok(true)
}
pub(crate) fn cancel(engine: &mut Unicorn<Trace>, id: u64, reason: &'static str) {
    crate::native_exceptions::user::cancel(engine, id);
    user_lifecycle::continuations::cancel(engine, id, reason);
    let frames = engine
        .get_data_mut()
        .apis
        .user_callbacks
        .pending
        .remove(&id)
        .unwrap_or_default();
    for frame in frames {
        if let Some(pending) = frame.apc_wait {
            user_threads::abort_pending(engine, pending, reason);
        }
        if let Some(index) = frame.event
            && let Some(event) = engine.get_data_mut().apis.events.get_mut(index)
        {
            event.pending = false;
            event.error = Some(reason.into());
            event.effect = Some(reason);
        }
    }
}

impl State {
    pub(crate) fn thread_ids(&self) -> Vec<u64> {
        self.pending.keys().copied().collect()
    }
}
