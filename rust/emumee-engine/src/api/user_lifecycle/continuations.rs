//! Serialized DLL/TLS thread notifications with resumable guest frames.
use super::*;
struct Frame {
    calls: Vec<LoaderInvocation>,
    next: usize,
    saved: unicorn_engine::Context,
    checked: Option<crt_startup::initializers::CheckedCall>,
    event: Option<usize>,
    sp: u64,
    reason: u32,
    exit_code: Option<u32>,
}
#[derive(Default)]
pub(super) struct State {
    frames: BTreeMap<u64, Frame>,
    owner: Option<u64>,
    action: bool,
}
pub(crate) fn queued(engine: &Unicorn<Trace>) -> bool {
    engine.get_data().user_lifecycle.continuations.action
}
pub(crate) fn busy(engine: &Unicorn<Trace>) -> bool {
    engine
        .get_data()
        .user_lifecycle
        .continuations
        .owner
        .is_some()
}
pub(crate) fn pending(engine: &Unicorn<Trace>, id: u64) -> bool {
    engine
        .get_data()
        .user_lifecycle
        .continuations
        .frames
        .contains_key(&id)
}
pub(crate) fn owns(engine: &Unicorn<Trace>, id: u64) -> bool {
    engine.get_data().user_lifecycle.continuations.owner == Some(id)
}
pub(crate) fn blocked(engine: &Unicorn<Trace>, id: u64) -> bool {
    pending(engine, id) && busy(engine) && !owns(engine, id)
}
pub(crate) fn queue_thread(
    engine: &mut Unicorn<Trace>,
    reason: u32,
    sp: u64,
    exit_code: Option<u32>,
) -> Result<bool> {
    ensure!(
        matches!(reason, 2 | 3),
        "Invalid resumable thread notification reason"
    );
    let calls = calls(engine, reason)?;
    if calls.is_empty() {
        return Ok(false);
    }
    let id = user_threads::current_id(engine);
    ensure!(
        !pending(engine, id) && engine.get_data().user_lifecycle.continuations.frames.len() < 65,
        "Thread notification continuation already present or bound exceeded"
    );
    let frame = Frame {
        calls,
        next: 0,
        saved: uc(engine.context_init())?,
        checked: None,
        event: None,
        sp,
        reason,
        exit_code,
    };
    let state = &mut engine.get_data_mut().user_lifecycle.continuations;
    state.frames.insert(id, frame);
    if state.owner.is_none() {
        state.owner = Some(id);
        state.action = true;
    } else {
        user_threads::schedule(engine);
    }
    Ok(true)
}
pub(crate) fn selected(engine: &mut Unicorn<Trace>, id: u64) {
    let state = &mut engine.get_data_mut().user_lifecycle.continuations;
    if state.owner.is_none() && state.frames.contains_key(&id) {
        state.owner = Some(id);
        state.action = true;
    }
    let active = state.owner == Some(id);
    engine.get_data_mut().loader_active = active;
    engine.get_data_mut().user_lifecycle.active = active;
}
pub(crate) fn before_instruction(engine: &mut Unicorn<Trace>, pc: u64) -> bool {
    let id = user_threads::current_id(engine);
    if pc == engine.get_data().return_marker + 0xc00
        && engine
            .get_data()
            .user_lifecycle
            .continuations
            .frames
            .get(&id)
            .is_some_and(|f| f.checked.is_some())
    {
        engine.get_data_mut().user_lifecycle.continuations.action = true;
        true
    } else {
        false
    }
}
pub(crate) fn transition(engine: &mut Unicorn<Trace>) -> Result<Option<Outcome>> {
    let id = user_threads::current_id(engine);
    ensure!(
        owns(engine, id),
        "Thread notification selected on a foreign CPU"
    );
    engine.get_data_mut().user_lifecycle.continuations.action = false;
    engine.get_data_mut().loader_active = true;
    engine.get_data_mut().user_lifecycle.active = true;
    let mut frame = engine
        .get_data_mut()
        .user_lifecycle
        .continuations
        .frames
        .remove(&id)
        .context("Thread notification frame missing")?;
    let result = (|| -> Result<bool> {
        if let Some(checked) = frame.checked.take() {
            let result = checked.validate(engine);
            let stopped = engine.get_data().instructions;
            if let Some(index) = frame.event.take() {
                let event = &mut engine.get_data_mut().user_lifecycle.events[index];
                event.stopped_instruction = Some(stopped);
                event.returned = result.is_ok();
                event.error = result.as_ref().err().map(|e| format!("{e:#}"));
            }
            uc(engine.context_restore(&frame.saved))?;
            result?;
        }
        let Some(call) = frame.calls.get(frame.next) else {
            return Ok(true);
        };
        ensure!(
            engine.get_data().user_lifecycle.events.len() < MAX_EVENTS,
            "Loader notification event quota exceeded"
        );
        user_loader::sync(engine)?;
        let index = engine.get_data().user_lifecycle.events.len();
        let started = engine.get_data().instructions;
        engine.get_data_mut().user_lifecycle.events.push(Event {
            invocation: call.clone(),
            reason: frame.reason,
            thread: id,
            started_instruction: started,
            stopped_instruction: None,
            returned: false,
            error: None,
        });
        frame.event = Some(index);
        frame.checked = Some(crt_startup::initializers::begin_checked_call(
            engine,
            call.address,
            frame.sp,
            &call.arguments,
            false,
            engine.get_data().return_marker + 0xc00,
        )?);
        frame.next += 1;
        Ok(false)
    })();
    if matches!(result, Ok(true)) {
        engine.get_data_mut().user_lifecycle.continuations.owner = None;
        engine.get_data_mut().loader_active = false;
        engine.get_data_mut().user_lifecycle.active = false;
        if let Some(code) = frame.exit_code {
            user_threads::notification_complete(engine, id, code);
        }
    } else {
        engine
            .get_data_mut()
            .user_lifecycle
            .continuations
            .frames
            .insert(id, frame);
    }
    result.map(|_| None)
}
pub(crate) fn cancel(engine: &mut Unicorn<Trace>, id: u64, reason: &'static str) {
    let frame = engine
        .get_data_mut()
        .user_lifecycle
        .continuations
        .frames
        .remove(&id);
    if let Some(frame) = frame
        && let Some(index) = frame.event
    {
        let stopped = engine.get_data().instructions;
        let event = &mut engine.get_data_mut().user_lifecycle.events[index];
        event.stopped_instruction = Some(stopped);
        event.error = Some(reason.into());
    }
    if owns(engine, id) {
        engine.get_data_mut().user_lifecycle.continuations.owner = None;
        engine.get_data_mut().user_lifecycle.continuations.action = false;
        if user_threads::current_id(engine) == id {
            engine.get_data_mut().loader_active = false;
            engine.get_data_mut().user_lifecycle.active = false;
        }
    }
}
