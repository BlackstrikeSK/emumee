use super::*;
use std::collections::BTreeSet;
use unicorn_engine::Context as CpuContext;

#[derive(Clone)]
pub(crate) enum Wait {
    Objects { handles: Vec<u64>, all: bool },
    Sleep,
    Critical(u64),
}
#[derive(Clone)]
struct Blocked {
    kind: Wait,
    deadline: Option<u64>,
    alertable: bool,
}
#[derive(Default)]
pub(super) struct State {
    contexts: BTreeMap<u64, CpuContext>,
    waits: BTreeMap<u64, Blocked>,
    pub(super) ready: BTreeSet<u64>,
    root_teb: u64,
    root_return: Option<u64>,
    root_exited: bool,
    last_exit: u32,
    retired_fls: BTreeSet<u64>,
    notified_detach: BTreeSet<u64>,
    context_request: Option<([u64; 2], bool)>,
    apcs: BTreeMap<u64, std::collections::VecDeque<(u64, u64)>>,
    deliver: BTreeSet<u64>,
}
impl State {
    pub(super) fn begin_entry(&mut self) {
        self.root_return = None;
    }
    pub(super) fn has_waits(&self) -> bool {
        !self.waits.is_empty()
    }
    pub(super) fn deadline(&self) -> Option<u64> {
        self.waits.values().filter_map(|w| w.deadline).min()
    }
}

pub(crate) fn wait(
    engine: &mut Unicorn<Trace>,
    kind: Wait,
    timeout: u32,
    argc: usize,
) -> Result<u64> {
    ensure!(
        (!engine.get_data().loader_active
            || user_lifecycle::continuations::owns(engine, current_id(engine)))
            && engine.get_data().continuation_depth == 1,
        "Blocking user wait inside a serialized guest callback cannot be scheduled"
    );
    engine.get_data_mut().clock.flush_cycles()?;
    let now = engine.get_data().clock.qpc();
    let deadline = if timeout == u32::MAX {
        None
    } else {
        Some(
            now.checked_add(timeout as u64 * 10_000)
                .context("User wait deadline overflow")?,
        )
    };
    let id = current_id(engine);
    queue(engine, 0, 0, argc)?;
    engine.get_data_mut().user_threads.scheduler.waits.insert(
        id,
        Blocked {
            kind,
            deadline,
            alertable: false,
        },
    );
    Ok(0)
}

pub(crate) fn alertable_wait(
    engine: &mut Unicorn<Trace>,
    kind: Wait,
    timeout: u32,
    argc: usize,
    alertable: bool,
) -> Result<u64> {
    let result = wait(engine, kind, timeout, argc)?;
    let id = current_id(engine);
    engine
        .get_data_mut()
        .user_threads
        .scheduler
        .waits
        .get_mut(&id)
        .unwrap()
        .alertable = alertable;
    Ok(result)
}
pub(crate) fn queue_apc(engine: &mut Unicorn<Trace>, id: u64, target: u64, value: u64) -> bool {
    let state = &mut engine.get_data_mut().user_threads.scheduler;
    if state.apcs.values().map(|q| q.len()).sum::<usize>() >= 1024 {
        return false;
    }
    let queue = state.apcs.entry(id).or_default();
    if queue.len() >= 128 {
        return false;
    }
    queue.push_back((target, value));
    true
}
fn deliver_apcs(
    engine: &mut Unicorn<Trace>,
    id: u64,
    _horizon: &ExecutionHorizon,
) -> Result<Option<Outcome>> {
    if !engine
        .get_data_mut()
        .user_threads
        .scheduler
        .deliver
        .remove(&id)
    {
        return Ok(None);
    }
    // Detach the completed outer wait before invoking guest callbacks. A callback
    // may itself wait; it must not overwrite the outer API's return authority.
    let calls = engine
        .get_data_mut()
        .user_threads
        .scheduler
        .apcs
        .remove(&id)
        .unwrap_or_default()
        .into_iter()
        .collect();
    user_callbacks::queue_apcs(engine, calls)?;
    Ok(None)
}

pub(super) fn detach_apc_wait(engine: &mut Unicorn<Trace>) -> Result<Pending> {
    let id = current_id(engine);
    let state = &mut engine.get_data_mut().user_threads;
    ensure!(
        state.scheduler.ready.remove(&id),
        "APC outer wait is not ready"
    );
    state.pending.remove(&id).context("APC outer wait missing")
}
pub(super) fn restore_apc_wait(engine: &mut Unicorn<Trace>, pending: Pending) -> Result<()> {
    let id = current_id(engine);
    let state = &mut engine.get_data_mut().user_threads;
    ensure!(
        !state.pending.contains_key(&id),
        "APC callback left an active API continuation"
    );
    state.pending.insert(id, pending);
    state.scheduler.ready.insert(id);
    Ok(())
}

fn save(engine: &mut Unicorn<Trace>, id: u64) -> Result<()> {
    user_bootstrap::before_instruction(engine)?;
    let mut context = uc(engine.context_init())?;
    uc(engine.context_save(&mut context))?;
    engine
        .get_data_mut()
        .user_threads
        .scheduler
        .contexts
        .insert(id, context);
    Ok(())
}
fn restore(engine: &mut Unicorn<Trace>, id: u64) -> Result<()> {
    let context = engine
        .get_data_mut()
        .user_threads
        .scheduler
        .contexts
        .remove(&id)
        .context("User CPU context missing")?;
    user_bootstrap::before_instruction(engine)?;
    uc(engine.context_restore(&context))?;
    engine
        .get_data_mut()
        .user_threads
        .scheduler
        .contexts
        .insert(id, context);
    engine.get_data_mut().user_threads.current = id;
    let teb = if id == 1 {
        engine.get_data().user_threads.scheduler.root_teb
    } else {
        engine
            .get_data()
            .user_threads
            .records
            .values()
            .find(|t| t.id == id)
            .context("Thread record missing")?
            .teb
    };
    user_bootstrap::activate_thread(engine, teb)?;
    user_lifecycle::continuations::selected(engine, id);
    Ok(())
}
fn prepare(engine: &mut Unicorn<Trace>, handle: u64) -> Result<()> {
    let id = engine.get_data().user_threads.records[&handle].id;
    if engine
        .get_data()
        .user_threads
        .scheduler
        .contexts
        .contains_key(&id)
    {
        return Ok(());
    }
    let caller_id = current_id(engine);
    let caller_teb = user_bootstrap::active_teb(engine).context("Caller TEB missing")?;
    user_bootstrap::before_instruction(engine)?;
    let mut caller = uc(engine.context_init())?;
    uc(engine.context_save(&mut caller))?;
    let result = (|| -> Result<()> {
        let thread = engine.get_data().user_threads.records[&handle].clone();
        user_loader::preflight_thread(engine, thread.stack_size)?;
        let stack = user_loader::allocate(engine, thread.stack_size)?;
        let teb = user_loader::allocate(engine, 8192)?;
        user_bootstrap::initialize_thread(engine, teb, stack, thread.stack_size, thread.id)?;
        user_loader::attach_thread(engine, thread.id, teb)?;
        {
            let record = engine
                .get_data_mut()
                .user_threads
                .records
                .get_mut(&handle)
                .unwrap();
            record.stack = stack;
            record.teb = teb;
        }
        engine.get_data_mut().user_threads.current = thread.id;
        user_bootstrap::activate_thread(engine, teb)?;
        let top = stack + thread.stack_size - 0x200;
        let arch = engine.get_data().architecture;
        let marker = engine.get_data().return_marker + 0x500;
        let sp = (top & !15) - if arch == Architecture::X64 { 40 } else { 8 };
        let mut frame = vec![0; if arch == Architecture::X64 { 40 } else { 8 }];
        let width = arch.width();
        frame[..width].copy_from_slice(&marker.to_le_bytes()[..width]);
        if width == 4 {
            frame[4..8].copy_from_slice(&(thread.parameter as u32).to_le_bytes());
        }
        crate::cpu::write(engine, sp, &frame)?;
        uc(engine.reg_write(sp_register(arch), sp))?;
        if width == 8 {
            uc(engine.reg_write(RegisterX86::RCX, thread.parameter))?;
        }
        uc(engine.reg_write(
            if width == 8 {
                RegisterX86::RIP
            } else {
                RegisterX86::EIP
            },
            thread.entry,
        ))?;
        save(engine, id)
    })();
    uc(engine.context_restore(&caller))?;
    engine.get_data_mut().user_threads.current = caller_id;
    user_bootstrap::activate_thread(engine, caller_teb)?;
    result
}
fn start(
    engine: &mut Unicorn<Trace>,
    handle: u64,
    _horizon: &ExecutionHorizon,
) -> Result<Option<Outcome>> {
    prepare(engine, handle)?;
    let thread = engine.get_data().user_threads.records[&handle].clone();
    restore(engine, thread.id)?;
    engine
        .get_data_mut()
        .user_threads
        .records
        .get_mut(&handle)
        .unwrap()
        .state = "running";
    // Notifications need their own frame below the prepared start frame.
    // Restoring CPU registers cannot undo an overlapping guest-stack write.
    let notification_sp = uc(engine.reg_read(sp_register(engine.get_data().architecture)))?
        .checked_sub(0x100)
        .context("Thread notification stack underflow")?;
    user_lifecycle::continuations::queue_thread(engine, 2, notification_sp, None)?;
    Ok(None)
}

fn finish(
    engine: &mut Unicorn<Trace>,
    id: u64,
    code: u32,
    forced: bool,
    _horizon: &ExecutionHorizon,
) -> Result<Option<Outcome>> {
    let thread = engine
        .get_data()
        .user_threads
        .records
        .values()
        .find(|t| t.id == id)
        .context("Exiting thread missing")?
        .clone();
    user_callbacks::cancel(engine, id, "aborted_by_thread_exit");
    if let Some(pending) = engine.get_data_mut().user_threads.pending.remove(&id) {
        abort_pending(engine, pending, "aborted_by_thread_exit");
    }
    user_loader::detach_thread(engine, id)?;
    // Switch away before freeing the active TEB; the parent owns its backing.
    restore(engine, 1)?;
    user_loader::release(engine, thread.teb)?;
    user_loader::release(engine, thread.stack)?;
    user_runtime::retire_thread(engine, id);
    engine.get_data_mut().apis.user_sync.abandon(id);
    let state = &mut engine.get_data_mut().user_threads;
    let record = state.records.get_mut(&thread.handle).unwrap();
    record.exit_code = Some(code);
    record.state = if forced { "terminated" } else { "exited" };
    record.backing_released = true;
    if record.auto_close {
        record.handle_closed = true;
        state.handles.remove(&thread.handle);
    }
    state.scheduler.last_exit = code;
    state.scheduler.contexts.remove(&id);
    state.scheduler.waits.remove(&id);
    state.scheduler.ready.remove(&id);
    state.scheduler.apcs.remove(&id);
    state.scheduler.deliver.remove(&id);
    Ok(None)
}
pub(crate) fn external(engine: &Unicorn<Trace>) -> BTreeMap<u64, bool> {
    let state = &engine.get_data().user_threads;
    state
        .handles
        .iter()
        .filter(|(_, h)| h.access & 0x100000 != 0)
        .map(|(handle, h)| {
            (
                *handle,
                state.record(h.canonical).unwrap().exit_code.is_some(),
            )
        })
        .chain(user_processes::external(engine))
        .collect()
}
fn wake(engine: &mut Unicorn<Trace>) -> Result<()> {
    let waits = engine.get_data().user_threads.scheduler.waits.clone();
    engine.get_data_mut().clock.flush_cycles()?;
    let now = engine.get_data().clock.qpc();
    for (id, blocked) in waits {
        if blocked.alertable
            && engine
                .get_data()
                .user_threads
                .scheduler
                .apcs
                .get(&id)
                .is_some_and(|q| !q.is_empty())
        {
            let state = &mut engine.get_data_mut().user_threads;
            state.scheduler.waits.remove(&id);
            state.scheduler.ready.insert(id);
            state.scheduler.deliver.insert(id);
            state
                .pending
                .get_mut(&id)
                .context("Alertable caller missing")?
                .result = 0xc0;
            continue;
        }
        let result = match &blocked.kind {
            Wait::Objects { handles, all } => {
                let external = external(engine);
                match engine
                    .get_data_mut()
                    .apis
                    .user_sync
                    .wait(handles, *all, id, &external)
                {
                    Ok(value) => value,
                    Err(error) => {
                        // A handle closed during a pending wait is a deterministic
                        // invalid-handle failure, never an accidental host wait.
                        if let Some(p) = engine.get_data_mut().user_threads.pending.get_mut(&id) {
                            p.result = u32::MAX as u64;
                        }
                        if let Some(p) = engine.get_data_mut().user_threads.pending.get_mut(&id) {
                            p.last_error = Some(error);
                        }
                        Some(u32::MAX)
                    }
                }
            }
            Wait::Sleep => None,
            Wait::Critical(address) => {
                user_runtime::acquire_critical(engine, *address, id)?.then_some(0)
            }
        }
        .or_else(|| {
            blocked
                .deadline
                .filter(|deadline| now >= *deadline)
                .map(|_| {
                    if matches!(blocked.kind, Wait::Sleep) {
                        0
                    } else {
                        emumee_core::user_sync::TIMEOUT
                    }
                })
        });
        if let Some(result) = result {
            let state = &mut engine.get_data_mut().user_threads;
            state.scheduler.waits.remove(&id);
            state.scheduler.ready.insert(id);
            if let Some(p) = state.pending.get_mut(&id) {
                p.result = result as u64;
            }
        }
    }
    Ok(())
}
fn runnable(engine: &Unicorn<Trace>) -> Vec<u64> {
    let state = &engine.get_data().user_threads;
    let mut ids = Vec::new();
    if state.scheduler.root_return.is_none()
        && !state.scheduler.waits.contains_key(&1)
        && state.root.as_ref().is_none_or(|t| t.suspended == 0)
        && !user_lifecycle::continuations::blocked(engine, 1)
    {
        ids.push(1);
    }
    ids.extend(
        state
            .records
            .values()
            .filter(|t| {
                t.exit_code.is_none()
                    && t.suspended == 0
                    && !state.scheduler.waits.contains_key(&t.id)
                    && !user_lifecycle::continuations::blocked(engine, t.id)
                    && (t.state != "created" || !user_lifecycle::continuations::busy(engine))
            })
            .map(|t| t.id),
    );
    ids.sort_unstable();
    ids
}
pub(crate) fn checkpoint(
    engine: &mut Unicorn<Trace>,
    horizon: &ExecutionHorizon,
    root_marker: u64,
) -> Result<Option<Outcome>> {
    if engine.get_data().apis.user_bootstrap.is_none()
        || engine.get_data().continuation_depth != 1
        || (engine.get_data().loader_active
            && !user_lifecycle::continuations::owns(engine, current_id(engine)))
        || (engine.get_data().user_threads.records.is_empty() && !exiting(engine))
    {
        return Ok(None);
    }
    pump(engine, horizon, Some(root_marker))
}
pub(super) fn pump(
    engine: &mut Unicorn<Trace>,
    horizon: &ExecutionHorizon,
    root_marker: Option<u64>,
) -> Result<Option<Outcome>> {
    ensure!(
        engine.get_data().continuation_depth == 1,
        "User thread transfer inside a serialized callback is unsupported"
    );
    if horizon.expired(engine.get_data().instructions) {
        return Ok(Some(Outcome {
            returned: false,
            value: None,
            error: None,
        }));
    }
    if let Some((args, set)) = engine
        .get_data_mut()
        .user_threads
        .scheduler
        .context_request
        .take()
    {
        let result = thread_context(engine, &args, set)?;
        let id = current_id(engine);
        engine
            .get_data_mut()
            .user_threads
            .pending
            .get_mut(&id)
            .context("Context API caller missing")?
            .result = result;
    }
    let id = current_id(engine);
    if engine.get_data().user_threads.scheduler.root_teb == 0 {
        engine.get_data_mut().user_threads.scheduler.root_teb =
            user_bootstrap::active_teb(engine).context("Root TEB absent")?;
    }
    let preferred = engine
        .get_data()
        .user_threads
        .pending
        .get(&id)
        .map(|p| p.handle)
        .filter(|h| *h != 0);
    engine.get_data_mut().user_threads.action = false;
    if engine.get_data().user_threads.pending.contains_key(&id)
        && !engine
            .get_data()
            .user_threads
            .scheduler
            .waits
            .contains_key(&id)
    {
        engine
            .get_data_mut()
            .user_threads
            .scheduler
            .ready
            .insert(id);
    }
    if user_lifecycle::continuations::pending(engine, id) {
        save(engine, id)?;
    } else {
        let pc = uc(engine.pc_read())?;
        let exit = engine.get_data_mut().user_threads.exit.take();
        if id != 1 && pc == engine.get_data().return_marker + 0x500 && exit.is_none() {
            let record = engine
                .get_data()
                .user_threads
                .records
                .values()
                .find(|t| t.id == id)
                .context("Returning user thread missing")?;
            let expected = (record.stack + record.stack_size - 0x200) & !15;
            let expected = if engine.get_data().architecture == Architecture::X64 {
                expected - 32
            } else if record.cdecl_start {
                expected - 4
            } else {
                expected
            };
            ensure!(
                uc(engine.reg_read(sp_register(engine.get_data().architecture)))? == expected,
                "User thread start routine violated its STDCALL1/Win64 return frame"
            );
        }
        let retiring = if exit.is_some() {
            exit
        } else if id != 1 && pc == engine.get_data().return_marker + 0x500 {
            Some((uc(engine.reg_read(RegisterX86::EAX))? as u32, false))
        } else {
            None
        };
        if let Some((code, false)) = retiring {
            let completed = engine
                .get_data_mut()
                .user_threads
                .scheduler
                .retired_fls
                .remove(&id);
            let sp = uc(engine.reg_read(sp_register(engine.get_data().architecture)))?;
            if !completed && user_callbacks::retire(engine, id, code, sp)? {
                return Ok(None);
            }
            let notified = engine
                .get_data_mut()
                .user_threads
                .scheduler
                .notified_detach
                .remove(&id);
            if !notified
                && user_lifecycle::continuations::queue_thread(
                    engine,
                    3,
                    sp.checked_sub(0x100)
                        .context("Thread detach stack underflow")?,
                    Some(code),
                )?
            {
                return Ok(None);
            }
        }
        if id == 1
            && let Some((code, forced)) = exit
        {
            save(engine, 1)?;
            user_callbacks::cancel(engine, 1, "aborted_by_thread_exit");
            if let Some(pending) = engine.get_data_mut().user_threads.pending.remove(&1) {
                abort_pending(engine, pending, "aborted_by_thread_exit");
            }
            user_loader::detach_thread(engine, 1)?;
            user_runtime::retire_thread(engine, 1);
            engine.get_data_mut().apis.user_sync.abandon(1);
            let state = &mut engine.get_data_mut().user_threads;
            state.scheduler.root_return = Some(code as u64);
            state.scheduler.root_exited = true;
            if let Some(root) = state.root.as_mut() {
                root.exit_code = Some(code);
                root.state = if forced { "terminated" } else { "exited" };
            }
            state.scheduler.last_exit = code;
            state.scheduler.waits.remove(&1);
            state.pending.remove(&1);
            state.scheduler.ready.remove(&1);
            state.scheduler.apcs.remove(&1);
            state.scheduler.deliver.remove(&1);
        } else if id != 1 && (pc == engine.get_data().return_marker + 0x500 || exit.is_some()) {
            let (code, forced) =
                exit.unwrap_or((uc(engine.reg_read(RegisterX86::EAX))? as u32, false));
            if let Some(outcome) = finish(engine, id, code, forced, horizon)? {
                return Ok(Some(outcome));
            }
        } else {
            save(engine, id)?;
            if id == 1 && root_marker == Some(pc) {
                engine.get_data_mut().user_threads.scheduler.root_return = Some(uc(engine
                    .reg_read(if engine.get_data().architecture == Architecture::X64 {
                        RegisterX86::RAX
                    } else {
                        RegisterX86::EAX
                    }))?);
            }
        }
    }
    loop {
        wake(engine)?;
        let ids = runnable(engine);
        if !ids.is_empty() {
            let preferred_id = preferred
                .and_then(|h| engine.get_data().user_threads.records.get(&h))
                .map(|t| t.id)
                .filter(|i| ids.contains(i));
            let next = preferred_id
                .or_else(|| ids.iter().copied().find(|i| *i > id))
                .unwrap_or(ids[0]);
            if next == 1
                || engine
                    .get_data()
                    .user_threads
                    .records
                    .values()
                    .any(|t| t.id == next && t.state != "created")
                    && engine
                        .get_data()
                        .user_threads
                        .scheduler
                        .contexts
                        .contains_key(&next)
            {
                restore(engine, next)?;
            } else {
                let handle = engine
                    .get_data()
                    .user_threads
                    .records
                    .values()
                    .find(|t| t.id == next)
                    .unwrap()
                    .handle;
                if let Some(outcome) = start(engine, handle, horizon)? {
                    return Ok(Some(outcome));
                }
            }
            if let Some(outcome) = deliver_apcs(engine, next, horizon)? {
                return Ok(Some(outcome));
            }
            return Ok(None);
        }
        let state = &engine.get_data().user_threads;
        if let Some(value) = state.scheduler.root_return
            && state.records.values().all(|t| t.exit_code.is_some())
        {
            let exited = state.scheduler.root_exited;
            let code = state.scheduler.last_exit;
            restore(engine, 1)?;
            if exited {
                user_lifecycle::request_exit(engine, code, false)?;
                return Ok(Some(Outcome {
                    returned: false,
                    value: None,
                    error: None,
                }));
            }
            return Ok(Some(Outcome {
                returned: true,
                value: Some(value),
                error: None,
            }));
        }
        if user_processes::idle(engine) {
            return Ok(None);
        }
        let state = &engine.get_data().user_threads;
        if let Some(deadline) = state
            .scheduler
            .waits
            .values()
            .filter_map(|w| w.deadline)
            .min()
        {
            engine.get_data_mut().clock.flush_cycles()?;
            let now = engine.get_data().clock.qpc();
            engine
                .get_data_mut()
                .clock
                .advance_100ns(deadline.saturating_sub(now))?;
            crate::time::sync(engine)?;
        } else {
            return Ok(Some(Outcome {
                returned: false,
                value: None,
                error: Some("User thread deadlock: no runnable work or future deadline".into()),
            }));
        }
    }
}
pub(crate) fn terminal_restore(engine: &mut Unicorn<Trace>) -> Result<()> {
    let id = current_id(engine);
    for record in engine.get_data_mut().user_threads.records.values_mut() {
        if record.exit_code.is_none() && record.teb != 0 {
            record.state = "interrupted";
        }
    }
    if id != 1
        && engine
            .get_data()
            .user_threads
            .scheduler
            .contexts
            .contains_key(&1)
    {
        restore(engine, 1)?;
    }
    Ok(())
}

pub(super) fn terminate_other(engine: &mut Unicorn<Trace>, id: u64, code: u32) -> Result<()> {
    user_callbacks::cancel(engine, id, "aborted_by_thread_termination");
    if id == 1 {
        user_loader::detach_thread(engine, 1)?;
        user_runtime::retire_thread(engine, 1);
        engine.get_data_mut().apis.user_sync.abandon(1);
        let state = &mut engine.get_data_mut().user_threads;
        state.scheduler.root_exited = true;
        state.scheduler.root_return = Some(code as u64);
        state.scheduler.last_exit = code;
        state.scheduler.waits.remove(&1);
        state.scheduler.apcs.remove(&1);
        state.scheduler.ready.remove(&1);
        state.scheduler.deliver.remove(&1);
        if let Some(root) = state.root.as_mut() {
            root.exit_code = Some(code);
            root.state = "terminated";
        }
        if let Some(pending) = state.pending.remove(&1)
            && let Some(index) = pending.event
            && let Some(event) = engine.get_data_mut().apis.events.get_mut(index)
        {
            event.pending = false;
            event.effect = Some("aborted_by_thread_termination");
        }
        return Ok(());
    }
    let thread = engine
        .get_data()
        .user_threads
        .records
        .values()
        .find(|t| t.id == id)
        .context("Terminated thread missing")?
        .clone();
    ensure!(
        id != current_id(engine),
        "Foreign termination cannot retire the active context"
    );
    if thread.exit_code.is_some() {
        return Ok(());
    }
    if thread.teb != 0 {
        user_loader::detach_thread(engine, id)?;
        user_loader::release(engine, thread.teb)?;
        user_loader::release(engine, thread.stack)?;
    }
    user_runtime::retire_thread(engine, id);
    engine.get_data_mut().apis.user_sync.abandon(id);
    let state = &mut engine.get_data_mut().user_threads;
    state.scheduler.last_exit = code;
    state.scheduler.contexts.remove(&id);
    state.scheduler.waits.remove(&id);
    state.scheduler.ready.remove(&id);
    state.scheduler.apcs.remove(&id);
    state.scheduler.deliver.remove(&id);
    let record = state.records.get_mut(&thread.handle).unwrap();
    record.state = "terminated";
    record.exit_code = Some(code);
    record.backing_released = true;
    if let Some(pending) = state.pending.remove(&id)
        && let Some(index) = pending.event
        && let Some(event) = engine.get_data_mut().apis.events.get_mut(index)
    {
        event.pending = false;
        event.effect = Some("aborted_by_thread_termination");
    }
    Ok(())
}

/// Register-bank writes (notably DR7) can invalidate a Unicorn translation.
/// Defer them until emu_start has stopped; replaying a hook in the invalidated
/// return stub would repeatedly invoke the same API without making progress.
pub(super) fn queue_context(engine: &mut Unicorn<Trace>, args: &[u64], set: bool) -> Result<u64> {
    ensure!(
        engine
            .get_data()
            .user_threads
            .scheduler
            .context_request
            .is_none(),
        "Context API transfer already pending"
    );
    queue(engine, 0, 0, 2)?;
    engine.get_data_mut().user_threads.scheduler.context_request = Some(([args[0], args[1]], set));
    Ok(0)
}
/// CONTEXT_CONTROL/INTEGER over the owned saved CPU. A running caller cannot
/// inspect or overwrite another running thread at an arbitrary host instant.
pub(super) fn thread_context(engine: &mut Unicorn<Trace>, args: &[u64], set: bool) -> Result<u64> {
    transfer_context(engine, args, set, false)
}
fn transfer_context(
    engine: &mut Unicorn<Trace>,
    args: &[u64],
    set: bool,
    remote: bool,
) -> Result<u64> {
    let handle = match authority::resolve(engine, args[0], if set { 0x10 } else { 8 }) {
        Ok(h) => h,
        Err(e) => return Ok(failure(engine, e, 0)),
    };
    let thread = engine
        .get_data()
        .user_threads
        .record(handle)
        .unwrap()
        .clone();
    if thread.exit_code.is_some()
        || (!remote && thread.id == current_id(engine))
        || thread.suspended == 0
    {
        return Ok(failure(engine, 87, 0));
    }
    let wide = engine.get_data().architecture == Architecture::X64;
    let (size, offset, machine) = if wide {
        (1232, 48, 0x100000)
    } else {
        (716, 0, 0x10000)
    };
    let permission = if set { P::READ } else { P::RW };
    if require(engine, args[1], size, permission).is_err() {
        return Ok(failure(engine, 998, 0));
    }
    let mut bytes = read(engine, args[1], size)?;
    let flags = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
    let groups = if wide { 0x1f } else { 0x3f };
    if flags & machine == 0 || flags & !(machine | groups) != 0 || flags & groups == 0 {
        return Ok(failure(engine, 87, 0));
    }
    if set
        && engine
            .get_data()
            .user_threads
            .pending
            .contains_key(&thread.id)
    {
        return Ok(failure(engine, 50, 0));
    }
    if thread.id != 1 {
        if thread.stack == 0 && user_loader::preflight_thread(engine, thread.stack_size).is_err() {
            return Ok(failure(engine, 8, 0));
        }
        prepare(engine, handle)?;
    }
    use RegisterX86::*;
    let fields = context_fields(wide);
    let context = &engine.get_data().user_threads.scheduler.contexts[&thread.id];
    let mut edits = Vec::new();
    for (at, reg, width, group) in fields {
        if flags & group == 0 {
            continue;
        }
        if set {
            let mut raw = [0; 8];
            raw[..width].copy_from_slice(&bytes[at..at + width]);
            let value = u64::from_le_bytes(raw);
            if matches!(reg, CS | SS | DS | ES | FS | GS) {
                if value != uc(context.reg_read(reg))? {
                    return Ok(failure(engine, 87, 0));
                }
            } else if reg == EFLAGS && (value ^ uc(context.reg_read(reg))?) & !0xcd5 != 0 {
                return Ok(failure(engine, 87, 0));
            } else {
                if (matches!(reg, RIP | EIP) && require(engine, value, 1, P::EXECUTE).is_err())
                    || (matches!(reg, RSP | ESP)
                        && require(engine, value, if wide { 8 } else { 4 }, P::RW).is_err())
                {
                    return Ok(failure(engine, 998, 0));
                }
                edits.push((reg, value));
            }
        } else {
            bytes[at..at + width]
                .copy_from_slice(&uc(context.reg_read(reg))?.to_le_bytes()[..width]);
        }
    }
    // Stage edits on the native CPU, save only after all validation succeeds,
    // then restore the executing caller regardless of the operation's result.
    let caller = uc(engine.context_init())?;
    let target = engine
        .get_data_mut()
        .user_threads
        .scheduler
        .contexts
        .remove(&thread.id)
        .unwrap();
    let result = (|| -> Result<Option<CpuContext>> {
        uc(engine.context_restore(&target))?;
        if !floating_context::transfer(engine, &mut bytes, flags, wide, set)? {
            return Ok(None);
        }
        if set {
            for (reg, value) in edits {
                uc(engine.reg_write(reg, value))?;
            }
        }
        Ok(Some(uc(engine.context_init())?))
    })();
    uc(engine.context_restore(&caller))?;
    let (context, valid) = match result {
        Ok(Some(context)) => (context, true),
        Ok(None) => (target, false),
        Err(error) => {
            engine
                .get_data_mut()
                .user_threads
                .scheduler
                .contexts
                .insert(thread.id, target);
            return Err(error);
        }
    };
    engine
        .get_data_mut()
        .user_threads
        .scheduler
        .contexts
        .insert(thread.id, context);
    if !valid {
        return Ok(failure(engine, 87, 0));
    }
    if !set {
        crate::cpu::write(engine, args[1], &bytes)?;
    }
    Ok(1)
}

pub(super) fn retirement_complete(engine: &mut Unicorn<Trace>, id: u64, code: u32) {
    let state = &mut engine.get_data_mut().user_threads;
    state.scheduler.retired_fls.insert(id);
    state.exit = Some((code, false));
    state.action = true;
}

pub(super) fn context_fields(wide: bool) -> Vec<(usize, RegisterX86, usize, u32)> {
    use RegisterX86::*;
    // (Windows byte offset, CPU register, width, flag group).
    let mut fields: Vec<(usize, RegisterX86, usize, u32)> = if wide {
        vec![
            (120, RAX, 8, 2),
            (128, RCX, 8, 2),
            (136, RDX, 8, 2),
            (144, RBX, 8, 2),
            (152, RSP, 8, 1),
            (160, RBP, 8, 2),
            (168, RSI, 8, 2),
            (176, RDI, 8, 2),
            (184, R8, 8, 2),
            (192, R9, 8, 2),
            (200, R10, 8, 2),
            (208, R11, 8, 2),
            (216, R12, 8, 2),
            (224, R13, 8, 2),
            (232, R14, 8, 2),
            (240, R15, 8, 2),
            (248, RIP, 8, 1),
            (68, EFLAGS, 4, 1),
            (56, CS, 2, 1),
            (66, SS, 2, 1),
            (58, DS, 2, 4),
            (60, ES, 2, 4),
            (62, FS, 2, 4),
            (64, GS, 2, 4),
        ]
    } else {
        vec![
            (156, EDI, 4, 2),
            (160, ESI, 4, 2),
            (164, EBX, 4, 2),
            (168, EDX, 4, 2),
            (172, ECX, 4, 2),
            (176, EAX, 4, 2),
            (180, EBP, 4, 1),
            (184, EIP, 4, 1),
            (188, CS, 4, 1),
            (192, EFLAGS, 4, 1),
            (196, ESP, 4, 1),
            (200, SS, 4, 1),
            (140, GS, 4, 4),
            (144, FS, 4, 4),
            (148, ES, 4, 4),
            (152, DS, 4, 4),
        ]
    };
    for (index, reg) in [DR0, DR1, DR2, DR3, DR6, DR7].into_iter().enumerate() {
        fields.push((
            if wide { 72 + index * 8 } else { 4 + index * 4 },
            reg,
            if wide { 8 } else { 4 },
            16,
        ));
    }
    fields
}

pub(super) fn notification_complete(engine: &mut Unicorn<Trace>, id: u64, code: u32) {
    let state = &mut engine.get_data_mut().user_threads;
    state.scheduler.notified_detach.insert(id);
    state.scheduler.retired_fls.insert(id);
    state.exit = Some((code, false));
    state.action = true;
}

pub(super) fn remote_context(
    engine: &mut Unicorn<Trace>,
    id: u64,
    handle: u64,
    buffer: u64,
    set: bool,
) -> Result<u64> {
    let current = current_id(engine);
    if id == current {
        let context = uc(engine.context_init())?;
        engine
            .get_data_mut()
            .user_threads
            .scheduler
            .contexts
            .insert(id, context);
    }
    let result = transfer_context(engine, &[handle, buffer], set, true);
    if id == current && set && result.as_ref().is_ok_and(|result| *result != 0) {
        uc(engine.context_restore(&engine.get_data().user_threads.scheduler.contexts[&id]))?;
    }
    result
}
