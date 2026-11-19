//! Bounded guest thread startup/teardown continuations. No native host threads.
//! Deterministic user scheduling is separate from the kernel scheduler.
pub(super) mod authority;
mod exception_context;
mod floating_context;
pub(crate) mod scheduling;
use super::*;
use crate::threads::{ExecutionHorizon, Outcome};
use anyhow::Context;
pub(crate) use scheduling::{Wait, checkpoint, terminal_restore, wait};

const MAX_THREADS: usize = 64;

#[derive(Clone, Copy)]
pub(super) enum Call {
    Create,
    Begin(bool),
    End(bool),
    Resume,
    Suspend,
    Yield,
    Apc,
    Exit,
    Terminate,
    ExitCode,
    Authority(authority::Call),
}

pub(super) fn definition(module: &str, name: &str) -> Option<(Call, usize, T)> {
    if matches!(
        module,
        "msvcrt" | "ucrtbase" | "api-ms-win-crt-runtime-l1-1-0" | "api-ms-win-crt-private-l1-1-0"
    ) {
        return Some(match name.strip_prefix("_o_").unwrap_or(name) {
            "_beginthread" => (Call::Begin(false), 3, T::Pointer),
            "_beginthreadex" => (Call::Begin(true), 6, T::Pointer),
            "_endthread" => (Call::End(false), 0, T::Void),
            "_endthreadex" => (Call::End(true), 1, T::Void),
            _ => return None,
        });
    }
    if !matches!(
        module,
        "kernel32" | "kernelbase" | "api-ms-win-core-processthreads-l1-1-0"
    ) {
        return None;
    }
    Some(match name {
        "CreateThread" => (Call::Create, 6, T::Pointer),
        "ResumeThread" => (Call::Resume, 1, T::U32),
        "SuspendThread" => (Call::Suspend, 1, T::U32),
        "QueueUserAPC" => (Call::Apc, 3, T::U32),
        "SwitchToThread" => (Call::Yield, 0, T::U32),
        "ExitThread" => (Call::Exit, 1, T::Void),
        "TerminateThread" => (Call::Terminate, 2, T::U32),
        "GetExitCodeThread" => (Call::ExitCode, 2, T::U32),
        _ => {
            let (call, argc, result) = authority::definition(name)?;
            (Call::Authority(call), argc, result)
        }
    })
}

#[derive(Clone, Debug, Serialize)]
pub struct Thread {
    pub id: u64,
    pub handle: u64,
    pub entry: u64,
    pub parameter: u64,
    pub stack_size: u64,
    pub stack: u64,
    pub teb: u64,
    pub suspended: u32,
    pub state: &'static str,
    pub exit_code: Option<u32>,
    pub handle_closed: bool,
    pub backing_released: bool,
    pub cdecl_start: bool,
    pub auto_close: bool,
}

#[derive(Clone)]
pub(super) struct Pending {
    handle: u64,
    result: u64,
    pc: u64,
    sp: u64,
    frame: Vec<u8>,
    event: Option<usize>,
    last_error: Option<u32>,
}

#[derive(Default)]
pub(crate) struct State {
    current: u64,
    root: Option<Thread>,
    records: BTreeMap<u64, Thread>,
    handles: BTreeMap<u64, authority::Handle>,
    next_handle: u64,
    pending: BTreeMap<u64, Pending>,
    scheduler: scheduling::State,
    action: bool,

    exit: Option<(u32, bool)>,
}

const ROOT_HANDLE: u64 = 0x6f000004;
impl State {
    fn record(&self, h: u64) -> Option<&Thread> {
        if h == ROOT_HANDLE {
            self.root.as_ref()
        } else {
            self.records.get(&h)
        }
    }
    fn record_mut(&mut self, h: u64) -> Option<&mut Thread> {
        if h == ROOT_HANDLE {
            self.root.as_mut()
        } else {
            self.records.get_mut(&h)
        }
    }
    fn by_id(&self, id: u64) -> Option<&Thread> {
        if id == 1 {
            self.root.as_ref()
        } else {
            self.records.values().find(|t| t.id == id)
        }
    }
}
pub(crate) fn initialize_root(engine: &mut Unicorn<Trace>) -> Result<()> {
    if engine.get_data().user_threads.root.is_some() {
        return Ok(());
    }
    let bootstrap = user_bootstrap::report(engine).context("Root bootstrap missing")?;
    engine.get_data_mut().user_threads.root = Some(Thread {
        id: 1,
        handle: ROOT_HANDLE,
        entry: 0,
        parameter: 0,
        stack_size: bootstrap.stack_base - bootstrap.stack_limit,
        stack: bootstrap.stack_limit,
        teb: bootstrap.teb,
        suspended: 0,
        state: "running",
        exit_code: None,
        handle_closed: false,
        backing_released: false,
        cdecl_start: false,
        auto_close: false,
    });
    Ok(())
}
#[derive(Debug, Serialize)]
pub struct HandleReport {
    pub handle: u64,
    pub thread: u64,
    pub access: u32,
    pub flags: u32,
}
pub(crate) fn begin_entry(engine: &mut Unicorn<Trace>) {
    engine.get_data_mut().user_threads.scheduler.begin_entry();
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub current: u64,
    pub threads: Vec<Thread>,
    pub root: Option<Thread>,
    pub pending: usize,
    pub handles: Vec<HandleReport>,
    pub scope: &'static str,
}

pub(crate) fn report(engine: &Unicorn<Trace>) -> Option<Report> {
    let state = &engine.get_data().user_threads;
    (state.root.is_some() || !state.records.is_empty()).then(|| Report {
        root: state.root.clone(), current: current_id(engine), threads: state.records.values().cloned().collect(), pending: state.pending.len(),
        handles: state.handles.iter().map(|(handle,h)| HandleReport { handle: *handle, thread: state.record(h.canonical).unwrap().id, access: h.access, flags: h.flags }).collect(),
        scope: "Deterministic guest-only user thread contexts with owned stack/TEB/static TLS/LastError, round-robin instruction slices, process-owned handles, virtual waits and shared execution horizons.",
    })
}
pub(crate) fn current_id(engine: &Unicorn<Trace>) -> u64 {
    engine.get_data().user_threads.current.max(1)
}
pub(crate) fn queued(engine: &Unicorn<Trace>) -> bool {
    engine.get_data().user_threads.action
}
pub(crate) fn active(engine: &Unicorn<Trace>) -> bool {
    !engine.get_data().user_threads.records.is_empty()
}
pub(crate) fn exiting(engine: &Unicorn<Trace>) -> bool {
    engine.get_data().user_threads.exit.is_some()
}
fn sp_register(architecture: Architecture) -> RegisterX86 {
    if architecture == Architecture::X64 {
        RegisterX86::RSP
    } else {
        RegisterX86::ESP
    }
}
fn failure(engine: &mut Unicorn<Trace>, error: u32, result: u64) -> u64 {
    engine.get_data_mut().apis.last_error = error;
    result
}
pub(crate) fn query_id(engine: &Unicorn<Trace>, handle: u64) -> std::result::Result<u64, u32> {
    authority::resolve(engine, handle, 0x800)
        .or_else(|_| authority::resolve(engine, handle, 0x40))
        .map(|h| engine.get_data().user_threads.record(h).unwrap().id)
}
pub(crate) fn wait_access(
    engine: &Unicorn<Trace>,
    handles: &[u64],
) -> std::result::Result<(), u32> {
    user_processes::wait_access(engine, handles)?;
    let mut identities = std::collections::BTreeSet::new();
    for handle in handles {
        if engine.get_data().user_threads.handles.contains_key(handle) {
            let canonical = authority::resolve(engine, *handle, 0x100000)?;
            if !identities.insert(canonical) {
                return Err(87);
            }
        }
    }
    Ok(())
}
pub(crate) fn close(engine: &mut Unicorn<Trace>, handle: u64) -> Option<u64> {
    let entry = engine.get_data().user_threads.handles.get(&handle)?;
    if entry.flags & 2 != 0 {
        return Some(failure(engine, 5, 0));
    }
    let canonical = entry.canonical;
    engine.get_data_mut().user_threads.handles.remove(&handle);
    if handle == canonical {
        engine
            .get_data_mut()
            .user_threads
            .record_mut(canonical)
            .unwrap()
            .handle_closed = true;
    }
    Some(1)
}
fn queue(engine: &mut Unicorn<Trace>, handle: u64, result: u64, argc: usize) -> Result<()> {
    ensure!(
        engine.get_data().user_threads.pending.len() < MAX_THREADS + 1,
        "User-thread pending-call count exceeds its bound"
    );
    let architecture = engine.get_data().architecture;
    let sp = uc(engine.reg_read(sp_register(architecture)))?;
    ensure!(
        architecture != Architecture::X64 || sp % 16 == 8,
        "User thread API has a misaligned Win64 caller"
    );
    let pending = Pending {
        handle,
        result,
        pc: uc(engine.pc_read())?,
        sp,
        frame: read(
            engine,
            sp,
            if architecture == Architecture::X64 {
                40
            } else {
                (argc as u64 + 1) * 4
            },
        )?,
        event: engine.get_data().apis.next_event_index(),
        last_error: None,
    };
    let id = current_id(engine);
    ensure!(
        !engine.get_data().user_threads.pending.contains_key(&id),
        "User thread already owns a pending API continuation"
    );
    engine
        .get_data_mut()
        .user_threads
        .pending
        .insert(id, pending);
    engine.get_data_mut().user_threads.action = true;
    Ok(())
}
pub(super) fn invoke(engine: &mut Unicorn<Trace>, call: Call, args: &[u64]) -> Result<u64> {
    ensure!(
        engine.get_data().apis.user_bootstrap.is_some() && engine.get_data().threads.is_none(),
        "User thread lifecycle requires the submitted-user process authority"
    );
    initialize_root(engine)?;
    if let Call::Authority(call) = call {
        return authority::invoke(engine, call, args);
    }
    let access = match call {
        Call::Suspend | Call::Resume => 2,
        Call::Terminate => 1,
        Call::ExitCode => 0x40,
        Call::Apc => 0x10,
        _ => 0,
    };
    let mut resolved = args.to_vec();
    if access != 0 {
        let index = if matches!(call, Call::Apc) { 1 } else { 0 };
        let pseudo = if engine.get_data().architecture == Architecture::X64 {
            u64::MAX - 1
        } else {
            u32::MAX as u64 - 1
        };
        let root_pseudo = current_id(engine) == 1
            && args[index] == pseudo
            && matches!(call, Call::Terminate | Call::Apc);
        match if root_pseudo {
            Ok(args[index])
        } else {
            authority::resolve(engine, args[index], access)
        } {
            Ok(handle) => resolved[index] = handle,
            Err(error) => {
                return Ok(failure(
                    engine,
                    error,
                    if matches!(call, Call::Suspend | Call::Resume) {
                        u32::MAX as u64
                    } else {
                        0
                    },
                ));
            }
        }
    }
    let args = resolved.as_slice();
    match call {
        Call::Begin(extended) => {
            if extended {
                create(engine, args, 6, false, false)
            } else {
                create(engine, &[0, args[1], args[0], args[2], 0, 0], 3, true, true)
            }
        }
        Call::End(extended) => invoke(engine, Call::Exit, &[if extended { args[0] } else { 0 }]),
        Call::Apc => {
            if require(engine, args[0], 1, P::EXECUTE).is_err() {
                return Ok(failure(engine, 998, 0));
            }
            let pseudo = if engine.get_data().architecture == Architecture::X64 {
                u64::MAX - 1
            } else {
                u32::MAX as u64 - 1
            };
            let id = if args[1] == pseudo {
                current_id(engine)
            } else if let Some(thread) = engine.get_data().user_threads.record(args[1]) {
                thread.id
            } else {
                return Ok(failure(engine, 6, 0));
            };
            if engine
                .get_data()
                .user_threads
                .records
                .values()
                .any(|t| t.id == id && t.exit_code.is_some())
            {
                return Ok(failure(engine, 31, 0));
            }
            Ok(if scheduling::queue_apc(engine, id, args[0], args[2]) {
                1
            } else {
                failure(engine, 8, 0)
            })
        }
        Call::Yield => {
            queue(engine, 0, 1, 0)?;
            Ok(0)
        }
        Call::Suspend => {
            if engine.get_data().user_threads.record(args[0]).is_none() {
                return Ok(failure(engine, 6, u32::MAX as u64));
            }
            let record = engine
                .get_data_mut()
                .user_threads
                .record_mut(args[0])
                .unwrap();
            if record.exit_code.is_some() {
                return Ok(failure(engine, 5, u32::MAX as u64));
            }
            let previous = record.suspended;
            if previous >= 127 {
                return Ok(failure(engine, 298, u32::MAX as u64));
            }
            record.suspended += 1;
            if record.id == current_id(engine) {
                queue(engine, 0, previous as u64, 1)?;
                return Ok(0);
            }
            Ok(previous as u64)
        }
        Call::Create => create(engine, args, 6, false, false),
        Call::Resume => {
            if engine.get_data().user_threads.record(args[0]).is_none() {
                return Ok(failure(engine, 6, u32::MAX as u64));
            }
            if engine.get_data().loader_active {
                return Ok(failure(engine, 50, u32::MAX as u64));
            }
            let thread = engine.get_data().user_threads.record(args[0]).unwrap();
            if thread.state == "created"
                && thread.stack == 0
                && thread.suspended == 1
                && user_loader::preflight_thread(engine, thread.stack_size).is_err()
            {
                return Ok(failure(engine, 8, u32::MAX as u64));
            }
            let thread = engine
                .get_data_mut()
                .user_threads
                .record_mut(args[0])
                .unwrap();
            if thread.exit_code.is_some() {
                return Ok(failure(engine, 5, u32::MAX as u64));
            }
            let previous = thread.suspended;
            if previous != 0 {
                thread.suspended -= 1;
            }
            if previous == 1 && thread.state == "created" {
                queue(engine, args[0], previous as u64, 1)?;
                return Ok(0);
            }
            Ok(previous as u64)
        }
        Call::Exit => {
            ensure!(
                !engine.get_data().loader_active,
                "ExitThread during a loader notification cannot resume safely"
            );
            engine.get_data_mut().user_threads.exit = Some((args[0] as u32, false));
            engine.get_data_mut().user_threads.action = true;
            uc(engine.emu_stop())?;
            Ok(0)
        }
        Call::Terminate => {
            let pseudo = if engine.get_data().architecture == Architecture::X64 {
                u64::MAX - 1
            } else {
                u32::MAX as u64 - 1
            };
            let current = current_id(engine);
            let id = if args[0] == pseudo {
                current
            } else if engine.get_data().user_threads.record(args[0]).is_some() {
                engine.get_data().user_threads.record(args[0]).unwrap().id
            } else {
                return Ok(failure(engine, 6, 0));
            };
            if id == current {
                ensure!(
                    !engine.get_data().loader_active,
                    "TerminateThread during a loader notification cannot resume safely"
                );
                engine.get_data_mut().user_threads.exit = Some((args[1] as u32, true));
                engine.get_data_mut().user_threads.action = true;
                uc(engine.emu_stop())?;
            } else {
                scheduling::terminate_other(engine, id, args[1] as u32)?;
            }
            Ok(1)
        }
        Call::Authority(_) => unreachable!(),
        Call::ExitCode => {
            if engine.get_data().user_threads.record(args[0]).is_none() {
                return Ok(failure(engine, 6, 0));
            }
            if require(engine, args[1], 4, P::WRITE).is_err() {
                return Ok(failure(engine, 998, 0));
            }
            let value = engine
                .get_data()
                .user_threads
                .record(args[0])
                .unwrap()
                .exit_code
                .unwrap_or(259);
            crate::cpu::write(engine, args[1], &value.to_le_bytes())?;
            Ok(1)
        }
    }
}

pub(crate) fn transition(
    engine: &mut Unicorn<Trace>,
    horizon: &ExecutionHorizon,
) -> Result<Option<Outcome>> {
    scheduling::pump(engine, horizon, None)
}

pub(crate) fn cleanup_process(engine: &mut Unicorn<Trace>, forced: bool) -> Result<()> {
    let exit_code = engine.get_data().process_exit_code;
    let mut callback_threads = engine.get_data().apis.user_callbacks.thread_ids();
    callback_threads.push(1);
    callback_threads.extend(
        engine
            .get_data()
            .user_threads
            .records
            .values()
            .map(|t| t.id),
    );
    callback_threads.sort_unstable();
    callback_threads.dedup();
    for id in callback_threads {
        user_callbacks::cancel(engine, id, "aborted_by_process_exit");
    }
    let records = engine
        .get_data()
        .user_threads
        .records
        .values()
        .cloned()
        .collect::<Vec<_>>();
    for thread in records {
        if !thread.backing_released {
            if thread.teb != 0 {
                user_loader::release(engine, thread.teb)?;
            }
            if thread.stack != 0 {
                user_loader::release(engine, thread.stack)?;
            }
        }
        user_runtime::retire_thread(engine, thread.id);
        let record = engine
            .get_data_mut()
            .user_threads
            .records
            .get_mut(&thread.handle)
            .unwrap();
        record.backing_released = true;
        record.handle_closed = true;
        if record.exit_code.is_none() {
            record.state = if forced {
                "process_terminated"
            } else {
                "process_exit"
            };
            record.exit_code = exit_code;
        }
    }
    if let Some(root) = engine.get_data_mut().user_threads.root.as_mut()
        && root.exit_code.is_none()
    {
        root.exit_code = exit_code;
        root.state = if forced {
            "process_terminated"
        } else {
            "process_exit"
        };
    }
    let pending = std::mem::take(&mut engine.get_data_mut().user_threads.pending);
    for caller in pending.into_values() {
        if let Some(index) = caller.event
            && let Some(event) = engine.get_data_mut().apis.events.get_mut(index)
        {
            event.pending = false;
            event.effect = Some("aborted_by_process_exit");
        }
    }
    user_runtime::retire_thread(engine, 1);
    engine.get_data_mut().user_threads.handles.clear();
    engine.get_data_mut().user_threads.scheduler = scheduling::State::default();
    engine.get_data_mut().user_threads.exit = None;
    engine.get_data_mut().user_threads.action = false;

    Ok(())
}

pub(crate) fn resume_api(engine: &mut Unicorn<Trace>, pc: u64) -> Result<bool> {
    let id = current_id(engine);
    if !engine
        .get_data_mut()
        .user_threads
        .scheduler
        .ready
        .remove(&id)
    {
        return Ok(false);
    }
    let pending = engine
        .get_data_mut()
        .user_threads
        .pending
        .remove(&id)
        .context("User wait caller absent")?;
    ensure!(
        pc == pending.pc
            && uc(engine.reg_read(sp_register(engine.get_data().architecture)))? == pending.sp
            && read(engine, pending.sp, pending.frame.len() as u64)? == pending.frame,
        "User thread continuation changed its suspended caller frame"
    );
    uc(engine.reg_write(
        if engine.get_data().architecture == Architecture::X64 {
            RegisterX86::RAX
        } else {
            RegisterX86::EAX
        },
        pending.result,
    ))?;
    if let Some(error) = pending.last_error {
        engine.get_data_mut().apis.last_error = error;
    }
    let last_error = engine.get_data().apis.last_error;
    if let Some(index) = pending.event
        && let Some(event) = engine.get_data_mut().apis.events.get_mut(index)
    {
        ensure!(event.pending, "User thread API event already completed");
        event.result = Some(pending.result);
        event.pending = false;
        event.last_error = last_error;
        event.effect = Some("user_thread_return_ready");
    }
    Ok(true)
}

fn create(
    engine: &mut Unicorn<Trace>,
    args: &[u64],
    argc: usize,
    cdecl_start: bool,
    auto_close: bool,
) -> Result<u64> {
    if engine.get_data().loader_active {
        return Ok(failure(engine, 50, 0));
    }
    let inherit = match user_sync::security_attributes(engine, args[0]) {
        Ok(v) => v,
        Err(e) => return Ok(failure(engine, e, 0)),
    };
    if args[4] & !0x10004 != 0 || args[1] > 16 * 1024 * 1024 {
        return Ok(failure(engine, 87, 0));
    }
    if require(engine, args[2], 1, P::EXECUTE).is_err() {
        return Ok(failure(engine, 998, 0));
    }
    if args[5] != 0 && require(engine, args[5], 4, P::WRITE).is_err() {
        return Ok(failure(engine, 998, 0));
    }
    let count = engine.get_data().user_threads.records.len();
    if count >= MAX_THREADS || !user_processes::thread_admission(engine) {
        return Ok(failure(engine, 8, 0));
    }
    let stack_size = if args[1] == 0 {
        1024 * 1024
    } else {
        args[1].max(65536).div_ceil(4096) * 4096
    };
    if user_loader::preflight_thread(engine, stack_size).is_err() {
        return Ok(failure(engine, 8, 0));
    }
    let id = count as u64 + 2;
    let public_id = user_processes::tid(user_processes::pid(engine), id);
    let handle = 0x6f000000 + public_id * 4;
    if args[5] != 0 {
        crate::cpu::write(engine, args[5], &(public_id as u32).to_le_bytes())?;
    }
    let thread = Thread {
        id,
        handle,
        entry: args[2],
        parameter: args[3],
        stack_size,
        stack: 0,
        teb: 0,
        suspended: u32::from(args[4] & 4 != 0),
        state: "created",
        exit_code: None,
        handle_closed: false,
        backing_released: false,
        cdecl_start,
        auto_close,
    };
    engine
        .get_data_mut()
        .user_threads
        .records
        .insert(handle, thread);
    engine.get_data_mut().user_threads.handles.insert(
        handle,
        authority::Handle {
            canonical: handle,
            access: authority::ALL,
            flags: u32::from(inherit),
        },
    );
    engine.get_data_mut().apis.last_error = 0;
    if args[4] & 4 == 0 {
        queue(engine, handle, handle, argc)?;
        return Ok(0);
    }
    Ok(handle)
}

pub(crate) fn retirement_complete(engine: &mut Unicorn<Trace>, id: u64, code: u32) {
    scheduling::retirement_complete(engine, id, code);
}

pub(crate) fn queue_process_api(engine: &mut Unicorn<Trace>, argc: usize) -> Result<()> {
    initialize_root(engine)?;
    queue(engine, 0, 0, argc)
}
pub(crate) fn complete_process_api(
    engine: &mut Unicorn<Trace>,
    result: u64,
    error: u32,
) -> Result<()> {
    let id = current_id(engine);
    let pending = engine
        .get_data_mut()
        .user_threads
        .pending
        .get_mut(&id)
        .context("Process API continuation missing")?;
    pending.result = result;
    pending.last_error = Some(error);
    engine.get_data_mut().user_threads.action = true;
    Ok(())
}
pub(crate) fn process_thread(trace: &Trace, id: u64) -> Option<&Thread> {
    trace.user_threads.by_id(id)
}
pub(crate) fn process_thread_count(trace: &Trace) -> usize {
    1 + trace.user_threads.records.len()
}
pub(crate) fn process_suspended(trace: &Trace) -> bool {
    trace
        .user_threads
        .root
        .as_ref()
        .is_some_and(|t| t.suspended != 0)
        && trace
            .user_threads
            .records
            .values()
            .all(|t| t.suspended != 0 || t.exit_code.is_some())
}
pub(crate) fn process_waiting(trace: &Trace) -> bool {
    trace.user_threads.scheduler.has_waits()
}
pub(crate) fn process_deadline(trace: &Trace) -> Option<u64> {
    trace.user_threads.scheduler.deadline()
}
pub(crate) fn set_primary_suspended(engine: &mut Unicorn<Trace>, suspended: bool) -> Result<()> {
    initialize_root(engine)?;
    engine
        .get_data_mut()
        .user_threads
        .root
        .as_mut()
        .unwrap()
        .suspended = u32::from(suspended);
    Ok(())
}
pub(crate) fn process_handle(trace: &Trace, handle: u64) -> Option<(u64, u32, u32)> {
    let h = trace.user_threads.handles.get(&handle)?;
    Some((
        trace.user_threads.record(h.canonical)?.id,
        h.access,
        h.flags,
    ))
}
pub(crate) fn inheritable_handles(trace: &Trace) -> Vec<HandleReport> {
    trace
        .user_threads
        .handles
        .iter()
        .filter(|(_, handle)| handle.flags & 1 != 0)
        .map(|(value, handle)| HandleReport {
            handle: *value,
            thread: trace.user_threads.record(handle.canonical).unwrap().id,
            access: handle.access,
            flags: handle.flags,
        })
        .collect()
}
pub(crate) fn inherit_alias_namespace(parent: &Trace, child: &mut Trace) {
    child.user_threads.next_handle = parent.user_threads.next_handle;
}
pub(crate) fn close_process_handle(trace: &mut Trace, value: u64) -> std::result::Result<(), u32> {
    let handle = *trace.user_threads.handles.get(&value).ok_or(6u32)?;
    if handle.flags & 2 != 0 {
        return Err(5);
    }
    trace.user_threads.handles.remove(&value);
    if value == handle.canonical {
        trace
            .user_threads
            .record_mut(handle.canonical)
            .ok_or(6u32)?
            .handle_closed = true;
    }
    Ok(())
}
pub(crate) fn remote_suspend(engine: &mut Unicorn<Trace>, id: u64, suspend: bool) -> Result<u64> {
    let handle = engine
        .get_data()
        .user_threads
        .by_id(id)
        .context("Remote thread absent")?
        .handle;
    let thread = engine
        .get_data_mut()
        .user_threads
        .record_mut(handle)
        .unwrap();
    if thread.exit_code.is_some() {
        return Ok(failure(engine, 5, u32::MAX as u64));
    }
    let previous = thread.suspended;
    if suspend {
        if previous >= 127 {
            return Ok(failure(engine, 298, u32::MAX as u64));
        }
        thread.suspended += 1;
    } else {
        thread.suspended = previous.saturating_sub(1);
    }
    schedule(engine);
    Ok(previous as u64)
}
pub(crate) fn remote_terminate(engine: &mut Unicorn<Trace>, id: u64, code: u32) -> Result<u64> {
    if id == current_id(engine) {
        engine.get_data_mut().user_threads.exit = Some((code, true));
    } else {
        scheduling::terminate_other(engine, id, code)?;
    }
    schedule(engine);
    Ok(1)
}
pub(crate) fn remote_create(
    engine: &mut Unicorn<Trace>,
    stack: u64,
    entry: u64,
    parameter: u64,
    flags: u64,
) -> Result<u64> {
    initialize_root(engine)?;
    let handle = create(
        engine,
        &[0, stack, entry, parameter, flags | 4, 0],
        6,
        false,
        false,
    )?;
    if handle == 0 {
        return Ok(0);
    }
    let record = engine
        .get_data_mut()
        .user_threads
        .records
        .get_mut(&handle)
        .unwrap();
    record.suspended = u32::from(flags & 4 != 0);
    let id = record.id;
    schedule(engine);
    Ok(id)
}
pub(crate) fn remote_context(
    engine: &mut Unicorn<Trace>,
    id: u64,
    buffer: u64,
    set: bool,
) -> Result<u64> {
    let handle = engine
        .get_data()
        .user_threads
        .by_id(id)
        .context("Remote context thread absent")?
        .handle;
    let previous = engine.get_data_mut().user_threads.handles.insert(
        handle,
        authority::Handle {
            canonical: handle,
            access: authority::ALL,
            flags: 0,
        },
    );
    let result = scheduling::remote_context(engine, id, handle, buffer, set);
    if let Some(previous) = previous {
        engine
            .get_data_mut()
            .user_threads
            .handles
            .insert(handle, previous);
    } else {
        engine.get_data_mut().user_threads.handles.remove(&handle);
    }
    result
}

pub(super) fn detach_apc_wait(engine: &mut Unicorn<Trace>) -> Result<Pending> {
    scheduling::detach_apc_wait(engine)
}
pub(super) fn restore_apc_wait(engine: &mut Unicorn<Trace>, pending: Pending) -> Result<()> {
    scheduling::restore_apc_wait(engine, pending)
}

pub(super) fn abort_pending(engine: &mut Unicorn<Trace>, pending: Pending, reason: &'static str) {
    if let Some(index) = pending.event
        && let Some(event) = engine.get_data_mut().apis.events.get_mut(index)
    {
        event.pending = false;
        event.error = Some(reason.into());
        event.effect = Some(reason);
    }
}

pub(crate) use exception_context::{capture as capture_context, restore as restore_context};

pub(crate) fn stack_bounds(engine: &Unicorn<Trace>) -> Result<(u64, u64)> {
    let id = current_id(engine);
    if id == 1 {
        let bootstrap = user_bootstrap::report(engine).context("User root stack missing")?;
        Ok((bootstrap.stack_limit, bootstrap.stack_base))
    } else {
        let thread = engine
            .get_data()
            .user_threads
            .by_id(id)
            .context("User thread stack missing")?;
        Ok((thread.stack, thread.stack + thread.stack_size))
    }
}

pub(crate) fn schedule(engine: &mut Unicorn<Trace>) {
    engine.get_data_mut().user_threads.action = true;
}
pub(crate) fn notification_complete(engine: &mut Unicorn<Trace>, id: u64, code: u32) {
    scheduling::notification_complete(engine, id, code);
}

pub(crate) fn prepare_process_exit(engine: &mut Unicorn<Trace>, code: u32) -> Result<()> {
    let current = current_id(engine);
    if current != 1
        && engine
            .get_data()
            .user_threads
            .root
            .as_ref()
            .is_some_and(|root| root.exit_code.is_none())
    {
        scheduling::terminate_other(engine, 1, code)?;
    }
    let others = engine
        .get_data()
        .user_threads
        .records
        .values()
        .filter(|thread| thread.id != current && thread.exit_code.is_none())
        .map(|thread| thread.id)
        .collect::<Vec<_>>();
    for id in others {
        scheduling::terminate_other(engine, id, code)?;
    }
    Ok(())
}
