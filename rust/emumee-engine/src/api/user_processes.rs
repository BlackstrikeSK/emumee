//! Isolated guest processes multiplexed on the single stopped native CPU.
use super::*;
use crate::threads::{ExecutionHorizon, Outcome};
use anyhow::Context as _;
use emumee_core::user_input::MAX_MAPPED_TOTAL;
mod handles;
mod preparation;
mod remote;

pub(crate) const ROOT: u64 = 1024;
const MAX_CHILDREN: usize = 32;
const PROCESS_ALL: u32 = 0x1fffff;
const THREAD_ALL: u32 = 0x1fffff;
const SYNCHRONIZE: u32 = 0x100000;

#[derive(Clone, Copy)]
pub(super) enum Call {
    Create(bool),
    CreateInternal(bool),
    WinExec,
    Open,
    Pid,
    Id,
    ThreadId,
    ThreadProcessId,
    ExitCode,
    Terminate,
    Debugger,
    Memory(bool),
    Virtual(u8),
    RemoteThread,
    Thread(user_threads::Call),
    OpenThread,
    QueryThreadId,
    Duplicate,
    Flags(bool),
    NtQuery,
}
pub(super) fn definition(module: &str, name: &str) -> Option<(Call, usize, T)> {
    if module == "ntdll"
        && matches!(
            name,
            "NtQueryInformationProcess" | "ZwQueryInformationProcess"
        )
    {
        return Some((Call::NtQuery, 5, T::U32));
    }
    if !matches!(module, "kernel32" | "kernelbase") && !module.starts_with("api-ms-win-core-") {
        return None;
    }
    Some(match name {
        "CreateProcessA" => (Call::Create(false), 10, T::U32),
        "CreateProcessW" => (Call::Create(true), 10, T::U32),
        "CreateProcessInternalA" => (Call::CreateInternal(false), 12, T::U32),
        "CreateProcessInternalW" => (Call::CreateInternal(true), 12, T::U32),
        "WinExec" => (Call::WinExec, 2, T::U32),
        "OpenProcess" => (Call::Open, 3, T::Pointer),
        "GetCurrentProcessId" => (Call::Pid, 0, T::U32),
        "GetCurrentThreadId" => (Call::ThreadId, 0, T::U32),
        "GetProcessId" => (Call::Id, 1, T::U32),
        "GetProcessIdOfThread" => (Call::ThreadProcessId, 1, T::U32),
        "GetThreadId" => (Call::QueryThreadId, 1, T::U32),
        "GetExitCodeProcess" => (Call::ExitCode, 2, T::U32),
        "TerminateProcess" => (Call::Terminate, 2, T::U32),
        "CheckRemoteDebuggerPresent" => (Call::Debugger, 2, T::U32),
        "ReadProcessMemory" => (Call::Memory(false), 5, T::U32),
        "WriteProcessMemory" => (Call::Memory(true), 5, T::U32),
        "VirtualAllocEx" => (Call::Virtual(0), 5, T::Pointer),
        "VirtualFreeEx" => (Call::Virtual(1), 4, T::U32),
        "VirtualProtectEx" => (Call::Virtual(2), 5, T::U32),
        "VirtualQueryEx" => (Call::Virtual(3), 4, T::Pointer),
        "CreateRemoteThread" => (Call::RemoteThread, 7, T::Pointer),
        "OpenThread" => (Call::OpenThread, 3, T::Pointer),
        "DuplicateHandle" => (Call::Duplicate, 7, T::U32),
        "GetHandleInformation" => (Call::Flags(false), 2, T::U32),
        "SetHandleInformation" => (Call::Flags(true), 3, T::U32),
        "ResumeThread" | "SuspendThread" | "TerminateThread" | "GetExitCodeThread"
        | "GetThreadContext" | "SetThreadContext" | "QueueUserAPC" => {
            let (call, count, result) = user_threads::definition(module, name)?;
            (Call::Thread(call), count, result)
        }
        _ => return None,
    })
}

pub(crate) struct Local {
    pub(crate) id: u64,
    idle: bool,
    quantum_end: u64,
    yielded: bool,
    startup: Option<preparation::Startup>,
}
impl Default for Local {
    fn default() -> Self {
        Self {
            id: ROOT,
            idle: false,
            quantum_end: u64::MAX,
            yielded: false,
            startup: None,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Target {
    Process(u64),
    Thread(u64, u64),
}
#[derive(Clone, Copy)]
struct Handle {
    target: Target,
    access: u32,
    flags: u32,
}
#[derive(Clone, Debug, Serialize)]
pub struct ProcessReport {
    pub id: u64,
    pub parent: u64,
    pub image: String,
    pub exit_code: Option<u32>,
    pub failure: Option<String>,
    pub failure_kind: Option<&'static str>,
    pub peb: u64,
    pub backing_released: bool,
}
struct Page {
    base: u64,
    bytes: Vec<u8>,
    permissions: Prot,
}
struct Snapshot {
    trace: Box<Trace>,
    cpu: unicorn_engine::Context,
    pages: Vec<Page>,
}
#[derive(Default)]
pub(crate) struct State {
    pub(crate) running: bool,
    parked: BTreeMap<u64, Snapshot>,
    records: BTreeMap<u64, ProcessReport>,
    handles: BTreeMap<(u64, u64), Handle>,
    next_handle: u64,
    request: Option<(Call, Vec<u64>)>,
    root_outcome: Option<Outcome>,
}
pub(crate) fn pid(engine: &Unicorn<Trace>) -> u64 {
    engine.get_data().process.id
}
pub(crate) fn thread_admission(engine: &Unicorn<Trace>) -> bool {
    user_threads::process_thread_count(engine.get_data())
        + engine
            .get_data()
            .processes
            .parked
            .values()
            .map(|s| user_threads::process_thread_count(&s.trace))
            .sum::<usize>()
        < 256
}
pub(crate) fn tid(process: u64, local: u64) -> u64 {
    if process == ROOT {
        local
    } else {
        (process - ROOT) * 0x10000 + local
    }
}
pub(crate) fn report(engine: &Unicorn<Trace>) -> Vec<ProcessReport> {
    engine
        .get_data()
        .processes
        .records
        .values()
        .cloned()
        .collect()
}
fn failure(engine: &mut Unicorn<Trace>, error: u32) -> u64 {
    engine.get_data_mut().apis.last_error = error;
    0
}
fn empty_outcome() -> Outcome {
    Outcome {
        returned: false,
        value: None,
        error: None,
    }
}
fn mapped(trace: &Trace) -> u64 {
    trace.apis.memory.regions().map(|r| r.size).sum()
}
fn allowance(engine: &mut Unicorn<Trace>) -> Result<()> {
    let inactive: u64 = engine
        .get_data()
        .processes
        .parked
        .values()
        .map(|s| mapped(&s.trace))
        .sum();
    engine.get_data_mut().apis.memory.aggregate_allowance(
        MAX_MAPPED_TOTAL
            .checked_sub(inactive)
            .context("Aggregate process mappings exhausted")?,
    )?;
    Ok(())
}
fn shared(source: &mut Trace, destination: &mut Trace) {
    destination.instructions = source.instructions;
    destination.entries = source.entries;
    destination.clock = source.clock.clone();
    destination.clock_error = source.clock_error;
    destination.cpu.processor = source.cpu.processor;
    destination.cpu.tsc_offset = source.cpu.tsc_offset;
    destination.cpu.tsc_adjust = source.cpu.tsc_adjust;
    destination.apis.user_callbacks.calls = source.apis.user_callbacks.calls;
    destination.maximum_continuation_depth = destination
        .maximum_continuation_depth
        .max(source.maximum_continuation_depth);
    destination.apis.calls = source.apis.calls;
    destination.apis.events = std::mem::take(&mut source.apis.events);
    destination.apis.captures = std::mem::take(&mut source.apis.captures);
}
fn exchange(engine: &mut Unicorn<Trace>, mut destination: Snapshot) -> Result<Snapshot> {
    user_bootstrap::before_instruction(engine)?;
    engine.get_data_mut().clock.flush_cycles()?;
    let cpu = uc(engine.context_init())?;
    let regions = uc(engine.mem_regions())?;
    ensure!(
        regions.iter().map(|r| r.end - r.begin + 1).sum::<u64>() <= MAX_MAPPED_TOTAL,
        "Native process snapshot exceeds aggregate bound"
    );
    let mut pages = Vec::with_capacity(regions.len());
    for region in &regions {
        pages.push(Page {
            base: region.begin,
            bytes: uc(
                engine.mem_read_as_vec(region.begin, (region.end - region.begin + 1) as usize)
            )?,
            permissions: if region.perms == 0 {
                Prot::NONE
            } else {
                (if region.perms & 1 != 0 {
                    Prot::READ
                } else {
                    Prot::NONE
                }) | (if region.perms & 2 != 0 {
                    Prot::WRITE
                } else {
                    Prot::NONE
                }) | (if region.perms & 4 != 0 {
                    Prot::EXEC
                } else {
                    Prot::NONE
                })
            },
        });
    }
    for region in regions {
        uc(engine.ctl_remove_cache(region.begin, region.end + 1))?;
        uc(engine.mem_unmap(region.begin, region.end - region.begin + 1))?;
    }
    let world = std::mem::take(&mut engine.get_data_mut().processes);
    shared(engine.get_data_mut(), &mut destination.trace);
    let old = std::mem::replace(engine.get_data_mut(), *destination.trace);
    engine.get_data_mut().processes = world;
    for page in destination.pages {
        if engine.get_data().clock_aliases.contains(&page.base) && page.bytes.len() == 4096 {
            crate::time::remap(engine, page.base)?;
        } else {
            uc(engine.mem_map(page.base, page.bytes.len() as u64, page.permissions))?;
            uc(engine.mem_write(page.base, &page.bytes))?;
        }
    }
    uc(engine.context_restore(&destination.cpu))?;
    if engine.get_data().clock_page.is_some() {
        crate::time::sync(engine)?;
    }
    Ok(Snapshot {
        trace: Box::new(old),
        cpu,
        pages,
    })
}
fn switch(engine: &mut Unicorn<Trace>, target: u64) -> Result<()> {
    if target == pid(engine) {
        return Ok(());
    }
    let old = pid(engine);
    let destination = engine
        .get_data_mut()
        .processes
        .parked
        .remove(&target)
        .context("Inactive process snapshot absent")?;
    let source = exchange(engine, destination)?;
    if old != ROOT
        && engine
            .get_data()
            .processes
            .records
            .get(&old)
            .is_some_and(|record| record.exit_code.is_some())
    {
        engine
            .get_data_mut()
            .processes
            .records
            .get_mut(&old)
            .unwrap()
            .backing_released = true;
        drop(source);
    } else {
        engine.get_data_mut().processes.parked.insert(old, source);
    }
    allowance(engine)
}
pub(crate) fn yield_requested(engine: &mut Unicorn<Trace>) -> bool {
    let trace = engine.get_data_mut();
    if trace.processes.running
        && trace.continuation_depth == 1
        && (trace.processes.request.is_some()
            || trace.process.idle
            || trace.instructions >= trace.process.quantum_end)
    {
        trace.process.yielded = true;
        true
    } else {
        false
    }
}
pub(crate) fn idle(engine: &mut Unicorn<Trace>) -> bool {
    if !engine.get_data().processes.running {
        return false;
    }
    engine.get_data_mut().process.idle = true;
    true
}
pub(crate) fn drive(
    engine: &mut Unicorn<Trace>,
    entry: u64,
    marker: u64,
    horizon: &ExecutionHorizon,
) -> Result<Outcome> {
    user_threads::initialize_root(engine)?;
    user_threads::begin_entry(engine);
    let image = engine.get_data().apis.persona.model.argv(ROOT)?[0].clone();
    let peb = user_bootstrap::report(engine)
        .context("Root process PEB absent")?
        .peb;
    engine
        .get_data_mut()
        .processes
        .records
        .entry(ROOT)
        .or_insert(ProcessReport {
            id: ROOT,
            parent: 0,
            image,
            exit_code: None,
            failure: None,
            failure_kind: None,
            peb,
            backing_released: false,
        });
    engine.get_data_mut().processes.running = true;
    uc(engine.reg_write(
        crate::threads::pc_register(engine.get_data().architecture),
        entry,
    ))?;
    let result = drive_inner(engine, marker, horizon);
    let restored = switch(engine, ROOT);
    engine.get_data_mut().processes.running = false;
    restored?;
    result
}
fn drive_inner(
    engine: &mut Unicorn<Trace>,
    marker: u64,
    horizon: &ExecutionHorizon,
) -> Result<Outcome> {
    let mut visited_idle = 0;
    loop {
        if horizon.expired(engine.get_data().instructions) {
            return Ok(empty_outcome());
        }
        if let Some((call, args)) = engine.get_data_mut().processes.request.take() {
            let result = remote::dispatch(engine, call, &args, horizon)?;
            let error = engine.get_data().apis.last_error;
            user_threads::complete_process_api(engine, result, error)?;
        }
        if engine.get_data().process.startup.is_some()
            && !user_threads::process_suspended(engine.get_data())
        {
            let startup = engine.get_data_mut().process.startup.take().unwrap();
            let outcome = native_loader::execute_startup(
                engine,
                startup.loader,
                &startup.image,
                crate::STACK + crate::STACK_SIZE - 0x200,
                horizon,
                false,
            )?;
            if !outcome.returned {
                if horizon.expired(engine.get_data().instructions) {
                    return Ok(outcome);
                }
                finish(engine, outcome, horizon)?;
            }
        }
        let current = pid(engine);
        let live = engine
            .get_data()
            .processes
            .records
            .get(&current)
            .is_some_and(|r| r.exit_code.is_none());
        let suspended = user_threads::process_suspended(engine.get_data());
        if live && !suspended {
            engine.get_data_mut().process.idle = false;
            if user_threads::queued(engine) || user_threads::process_waiting(engine.get_data()) {
                if let Some(outcome) = user_threads::transition(engine, horizon)? {
                    finish(engine, outcome, horizon)?;
                }
            }
            if !engine.get_data().process.idle
                && engine.get_data().processes.records[&current]
                    .exit_code
                    .is_none()
            {
                engine.get_data_mut().process.yielded = false;
                engine.get_data_mut().process.quantum_end =
                    engine.get_data().instructions.saturating_add(4096);
                let pc = uc(engine.pc_read())?;
                let marker = if current == ROOT {
                    marker
                } else {
                    engine.get_data().return_marker
                };
                let outcome = crate::threads::execute_horizon_inner(engine, pc, marker, horizon)?;
                if engine.get_data().processes.request.is_some() {
                    continue;
                }
                if !engine.get_data().process.yielded {
                    if horizon.expired(engine.get_data().instructions) {
                        return Ok(outcome);
                    }
                    finish(engine, outcome, horizon)?;
                }
                visited_idle = 0;
            } else {
                visited_idle += 1;
            }
        } else {
            visited_idle += 1;
        }
        let quiescent_root = engine.get_data().processes.root_outcome.is_some();
        let live: Vec<u64> = engine
            .get_data()
            .processes
            .records
            .values()
            .filter(|r| r.exit_code.is_none() && !(r.id == ROOT && quiescent_root))
            .map(|r| r.id)
            .collect();
        if live.is_empty() {
            return Ok(engine
                .get_data_mut()
                .processes
                .root_outcome
                .take()
                .unwrap_or_else(empty_outcome));
        }
        if visited_idle >= live.len() {
            let deadline = std::iter::once(engine.get_data())
                .chain(
                    engine
                        .get_data()
                        .processes
                        .parked
                        .values()
                        .map(|s| s.trace.as_ref()),
                )
                .filter_map(user_threads::process_deadline)
                .min();
            if let Some(deadline) = deadline {
                engine.get_data_mut().clock.flush_cycles()?;
                let now = engine.get_data().clock.qpc();
                engine
                    .get_data_mut()
                    .clock
                    .advance_100ns(deadline.saturating_sub(now))?;
                crate::time::sync(engine)?;
                visited_idle = 0;
            } else {
                return Ok(Outcome { returned: false, value: None,
                    error: Some("User thread deadlock: no runnable work or future deadline across guest processes".into()) });
            }
        }
        let next = live
            .iter()
            .copied()
            .find(|id| *id > current)
            .unwrap_or(live[0]);
        switch(engine, next)?;
    }
}
fn finish(
    engine: &mut Unicorn<Trace>,
    mut outcome: Outcome,
    horizon: &ExecutionHorizon,
) -> Result<()> {
    let id = pid(engine);
    let code = engine.get_data().process_exit_code.unwrap_or_else(|| {
        outcome
            .value
            .map(|value| value as u32)
            .or(engine.get_data().guest_failure_code)
            .unwrap_or(0xc0000001)
    });
    if id != ROOT && outcome.returned && engine.get_data().process_exit_code.is_none() {
        user_lifecycle::request_exit(engine, code, false)?;
    }
    if id != ROOT && engine.get_data().process_exit_code.is_some() {
        if let Some(cleanup) = user_lifecycle::finish_process(
            engine,
            crate::STACK + crate::STACK_SIZE - 0x200,
            horizon,
        )? {
            outcome = cleanup;
        }
    }
    let reason = outcome
        .error
        .clone()
        .or_else(|| engine.get_data().apis.fault.clone())
        .or_else(|| engine.get_data().cpu.fault.clone());
    if id != ROOT {
        let files = std::mem::take(&mut engine.get_data_mut().apis.files);
        for (path, data) in files.into_files() {
            if engine.get_data().machine.capture_file(&path, &data) {
                engine.get_data_mut().apis.captures.add(
                    data,
                    emumee_core::artifacts::ArtifactKind::GuestFile,
                    "virtual_child_file_at_stop",
                    &path,
                );
            }
        }
    }
    let failure_kind = reason.as_ref().map(|_| {
        if engine.get_data().guest_failure_code.is_some() {
            "guest_exception"
        } else {
            "engine_error"
        }
    });
    let real_exit =
        id != ROOT || !outcome.returned || engine.get_data().process_exit_code.is_some();
    if real_exit {
        engine
            .get_data_mut()
            .processes
            .handles
            .retain(|(owner, _), _| *owner != id);
    }
    let record = engine
        .get_data_mut()
        .processes
        .records
        .get_mut(&id)
        .context("Active process record absent")?;
    record.exit_code = real_exit.then_some(code);
    record.failure = reason;
    record.failure_kind = failure_kind;
    if id == ROOT {
        engine.get_data_mut().processes.root_outcome = Some(outcome);
    }
    Ok(())
}
pub(super) fn invoke(engine: &mut Unicorn<Trace>, call: Call, args: &[u64]) -> Result<u64> {
    if engine.get_data().apis.kernel_mode {
        bail!("Virtual processes require user-mode authority");
    }
    if let Some(result) = handles::invoke(engine, call, args)? {
        return Ok(result);
    }
    if matches!(call, Call::Memory(_) | Call::Virtual(0..=2))
        && handles::process(engine, args[0], 0) == Ok(pid(engine))
    {
        return remote::local_fallback(engine, call, args);
    }
    if matches!(call, Call::Terminate) && handles::process(engine, args[0], 1) == Ok(pid(engine)) {
        user_lifecycle::request_exit(engine, args[1] as u32, true)?;
        return Ok(1);
    }
    if engine.get_data().apis.user_bootstrap.is_none() {
        return remote::local_fallback(engine, call, args);
    }
    if !engine.get_data().processes.running
        || engine.get_data().continuation_depth != 1
        || engine.get_data().loader_active
    {
        return Ok(failure(engine, 50));
    }
    user_threads::queue_process_api(engine, args.len())?;
    engine.get_data_mut().processes.request = Some((call, args.to_vec()));
    Ok(0)
}
pub(crate) fn close(engine: &mut Unicorn<Trace>, handle: u64) -> Option<u64> {
    handles::close(engine, handle)
}
pub(crate) fn process_access(engine: &Unicorn<Trace>, handle: u64, access: u32) -> bool {
    handles::process(engine, handle, access).is_ok()
}
pub(crate) fn external(engine: &Unicorn<Trace>) -> BTreeMap<u64, bool> {
    handles::external(engine)
}
pub(crate) fn wait_access(
    engine: &Unicorn<Trace>,
    handles: &[u64],
) -> std::result::Result<(), u32> {
    handles::wait_access(engine, handles)
}
