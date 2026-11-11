//! Bounded guest thread startup/teardown continuations. No native host threads.
//! General quantum scheduling and blocking waits belong to the scheduler batch.
use super::*;
use crate::threads::{ExecutionHorizon, Outcome};
use anyhow::Context;

const MAX_THREADS: usize = 64;

#[derive(Clone, Copy)]
pub(super) enum Call {
    Create,
    Resume,
    Exit,
    Terminate,
    ExitCode,
}

pub(super) fn definition(module: &str, name: &str) -> Option<(Call, usize, T)> {
    if !matches!(
        module,
        "kernel32" | "kernelbase" | "api-ms-win-core-processthreads-l1-1-0"
    ) {
        return None;
    }
    Some(match name {
        "CreateThread" => (Call::Create, 6, T::Pointer),
        "ResumeThread" => (Call::Resume, 1, T::U32),
        "ExitThread" => (Call::Exit, 1, T::Void),
        "TerminateThread" => (Call::Terminate, 2, T::U32),
        "GetExitCodeThread" => (Call::ExitCode, 2, T::U32),
        _ => return None,
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
}

#[derive(Clone)]
struct Pending {
    handle: u64,
    result: u64,
    pc: u64,
    sp: u64,
    frame: Vec<u8>,
    event: Option<usize>,
}

#[derive(Default)]
pub(crate) struct State {
    current: u64,
    records: BTreeMap<u64, Thread>,
    pending: Vec<Pending>,
    action: bool,
    resume: bool,
    exit: Option<(u32, bool)>,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub current: u64,
    pub threads: Vec<Thread>,
    pub pending: usize,
    pub scope: &'static str,
}

pub(crate) fn report(engine: &Unicorn<Trace>) -> Option<Report> {
    let state = &engine.get_data().user_threads;
    (!state.records.is_empty()).then(|| Report {
        current: current_id(engine), threads: state.records.values().cloned().collect(), pending: state.pending.len(),
        scope: "Bounded guest-only run-to-completion thread continuations with independent owned stack/TEB/static TLS/LastError, process-owned handles, actual thread attach/detach and shared run budgets. Suspended creation can resume before first execution. General quantum scheduling, live-thread suspension, blocking waits and FLS destructors remain M4 obligations.",
    })
}
pub(crate) fn current_id(engine: &Unicorn<Trace>) -> u64 {
    engine.get_data().user_threads.current.max(1)
}
pub(crate) fn queued(engine: &Unicorn<Trace>) -> bool {
    engine.get_data().user_threads.action
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
fn valid(engine: &Unicorn<Trace>, handle: u64) -> bool {
    engine
        .get_data()
        .user_threads
        .records
        .get(&handle)
        .is_some_and(|thread| !thread.handle_closed)
}
pub(crate) fn handle_id(engine: &Unicorn<Trace>, handle: u64) -> Option<u64> {
    engine
        .get_data()
        .user_threads
        .records
        .get(&handle)
        .filter(|thread| !thread.handle_closed)
        .map(|thread| thread.id)
}
pub(crate) fn close(engine: &mut Unicorn<Trace>, handle: u64) -> Option<u64> {
    let thread = engine
        .get_data_mut()
        .user_threads
        .records
        .get_mut(&handle)?;
    if thread.handle_closed {
        return Some(failure(engine, 6, 0));
    }
    thread.handle_closed = true;
    Some(1)
}
fn queue(engine: &mut Unicorn<Trace>, handle: u64, result: u64, argc: usize) -> Result<()> {
    ensure!(
        engine.get_data().user_threads.pending.len() < 16,
        "User-thread continuation depth exceeds 16"
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
    };
    engine.get_data_mut().user_threads.pending.push(pending);
    engine.get_data_mut().user_threads.action = true;
    Ok(())
}
pub(super) fn invoke(engine: &mut Unicorn<Trace>, call: Call, args: &[u64]) -> Result<u64> {
    ensure!(
        engine.get_data().apis.user_bootstrap.is_some() && engine.get_data().threads.is_none(),
        "User thread lifecycle requires the submitted-user process authority"
    );
    match call {
        Call::Create => {
            if engine.get_data().loader_active {
                return Ok(failure(engine, 50, 0));
            }
            if args[4] & !4 != 0 || args[1] > 16 * 1024 * 1024 {
                return Ok(failure(engine, 87, 0));
            }
            if require(engine, args[2], 1, P::EXECUTE).is_err() {
                return Ok(failure(engine, 998, 0));
            }
            if args[5] != 0 && require(engine, args[5], 4, P::WRITE).is_err() {
                return Ok(failure(engine, 998, 0));
            }
            let count = engine.get_data().user_threads.records.len();
            if count >= MAX_THREADS {
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
            let handle = 0x6f000000 + id * 4;
            if args[5] != 0 {
                crate::cpu::write(engine, args[5], &(id as u32).to_le_bytes())?;
            }
            let thread = Thread {
                id,
                handle,
                entry: args[2],
                parameter: args[3],
                stack_size,
                stack: 0,
                teb: 0,
                suspended: u32::from(args[4] == 4),
                state: "created",
                exit_code: None,
                handle_closed: false,
                backing_released: false,
            };
            engine
                .get_data_mut()
                .user_threads
                .records
                .insert(handle, thread);
            engine.get_data_mut().apis.last_error = 0;
            if args[4] == 0 {
                queue(engine, handle, handle, 6)?;
                return Ok(0);
            }
            Ok(handle)
        }
        Call::Resume => {
            if !valid(engine, args[0]) {
                return Ok(failure(engine, 6, u32::MAX as u64));
            }
            if engine.get_data().loader_active {
                return Ok(failure(engine, 50, u32::MAX as u64));
            }
            let thread = &engine.get_data().user_threads.records[&args[0]];
            if thread.state == "created"
                && thread.suspended == 1
                && user_loader::preflight_thread(engine, thread.stack_size).is_err()
            {
                return Ok(failure(engine, 8, u32::MAX as u64));
            }
            let thread = engine
                .get_data_mut()
                .user_threads
                .records
                .get_mut(&args[0])
                .unwrap();
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
            if current_id(engine) == 1 {
                user_lifecycle::request_exit(engine, args[0] as u32, false)?;
            } else {
                engine.get_data_mut().user_threads.exit = Some((args[0] as u32, false));
                uc(engine.emu_stop())?;
            }
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
            } else if valid(engine, args[0]) {
                engine.get_data().user_threads.records[&args[0]].id
            } else {
                return Ok(failure(engine, 6, 0));
            };
            if id == current {
                ensure!(
                    !engine.get_data().loader_active,
                    "TerminateThread during a loader notification cannot resume safely"
                );
                if id == 1 {
                    user_lifecycle::request_exit(engine, args[1] as u32, true)?;
                } else {
                    engine.get_data_mut().user_threads.exit = Some((args[1] as u32, true));
                    uc(engine.emu_stop())?;
                }
            } else {
                let thread = engine
                    .get_data_mut()
                    .user_threads
                    .records
                    .get_mut(&args[0])
                    .unwrap();
                if thread.state == "running" {
                    return Ok(failure(engine, 50, 0));
                }
                thread.state = "terminated";
                thread.exit_code = Some(args[1] as u32);
            }
            Ok(1)
        }
        Call::ExitCode => {
            if !valid(engine, args[0]) {
                return Ok(failure(engine, 6, 0));
            }
            if require(engine, args[1], 4, P::WRITE).is_err() {
                return Ok(failure(engine, 998, 0));
            }
            let value = engine.get_data().user_threads.records[&args[0]]
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
    ensure!(queued(engine), "User thread continuation is not queued");
    engine.get_data_mut().user_threads.action = false;
    let pending = engine
        .get_data()
        .user_threads
        .pending
        .last()
        .context("User thread caller is absent")?
        .clone();
    let thread = engine.get_data().user_threads.records[&pending.handle].clone();
    let parent = current_id(engine);
    let parent_teb =
        user_bootstrap::active_teb(engine).context("User thread parent TEB is absent")?;
    let mut context = uc(engine.context_init())?;
    uc(engine.context_save(&mut context))?;
    let stack = user_loader::allocate(engine, thread.stack_size)?;
    let teb = user_loader::allocate(engine, 8192)?;
    user_bootstrap::initialize_thread(engine, teb, stack, thread.stack_size, thread.id)?;
    user_loader::attach_thread(engine, thread.id, teb)?;
    {
        let thread = engine
            .get_data_mut()
            .user_threads
            .records
            .get_mut(&pending.handle)
            .unwrap();
        thread.stack = stack;
        thread.teb = teb;
        thread.state = "running";
    }
    engine.get_data_mut().user_threads.current = thread.id;
    let result = (|| -> Result<Option<Outcome>> {
        user_bootstrap::activate_thread(engine, teb)?;
        let top = stack + thread.stack_size - 0x200;
        if let Some(outcome) = user_lifecycle::notify(engine, 2, top, horizon)? {
            return Ok(Some(outcome));
        }
        let architecture = engine.get_data().architecture;
        let marker = engine.get_data().return_marker + 0x500;
        let sp = (top & !15)
            - if architecture == Architecture::X64 {
                40
            } else {
                8
            };
        let width = architecture.width();
        let mut frame = vec![0; if width == 8 { 40 } else { 8 }];
        frame[..width].copy_from_slice(&marker.to_le_bytes()[..width]);
        if width == 4 {
            frame[4..8].copy_from_slice(&(thread.parameter as u32).to_le_bytes());
        }
        crate::cpu::write(engine, sp, &frame)?;
        uc(engine.reg_write(sp_register(architecture), sp))?;
        if width == 8 {
            uc(engine.reg_write(RegisterX86::RCX, thread.parameter))?;
        }
        let outcome = crate::threads::execute_horizon(engine, thread.entry, marker, horizon)?;
        let exit = engine.get_data_mut().user_threads.exit.take();
        if !outcome.returned && exit.is_none() {
            return Ok(Some(outcome));
        }
        if outcome.returned {
            ensure!(
                uc(engine.reg_read(sp_register(architecture)))? == sp + 8,
                "User thread start routine violated its STDCALL1/Win64 return frame"
            );
        }
        let (code, forced) = exit.unwrap_or((outcome.value.unwrap_or(0) as u32, false));
        if !forced && let Some(outcome) = user_lifecycle::notify(engine, 3, top, horizon)? {
            return Ok(Some(outcome));
        }
        let record = engine
            .get_data_mut()
            .user_threads
            .records
            .get_mut(&pending.handle)
            .unwrap();
        record.exit_code = Some(code);
        record.state = if forced { "terminated" } else { "exited" };
        Ok(None)
    })();
    // Restore the real suspended parent on every path; global guest effects,
    // instruction count and deadline remain shared across native contexts.
    let switched = user_bootstrap::before_instruction(engine);
    uc(engine.context_restore(&context))?;
    engine.get_data_mut().user_threads.current = parent;
    user_bootstrap::activate_thread(engine, parent_teb)?;
    switched?;
    match result {
        Ok(None) => {
            user_loader::detach_thread(engine, thread.id)?;
            user_loader::release(engine, teb)?;
            user_loader::release(engine, stack)?;
            user_runtime::retire_thread(engine, thread.id);
            engine
                .get_data_mut()
                .user_threads
                .records
                .get_mut(&pending.handle)
                .unwrap()
                .backing_released = true;
            engine.get_data_mut().user_threads.resume = true;
            Ok(None)
        }
        Ok(Some(outcome)) => {
            engine
                .get_data_mut()
                .user_threads
                .records
                .get_mut(&pending.handle)
                .unwrap()
                .state = "interrupted";
            Ok(Some(outcome))
        }
        Err(error) => {
            engine
                .get_data_mut()
                .user_threads
                .records
                .get_mut(&pending.handle)
                .unwrap()
                .state = "interrupted";
            Err(error)
        }
    }
}

pub(crate) fn cleanup_process(engine: &mut Unicorn<Trace>, forced: bool) -> Result<()> {
    let exit_code = engine.get_data().process_exit_code;
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
    let pending = std::mem::take(&mut engine.get_data_mut().user_threads.pending);
    for caller in pending {
        if let Some(index) = caller.event
            && let Some(event) = engine.get_data_mut().apis.events.get_mut(index)
        {
            event.pending = false;
            event.effect = Some("aborted_by_process_exit");
        }
    }
    engine.get_data_mut().user_threads.action = false;
    engine.get_data_mut().user_threads.resume = false;
    Ok(())
}

pub(crate) fn resume_api(engine: &mut Unicorn<Trace>, pc: u64) -> Result<bool> {
    if !engine.get_data().user_threads.resume {
        return Ok(false);
    }
    let pending = engine
        .get_data()
        .user_threads
        .pending
        .last()
        .context("User thread resumed caller is absent")?
        .clone();
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
    engine.get_data_mut().user_threads.pending.pop();
    engine.get_data_mut().user_threads.resume = false;
    Ok(true)
}
