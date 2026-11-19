//! Guest-owned CRT invocation state and deferred native initializer callbacks.
use super::*;
use crate::threads::{ExecutionHorizon, Outcome};
use anyhow::Context;
use emumee_core::{
    crt_startup::{MAX_BYTES, StringArray, initializer_count},
    virtual_memory as vm,
};
pub(crate) mod initializers;
pub(crate) mod command_line;
pub(crate) use initializers::{queued, resume_api, transition};
const OWNER: u64 = 1024;

#[derive(Clone, Copy)]
pub(super) enum Call {
    MainArgs(bool),
    Global { index: u8, legacy: bool },
    InitialEnvironment(bool),
    InitializeEnvironment(bool),
    ConfigureArguments,
    Initializers(bool),
    CommandLineData,
    CommandLine,
    Cell(Cell),
    FileMode,
    ApplicationType,
    Lock(bool),
    ThreadLocale,
    AdjustDivide,
    MathError,
    InvalidParameter,
    NewMode,
    Register(Register),
    Exit { handlers: bool, code: Option<u32> },
}
/// One stable process-owned CRT global cell. Accessors hand the guest the same
/// address every time, so a guest store is observed by every later read.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Cell {
    Commode,
    FileMode,
    InitialEnvironment,
}
/// Exit-function registration shapes. They differ only in what they return.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Register {
    Table,
    TableFunction,
    Atexit,
    OnExit,
    DllOnExit,
    ThreadLocal,
}
pub(super) fn definition(
    _architecture: Architecture,
    module: &str,
    name: &str,
) -> Option<(Call, usize, T)> {
    let legacy = module == "msvcrt";
    let modern = matches!(
        module,
        "ucrtbase" | "api-ms-win-crt-runtime-l1-1-0" | "api-ms-win-crt-private-l1-1-0"
    );
    if !legacy && !modern {
        return None;
    }
    let alias = modern && name.starts_with("_o_");
    let name = if modern {
        name.strip_prefix("_o_").unwrap_or(name)
    } else {
        name
    };
    Some(match name {
        "_acmdln" if legacy => (Call::CommandLineData, 0, T::Pointer),
        "__p__acmdln" if legacy => (Call::CommandLine, 0, T::Pointer),
        "__getmainargs" if legacy => (Call::MainArgs(false), 5, T::U32),
        "__wgetmainargs" if legacy => (Call::MainArgs(true), 5, T::U32),
        // Legacy msvcrt exports these on both architectures.
        "__p___argc" => (Call::Global { index: 0, legacy }, 0, T::Pointer),
        "__p___argv" => (Call::Global { index: 1, legacy }, 0, T::Pointer),
        "__p___wargv" => (Call::Global { index: 2, legacy }, 0, T::Pointer),
        "_get_initial_narrow_environment" => (Call::InitialEnvironment(false), 0, T::Pointer),
        "_get_initial_wide_environment" => (Call::InitialEnvironment(true), 0, T::Pointer),
        "_initialize_narrow_environment" => (Call::InitializeEnvironment(false), 0, T::U32),
        "_initialize_wide_environment" => (Call::InitializeEnvironment(true), 0, T::U32),
        "_configure_narrow_argv" | "_configure_wide_argv" => (Call::ConfigureArguments, 1, T::U32),
        "__p__commode" => (Call::Cell(Cell::Commode), 0, T::Pointer),
        "__p__fmode" => (Call::Cell(Cell::FileMode), 0, T::Pointer),
        "__p___initenv" => (Call::Cell(Cell::InitialEnvironment), 0, T::Pointer),
        "_set_fmode" => (Call::FileMode, 1, T::U32),
        "__set_app_type" | "_set_app_type" => (Call::ApplicationType, 1, T::Void),
        "_lock" => (Call::Lock(true), 1, T::Void),
        "_unlock" => (Call::Lock(false), 1, T::Void),
        "_configthreadlocale" => (Call::ThreadLocale, 1, T::U32),
        "_adjust_fdiv" => (Call::AdjustDivide, 0, T::Void),
        "_setusermatherr" | "__setusermatherr" => (Call::MathError, 1, T::Void),
        "_set_invalid_parameter_handler" => (Call::InvalidParameter, 1, T::Pointer),
        "_set_new_mode" => (Call::NewMode, 1, T::U32),
        "_initialize_onexit_table" => (Call::Register(Register::Table), 1, T::U32),
        "_register_onexit_function" => (Call::Register(Register::TableFunction), 2, T::U32),
        "_crt_atexit" => (Call::Register(Register::Atexit), 1, T::U32),
        "_onexit" => (Call::Register(Register::OnExit), 1, T::Pointer),
        "__dllonexit" => (Call::Register(Register::DllOnExit), 3, T::Pointer),
        "_register_thread_local_exe_atexit_callback" => {
            (Call::Register(Register::ThreadLocal), 1, T::Void)
        }
        "exit" => (
            Call::Exit {
                handlers: true,
                code: None,
            },
            1,
            T::Void,
        ),
        "_exit" => (
            Call::Exit {
                handlers: false,
                code: None,
            },
            1,
            T::Void,
        ),
        "_cexit" => (
            Call::Exit {
                handlers: true,
                code: Some(0),
            },
            0,
            T::Void,
        ),
        "_c_exit" => (
            Call::Exit {
                handlers: false,
                code: Some(0),
            },
            0,
            T::Void,
        ),
        // The frozen reference terminates for std::terminate as well; the abort
        // exit code is what the real runtime leaves behind.
        "terminate" => (
            Call::Exit {
                handlers: false,
                code: Some(3),
            },
            1,
            T::Void,
        ),
        "_initterm" if !alias => (Call::Initializers(false), 2, T::Void),
        "_initterm_e" if !alias => (Call::Initializers(true), 2, T::U32),
        _ => return None,
    })
}
#[derive(Clone, Debug, Serialize)]
pub struct Backing {
    pub address: u64,
    pub size: u64,
}
#[derive(Default)]
pub(crate) struct State {
    argv: Vec<String>,
    environment: Vec<String>,
    initialized: bool,
    arguments: [Option<u64>; 2],
    environments: [Option<u64>; 2],
    legacy_arguments: [Option<u64>; 2],
    legacy_environments: [Option<u64>; 2],
    globals: Option<u64>,
    legacy_globals: Option<u64>,
    command_line: Option<Backing>,
    command_line_used: bool,
    cells: [Option<u64>; 3],
    application_type: Option<u32>,
    new_mode: u32,
    thread_locale: u32,
    locks: Vec<u32>,
    invalid_parameter: Option<u64>,
    math_error: Option<u64>,
    exit_functions: Vec<u64>,
    thread_local_exit: Vec<u64>,
    exiting: Option<u32>,
    touched: bool,
    backing: Vec<Backing>,
    pub(super) pending: Option<initializers::Pending>,
    pub(super) suspended: Vec<initializers::Pending>,
    pub(super) action: bool,
    pub(super) active: bool,
    pub(super) resume: bool,
    pub(super) events: Vec<initializers::Event>,
    pub(super) events_omitted: u64,
    pub(super) interrupted: Vec<initializers::Interrupted>,
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub profile: &'static str,
    pub argc: usize,
    pub environment_count: usize,
    pub argument_globals: Option<u64>,
    pub msvcrt_argument_globals: Option<u64>,
    pub msvcrt_command_line: Option<Backing>,
    pub commode: Option<u64>,
    pub file_mode: Option<u64>,
    pub initial_environment_pointer: Option<u64>,
    pub application_type: Option<u32>,
    pub new_mode: u32,
    pub thread_locale_mode: u32,
    pub held_locks: Vec<u32>,
    pub invalid_parameter_handler: Option<u64>,
    pub math_error_handler: Option<u64>,
    pub registered_exit_functions: usize,
    pub thread_local_exit_callbacks: Vec<u64>,
    pub requested_exit_code: Option<u32>,
    pub argument_arrays: [Option<u64>; 2],
    pub initial_environment_arrays: [Option<u64>; 2],
    pub msvcrt_argument_arrays: [Option<u64>; 2],
    pub msvcrt_environment_arrays: [Option<u64>; 2],
    pub owned_backing: Vec<Backing>,
    pub initializers: Vec<initializers::Event>,
    pub initializer_events_omitted: u64,
    pub initializer_pending: bool,
    pub suspended_initializers: usize,
    pub interrupted_initializers: Vec<initializers::Interrupted>,
    pub scope: &'static str,
}
pub(crate) fn report(engine: &Unicorn<Trace>) -> Option<Report> {
    let state = &engine.get_data().apis.crt_startup;
    if state.backing.is_empty()
        && state.events.is_empty()
        && state.pending.is_none()
        && !state.command_line_used
        && !state.touched
    {
        return None;
    }
    Some(Report {
        profile: "bounded-crt-startup-v1",
        argc: state.argv.len(),
        environment_count: state.environment.len(),
        argument_globals: state.globals,
        msvcrt_argument_globals: state.legacy_globals,
        msvcrt_command_line: state
            .command_line_used
            .then(|| state.command_line.clone())
            .flatten(),
        commode: state.cells[0],
        file_mode: state.cells[1],
        initial_environment_pointer: state.cells[2],
        application_type: state.application_type,
        new_mode: state.new_mode,
        thread_locale_mode: state.thread_locale,
        held_locks: state.locks.clone(),
        invalid_parameter_handler: state.invalid_parameter,
        math_error_handler: state.math_error,
        registered_exit_functions: state.exit_functions.len(),
        thread_local_exit_callbacks: state.thread_local_exit.clone(),
        requested_exit_code: state.exiting,
        argument_arrays: state.arguments,
        initial_environment_arrays: state.environments,
        msvcrt_argument_arrays: state.legacy_arguments,
        msvcrt_environment_arrays: state.legacy_environments,
        owned_backing: state.backing.clone(),
        initializers: state.events.clone(),
        initializer_events_omitted: state.events_omitted,
        initializer_pending: state.pending.is_some(),
        suspended_initializers: state.suspended.len(),
        interrupted_initializers: state.interrupted.clone(),
        scope: if engine.get_data().apis.user_bootstrap.is_some() {
            "Guest-owned RW/NX CDECL startup arguments/globals and pre-entry environment snapshots. Nested initializers execute actual guest instructions with checked caller frames and ABI under one shared horizon. Interrupted continuations unwind to archived diagnostics. Wildcard expansion, CRT teardown and general runtime initialization remain outside this profile."
        } else {
            "Guest-owned RW/NX CDECL startup arguments/globals and pre-entry environment snapshots. Initializers execute real guest instructions under the caller horizon. Wildcard expansion, initializer reentrancy, CRT teardown and general runtime initialization remain outside this profile."
        },
    })
}
pub(crate) fn initialize(engine: &mut Unicorn<Trace>) -> Result<()> {
    if engine.get_data().apis.kernel_mode {
        return Ok(());
    }
    let persona = &engine.get_data().apis.persona.model;
    // CRT arguments follow the baseline view: a process created with a raw
    // command line and no configured argument list recovers them by splitting it.
    let argv = persona.crt_argv(OWNER)?;
    let environment = persona
        .environment(OWNER)?
        .entries()
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    let state = &mut engine.get_data_mut().apis.crt_startup;
    ensure!(!state.initialized, "CRT startup already initialized");
    state.argv = argv;
    state.environment = environment;
    state.initialized = true;
    Ok(())
}
pub(crate) fn require_allocation_change(
    engine: &Unicorn<Trace>,
    address: u64,
    size: u64,
) -> Result<()> {
    let end = address
        .checked_add(size.max(1))
        .context("CRT startup mapping range overflow")?;
    ensure!(
        !engine
            .get_data()
            .apis
            .crt_startup
            .backing
            .iter()
            .chain(engine.get_data().apis.crt_startup.command_line.iter())
            .any(|b| address < b.address + b.size && b.address < end),
        "Allocation change overlaps CRT startup-owned storage"
    );
    Ok(())
}
fn allocate(engine: &mut Unicorn<Trace>, size: usize) -> Result<u64> {
    ensure!(
        size > 0 && size <= MAX_BYTES,
        "CRT startup allocation exceeds bound"
    );
    let state = &engine.get_data().apis;
    let plan = state
        .allocations
        .allocate(&state.memory, 0, size as u64, vm::RESERVE | vm::COMMIT, 4)
        .map_err(|e| anyhow::anyhow!("CRT startup allocation: {e}"))?;
    let address = allocation::apply(engine, plan)?;
    engine
        .get_data_mut()
        .apis
        .crt_startup
        .backing
        .push(Backing {
            address,
            size: (size as u64).div_ceil(4096) * 4096,
        });
    Ok(address)
}
#[derive(Clone, Copy)]
enum ArrayKind {
    Arguments,
    Environment,
    LegacyArguments,
    LegacyEnvironment,
}
fn array(engine: &mut Unicorn<Trace>, wide: bool, kind: ArrayKind) -> Result<u64> {
    let index = usize::from(wide);
    let state = &engine.get_data().apis.crt_startup;
    let existing = match kind {
        ArrayKind::Arguments => state.arguments[index],
        ArrayKind::Environment => state.environments[index],
        ArrayKind::LegacyArguments => state.legacy_arguments[index],
        ArrayKind::LegacyEnvironment => state.legacy_environments[index],
    };
    if let Some(address) = existing {
        return Ok(address);
    }
    let strings = if matches!(kind, ArrayKind::Environment | ArrayKind::LegacyEnvironment) {
        &state.environment
    } else {
        &state.argv
    };
    let plan = StringArray::new(engine.get_data().architecture, strings, wide)
        .map_err(anyhow::Error::msg)?;
    let address = allocate(engine, plan.size())?;
    crate::cpu::write(
        engine,
        address,
        &plan.materialize(address).map_err(anyhow::Error::msg)?,
    )?;
    let state = &mut engine.get_data_mut().apis.crt_startup;
    match kind {
        ArrayKind::Arguments => state.arguments[index] = Some(address),
        ArrayKind::Environment => state.environments[index] = Some(address),
        ArrayKind::LegacyArguments => state.legacy_arguments[index] = Some(address),
        ArrayKind::LegacyEnvironment => state.legacy_environments[index] = Some(address),
    }
    Ok(address)
}
fn globals(engine: &mut Unicorn<Trace>, legacy: bool) -> Result<u64> {
    let state = &engine.get_data().apis.crt_startup;
    if let Some(address) = if legacy {
        state.legacy_globals
    } else {
        state.globals
    } {
        return Ok(address);
    }
    let narrow = array(
        engine,
        false,
        if legacy {
            ArrayKind::LegacyArguments
        } else {
            ArrayKind::Arguments
        },
    )?;
    let wide = array(
        engine,
        true,
        if legacy {
            ArrayKind::LegacyArguments
        } else {
            ArrayKind::Arguments
        },
    )?;
    let width = engine.get_data().architecture.width();
    let address = allocate(engine, 3 * width)?;
    let argc = engine.get_data().apis.crt_startup.argv.len() as u32;
    let mut bytes = vec![0; 3 * width];
    bytes[..4].copy_from_slice(&argc.to_le_bytes());
    bytes[width..2 * width].copy_from_slice(&narrow.to_le_bytes()[..width]);
    bytes[2 * width..3 * width].copy_from_slice(&wide.to_le_bytes()[..width]);
    crate::cpu::write(engine, address, &bytes)?;
    let state = &mut engine.get_data_mut().apis.crt_startup;
    if legacy {
        state.legacy_globals = Some(address);
    } else {
        state.globals = Some(address);
    }
    Ok(address)
}
/// Stable storage for one CRT global. The frozen reference hands out fresh
/// storage per call; one process-owned cell is what the real runtime exports and
/// what import, accessor and setter agreement requires.
fn cell(engine: &mut Unicorn<Trace>, kind: Cell) -> Result<u64> {
    let index = match kind {
        Cell::Commode => 0,
        Cell::FileMode => 1,
        Cell::InitialEnvironment => 2,
    };
    if let Some(address) = engine.get_data().apis.crt_startup.cells[index] {
        return Ok(address);
    }
    let width = engine.get_data().architecture.width();
    let size = if kind == Cell::InitialEnvironment { width } else { 4 };
    let value = match kind {
        // _IOCOMMIT and _O_TEXT, as the frozen reference publishes them.
        Cell::Commode | Cell::FileMode => 0x4000,
        // The same narrow array the initial environment accessors publish.
        Cell::InitialEnvironment => array(engine, false, ArrayKind::Environment)?,
    };
    let address = allocate(engine, size)?;
    crate::cpu::write(engine, address, &value.to_le_bytes()[..size])?;
    let state = &mut engine.get_data_mut().apis.crt_startup;
    state.cells[index] = Some(address);
    state.touched = true;
    Ok(address)
}
/// Records one exit function. Registration order is preserved; the teardown walk
/// reverses it, as the real runtime does.
fn register(engine: &mut Unicorn<Trace>, target: u64, thread_local: bool) -> Result<()> {
    if target != 0 {
        require(engine, target, 1, P::EXECUTE)?;
    }
    let state = &mut engine.get_data_mut().apis.crt_startup;
    state.touched = true;
    let list = if thread_local {
        &mut state.thread_local_exit
    } else {
        &mut state.exit_functions
    };
    ensure!(list.len() < 1024, "CRT exit function quota exceeded");
    if target != 0 {
        list.push(target);
    }
    Ok(())
}
pub(super) fn invoke(engine: &mut Unicorn<Trace>, args: &[u64], call: Call) -> Result<u64> {
    ensure!(
        !engine.get_data().apis.kernel_mode && engine.get_data().apis.crt_startup.initialized,
        "CRT startup requires initialized user process"
    );
    match call {
        Call::CommandLineData => bail!("CRT data export _acmdln cannot be invoked as a routine"),
        Call::CommandLine => command_line::accessor(engine),
        Call::MainArgs(wide) => {
            let width = engine.get_data().architecture.width() as u64;
            for (address, size) in [(args[0], 4), (args[1], width), (args[2], width)] {
                require(engine, address, size, P::WRITE)?;
            }
            if args[4] != 0 {
                ensure!(
                    read(engine, args[4], 4)? == [0, 0, 0, 0],
                    "Nondefault CRT startup new-mode is not modeled"
                );
            }
            ensure!(
                args[3] as u32 == 0
                    || !engine
                        .get_data()
                        .apis
                        .crt_startup
                        .argv
                        .iter()
                        .skip(1)
                        .any(|a| a.contains(['*', '?'])),
                "CRT wildcard expansion is not modeled"
            );
            let base = globals(engine, true)?;
            let argc = read(engine, base, 4)?;
            let argv = read(engine, base + width * if wide { 2 } else { 1 }, width)?;
            let env = array(engine, wide, ArrayKind::LegacyEnvironment)?;
            crate::cpu::write(engine, args[0], &argc)?;
            crate::cpu::write(engine, args[1], &argv[..width as usize])?;
            crate::cpu::write(engine, args[2], &env.to_le_bytes()[..width as usize])?;
            Ok(0)
        }
        Call::Global { index, legacy } => Ok(globals(engine, legacy)?
            + u64::from(index) * engine.get_data().architecture.width() as u64),
        Call::InitialEnvironment(wide) => array(engine, wide, ArrayKind::Environment),
        Call::InitializeEnvironment(wide) => {
            array(engine, wide, ArrayKind::Environment)?;
            Ok(0)
        }
        Call::ConfigureArguments => {
            ensure!(
                args[0] as u32 == 1,
                "CRT argv mode outside unexpanded-arguments profile"
            );
            Ok(0)
        }
        Call::Initializers(error_returning) => initializers::queue(engine, args, error_returning),
        Call::Cell(kind) => cell(engine, kind),
        Call::FileMode => {
            // Only the text and binary modes this profile models are accepted;
            // anything else reports EINVAL and leaves the global alone.
            if args[0] as u32 != 0x4000 && args[0] as u32 != 0x8000 {
                return Ok(22);
            }
            let address = cell(engine, Cell::FileMode)?;
            crate::cpu::write(engine, address, &(args[0] as u32).to_le_bytes())?;
            Ok(0)
        }
        Call::ApplicationType => {
            ensure!(
                args[0] as u32 <= 2,
                "CRT application type {} is not modeled",
                args[0]
            );
            let state = &mut engine.get_data_mut().apis.crt_startup;
            state.application_type = Some(args[0] as u32);
            state.touched = true;
            Ok(0)
        }
        // The reference leaves the CRT locks unmodeled. They are tracked here so
        // an unbalanced release stops instead of passing silently; nesting is
        // allowed because the real locks are recursive.
        Call::Lock(acquire) => {
            ensure!(args[0] < 64, "CRT lock number {} is outside bounds", args[0]);
            let state = &mut engine.get_data_mut().apis.crt_startup;
            state.touched = true;
            if acquire {
                ensure!(state.locks.len() < 256, "CRT lock depth quota exceeded");
                state.locks.push(args[0] as u32);
            } else {
                let position = state
                    .locks
                    .iter()
                    .rposition(|held| *held == args[0] as u32)
                    .context("CRT lock released without being acquired")?;
                state.locks.remove(position);
            }
            Ok(0)
        }
        // Zero queries, one enables and two disables per-thread locales. Only the
        // process-wide default is modeled, so enabling stops explicitly.
        Call::ThreadLocale => {
            ensure!(args[0] as u32 <= 2, "CRT thread locale mode is invalid");
            ensure!(args[0] as u32 != 1, "Per-thread CRT locales are not modeled");
            let state = &mut engine.get_data_mut().apis.crt_startup;
            state.touched = true;
            if state.thread_locale == 0 {
                state.thread_locale = 2;
            }
            Ok(u64::from(state.thread_locale))
        }
        // The Pentium FDIV workaround has nothing to adjust here.
        Call::AdjustDivide => Ok(0),
        Call::MathError => {
            if args[0] != 0 {
                require(engine, args[0], 1, P::EXECUTE)?;
            }
            let state = &mut engine.get_data_mut().apis.crt_startup;
            state.math_error = Some(args[0]);
            state.touched = true;
            Ok(0)
        }
        Call::InvalidParameter => {
            if args[0] != 0 {
                require(engine, args[0], 1, P::EXECUTE)?;
            }
            let state = &mut engine.get_data_mut().apis.crt_startup;
            let previous = state.invalid_parameter.unwrap_or(0);
            state.invalid_parameter = Some(args[0]);
            state.touched = true;
            Ok(previous)
        }
        Call::NewMode => {
            ensure!(
                args[0] as u32 == 0,
                "CRT new-handler allocation mode is not modeled"
            );
            let state = &mut engine.get_data_mut().apis.crt_startup;
            state.touched = true;
            Ok(u64::from(state.new_mode))
        }
        Call::Register(kind) => {
            let width = engine.get_data().architecture.width() as u64;
            match kind {
                // The table stays empty: registrations live in process state, so
                // a guest walk of the table never finds a stale pointer.
                Register::Table => {
                    require(engine, args[0], 2 * width, P::RW)?;
                    let zero = vec![0u8; 2 * width as usize];
                    crate::cpu::write(engine, args[0], &zero)?;
                    engine.get_data_mut().apis.crt_startup.touched = true;
                    Ok(0)
                }
                Register::TableFunction => {
                    require(engine, args[0], 2 * width, P::RW)?;
                    register(engine, args[1], false)?;
                    Ok(0)
                }
                Register::Atexit => {
                    register(engine, args[0], false)?;
                    Ok(0)
                }
                Register::OnExit | Register::DllOnExit => {
                    register(engine, args[0], false)?;
                    Ok(args[0])
                }
                // Recorded but never invoked: per-thread teardown callbacks are
                // outside this profile.
                Register::ThreadLocal => {
                    register(engine, args[0], true)?;
                    Ok(0)
                }
            }
        }
        Call::Exit { handlers, code } => {
            let code = code.unwrap_or_else(|| args[0] as u32);
            ensure!(
                engine.get_data().apis.crt_startup.exiting.is_none(),
                "CRT exit reentrancy is not modeled"
            );
            let targets: Vec<u64> = if handlers {
                engine
                    .get_data()
                    .apis
                    .crt_startup
                    .exit_functions
                    .iter()
                    .rev()
                    .copied()
                    .collect()
            } else {
                Vec::new()
            };
            let state = &mut engine.get_data_mut().apis.crt_startup;
            state.touched = true;
            state.exiting = Some(code);
            if targets.is_empty() {
                user_lifecycle::request_exit(engine, code, false)?;
                return Ok(0);
            }
            // Registered functions run once, from emulator-owned NX storage the
            // guest cannot retire.
            state.exit_functions.clear();
            let width = engine.get_data().architecture.width();
            let table = allocate(engine, targets.len() * width)?;
            let mut bytes = Vec::with_capacity(targets.len() * width);
            for target in &targets {
                bytes.extend_from_slice(&target.to_le_bytes()[..width]);
            }
            crate::cpu::write(engine, table, &bytes)?;
            initializers::queue_table(engine, table, targets.len() as u64, false)
        }
    }
}
