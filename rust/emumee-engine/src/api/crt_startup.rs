//! Guest-owned CRT invocation state and deferred native initializer callbacks.
use super::*;
use crate::threads::{ExecutionHorizon, Outcome};
use anyhow::Context;
use emumee_core::{
    crt_startup::{MAX_BYTES, StringArray, initializer_count},
    virtual_memory as vm,
};
mod initializers;
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
}
pub(super) fn definition(
    architecture: Architecture,
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
        "__getmainargs" if legacy => (Call::MainArgs(false), 5, T::U32),
        "__wgetmainargs" if legacy => (Call::MainArgs(true), 5, T::U32),
        "__p___argc" if modern || legacy && architecture == Architecture::X86 => {
            (Call::Global { index: 0, legacy }, 0, T::Pointer)
        }
        "__p___argv" if modern || legacy && architecture == Architecture::X86 => {
            (Call::Global { index: 1, legacy }, 0, T::Pointer)
        }
        "__p___wargv" if modern || legacy && architecture == Architecture::X86 => {
            (Call::Global { index: 2, legacy }, 0, T::Pointer)
        }
        "_get_initial_narrow_environment" if modern => {
            (Call::InitialEnvironment(false), 0, T::Pointer)
        }
        "_get_initial_wide_environment" if modern => {
            (Call::InitialEnvironment(true), 0, T::Pointer)
        }
        "_initialize_narrow_environment" if modern => {
            (Call::InitializeEnvironment(false), 0, T::U32)
        }
        "_initialize_wide_environment" if modern => (Call::InitializeEnvironment(true), 0, T::U32),
        "_configure_narrow_argv" | "_configure_wide_argv" if modern => {
            (Call::ConfigureArguments, 1, T::U32)
        }
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
    backing: Vec<Backing>,
    pub(super) pending: Option<initializers::Pending>,
    pub(super) action: bool,
    pub(super) active: bool,
    pub(super) resume: bool,
    pub(super) events: Vec<initializers::Event>,
    pub(super) events_omitted: u64,
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub profile: &'static str,
    pub argc: usize,
    pub environment_count: usize,
    pub argument_globals: Option<u64>,
    pub msvcrt_argument_globals: Option<u64>,
    pub argument_arrays: [Option<u64>; 2],
    pub initial_environment_arrays: [Option<u64>; 2],
    pub msvcrt_argument_arrays: [Option<u64>; 2],
    pub msvcrt_environment_arrays: [Option<u64>; 2],
    pub owned_backing: Vec<Backing>,
    pub initializers: Vec<initializers::Event>,
    pub initializer_events_omitted: u64,
    pub initializer_pending: bool,
    pub scope: &'static str,
}
pub(crate) fn report(engine: &Unicorn<Trace>) -> Option<Report> {
    let state = &engine.get_data().apis.crt_startup;
    if state.backing.is_empty() && state.events.is_empty() && state.pending.is_none() {
        return None;
    }
    Some(Report {
        profile: "bounded-crt-startup-v1",
        argc: state.argv.len(),
        environment_count: state.environment.len(),
        argument_globals: state.globals,
        msvcrt_argument_globals: state.legacy_globals,
        argument_arrays: state.arguments,
        initial_environment_arrays: state.environments,
        msvcrt_argument_arrays: state.legacy_arguments,
        msvcrt_environment_arrays: state.legacy_environments,
        owned_backing: state.backing.clone(),
        initializers: state.events.clone(),
        initializer_events_omitted: state.events_omitted,
        initializer_pending: state.pending.is_some(),
        scope: "Guest-owned RW/NX CDECL startup arguments/globals and pre-entry environment snapshots. Initializers execute real guest instructions under the caller horizon. Wildcard expansion, initializer reentrancy, CRT teardown and general runtime initialization remain outside this profile.",
    })
}
pub(crate) fn initialize(engine: &mut Unicorn<Trace>) -> Result<()> {
    if engine.get_data().apis.kernel_mode {
        return Ok(());
    }
    let persona = &engine.get_data().apis.persona.model;
    let argv = persona.argv(OWNER)?.to_vec();
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
pub(super) fn invoke(engine: &mut Unicorn<Trace>, args: &[u64], call: Call) -> Result<u64> {
    ensure!(
        !engine.get_data().apis.kernel_mode && engine.get_data().apis.crt_startup.initialized,
        "CRT startup requires initialized user process"
    );
    match call {
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
    }
}
