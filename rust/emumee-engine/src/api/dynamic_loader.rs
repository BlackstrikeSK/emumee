//! Bounded user DLL operations. ModuleCatalog alone owns references and images.
//! Native execution is entered only by transition(), after the outer start stopped.
use super::*;
use crate::threads::{ExecutionHorizon, Outcome};
use anyhow::Context as _;
use emumee_core::modules::ModuleId;
mod mapping;
const OWNER: u64 = 1024; // Existing single-user VFS/API process, never a host PID.
const STATUS_INVALID_PARAMETER: u64 = 0xc000000d;
const STATUS_NOT_SUPPORTED: u64 = 0xc00000bb;
const STATUS_ACCESS_VIOLATION: u64 = 0xc0000005;
const STATUS_DLL_NOT_FOUND: u64 = 0xc0000135;
const STATUS_DLL_INIT_FAILED: u64 = 0xc0000142;

#[derive(Clone, Copy, Debug)]
pub(super) enum Call {
    Load { wide: bool, extended: bool },
    Free,
    LdrLoad,
    LdrUnload,
}
pub(super) fn definition(module: &str, name: &str) -> Option<(Call, usize, C, T)> {
    let win32 = matches!(
        module,
        "kernel32" | "kernelbase" | "api-ms-win-core-libraryloader-l1-2-0"
    );
    Some(match (module, name) {
        (_, "LoadLibraryA" | "LoadLibraryW") if win32 => (
            Call::Load {
                wide: name.ends_with('W'),
                extended: false,
            },
            1,
            C::Stdcall,
            T::Pointer,
        ),
        (_, "LoadLibraryExA" | "LoadLibraryExW") if win32 => (
            Call::Load {
                wide: name.ends_with('W'),
                extended: true,
            },
            3,
            C::Stdcall,
            T::Pointer,
        ),
        (_, "FreeLibrary") if win32 => (Call::Free, 1, C::Stdcall, T::U32),
        ("ntdll", "LdrLoadDll") => (Call::LdrLoad, 4, C::Stdcall, T::U32),
        ("ntdll", "LdrUnloadDll") => (Call::LdrUnload, 1, C::Stdcall, T::U32),
        _ => return None,
    })
}
#[derive(Clone, Debug)]
enum Request {
    Load { name: String, output: Option<u64> },
    Free { handle: u64 },
}
#[derive(Clone, Debug)]
struct Caller {
    pc: u64,
    sp: u64,
    frame: Vec<u8>,
    nt: bool,
    load: bool,
    event: Option<usize>,
    call: u64,
}
#[derive(Clone, Debug)]
struct Pending {
    caller: Caller,
    request: Request,
    operation: Option<u64>,
    result: Option<u64>,
}
#[derive(Default)]
pub(crate) struct State {
    pending: Option<Pending>,
    action: bool,
    resume: bool,
    requests: u64,
    resumed: u64,
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub profile: &'static str,
    pub state: emumee_core::modules::DynamicState,
    pub images: Vec<emumee_core::modules::LoadedModule>,
    pub pending_api: Option<String>,
    pub pending_result: Option<u64>,
    pub requests: u64,
    pub resumed: u64,
    pub native_effect_failure: Option<String>,
    pub scope: &'static str,
}
pub(crate) fn report(engine: &Unicorn<Trace>) -> Option<Report> {
    let state = &engine.get_data().dynamic_loader;
    if state.requests == 0 {
        return None;
    }
    Some(Report {
        profile: "bounded-vfs-leaf-dll-v1",
        state: engine.get_data().apis.modules.dynamic_state().clone(),
        images: engine
            .get_data()
            .apis
            .modules
            .modules()
            .filter(|m| m.dynamic_image().is_some())
            .cloned()
            .collect(),
        pending_api: state.pending.as_ref().map(|p| {
            format!(
                "{}:{}",
                if p.caller.nt { "nt" } else { "win32" },
                if p.caller.load { "load" } else { "release" }
            )
        }),
        pending_result: state.pending.as_ref().and_then(|p| p.result),
        requests: state.requests,
        resumed: state.resumed,
        native_effect_failure: engine.get_data().loader_native_effect_failure.clone(),
        scope: "Actual native DLL bytes from the same guest VFS and catalog. Leaf dependencies must already be ready; real callback-only TLS/DllMain attach, FALSE cleanup, detach, native unmap and reference edges. No host lookup, recursive missing dependencies, storage TLS, initializer reentrancy, special flags, EXE-as-image loads or consumption of static process anchors. Incomplete operations retain pending evidence and never publish completed API success.",
    })
}
fn sp_register(arch: Architecture) -> RegisterX86 {
    if arch == Architecture::X64 {
        RegisterX86::RSP
    } else {
        RegisterX86::ESP
    }
}
fn counted_name(engine: &Unicorn<Trace>, address: u64) -> Result<Option<String>> {
    let width = engine.get_data().architecture.width();
    let header = read(engine, address, if width == 8 { 16 } else { 8 })?;
    let length = u16::from_le_bytes(header[..2].try_into().unwrap()) as usize;
    let maximum = u16::from_le_bytes(header[2..4].try_into().unwrap()) as usize;
    if length == 0
        || length > 4096
        || maximum < length
        || maximum > 4096
        || maximum % 2 != 0
        || length % 2 != 0
    {
        return Ok(None);
    }
    let mut pointer = [0; 8];
    pointer[..width].copy_from_slice(&header[width..2 * width]);
    let pointer = u64::from_le_bytes(pointer);
    if pointer == 0 {
        return Ok(None);
    }
    let raw = read(engine, pointer, length as u64)?;
    let units = raw
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect::<Vec<_>>();
    Ok(String::from_utf16(&units)
        .ok()
        .filter(|s| !s.contains('\0')))
}
pub(super) fn invoke(engine: &mut Unicorn<Trace>, call: Call, args: &[u64]) -> Result<u64> {
    ensure!(
        !engine.get_data().apis.kernel_mode
            && engine.get_data().threads.is_none()
            && !crate::ipi::active(engine),
        "Dynamic DLL operations require the actual single-user process"
    );
    ensure!(
        !engine.get_data().loader_active && engine.get_data().dynamic_loader.pending.is_none(),
        "Dynamic DLL initializer/detacher reentrancy is not modeled"
    );
    let nt = matches!(call, Call::LdrLoad | Call::LdrUnload);
    let load = matches!(call, Call::Load { .. } | Call::LdrLoad);
    let request = match call {
        Call::Load { wide, extended } => {
            ensure!(
                !extended || (args[1] == 0 && args[2] as u32 == 0),
                "LoadLibraryEx nonzero file/flags are not modeled"
            );
            let name = files::path(engine, args[0], wide)?;
            if name.is_empty() {
                engine.get_data_mut().apis.last_error = 126;
                return Ok(0);
            }
            Request::Load { name, output: None }
        }
        Call::Free => Request::Free { handle: args[0] },
        Call::LdrUnload => {
            if args[0] == 0 {
                return Ok(STATUS_INVALID_PARAMETER);
            }
            Request::Free { handle: args[0] }
        }
        Call::LdrLoad => {
            if args[2] == 0 {
                return Ok(STATUS_INVALID_PARAMETER);
            }
            if args[0] != 0 {
                return Ok(STATUS_NOT_SUPPORTED);
            }
            if args[1] != 0 {
                let value = match read(engine, args[1], 4) {
                    Ok(v) => u32::from_le_bytes(v.try_into().unwrap()),
                    Err(_) => return Ok(STATUS_ACCESS_VIOLATION),
                };
                if value != 0 {
                    return Ok(STATUS_NOT_SUPPORTED);
                }
            }
            let name = match counted_name(engine, args[2]) {
                Ok(Some(v)) => v,
                Ok(None) => return Ok(STATUS_INVALID_PARAMETER),
                Err(_) => return Ok(STATUS_ACCESS_VIOLATION),
            };
            let output = (args[3] != 0).then_some(args[3]);
            if let Some(output) = output {
                if require(
                    engine,
                    output,
                    engine.get_data().architecture.width() as u64,
                    P::WRITE,
                )
                .is_err()
                {
                    return Ok(STATUS_ACCESS_VIOLATION);
                }
            }
            Request::Load { name, output }
        }
    };
    let arch = engine.get_data().architecture;
    let pc = uc(engine.pc_read())?;
    let sp = uc(engine.reg_read(sp_register(arch)))?;
    ensure!(
        arch != Architecture::X64 || sp % 16 == 8,
        "Win64 loader API has misaligned caller stack"
    );
    let frame = read(
        engine,
        sp,
        if arch == Architecture::X64 {
            40
        } else {
            (args.len() as u64 + 1) * 4
        },
    )?;
    let mut marker = [0; 8];
    marker[..arch.width()].copy_from_slice(&frame[..arch.width()]);
    ensure!(
        u64::from_le_bytes(marker) != 0,
        "Dynamic DLL API has a null actual return address"
    );
    let event = engine.get_data().apis.next_event_index();
    let caller = Caller {
        pc,
        sp,
        frame,
        nt,
        load,
        event,
        call: engine.get_data().apis.calls,
    };
    engine
        .get_data_mut()
        .apis
        .modules
        .establish_user_loader(OWNER)?;
    let state = &mut engine.get_data_mut().dynamic_loader;
    state.requests = state
        .requests
        .checked_add(1)
        .context("Loader request counter overflow")?;
    state.pending = Some(Pending {
        caller,
        request,
        operation: None,
        result: None,
    });
    state.action = true;
    Ok(0) // Not a guest result; dispatch records pending and does not write AX.
}
pub(crate) fn queued(engine: &Unicorn<Trace>) -> bool {
    engine.get_data().dynamic_loader.action
}
fn normal_failure(engine: &mut Unicorn<Trace>, error: u32) -> Result<()> {
    ensure!(
        error != 50,
        "Dynamic DLL operation outside the bounded execution profile"
    );
    let nt = engine
        .get_data()
        .dynamic_loader
        .pending
        .as_ref()
        .context("Loader pending frame absent")?
        .caller
        .nt;
    engine.get_data_mut().apis.last_error = error;
    engine
        .get_data_mut()
        .dynamic_loader
        .pending
        .as_mut()
        .unwrap()
        .result = Some(if nt {
        if error == 1114 {
            STATUS_DLL_INIT_FAILED
        } else {
            STATUS_DLL_NOT_FOUND
        }
    } else {
        0
    });
    Ok(())
}
fn completion(engine: &mut Unicorn<Trace>, result: u64) {
    engine
        .get_data_mut()
        .dynamic_loader
        .pending
        .as_mut()
        .unwrap()
        .result = Some(result);
}
fn native_failure(engine: &mut Unicorn<Trace>, operation: &str, error: &anyhow::Error) {
    engine.get_data_mut().loader_native_effect_failure = Some(format!(
        "Dynamic DLL {operation} failed; partial native effects are terminal: {error:#}"
    ));
}
fn current_operation(engine: &mut Unicorn<Trace>) {
    let id = engine
        .get_data()
        .apis
        .modules
        .dynamic_state()
        .active
        .as_ref()
        .map(|op| op.id);
    engine
        .get_data_mut()
        .dynamic_loader
        .pending
        .as_mut()
        .unwrap()
        .operation = id;
}
fn routine(
    engine: &mut Unicorn<Trace>,
    call: &emumee_core::modules::LoaderInvocation,
    horizon: &ExecutionHorizon,
) -> Result<Outcome> {
    let count = engine.get_data().instructions;
    let event = engine
        .get_data_mut()
        .apis
        .modules
        .begin_dynamic_routine(call, count)?;
    let stack_top = engine
        .get_data()
        .dynamic_loader
        .pending
        .as_ref()
        .context("DLL caller absent")?
        .caller
        .sp
        .checked_sub(0x100)
        .context("DLL callback stack underflow")?;
    engine.get_data_mut().loader_active = true;
    let result = native_loader::invoke_inner(engine, call, stack_top, horizon);
    engine.get_data_mut().loader_active = false;
    let outcome = match result {
        Ok(v) => v,
        Err(e) => Outcome {
            returned: false,
            value: None,
            error: Some(format!("{e:#}")),
        },
    };
    let failure = (!outcome.returned).then(|| {
        outcome
            .error
            .clone()
            .or_else(|| engine.get_data().apis.fault.clone())
            .or_else(|| engine.get_data().cpu.fault.clone())
            .or_else(|| {
                engine
                    .get_data()
                    .clock_error
                    .then(|| "Shared guest clock model failed".into())
            })
            .unwrap_or_else(|| "Shared instruction or wall horizon exhausted".into())
    });
    let count = engine.get_data().instructions;
    engine.get_data_mut().apis.modules.settle_dynamic_routine(
        call,
        event,
        count,
        if outcome.returned {
            outcome.value
        } else {
            None
        },
        failure,
    )?;
    Ok(outcome)
}
fn retire(engine: &mut Unicorn<Trace>, id: ModuleId) -> Result<()> {
    let module = engine
        .get_data()
        .apis
        .modules
        .by_identity(id)
        .context("DLL retirement identity absent")?;
    let (base, size) = (module.base, module.size);
    let mut catalog = engine.get_data().apis.modules.clone();
    catalog.retire_dynamic_image(id, engine.get_data().instructions)?;
    let mut memory = engine.get_data().apis.memory.clone();
    memory.unmap(base, size)?;
    if let Err(error) = uc(engine.mem_unmap(base, size))
        .with_context(|| format!("Dynamic DLL native unmap at {base:#x}+{size:#x}"))
    {
        native_failure(engine, "unmap", &error);
        return Err(error);
    }
    engine.get_data_mut().apis.modules = catalog;
    engine.get_data_mut().apis.memory = memory;
    engine
        .get_data_mut()
        .cpu
        .cache
        .invalidate(base, size as usize);
    if let Err(error) = uc(engine.ctl_remove_cache(base, base + size)) {
        native_failure(engine, "cache retirement after successful unmap", &error);
        return Err(error);
    }
    Ok(())
}
fn detach(engine: &mut Unicorn<Trace>, horizon: &ExecutionHorizon) -> Result<Option<Outcome>> {
    loop {
        let operation = engine
            .get_data()
            .apis
            .modules
            .dynamic_state()
            .active
            .as_ref()
            .context("DLL detach operation absent")?;
        if operation.returning {
            return Ok(None);
        }
        let id = operation.modules[operation.cursor];
        for call in engine.get_data().apis.modules.dynamic_calls(id, true)? {
            let result = routine(engine, &call, horizon)?;
            if !result.returned {
                return Ok(Some(result));
            }
        }
        retire(engine, id)?;
    }
}
/// Called only after emu_start has returned; recursive host frames share horizon.
pub(crate) fn transition(
    engine: &mut Unicorn<Trace>,
    horizon: &ExecutionHorizon,
) -> Result<Option<Outcome>> {
    ensure!(
        engine.get_data().dynamic_loader.action,
        "No queued dynamic DLL transition"
    );
    engine.get_data_mut().dynamic_loader.action = false;
    let request = engine
        .get_data()
        .dynamic_loader
        .pending
        .as_ref()
        .context("DLL request absent")?
        .request
        .clone();
    match request {
        Request::Load { name, output } => {
            if let Some(output) = output {
                let width = engine.get_data().architecture.width();
                require(engine, output, width as u64, P::WRITE)?;
                if let Err(error) = crate::cpu::write(engine, output, &vec![0; width]) {
                    native_failure(engine, "NT output initialization", &error);
                    return Err(error);
                }
            }
            match mapping::load(engine, &name) {
                Err(mapping::LoadError::Refused(error)) => normal_failure(engine, error)?,
                Err(mapping::LoadError::Fatal(error)) => return Err(error),
                Ok(mapping::Loaded::Retained(base)) => {
                    mapping::publish_handle(engine, output, base)?;
                    let nt = engine
                        .get_data()
                        .dynamic_loader
                        .pending
                        .as_ref()
                        .unwrap()
                        .caller
                        .nt;
                    completion(engine, if nt { 0 } else { base });
                }
                Ok(mapping::Loaded::New(id, base)) => {
                    current_operation(engine);
                    let mut refused = false;
                    for call in engine.get_data().apis.modules.dynamic_calls(id, false)? {
                        let outcome = routine(engine, &call, horizon)?;
                        if !outcome.returned {
                            return Ok(Some(outcome));
                        }
                        if matches!(call.routine, emumee_core::modules::LoaderRoutine::DllAttach)
                            && outcome.value.unwrap() as u32 == 0
                        {
                            refused = true;
                            break;
                        }
                    }
                    if refused {
                        let count = engine.get_data().instructions;
                        engine
                            .get_data_mut()
                            .apis
                            .modules
                            .fail_dynamic_attach(id, count)?;
                        if let Some(outcome) = detach(engine, horizon)? {
                            return Ok(Some(outcome));
                        }
                        normal_failure(engine, 1114)?;
                    } else {
                        let count = engine.get_data().instructions;
                        engine
                            .get_data_mut()
                            .apis
                            .modules
                            .dynamic_ready(id, count)?;
                        mapping::publish_handle(engine, output, base)?;
                        let nt = engine
                            .get_data()
                            .dynamic_loader
                            .pending
                            .as_ref()
                            .unwrap()
                            .caller
                            .nt;
                        completion(engine, if nt { 0 } else { base });
                    }
                }
            }
        }
        Request::Free { handle } => {
            let id = engine
                .get_data()
                .apis
                .modules
                .modules()
                .find(|m| m.base == handle)
                .map(|m| m.identity());
            if let Some(id) = id {
                let count = engine.get_data().instructions;
                match engine
                    .get_data_mut()
                    .apis
                    .modules
                    .release_dynamic_reference(id, OWNER, count)
                {
                    Err(error) => {
                        ensure!(error.win32 != 50, "{error}");
                        normal_failure(engine, error.win32)?;
                    }
                    Ok(pending) => {
                        if pending {
                            current_operation(engine);
                            if let Some(outcome) = detach(engine, horizon)? {
                                return Ok(Some(outcome));
                            }
                        }
                        let nt = engine
                            .get_data()
                            .dynamic_loader
                            .pending
                            .as_ref()
                            .unwrap()
                            .caller
                            .nt;
                        completion(engine, if nt { 0 } else { 1 });
                    }
                }
            } else {
                normal_failure(engine, 6)?;
            }
        }
    }
    let pending = engine.get_data().dynamic_loader.pending.as_ref().unwrap();
    let (pc, sp) = (pending.caller.pc, pending.caller.sp);
    // Do not restore a Context: callback volatile/global/clock/LastError effects are real.
    let publication = (|| -> Result<()> {
        uc(engine.reg_write(sp_register(engine.get_data().architecture), sp))?;
        uc(engine.reg_write(
            if engine.get_data().architecture == Architecture::X64 {
                RegisterX86::RIP
            } else {
                RegisterX86::EIP
            },
            pc,
        ))?;
        Ok(())
    })();
    if let Err(error) = publication {
        native_failure(engine, "caller continuation", &error);
        return Err(error);
    }
    engine.get_data_mut().dynamic_loader.resume = true;
    Ok(None)
}
/// The next actual gate attempt publishes a result once; native RET does cleanup.
pub(crate) fn resume_api(engine: &mut Unicorn<Trace>, pc: u64) -> Result<bool> {
    if !engine.get_data().dynamic_loader.resume {
        return Ok(false);
    }
    let pending = engine
        .get_data()
        .dynamic_loader
        .pending
        .as_ref()
        .context("DLL resumed frame absent")?
        .clone();
    ensure!(
        pc == pending.caller.pc
            && uc(engine.reg_read(sp_register(engine.get_data().architecture)))?
                == pending.caller.sp,
        "DLL caller continuation no longer matches its real API frame"
    );
    ensure!(
        read(engine, pending.caller.sp, pending.caller.frame.len() as u64)? == pending.caller.frame,
        "DLL callback changed the suspended caller return/argument frame"
    );
    let value = pending
        .result
        .context("DLL resume attempted before a real result")?;
    let arch = engine.get_data().architecture;
    uc(engine.reg_write(
        if arch == Architecture::X64 {
            RegisterX86::RAX
        } else {
            RegisterX86::EAX
        },
        if pending.caller.nt || !pending.caller.load {
            value as u32 as u64
        } else {
            value
        },
    ))?;
    if let Some(operation) = pending.operation {
        let count = engine.get_data().instructions;
        engine
            .get_data_mut()
            .apis
            .modules
            .finish_dynamic_operation(operation, count)?;
    }
    if let Some(index) = pending.caller.event {
        let last_error = engine.get_data().apis.last_error;
        if let Some(event) = engine.get_data_mut().apis.events.get_mut(index) {
            ensure!(event.pending, "DLL original API event already completed");
            event.result = Some(value);
            event.last_error = last_error;
            event.pending = false;
            event.effect = Some("dynamic_loader_return_ready");
        }
    }
    ensure!(
        engine.get_data().apis.calls >= pending.caller.call,
        "DLL API call count regressed"
    );
    let state = &mut engine.get_data_mut().dynamic_loader;
    state.resumed = state
        .resumed
        .checked_add(1)
        .context("DLL resumed counter overflow")?;
    state.pending = None;
    state.resume = false;
    Ok(true)
}

pub(super) fn module_handle(engine: &Unicorn<Trace>, name: &str) -> Result<Option<u64>> {
    Ok(mapping::lookup(engine, name)?.and_then(|id| {
        engine
            .get_data()
            .apis
            .modules
            .by_identity(id)
            .map(|m| m.base)
    }))
}
pub(super) fn retain_followed_edges(
    engine: &mut Unicorn<Trace>,
    module: &str,
    chain: &[String],
) -> Result<()> {
    mapping::retain_followed_edges(engine, module, chain)
}
