//! Win32 process/bootstrap models over owned guest state. No host process APIs.
use super::*;
use anyhow::Context;
use emumee_core::{
    persona::Encoding,
    user_runtime::{CriticalSection, Slots},
    virtual_memory as vm,
};
const OWNER: u64 = 1024;
#[derive(Clone, Copy)]
pub(super) enum Call {
    Process,
    Exception(crate::native_exceptions::user::Call),
    RuntimeTable(crate::native_exceptions::function_tables::Call),
    Thread,
    ThreadId,
    ProcessId(bool),
    OpenProcess,
    Debugger,
    RemoteDebugger,
    ProcessExitCode,
    Terminate,
    ProcessMemory(bool),
    VirtualEx(u8),
    Pointer(bool),
    SlotAllocate(bool),
    SlotFree(bool),
    SlotGet { fiber: bool, preserve_error: bool },
    SlotSet(bool),
    CriticalInitialize(u8),
    CriticalEnter(bool),
    CriticalLeave,
    CriticalDelete,
    CriticalSpin,
    Startup(bool),
    SystemInfo(bool),
    Version,
    /// `wide` is `None` for the generic `GetVersionEx` spelling, whose structure
    /// width is decided by the caller's own size field.
    VersionInfo { wide: Option<bool>, nt: bool },
    VersionCondition,
    VerifyVersion { nt: bool },
    NtVersionNumbers,
    MemoryStatus(bool),
    InstalledMemory,
    Affinity,
    ProcessorNumber(bool),
    ProcessorCount,
    GroupCount,
    Wow64(bool),
    ModuleFilename(bool),
    ProcessPolicy,
    SessionId,
    ProcessorFeature,
}
#[derive(Default)]
pub(crate) struct State {
    slots: Slots,
    fls_callbacks: BTreeMap<u32, u64>,
    critical: BTreeMap<u64, CriticalSection>,
    handles: BTreeMap<u64, u32>,
    next_handle: u64,
    strings: BTreeMap<(String, bool), (u64, u64)>,
}
pub(crate) fn take_fls(
    engine: &mut Unicorn<Trace>,
    index: Option<u32>,
    thread: Option<u64>,
) -> Vec<(u64, u64)> {
    let callbacks = engine.get_data().apis.user_runtime.fls_callbacks.clone();
    let mut calls = Vec::new();
    for (slot, target) in callbacks {
        if index.is_some_and(|i| i != slot) {
            continue;
        }
        if let Some(values) = engine
            .get_data_mut()
            .apis
            .user_runtime
            .slots
            .take_fls(slot, thread)
            && target != 0
        {
            calls.extend(values.into_iter().map(|value| (target, value)));
        }
    }
    calls
}
pub(crate) fn retire_thread(engine: &mut Unicorn<Trace>, thread: u64) {
    engine
        .get_data_mut()
        .apis
        .user_runtime
        .slots
        .retire_thread(thread);
}
pub(super) fn definition(
    architecture: Architecture,
    module: &str,
    name: &str,
) -> Option<(Call, usize, T)> {
    // A ULONGLONG argument occupies two x86 stack slots and one x64 register.
    let quad = usize::from(architecture == Architecture::X86);
    let kernel = matches!(module, "kernel32" | "kernelbase");
    let process = kernel || module.starts_with("api-ms-win-core-processthreads-");
    let sync = kernel || module.starts_with("api-ms-win-core-synch-");
    let fiber = kernel || module.starts_with("api-ms-win-core-fibers-");
    let system = kernel || module.starts_with("api-ms-win-core-sysinfo-");
    let debug = kernel || module.starts_with("api-ms-win-core-debug-");
    let memory = kernel || module.starts_with("api-ms-win-core-memory-");
    let loader = kernel || module.starts_with("api-ms-win-core-libraryloader-");
    Some(match name {
        "_except_handler4_common" if module == "msvcrt" || module == "vcruntime140" => (
            Call::Exception(crate::native_exceptions::user::Call::Eh4),
            6,
            T::U32,
        ),
        "RtlAddFunctionTable" if kernel || module == "ntdll" => (
            Call::RuntimeTable(crate::native_exceptions::function_tables::Call::Add),
            3,
            T::U32,
        ),
        "RtlDeleteFunctionTable" if kernel || module == "ntdll" => (
            Call::RuntimeTable(crate::native_exceptions::function_tables::Call::Delete),
            1,
            T::U32,
        ),
        "RtlLookupFunctionEntry" if kernel || module == "ntdll" => (
            Call::RuntimeTable(crate::native_exceptions::function_tables::Call::Lookup),
            3,
            T::Pointer,
        ),
        "RaiseException" if debug => (
            Call::Exception(crate::native_exceptions::user::Call::Raise),
            4,
            T::Void,
        ),
        "AddVectoredExceptionHandler" | "RtlAddVectoredExceptionHandler"
            if debug || module == "ntdll" =>
        {
            (
                Call::Exception(crate::native_exceptions::user::Call::Add(false)),
                2,
                T::Pointer,
            )
        }
        "AddVectoredContinueHandler" | "RtlAddVectoredContinueHandler"
            if debug || module == "ntdll" =>
        {
            (
                Call::Exception(crate::native_exceptions::user::Call::Add(true)),
                2,
                T::Pointer,
            )
        }
        "RemoveVectoredExceptionHandler" | "RtlRemoveVectoredExceptionHandler"
            if debug || module == "ntdll" =>
        {
            (
                Call::Exception(crate::native_exceptions::user::Call::Remove(false)),
                1,
                T::U32,
            )
        }
        "RemoveVectoredContinueHandler" | "RtlRemoveVectoredContinueHandler"
            if debug || module == "ntdll" =>
        {
            (
                Call::Exception(crate::native_exceptions::user::Call::Remove(true)),
                1,
                T::U32,
            )
        }
        "SetUnhandledExceptionFilter" if debug => (
            Call::Exception(crate::native_exceptions::user::Call::Filter),
            1,
            T::Pointer,
        ),
        "GetCurrentProcess" if process => (Call::Process, 0, T::Pointer),
        "GetCurrentThread" if process => (Call::Thread, 0, T::Pointer),
        "GetCurrentThreadId" if process => (Call::ThreadId, 0, T::U32),
        "GetProcessId" if process => (Call::ProcessId(false), 1, T::U32),
        "GetThreadId" if process => (Call::ProcessId(true), 1, T::U32),
        "OpenProcess" if process => (Call::OpenProcess, 3, T::Pointer),
        "IsDebuggerPresent" if debug => (Call::Debugger, 0, T::U32),
        "CheckRemoteDebuggerPresent" if debug => (Call::RemoteDebugger, 2, T::U32),
        "GetExitCodeProcess" if process => (Call::ProcessExitCode, 2, T::U32),
        "TerminateProcess" if process => (Call::Terminate, 2, T::U32),
        "ReadProcessMemory" if debug || memory => (Call::ProcessMemory(false), 5, T::U32),
        "WriteProcessMemory" if debug || memory => (Call::ProcessMemory(true), 5, T::U32),
        "VirtualAllocEx" if memory => (Call::VirtualEx(0), 5, T::Pointer),
        "VirtualFreeEx" if memory => (Call::VirtualEx(1), 4, T::U32),
        "VirtualProtectEx" if memory => (Call::VirtualEx(2), 5, T::U32),
        "EncodePointer" | "RtlEncodePointer" if kernel || module == "ntdll" => {
            (Call::Pointer(false), 1, T::Pointer)
        }
        "DecodePointer" | "RtlDecodePointer" if kernel || module == "ntdll" => {
            (Call::Pointer(true), 1, T::Pointer)
        }
        "TlsAlloc" if process => (Call::SlotAllocate(false), 0, T::U32),
        "TlsFree" if process => (Call::SlotFree(false), 1, T::U32),
        "TlsGetValue" if process => (
            Call::SlotGet {
                fiber: false,
                preserve_error: false,
            },
            1,
            T::Pointer,
        ),
        "TlsGetValue2" if process => (
            Call::SlotGet {
                fiber: false,
                preserve_error: true,
            },
            1,
            T::Pointer,
        ),
        "TlsSetValue" if process => (Call::SlotSet(false), 2, T::U32),
        "FlsAlloc" if fiber => (Call::SlotAllocate(true), 1, T::U32),
        "FlsFree" if fiber => (Call::SlotFree(true), 1, T::U32),
        "FlsGetValue" if fiber => (
            Call::SlotGet {
                fiber: true,
                preserve_error: false,
            },
            1,
            T::Pointer,
        ),
        "FlsGetValue2" if fiber => (
            Call::SlotGet {
                fiber: true,
                preserve_error: true,
            },
            1,
            T::Pointer,
        ),
        "FlsSetValue" if fiber => (Call::SlotSet(true), 2, T::U32),
        "InitializeCriticalSection" if sync => (Call::CriticalInitialize(0), 1, T::Void),
        "InitializeCriticalSectionAndSpinCount" if sync => (Call::CriticalInitialize(1), 2, T::U32),
        "InitializeCriticalSectionEx" if sync => (Call::CriticalInitialize(2), 3, T::U32),
        "EnterCriticalSection" if sync => (Call::CriticalEnter(false), 1, T::Void),
        "TryEnterCriticalSection" if sync => (Call::CriticalEnter(true), 1, T::U32),
        "LeaveCriticalSection" if sync => (Call::CriticalLeave, 1, T::Void),
        "DeleteCriticalSection" if sync => (Call::CriticalDelete, 1, T::Void),
        "SetCriticalSectionSpinCount" if sync => (Call::CriticalSpin, 2, T::U32),
        "GetStartupInfoA" | "GetStartupInfoW" if process => {
            (Call::Startup(name.ends_with('W')), 1, T::Void)
        }
        "GetSystemInfo" if system => (Call::SystemInfo(false), 1, T::Void),
        "GetNativeSystemInfo" if system => (Call::SystemInfo(true), 1, T::Void),
        "GetVersion" if system => (Call::Version, 0, T::U32),
        "GetVersionExA" | "GetVersionExW" if system => (
            Call::VersionInfo {
                wide: Some(name.ends_with('W')),
                nt: false,
            },
            1,
            T::U32,
        ),
        "GetVersionEx" if system => (Call::VersionInfo { wide: None, nt: false }, 1, T::U32),
        "RtlGetVersion" if module == "ntdll" => (
            Call::VersionInfo {
                wide: Some(true),
                nt: true,
            },
            1,
            T::U32,
        ),
        // VerSetConditionMask is a pure bit packer; both spellings share it.
        "VerSetConditionMask" if system || module == "ntdll" => {
            (Call::VersionCondition, 3 + quad, T::U64)
        }
        "VerifyVersionInfo" | "VerifyVersionInfoA" | "VerifyVersionInfoW" if system => {
            (Call::VerifyVersion { nt: false }, 3 + quad, T::U32)
        }
        "RtlVerifyVersionInfo" if module == "ntdll" => {
            (Call::VerifyVersion { nt: true }, 3 + quad, T::U32)
        }
        "RtlGetNtVersionNumbers" if module == "ntdll" => (Call::NtVersionNumbers, 3, T::Void),
        "GlobalMemoryStatusEx" if system => (Call::MemoryStatus(true), 1, T::U32),
        "GlobalMemoryStatus" if system => (Call::MemoryStatus(false), 1, T::Void),
        "GetPhysicallyInstalledSystemMemory" if system => (Call::InstalledMemory, 1, T::U32),
        "GetProcessAffinityMask" if process => (Call::Affinity, 3, T::U32),
        "GetCurrentProcessorNumber" if process || system => {
            (Call::ProcessorNumber(false), 0, T::U32)
        }
        "GetCurrentProcessorNumberEx" if process || system => {
            (Call::ProcessorNumber(true), 1, T::Void)
        }
        "GetActiveProcessorCount" | "GetMaximumProcessorCount" if system => {
            (Call::ProcessorCount, 1, T::U32)
        }
        "GetActiveProcessorGroupCount" | "GetMaximumProcessorGroupCount" if system => {
            (Call::GroupCount, 0, T::U32)
        }
        "IsWow64Process" | "IsWow64Process2" if process => (
            Call::Wow64(name.ends_with('2')),
            if name.ends_with('2') { 3 } else { 2 },
            T::U32,
        ),
        "GetModuleFileNameA" | "GetModuleFileNameW" if loader => {
            (Call::ModuleFilename(name.ends_with('W')), 3, T::U32)
        }
        "AppPolicyGetProcessTerminationMethod" if kernel => (Call::ProcessPolicy, 2, T::U32),
        "ProcessIdToSessionId" if kernel => (Call::SessionId, 2, T::U32),
        "IsProcessorFeaturePresent" if system => (Call::ProcessorFeature, 1, T::U32),
        _ => return None,
    })
}
fn max(engine: &Unicorn<Trace>) -> u64 {
    if engine.get_data().architecture == Architecture::X64 {
        u64::MAX
    } else {
        u32::MAX as u64
    }
}
fn fail(engine: &mut Unicorn<Trace>, error: u32) -> u64 {
    engine.get_data_mut().apis.last_error = error;
    0
}
pub(super) fn process_access(engine: &Unicorn<Trace>, handle: u64, access: u32) -> bool {
    user_processes::process_access(engine, handle, access)
        || engine
            .get_data()
            .apis
            .user_runtime
            .handles
            .get(&handle)
            .is_some_and(|rights| rights & access == access)
}
fn writable(engine: &Unicorn<Trace>, address: u64, size: u64) -> bool {
    address != 0
        && engine
            .get_data()
            .apis
            .memory
            .allows(address, size, P::WRITE)
}
fn put(engine: &mut Unicorn<Trace>, address: u64, bytes: &[u8]) -> Result<()> {
    require(engine, address, bytes.len() as u64, P::WRITE)?;
    crate::cpu::write(engine, address, bytes)
}
fn p(bytes: &mut [u8], at: usize, value: u64, width: usize) {
    bytes[at..at + width].copy_from_slice(&value.to_le_bytes()[..width]);
}
/// The single modeled Windows identity every version query reports. Structure
/// reads and VerifyVersionInfo comparisons share it, so a guest cannot observe
/// one version through `GetVersionEx` and a different one through a predicate.
struct ModeledVersion {
    major: u32,
    minor: u32,
    build: u32,
    platform: u32,
    service_pack_major: u16,
    service_pack_minor: u16,
    suite_mask: u16,
    product_type: u8,
}
fn modeled_version(engine: &Unicorn<Trace>) -> ModeledVersion {
    ModeledVersion {
        major: 10,
        minor: 0,
        build: engine.get_data().machine.windows_build(),
        platform: 2,
        service_pack_major: 0,
        service_pack_minor: 0,
        suite_mask: 0x100,
        product_type: 1,
    }
}
/// VER_EQUAL/GREATER/GREATER_EQUAL/LESS/LESS_EQUAL over one scalar field.
/// VER_AND and VER_OR are only defined for the suite mask, so they answer
/// `None` here and become an invalid-argument result.
fn version_condition(actual: u64, requested: u64, condition: u8) -> Option<bool> {
    Some(match condition {
        1 => actual == requested,
        2 => actual > requested,
        3 => actual >= requested,
        4 => actual < requested,
        5 => actual <= requested,
        _ => return None,
    })
}
fn critical_bytes(engine: &Unicorn<Trace>, state: &CriticalSection) -> Vec<u8> {
    let w = engine.get_data().architecture.width();
    let mut b = vec![0; if w == 8 { 40 } else { 24 }];
    b[w..w + 4].copy_from_slice(&(state.recursion as i32 - 1).to_le_bytes());
    b[w + 4..w + 8].copy_from_slice(&state.recursion.to_le_bytes());
    p(&mut b, w + 8, state.owner.unwrap_or(0), w);
    p(&mut b, 2 * w + 8 + w, state.spin.into(), w);
    b
}
fn critical(engine: &Unicorn<Trace>, address: u64) -> Result<CriticalSection> {
    let state = engine
        .get_data()
        .apis
        .user_runtime
        .critical
        .get(&address)
        .context("Uninitialized critical section")?
        .clone();
    let expected = critical_bytes(engine, &state);
    ensure!(
        read(engine, address, expected.len() as u64)? == expected,
        "Guest critical-section state differs from its owned model"
    );
    Ok(state)
}
pub(crate) fn acquire_critical(
    engine: &mut Unicorn<Trace>,
    address: u64,
    thread: u64,
) -> Result<bool> {
    let mut state = critical(engine, address)?;
    let entered = state.enter(thread).map_err(anyhow::Error::msg)?;
    if entered {
        publish_critical(engine, address, state)?;
    }
    Ok(entered)
}
fn publish_critical(
    engine: &mut Unicorn<Trace>,
    address: u64,
    state: CriticalSection,
) -> Result<()> {
    put(engine, address, &critical_bytes(engine, &state))?;
    engine
        .get_data_mut()
        .apis
        .user_runtime
        .critical
        .insert(address, state);
    Ok(())
}
pub(crate) fn close(engine: &mut Unicorn<Trace>, handle: u64) -> Option<u64> {
    engine
        .get_data_mut()
        .apis
        .user_runtime
        .handles
        .remove(&handle)
        .map(|_| 1)
}
pub(crate) fn require_change(engine: &Unicorn<Trace>, address: u64, size: u64) -> Result<()> {
    let end = address
        .checked_add(size.max(1))
        .context("User runtime mapping range overflow")?;
    ensure!(
        !engine
            .get_data()
            .apis
            .user_runtime
            .strings
            .values()
            .any(|(base, len)| address < base + len && *base < end),
        "Mapping change overlaps owned startup strings"
    );
    Ok(())
}
pub(super) const DESKTOP_NAME: &str = r"WinSta0\Default";

pub(super) fn stable_string(engine: &mut Unicorn<Trace>, text: &str, wide: bool) -> Result<u64> {
    let key = (text.to_owned(), wide);
    if let Some((address, _)) = engine.get_data().apis.user_runtime.strings.get(&key) {
        return Ok(*address);
    }
    let bytes = if wide {
        Encoding::Utf16
    } else {
        Encoding::Cp1252
    }
    .encode(text, true);
    let state = &engine.get_data().apis;
    let plan = state.allocations.allocate(
        &state.memory,
        0,
        bytes.len() as u64,
        vm::RESERVE | vm::COMMIT,
        2,
    )?;
    let address = allocation::apply(engine, plan)?;
    crate::cpu::write(engine, address, &bytes)?;
    engine
        .get_data_mut()
        .apis
        .user_runtime
        .strings
        .insert(key, (address, (bytes.len() as u64).div_ceil(4096) * 4096));
    Ok(address)
}
pub(super) fn invoke(engine: &mut Unicorn<Trace>, args: &[u64], call: Call) -> Result<u64> {
    ensure!(
        !engine.get_data().apis.kernel_mode,
        "Win32 process APIs require a user process"
    );
    let width = engine.get_data().architecture.width();
    let thread = crate::threads::current_id(engine);
    Ok(match call {
        Call::RuntimeTable(call) => {
            crate::native_exceptions::function_tables::invoke(engine, call, args)?
        }
        Call::Exception(call) => crate::native_exceptions::user::invoke(engine, call, args)?,
        Call::Process => max(engine),
        Call::Thread => max(engine) - 1,
        Call::ThreadId => thread,
        Call::ProcessId(is_thread) => {
            if is_thread && args[0] != max(engine) - 1 {
                return Ok(match user_threads::query_id(engine, args[0]) {
                    Ok(id) => id,
                    Err(error) => fail(engine, error),
                });
            }
            if if is_thread {
                args[0] == max(engine) - 1
            } else {
                process_access(engine, args[0], 0)
            } {
                if is_thread { thread } else { OWNER }
            } else {
                fail(engine, 6)
            }
        }
        Call::OpenProcess => {
            if args[2] as u32 != OWNER as u32 {
                return Ok(fail(engine, 87));
            }
            let state = &mut engine.get_data_mut().apis.user_runtime;
            ensure!(state.handles.len() < 4096, "Process handle limit exceeded");
            let h = state.next_handle.max(0x22000000);
            state.next_handle = h + 4;
            state.handles.insert(h, args[0] as u32);
            h
        }
        Call::Debugger => 0,
        Call::RemoteDebugger => {
            if !process_access(engine, args[0], 0x400) && !process_access(engine, args[0], 0x1000) {
                return Ok(fail(
                    engine,
                    if process_access(engine, args[0], 0) {
                        5
                    } else {
                        6
                    },
                ));
            }
            if !writable(engine, args[1], 4) {
                return Ok(fail(engine, if args[1] == 0 { 87 } else { 998 }));
            }
            put(engine, args[1], &[0; 4])?;
            engine.get_data_mut().apis.last_error = 0;
            1
        }
        Call::ProcessExitCode => {
            if !process_access(engine, args[0], 0x1000) && !process_access(engine, args[0], 0x400) {
                return Ok(fail(engine, 6));
            }
            if !writable(engine, args[1], 4) {
                return Ok(fail(engine, 998));
            }
            put(engine, args[1], &259u32.to_le_bytes())?;
            1
        }
        Call::Terminate => {
            if !process_access(engine, args[0], 1) {
                return Ok(fail(engine, 6));
            }
            user_lifecycle::request_exit(engine, args[1] as u32, true)?;
            1
        }
        Call::VirtualEx(operation) => {
            if !process_access(engine, args[0], 8) {
                return Ok(fail(
                    engine,
                    if process_access(engine, args[0], 0) {
                        5
                    } else {
                        6
                    },
                ));
            }
            match operation {
                0 => allocation::allocate(engine, &args[1..])?,
                1 => allocation::free(engine, &args[1..])?,
                _ => allocation::protect(engine, &args[1..])?,
            }
        }
        Call::ProcessMemory(write) => {
            if !process_access(engine, args[0], if write { 0x28 } else { 0x10 }) {
                return Ok(fail(
                    engine,
                    if process_access(engine, args[0], 0) {
                        5
                    } else {
                        6
                    },
                ));
            }
            if args[4] != 0 && !writable(engine, args[4], width as u64) {
                return Ok(fail(engine, 998));
            }
            let size = args[3];
            if size > MAX_TRANSFER {
                return Ok(fail(engine, 87));
            }
            let (source, destination) = if write {
                (args[2], args[1])
            } else {
                (args[1], args[2])
            };
            if size != 0
                && (!engine.get_data().apis.memory.allows(source, size, P::READ)
                    || !writable(engine, destination, size))
            {
                if args[4] != 0 {
                    put(engine, args[4], &[0; 8][..width])?;
                }
                return Ok(fail(engine, 299));
            }
            if size != 0 {
                let bytes = read(engine, source, size)?;
                put(engine, destination, &bytes)?;
                // N15: bytes a guest injects into another process are retained
                // and attributed to that write. Writing into our own process is
                // ordinary memory traffic and is left to the carve transitions.
                if write {
                    if let Some(target) = user_processes::remote_process(engine, args[0]) {
                        carve_remote_write(engine, target, destination, bytes);
                    }
                }
            }
            if args[4] != 0 {
                put(engine, args[4], &size.to_le_bytes()[..width])?;
            }
            1
        }
        Call::Pointer(decode) => {
            let value = if decode {
                args[0].wrapping_sub(1)
            } else {
                args[0].wrapping_add(1)
            };
            value & max(engine)
        }
        Call::SlotAllocate(fiber) => {
            if fiber && args[0] != 0 && require(engine, args[0], 1, P::EXECUTE).is_err() {
                return Ok(fail(engine, 998));
            }
            let index = engine
                .get_data_mut()
                .apis
                .user_runtime
                .slots
                .allocate(fiber);
            if fiber && let Some(index) = index {
                engine
                    .get_data_mut()
                    .apis
                    .user_runtime
                    .fls_callbacks
                    .insert(index, args[0]);
            }
            index.map_or(u32::MAX as u64, u64::from)
        }
        Call::SlotFree(fiber) => {
            let index = args[0] as u32;
            if fiber {
                let calls = take_fls(engine, Some(index), None);
                if !engine
                    .get_data_mut()
                    .apis
                    .user_runtime
                    .slots
                    .free(true, index)
                {
                    return Ok(fail(engine, 87));
                }
                engine
                    .get_data_mut()
                    .apis
                    .user_runtime
                    .fls_callbacks
                    .remove(&index);
                if !calls.is_empty() {
                    return user_callbacks::queue(engine, calls);
                }
                1
            } else if engine
                .get_data_mut()
                .apis
                .user_runtime
                .slots
                .free(false, index)
            {
                1
            } else {
                fail(engine, 87)
            }
        }
        Call::SlotSet(fiber) => {
            if engine.get_data_mut().apis.user_runtime.slots.set(
                fiber,
                args[0] as u32,
                thread,
                args[1],
            ) {
                engine.get_data_mut().apis.last_error = 0;
                1
            } else {
                fail(engine, 87)
            }
        }
        Call::SlotGet {
            fiber,
            preserve_error,
        } => match engine
            .get_data()
            .apis
            .user_runtime
            .slots
            .get(fiber, args[0] as u32, thread)
        {
            Some(value) => {
                if !preserve_error {
                    engine.get_data_mut().apis.last_error = 0;
                }
                value
            }
            None if preserve_error => 0,
            None => fail(engine, 87),
        },
        Call::CriticalInitialize(kind) => {
            if kind == 2 {
                ensure!(
                    args[2] as u32 & !0x11000000 == 0,
                    "Critical-section flags outside the modeled profile"
                );
            }
            ensure!(
                !engine
                    .get_data()
                    .apis
                    .user_runtime
                    .critical
                    .contains_key(&args[0]),
                "Critical section initialized twice"
            );
            publish_critical(
                engine,
                args[0],
                CriticalSection {
                    spin: if kind == 0 { 0 } else { args[1] as u32 },
                    ..Default::default()
                },
            )?;
            1
        }
        Call::CriticalEnter(try_only) => {
            let mut state = critical(engine, args[0])?;
            let entered = state.enter(thread).map_err(anyhow::Error::msg)?;
            if !entered && !try_only {
                return user_threads::wait(
                    engine,
                    user_threads::Wait::Critical(args[0]),
                    u32::MAX,
                    1,
                );
            }
            if entered {
                publish_critical(engine, args[0], state)?;
            }
            u64::from(entered)
        }
        Call::CriticalLeave => {
            let mut state = critical(engine, args[0])?;
            state.leave(thread).map_err(anyhow::Error::msg)?;
            publish_critical(engine, args[0], state)?;
            0
        }
        Call::CriticalDelete => {
            let state = critical(engine, args[0])?;
            ensure!(state.owner.is_none(), "Deleting an owned critical section");
            engine
                .get_data_mut()
                .apis
                .user_runtime
                .critical
                .remove(&args[0]);
            0
        }
        Call::CriticalSpin => {
            let mut state = critical(engine, args[0])?;
            let old = state.spin;
            state.spin = args[1] as u32;
            publish_critical(engine, args[0], state)?;
            old.into()
        }
        Call::Startup(wide) => {
            let size = if width == 8 { 104 } else { 68 };
            require(engine, args[0], size, P::WRITE)?;
            let desktop = stable_string(engine, DESKTOP_NAME, wide)?;
            let image = engine.get_data().apis.persona.model.argv(OWNER)?[0].clone();
            let title = stable_string(engine, &image, wide)?;
            let std = engine
                .get_data()
                .apis
                .crt_stdio
                .model
                .standard_handles(OWNER)?;
            let mut b = vec![0; size as usize];
            b[..4].copy_from_slice(&(size as u32).to_le_bytes());
            p(&mut b, 2 * width, desktop, width);
            p(&mut b, 3 * width, title, width);
            for (i, h) in std.into_iter().enumerate() {
                p(
                    &mut b,
                    if width == 8 { 80 } else { 56 } + i * width,
                    h,
                    width,
                );
            }
            put(engine, args[0], &b)?;
            0
        }
        Call::SystemInfo(native) => {
            let arch64 = native || width == 8;
            let mut b = vec![0; if width == 8 { 48 } else { 36 }];
            b[..2].copy_from_slice(&(if arch64 { 9u16 } else { 0 }).to_le_bytes());
            b[4..8].copy_from_slice(&4096u32.to_le_bytes());
            p(&mut b, 8, 0x10000, width);
            p(
                &mut b,
                8 + width,
                if width == 8 {
                    0x7ffffffeffff
                } else {
                    0x7ffeffff
                },
                width,
            );
            let cpu = &engine.get_data().cpu.profile;
            let logical = cpu.cores * cpu.threads_per_core;
            p(
                &mut b,
                8 + 2 * width,
                if logical == 64 {
                    u64::MAX
                } else {
                    (1u64 << logical) - 1
                },
                width,
            );
            let at = 8 + 3 * width;
            b[at..at + 4].copy_from_slice(&logical.to_le_bytes());
            b[at + 4..at + 8].copy_from_slice(&(if arch64 { 8664u32 } else { 586 }).to_le_bytes());
            b[at + 8..at + 12].copy_from_slice(&65536u32.to_le_bytes());
            b[at + 12..at + 14].copy_from_slice(&6u16.to_le_bytes());
            let revision = ((((cpu.signature >> 16) & 15) << 4 | ((cpu.signature >> 4) & 15)) << 8)
                | (cpu.signature & 15);
            b[at + 14..at + 16].copy_from_slice(&(revision as u16).to_le_bytes());
            put(engine, args[0], &b)?;
            0
        }
        Call::Version => u64::from((engine.get_data().machine.windows_build() << 16) | 10),
        Call::VersionInfo { wide, nt } => {
            let size = u32::from_le_bytes(read(engine, args[0], 4)?.try_into().unwrap()) as usize;
            let basic = match wide {
                Some(true) => 276,
                Some(false) => 148,
                // The generic spelling accepts either structure; only the
                // caller's own size field distinguishes them.
                None if size == 276 || size == 284 => 276,
                None => 148,
            };
            if size != basic && size != basic + 8 {
                if nt {
                    return Ok(0xc000000d);
                }
                return Ok(fail(engine, 87));
            }
            require(engine, args[0], size as u64, P::WRITE)?;
            let version = modeled_version(engine);
            let mut b = vec![0; size];
            b[..4].copy_from_slice(&(size as u32).to_le_bytes());
            b[4..8].copy_from_slice(&version.major.to_le_bytes());
            b[8..12].copy_from_slice(&version.minor.to_le_bytes());
            b[12..16].copy_from_slice(&version.build.to_le_bytes());
            b[16..20].copy_from_slice(&version.platform.to_le_bytes());
            if size > basic {
                b[basic..basic + 2].copy_from_slice(&version.service_pack_major.to_le_bytes());
                b[basic + 2..basic + 4].copy_from_slice(&version.service_pack_minor.to_le_bytes());
                b[basic + 4..basic + 6].copy_from_slice(&version.suite_mask.to_le_bytes());
                b[basic + 6] = version.product_type;
            }
            put(engine, args[0], &b)?;
            if nt { 0 } else { 1 }
        }
        Call::VersionCondition => {
            let x86 = engine.get_data().architecture == Architecture::X86;
            let (mask, type_mask, condition) = if x86 {
                (args[0] | (args[1] << 32), args[2] as u32, args[3])
            } else {
                (args[0], args[1] as u32, args[2])
            };
            let condition = condition & 0x07;
            // A zero type mask or condition leaves the accumulated mask alone,
            // which is what the documented packer does.
            if type_mask == 0 || condition == 0 {
                return Ok(mask);
            }
            // Exactly one slot is written per call, highest type bit first.
            let slot = match type_mask {
                _ if type_mask & 0x80 != 0 => 7,
                _ if type_mask & 0x40 != 0 => 6,
                _ if type_mask & 0x20 != 0 => 5,
                _ if type_mask & 0x10 != 0 => 4,
                _ if type_mask & 0x08 != 0 => 3,
                _ if type_mask & 0x04 != 0 => 2,
                _ if type_mask & 0x02 != 0 => 1,
                _ if type_mask & 0x01 != 0 => 0,
                _ => return Ok(mask),
            };
            mask | (condition << (slot * 3))
        }
        Call::VerifyVersion { nt } => {
            let x86 = engine.get_data().architecture == Architecture::X86;
            let type_mask = args[1] as u32;
            let condition_mask = if x86 {
                args[2] | (args[3] << 32)
            } else {
                args[2]
            };
            // ERROR_BAD_ARGUMENTS/STATUS_INVALID_PARAMETER and
            // ERROR_OLD_WIN_VERSION/STATUS_REVISION_MISMATCH are the only
            // failure shapes this predicate has.
            let invalid = 0xc000_000du64;
            let revision = 0xc000_0059u64;
            if type_mask == 0 || type_mask & !0xff != 0 || condition_mask == 0 {
                return Ok(if nt { invalid } else { fail(engine, 160) });
            }
            let size = u32::from_le_bytes(read(engine, args[0], 4)?.try_into().unwrap()) as usize;
            // The predicate is defined over OSVERSIONINFOEX; the shorter
            // structure has no suite, product or service-pack fields to read.
            let basic = match size {
                156 => 148,
                284 => 276,
                _ => return Ok(if nt { invalid } else { fail(engine, 160) }),
            };
            let requested = read(engine, args[0], size as u64)?;
            let dword = |at: usize| {
                u32::from_le_bytes(requested[at..at + 4].try_into().unwrap()) as u64
            };
            let word =
                |at: usize| u16::from_le_bytes(requested[at..at + 2].try_into().unwrap()) as u64;
            let version = modeled_version(engine);
            let condition = |slot: u32| ((condition_mask >> (slot * 3)) & 0x07) as u8;
            let mut mismatch = false;
            // Product type, suite, platform and build are independent fields.
            for (bit, slot, actual, asked) in [
                (
                    0x80u32,
                    7u32,
                    u64::from(version.product_type),
                    word(basic + 6) & 0xff,
                ),
                (0x08, 3, u64::from(version.platform), dword(16)),
                (0x04, 2, u64::from(version.build), dword(12)),
            ] {
                if type_mask & bit == 0 {
                    continue;
                }
                match version_condition(actual, asked, condition(slot)) {
                    Some(true) => {}
                    Some(false) => mismatch = true,
                    None => return Ok(if nt { invalid } else { fail(engine, 160) }),
                }
            }
            if type_mask & 0x40 != 0 {
                let actual = u64::from(version.suite_mask);
                let asked = word(basic + 4);
                let satisfied = match condition(6) {
                    6 => asked & actual == asked,
                    7 => asked == 0 || asked & actual != 0,
                    _ => return Ok(if nt { invalid } else { fail(engine, 160) }),
                };
                if !satisfied {
                    mismatch = true;
                }
            }
            // Major, minor and the service-pack pair compare as one ordered
            // sequence: the first field that differs decides the answer.
            let sequence = [
                (0x02u32, u64::from(version.major), dword(4)),
                (0x01, u64::from(version.minor), dword(8)),
                (
                    0x20,
                    u64::from(version.service_pack_major),
                    word(basic),
                ),
                (
                    0x10,
                    u64::from(version.service_pack_minor),
                    word(basic + 2),
                ),
            ];
            if type_mask & 0x33 != 0 {
                let slot = if type_mask & 0x02 != 0 {
                    1
                } else if type_mask & 0x01 != 0 {
                    0
                } else if type_mask & 0x20 != 0 {
                    5
                } else {
                    4
                };
                let condition = condition(slot);
                let mut selected = sequence
                    .iter()
                    .filter(|(bit, _, _)| type_mask & bit != 0)
                    .map(|(_, actual, asked)| (*actual, *asked));
                if condition == 1 {
                    if selected.clone().any(|(actual, asked)| actual != asked) {
                        mismatch = true;
                    }
                } else if !(1..=5).contains(&condition) {
                    return Ok(if nt { invalid } else { fail(engine, 160) });
                } else {
                    let satisfied = match selected.find(|(actual, asked)| actual != asked) {
                        None => matches!(condition, 3 | 5),
                        Some((actual, asked)) => {
                            if actual > asked {
                                matches!(condition, 2 | 3)
                            } else {
                                matches!(condition, 4 | 5)
                            }
                        }
                    };
                    if !satisfied {
                        mismatch = true;
                    }
                }
            }
            if mismatch {
                return Ok(if nt { revision } else { fail(engine, 1150) });
            }
            if nt { 0 } else { 1 }
        }
        Call::NtVersionNumbers => {
            let version = modeled_version(engine);
            // The real helper reports the build with its high nibble set.
            for (at, value) in [
                (args[0], version.major),
                (args[1], version.minor),
                (args[2], version.build | 0xf000_0000),
            ] {
                if at != 0 {
                    put(engine, at, &value.to_le_bytes())?;
                }
            }
            0
        }
        Call::MemoryStatus(extended) => {
            let total = engine.get_data().machine.physical_pages() as u64 * 4096;
            let available = engine
                .get_data()
                .machine
                .receipt()
                .map_or(total / 2, |r| r.available_memory_mb * 1024 * 1024);
            let load = ((total - available.min(total)) * 100 / total) as u32;
            let size = if extended { 64 } else { 8 + 6 * width };
            if extended && read(engine, args[0], 4)? != 64u32.to_le_bytes() {
                return Ok(fail(engine, 87));
            }
            let mut b = vec![0; size];
            b[..4].copy_from_slice(&(size as u32).to_le_bytes());
            b[4..8].copy_from_slice(&load.to_le_bytes());
            let values = [
                total,
                available,
                total,
                available,
                if width == 8 {
                    0x7fffffff0000
                } else {
                    0x7fff0000
                },
                if width == 8 {
                    0x7ffff0000000
                } else {
                    0x7ffe0000
                },
            ];
            for (i, value) in values.into_iter().enumerate() {
                p(
                    &mut b,
                    8 + i * if extended { 8 } else { width },
                    if extended || width == 8 {
                        value
                    } else {
                        value.min(u32::MAX as u64)
                    },
                    if extended { 8 } else { width },
                );
            }
            put(engine, args[0], &b)?;
            1
        }
        Call::InstalledMemory => {
            if !writable(engine, args[0], 8) {
                return Ok(fail(engine, 87));
            }
            put(
                engine,
                args[0],
                &(engine.get_data().machine.physical_pages() as u64 * 4).to_le_bytes(),
            )?;
            1
        }
        Call::Affinity => {
            if !process_access(engine, args[0], 0x400) && !process_access(engine, args[0], 0x1000) {
                return Ok(fail(engine, 6));
            }
            if !writable(engine, args[1], width as u64) || !writable(engine, args[2], width as u64)
            {
                return Ok(fail(engine, 87));
            }
            let n = (engine.get_data().cpu.profile.cores
                * engine.get_data().cpu.profile.threads_per_core)
                .min((width * 8) as u32);
            let mask = if n == 64 { u64::MAX } else { (1u64 << n) - 1 };
            for at in [args[1], args[2]] {
                put(engine, at, &mask.to_le_bytes()[..width])?;
            }
            1
        }
        Call::ProcessorNumber(extended) => {
            let n = engine.get_data().cpu.processor;
            if extended {
                put(engine, args[0], &[0, 0, n as u8, 0])?;
                0
            } else {
                n.into()
            }
        }
        Call::ProcessorCount => {
            if args[0] as u16 != 0 && args[0] as u16 != 0xffff {
                return Ok(fail(engine, 87));
            }
            (engine.get_data().cpu.profile.cores * engine.get_data().cpu.profile.threads_per_core)
                .into()
        }
        Call::GroupCount => 1,
        Call::Wow64(two) => {
            if !process_access(engine, args[0], 0x400) && !process_access(engine, args[0], 0x1000) {
                return Ok(fail(engine, 6));
            }
            if !writable(engine, args[1], if two { 2 } else { 4 })
                || two && !writable(engine, args[2], 2)
            {
                return Ok(fail(engine, 87));
            }
            if two {
                put(
                    engine,
                    args[1],
                    &(if width == 4 { 0x14cu16 } else { 0 }).to_le_bytes(),
                )?;
                put(engine, args[2], &0x8664u16.to_le_bytes())?;
            } else {
                put(engine, args[1], &u32::from(width == 4).to_le_bytes())?;
            }
            1
        }
        Call::ModuleFilename(wide) => {
            let module = if args[0] == 0 {
                engine.get_data().apis.modules.primary()
            } else {
                engine
                    .get_data()
                    .apis
                    .modules
                    .modules()
                    .find(|m| m.base == args[0])
            };
            let path = module
                .and_then(|m| m.provenance())
                .map(|p| p.guest_path.clone());
            let Some(path) = path else {
                return Ok(fail(engine, 126));
            };
            let capacity = args[2] as u32 as usize;
            if capacity == 0 {
                return Ok(fail(engine, 122));
            }
            ensure!(capacity <= 32768, "Module filename capacity exceeds bound");
            let encoding = if wide {
                Encoding::Utf16
            } else {
                Encoding::Cp1252
            };
            let bytes = encoding.encode(&path, true);
            let unit = encoding.width();
            let truncated = bytes.len() / unit > capacity;
            let mut output = bytes[..bytes.len().min(capacity * unit)].to_vec();
            if truncated {
                let len = output.len();
                output[len - unit..].fill(0);
                engine.get_data_mut().apis.last_error = 122;
            }
            put(engine, args[1], &output)?;
            if truncated {
                capacity as u64
            } else {
                (bytes.len() / unit - 1) as u64
            }
        }
        Call::ProcessPolicy => {
            if args[0] != max(engine) - 3 {
                return Ok(6);
            }
            if !writable(engine, args[1], 4) {
                87
            } else {
                put(engine, args[1], &[0; 4])?;
                0
            }
        }
        Call::SessionId => {
            if args[0] as u32 != OWNER as u32 || !writable(engine, args[1], 4) {
                return Ok(fail(engine, 87));
            }
            put(engine, args[1], &1u32.to_le_bytes())?;
            1
        }
        Call::ProcessorFeature => {
            let leaf1 = engine
                .get_data()
                .cpu
                .profile
                .leaf(1, 0, engine.get_data().cpu.processor);
            let leaf7 = engine
                .get_data()
                .cpu
                .profile
                .leaf(7, 0, engine.get_data().cpu.processor);
            let feature = match args[0] as u32 {
                2 => leaf1[3] & (1 << 8) != 0,
                3 => leaf1[3] & (1 << 23) != 0,
                6 => leaf1[3] & (1 << 25) != 0,
                8 => leaf1[3] & (1 << 4) != 0,
                9 => leaf1[3] & (1 << 6) != 0,
                10 => leaf1[3] & (1 << 26) != 0,
                12 => true,
                13 => leaf1[2] & 1 != 0,
                14 => leaf1[2] & (1 << 13) != 0,
                17 => leaf1[2] & (1 << 26) != 0,
                23 => true,
                28 => leaf1[2] & (1 << 30) != 0,
                36 => leaf1[2] & (1 << 9) != 0,
                37 => leaf1[2] & (1 << 19) != 0,
                38 => leaf1[2] & (1 << 20) != 0,
                39 => leaf1[2] & (1 << 28) != 0,
                40 => leaf7[1] & (1 << 5) != 0,
                _ => false,
            };
            u64::from(feature)
        }
    })
}

/// Retain and attribute bytes the guest wrote into another process's address
/// space. Opt-in with the submitted request's carve configuration, user-mode
/// only, bounded by the single-artifact cap; an all-zero payload is not an
/// artifact. This records what was injected, never that it executed.
pub(super) fn carve_remote_write(
    engine: &mut Unicorn<Trace>,
    target_process_id: u64,
    destination: u64,
    bytes: Vec<u8>,
) {
    if !engine.get_data().carve_executable_regions || engine.get_data().apis.kernel_mode {
        return;
    }
    if bytes.is_empty()
        || bytes.len() > emumee_core::pe_carve::MAX_ARTIFACT_BYTES
        || bytes.iter().all(|byte| *byte == 0)
    {
        return;
    }
    let context = serde_json::json!({
        "transition": "remote_write",
        "guest_base": destination,
        "region_bytes": bytes.len() as u64,
        "target_process_id": target_process_id,
        "capture_boundary": "api_call",
    });
    let context = context.as_object().expect("object literal").clone();
    let _ = emumee_core::artifact_bridge::capture_remote_write(
        &mut engine.get_data_mut().apis.captures,
        bytes,
        "remote_write",
        context,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn user_runtime_getvalue2_preserves_last_error_for_zero_valid_and_invalid_results() {
        for arch in [Architecture::X86, Architecture::X64] {
            let mut engine = crate::new_engine(arch).unwrap();
            let mut observed = Vec::new();
            for fiber in [false, true] {
                for allocated in [false, true] {
                    let index = if allocated {
                        engine
                            .get_data_mut()
                            .apis
                            .user_runtime
                            .slots
                            .allocate(fiber)
                            .unwrap()
                    } else {
                        u32::MAX
                    };
                    engine.get_data_mut().apis.last_error = 0x12345678;
                    let value = invoke(
                        &mut engine,
                        &[index.into()],
                        Call::SlotGet {
                            fiber,
                            preserve_error: true,
                        },
                    )
                    .unwrap();
                    observed.push((value, engine.get_data().apis.last_error));
                }
            }
            drop(engine);
            assert_eq!(observed, vec![(0, 0x12345678); 4], "{arch:?}");
        }
    }
}
