//! Harmless deterministic PE fixtures, generated without any external input.
use crate::pe::Architecture;
mod callback;
mod dynamic_loader;
mod native_loader;
pub use dynamic_loader::{DynamicLoaderFixture, dynamic_loader_probe};
pub use native_loader::{LoaderFixture, native_loader_probe};
mod configured;
mod plan;
pub use plan::installed_plan_probe;
mod kernel_files;
mod kernel_prompt;
mod kernel_tail;
pub use kernel_tail::{TailDiagnostic, kernel_tail_probe};
mod kernel_tid;
pub use kernel_tid::kernel_tid_probe;
mod kernel_diagnostics;
mod kernel_dpc;
mod kernel_rtl;
mod kernel_time;
mod kernel_timers;
pub use kernel_diagnostics::{DiagnosticFixture, kernel_diagnostic_probe};
pub use kernel_dpc::{DpcFixture, kernel_dpc_idle_budget_probe, kernel_dpc_probe};
pub use kernel_time::{TimeFixture, kernel_time_probe};
pub use kernel_timers::{TimerFixture, kernel_timer_probe};
mod native_registry;
pub use kernel_files::{NativeFilesFixture, native_files_document, native_files_probe};
pub use kernel_rtl::{RtlFixture, kernel_rtl_probe};
pub use native_registry::{NativeRegistryFixture, native_registry_document, native_registry_probe};
mod environment_block;
mod persona;
pub use configured::{ConfiguredFixture, configured_document, configured_probe};
pub use environment_block::{EnvironmentBlockFixture, environment_block_probe};
pub use persona::{PersonaFixture, persona_probe};
mod console;
mod vfs_metadata;
mod vfs_mutation;
pub use vfs_metadata::{VfsFixture, vfs_probe};
pub use vfs_mutation::{MutationFixture, mutation_probe};
mod cpu;
mod crt;
mod crt_format;
pub use console::{ConsoleFixture, console_probe};
mod crt_stdio;
pub use crt_format::{FormatFixture, format_probe};
pub use crt_stdio::{StdioFixture, stdio_probe};
mod download;
mod heap;
mod mdl;
mod provider_metadata;
mod provider_mixed;
pub use callback::{CallbackFixture, callback_probe};
pub use provider_metadata::{MetadataFixture, provider_metadata_probe};
pub use provider_mixed::{ProviderMixedFixture, provider_mixed_probe};
mod cr8;
mod ipi;
pub use cr8::{Cr8Fixture, cr8_probe};
mod kernel_environment;
mod kernel_modules;
mod kernel_objects;
mod kernel_spin;
mod kernel_sync;
pub use kernel_modules::{ModuleFixture, kernel_modules_probe};
pub use kernel_spin::{SpinFixture, kernel_spin_probe};
pub use kernel_sync::{SyncFixture, kernel_sync_probe};
mod kernel_thread_objects;
mod kernel_waits;
pub use ipi::{IpiFixture, ipi_probe};
pub use kernel_objects::{ObjectFixture, kernel_objects_probe};
pub use kernel_thread_objects::{ThreadObjectFixture, kernel_thread_objects_probe};
pub use kernel_waits::{WaitFixture, kernel_waits_probe};
mod registry;
mod rundown;
pub use crt::{CrtFixture, crt_probe};
pub use kernel_environment::{EnvironmentFixture, kernel_environment_probe};
pub use mdl::{MdlFixture, mdl_probe};
pub use registry::{RegistryFixture, registry_probe};
pub use rundown::{RundownFixture, rundown_probe};
mod internet;
pub use internet::{InternetFixture, internet_probe};
pub mod http;
mod winhttp;
pub use download::{DownloadFixture, download_probe};
pub use heap::{HeapFixture, heap_probe};
pub use winhttp::{WinHttpFixture, winhttp_probe};
mod managed;
pub use cpu::{CpuFixture, cpu_probe};
pub use managed::{CilFixture, cil_probe, managed_indicator_probe, managed_probe};

fn put16(out: &mut [u8], at: usize, value: u16) {
    out[at..at + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(out: &mut [u8], at: usize, value: u32) {
    out[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(out: &mut [u8], at: usize, value: u64) {
    out[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

pub fn counted_driver(architecture: Architecture, iterations: u32) -> Vec<u8> {
    assert!(iterations > 0);
    let wide = architecture == Architecture::X64;
    let mut out = vec![0; 0x600];
    out[..2].copy_from_slice(b"MZ");
    put32(&mut out, 0x3c, 0x80);
    out[0x80..0x84].copy_from_slice(b"PE\0\0");
    put16(&mut out, 0x84, if wide { 0x8664 } else { 0x14c });
    put16(&mut out, 0x86, 2);
    put16(&mut out, 0x94, if wide { 0xf0 } else { 0xe0 });
    put16(&mut out, 0x96, 0x2022);
    let o = 0x98;
    put16(&mut out, o, if wide { 0x20b } else { 0x10b });
    put32(&mut out, o + 4, 0x200);
    put32(&mut out, o + 8, 0x200);
    put32(&mut out, o + 16, 0x1000);
    put32(&mut out, o + 20, 0x1000);
    if wide {
        put64(&mut out, o + 24, 0x140000000)
    } else {
        put32(&mut out, o + 28, 0x400000)
    };
    put32(&mut out, o + 32, 4096);
    put32(&mut out, o + 36, 512);
    put32(&mut out, o + 56, 0x3000);
    put32(&mut out, o + 60, 512);
    put16(&mut out, o + 68, 1);
    put32(&mut out, o + if wide { 108 } else { 92 }, 16);
    let table = o + if wide { 0xf0 } else { 0xe0 };
    for (i, name, rva, offset, flags) in [
        (0, b".text\0\0\0", 0x1000, 0x200, 0x60000020),
        (1, b".data\0\0\0", 0x2000, 0x400, 0xc0000040),
    ] {
        let s = table + i * 40;
        out[s..s + 8].copy_from_slice(name);
        put32(&mut out, s + 8, 512);
        put32(&mut out, s + 12, rva);
        put32(&mut out, s + 16, 512);
        put32(&mut out, s + 20, offset);
        put32(&mut out, s + 36, flags);
    }
    let mut code = vec![0xb9];
    code.extend(iterations.to_le_bytes()); // mov ecx,N
    code.extend([0x31, 0xc0]); // xor eax,eax
    code.extend([0xff, 0xc0, 0xff, 0xc9, 0x75, 0xfa, 0xc3]); // inc eax; dec ecx; jnz; ret
    out[0x200..0x200 + code.len()].copy_from_slice(&code);
    out
}
/// A relocatable driver whose code calls through a relocated absolute pointer.
pub fn relocating_driver(architecture: Architecture) -> Vec<u8> {
    let wide = architecture == Architecture::X64;
    let mut data = counted_driver(architecture, 17);
    let preferred = if wide { 0x140000000u64 } else { 0x400000 };
    let mut code = if wide {
        vec![0x48, 0x8b, 0x1d]
    } else {
        vec![0xa1]
    };
    if wide {
        code.extend((0x2000i32 - 0x1007).to_le_bytes());
        code.extend([0x48, 0x89, 0xd8, 0x48, 0xc1, 0xe8, 63]);
    } else {
        code.extend(((preferred + 0x2000) as u32).to_le_bytes());
        code.extend([0x89, 0xc3, 0xc1, 0xe8, 31]);
    }
    code.extend([0x3d, 1, 0, 0, 0, 0x74, 1, 0xcc]);
    if wide {
        code.extend([0x48, 0x89, 0xd8, 0x48, 0x2d]);
        code.extend(0x1180u32.to_le_bytes());
        code.extend([0x48, 0x3b, 0x41, 24]);
    } else {
        code.extend([0x8b, 0x54, 0x24, 4, 0x89, 0xd8, 0x2d]);
        code.extend(0x1180u32.to_le_bytes());
        code.extend([0x3b, 0x42, 12]);
    }
    code.extend([0x74, 1, 0xcc, 0xff, 0xd3, 0xc3]);
    data[0x200..0x400].fill(0xcc);
    data[0x200..0x200 + code.len()].copy_from_slice(&code);
    data[0x380..0x386].copy_from_slice(&[0xb8, 17, 0, 0, 0, 0xc3]);
    if wide {
        put64(&mut data, 0x400, preferred + 0x1180);
    } else {
        put32(&mut data, 0x400, (preferred + 0x1180) as u32);
    }
    let dd = 0x98 + if wide { 112 } else { 96 };
    put32(&mut data, dd + 5 * 8, 0x2080);
    put32(&mut data, dd + 5 * 8 + 4, if wide { 12 } else { 24 });
    let mut block = 0x480;
    if !wide {
        put32(&mut data, block, 0x1000);
        put32(&mut data, block + 4, 12);
        put16(&mut data, block + 8, 0x3001);
        put16(&mut data, block + 10, 0);
        block += 12;
    }
    put32(&mut data, block, 0x2000);
    put32(&mut data, block + 4, 12);
    put16(&mut data, block + 8, if wide { 0xa000 } else { 0x3000 });
    put16(&mut data, block + 10, 0);
    data
}

#[derive(Clone, Copy, Debug)]
pub enum ApiFixture {
    NativeLoader(LoaderFixture),
    DynamicLoader(DynamicLoaderFixture),
    Crt(CrtFixture),
    Stdio(StdioFixture),
    Format(FormatFixture),
    Console(ConsoleFixture),
    Vfs(VfsFixture, bool),
    Mutation(MutationFixture, bool),
    Registry(RegistryFixture, bool),
    Mdl(MdlFixture),
    Callback(CallbackFixture),
    Rundown(RundownFixture),
    Environment(EnvironmentFixture),
    Objects(ObjectFixture),
    ThreadObjects(ThreadObjectFixture),
    GuestTid,
    Waits(WaitFixture),
    Ipi(IpiFixture),
    Cr8(Cr8Fixture),
    ProviderMixed(ProviderMixedFixture),
    Metadata(MetadataFixture),
    Sync(SyncFixture),
    KernelSpin(SpinFixture),
    Modules(ModuleFixture),
    Persona(PersonaFixture, bool),
    Configured(ConfiguredFixture, bool),
    NativeRegistry(NativeRegistryFixture),
    NativeFiles(NativeFilesFixture),
    KernelRtl(RtlFixture),
    KernelTimeConversion(TimeFixture),
    KernelTimers(TimerFixture),
    KernelDpc(DpcFixture),
    KernelDpcIdleBudget,
    KernelDiagnostic(DiagnosticFixture),
    EnvironmentBlock(EnvironmentBlockFixture, bool),
    Heap(HeapFixture),
    PoolLifecycle,
    PoolZeroNx,
    PoolExecutable,
    PoolNxExecute,
    PoolFreedRead,
    PoolBadTag,
    PoolPagedIrql,
    PoolBadFlags,
    PoolTooLarge,
    PoolDoubleFree,
    KernelCatalogCall,
    KernelCatalogCodeRead,
    KernelCatalogDataRead,
    KernelResolve,
    KernelResolveBadLength,
    KernelResolveIrql,
    KernelResolveUnknown,
    UserResolveA,
    UserResolveW,
    UserResolveUnknown,
    UserResolveBadModule,
    UserState,
    Copy,
    WriteCode,
    Prompt,
    PromptReadOnly,
    Unsupported,
    VirtualLifecycle,
    VirtualWriteProtected,
    VirtualReleasedRead,
    VirtualReserveRead,
    VirtualBadProtectOutput,
    VirtualRecommit,
    ApiLoop,
    FileRoundTripA,
    FileRoundTripW,
    FileReadOnly,
    FileReadCode,
    GuardedMutex,
    GuardedBusy,
    GuardedBadRelease,
    GuardedIrql,
    CriticalUnderflow,
    SystemThread,
    SystemThreadReturn,
    ThreadMsr,
    ThreadTsc,
    KernelApiAddress,
    UserApiAddress,
    SystemThreadBadStart,
    MutexHandoff,
    MutexDeadlock,
    UserTime,
    KernelTime,
    TimeBadOutput,
    EventAuto,
    EventManual,
    EventTimeout,
    EventLongTimeout,
    EventAbsolute,
    EventDeadlock,
    EventHandoff,
    EventIrql,
    EventAlertable,
    EventTamper,
}

#[derive(Clone, Copy, Debug)]
pub enum LinkedFixture {
    Direct,
    Forwarded,
}
/// Companions have no DllMain. Their actual CPU export body returns 17.
pub fn linked_probe(
    architecture: Architecture,
    kind: LinkedFixture,
) -> (Vec<u8>, Vec<(String, Vec<u8>)>) {
    let wide = architecture == Architecture::X64;
    let mut main = api_probe(architecture, ApiFixture::Unsupported);
    main[0x440..0x460].fill(0);
    main[0x440..0x44a].copy_from_slice(b"guest.dll\0");
    main[0x702..0x740].fill(0);
    main[0x702..0x708].copy_from_slice(b"Alpha\0");
    fn companion(
        architecture: Architecture,
        base: u64,
        name: &[u8],
        forwarder: Option<&[u8]>,
    ) -> Vec<u8> {
        let wide = architecture == Architecture::X64;
        let mut data = counted_driver(architecture, 17);
        put16(&mut data, 0x98 + 68, 3);
        put32(&mut data, 0x98 + 16, 0); // No initialization routine in this fixture.
        if wide {
            put64(&mut data, 0x98 + 24, base);
        } else {
            put32(&mut data, 0x98 + 28, base as u32);
        }
        let dd = 0x98 + if wide { 112 } else { 96 };
        put32(&mut data, dd, 0x2000);
        put32(&mut data, dd + 4, 0x100);
        for (at, value) in [
            (0x410, 1),
            (0x414, 1),
            (0x418, 1),
            (0x41c, 0x2040),
            (0x420, 0x2050),
            (0x424, 0x2060),
            (0x450, 0x20a0),
        ] {
            put32(&mut data, at, value);
        }
        data[0x4a0..0x4a0 + name.len()].copy_from_slice(name);
        if let Some(text) = forwarder {
            put32(&mut data, 0x440, 0x2080);
            data[0x480..0x480 + text.len()].copy_from_slice(text);
        } else {
            put32(&mut data, 0x440, 0x1000);
        }
        data
    }
    let first = if wide { 0x150000000 } else { 0x500000 };
    let second = if wide { 0x160000000 } else { 0x600000 };
    let companions = match kind {
        LinkedFixture::Direct => vec![(
            "guest.dll".into(),
            companion(architecture, first, b"Alpha\0", None),
        )],
        LinkedFixture::Forwarded => vec![
            (
                "guest.dll".into(),
                companion(architecture, first, b"Alpha\0", Some(b"other.Target\0")),
            ),
            (
                "other.dll".into(),
                companion(architecture, second, b"Target\0", None),
            ),
        ],
    };
    (main, companions)
}

pub fn api_probe(architecture: Architecture, fixture: ApiFixture) -> Vec<u8> {
    if let ApiFixture::KernelDiagnostic(kind) = fixture {
        return kernel_diagnostic_probe(architecture, kind);
    }
    if let ApiFixture::KernelDpc(kind) = fixture {
        return kernel_dpc_probe(architecture, kind);
    }
    if matches!(fixture, ApiFixture::KernelDpcIdleBudget) {
        return kernel_dpc_idle_budget_probe(architecture);
    }
    if let ApiFixture::KernelTimers(kind) = fixture {
        return kernel_timer_probe(architecture, kind);
    }
    if let ApiFixture::DynamicLoader(kind) = fixture {
        return dynamic_loader_probe(architecture, kind).0;
    }
    if let ApiFixture::NativeLoader(kind) = fixture {
        return native_loader_probe(architecture, kind).0;
    }
    if matches!(fixture, ApiFixture::GuestTid) {
        return kernel_tid_probe(architecture);
    }
    if let ApiFixture::KernelSpin(kind) = fixture {
        return kernel_spin_probe(architecture, kind);
    }
    if let ApiFixture::KernelTimeConversion(kind) = fixture {
        return kernel_time_probe(architecture, kind);
    }
    if let ApiFixture::KernelRtl(kind) = fixture {
        return kernel_rtl_probe(architecture, kind);
    }
    if let ApiFixture::Modules(kind) = fixture {
        return kernel_modules_probe(architecture, kind);
    }
    if let ApiFixture::NativeFiles(kind) = fixture {
        return native_files_probe(architecture, kind);
    }
    if let ApiFixture::NativeRegistry(kind) = fixture {
        return native_registry_probe(architecture, kind);
    }
    if let ApiFixture::Sync(kind) = fixture {
        return kernel_sync_probe(architecture, kind);
    }
    if let ApiFixture::Metadata(kind) = fixture {
        return provider_metadata_probe(architecture, kind);
    }
    if let ApiFixture::Cr8(kind) = fixture {
        return cr8_probe(architecture, kind);
    }
    if let ApiFixture::Configured(kind, unicode) = fixture {
        return configured_probe(architecture, kind, unicode);
    }
    if let ApiFixture::ProviderMixed(kind) = fixture {
        return provider_mixed_probe(architecture, kind);
    }
    if let ApiFixture::Ipi(kind) = fixture {
        return ipi_probe(architecture, kind);
    }
    if let ApiFixture::EnvironmentBlock(kind, unicode) = fixture {
        return environment_block_probe(architecture, kind, unicode);
    }
    if let ApiFixture::Waits(kind) = fixture {
        return kernel_waits_probe(architecture, kind);
    }
    if let ApiFixture::Mutation(kind, unicode) = fixture {
        return mutation_probe(architecture, kind, unicode);
    }
    if let ApiFixture::ThreadObjects(kind) = fixture {
        return kernel_thread_objects_probe(architecture, kind);
    }
    if let ApiFixture::Vfs(kind, unicode) = fixture {
        return vfs_probe(architecture, kind, unicode);
    }
    if let ApiFixture::Objects(kind) = fixture {
        return kernel_objects_probe(architecture, kind);
    }
    if let ApiFixture::Console(kind) = fixture {
        return console_probe(architecture, kind);
    }
    if let ApiFixture::Environment(kind) = fixture {
        return kernel_environment_probe(architecture, kind);
    }
    if let ApiFixture::Format(kind) = fixture {
        return format_probe(architecture, kind);
    }
    if let ApiFixture::Stdio(kind) = fixture {
        return stdio_probe(architecture, kind);
    }
    if let ApiFixture::Rundown(kind) = fixture {
        return rundown_probe(architecture, kind);
    }
    if let ApiFixture::Persona(kind, unicode) = fixture {
        return persona_probe(architecture, kind, unicode);
    }
    if let ApiFixture::Callback(kind) = fixture {
        return callback_probe(architecture, kind);
    }
    if let ApiFixture::Mdl(kind) = fixture {
        return mdl_probe(architecture, kind);
    }
    if let ApiFixture::Registry(kind, unicode) = fixture {
        return registry_probe(architecture, kind, unicode);
    }
    if let ApiFixture::Crt(kind) = fixture {
        return crt_probe(architecture, kind);
    }
    if let ApiFixture::Heap(kind) = fixture {
        return heap_probe(architecture, kind);
    }
    if architecture == Architecture::X64
        && matches!(fixture, ApiFixture::Prompt | ApiFixture::PromptReadOnly)
    {
        return kernel_prompt::probe(matches!(fixture, ApiFixture::PromptReadOnly));
    }
    let wide = architecture == Architecture::X64;
    let base = if wide { 0x140000000u64 } else { 0x400000 };
    let width = architecture.width();
    let mut data = counted_driver(architecture, 1);
    data.resize(0x1400, 0);
    let section = 0x98 + if wide { 0xf0 } else { 0xe0 } + 40;
    put32(&mut data, section + 8, 0x1000);
    put32(&mut data, section + 16, 0x1000);
    let dd = 0x98 + if wide { 112 } else { 96 };
    put32(&mut data, dd + 8, 0x2000);
    put32(&mut data, dd + 12, 40);
    let names: &[&str] = match fixture {
        ApiFixture::Mutation(_, _)
        | ApiFixture::Vfs(_, _)
        | ApiFixture::Console(_)
        | ApiFixture::Format(_)
        | ApiFixture::Stdio(_)
        | ApiFixture::Crt(_)
        | ApiFixture::Heap(_)
        | ApiFixture::Registry(_, _)
        | ApiFixture::Mdl(_)
        | ApiFixture::Modules(_)
        | ApiFixture::Sync(_)
        | ApiFixture::KernelSpin(_)
        | ApiFixture::Metadata(_)
        | ApiFixture::ProviderMixed(_)
        | ApiFixture::Cr8(_)
        | ApiFixture::Ipi(_)
        | ApiFixture::Waits(_)
        | ApiFixture::ThreadObjects(_)
        | ApiFixture::GuestTid
        | ApiFixture::Objects(_)
        | ApiFixture::Environment(_)
        | ApiFixture::Rundown(_)
        | ApiFixture::Callback(_)
        | ApiFixture::EnvironmentBlock(_, _)
        | ApiFixture::Configured(_, _)
        | ApiFixture::NativeRegistry(_)
        | ApiFixture::NativeLoader(_)
        | ApiFixture::DynamicLoader(_)
        | ApiFixture::NativeFiles(_)
        | ApiFixture::KernelRtl(_)
        | ApiFixture::KernelTimeConversion(_)
        | ApiFixture::KernelTimers(_)
        | ApiFixture::KernelDpc(_)
        | ApiFixture::KernelDpcIdleBudget
        | ApiFixture::KernelDiagnostic(_)
        | ApiFixture::Persona(_, _) => {
            unreachable!("special generated fixtures handled separately")
        }
        ApiFixture::PoolLifecycle
        | ApiFixture::PoolZeroNx
        | ApiFixture::PoolExecutable
        | ApiFixture::PoolNxExecute
        | ApiFixture::PoolFreedRead
        | ApiFixture::PoolBadTag
        | ApiFixture::PoolPagedIrql
        | ApiFixture::PoolBadFlags
        | ApiFixture::PoolTooLarge
        | ApiFixture::PoolDoubleFree => &[
            "ExAllocatePool2",
            "ExAllocatePoolWithTag",
            "ExFreePoolWithTag",
            "ExFreePool",
            "KeRaiseIrql",
            "KeLowerIrql",
        ],
        ApiFixture::KernelResolve
        | ApiFixture::KernelResolveBadLength
        | ApiFixture::KernelResolveIrql
        | ApiFixture::KernelResolveUnknown
        | ApiFixture::KernelCatalogCall
        | ApiFixture::KernelCatalogCodeRead
        | ApiFixture::KernelCatalogDataRead => &[
            "MmGetSystemRoutineAddress",
            "KeRaiseIrql",
            "KeGetCurrentIrql",
        ],
        ApiFixture::UserResolveA
        | ApiFixture::UserResolveW
        | ApiFixture::UserResolveUnknown
        | ApiFixture::UserResolveBadModule => &[
            if matches!(fixture, ApiFixture::UserResolveW) {
                "GetModuleHandleW"
            } else {
                "GetModuleHandleA"
            },
            "GetProcAddress",
            "GetLastError",
            "GetCurrentProcessId",
        ],
        ApiFixture::KernelApiAddress => &["KeGetCurrentIrql"],
        ApiFixture::UserApiAddress => &["GetCurrentProcessId"],
        ApiFixture::EventAuto
        | ApiFixture::EventManual
        | ApiFixture::EventTimeout
        | ApiFixture::EventLongTimeout
        | ApiFixture::EventAbsolute
        | ApiFixture::EventDeadlock
        | ApiFixture::EventHandoff
        | ApiFixture::EventIrql
        | ApiFixture::EventAlertable
        | ApiFixture::EventTamper => &[
            "KeInitializeEvent",
            "KeWaitForSingleObject",
            "KeSetEvent",
            "KeResetEvent",
            "KeClearEvent",
            "PsCreateSystemThread",
            "PsTerminateSystemThread",
            "KeRaiseIrql",
        ],
        ApiFixture::UserState => &[
            "GetCurrentProcessId",
            "SetLastError",
            "GetLastError",
            "Sleep",
            "GetTickCount64",
        ],
        ApiFixture::Copy | ApiFixture::WriteCode => &["RtlMoveMemory"],
        ApiFixture::Prompt | ApiFixture::PromptReadOnly => &["DbgPrompt"],
        ApiFixture::Unsupported => &["EmumeeUnimplementedFixtureApi"],
        ApiFixture::ApiLoop => &["SetLastError", "GetLastError"],
        ApiFixture::UserTime | ApiFixture::TimeBadOutput => &[
            "QueryPerformanceFrequency",
            "QueryPerformanceCounter",
            "Sleep",
            "GetSystemTimeAsFileTime",
            "GetLastError",
        ],
        ApiFixture::KernelTime => &[
            "KeQueryPerformanceCounter",
            "KeQuerySystemTimePrecise",
            "KeQueryInterruptTime",
        ],
        ApiFixture::SystemThread
        | ApiFixture::SystemThreadReturn
        | ApiFixture::ThreadMsr
        | ApiFixture::ThreadTsc
        | ApiFixture::SystemThreadBadStart => &["PsCreateSystemThread", "PsTerminateSystemThread"],
        ApiFixture::MutexHandoff | ApiFixture::MutexDeadlock => &[
            "KeInitializeGuardedMutex",
            "PsCreateSystemThread",
            "KeAcquireGuardedMutex",
            "KeReleaseGuardedMutex",
            "PsTerminateSystemThread",
            "KeGetCurrentIrql",
        ],
        ApiFixture::GuardedMutex
        | ApiFixture::GuardedBusy
        | ApiFixture::GuardedBadRelease
        | ApiFixture::GuardedIrql
        | ApiFixture::CriticalUnderflow => &[
            "KeInitializeGuardedMutex",
            "KeAcquireGuardedMutex",
            "KeGetCurrentIrql",
            "KeReleaseGuardedMutex",
            "KeEnterCriticalRegion",
            "KeLeaveCriticalRegion",
            "KeRaiseIrql",
        ],
        ApiFixture::FileRoundTripA
        | ApiFixture::FileRoundTripW
        | ApiFixture::FileReadOnly
        | ApiFixture::FileReadCode => &[
            if matches!(fixture, ApiFixture::FileRoundTripW) {
                "CreateFileW"
            } else {
                "CreateFileA"
            },
            "WriteFile",
            "SetFilePointer",
            "ReadFile",
            "GetFileSizeEx",
            "CloseHandle",
            "GetLastError",
        ],
        ApiFixture::VirtualLifecycle
        | ApiFixture::VirtualWriteProtected
        | ApiFixture::VirtualReleasedRead
        | ApiFixture::VirtualReserveRead
        | ApiFixture::VirtualBadProtectOutput
        | ApiFixture::VirtualRecommit => &[
            "VirtualAlloc",
            "VirtualProtect",
            "VirtualFree",
            "GetLastError",
        ],
    };
    let module = if matches!(
        fixture,
        ApiFixture::Copy
            | ApiFixture::PoolLifecycle
            | ApiFixture::PoolZeroNx
            | ApiFixture::PoolExecutable
            | ApiFixture::PoolNxExecute
            | ApiFixture::PoolFreedRead
            | ApiFixture::PoolBadTag
            | ApiFixture::PoolPagedIrql
            | ApiFixture::PoolBadFlags
            | ApiFixture::PoolTooLarge
            | ApiFixture::PoolDoubleFree
            | ApiFixture::KernelResolve
            | ApiFixture::KernelResolveBadLength
            | ApiFixture::KernelResolveIrql
            | ApiFixture::KernelResolveUnknown
            | ApiFixture::KernelCatalogCall
            | ApiFixture::KernelCatalogCodeRead
            | ApiFixture::KernelCatalogDataRead
            | ApiFixture::WriteCode
            | ApiFixture::Prompt
            | ApiFixture::PromptReadOnly
            | ApiFixture::Unsupported
            | ApiFixture::GuardedMutex
            | ApiFixture::GuardedBusy
            | ApiFixture::GuardedBadRelease
            | ApiFixture::GuardedIrql
            | ApiFixture::CriticalUnderflow
            | ApiFixture::SystemThread
            | ApiFixture::SystemThreadReturn
            | ApiFixture::ThreadMsr
            | ApiFixture::ThreadTsc
            | ApiFixture::KernelApiAddress
            | ApiFixture::SystemThreadBadStart
            | ApiFixture::MutexHandoff
            | ApiFixture::MutexDeadlock
            | ApiFixture::KernelTime
            | ApiFixture::EventAuto
            | ApiFixture::EventManual
            | ApiFixture::EventTimeout
            | ApiFixture::EventLongTimeout
            | ApiFixture::EventAbsolute
            | ApiFixture::EventDeadlock
            | ApiFixture::EventHandoff
            | ApiFixture::EventIrql
            | ApiFixture::EventAlertable
            | ApiFixture::EventTamper
    ) {
        b"ntoskrnl.exe\0".as_slice()
    } else {
        put16(&mut data, 0x98 + 68, 3);
        put16(&mut data, 0x96, 0x22);
        b"kernel32.dll\0".as_slice()
    };
    data[0x440..0x440 + module.len()].copy_from_slice(module);
    put32(&mut data, 0x400, 0x20d0);
    put32(&mut data, 0x40c, 0x2040);
    put32(&mut data, 0x410, 0x2080);
    for (index, name) in names.iter().enumerate() {
        let rva = 0x2300 + index as u32 * 64;
        for table in [0x480, 0x4d0] {
            if wide {
                put64(&mut data, table + index * width, rva as u64)
            } else {
                put32(&mut data, table + index * width, rva)
            }
        }
        let raw = rva as usize - 0x1c00;
        data[raw + 2..raw + 2 + name.len()].copy_from_slice(name.as_bytes());
    }
    // Import tables, names and response bytes are all in the fixture's data.
    let prompt = b"Rust no input?\0";
    data[0xf00..0xf00 + prompt.len()].copy_from_slice(prompt);
    data[0xf40..0xf44].copy_from_slice(b"RRRR");
    let mut code = if wide {
        vec![0x48, 0x83, 0xec, 0x48]
    } else {
        Vec::new()
    };
    fn call(code: &mut Vec<u8>, wide: bool, base: u64, index: usize, args: &[u64]) {
        if wide {
            for (position, value) in args.iter().enumerate() {
                if position < 4 {
                    code.extend([[0x48, 0xb9], [0x48, 0xba], [0x49, 0xb8], [0x49, 0xb9]][position]);
                    code.extend(value.to_le_bytes());
                } else {
                    assert!(position < 8);
                    code.extend([0x48, 0xb8]);
                    code.extend(value.to_le_bytes());
                    code.extend([0x48, 0x89, 0x44, 0x24, (32 + (position - 4) * 8) as u8]);
                }
            }
            let next = 0x1000 + code.len() + 6;
            code.extend([0xff, 0x15]);
            code.extend((0x2080i32 + index as i32 * 8 - next as i32).to_le_bytes());
        } else {
            for value in args.iter().rev() {
                code.push(0x68);
                code.extend((*value as u32).to_le_bytes());
            }
            code.extend([0xff, 0x15]);
            code.extend(((base + 0x2080) as u32 + index as u32 * 4).to_le_bytes());
        }
    }
    fn store(code: &mut Vec<u8>, wide: bool, address: u64) {
        if wide {
            code.extend([0x48, 0xa3]);
            code.extend(address.to_le_bytes());
        } else {
            code.push(0xa3);
            code.extend((address as u32).to_le_bytes());
        }
    }
    fn load(code: &mut Vec<u8>, wide: bool, address: u64) {
        code.push(0xa1);
        if wide {
            code.extend(address.to_le_bytes());
        } else {
            code.extend((address as u32).to_le_bytes());
        }
    }
    fn write_constant(code: &mut Vec<u8>, wide: bool, address: u64) {
        code.push(0xb8);
        code.extend(0x54535552u32.to_le_bytes());
        store(code, wide, address);
    }
    fn wait_flag(code: &mut Vec<u8>, wide: bool, address: u64) {
        let start = code.len();
        load(code, wide, address);
        code.extend([0x85, 0xc0, 0x74]);
        code.push((start as isize - (code.len() + 1) as isize) as i8 as u8);
    }
    match fixture {
        ApiFixture::Mutation(_, _)
        | ApiFixture::Vfs(_, _)
        | ApiFixture::Console(_)
        | ApiFixture::Format(_)
        | ApiFixture::Stdio(_)
        | ApiFixture::Crt(_)
        | ApiFixture::Heap(_)
        | ApiFixture::Registry(_, _)
        | ApiFixture::Mdl(_)
        | ApiFixture::Modules(_)
        | ApiFixture::Sync(_)
        | ApiFixture::KernelSpin(_)
        | ApiFixture::Metadata(_)
        | ApiFixture::ProviderMixed(_)
        | ApiFixture::Cr8(_)
        | ApiFixture::Ipi(_)
        | ApiFixture::Waits(_)
        | ApiFixture::ThreadObjects(_)
        | ApiFixture::GuestTid
        | ApiFixture::Objects(_)
        | ApiFixture::Environment(_)
        | ApiFixture::Rundown(_)
        | ApiFixture::Callback(_)
        | ApiFixture::EnvironmentBlock(_, _)
        | ApiFixture::Configured(_, _)
        | ApiFixture::NativeRegistry(_)
        | ApiFixture::NativeLoader(_)
        | ApiFixture::DynamicLoader(_)
        | ApiFixture::NativeFiles(_)
        | ApiFixture::KernelRtl(_)
        | ApiFixture::KernelTimeConversion(_)
        | ApiFixture::KernelTimers(_)
        | ApiFixture::KernelDpc(_)
        | ApiFixture::KernelDpcIdleBudget
        | ApiFixture::KernelDiagnostic(_)
        | ApiFixture::Persona(_, _) => {
            unreachable!("special generated fixtures handled separately")
        }
        ApiFixture::PoolZeroNx => {
            let pool_base = if wide {
                0xffffb00000000000u64
            } else {
                0xe0000000
            };
            let tag = 0x54535552u64;
            call(&mut code, wide, base, 1, &[0x600, 4097, tag]);
            if wide {
                code.extend([0x48, 0x89, 0xc3, 0x48, 0xba]);
                code.extend(pool_base.to_le_bytes());
                code.extend([0x48, 0x39, 0xd0]);
            } else {
                code.extend([0x89, 0xc3, 0x3d]);
                code.extend((pool_base as u32).to_le_bytes());
            }
            code.extend([0x74, 1, 0xcc]);
            code.extend([0x83, 0x3b, 0, 0x74, 1, 0xcc]);
            code.extend([0x83, 0xbb, 0, 0x10, 0, 0, 0, 0x74, 1, 0xcc]);
            call(&mut code, wide, base, 3, &[pool_base]);
            code.extend([0xb8, 1, 0, 0, 0]);
        }
        ApiFixture::PoolLifecycle
        | ApiFixture::PoolExecutable
        | ApiFixture::PoolNxExecute
        | ApiFixture::PoolFreedRead
        | ApiFixture::PoolBadTag
        | ApiFixture::PoolPagedIrql
        | ApiFixture::PoolBadFlags
        | ApiFixture::PoolTooLarge
        | ApiFixture::PoolDoubleFree => {
            let pool_base = if wide {
                0xffffb00000000000u64
            } else {
                0xe0000000
            };
            let tag = 0x54535552u64;
            if matches!(fixture, ApiFixture::PoolPagedIrql) {
                call(&mut code, wide, base, 4, &[2, base + 0x2d00]);
            }
            let flags = if matches!(fixture, ApiFixture::PoolExecutable) {
                0x80
            } else if matches!(fixture, ApiFixture::PoolPagedIrql) {
                0x100
            } else if matches!(fixture, ApiFixture::PoolBadFlags) {
                0x41
            } else {
                0x8000000000000040
            };
            let size = if matches!(fixture, ApiFixture::PoolTooLarge) {
                128 * 1024 * 1024 + 1
            } else {
                4097
            };
            let args = if wide {
                vec![flags, size, tag]
            } else {
                vec![flags as u32 as u64, flags >> 32, size, tag]
            };
            call(&mut code, wide, base, 0, &args);
            if !matches!(fixture, ApiFixture::PoolTooLarge) {
                if wide {
                    code.extend([0x48, 0x89, 0xc3, 0x48, 0xba]);
                    code.extend(pool_base.to_le_bytes());
                    code.extend([0x48, 0x39, 0xd0]);
                } else {
                    code.extend([0x89, 0xc3, 0x3d]);
                    code.extend((pool_base as u32).to_le_bytes());
                }
                code.extend([0x74, 1, 0xcc, 0x83, 0x3b, 0, 0x74, 1, 0xcc]);
                code.extend([0x80, 0xbb, 0, 0x10, 0, 0, 0, 0x74, 1, 0xcc]);
                if matches!(
                    fixture,
                    ApiFixture::PoolExecutable | ApiFixture::PoolNxExecute
                ) {
                    code.extend([0xc7, 0x03]);
                    code.extend(0x000011b8u32.to_le_bytes());
                    code.extend([0xc7, 0x43, 4]);
                    code.extend(0x0000c300u32.to_le_bytes());
                    code.extend([0xff, 0xd3, 0x3d, 17, 0, 0, 0, 0x74, 1, 0xcc]);
                }
                call(
                    &mut code,
                    wide,
                    base,
                    2,
                    &[
                        pool_base,
                        if matches!(fixture, ApiFixture::PoolBadTag) {
                            7
                        } else {
                            tag
                        },
                    ],
                );
                if matches!(fixture, ApiFixture::PoolFreedRead) {
                    code.extend([0x8b, 0x03]);
                }
                if matches!(fixture, ApiFixture::PoolDoubleFree) {
                    call(&mut code, wide, base, 3, &[pool_base]);
                }
                if matches!(fixture, ApiFixture::PoolLifecycle) {
                    call(&mut code, wide, base, 1, &[512, 17, tag]);
                    if wide {
                        code.push(0x48);
                    }
                    code.extend([0x39, 0xd8, 0x74, 1, 0xcc]);
                    // The legacy allocation is unspecified; only inspect after writing.
                    code.extend([0xc7, 0x03]);
                    code.extend(0x54535552u32.to_le_bytes());
                    code.extend([0x81, 0x3b]);
                    code.extend(0x54535552u32.to_le_bytes());
                    code.extend([0x74, 1, 0xcc]);
                    call(&mut code, wide, base, 3, &[pool_base]);
                }
                code.extend([0xb8, 1, 0, 0, 0]);
            }
        }
        ApiFixture::KernelResolve
        | ApiFixture::KernelResolveBadLength
        | ApiFixture::KernelResolveIrql
        | ApiFixture::KernelResolveUnknown
        | ApiFixture::KernelCatalogCall
        | ApiFixture::KernelCatalogCodeRead
        | ApiFixture::KernelCatalogDataRead => {
            let name = if matches!(
                fixture,
                ApiFixture::KernelCatalogCall | ApiFixture::KernelCatalogCodeRead
            ) {
                "KeInsertQueueDpc"
            } else if matches!(fixture, ApiFixture::KernelCatalogDataRead) {
                "MmSystemRangeStart"
            } else if matches!(fixture, ApiFixture::KernelResolveUnknown) {
                "EmumeeUnknownKernelRoutine"
            } else {
                "KeGetCurrentIrql"
            };
            let units = name.encode_utf16().collect::<Vec<_>>();
            put16(
                &mut data,
                0x1000,
                if matches!(fixture, ApiFixture::KernelResolveBadLength) {
                    3
                } else {
                    units.len() as u16 * 2
                },
            );
            put16(&mut data, 0x1002, units.len() as u16 * 2);
            if wide {
                put64(&mut data, 0x1008, base + 0x2c40);
            } else {
                put32(&mut data, 0x1004, (base + 0x2c40) as u32);
            }
            for (index, unit) in units.iter().enumerate() {
                put16(&mut data, 0x1040 + index * 2, *unit);
            }
            if matches!(fixture, ApiFixture::KernelResolveIrql) {
                call(&mut code, wide, base, 1, &[2, base + 0x2d00]);
            }
            call(&mut code, wide, base, 0, &[base + 0x2c00]);
            if matches!(
                fixture,
                ApiFixture::KernelCatalogCall
                    | ApiFixture::KernelCatalogCodeRead
                    | ApiFixture::KernelCatalogDataRead
            ) {
                if matches!(fixture, ApiFixture::KernelCatalogCall) {
                    code.extend([0xff, 0xd0]);
                } else {
                    if wide {
                        code.push(0x48);
                    }
                    code.extend([0x8b, 0x00]);
                }
                code.push(0xcc);
            } else {
                if wide {
                    code.extend([0x48, 0x89, 0xc3, 0x48, 0xc1, 0xe8, 63]);
                } else {
                    code.extend([0x89, 0xc3, 0xc1, 0xe8, 31]);
                }
                code.extend([0x3d, 1, 0, 0, 0, 0x74, 1, 0xcc]);
                if wide {
                    code.push(0x48);
                }
                load(&mut code, wide, base + 0x2080 + 2 * width as u64);
                if wide {
                    code.push(0x48);
                }
                code.extend([0x39, 0xd8, 0x74, 1, 0xcc]);
                if wide {
                    code.extend([0x48, 0x89, 0xda, 0x48, 0x81, 0xe2]);
                } else {
                    code.extend([0x89, 0xda, 0x81, 0xe2]);
                }
                code.extend(0xffff0000u32.to_le_bytes());
                code.extend([
                    0x66, 0x81, 0x3a, 0x4d, 0x5a, 0x74, 1, 0xcc, 0xff, 0xd3, 0x3d, 0, 0, 0, 0,
                    0x74, 1, 0xcc, 0xb8, 1, 0, 0, 0,
                ]);
            }
        }
        ApiFixture::UserResolveA
        | ApiFixture::UserResolveW
        | ApiFixture::UserResolveUnknown
        | ApiFixture::UserResolveBadModule => {
            let module = "KERNEL32.DLL";
            if matches!(fixture, ApiFixture::UserResolveW) {
                for (i, u) in module.encode_utf16().enumerate() {
                    put16(&mut data, 0x1040 + i * 2, u);
                }
            } else {
                data[0x1040..0x1040 + module.len()].copy_from_slice(module.as_bytes());
            }
            let name = if matches!(fixture, ApiFixture::UserResolveUnknown) {
                "EmumeeUnknownWin32Routine"
            } else {
                "GetCurrentProcessId"
            };
            data[0x1080..0x1080 + name.len()].copy_from_slice(name.as_bytes());
            call(&mut code, wide, base, 0, &[base + 0x2c40]);
            code.extend([
                0x3d, 0, 0, 0, 0x74, 0x74, 1, 0xcc, 0x66, 0x81, 0x38, 0x4d, 0x5a, 0x74, 1, 0xcc,
            ]);
            call(
                &mut code,
                wide,
                base,
                1,
                &[
                    if matches!(fixture, ApiFixture::UserResolveBadModule) {
                        0xdead0000
                    } else {
                        0x74000000
                    },
                    base + 0x2c80,
                ],
            );
            if matches!(fixture, ApiFixture::UserResolveBadModule) {
                code.extend([0x85, 0xc0, 0x74, 1, 0xcc]);
                call(&mut code, wide, base, 2, &[]);
            } else {
                if wide {
                    code.push(0x48);
                }
                code.extend([0x89, 0xc3]);
                if wide {
                    code.push(0x48);
                }
                load(&mut code, wide, base + 0x2080 + 3 * width as u64);
                if wide {
                    code.push(0x48);
                }
                code.extend([0x39, 0xd8, 0x74, 1, 0xcc, 0xff, 0xd3]);
            }
        }
        ApiFixture::KernelApiAddress | ApiFixture::UserApiAddress => {
            if wide {
                code.push(0x48);
            }
            load(&mut code, wide, base + 0x2080);
            code.extend(if wide {
                &[0x48, 0xc1, 0xe8, 63][..]
            } else {
                &[0xc1, 0xe8, 31][..]
            });
            code.push(0x3d);
            code.extend(u32::from(matches!(fixture, ApiFixture::KernelApiAddress)).to_le_bytes());
            code.extend([0x74, 1, 0xcc]);
            call(&mut code, wide, base, 0, &[]);
            code.push(0x3d);
            code.extend(
                (if matches!(fixture, ApiFixture::KernelApiAddress) {
                    0u32
                } else {
                    1024
                })
                .to_le_bytes(),
            );
            code.extend([0x74, 1, 0xcc, 0xb8, 1, 0, 0, 0]);
        }
        ApiFixture::EventAuto
        | ApiFixture::EventManual
        | ApiFixture::EventTimeout
        | ApiFixture::EventLongTimeout
        | ApiFixture::EventAbsolute
        | ApiFixture::EventDeadlock
        | ApiFixture::EventHandoff
        | ApiFixture::EventIrql
        | ApiFixture::EventAlertable
        | ApiFixture::EventTamper => {
            fn expect(code: &mut Vec<u8>, value: u32) {
                code.push(0x3d);
                code.extend(value.to_le_bytes());
                code.extend([0x74, 1, 0xcc]);
            }
            let event = base + 0x2b00;
            let timeout = base + 0x2bc0;
            let lifecycle = matches!(fixture, ApiFixture::EventAuto | ApiFixture::EventManual);
            let manual = matches!(fixture, ApiFixture::EventManual);
            call(
                &mut code,
                wide,
                base,
                0,
                &[event, if manual { 0 } else { 1 }, u64::from(lifecycle)],
            );
            if lifecycle {
                call(&mut code, wide, base, 1, &[event, 0, 0, 0, timeout]);
                expect(&mut code, 0);
                call(&mut code, wide, base, 1, &[event, 0, 0, 0, timeout]);
                expect(&mut code, if manual { 0 } else { 0x102 });
                call(&mut code, wide, base, 3, &[event]);
                expect(&mut code, u32::from(manual));
                call(&mut code, wide, base, 2, &[event, 0, 0]);
                expect(&mut code, 0);
                call(&mut code, wide, base, 4, &[event]);
                call(&mut code, wide, base, 1, &[event, 0, 0, 0, timeout]);
                expect(&mut code, 0x102);
                code.extend([0xb8, 1, 0, 0, 0]);
            } else if matches!(fixture, ApiFixture::EventHandoff) {
                call(
                    &mut code,
                    wide,
                    base,
                    5,
                    &[base + 0x2b80, 0x1fffff, 0, 0, 0, base + 0x1180, 0],
                );
                call(&mut code, wide, base, 1, &[event, 0, 0, 0, 0]);
                expect(&mut code, 0);
                code.extend([0xb8, 1, 0, 0, 0]);
                if wide {
                    code.extend([0x48, 0x83, 0xc4, 0x48, 0xc3]);
                } else {
                    code.extend([0xc2, 8, 0]);
                }
                assert!(code.len() < 0x180);
                code.resize(0x180, 0xcc);
                if wide {
                    code.extend([0x48, 0x83, 0xec, 0x48]);
                }
                call(&mut code, wide, base, 2, &[event, 0, 0]);
                call(&mut code, wide, base, 6, &[0]);
                code.push(0xcc);
            } else {
                let infinite = matches!(fixture, ApiFixture::EventDeadlock);
                let alertable = matches!(fixture, ApiFixture::EventAlertable);
                if matches!(fixture, ApiFixture::EventIrql) {
                    call(&mut code, wide, base, 7, &[2, base + 0x2bb0]);
                }
                if matches!(fixture, ApiFixture::EventTamper) {
                    write_constant(&mut code, wide, event + 4);
                }
                let interval = if matches!(fixture, ApiFixture::EventLongTimeout) {
                    (-864000000000i64) as u64
                } else if matches!(fixture, ApiFixture::EventAbsolute) {
                    133000000000250000u64
                } else {
                    (-250000i64) as u64
                };
                put64(&mut data, 0x400 + 0xbc0, interval);
                call(
                    &mut code,
                    wide,
                    base,
                    1,
                    &[
                        event,
                        0,
                        0,
                        u64::from(alertable),
                        if infinite { 0 } else { timeout },
                    ],
                );
            }
        }
        ApiFixture::UserTime | ApiFixture::KernelTime | ApiFixture::TimeBadOutput => {
            fn expect(code: &mut Vec<u8>, value: u32) {
                code.push(0x3d);
                code.extend(value.to_le_bytes());
                code.extend([0x74, 1, 0xcc]);
            }
            if matches!(fixture, ApiFixture::TimeBadOutput) {
                call(&mut code, wide, base, 1, &[base + 0x1000]);
                expect(&mut code, 0);
                call(&mut code, wide, base, 4, &[]);
            } else {
                let kernel = matches!(fixture, ApiFixture::KernelTime);
                call(&mut code, wide, base, 0, &[base + 0x2c00]);
                load(&mut code, wide, base + 0x2c00);
                expect(&mut code, 10_000_000);
                load(&mut code, wide, base + 0x2c04);
                expect(&mut code, 0);
                if kernel {
                    call(&mut code, wide, base, 0, &[0]);
                    store(&mut code, wide, base + 0x2c10);
                    if !wide {
                        code.extend([0x89, 0xd0]);
                        store(&mut code, wide, base + 0x2c14);
                    }
                } else {
                    call(&mut code, wide, base, 1, &[base + 0x2c10]);
                    call(&mut code, wide, base, 2, &[25]);
                }
                if kernel {
                    call(&mut code, wide, base, 2, &[]);
                    store(&mut code, wide, base + 0x2c20);
                    if !wide {
                        code.extend([0x89, 0xd0]);
                        store(&mut code, wide, base + 0x2c24);
                    }
                } else {
                    call(&mut code, wide, base, 1, &[base + 0x2c20]);
                }
                load(&mut code, wide, base + 0x2c20);
                code.extend([0x89, 0xc3]);
                load(&mut code, wide, 0x7ffe0008);
                code.extend([0x29, 0xd8, 0x3d]);
                code.extend(1000u32.to_le_bytes());
                code.extend([0x76, 1, 0xcc]);
                load(&mut code, wide, base + 0x2c20);
                code.extend([0x89, 0xc3]);
                load(&mut code, wide, base + 0x2c10);
                code.extend([0x29, 0xc3, 0x81, 0xfb]);
                code.extend((if kernel { 10u32 } else { 250000u32 }).to_le_bytes());
                code.extend([0x73, 1, 0xcc]);
                code.extend([0x81, 0xfb]);
                code.extend((if kernel { 1000u32 } else { 251000u32 }).to_le_bytes());
                code.extend([0x76, 1, 0xcc]);
                code.push(0xb8);
                code.extend(0x12345678u32.to_le_bytes());
                call(
                    &mut code,
                    wide,
                    base,
                    if kernel { 1 } else { 3 },
                    &[base + 0x2c30],
                );
                expect(&mut code, 0x12345678); // A void API must not fabricate EAX=0.
                load(&mut code, wide, base + 0x2c34);
                code.extend([0x89, 0xc3]);
                load(&mut code, wide, 0x7ffe0018);
                code.extend([0x39, 0xd8, 0x74, 1, 0xcc]);
                load(&mut code, wide, base + 0x2c24);
                code.extend([0x89, 0xc3]);
                load(&mut code, wide, 0x7ffe000c);
                code.extend([0x39, 0xd8, 0x74, 1, 0xcc]);
                code.extend([0xb8, 1, 0, 0, 0]);
            }
        }
        ApiFixture::UserState => {
            call(&mut code, wide, base, 0, &[]);
            store(&mut code, wide, base + 0x2a00);
            call(&mut code, wide, base, 1, &[0x12345678]);
            call(&mut code, wide, base, 2, &[]);
            store(&mut code, wide, base + 0x2a10);
            call(&mut code, wide, base, 3, &[25]);
            call(&mut code, wide, base, 4, &[]);
            code.push(0xa1);
            if wide {
                code.extend((base + 0x2a10).to_le_bytes())
            } else {
                code.extend(((base + 0x2a10) as u32).to_le_bytes())
            };
        }
        ApiFixture::Copy | ApiFixture::WriteCode => {
            let destination = base
                + if matches!(fixture, ApiFixture::WriteCode) {
                    0x1000
                } else {
                    0x2b40
                };
            data[0xf00..0xf04].copy_from_slice(b"RUST");
            call(&mut code, wide, base, 0, &[destination, base + 0x2b00, 4]);
            code.push(0xa1);
            if wide {
                code.extend(destination.to_le_bytes())
            } else {
                code.extend((destination as u32).to_le_bytes())
            };
        }
        ApiFixture::Prompt | ApiFixture::PromptReadOnly => {
            let response = base
                + if matches!(fixture, ApiFixture::PromptReadOnly) {
                    0x1000
                } else {
                    0x2b40
                };
            call(&mut code, wide, base, 0, &[base + 0x2b00, response, 32]);
            code.push(0xa1);
            if wide {
                code.extend(response.to_le_bytes())
            } else {
                code.extend((response as u32).to_le_bytes())
            };
        }
        ApiFixture::Unsupported => call(&mut code, wide, base, 0, &[]),
        ApiFixture::ApiLoop => {
            code.push(0xbb);
            code.extend(100_000u32.to_le_bytes());
            let start = code.len();
            call(&mut code, wide, base, 0, &[0x12345678]);
            code.extend([0xff, 0xcb, 0x0f, 0x85]);
            let displacement = start as i32 - (code.len() + 4) as i32;
            code.extend(displacement.to_le_bytes());
            call(&mut code, wide, base, 1, &[]);
        }
        ApiFixture::GuardedMutex => {
            call(&mut code, wide, base, 4, &[]);
            call(&mut code, wide, base, 0, &[base + 0x2b00]);
            call(&mut code, wide, base, 1, &[base + 0x2b00]);
            call(&mut code, wide, base, 2, &[]);
            store(&mut code, wide, base + 0x2a00);
            call(&mut code, wide, base, 3, &[base + 0x2b00]);
            call(&mut code, wide, base, 2, &[]);
            call(&mut code, wide, base, 5, &[]);
            load(&mut code, wide, base + 0x2a00);
        }
        ApiFixture::GuardedBusy | ApiFixture::GuardedBadRelease | ApiFixture::GuardedIrql => {
            call(&mut code, wide, base, 0, &[base + 0x2b00]);
            if matches!(fixture, ApiFixture::GuardedBusy) {
                code.extend([0x31, 0xc0]);
                store(&mut code, wide, base + 0x2b00);
            }
            if matches!(fixture, ApiFixture::GuardedIrql) {
                call(&mut code, wide, base, 6, &[2, base + 0x2b80]);
            }
            call(
                &mut code,
                wide,
                base,
                if matches!(fixture, ApiFixture::GuardedBadRelease) {
                    3
                } else {
                    1
                },
                &[base + 0x2b00],
            );
        }
        ApiFixture::CriticalUnderflow => call(&mut code, wide, base, 5, &[]),
        ApiFixture::MutexHandoff | ApiFixture::MutexDeadlock => {
            let deadlock = matches!(fixture, ApiFixture::MutexDeadlock);
            let first = base + 0x2b00;
            let second = base + 0x2b40;
            call(&mut code, wide, base, 0, &[first]);
            if deadlock {
                call(&mut code, wide, base, 0, &[second]);
            }
            call(
                &mut code,
                wide,
                base,
                1,
                &[
                    base + 0x2c00,
                    0x1fffff,
                    0,
                    0,
                    0,
                    base + 0x1100,
                    if deadlock { second } else { first },
                ],
            );
            if deadlock {
                call(&mut code, wide, base, 2, &[first]);
            }
            wait_flag(&mut code, wide, base + 0x2b80);
            write_constant(&mut code, wide, base + 0x2b90);
            call(
                &mut code,
                wide,
                base,
                2,
                &[if deadlock { second } else { first }],
            );
            call(&mut code, wide, base, 5, &[]);
            store(&mut code, wide, base + 0x2a00);
            call(&mut code, wide, base, 3, &[first]);
            load(&mut code, wide, base + 0x2a00);
            if wide {
                code.extend([0x48, 0x83, 0xc4, 0x48, 0xc3]);
            } else {
                code.extend([0xc2, 8, 0]);
            }
            assert!(code.len() < 0x100);
            code.resize(0x100, 0xcc);
            if wide {
                code.extend([0x48, 0x83, 0xec, 0x48]);
            }
            call(
                &mut code,
                wide,
                base,
                2,
                &[if deadlock { second } else { first }],
            );
            write_constant(&mut code, wide, base + 0x2b80);
            wait_flag(&mut code, wide, base + 0x2b90);
            if deadlock {
                call(&mut code, wide, base, 2, &[first]);
            } else {
                call(&mut code, wide, base, 3, &[first]);
                call(&mut code, wide, base, 4, &[0]);
            }
            code.push(0xcc);
        }
        ApiFixture::SystemThread
        | ApiFixture::SystemThreadReturn
        | ApiFixture::ThreadMsr
        | ApiFixture::ThreadTsc
        | ApiFixture::SystemThreadBadStart => {
            let routine = base
                + if matches!(fixture, ApiFixture::SystemThreadBadStart) {
                    0x2b80
                } else {
                    0x1100
                };
            call(
                &mut code,
                wide,
                base,
                0,
                &[
                    base + 0x2b00,
                    0x1fffff,
                    0,
                    0,
                    base + 0x2b20,
                    routine,
                    base + 0x2b80,
                ],
            );
            if matches!(fixture, ApiFixture::ThreadMsr | ApiFixture::ThreadTsc) {
                code.push(0xb9);
                code.extend(
                    (if matches!(fixture, ApiFixture::ThreadTsc) {
                        0x10u32
                    } else {
                        0xc0000082
                    })
                    .to_le_bytes(),
                );
                code.push(0xb8);
                code.extend(
                    (if matches!(fixture, ApiFixture::ThreadTsc) {
                        1000u32
                    } else {
                        0x12345678
                    })
                    .to_le_bytes(),
                );
                code.extend([0x31, 0xd2, 0x0f, 0x30]);
            }
            let spin = code.len();
            load(&mut code, wide, base + 0x2b80);
            code.extend([0x85, 0xc0, 0x74]);
            code.push((spin as isize - (code.len() + 1) as isize) as i8 as u8);
            if matches!(fixture, ApiFixture::ThreadMsr | ApiFixture::ThreadTsc) {
                load(&mut code, wide, base + 0x2b90);
                if matches!(fixture, ApiFixture::ThreadTsc) {
                    code.push(0x3d);
                    code.extend(1000u32.to_le_bytes());
                    code.extend([0x73, 1, 0xcc, 0x3d]);
                    code.extend(100000u32.to_le_bytes());
                    code.extend([0x76, 1, 0xcc, 0xb8, 1, 0, 0, 0]);
                }
            } else {
                code.extend([0x31, 0xc0]);
            }
            if wide {
                code.extend([0x48, 0x83, 0xc4, 0x48, 0xc3]);
            } else {
                code.extend([0xc2, 8, 0]);
            }
            assert!(code.len() < 0x100);
            code.resize(0x100, 0xcc);
            if matches!(fixture, ApiFixture::ThreadMsr | ApiFixture::ThreadTsc) {
                if wide {
                    code.extend([0x48, 0x83, 0xec, 0x48, 0x48, 0x89, 0xce]);
                }
                code.push(0xb9);
                code.extend(
                    (if matches!(fixture, ApiFixture::ThreadTsc) {
                        0x10u32
                    } else {
                        0xc0000082
                    })
                    .to_le_bytes(),
                );
                code.extend([0x0f, 0x32]);
                store(&mut code, wide, base + 0x2b90);
                if wide {
                    code.extend([0x48, 0x89, 0xf1, 0xc7, 0x01]);
                } else {
                    code.extend([0x8b, 0x44, 0x24, 4, 0xc7, 0x00]);
                }
            } else if wide {
                code.extend([0x48, 0x83, 0xec, 0x48, 0xc7, 0x01]);
            } else {
                code.extend([0x8b, 0x44, 0x24, 4, 0xc7, 0x00]);
            }
            code.extend(1u32.to_le_bytes());
            if matches!(
                fixture,
                ApiFixture::SystemThreadReturn | ApiFixture::ThreadMsr | ApiFixture::ThreadTsc
            ) {
                if wide {
                    code.extend([0x48, 0x83, 0xc4, 0x48, 0xc3]);
                } else {
                    code.extend([0xc2, 4, 0]);
                }
            } else {
                call(&mut code, wide, base, 1, &[0]);
                code.push(0xcc);
            }
        }
        ApiFixture::FileRoundTripA
        | ApiFixture::FileRoundTripW
        | ApiFixture::FileReadOnly
        | ApiFixture::FileReadCode => {
            let name = "C:\\workspace\\rust-fixture.bin\0";
            let path = if matches!(fixture, ApiFixture::FileRoundTripW) {
                name.encode_utf16()
                    .flat_map(u16::to_le_bytes)
                    .collect::<Vec<_>>()
            } else {
                name.as_bytes().to_vec()
            };
            data[0xf00..0xf80].fill(0);
            data[0xf00..0xf00 + path.len()].copy_from_slice(&path);
            data[0xf80..0xf84].copy_from_slice(b"RUST");
            let readonly = matches!(fixture, ApiFixture::FileReadOnly);
            call(
                &mut code,
                wide,
                base,
                0,
                &[
                    base + 0x2b00,
                    if readonly { 0x80000000 } else { 0xc0000000 },
                    3,
                    0,
                    if readonly { 4 } else { 2 },
                    0x80,
                    0,
                ],
            );
            store(&mut code, wide, base + 0x2a00);
            call(
                &mut code,
                wide,
                base,
                1,
                &[0x100, base + 0x2b80, 4, base + 0x2ba0, 0],
            );
            if readonly {
                call(&mut code, wide, base, 6, &[]);
            } else {
                call(&mut code, wide, base, 2, &[0x100, 0, 0, 0]);
                call(
                    &mut code,
                    wide,
                    base,
                    3,
                    &[
                        0x100,
                        base + if matches!(fixture, ApiFixture::FileReadCode) {
                            0x1000
                        } else {
                            0x2bc0
                        },
                        4,
                        base + 0x2ba0,
                        0,
                    ],
                );
                if matches!(fixture, ApiFixture::FileReadCode) {
                    call(&mut code, wide, base, 6, &[]);
                } else {
                    call(&mut code, wide, base, 4, &[0x100, base + 0x2be0]);
                    call(&mut code, wide, base, 5, &[0x100]);
                    load(&mut code, wide, base + 0x2bc0);
                }
            }
        }
        ApiFixture::VirtualLifecycle => {
            let allocation = 0x18000000;
            call(&mut code, wide, base, 0, &[allocation, 8192, 0x2000, 4]);
            call(&mut code, wide, base, 0, &[allocation, 8192, 0x1000, 4]);
            write_constant(&mut code, wide, allocation);
            call(
                &mut code,
                wide,
                base,
                1,
                &[allocation, 4096, 2, base + 0x2b50],
            );
            call(&mut code, wide, base, 2, &[allocation, 0, 0x4000]);
            call(&mut code, wide, base, 0, &[allocation, 4096, 0x1000, 4]);
            load(&mut code, wide, allocation);
            store(&mut code, wide, base + 0x2a00);
            call(&mut code, wide, base, 2, &[allocation + 4096, 0, 0x8000]);
            call(&mut code, wide, base, 3, &[]);
            call(&mut code, wide, base, 2, &[allocation, 0, 0x8000]);
            load(&mut code, wide, base + 0x2a00);
        }
        ApiFixture::VirtualWriteProtected
        | ApiFixture::VirtualReleasedRead
        | ApiFixture::VirtualReserveRead
        | ApiFixture::VirtualBadProtectOutput
        | ApiFixture::VirtualRecommit => {
            let allocation = 0x18000000;
            let flags = if matches!(fixture, ApiFixture::VirtualReserveRead) {
                0x2000
            } else {
                0x3000
            };
            call(&mut code, wide, base, 0, &[allocation, 4096, flags, 4]);
            match fixture {
                ApiFixture::VirtualWriteProtected => {
                    call(
                        &mut code,
                        wide,
                        base,
                        1,
                        &[allocation, 4096, 2, base + 0x2b50],
                    );
                    write_constant(&mut code, wide, allocation);
                }
                ApiFixture::VirtualReleasedRead => {
                    call(&mut code, wide, base, 2, &[allocation, 0, 0x8000]);
                    load(&mut code, wide, allocation);
                }
                ApiFixture::VirtualReserveRead => load(&mut code, wide, allocation),
                ApiFixture::VirtualBadProtectOutput => {
                    call(
                        &mut code,
                        wide,
                        base,
                        1,
                        &[allocation, 4096, 2, base + 0x1000],
                    );
                    write_constant(&mut code, wide, allocation);
                    load(&mut code, wide, allocation);
                }
                ApiFixture::VirtualRecommit => {
                    write_constant(&mut code, wide, allocation);
                    call(
                        &mut code,
                        wide,
                        base,
                        1,
                        &[allocation, 4096, 2, base + 0x2b50],
                    );
                    call(&mut code, wide, base, 0, &[allocation, 4096, 0x1000, 4]);
                    load(&mut code, wide, allocation);
                    store(&mut code, wide, allocation);
                }
                _ => unreachable!(),
            }
        }
    }
    if wide {
        code.extend([0x48, 0x83, 0xc4, 0x48, 0xc3]);
    } else {
        code.extend([0xc2, 8, 0]);
    }
    assert!(code.len() < 512);
    data[0x200..0x400].fill(0xcc);
    data[0x200..0x200 + code.len()].copy_from_slice(&code);
    data
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::{Kind, PeImage};
    #[test]
    fn relocation_requires_a_nonempty_table_and_preserved_relocation_flag() {
        for architecture in [Architecture::X86, Architecture::X64] {
            let mut data = relocating_driver(architecture);
            let pe = PeImage::parse(&data, "fixture.sys").unwrap();
            let base = if architecture == Architecture::X64 {
                0xfffff80100000000
            } else {
                0x90000000
            };
            let image = pe.materialize(&data, base).unwrap();
            let pointer = if architecture == Architecture::X64 {
                u64::from_le_bytes(image[0x2000..0x2008].try_into().unwrap())
            } else {
                u32::from_le_bytes(image[0x2000..0x2004].try_into().unwrap()) as u64
            };
            assert_eq!(pointer, base + 0x1180);
            put16(&mut data, 0x96, 0x2023);
            let stripped = PeImage::parse(&data, "fixture.sys").unwrap();
            assert!(stripped.materialize(&data, base).is_err());
            assert!(stripped.materialize(&data, stripped.image_base).is_ok());
            put16(&mut data, 0x96, 0x2022);
            let directory = 0x98
                + if architecture == Architecture::X64 {
                    112
                } else {
                    96
                };
            put32(&mut data, directory + 5 * 8 + 4, 0);
            let empty = PeImage::parse(&data, "fixture.sys").unwrap();
            assert!(empty.materialize(&data, base).is_err());
            let mut imported = api_probe(architecture, ApiFixture::UserState);
            put16(&mut imported, 0x96, 0x23);
            assert_eq!(
                PeImage::parse(&imported, "fixture.exe")
                    .unwrap()
                    .imports
                    .len(),
                5
            );
        }
    }
    #[test]
    fn fixtures_parse_and_materialize_for_both_architectures() {
        for arch in [Architecture::X86, Architecture::X64] {
            let bytes = counted_driver(arch, 17);
            let pe = PeImage::parse(&bytes, "fixture.sys").unwrap();
            assert_eq!(pe.sample.architecture, arch);
            assert_eq!(pe.sample.kind, Kind::Driver);
            let image = pe.materialize(&bytes, pe.image_base).unwrap();
            assert_eq!(&image[0x1000..0x1010], &bytes[0x200..0x210]);
            assert_eq!(image.len(), 0x3000);
        }
    }
    #[test]
    fn every_truncation_and_unsupported_relocation_fails_without_panicking() {
        let bytes = counted_driver(Architecture::X64, 1);
        for end in 0..bytes.len() {
            assert!(PeImage::parse(&bytes[..end], "fixture.sys").is_err());
        }
        let pe = PeImage::parse(&bytes, "fixture.sys").unwrap();
        assert!(pe.materialize(&bytes, pe.image_base + 4096).is_err());
        assert!(pe.materialize(&bytes, u64::MAX).is_err());
    }
    #[test]
    fn malformed_layouts_are_rejected() {
        for (offset, value) in [
            (0x3c, u32::MAX),
            (0x98 + 56, u32::MAX),
            (0x1b0 + 12, 0x1000),
        ] {
            let mut bytes = counted_driver(Architecture::X64, 1);
            put32(&mut bytes, offset, value);
            assert!(PeImage::parse(&bytes, "fixture.sys").is_err());
        }
    }
}
