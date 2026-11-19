//! Guest instruction assertions for CRT global cells, exit-function
//! registration and actual teardown execution. Registered functions are real
//! guest code; the last one to run checks the recorded order itself.
use super::m4::M4Code as Code;
use super::winhttp::Arg::Value as V;
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrtRuntimeFixture {
    Globals,
    Atexit,
    ExitImmediate,
    CleanExit,
    Terminate,
    UnbalancedUnlock,
    ExitReentrant,
    NewMode,
    ThreadLocale,
    AppType,
}

/// Scratch cells and the teardown order log inside the fixture's own data.
const SAVED: u64 = 0x3f00;
const TABLE: u64 = 0x3f30;
const LOG: u64 = 0x3e00;
const CALLBACK: u64 = 0x1800;

fn pointer_load(code: &mut Code, wide: bool, address: u64) {
    if wide {
        code.bytes.push(0x48);
    }
    code.load(address);
}
fn nonzero(code: &mut Code) {
    code.bytes.extend([0x85, 0xc0, 0x75, 1, 0xcc]);
}
fn same(code: &mut Code, wide: bool, saved: u64) {
    if wide {
        code.bytes.extend([0x48, 0xb9]);
        code.bytes.extend(saved.to_le_bytes());
        code.bytes.extend([0x48, 0x3b, 1]);
    } else {
        code.bytes.extend([0x3b, 5]);
        code.bytes.extend((saved as u32).to_le_bytes());
    }
    code.bytes.extend([0x74, 1, 0xcc]);
}
fn expect_pointer(code: &mut Code, wide: bool, value: u64) {
    if wide {
        code.bytes.extend([0x48, 0xb9]);
        code.bytes.extend(value.to_le_bytes());
        code.bytes.extend([0x48, 0x39, 0xc8]);
    } else {
        code.bytes.push(0xb9);
        code.bytes.extend((value as u32).to_le_bytes());
        code.bytes.extend([0x39, 0xc8]);
    }
    code.bytes.extend([0x74, 1, 0xcc]);
}
/// Compares the dword the accumulator points at.
fn points_to_dword(code: &mut Code, value: u32) {
    code.bytes.extend([0x81, 0x38]);
    code.bytes.extend(value.to_le_bytes());
    code.bytes.extend([0x74, 1, 0xcc]);
}
fn store_dword_through(code: &mut Code, value: u32) {
    code.bytes.extend([0xc7, 0]);
    code.bytes.extend(value.to_le_bytes());
}
fn breakpoint(code: &mut Code) {
    code.bytes.push(0xcc);
}
/// Calls a CDECL import and restores the stack the caller pushed on x86.
fn cdecl(code: &mut Code, wide: bool, index: usize, args: &[super::winhttp::Arg]) {
    code.call(index, args);
    if !wide && !args.is_empty() {
        code.bytes.extend([0x83, 0xc4, (args.len() * 4) as u8]);
    }
}
/// One registered exit function: it shifts its own identifier into the order
/// log, so the log records exactly which functions ran and in what order.
fn exit_function(arch: Architecture, rva: usize, id: u8, verify: Option<u32>) -> Vec<u8> {
    let wide = arch == Architecture::X64;
    let mut code = Code::new(arch, rva);
    let log = code.base() + LOG;
    if wide {
        code.bytes.extend([0x48, 0xb8]);
        code.bytes.extend(log.to_le_bytes());
    } else {
        code.bytes.push(0xb8);
        code.bytes.extend((log as u32).to_le_bytes());
    }
    code.bytes.extend([0xc1, 0x20, 8]);
    code.bytes.extend([0x83, 8, id]);
    if let Some(expected) = verify {
        code.bytes.extend([0x81, 0x38]);
        code.bytes.extend(expected.to_le_bytes());
        code.bytes.extend([0x74, 1, 0xcc]);
    }
    code.bytes.push(0xc3);
    code.finish()
}
/// An exit function that calls exit again, proving teardown reentrancy stops.
fn reentrant_exit_function(arch: Architecture, rva: usize, index: usize) -> Vec<u8> {
    let mut code = Code::new(arch, rva);
    if arch == Architecture::X64 {
        code.bytes.extend([0x48, 0x83, 0xec, 0x28]);
    }
    code.call(index, &[V(1)]);
    if arch == Architecture::X86 {
        code.bytes.extend([0x83, 0xc4, 4]);
    }
    code.bytes.push(0xc3);
    code.finish()
}
pub fn crt_runtime_probe(arch: Architecture, kind: CrtRuntimeFixture) -> Vec<u8> {
    let wide = arch == Architecture::X64;
    let width = arch.width() as u64;
    let mut root = Code::new(arch, 0x1000);
    let base = root.base();
    let (saved, table) = (base + SAVED, base + TABLE);
    root.prologue();
    match kind {
        CrtRuntimeFixture::Globals => {
            // One stable cell per global, shared by accessor and setter.
            cdecl(&mut root, wide, 0, &[]);
            nonzero(&mut root);
            points_to_dword(&mut root, 0x4000);
            root.store(saved);
            cdecl(&mut root, wide, 0, &[]);
            same(&mut root, wide, saved);
            store_dword_through(&mut root, 7);
            cdecl(&mut root, wide, 0, &[]);
            points_to_dword(&mut root, 7);
            cdecl(&mut root, wide, 1, &[]);
            nonzero(&mut root);
            points_to_dword(&mut root, 0x4000);
            root.store(saved + 8);
            cdecl(&mut root, wide, 2, &[V(0x8000)]);
            root.expect(0);
            pointer_load(&mut root, wide, saved + 8);
            points_to_dword(&mut root, 0x8000);
            // An unmodeled mode reports EINVAL and changes nothing.
            cdecl(&mut root, wide, 2, &[V(5)]);
            root.expect(22);
            pointer_load(&mut root, wide, saved + 8);
            points_to_dword(&mut root, 0x8000);
            cdecl(&mut root, wide, 10, &[]);
            root.expect(0);
            cdecl(&mut root, wide, 7, &[]);
            nonzero(&mut root);
            root.store(saved + 16);
            cdecl(&mut root, wide, 3, &[]);
            nonzero(&mut root);
            // The initial environment pointer cell holds that same array.
            if wide {
                root.bytes.push(0x48);
            }
            root.bytes.extend([0x8b, 0]);
            same(&mut root, wide, saved + 16);
            cdecl(&mut root, wide, 4, &[]);
            nonzero(&mut root);
            points_to_dword(&mut root, 1);
            cdecl(&mut root, wide, 5, &[]);
            nonzero(&mut root);
            cdecl(&mut root, wide, 6, &[]);
            nonzero(&mut root);
            cdecl(&mut root, wide, 8, &[]);
            nonzero(&mut root);
            cdecl(&mut root, wide, 11, &[V(0)]);
            root.expect(0);
            cdecl(&mut root, wide, 9, &[V(1)]);
            root.expect(0);
            // Per-thread locales stay disabled, so the query reports two.
            cdecl(&mut root, wide, 12, &[V(0)]);
            root.expect(2);
        }
        CrtRuntimeFixture::Atexit => {
            cdecl(&mut root, wide, 0, &[V(table)]);
            root.expect(0);
            cdecl(&mut root, wide, 1, &[V(table), V(base + CALLBACK)]);
            root.expect(0);
            cdecl(&mut root, wide, 2, &[V(base + CALLBACK + 0x40)]);
            root.expect(0);
            cdecl(&mut root, wide, 3, &[V(base + CALLBACK + 0x80)]);
            expect_pointer(&mut root, wide, base + CALLBACK + 0x80);
            cdecl(&mut root, wide, 4, &[V(base + CALLBACK + 0xc0), V(table), V(table + width)]);
            expect_pointer(&mut root, wide, base + CALLBACK + 0xc0);
            // Thread-local teardown callbacks are recorded, never executed; the
            // order the last function checks proves it.
            cdecl(&mut root, wide, 5, &[V(base + CALLBACK + 0xc0)]);
            cdecl(&mut root, wide, 6, &[V(7)]);
            // exit never returns.
            breakpoint(&mut root);
        }
        CrtRuntimeFixture::ExitImmediate => {
            cdecl(&mut root, wide, 2, &[V(base + CALLBACK)]);
            root.expect(0);
            cdecl(&mut root, wide, 1, &[V(5)]);
            breakpoint(&mut root);
        }
        CrtRuntimeFixture::CleanExit => {
            cdecl(&mut root, wide, 2, &[V(base + CALLBACK)]);
            root.expect(0);
            cdecl(&mut root, wide, 7, &[]);
            breakpoint(&mut root);
        }
        CrtRuntimeFixture::Terminate => {
            cdecl(&mut root, wide, 8, &[V(0)]);
            breakpoint(&mut root);
        }
        CrtRuntimeFixture::UnbalancedUnlock => {
            cdecl(&mut root, wide, 9, &[V(4)]);
            cdecl(&mut root, wide, 10, &[V(4)]);
            cdecl(&mut root, wide, 10, &[V(4)]);
        }
        CrtRuntimeFixture::ExitReentrant => {
            cdecl(&mut root, wide, 2, &[V(base + CALLBACK)]);
            root.expect(0);
            cdecl(&mut root, wide, 6, &[V(1)]);
        }
        CrtRuntimeFixture::NewMode => {
            cdecl(&mut root, wide, 11, &[V(1)]);
        }
        CrtRuntimeFixture::ThreadLocale => {
            cdecl(&mut root, wide, 12, &[V(1)]);
        }
        CrtRuntimeFixture::AppType => {
            cdecl(&mut root, wide, 3, &[V(5)]);
        }
    }
    root.epilogue(1, 0);
    let names: &[&str] = match kind {
        CrtRuntimeFixture::Globals => &[
            "__p__commode",
            "__p__fmode",
            "_set_fmode",
            "__p___initenv",
            "__p___argc",
            "__p___argv",
            "__p___wargv",
            "_get_initial_narrow_environment",
            "_get_initial_wide_environment",
            "_configure_narrow_argv",
            "_initialize_narrow_environment",
            "_set_new_mode",
            "_configthreadlocale",
        ],
        CrtRuntimeFixture::Atexit => &[
            "_initialize_onexit_table",
            "_register_onexit_function",
            "_crt_atexit",
            "_onexit",
            "__dllonexit",
            "_register_thread_local_exe_atexit_callback",
            "exit",
        ],
        CrtRuntimeFixture::ExitImmediate
        | CrtRuntimeFixture::CleanExit
        | CrtRuntimeFixture::Terminate
        | CrtRuntimeFixture::UnbalancedUnlock
        | CrtRuntimeFixture::ExitReentrant
        | CrtRuntimeFixture::NewMode
        | CrtRuntimeFixture::ThreadLocale
        | CrtRuntimeFixture::AppType => &[
            "exit",
            "_exit",
            "_crt_atexit",
            "__set_app_type",
            "_adjust_fdiv",
            "_register_thread_local_exe_atexit_callback",
            "exit",
            "_cexit",
            "terminate",
            "_lock",
            "_unlock",
            "_set_new_mode",
            "_configthreadlocale",
        ],
    };
    // Four exit functions, then the verifying one that runs last.
    let mut callbacks = vec![0u8; 0x100];
    let order: [(usize, u8, Option<u32>); 4] = [
        (0x1800, 1, Some(0x04030201)),
        (0x1840, 2, None),
        (0x1880, 3, None),
        (0x18c0, 4, None),
    ];
    for (rva, id, verify) in order {
        let body = if kind == CrtRuntimeFixture::ExitReentrant && rva == 0x1800 {
            reentrant_exit_function(arch, rva, 6)
        } else if matches!(
            kind,
            CrtRuntimeFixture::ExitImmediate | CrtRuntimeFixture::CleanExit
        ) && rva == 0x1800
        {
            exit_function(arch, rva, id, None)
        } else {
            exit_function(arch, rva, id, verify)
        };
        assert!(body.len() <= 0x40);
        let at = rva - 0x1800;
        callbacks[at..at + body.len()].copy_from_slice(&body);
    }
    let names: Vec<&str> = names.to_vec();
    let mut bytes = m4_custom_probe(arch, &names, &root.finish(), &callbacks, &[]);
    bytes[0x1440..0x1450].fill(0);
    bytes[0x1440..0x144b].copy_from_slice(b"msvcrt.dll\0");
    bytes
}
