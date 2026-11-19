//! Guest instruction assertions for CRT allocation and ownership boundaries.
use super::winhttp::{
    Arg::{Memory as M, Value as V},
    call, expect_dword, failure, store, success,
};
use super::*;

#[derive(Clone, Copy, Debug)]
pub enum CrtAllocFixture {
    Normal,
    Overflow,
    Interior,
    DoubleFree,
    OwnedRelease,
    CrossFamily,
    Win32Free,
}
pub fn crt_alloc_probe(arch: Architecture, kind: CrtAllocFixture, modern: bool) -> Vec<u8> {
    let wide = arch == Architecture::X64;
    let width = arch.width();
    let base = if wide { 0x140000000u64 } else { 0x400000 };
    let mut data = heap_probe(arch, HeapFixture::Zero);
    let directories = 0x98 + if wide { 112 } else { 96 };
    put32(&mut data, directories + 12, 60);
    data[0x1240..0x1250].fill(0);
    let module: &[u8] = if modern {
        b"ucrtbase.dll\0"
    } else {
        b"msvcrt.dll\0"
    };
    data[0x1240..0x1240 + module.len()].copy_from_slice(module);
    for (i, name) in ["malloc", "calloc", "free", "??2@YAPAXI@Z", "??3@YAXPAX@Z"]
        .iter()
        .enumerate()
    {
        let name = if modern && i == 3 {
            "malloc"
        } else if modern && i == 4 {
            "free"
        } else {
            name
        };
        let raw = 0x1500 + i * 64;
        data[raw..raw + 64].fill(0);
        data[raw + 2..raw + 2 + name.len()].copy_from_slice(name.as_bytes());
    }
    for raw in [0x1280, 0x1380] {
        data[raw + 5 * width..raw + 6 * width].fill(0);
    }
    // Separate Win32 import proves CRT backing cannot be retired via VirtualFree.
    put32(&mut data, 0x1214, 0x21e0);
    put32(&mut data, 0x1220, 0x27a0);
    put32(&mut data, 0x1224, 0x20e0);
    data[0x19a0..0x19ad].copy_from_slice(b"kernel32.dll\0");
    data[0x19c2..0x19ce].copy_from_slice(b"VirtualFree\0");
    if matches!(
        kind,
        CrtAllocFixture::CrossFamily | CrtAllocFixture::Win32Free
    ) {
        data[0x19a0..0x19c0].fill(0);
        data[0x19c0..0x19e0].fill(0);
        let (module, name): (&[u8], &[u8]) = if matches!(kind, CrtAllocFixture::Win32Free) {
            (b"kernel32.dll\0", b"HeapFree\0")
        } else if modern {
            (b"msvcrt.dll\0", b"free\0")
        } else {
            (b"ucrtbase.dll\0", b"free\0")
        };
        data[0x19a0..0x19a0 + module.len()].copy_from_slice(module);
        data[0x19c2..0x19c2 + name.len()].copy_from_slice(name);
    }
    for raw in [0x12e0, 0x13e0] {
        data[raw..raw + 2 * width].fill(0);
        data[raw..raw + width].copy_from_slice(&0x27c0u64.to_le_bytes()[..width]);
    }
    let saved = base + 0x2900;
    let mut code = Vec::new();
    if wide {
        code.extend([0x48, 0x83, 0xec, 0x28]);
    }
    let invoke = |code: &mut Vec<u8>, index, args: &[super::winhttp::Arg]| {
        call(code, wide, base, index, args);
        if !wide && !args.is_empty() {
            code.extend([0x83, 0xc4, (args.len() * 4) as u8]);
        }
    };
    if matches!(kind, CrtAllocFixture::Overflow) {
        let max = if wide { u64::MAX } else { u32::MAX as u64 };
        invoke(&mut code, 1, &[V(max), V(2)]);
        failure(&mut code);
        invoke(&mut code, 0, &[V(max)]);
        failure(&mut code);
    } else {
        invoke(&mut code, 1, &[V(4), V(8)]);
        success(&mut code);
        store(&mut code, wide, saved);
        // Check all requested bytes, plus ABI alignment, in the guest itself.
        code.extend([0xa8, if wide { 15 } else { 7 }, 0x74, 1, 0xcc]);
        for offset in (0..32).step_by(4) {
            code.extend([0x83, 0x78, offset, 0, 0x74, 1, 0xcc]);
        }
        if matches!(kind, CrtAllocFixture::Normal) {
            code.extend([0xc7, 0, 0x78, 0x56, 0x34, 0x12]);
            invoke(
                &mut code,
                0,
                &[V(if wide { u64::MAX } else { u32::MAX as u64 })],
            );
            failure(&mut code);
            if wide {
                code.push(0x48);
            }
            super::winhttp::load(&mut code, wide, saved);
            code.extend([0x81, 0x38, 0x78, 0x56, 0x34, 0x12, 0x74, 1, 0xcc]);
        }
        if matches!(kind, CrtAllocFixture::Interior) {
            if wide {
                code.push(0x48);
            }
            code.extend([0x83, 0xc0, 1]);
            store(&mut code, wide, saved);
        }
        if matches!(kind, CrtAllocFixture::CrossFamily) {
            invoke(&mut code, 0x60 / width, &[M(saved)]);
        } else if matches!(kind, CrtAllocFixture::Win32Free) {
            call(
                &mut code,
                wide,
                base,
                0x60 / width,
                &[V(0x5b000008), V(0), M(saved)],
            );
        } else if matches!(kind, CrtAllocFixture::OwnedRelease) {
            call(
                &mut code,
                wide,
                base,
                0x60 / width,
                &[M(saved), V(0), V(0x8000)],
            );
        } else {
            invoke(&mut code, 2, &[M(saved)]);
            if matches!(kind, CrtAllocFixture::DoubleFree) {
                invoke(&mut code, 2, &[M(saved)]);
            }
        }
        if matches!(kind, CrtAllocFixture::Normal) {
            invoke(&mut code, 2, &[V(0)]);
            invoke(&mut code, 3, &[V(0)]);
            success(&mut code);
            store(&mut code, wide, saved);
            invoke(&mut code, 4, &[M(saved)]);
            expect_dword(&mut code, wide, saved + 16, 0);
        }
    }
    code.extend([0xb8, 1, 0, 0, 0]);
    if wide {
        code.extend([0x48, 0x83, 0xc4, 0x28]);
    }
    code.push(0xc3);
    data[0x200..0x1200].fill(0);
    data[0x200..0x200 + code.len()].copy_from_slice(&code);
    data
}
