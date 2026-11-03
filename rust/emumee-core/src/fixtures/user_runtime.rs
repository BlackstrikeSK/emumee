//! Synthetic Win32 callers validate outputs, ownership, and error contracts.
use super::winhttp::{
    Arg::{Memory as M, Value as V},
    call, expect_dword, store, write_dword,
};
use super::*;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserRuntimeFixture {
    Slots,
    Critical,
    Process,
    System,
    Startup,
    Memory,
    OwnedProtect,
}
impl UserRuntimeFixture {
    pub const ALL: [Self; 7] = [
        Self::Slots,
        Self::Critical,
        Self::Process,
        Self::System,
        Self::Startup,
        Self::Memory,
        Self::OwnedProtect,
    ];
}
fn expect(code: &mut Vec<u8>, value: u32) {
    code.push(0x3d);
    code.extend(value.to_le_bytes());
    code.extend([0x74, 1, 0xcc]);
}
pub fn user_runtime_probe(arch: Architecture, kind: UserRuntimeFixture) -> Vec<u8> {
    let wide = arch == Architecture::X64;
    let width = arch.width();
    let base = if wide { 0x140000000 } else { 0x400000 };
    let original = counted_driver(arch, 1);
    let mut data = vec![0; 0x3200];
    data[..0x200].copy_from_slice(&original[..0x200]);
    let table = 0x98 + if wide { 0xf0 } else { 0xe0 };
    let dd = 0x98 + if wide { 112 } else { 96 };
    for (at, value) in [
        (0x98 + 4, 0x1000),
        (0x98 + 8, 0x2000),
        (0x98 + 56, 0x4000),
        (table + 8, 0x1000),
        (table + 16, 0x1000),
        (table + 48, 0x2000),
        (table + 56, 0x2000),
        (table + 60, 0x1200),
        (dd + 8, 0x2000),
        (dd + 12, 40),
        (0x1200, 0x2180),
        (0x120c, 0x2240),
        (0x1210, 0x2080),
    ] {
        put32(&mut data, at, value);
    }
    put16(&mut data, 0x96, 0x22);
    put16(&mut data, 0x98 + 68, 3);
    data[0x1440..0x144d].copy_from_slice(b"kernel32.dll\0");
    let names: &[&str] = match kind {
        UserRuntimeFixture::Slots => &[
            "TlsAlloc",
            "TlsSetValue",
            "TlsGetValue",
            "TlsFree",
            "SetLastError",
            "GetLastError",
            "FlsAlloc",
            "FlsSetValue",
            "FlsGetValue",
            "FlsFree",
        ],
        UserRuntimeFixture::Critical => &[
            "InitializeCriticalSectionAndSpinCount",
            "EnterCriticalSection",
            "TryEnterCriticalSection",
            "LeaveCriticalSection",
            "SetCriticalSectionSpinCount",
            "DeleteCriticalSection",
        ],
        UserRuntimeFixture::Process => &[
            "GetCurrentProcess",
            "GetCurrentThread",
            "GetCurrentProcessId",
            "GetCurrentThreadId",
            "GetProcessId",
            "GetThreadId",
            "OpenProcess",
            "CloseHandle",
            "GetExitCodeProcess",
            "CheckRemoteDebuggerPresent",
            "GetLastError",
        ],
        UserRuntimeFixture::System => &[
            "GetSystemInfo",
            "GetNativeSystemInfo",
            "GetVersionExW",
            "GlobalMemoryStatusEx",
            "IsWow64Process2",
            "IsProcessorFeaturePresent",
            "GetCurrentProcess",
            "GetLastError",
        ],
        UserRuntimeFixture::Startup | UserRuntimeFixture::OwnedProtect => &[
            "GetStartupInfoW",
            "GetModuleFileNameW",
            "GetStdHandle",
            "VirtualProtect",
            "GetLastError",
        ],
        UserRuntimeFixture::Memory => &[
            "GetCurrentProcess",
            "OpenProcess",
            "ReadProcessMemory",
            "WriteProcessMemory",
            "VirtualAllocEx",
            "VirtualFreeEx",
            "CloseHandle",
            "GetLastError",
        ],
    };
    for (index, name) in names.iter().enumerate() {
        let rva = 0x2300 + index * 64;
        for at in [0x1280, 0x1380] {
            if wide {
                put64(&mut data, at + index * width, rva as u64);
            } else {
                put32(&mut data, at + index * width, rva as u32);
            }
        }
        let raw = rva - 0xe00;
        data[raw + 2..raw + 2 + name.len()].copy_from_slice(name.as_bytes());
    }
    let out = base + 0x2d00;
    let saved = base + 0x2e00;
    let other = base + 0x2e20;
    let mut c = vec![];
    if wide {
        c.extend([0x48, 0x83, 0xec, 0x48]);
    }
    match kind {
        UserRuntimeFixture::Slots => {
            for (a, s, g, f) in [(0, 1, 2, 3), (6, 7, 8, 9)] {
                call(&mut c, wide, base, a, if a == 0 { &[] } else { &[V(0)] });
                store(&mut c, wide, saved);
                call(&mut c, wide, base, g, &[M(saved)]);
                expect(&mut c, 0);
                call(&mut c, wide, base, s, &[M(saved), V(0x12345678)]);
                expect(&mut c, 1);
                call(&mut c, wide, base, 4, &[V(0x5678)]);
                call(&mut c, wide, base, g, &[M(saved)]);
                expect(&mut c, 0x12345678);
                call(&mut c, wide, base, 5, &[]);
                expect(&mut c, 0);
                call(&mut c, wide, base, f, &[M(saved)]);
                expect(&mut c, 1);
                call(&mut c, wide, base, g, &[M(saved)]);
                expect(&mut c, 0);
                call(&mut c, wide, base, 5, &[]);
                expect(&mut c, 87);
                call(&mut c, wide, base, a, if a == 0 { &[] } else { &[V(0)] });
                expect(&mut c, 0);
                call(&mut c, wide, base, g, &[M(saved)]);
                expect(&mut c, 0);
            }
        }
        UserRuntimeFixture::Critical => {
            call(&mut c, wide, base, 0, &[V(out), V(13)]);
            expect(&mut c, 1);
            expect_dword(&mut c, wide, out + width as u64, u32::MAX);
            call(&mut c, wide, base, 1, &[V(out)]);
            call(&mut c, wide, base, 2, &[V(out)]);
            expect(&mut c, 1);
            expect_dword(&mut c, wide, out + width as u64 + 4, 2);
            call(&mut c, wide, base, 4, &[V(out), V(77)]);
            expect(&mut c, 13);
            call(&mut c, wide, base, 3, &[V(out)]);
            call(&mut c, wide, base, 3, &[V(out)]);
            expect_dword(&mut c, wide, out + width as u64, u32::MAX);
            call(&mut c, wide, base, 5, &[V(out)]);
        }
        UserRuntimeFixture::Process => {
            call(&mut c, wide, base, 0, &[]);
            store(&mut c, wide, saved);
            call(&mut c, wide, base, 1, &[]);
            store(&mut c, wide, other);
            call(&mut c, wide, base, 2, &[]);
            expect(&mut c, 1024);
            call(&mut c, wide, base, 3, &[]);
            expect(&mut c, 1);
            call(&mut c, wide, base, 4, &[M(saved)]);
            expect(&mut c, 1024);
            call(&mut c, wide, base, 5, &[M(other)]);
            expect(&mut c, 1);
            call(&mut c, wide, base, 6, &[V(0x1000), V(0), V(1024)]);
            store(&mut c, wide, saved);
            call(&mut c, wide, base, 8, &[M(saved), V(out)]);
            expect(&mut c, 1);
            expect_dword(&mut c, wide, out, 259);
            call(&mut c, wide, base, 9, &[M(saved), V(out)]);
            expect(&mut c, 1);
            expect_dword(&mut c, wide, out, 0);
            call(&mut c, wide, base, 7, &[M(saved)]);
            expect(&mut c, 1);
            call(&mut c, wide, base, 4, &[M(saved)]);
            expect(&mut c, 0);
            call(&mut c, wide, base, 10, &[]);
            expect(&mut c, 6);
        }
        UserRuntimeFixture::System => {
            call(&mut c, wide, base, 0, &[V(out)]);
            expect_dword(&mut c, wide, out, if wide { 9 } else { 0 });
            expect_dword(&mut c, wide, out + 4, 4096);
            call(&mut c, wide, base, 1, &[V(out)]);
            expect_dword(&mut c, wide, out, 9);
            write_dword(&mut c, wide, out, 284);
            call(&mut c, wide, base, 2, &[V(out)]);
            expect(&mut c, 1);
            expect_dword(&mut c, wide, out + 4, 10);
            write_dword(&mut c, wide, out, 64);
            call(&mut c, wide, base, 3, &[V(out)]);
            expect(&mut c, 1);
            write_dword(&mut c, wide, out, 0);
            call(&mut c, wide, base, 3, &[V(out)]);
            expect(&mut c, 0);
            call(&mut c, wide, base, 7, &[]);
            expect(&mut c, 87);
            call(&mut c, wide, base, 6, &[]);
            store(&mut c, wide, saved);
            call(&mut c, wide, base, 4, &[M(saved), V(out), V(out + 2)]);
            expect(&mut c, 1);
            expect_dword(
                &mut c,
                wide,
                out,
                if wide { 0x86640000 } else { 0x8664014c },
            );
            call(&mut c, wide, base, 5, &[V(18)]);
            expect(&mut c, 0);
            call(&mut c, wide, base, 5, &[V(36)]);
            expect(&mut c, 1);
        }
        UserRuntimeFixture::Startup | UserRuntimeFixture::OwnedProtect => {
            call(&mut c, wide, base, 0, &[V(out)]);
            expect_dword(&mut c, wide, out, if wide { 104 } else { 68 });
            // Read a character through the returned desktop pointer.
            if wide {
                c.push(0x48);
            }
            super::winhttp::load(&mut c, wide, out + 2 * width as u64);
            if kind == UserRuntimeFixture::OwnedProtect {
                store(&mut c, wide, saved);
                call(&mut c, wide, base, 3, &[M(saved), V(4096), V(4), V(other)]);
            } else {
                c.extend([0x8b, 0x00]);
                expect(&mut c, 0x00690057);
                call(&mut c, wide, base, 1, &[V(0), V(other), V(2)]);
                expect(&mut c, 2);
                expect_dword(&mut c, wide, other, 0x43);
                call(&mut c, wide, base, 4, &[]);
                expect(&mut c, 122);
            }
        }
        UserRuntimeFixture::Memory => {
            call(&mut c, wide, base, 0, &[]);
            store(&mut c, wide, saved);
            call(
                &mut c,
                wide,
                base,
                4,
                &[M(saved), V(0), V(4096), V(0x3000), V(4)],
            );
            store(&mut c, wide, other);
            write_dword(&mut c, wide, out, 0x12345678);
            call(
                &mut c,
                wide,
                base,
                3,
                &[M(saved), M(other), V(out), V(4), V(out + 8)],
            );
            expect(&mut c, 1);
            expect_dword(&mut c, wide, out + 8, 4);
            call(
                &mut c,
                wide,
                base,
                2,
                &[M(saved), M(other), V(out + 16), V(4), V(out + 8)],
            );
            expect(&mut c, 1);
            expect_dword(&mut c, wide, out + 16, 0x12345678);
            call(&mut c, wide, base, 1, &[V(0x10), V(0), V(1024)]);
            store(&mut c, wide, out + 32);
            call(
                &mut c,
                wide,
                base,
                3,
                &[M(out + 32), M(other), V(out), V(4), V(out + 8)],
            );
            expect(&mut c, 0);
            call(&mut c, wide, base, 7, &[]);
            expect(&mut c, 5);
            call(
                &mut c,
                wide,
                base,
                5,
                &[M(saved), M(other), V(0), V(0x8000)],
            );
            expect(&mut c, 1);
            call(
                &mut c,
                wide,
                base,
                2,
                &[M(saved), M(other), V(out + 16), V(4), V(out + 8)],
            );
            expect(&mut c, 0);
            expect_dword(&mut c, wide, out + 8, 0);
            call(&mut c, wide, base, 7, &[]);
            expect(&mut c, 299);
        }
    }
    c.extend([0xb8, 1, 0, 0, 0]);
    if wide {
        c.extend([0x48, 0x83, 0xc4, 0x48]);
    }
    c.push(0xc3);
    assert!(c.len() < 0x1000);
    data[0x200..0x200 + c.len()].copy_from_slice(&c);
    data
}
