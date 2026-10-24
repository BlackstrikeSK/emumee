//! Harmless Cdecl CRT callers. No native CRT or host console is executed.
use super::winhttp::{
    Arg::{Memory as M, Value as V},
    call, load, store, write_dword,
};
use super::{ApiFixture, api_probe, put16, put32, put64};
use crate::pe::Architecture;
#[derive(Clone, Copy, Debug)]
pub enum StdioFixture {
    Legacy,
    Ucrt,
    Errno,
    Modes,
    Write,
    Utf16,
    Utf8,
    BadEncoding,
    BadBuffer,
    BadDescriptor,
    OwnedFree,
    OwnedProtect,
    OwnedRecommit,
    FormatUnsupported,
}
fn expect(c: &mut Vec<u8>, v: u32) {
    c.push(0x3d);
    c.extend(v.to_le_bytes());
    c.extend([0x74, 1, 0xcc]);
}
fn invoke(c: &mut Vec<u8>, wide: bool, base: u64, index: usize, args: &[super::winhttp::Arg]) {
    call(c, wide, base, index, args);
    if !wide && index < 10 && !args.is_empty() {
        c.extend([0x83, 0xc4, (args.len() * 4) as u8]);
    }
}
fn pointed(c: &mut Vec<u8>, wide: bool, saved: u64, offset: u32, expected: u32) {
    if wide {
        c.push(0x48);
    }
    load(c, wide, saved);
    c.extend([0x8b, 0x80]);
    c.extend(offset.to_le_bytes());
    expect(c, expected);
}
fn equal(c: &mut Vec<u8>, wide: bool, saved: u64) {
    if wide {
        c.extend([0x48, 0xba]);
        c.extend(saved.to_le_bytes());
        c.extend([0x48, 0x8b, 0x12, 0x48, 0x39, 0xd0]);
    } else {
        c.extend([0x8b, 0x15]);
        c.extend((saved as u32).to_le_bytes());
        c.extend([0x39, 0xd0]);
    }
    c.extend([0x74, 1, 0xcc]);
}
pub fn stdio_probe(architecture: Architecture, kind: StdioFixture) -> Vec<u8> {
    let wide = architecture == Architecture::X64;
    let base = if wide { 0x140000000u64 } else { 0x400000 };
    let original = api_probe(architecture, ApiFixture::Unsupported);
    let mut data = vec![0; 0x3200];
    data[..0x200].copy_from_slice(&original[..0x200]);
    let table = 0x98 + if wide { 0xf0 } else { 0xe0 };
    let dd = 0x98 + if wide { 112 } else { 96 };
    put32(&mut data, 0x98 + 4, 0x1000);
    put32(&mut data, 0x98 + 8, 0x2000);
    put32(&mut data, 0x98 + 56, 0x4000);
    put32(&mut data, table + 8, 0x1000);
    put32(&mut data, table + 16, 0x1000);
    put32(&mut data, table + 48, 0x2000);
    put32(&mut data, table + 56, 0x2000);
    put32(&mut data, table + 60, 0x1200);
    put16(&mut data, 0x98 + 68, 3);
    put16(&mut data, 0x96, 0x22);
    put32(&mut data, dd + 8, 0x2000);
    put32(&mut data, dd + 12, 60);
    let width = if wide { 8 } else { 4 };
    put32(&mut data, 0x1200, 0x2180);
    put32(&mut data, 0x120c, 0x2040);
    put32(&mut data, 0x1210, 0x2080);
    put32(&mut data, 0x1214, 0x2180 + 11 * width);
    put32(&mut data, 0x1220, 0x2060);
    put32(&mut data, 0x1224, 0x2080 + 11 * width);
    data[0x1240..0x124b].copy_from_slice(b"msvcrt.dll\0");
    data[0x1260..0x126d].copy_from_slice(b"kernel32.dll\0");
    let imports = [
        "__iob_func",
        "__acrt_iob_func",
        "_fileno",
        "_write",
        "_setmode",
        "fflush",
        "_isatty",
        "_get_osfhandle",
        "_errno",
        "fprintf",
        "",
        "SetLastError",
        "GetLastError",
        "VirtualFree",
        "VirtualProtect",
        "VirtualAlloc",
    ];
    assert!(0x1380 + (imports.len() + 1) * width as usize <= 0x1500);
    for (index, name) in imports.iter().enumerate() {
        if name.is_empty() {
            continue;
        }
        let rva = 0x2300 + index as u32 * 64;
        for raw in [0x1280, 0x1380] {
            if wide {
                put64(&mut data, raw + index * 8, rva.into());
            } else {
                put32(&mut data, raw + index * 4, rva);
            }
        }
        let raw = 0x1500 + index * 64;
        assert!(raw + 2 + name.len() < 0x1c00);
        data[raw + 2..raw + 2 + name.len()].copy_from_slice(name.as_bytes());
    }
    let saved = base + 0x2e00;
    let out = base + 0x2e10;
    let payload = base + 0x2a00;
    data[0x1c00..0x1c08].copy_from_slice(b"hello\n\0\0");
    data[0x1c20..0x1c26].copy_from_slice(&[0x41, 0, 0xa9, 3, 10, 0]);
    data[0x1c40..0x1c44].copy_from_slice(&[0x41, 0xc3, 0xa9, 10]);
    data[0x1c60] = 0xff;
    let mut c = Vec::new();
    if wide {
        c.extend([0x48, 0x83, 0xec, 0x38]);
    }
    invoke(&mut c, wide, base, 11, &[V(0x12345678)]);
    match kind {
        StdioFixture::Legacy => {
            invoke(&mut c, wide, base, 0, &[]);
            store(&mut c, wide, saved);
            let (stride, flag, fd) = crate::crt_stdio::legacy_layout(architecture);
            for n in 0..3 {
                pointed(
                    &mut c,
                    wide,
                    saved,
                    (n * stride + flag) as u32,
                    if n == 0 { 1 } else { 2 },
                );
                pointed(&mut c, wide, saved, (n * stride + fd) as u32, n as u32);
            }
            pointed(&mut c, wide, saved, (3 * stride + flag) as u32, 0);
            invoke(&mut c, wide, base, 2, &[M(saved)]);
            expect(&mut c, 0);
            invoke(&mut c, wide, base, 0, &[]);
            equal(&mut c, wide, saved);
            invoke(&mut c, wide, base, 5, &[M(saved)]);
            expect(&mut c, 0);
            invoke(&mut c, wide, base, 5, &[V(0)]);
            expect(&mut c, 0);
        }
        StdioFixture::Ucrt => {
            invoke(&mut c, wide, base, 1, &[V(2)]);
            store(&mut c, wide, saved);
            pointed(&mut c, wide, saved, 0, 0);
            pointed(&mut c, wide, saved, 124, 0);
            invoke(&mut c, wide, base, 2, &[M(saved)]);
            expect(&mut c, 2);
            invoke(&mut c, wide, base, 1, &[V(2)]);
            equal(&mut c, wide, saved);
            invoke(&mut c, wide, base, 2, &[V(0)]);
            expect(&mut c, u32::MAX);
        }
        StdioFixture::Errno => {
            invoke(&mut c, wide, base, 8, &[]);
            store(&mut c, wide, saved);
            pointed(&mut c, wide, saved, 0, 0);
            if wide {
                c.push(0x48);
            }
            load(&mut c, wide, saved);
            c.extend([0xc7, 0x00]);
            c.extend(123u32.to_le_bytes());
            invoke(&mut c, wide, base, 8, &[]);
            equal(&mut c, wide, saved);
            pointed(&mut c, wide, saved, 0, 123);
            invoke(&mut c, wide, base, 3, &[V(1), V(0), V(0)]);
            expect(&mut c, 0);
            pointed(&mut c, wide, saved, 0, 123);
        }
        StdioFixture::Modes => {
            for mode in [0x8000, 0x10000, 0x20000, 0x40000, 0x4000] {
                invoke(&mut c, wide, base, 4, &[V(1), V(mode)]);
                expect(
                    &mut c,
                    match mode {
                        0x8000 => 0x4000,
                        0x10000 => 0x8000,
                        0x20000 => 0x10000,
                        0x40000 => 0x20000,
                        _ => 0x40000,
                    },
                );
            }
            for fd in 0..3 {
                invoke(&mut c, wide, base, 6, &[V(fd)]);
                expect(&mut c, 1);
                invoke(&mut c, wide, base, 7, &[V(fd)]);
                expect(&mut c, 0xf001 + fd as u32);
            }
            invoke(&mut c, wide, base, 6, &[V(17)]);
            expect(&mut c, 0);
        }
        StdioFixture::Write => {
            invoke(&mut c, wide, base, 3, &[V(1), V(payload), V(6)]);
            expect(&mut c, 6);
            invoke(&mut c, wide, base, 3, &[V(2), V(payload), V(6)]);
            expect(&mut c, 6);
            invoke(&mut c, wide, base, 3, &[V(1), V(0), V(0)]);
            expect(&mut c, 0);
        }
        StdioFixture::Utf16 | StdioFixture::Utf8 => {
            let u16 = matches!(kind, StdioFixture::Utf16);
            invoke(
                &mut c,
                wide,
                base,
                4,
                &[V(1), V(if u16 { 0x20000 } else { 0x40000 })],
            );
            expect(&mut c, 0x4000);
            let size = if u16 { 6 } else { 4 };
            invoke(
                &mut c,
                wide,
                base,
                3,
                &[V(1), V(payload + if u16 { 0x20 } else { 0x40 }), V(size)],
            );
            expect(&mut c, size as u32);
        }
        StdioFixture::BadEncoding => {
            invoke(&mut c, wide, base, 3, &[V(1), V(payload + 0x60), V(1)])
        }
        StdioFixture::BadBuffer => invoke(&mut c, wide, base, 3, &[V(1), V(0), V(1)]),
        StdioFixture::BadDescriptor => invoke(&mut c, wide, base, 3, &[V(17), V(payload), V(1)]),
        StdioFixture::OwnedFree | StdioFixture::OwnedProtect | StdioFixture::OwnedRecommit => {
            invoke(&mut c, wide, base, 8, &[]);
            store(&mut c, wide, saved);
            pointed(&mut c, wide, saved, 0, 0);
            match kind {
                StdioFixture::OwnedFree => {
                    invoke(&mut c, wide, base, 13, &[M(saved), V(0), V(0x8000)])
                }
                StdioFixture::OwnedProtect => {
                    write_dword(&mut c, wide, out, 0x77777777);
                    invoke(&mut c, wide, base, 14, &[M(saved), V(4096), V(2), V(out)]);
                }
                _ => invoke(
                    &mut c,
                    wide,
                    base,
                    15,
                    &[M(saved), V(4096), V(0x1000), V(4)],
                ),
            }
        }
        StdioFixture::FormatUnsupported => invoke(&mut c, wide, base, 9, &[V(0), V(payload)]),
    }
    invoke(&mut c, wide, base, 12, &[]);
    expect(&mut c, 0x12345678);
    c.push(0xb8);
    c.extend(17u32.to_le_bytes());
    if wide {
        c.extend([0x48, 0x83, 0xc4, 0x38]);
    }
    c.push(0xc3);
    assert!(c.len() < 0x1000);
    data[0x200..0x200 + c.len()].copy_from_slice(&c);
    data
}
