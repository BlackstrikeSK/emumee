//! Harmless Stdcall console callers plus Cdecl CRT writes for shared ordering.
use super::winhttp::{
    Arg,
    Arg::{Memory as M, Value as V},
    call, expect_dword, store, write_dword,
};
use super::{ApiFixture, api_probe, put16, put32, put64};
use crate::pe::Architecture;
#[derive(Clone, Copy, Debug)]
pub enum ConsoleFixture {
    Standard,
    Ansi,
    Wide,
    File,
    Mixed,
    Redirect,
    Alias,
    Closed,
    ReadOnly,
    Mode,
    Screen,
    BadBuffer,
    BadCount,
    Reserved,
    Zero,
    InvalidHandle,
    Input,
    Overlapped,
}
fn expect(c: &mut Vec<u8>, value: u32) {
    c.push(0x3d);
    c.extend(value.to_le_bytes());
    c.extend([0x74, 1, 0xcc]);
}
fn invoke(c: &mut Vec<u8>, wide: bool, base: u64, index: usize, args: &[Arg]) {
    call(c, wide, base, index, args);
    if !wide && index >= 18 && !args.is_empty() {
        c.extend([0x83, 0xc4, (args.len() * 4) as u8]);
    }
}
fn last(c: &mut Vec<u8>, wide: bool, base: u64, value: u32) {
    invoke(c, wide, base, 14, &[]);
    expect(c, value);
}
fn pointer(c: &mut Vec<u8>, wide: bool, value: u64) {
    if wide {
        c.extend([0x48, 0xba]);
        c.extend(value.to_le_bytes());
        c.extend([0x48, 0x39, 0xd0, 0x74, 1, 0xcc]);
    } else {
        expect(c, value as u32);
    }
}
fn bytes(c: &mut Vec<u8>, wide: bool, address: u64, value: &[u8]) {
    for (index, chunk) in value.chunks(4).enumerate() {
        let mut expected = [0x77; 4];
        expected[..chunk.len()].copy_from_slice(chunk);
        expect_dword(
            c,
            wide,
            address + index as u64 * 4,
            u32::from_le_bytes(expected),
        );
    }
    expect_dword(
        c,
        wide,
        address + value.len().div_ceil(4) as u64 * 4,
        0x77777777,
    );
}
fn text(data: &mut [u8], rva: usize, value: &str, wide: bool) {
    let bytes = if wide {
        value
            .encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>()
    } else {
        value.bytes().chain([0]).collect()
    };
    let raw = rva - 0xe00;
    data[raw..raw + bytes.len()].copy_from_slice(&bytes);
}
pub fn console_probe(architecture: Architecture, kind: ConsoleFixture) -> Vec<u8> {
    let wide = architecture == Architecture::X64;
    let width = if wide { 8 } else { 4 };
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
    put32(&mut data, 0x1200, 0x2180);
    put32(&mut data, 0x120c, 0x2040);
    put32(&mut data, 0x1210, 0x2080);
    put32(&mut data, 0x1214, 0x2180 + 18 * width);
    put32(&mut data, 0x1220, 0x2060);
    put32(&mut data, 0x1224, 0x2080 + 18 * width);
    data[0x1240..0x124d].copy_from_slice(b"kernel32.dll\0");
    data[0x1260..0x126b].copy_from_slice(b"msvcrt.dll\0");
    let names = [
        "GetStdHandle",
        "SetStdHandle",
        "WriteConsoleA",
        "WriteConsoleW",
        "WriteFile",
        "GetFileType",
        "GetConsoleMode",
        "SetConsoleMode",
        "GetConsoleCP",
        "GetConsoleOutputCP",
        "GetConsoleScreenBufferInfo",
        "CreateFileA",
        "CloseHandle",
        "ReadFile",
        "GetLastError",
        "SetLastError",
        "CreateFileW",
        "",
        "_write",
        "wprintf",
        "_get_osfhandle",
    ];
    assert!(0x1380 + (names.len() + 1) * (width as usize) < 0x1500);
    for (index, name) in names.iter().enumerate() {
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
    let payload = base + 0x2b00;
    let wtext = base + 0x2b20;
    let ascii = base + 0x2b60;
    let format = base + 0x2b80;
    let path = base + 0x2bc0;
    let out = base + 0x2d00;
    let saved = base + 0x2e00;
    text(&mut data, 0x2a00, "CONOUT$", false);
    text(&mut data, 0x2a40, "CONOUT$", true);
    text(&mut data, 0x2a80, "CONIN$", false);
    data[0x1d00] = 0x82;
    text(&mut data, 0x2b20, "Ω😀", true);
    data[0x1d40..0x1d42].copy_from_slice(&[0, 0xd8]);
    text(&mut data, 0x2b60, "a", false);
    text(&mut data, 0x2b80, "z", true);
    text(&mut data, 0x2bc0, "console-redirect.bin", false);
    text(&mut data, 0x2c00, "file", false);
    let mut c = Vec::new();
    if wide {
        c.extend([0x48, 0x83, 0xec, 0x58]);
    }
    invoke(&mut c, wide, base, 15, &[V(0x12345678)]);
    for offset in (0..32).step_by(4) {
        write_dword(&mut c, wide, out + offset, 0x77777777);
    }
    match kind {
        ConsoleFixture::Standard => {
            for (sel, handle) in [
                (0xfffffff6, 0xf001),
                (0xfffffff5, 0xf002),
                (0xfffffff4, 0xf003),
            ] {
                invoke(&mut c, wide, base, 0, &[V(sel)]);
                pointer(&mut c, wide, handle);
                last(&mut c, wide, base, 0x12345678);
            }
            let value = if wide { 0x1234567887654321 } else { 0x87654321 };
            invoke(&mut c, wide, base, 1, &[V(0xfffffff5), V(value)]);
            expect(&mut c, 1);
            last(&mut c, wide, base, 0x12345678);
            invoke(&mut c, wide, base, 0, &[V(0xfffffff5)]);
            pointer(&mut c, wide, value);
            invoke(&mut c, wide, base, 20, &[V(1)]);
            pointer(&mut c, wide, value);
            invoke(&mut c, wide, base, 1, &[V(0xfffffff5), V(0xf002)]);
            expect(&mut c, 1);
            invoke(&mut c, wide, base, 0, &[V(17)]);
            pointer(&mut c, wide, if wide { u64::MAX } else { u32::MAX as u64 });
            last(&mut c, wide, base, 87);
            invoke(&mut c, wide, base, 1, &[V(17), V(0)]);
            expect(&mut c, 0);
            last(&mut c, wide, base, 87);
        }
        ConsoleFixture::Ansi => {
            invoke(
                &mut c,
                wide,
                base,
                2,
                &[V(0xf002), V(payload), V(1), V(out), V(0)],
            );
            expect(&mut c, 1);
            expect_dword(&mut c, wide, out, 1);
            last(&mut c, wide, base, 0);
        }
        ConsoleFixture::Wide => {
            invoke(
                &mut c,
                wide,
                base,
                3,
                &[V(0xf003), V(wtext), V(3), V(out), V(0)],
            );
            expect(&mut c, 1);
            expect_dword(&mut c, wide, out, 3);
            last(&mut c, wide, base, 0);
            invoke(
                &mut c,
                wide,
                base,
                3,
                &[V(0xf003), V(base + 0x2b40), V(1), V(out), V(0)],
            );
            expect(&mut c, 1);
            expect_dword(&mut c, wide, out, 1);
            last(&mut c, wide, base, 0);
        }
        ConsoleFixture::File => {
            invoke(
                &mut c,
                wide,
                base,
                4,
                &[V(0xf002), V(payload), V(1), V(out), V(0)],
            );
            expect(&mut c, 1);
            expect_dword(&mut c, wide, out, 1);
            last(&mut c, wide, base, 0);
        }
        ConsoleFixture::Mixed => {
            invoke(&mut c, wide, base, 18, &[V(1), V(ascii), V(1)]);
            expect(&mut c, 1);
            last(&mut c, wide, base, 0x12345678);
            invoke(
                &mut c,
                wide,
                base,
                4,
                &[V(0xf002), V(payload), V(1), V(out), V(0)],
            );
            expect(&mut c, 1);
            invoke(
                &mut c,
                wide,
                base,
                2,
                &[V(0xf002), V(payload), V(1), V(out), V(0)],
            );
            expect(&mut c, 1);
            invoke(
                &mut c,
                wide,
                base,
                3,
                &[V(0xf002), V(wtext), V(3), V(out), V(0)],
            );
            expect(&mut c, 1);
            invoke(&mut c, wide, base, 19, &[V(format)]);
            expect(&mut c, 1);
            last(&mut c, wide, base, 0);
        }
        ConsoleFixture::Redirect => {
            invoke(
                &mut c,
                wide,
                base,
                11,
                &[V(path), V(0xc0000000), V(3), V(0), V(2), V(0x80), V(0)],
            );
            store(&mut c, wide, saved);
            invoke(&mut c, wide, base, 1, &[V(0xfffffff5), M(saved)]);
            expect(&mut c, 1);
            invoke(&mut c, wide, base, 0, &[V(0xfffffff5)]);
            store(&mut c, wide, saved + 8);
            invoke(&mut c, wide, base, 5, &[M(saved + 8)]);
            expect(&mut c, 1);
            invoke(
                &mut c,
                wide,
                base,
                4,
                &[M(saved + 8), V(base + 0x2c00), V(4), V(out), V(0)],
            );
            expect(&mut c, 1);
            expect_dword(&mut c, wide, out, 4);
            invoke(
                &mut c,
                wide,
                base,
                2,
                &[M(saved + 8), V(payload), V(1), V(out), V(0)],
            );
            expect(&mut c, 0);
            last(&mut c, wide, base, 6);
            expect_dword(&mut c, wide, out, 4);
            invoke(&mut c, wide, base, 12, &[M(saved)]);
            expect(&mut c, 1);
        }
        ConsoleFixture::Alias | ConsoleFixture::Closed | ConsoleFixture::ReadOnly => {
            let access = if matches!(kind, ConsoleFixture::ReadOnly) {
                0x80000000
            } else {
                0xc0000000
            };
            invoke(
                &mut c,
                wide,
                base,
                11,
                &[V(base + 0x2a00), V(access), V(3), V(0), V(3), V(0), V(0)],
            );
            pointer(&mut c, wide, 0xf100);
            store(&mut c, wide, saved);
            last(&mut c, wide, base, 0);
            if matches!(kind, ConsoleFixture::Closed) {
                invoke(&mut c, wide, base, 12, &[M(saved)]);
                expect(&mut c, 1);
                invoke(&mut c, wide, base, 5, &[M(saved)]);
                expect(&mut c, 0);
                last(&mut c, wide, base, 6);
                invoke(
                    &mut c,
                    wide,
                    base,
                    2,
                    &[M(saved), V(payload), V(1), V(out), V(0)],
                );
                expect(&mut c, 0);
                last(&mut c, wide, base, 6);
                expect_dword(&mut c, wide, out, 0x77777777);
                invoke(&mut c, wide, base, 12, &[M(saved)]);
                expect(&mut c, 0);
                last(&mut c, wide, base, 6);
            } else {
                if matches!(kind, ConsoleFixture::Alias) {
                    invoke(&mut c, wide, base, 1, &[V(0xfffffff5), V(0x9999)]);
                    expect(&mut c, 1);
                }
                invoke(
                    &mut c,
                    wide,
                    base,
                    2,
                    &[M(saved), V(payload), V(1), V(out), V(0)],
                );
                expect(
                    &mut c,
                    if matches!(kind, ConsoleFixture::Alias) {
                        1
                    } else {
                        0
                    },
                );
                last(
                    &mut c,
                    wide,
                    base,
                    if matches!(kind, ConsoleFixture::Alias) {
                        0
                    } else {
                        5
                    },
                );
                expect_dword(
                    &mut c,
                    wide,
                    out,
                    if matches!(kind, ConsoleFixture::Alias) {
                        1
                    } else {
                        0x77777777
                    },
                );
                if matches!(kind, ConsoleFixture::Alias) {
                    invoke(
                        &mut c,
                        wide,
                        base,
                        16,
                        &[
                            V(base + 0x2a40),
                            V(0xc0000000),
                            V(3),
                            V(0),
                            V(3),
                            V(0),
                            V(0),
                        ],
                    );
                    pointer(&mut c, wide, 0xf101);
                    store(&mut c, wide, saved + 8);
                    invoke(
                        &mut c,
                        wide,
                        base,
                        4,
                        &[M(saved + 8), V(payload), V(1), V(out), V(0)],
                    );
                    expect(&mut c, 1);
                    expect_dword(&mut c, wide, out, 1);
                    last(&mut c, wide, base, 0);
                    invoke(&mut c, wide, base, 12, &[M(saved + 8)]);
                    expect(&mut c, 1);
                }
                invoke(&mut c, wide, base, 12, &[M(saved)]);
                expect(&mut c, 1);
                invoke(&mut c, wide, base, 1, &[V(0xfffffff5), V(0xf002)]);
                expect(&mut c, 1);
            }
        }
        ConsoleFixture::Mode => {
            invoke(&mut c, wide, base, 6, &[V(0xf001), V(out)]);
            expect(&mut c, 1);
            expect_dword(&mut c, wide, out, 0xf7);
            invoke(&mut c, wide, base, 7, &[V(0xf001), V(4)]);
            expect(&mut c, 0);
            last(&mut c, wide, base, 87);
            invoke(&mut c, wide, base, 6, &[V(0xf001), V(out)]);
            expect(&mut c, 1);
            expect_dword(&mut c, wide, out, 0xf7);
            invoke(&mut c, wide, base, 7, &[V(0xf001), V(6)]);
            expect(&mut c, 1);
            invoke(&mut c, wide, base, 6, &[V(0xf001), V(out)]);
            expect(&mut c, 1);
            expect_dword(&mut c, wide, out, 6);
            invoke(&mut c, wide, base, 7, &[V(0xf003), V(7)]);
            expect(&mut c, 1);
            invoke(&mut c, wide, base, 6, &[V(0xf002), V(out)]);
            expect(&mut c, 1);
            expect_dword(&mut c, wide, out, 7);
            invoke(&mut c, wide, base, 8, &[]);
            expect(&mut c, 437);
            invoke(&mut c, wide, base, 9, &[]);
            expect(&mut c, 437);
            last(&mut c, wide, base, 0);
        }
        ConsoleFixture::Screen => {
            invoke(&mut c, wide, base, 10, &[V(0xf002), V(out)]);
            expect(&mut c, 1);
            let expected: Vec<_> = [80i16, 25, 0, 0, 7, 0, 0, 79, 24, 80, 25]
                .into_iter()
                .flat_map(i16::to_le_bytes)
                .collect();
            bytes(&mut c, wide, out, &expected);
            last(&mut c, wide, base, 0);
        }
        ConsoleFixture::BadBuffer => {
            invoke(
                &mut c,
                wide,
                base,
                2,
                &[V(0xf002), V(1), V(1), V(out), V(0)],
            );
            expect(&mut c, 0);
            last(&mut c, wide, base, 998);
            expect_dword(&mut c, wide, out, 0x77777777);
            invoke(
                &mut c,
                wide,
                base,
                4,
                &[V(0xf002), V(1), V(1), V(out), V(0)],
            );
            expect(&mut c, 0);
            last(&mut c, wide, base, 998);
            expect_dword(&mut c, wide, out, 0);
        }
        ConsoleFixture::BadCount => {
            invoke(
                &mut c,
                wide,
                base,
                2,
                &[V(0xf002), V(payload), V(1), V(1), V(0)],
            );
            expect(&mut c, 0);
            last(&mut c, wide, base, 998);
            expect_dword(&mut c, wide, out, 0x77777777);
        }
        ConsoleFixture::Reserved => {
            invoke(
                &mut c,
                wide,
                base,
                2,
                &[V(0xf002), V(payload), V(1), V(out), V(1)],
            );
            expect(&mut c, 0);
            last(&mut c, wide, base, 87);
            expect_dword(&mut c, wide, out, 0x77777777);
        }
        ConsoleFixture::Zero => {
            for index in [2, 3, 4] {
                invoke(
                    &mut c,
                    wide,
                    base,
                    index,
                    &[V(0xf002), V(0), V(0), V(out), V(0)],
                );
                expect(&mut c, 1);
                expect_dword(&mut c, wide, out, 0);
                last(&mut c, wide, base, 0);
            }
        }
        ConsoleFixture::InvalidHandle => {
            invoke(
                &mut c,
                wide,
                base,
                3,
                &[V(0x9999), V(1), V(1), V(out), V(1)],
            );
            expect(&mut c, 0);
            last(&mut c, wide, base, 6);
            expect_dword(&mut c, wide, out, 0x77777777);
            invoke(&mut c, wide, base, 5, &[V(0x9999)]);
            expect(&mut c, 0);
            last(&mut c, wide, base, 6);
            invoke(&mut c, wide, base, 6, &[V(0x9999), V(out)]);
            expect(&mut c, 0);
            last(&mut c, wide, base, 6);
        }
        ConsoleFixture::Input => {
            invoke(
                &mut c,
                wide,
                base,
                11,
                &[
                    V(base + 0x2a80),
                    V(0xc0000000),
                    V(3),
                    V(0),
                    V(3),
                    V(0),
                    V(0),
                ],
            );
            pointer(&mut c, wide, 0xf100);
            store(&mut c, wide, saved);
            invoke(
                &mut c,
                wide,
                base,
                13,
                &[M(saved), V(out + 8), V(1), V(out), V(0)],
            );
        }
        ConsoleFixture::Overlapped => invoke(
            &mut c,
            wide,
            base,
            4,
            &[V(0xf002), V(payload), V(1), V(out), V(1)],
        ),
    }
    invoke(&mut c, wide, base, 15, &[V(0x12345678)]);
    last(&mut c, wide, base, 0x12345678);
    c.push(0xb8);
    c.extend(17u32.to_le_bytes());
    if wide {
        c.extend([0x48, 0x83, 0xc4, 0x58]);
    }
    c.push(0xc3);
    assert!(c.len() < 0x1000);
    data[0x200..0x200 + c.len()].copy_from_slice(&c);
    data
}
