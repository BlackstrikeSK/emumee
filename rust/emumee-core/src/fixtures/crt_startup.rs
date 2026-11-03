//! Harmless native callers verify CRT pointer arrays and real initializer effects.
use super::winhttp::{
    Arg::{Memory as M, Value as V},
    call, expect_dword, load, store, write_dword,
};
use super::*;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartupFixture {
    ArgumentsNarrow,
    ArgumentsWide,
    EnvironmentNarrow,
    EnvironmentWide,
    InitializersVoid,
    InitializersError,
    InitializersFail,
    InitializersEmpty,
    InitializersMutate,
    InitializersFault,
    InitializersNx,
    InitializersBadRange,
    InitializersBadStack,
    InitializersNonvolatile,
    InitializersReentrant,
    InitializersInfinite,
    BadOutput,
    Wildcard,
    OwnedRelease,
    OwnedProtect,
}
impl StartupFixture {
    pub const ALL: [Self; 20] = [
        Self::ArgumentsNarrow,
        Self::ArgumentsWide,
        Self::EnvironmentNarrow,
        Self::EnvironmentWide,
        Self::InitializersVoid,
        Self::InitializersError,
        Self::InitializersFail,
        Self::InitializersEmpty,
        Self::InitializersMutate,
        Self::InitializersFault,
        Self::InitializersNx,
        Self::InitializersBadRange,
        Self::InitializersBadStack,
        Self::InitializersNonvolatile,
        Self::InitializersReentrant,
        Self::InitializersInfinite,
        Self::BadOutput,
        Self::Wildcard,
        Self::OwnedRelease,
        Self::OwnedProtect,
    ];
    pub fn name(self) -> &'static str {
        match self {
            Self::ArgumentsNarrow => "arguments-narrow",
            Self::ArgumentsWide => "arguments-wide",
            Self::EnvironmentNarrow => "environment-narrow",
            Self::EnvironmentWide => "environment-wide",
            Self::InitializersVoid => "initializers-void",
            Self::InitializersError => "initializers-error",
            Self::InitializersFail => "initializers-fail",
            Self::InitializersEmpty => "initializers-empty",
            Self::InitializersMutate => "initializers-mutate",
            Self::InitializersFault => "initializers-fault",
            Self::InitializersNx => "initializers-nx",
            Self::InitializersBadRange => "initializers-bad-range",
            Self::InitializersBadStack => "initializers-bad-stack",
            Self::InitializersNonvolatile => "initializers-nonvolatile",
            Self::InitializersReentrant => "initializers-reentrant",
            Self::InitializersInfinite => "initializers-infinite",
            Self::BadOutput => "bad-output",
            Self::Wildcard => "wildcard",
            Self::OwnedRelease => "owned-release",
            Self::OwnedProtect => "owned-protect",
        }
    }
    pub fn positive(self) -> bool {
        matches!(
            self,
            Self::ArgumentsNarrow
                | Self::ArgumentsWide
                | Self::EnvironmentNarrow
                | Self::EnvironmentWide
                | Self::InitializersVoid
                | Self::InitializersError
                | Self::InitializersFail
                | Self::InitializersEmpty
                | Self::InitializersMutate
        )
    }
}
fn raw(rva: u32) -> usize {
    (rva - 0xe00) as usize
}
fn ptr(data: &mut [u8], arch: Architecture, at: u32, value: u64) {
    let at = raw(at);
    data[at..at + arch.width()].copy_from_slice(&value.to_le_bytes()[..arch.width()]);
}
fn invoke(c: &mut Vec<u8>, wide: bool, base: u64, index: usize, args: &[super::winhttp::Arg]) {
    call(c, wide, base, index + usize::from(index >= 2), args);
    if !wide && index < 14 && !args.is_empty() {
        c.extend([0x83, 0xc4, (args.len() * 4) as u8]);
    }
}
fn expect(c: &mut Vec<u8>, value: u32) {
    c.push(0x3d);
    c.extend(value.to_le_bytes());
    c.extend([0x74, 1, 0xcc]);
}
fn pointed(c: &mut Vec<u8>, wide: bool, offset: u8) {
    if wide {
        c.push(0x48);
    }
    c.extend([0x8b, 0x40, offset]);
}
fn bytes_at_ax(c: &mut Vec<u8>, bytes: &[u8]) {
    for (i, b) in bytes.iter().enumerate() {
        c.extend([0x80, 0x78, i as u8, *b, 0x74, 1, 0xcc]);
    }
}
pub fn crt_startup_probe(arch: Architecture, kind: StartupFixture) -> Vec<u8> {
    let wide = arch == Architecture::X64;
    let width = arch.width();
    let base = if wide { 0x140000000 } else { 0x400000 };
    let original = counted_driver(arch, 1);
    let mut data = vec![0; 0x3200];
    data[..0x200].copy_from_slice(&original[..0x200]);
    let table = 0x98 + if wide { 0xf0 } else { 0xe0 };
    let dd = 0x98 + if wide { 112 } else { 96 };
    for (at, v) in [
        (0x98 + 4, 0x1000),
        (0x98 + 8, 0x2000),
        (0x98 + 56, 0x4000),
        (table + 8, 0x1000),
        (table + 16, 0x1000),
        (table + 48, 0x2000),
        (table + 56, 0x2000),
        (table + 60, 0x1200),
        (dd + 8, 0x2000),
        (dd + 12, 80),
    ] {
        put32(&mut data, at, v);
    }
    put16(&mut data, 0x96, 0x22);
    put16(&mut data, 0x98 + 68, 3);
    put32(&mut data, 0x1200, 0x2180 + (3 * width) as u32);
    put32(&mut data, 0x120c, 0x2240);
    put32(&mut data, 0x1210, 0x2080 + (3 * width) as u32);
    put32(&mut data, 0x1214, 0x2180);
    put32(&mut data, 0x1220, 0x2260);
    put32(&mut data, 0x1224, 0x2080);
    put32(&mut data, 0x1228, 0x2180 + (15 * width) as u32);
    put32(&mut data, 0x1234, 0x2280);
    put32(&mut data, 0x1238, 0x2080 + (15 * width) as u32);
    data[0x1440..0x144d].copy_from_slice(b"ucrtbase.dll\0");
    data[0x1460..0x146b].copy_from_slice(b"msvcrt.dll\0");
    data[0x1480..0x148d].copy_from_slice(b"kernel32.dll\0");
    let names = [
        "__getmainargs",
        "__wgetmainargs",
        "",
        "__p___argc",
        "__p___argv",
        "__p___wargv",
        "_get_initial_narrow_environment",
        "_get_initial_wide_environment",
        "_initterm",
        "_initterm_e",
        "_initialize_narrow_environment",
        "_initialize_wide_environment",
        "_configure_narrow_argv",
        "_configure_wide_argv",
        "",
        "SetEnvironmentVariableA",
        "VirtualFree",
        "VirtualProtect",
        "",
    ];
    for (i, name) in names.iter().enumerate() {
        if name.is_empty() {
            continue;
        }
        let rva = 0x2300 + i as u32 * 64;
        ptr(&mut data, arch, 0x2080 + (i * width) as u32, rva.into());
        ptr(&mut data, arch, 0x2180 + (i * width) as u32, rva.into());
        data[raw(rva) + 2..raw(rva) + 2 + name.len()].copy_from_slice(name.as_bytes());
    }
    let out = base + 0x2d00;
    let saved = base + 0x2e00;
    let journal = base + 0x2f00;
    let init_table = base + 0x2f40;
    let mut code = Vec::new();
    if wide {
        code.extend([0x48, 0x83, 0xec, 0x48]);
    }
    match kind {
        StartupFixture::ArgumentsNarrow
        | StartupFixture::ArgumentsWide
        | StartupFixture::BadOutput
        | StartupFixture::Wildcard => {
            let unicode = kind == StartupFixture::ArgumentsWide;
            invoke(
                &mut code,
                wide,
                base,
                if unicode { 12 } else { 11 },
                &[V(1)],
            );
            expect(&mut code, 0);
            invoke(
                &mut code,
                wide,
                base,
                usize::from(unicode),
                &[
                    V(if kind == StartupFixture::BadOutput {
                        base + 0x1000
                    } else {
                        out
                    }),
                    V(out + 8),
                    V(out + 16),
                    V(u64::from(kind == StartupFixture::Wildcard)),
                    V(0),
                ],
            );
            expect(&mut code, 0);
            expect_dword(&mut code, wide, out, 3);
            if wide {
                code.push(0x48);
            }
            load(&mut code, wide, out + 8);
            pointed(&mut code, wide, 0);
            let expected = if unicode {
                crate::persona::Encoding::Utf16
            } else {
                crate::persona::Encoding::Cp1252
            }
            .encode(r"C:\emumee\sample.exe", true);
            bytes_at_ax(&mut code, &expected);
            invoke(&mut code, wide, base, 2, &[]);
            pointed(&mut code, wide, 0);
            expect(&mut code, 3);
            invoke(&mut code, wide, base, if unicode { 4 } else { 3 }, &[]);
            pointed(&mut code, wide, 0);
            store(&mut code, wide, saved);
            if wide {
                code.extend([0x48, 0x3b, 0x05]);
                let next = 0x1000 + code.len() + 4;
                code.extend((0x2d08i32 - next as i32).to_le_bytes());
            } else {
                code.extend([0x3b, 0x05]);
                code.extend(((out + 8) as u32).to_le_bytes());
            }
            // MSVCRT and UCRT are distinct CRT instances, with separate arrays.
            code.extend([0x75, 1, 0xcc]);
            pointed(&mut code, wide, width as u8);
            let text = if unicode {
                crate::persona::Encoding::Utf16
            } else {
                crate::persona::Encoding::Cp1252
            }
            .encode("two words", true);
            bytes_at_ax(&mut code, &text);
            if wide {
                code.push(0x48);
            }
            load(&mut code, wide, saved);
            pointed(&mut code, wide, (2 * width) as u8);
            let text = if unicode {
                crate::persona::Encoding::Utf16
            } else {
                crate::persona::Encoding::Cp1252
            }
            .encode("é😀", true);
            bytes_at_ax(&mut code, &text);
            if wide {
                code.push(0x48);
            }
            load(&mut code, wide, saved);
            pointed(&mut code, wide, (3 * width) as u8);
            expect(&mut code, 0);
        }
        StartupFixture::EnvironmentNarrow | StartupFixture::EnvironmentWide => {
            let unicode = kind == StartupFixture::EnvironmentWide;
            for (rva, text) in [(0x2c00, "USERPROFILE"), (0x2c40, "CHANGED")] {
                data[raw(rva)..raw(rva) + text.len() + 1]
                    .copy_from_slice(&text.bytes().chain([0]).collect::<Vec<_>>());
            }
            invoke(
                &mut code,
                wide,
                base,
                14,
                &[V(base + 0x2c00), V(base + 0x2c40)],
            );
            expect(&mut code, 1);
            invoke(&mut code, wide, base, if unicode { 10 } else { 9 }, &[]);
            expect(&mut code, 0);
            invoke(&mut code, wide, base, if unicode { 6 } else { 5 }, &[]);
            store(&mut code, wide, saved);
            pointed(&mut code, wide, 0);
            let text = if unicode {
                crate::persona::Encoding::Utf16
            } else {
                crate::persona::Encoding::Cp1252
            }
            .encode("USERPROFILE=C:\\", false);
            bytes_at_ax(&mut code, &text);
            invoke(&mut code, wide, base, if unicode { 6 } else { 5 }, &[]);
            if wide {
                code.extend([0x48, 0xbb]);
                code.extend(saved.to_le_bytes());
                code.extend([0x48, 0x3b, 0x03]);
            } else {
                code.extend([0x3b, 0x05]);
                code.extend((saved as u32).to_le_bytes());
            }
            code.extend([0x74, 1, 0xcc]);
        }
        StartupFixture::OwnedRelease | StartupFixture::OwnedProtect => {
            invoke(&mut code, wide, base, 2, &[]);
            store(&mut code, wide, saved);
            if kind == StartupFixture::OwnedRelease {
                invoke(&mut code, wide, base, 15, &[M(saved), V(0), V(0x8000)]);
            } else {
                invoke(
                    &mut code,
                    wide,
                    base,
                    16,
                    &[M(saved), V(4096), V(0x40), V(out)],
                );
            }
        }
        _ => {
            let empty = kind == StartupFixture::InitializersEmpty;
            let mut first = Vec::new();
            write_dword(&mut first, wide, journal, 1);
            if kind == StartupFixture::InitializersMutate {
                if wide {
                    first.extend([0x48, 0xb8]);
                    first.extend((base + 0x1a00).to_le_bytes());
                    first.extend([0x48, 0xa3]);
                    first.extend((init_table + 2 * width as u64).to_le_bytes());
                } else {
                    write_dword(
                        &mut first,
                        false,
                        init_table + 2 * width as u64,
                        (base + 0x1a00) as u32,
                    );
                }
            }
            if kind == StartupFixture::InitializersNonvolatile {
                first.extend([0xbb, 0x12, 0x34, 0x56, 0x78]);
            }
            if kind == StartupFixture::InitializersFault {
                first.extend([0x0f, 0x0b]);
            }
            if kind == StartupFixture::InitializersInfinite {
                first.extend([0xeb, 0xfe]);
            }
            if kind == StartupFixture::InitializersReentrant {
                // IAT calls from a callback use its actual RVA for the relative call.
                if wide {
                    first.extend([0x48, 0x83, 0xec, 0x28, 0x31, 0xc9, 0x31, 0xd2, 0xff, 0x15]);
                    let next = 0x1800 + first.len() + 4;
                    first.extend((0x2080i32 + 9 * width as i32 - next as i32).to_le_bytes());
                } else {
                    first.extend([0x6a, 0, 0x6a, 0, 0xff, 0x15]);
                    first.extend(((base + 0x2080 + 9 * width as u64) as u32).to_le_bytes());
                }
            }
            first.push(0xb8);
            first.extend(
                (if kind == StartupFixture::InitializersFail {
                    7u32
                } else {
                    0
                })
                .to_le_bytes(),
            );
            if kind == StartupFixture::InitializersBadStack {
                first.extend([0xc2, 4, 0]);
            } else {
                first.push(0xc3);
            }
            data[0xa00..0xa00 + first.len()].copy_from_slice(&first);
            for (offset, value) in [(0xb00, 2), (0xc00, 3)] {
                let mut c = Vec::new();
                write_dword(&mut c, wide, journal, value);
                c.extend([0x31, 0xc0, 0xc3]);
                data[offset..offset + c.len()].copy_from_slice(&c);
            }
            ptr(
                &mut data,
                arch,
                0x2f40,
                if kind == StartupFixture::InitializersNx {
                    base + 0x2f00
                } else {
                    base + 0x1800
                },
            );
            ptr(&mut data, arch, 0x2f40 + 2 * width as u32, base + 0x1900);
            let begin = if kind == StartupFixture::InitializersBadRange {
                init_table + 1
            } else {
                init_table
            };
            invoke(
                &mut code,
                wide,
                base,
                if kind == StartupFixture::InitializersVoid {
                    7
                } else {
                    8
                },
                &[
                    V(begin),
                    V(if empty {
                        begin
                    } else {
                        init_table + 3 * width as u64
                    }),
                ],
            );
            if kind != StartupFixture::InitializersVoid {
                expect(
                    &mut code,
                    if kind == StartupFixture::InitializersFail {
                        7
                    } else {
                        0
                    },
                );
            }
            expect_dword(
                &mut code,
                wide,
                journal,
                if empty {
                    0
                } else if kind == StartupFixture::InitializersFail {
                    1
                } else if kind == StartupFixture::InitializersMutate {
                    3
                } else {
                    2
                },
            );
        }
    }
    code.extend([0xb8, 1, 0, 0, 0]);
    if wide {
        code.extend([0x48, 0x83, 0xc4, 0x48]);
    }
    code.push(0xc3);
    assert!(code.len() < 0x800);
    data[0x200..0x200 + code.len()].copy_from_slice(&code);
    data
}
