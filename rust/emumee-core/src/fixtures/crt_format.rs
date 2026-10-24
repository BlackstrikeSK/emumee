//! Owned Cdecl format callers with direct varargs and guest va_list buffers.
use super::winhttp::{
    Arg,
    Arg::{Memory as M, Value as V},
    call, expect_dword, store, write_dword,
};
use super::{ApiFixture, api_probe, put16, put32, put64};
use crate::pe::Architecture;
#[derive(Clone, Copy, Debug)]
pub enum FormatFixture {
    WideConsole,
    WideStream,
    WideBuffer,
    Equal,
    Truncate,
    Secure,
    SecureTruncate,
    CommonWide,
    CommonNarrow,
    Integer64,
    InvalidFormat,
    InvalidOption,
    BadFormat,
    BadOutput,
    MalformedUtf16,
    SurrogateChar,
}
fn expect(c: &mut Vec<u8>, value: u32) {
    c.push(0x3d);
    c.extend(value.to_le_bytes());
    c.extend([0x74, 1, 0xcc]);
}
fn invoke(c: &mut Vec<u8>, wide: bool, base: u64, index: usize, args: &[Arg]) {
    call(c, wide, base, index, args);
    if !wide && index < 12 && !args.is_empty() {
        c.extend([0x83, 0xc4, (args.len() * 4) as u8]);
    }
}
fn wide_text(data: &mut [u8], rva: usize, value: &str) {
    let bytes: Vec<_> = value
        .encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect();
    let raw = rva - 0xe00;
    data[raw..raw + bytes.len()].copy_from_slice(&bytes);
}
fn narrow_text(data: &mut [u8], rva: usize, value: &str) {
    let raw = rva - 0xe00;
    data[raw..raw + value.len()].copy_from_slice(value.as_bytes());
}
fn poison(c: &mut Vec<u8>, wide: bool, address: u64) {
    for offset in (0..80).step_by(4) {
        write_dword(c, wide, address + offset, 0x77777777);
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
fn units(value: &str, nul: bool) -> Vec<u8> {
    value
        .encode_utf16()
        .chain(nul.then_some(0))
        .flat_map(u16::to_le_bytes)
        .collect()
}
pub fn format_probe(architecture: Architecture, kind: FormatFixture) -> Vec<u8> {
    let wide = architecture == Architecture::X64;
    let width = if wide { 8 } else { 4 };
    let base = if wide { 0x140000000u64 } else { 0x400000 };
    let original = api_probe(architecture, ApiFixture::Unsupported);
    let mut data = vec![0; 0x4200];
    data[..0x200].copy_from_slice(&original[..0x200]);
    let table = 0x98 + if wide { 0xf0 } else { 0xe0 };
    let dd = 0x98 + if wide { 112 } else { 96 };
    put32(&mut data, 0x98 + 4, 0x1000);
    put32(&mut data, 0x98 + 8, 0x3000);
    put32(&mut data, 0x98 + 56, 0x5000);
    put32(&mut data, table + 8, 0x1000);
    put32(&mut data, table + 16, 0x1000);
    put32(&mut data, table + 48, 0x3000);
    put32(&mut data, table + 56, 0x3000);
    put32(&mut data, table + 60, 0x1200);
    put16(&mut data, 0x98 + 68, 3);
    put16(&mut data, 0x96, 0x22);
    put32(&mut data, dd + 8, 0x2000);
    put32(&mut data, dd + 12, 80);
    // Three descriptors: msvcrt[0..8], ucrt[9..11], kernel[13..14].
    // Their null slots are real zeros and all names receive both ILT/IAT entries.
    for (raw, start, module_rva) in [
        (0x1200, 0, 0x2050),
        (0x1214, 9, 0x2060),
        (0x1228, 13, 0x2070),
    ] {
        put32(&mut data, raw, 0x2180 + start * width);
        put32(&mut data, raw + 12, module_rva);
        put32(&mut data, raw + 16, 0x2080 + start * width);
    }
    data[0x1250..0x125b].copy_from_slice(b"msvcrt.dll\0");
    data[0x1260..0x126d].copy_from_slice(b"ucrtbase.dll\0");
    data[0x1270..0x127d].copy_from_slice(b"kernel32.dll\0");
    let names = [
        "wprintf",
        "fwprintf",
        "_vsnwprintf",
        "swprintf_s",
        "_snwprintf_s",
        "__acrt_iob_func",
        "_setmode",
        "_errno",
        "",
        "__stdio_common_vswprintf",
        "__stdio_common_vfprintf",
        "__acrt_iob_func",
        "",
        "SetLastError",
        "GetLastError",
    ];
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
    let fmt = base + 0x2a00;
    let string = base + 0x2b00;
    let narrow = base + 0x2b40;
    let list = base + 0x2c00;
    let out = base + 0x3000;
    let saved = base + 0x3100;
    wide_text(&mut data, 0x2a00, "%s %d");
    wide_text(&mut data, 0x2b00, "Test");
    narrow_text(&mut data, 0x2b40, "test\0");
    for (index, value) in [string, 42].into_iter().enumerate() {
        if wide {
            put64(&mut data, 0x1e00 + index * 8, value);
        } else {
            put32(&mut data, 0x1e00 + index * 4, value as u32);
        }
    }
    let mut c = Vec::new();
    if wide {
        c.extend([0x48, 0x83, 0xec, 0x58]);
    }
    invoke(&mut c, wide, base, 13, &[V(0x12345678)]);
    // Mutable errno and LastError sentinels prove formatting is process-local.
    invoke(&mut c, wide, base, 7, &[]);
    store(&mut c, wide, saved);
    if wide {
        c.push(0x48);
    }
    super::winhttp::load(&mut c, wide, saved);
    c.extend([0xc7, 0x00]);
    c.extend(123u32.to_le_bytes());
    match kind {
        FormatFixture::WideConsole => {
            wide_text(&mut data, 0x2a00, "%s|%S|%s|%ls%%");
            wide_text(&mut data, 0x2b00, "Ω😀");
            invoke(
                &mut c,
                wide,
                base,
                0,
                &[V(fmt), V(string), V(narrow), V(0), V(string)],
            );
            expect(&mut c, "Ω😀|test|(null)|Ω😀%".encode_utf16().count() as u32);
        }
        FormatFixture::WideStream => {
            wide_text(&mut data, 0x2a00, "Host: %ls\n");
            wide_text(&mut data, 0x2b00, "Ω😀");
            invoke(&mut c, wide, base, 5, &[V(2)]);
            store(&mut c, wide, saved + 8);
            invoke(&mut c, wide, base, 1, &[M(saved + 8), V(fmt), V(string)]);
            expect(&mut c, "Host: Ω😀\n".encode_utf16().count() as u32);
        }
        FormatFixture::WideBuffer | FormatFixture::Equal | FormatFixture::Truncate => {
            poison(&mut c, wide, out);
            let count = match kind {
                FormatFixture::Equal => 7,
                FormatFixture::Truncate => 4,
                _ => 16,
            };
            invoke(&mut c, wide, base, 2, &[V(out), V(count), V(fmt), V(list)]);
            expect(&mut c, if count == 4 { u32::MAX } else { 7 });
            bytes(
                &mut c,
                wide,
                out,
                &units(if count == 4 { "Test" } else { "Test 42" }, count == 16),
            );
        }
        FormatFixture::Secure => {
            poison(&mut c, wide, out);
            invoke(
                &mut c,
                wide,
                base,
                3,
                &[V(out), V(16), V(fmt), V(string), V(42)],
            );
            expect(&mut c, 7);
            bytes(&mut c, wide, out, &units("Test 42", true));
            poison(&mut c, wide, out);
            invoke(
                &mut c,
                wide,
                base,
                3,
                &[V(out), V(7), V(fmt), V(string), V(42)],
            );
            expect(&mut c, u32::MAX);
            let mut expected = units("Test 42", false);
            expected[0] = 0;
            expected[1] = 0;
            bytes(&mut c, wide, out, &expected);
        }
        FormatFixture::SecureTruncate => {
            poison(&mut c, wide, out);
            invoke(
                &mut c,
                wide,
                base,
                4,
                &[
                    V(out),
                    V(4),
                    V(if wide { u64::MAX } else { u32::MAX as u64 }),
                    V(fmt),
                    V(string),
                    V(42),
                ],
            );
            expect(&mut c, u32::MAX);
            bytes(&mut c, wide, out, &units("Tes", true));
        }
        FormatFixture::CommonWide | FormatFixture::InvalidOption => {
            poison(&mut c, wide, out);
            let options = if matches!(kind, FormatFixture::InvalidOption) {
                1u64 << 40
            } else {
                1
            };
            let mut args = if wide {
                vec![V(options)]
            } else {
                vec![V(options as u32 as u64), V(options >> 32)]
            };
            args.extend([V(out), V(16), V(fmt), V(0), V(list)]);
            invoke(&mut c, wide, base, 9, &args);
            expect(&mut c, 7);
            bytes(&mut c, wide, out, &units("Test 42", true));
        }
        FormatFixture::CommonNarrow => {
            narrow_text(&mut data, 0x2a00, "%*s|%-*s\n\0");
            for (index, value) in [7, narrow, 7, narrow].into_iter().enumerate() {
                if wide {
                    put64(&mut data, 0x1e00 + index * 8, value);
                } else {
                    put32(&mut data, 0x1e00 + index * 4, value as u32);
                }
            }
            invoke(&mut c, wide, base, 11, &[V(2)]);
            store(&mut c, wide, saved + 8);
            let mut args = if wide { vec![V(0)] } else { vec![V(0), V(0)] };
            args.extend([M(saved + 8), V(fmt), V(0), V(list)]);
            invoke(&mut c, wide, base, 10, &args);
            expect(&mut c, 16);
        }
        FormatFixture::Integer64 => {
            wide_text(&mut data, 0x2a00, "%I64x:%d");
            narrow_text(&mut data, 0x2a80, "%I64x:%d\0");
            let values = if wide {
                vec![0x1234567889abcdef, 7]
            } else {
                vec![0x89abcdef, 0x12345678, 7]
            };
            for (index, value) in values.into_iter().enumerate() {
                if wide {
                    put64(&mut data, 0x1e00 + index * 8, value);
                } else {
                    put32(&mut data, 0x1e00 + index * 4, value as u32);
                }
            }
            poison(&mut c, wide, out);
            invoke(&mut c, wide, base, 2, &[V(out), V(32), V(fmt), V(list)]);
            expect(&mut c, 18);
            bytes(&mut c, wide, out, &units("1234567889abcdef:7", true));
            invoke(&mut c, wide, base, 11, &[V(1)]);
            store(&mut c, wide, saved + 8);
            let mut args = if wide { vec![V(0)] } else { vec![V(0), V(0)] };
            args.extend([M(saved + 8), V(fmt + 0x80), V(0), V(list)]);
            invoke(&mut c, wide, base, 10, &args);
            expect(&mut c, 18);
        }
        FormatFixture::InvalidFormat => {
            wide_text(&mut data, 0x2a00, "%n");
            invoke(&mut c, wide, base, 2, &[V(out), V(16), V(fmt), V(list)]);
        }
        FormatFixture::BadFormat => invoke(&mut c, wide, base, 2, &[V(out), V(16), V(1), V(list)]),
        FormatFixture::BadOutput => invoke(&mut c, wide, base, 2, &[V(1), V(16), V(fmt), V(list)]),
        FormatFixture::MalformedUtf16 => {
            data[0x1c00..0x1c04].copy_from_slice(&[0, 0xd8, 0, 0]);
            invoke(&mut c, wide, base, 2, &[V(out), V(16), V(fmt), V(list)]);
        }
        FormatFixture::SurrogateChar => {
            wide_text(&mut data, 0x2a00, "%c");
            if wide {
                put64(&mut data, 0x1e00, 0xd800);
            } else {
                put32(&mut data, 0x1e00, 0xd800);
            }
            invoke(&mut c, wide, base, 2, &[V(out), V(16), V(fmt), V(list)]);
        }
    }
    if wide {
        c.push(0x48);
    }
    super::winhttp::load(&mut c, wide, saved);
    c.extend([0x8b, 0x00]);
    expect(&mut c, 123);
    invoke(&mut c, wide, base, 14, &[]);
    expect(&mut c, 0x12345678);
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
