//! Owned Cdecl callers verify pointer widths, byte/code-unit effects and pages.
use super::winhttp::{
    Arg::{self, Value as V},
    call, expect_dword, write_dword,
};
use super::{ApiFixture, api_probe, put16, put32, put64};
use crate::pe::Architecture;
#[derive(Clone, Copy, Debug)]
pub enum CrtFixture {
    Memory,
    Copy,
    StringOverlap,
    CopyInvalid,
    Strings,
    Wide,
    Boundary,
    ReadFault,
    WriteFault,
    Overlap,
    Overflow,
    Rewrite,
}
fn invoke(c: &mut Vec<u8>, wide: bool, base: u64, index: usize, args: &[Arg]) {
    call(c, wide, base, index, args);
    if !wide && !args.is_empty() {
        c.extend([0x83, 0xc4, (args.len() * 4) as u8]);
    }
}
fn expect(c: &mut Vec<u8>, value: u32) {
    c.push(0x3d);
    c.extend(value.to_le_bytes());
    c.extend([0x74, 1, 0xcc]);
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
fn sign(c: &mut Vec<u8>, positive: bool) {
    c.extend([0x85, 0xc0, if positive { 0x7f } else { 0x7c }, 1, 0xcc]);
}
fn execute(c: &mut Vec<u8>, wide: bool, address: u64) {
    if wide {
        c.extend([0x48, 0xb8]);
        c.extend(address.to_le_bytes());
    } else {
        c.push(0xb8);
        c.extend((address as u32).to_le_bytes());
    }
    c.extend([0xff, 0xd0]);
}
pub fn crt_probe(architecture: Architecture, kind: CrtFixture) -> Vec<u8> {
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
    put32(&mut data, table + 40 + 8, 0x2000);
    put32(&mut data, table + 40 + 16, 0x2000);
    put32(&mut data, table + 40 + 20, 0x1200);
    if matches!(kind, CrtFixture::Rewrite) {
        put32(&mut data, table + 40 + 36, 0xe0000040);
    }
    put16(&mut data, 0x98 + 68, 3);
    put16(&mut data, 0x96, 0x22);
    put32(&mut data, dd + 8, 0x2000);
    put32(&mut data, dd + 12, 40);
    put32(&mut data, 0x1200, 0x2180);
    put32(&mut data, 0x120c, 0x2040);
    put32(&mut data, 0x1210, 0x2080);
    let module = match kind {
        CrtFixture::Strings => "ucrtbase.dll",
        CrtFixture::Wide => "api-ms-win-crt-string-l1-1-0.dll",
        _ => "msvcrt.dll",
    };
    data[0x1240..0x1240 + module.len()].copy_from_slice(module.as_bytes());
    for (i, name) in [
        "memcpy", "memmove", "memset", "memcmp", "memchr", "wmemcpy", "wmemmove", "wmemset",
        "wmemcmp", "wmemchr", "strlen", "wcslen", "strnlen", "wcsnlen", "strcmp", "wcscmp",
        "strncmp", "wcsncmp", "strchr", "strrchr", "wcschr", "wcsrchr", "strcpy", "strncpy",
        "wcscpy", "wcsncpy",
    ]
    .iter()
    .enumerate()
    {
        let rva = 0x2300 + i as u32 * 64;
        for raw in [0x1280, 0x1380] {
            if wide {
                put64(&mut data, raw + i * 8, rva as u64)
            } else {
                put32(&mut data, raw + i * 4, rva)
            }
        }
        let raw = 0x1500 + i * 64;
        data[raw + 2..raw + 2 + name.len()].copy_from_slice(name.as_bytes());
    }
    for i in 0..32 {
        data[0x1c00 + i] = i as u8;
    }
    data[0x1c40..0x1c44].fill(0xaa);
    data[0x1c80] = 0x7f;
    data[0x1c90] = 0x80;
    data[0x1e00..0x1e05].copy_from_slice(b"abca\0");
    data[0x1e20..0x1e22].copy_from_slice(b"z\0");
    data[0x1e40..0x1e45].copy_from_slice(b"abcX\0");
    for (i, value) in [0x0041u16, 0xd800, 0xdc00, 0x0041, 0].iter().enumerate() {
        put16(&mut data, 0x1e80 + i * 2, *value);
    }
    data[0x31fc..0x3200].copy_from_slice(b"abc\0");
    if matches!(kind, CrtFixture::ReadFault) {
        data[0x31fc..0x3200].copy_from_slice(b"abcd");
    }
    if matches!(kind, CrtFixture::Rewrite) {
        data[0x1c00..0x1c06].copy_from_slice(&[0xb8, 17, 0, 0, 0, 0xc3]);
        data[0x1d00..0x1d06].copy_from_slice(&[0xb8, 1, 0, 0, 0, 0xc3]);
    }
    let src = base + 0x2a00;
    let dst = base + 0x2b00;
    let string = base + 0x2c00;
    let words = base + 0x2c80;
    let end = base + 0x3ffc;
    let mut c = vec![];
    if wide {
        c.extend([0x48, 0x83, 0xec, 0x48]);
    }
    match kind {
        CrtFixture::Copy => {
            write_dword(&mut c, wide, dst + 4, 0x77777777);
            invoke(&mut c, wide, base, 22, &[V(dst), V(string)]);
            pointer(&mut c, wide, dst);
            expect_dword(&mut c, wide, dst, 0x61636261);
            expect_dword(&mut c, wide, dst + 4, 0x77777700);
            write_dword(&mut c, wide, dst, 0x77777777);
            invoke(&mut c, wide, base, 23, &[V(dst), V(string), V(3)]);
            pointer(&mut c, wide, dst);
            expect_dword(&mut c, wide, dst, 0x77636261);
            write_dword(&mut c, wide, dst + 8, 0x77777777);
            invoke(&mut c, wide, base, 23, &[V(dst), V(string), V(8)]);
            pointer(&mut c, wide, dst);
            expect_dword(&mut c, wide, dst, 0x61636261);
            expect_dword(&mut c, wide, dst + 4, 0);
            expect_dword(&mut c, wide, dst + 8, 0x77777777);
            invoke(&mut c, wide, base, 24, &[V(dst), V(words)]);
            pointer(&mut c, wide, dst);
            expect_dword(&mut c, wide, dst, 0xd8000041);
            expect_dword(&mut c, wide, dst + 4, 0x0041dc00);
            expect_dword(&mut c, wide, dst + 8, 0x77770000);
            write_dword(&mut c, wide, dst + 4, 0x77777777);
            invoke(&mut c, wide, base, 25, &[V(dst), V(words), V(2)]);
            pointer(&mut c, wide, dst);
            expect_dword(&mut c, wide, dst, 0xd8000041);
            expect_dword(&mut c, wide, dst + 4, 0x77777777);
            write_dword(&mut c, wide, dst + 12, 0x77777777);
            invoke(&mut c, wide, base, 25, &[V(dst), V(words), V(6)]);
            pointer(&mut c, wide, dst);
            expect_dword(&mut c, wide, dst + 4, 0x0041dc00);
            expect_dword(&mut c, wide, dst + 8, 0);
            expect_dword(&mut c, wide, dst + 12, 0x77777777);
        }
        CrtFixture::StringOverlap => invoke(&mut c, wide, base, 22, &[V(string + 1), V(string)]),
        CrtFixture::CopyInvalid => invoke(&mut c, wide, base, 23, &[V(0), V(string), V(4)]),
        CrtFixture::Memory => {
            invoke(&mut c, wide, base, 0, &[V(dst), V(src), V(8)]);
            pointer(&mut c, wide, dst);
            expect_dword(&mut c, wide, dst, 0x03020100);
            expect_dword(&mut c, wide, dst + 4, 0x07060504);
            invoke(&mut c, wide, base, 1, &[V(dst + 1), V(dst), V(7)]);
            pointer(&mut c, wide, dst + 1);
            expect_dword(&mut c, wide, dst, 0x02010000);
            expect_dword(&mut c, wide, dst + 4, 0x06050403);
            invoke(&mut c, wide, base, 1, &[V(dst), V(dst + 1), V(7)]);
            expect_dword(&mut c, wide, dst, 0x03020100);
            expect_dword(&mut c, wide, dst + 4, 0x06060504);
            invoke(&mut c, wide, base, 2, &[V(dst), V(0x1aa), V(4)]);
            pointer(&mut c, wide, dst);
            expect_dword(&mut c, wide, dst, 0xaaaaaaaa);
            invoke(&mut c, wide, base, 3, &[V(dst), V(src + 0x40), V(4)]);
            expect(&mut c, 0);
            invoke(&mut c, wide, base, 3, &[V(src + 0x80), V(src + 0x90), V(1)]);
            sign(&mut c, false);
            invoke(&mut c, wide, base, 3, &[V(src + 0x90), V(src + 0x80), V(1)]);
            sign(&mut c, true);
            invoke(&mut c, wide, base, 4, &[V(src), V(5), V(8)]);
            pointer(&mut c, wide, src + 5);
            invoke(&mut c, wide, base, 4, &[V(src), V(255), V(8)]);
            pointer(&mut c, wide, 0);
        }
        CrtFixture::Strings => {
            invoke(&mut c, wide, base, 10, &[V(string)]);
            expect(&mut c, 4);
            invoke(&mut c, wide, base, 12, &[V(string), V(3)]);
            expect(&mut c, 3);
            invoke(&mut c, wide, base, 12, &[V(string), V(u64::MAX)]);
            expect(&mut c, 4);
            invoke(&mut c, wide, base, 14, &[V(string), V(string)]);
            expect(&mut c, 0);
            invoke(&mut c, wide, base, 14, &[V(string), V(string + 0x20)]);
            sign(&mut c, false);
            invoke(&mut c, wide, base, 16, &[V(string), V(string + 0x40), V(3)]);
            expect(&mut c, 0);
            invoke(&mut c, wide, base, 16, &[V(string), V(string + 0x40), V(4)]);
            sign(&mut c, true);
            for (index, ch, result) in [
                (18, 97, string),
                (19, 97, string + 3),
                (18, 0, string + 4),
                (19, 0, string + 4),
                (18, 122, 0),
            ] {
                invoke(&mut c, wide, base, index, &[V(string), V(ch)]);
                pointer(&mut c, wide, result);
            }
        }
        CrtFixture::Wide => {
            invoke(&mut c, wide, base, 5, &[V(dst), V(words), V(4)]);
            pointer(&mut c, wide, dst);
            expect_dword(&mut c, wide, dst, 0xd8000041);
            expect_dword(&mut c, wide, dst + 4, 0x0041dc00);
            invoke(&mut c, wide, base, 6, &[V(dst + 2), V(dst), V(3)]);
            pointer(&mut c, wide, dst + 2);
            expect_dword(&mut c, wide, dst, 0x00410041);
            expect_dword(&mut c, wide, dst + 4, 0xdc00d800);
            invoke(&mut c, wide, base, 7, &[V(dst), V(0x1d800), V(3)]);
            pointer(&mut c, wide, dst);
            expect_dword(&mut c, wide, dst, 0xd800d800);
            invoke(&mut c, wide, base, 8, &[V(dst), V(words), V(1)]);
            sign(&mut c, true);
            invoke(&mut c, wide, base, 8, &[V(words), V(words), V(4)]);
            expect(&mut c, 0);
            invoke(&mut c, wide, base, 9, &[V(words), V(0xd800), V(4)]);
            pointer(&mut c, wide, words + 2);
            invoke(&mut c, wide, base, 11, &[V(words)]);
            expect(&mut c, 4);
            invoke(&mut c, wide, base, 13, &[V(words), V(2)]);
            expect(&mut c, 2);
            invoke(&mut c, wide, base, 15, &[V(words), V(words)]);
            expect(&mut c, 0);
            invoke(&mut c, wide, base, 17, &[V(words), V(words), V(3)]);
            expect(&mut c, 0);
            for (index, ch, result) in [
                (20, 0x41, words),
                (21, 0x41, words + 6),
                (20, 0, words + 8),
                (21, 0xd800, words + 2),
                (20, 0x99, 0),
            ] {
                invoke(&mut c, wide, base, index, &[V(words), V(ch)]);
                pointer(&mut c, wide, result);
            }
        }
        CrtFixture::Boundary => {
            invoke(&mut c, wide, base, 10, &[V(end)]);
            expect(&mut c, 3);
            invoke(
                &mut c,
                wide,
                base,
                16,
                &[V(end), V(string + 0x20), V(u64::MAX)],
            );
            sign(&mut c, false);
            write_dword(&mut c, wide, end, 0x64636261);
            invoke(&mut c, wide, base, 12, &[V(end), V(4)]);
            expect(&mut c, 4);
            invoke(&mut c, wide, base, 0, &[V(0), V(0), V(0)]);
            pointer(&mut c, wide, 0);
            invoke(&mut c, wide, base, 3, &[V(0), V(0), V(0)]);
            expect(&mut c, 0);
            invoke(&mut c, wide, base, 13, &[V(0), V(0)]);
            expect(&mut c, 0);
            invoke(&mut c, wide, base, 17, &[V(0), V(0), V(0)]);
            expect(&mut c, 0);
            write_dword(&mut c, wide, end, 0x00000041);
            invoke(&mut c, wide, base, 11, &[V(end)]);
            expect(&mut c, 1);
            invoke(&mut c, wide, base, 11, &[V(end + 2)]);
            expect(&mut c, 0);
        }
        CrtFixture::ReadFault => invoke(&mut c, wide, base, 10, &[V(end)]),
        CrtFixture::WriteFault => invoke(&mut c, wide, base, 0, &[V(base + 0x1000), V(src), V(4)]),
        CrtFixture::Overlap => invoke(&mut c, wide, base, 0, &[V(dst + 1), V(dst), V(4)]),
        CrtFixture::Overflow => invoke(&mut c, wide, base, 5, &[V(dst), V(src), V(u64::MAX)]),
        CrtFixture::Rewrite => {
            execute(&mut c, wide, dst);
            expect(&mut c, 1);
            invoke(&mut c, wide, base, 0, &[V(dst), V(src), V(6)]);
            pointer(&mut c, wide, dst);
            execute(&mut c, wide, dst);
            expect(&mut c, 17);
        }
    }
    c.extend([0xb8, 1, 0, 0, 0]);
    if wide {
        c.extend([0x48, 0x83, 0xc4, 0x48]);
    }
    c.push(0xc3);
    assert!(c.len() <= 0x1000);
    data[0x200..0x200 + c.len()].copy_from_slice(&c);
    data
}
