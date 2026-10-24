//! Owned Win32 callers for real guest directory/catalog/search/path authority.
use super::winhttp::{
    Arg::{Memory as M, Value as V},
    call, expect_dword, load, store, write_dword,
};
use super::{ApiFixture, api_probe, put16, put32, put64};
use crate::pe::Architecture;
#[derive(Clone, Copy, Debug)]
pub enum VfsFixture {
    Directory,
    Metadata,
    Enumeration,
    Snapshot,
    Retry,
    Wildcard,
    CurrentDirectory,
    Paths,
    Missing,
    ReadOnly,
    TypedHandles,
    AttributesUnsupported,
    MaskUnsupported,
    SecurityUnsupported,
    ShortNameUnsupported,
}
fn expect(c: &mut Vec<u8>, value: u32) {
    c.push(0x3d);
    c.extend(value.to_le_bytes());
    c.extend([0x74, 1, 0xcc]);
}
fn last(c: &mut Vec<u8>, wide: bool, base: u64, value: u32) {
    call(c, wide, base, 16, &[]);
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
fn encoded(value: &str, unicode: bool, nul: bool) -> Vec<u8> {
    let mut bytes: Vec<u8> = if unicode {
        value.encode_utf16().flat_map(u16::to_le_bytes).collect()
    } else {
        value
            .chars()
            .map(|c| {
                assert!(c.is_ascii() || c == 'é');
                c as u8
            })
            .collect()
    };
    if nul {
        bytes.extend(std::iter::repeat_n(0, if unicode { 2 } else { 1 }));
    }
    bytes
}
fn text(data: &mut [u8], rva: usize, value: &str, unicode: bool) {
    let bytes = encoded(value, unicode, true);
    let raw = rva - 0xe00;
    assert!(bytes.len() <= 64);
    data[raw..raw + bytes.len()].copy_from_slice(&bytes);
}
fn check(c: &mut Vec<u8>, wide: bool, address: u64, bytes: &[u8], padding: u8) {
    for (index, chunk) in bytes.chunks(4).enumerate() {
        let mut value = [padding; 4];
        value[..chunk.len()].copy_from_slice(chunk);
        expect_dword(
            c,
            wide,
            address + index as u64 * 4,
            u32::from_le_bytes(value),
        );
    }
}
fn string(c: &mut Vec<u8>, wide: bool, address: u64, value: &str, unicode: bool) {
    let bytes = encoded(value, unicode, true);
    check(c, wide, address, &bytes, 0x77);
    expect_dword(
        c,
        wide,
        address + bytes.len().div_ceil(4) as u64 * 4,
        0x77777777,
    );
}
fn metadata(attributes: u32, size: u64) -> Vec<u8> {
    let mut bytes = attributes.to_le_bytes().to_vec();
    for _ in 0..3 {
        bytes.extend(133000000000000000u64.to_le_bytes());
    }
    bytes.extend(((size >> 32) as u32).to_le_bytes());
    bytes.extend((size as u32).to_le_bytes());
    bytes
}
fn find(
    c: &mut Vec<u8>,
    wide: bool,
    address: u64,
    name: &str,
    attributes: u32,
    size: u64,
    unicode: bool,
) {
    check(c, wide, address, &metadata(attributes, size), 0);
    expect_dword(c, wide, address + 36, 0);
    expect_dword(c, wide, address + 40, 0);
    let name = encoded(name, unicode, true);
    check(c, wide, address + 44, &name, 0);
    expect_dword(c, wide, address + if unicode { 564 } else { 304 }, 0);
    expect_dword(c, wide, address + if unicode { 588 } else { 316 }, 0);
    expect_dword(
        c,
        wide,
        address + if unicode { 592 } else { 320 },
        0x77777777,
    );
}
#[derive(Clone, Copy)]
struct Transfer {
    payload: u64,
    output: u64,
}
fn make_file(
    c: &mut Vec<u8>,
    wide: bool,
    base: u64,
    path: u64,
    saved: u64,
    count: u64,
    transfer: Transfer,
) {
    let Transfer { payload, output } = transfer;
    call(
        c,
        wide,
        base,
        12,
        &[V(path), V(0xc0000000), V(3), V(0), V(2), V(0x80), V(0)],
    );
    store(c, wide, saved);
    if count != 0 {
        call(
            c,
            wide,
            base,
            13,
            &[M(saved), V(payload), V(count), V(output), V(0)],
        );
        expect(c, 1);
        expect_dword(c, wide, output, count as u32);
    }
    call(c, wide, base, 15, &[M(saved)]);
    expect(c, 1);
}
fn poison(c: &mut Vec<u8>, wide: bool, address: u64) {
    for offset in (0..64).step_by(4) {
        write_dword(c, wide, address + offset, 0x77777777);
    }
}
pub fn vfs_probe(architecture: Architecture, kind: VfsFixture, unicode: bool) -> Vec<u8> {
    let wide = architecture == Architecture::X64;
    let base = if wide { 0x140000000u64 } else { 0x400000 };
    let width = if wide { 8 } else { 4 };
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
    put32(&mut data, dd + 12, 40);
    put32(&mut data, 0x1200, 0x2180);
    put32(&mut data, 0x120c, 0x2040);
    put32(&mut data, 0x1210, 0x2080);
    data[0x1240..0x124d].copy_from_slice(b"kernel32.dll\0");
    let suffix = if unicode { "W" } else { "A" };
    let names = [
        format!("CreateDirectory{suffix}"),
        format!("RemoveDirectory{suffix}"),
        format!("GetFileAttributes{suffix}"),
        format!("SetFileAttributes{suffix}"),
        format!("GetFileAttributesEx{suffix}"),
        format!("FindFirstFile{suffix}"),
        format!("FindNextFile{suffix}"),
        "FindClose".into(),
        format!("GetFullPathName{suffix}"),
        format!("GetLongPathName{suffix}"),
        format!("SetCurrentDirectory{suffix}"),
        format!("GetCurrentDirectory{suffix}"),
        format!("CreateFile{suffix}"),
        "WriteFile".into(),
        "ReadFile".into(),
        "CloseHandle".into(),
        "GetLastError".into(),
        "SetLastError".into(),
    ];
    assert!(0x1380 + (names.len() + 1) * (width as usize) < 0x1500);
    for (index, name) in names.iter().enumerate() {
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
    for (rva, value) in [
        (0x2a00, "probe"),
        (0x2a40, "probe\\café.txt"),
        (0x2a80, "probe\\readme"),
        (0x2ac0, "probe\\sub"),
        (0x2b00, "probe\\zeta.txt"),
        (0x2b40, "probe\\sub\\nested.txt"),
        (0x2b80, "probe\\*.*"),
        (0x2bc0, "probe\\a?.txt"),
        (0x2c00, "missing"),
        (0x2c40, "."),
        (0x2c80, ".."),
    ] {
        text(&mut data, rva, value, unicode);
    }
    data[0x2100..0x2104].copy_from_slice(b"RUST");
    data[0x2600..0x2880].fill(0x77);
    data[0x2900..0x2940].fill(0x77);
    data[0x2a20..0x2a28].fill(0x77);
    data[0x2b00..0x2b40].fill(0x77);
    let dir = base + 0x2a00;
    let a = base + 0x2a40;
    let b = base + 0x2a80;
    let sub = base + 0x2ac0;
    let z = base + 0x2b00;
    let nested = base + 0x2b40;
    let query = base + 0x2b80;
    let other = base + 0x2bc0;
    let missing = base + 0x2c00;
    let dot = base + 0x2c40;
    let parent = base + 0x2c80;
    let payload = base + 0x2f00;
    let out = base + 0x3400;
    let meta = base + 0x3700;
    let saved = base + 0x3800;
    let part = base + 0x3820;
    let readout = base + 0x3900;
    let transfer = Transfer {
        payload,
        output: meta,
    };
    let invalid = if wide { u64::MAX } else { u32::MAX as u64 };
    let mut c = Vec::new();
    if wide {
        c.extend([0x48, 0x83, 0xec, 0x58]);
    }
    call(&mut c, wide, base, 17, &[V(0x12345678)]);
    let no_dir = matches!(
        kind,
        VfsFixture::Paths | VfsFixture::Missing | VfsFixture::ShortNameUnsupported
    );
    if !no_dir {
        call(&mut c, wide, base, 0, &[V(dir), V(0)]);
        expect(&mut c, 1);
    }
    match kind {
        VfsFixture::Directory => {
            call(&mut c, wide, base, 2, &[V(dir)]);
            expect(&mut c, 0x10);
            call(&mut c, wide, base, 3, &[V(dir), V(2)]);
            expect(&mut c, 1);
            call(&mut c, wide, base, 2, &[V(dir)]);
            expect(&mut c, 0x12);
            call(&mut c, wide, base, 4, &[V(dir), V(0), V(meta)]);
            expect(&mut c, 1);
            check(&mut c, wide, meta, &metadata(0x12, 0), 0x77);
            expect_dword(&mut c, wide, meta + 36, 0x77777777);
            call(&mut c, wide, base, 0, &[V(dir), V(0)]);
            expect(&mut c, 0);
            last(&mut c, wide, base, 183);
            call(&mut c, wide, base, 0, &[V(sub), V(0)]);
            expect(&mut c, 1);
            call(&mut c, wide, base, 1, &[V(dir)]);
            expect(&mut c, 0);
            last(&mut c, wide, base, 145);
            call(&mut c, wide, base, 1, &[V(sub)]);
            expect(&mut c, 1);
            call(&mut c, wide, base, 1, &[V(dir)]);
            expect(&mut c, 1);
            call(&mut c, wide, base, 2, &[V(dir)]);
            expect(&mut c, u32::MAX);
            last(&mut c, wide, base, 2);
        }
        VfsFixture::Metadata | VfsFixture::ReadOnly | VfsFixture::AttributesUnsupported => {
            make_file(
                &mut c,
                wide,
                base,
                a,
                saved,
                if matches!(kind, VfsFixture::AttributesUnsupported) {
                    0
                } else {
                    4
                },
                transfer,
            );
            if matches!(kind, VfsFixture::AttributesUnsupported) {
                call(&mut c, wide, base, 3, &[V(a), V(0x80000000)]);
            } else {
                let attrs = if matches!(kind, VfsFixture::ReadOnly) {
                    3
                } else {
                    0x80
                };
                if matches!(kind, VfsFixture::ReadOnly) {
                    call(&mut c, wide, base, 3, &[V(a), V(attrs)]);
                    expect(&mut c, 1);
                    call(
                        &mut c,
                        wide,
                        base,
                        12,
                        &[V(a), V(0x40000000), V(3), V(0), V(3), V(0x80), V(0)],
                    );
                    pointer(&mut c, wide, invalid);
                    last(&mut c, wide, base, 5);
                    call(
                        &mut c,
                        wide,
                        base,
                        12,
                        &[V(a), V(0x80000000), V(3), V(0), V(3), V(0x80), V(0)],
                    );
                    store(&mut c, wide, saved);
                    call(
                        &mut c,
                        wide,
                        base,
                        14,
                        &[M(saved), V(readout), V(4), V(meta), V(0)],
                    );
                    expect(&mut c, 1);
                    expect_dword(&mut c, wide, meta, 4);
                    expect_dword(&mut c, wide, readout, u32::from_le_bytes(*b"RUST"));
                    call(&mut c, wide, base, 15, &[M(saved)]);
                    expect(&mut c, 1);
                }
                call(&mut c, wide, base, 2, &[V(a)]);
                expect(&mut c, attrs as u32);
                call(&mut c, wide, base, 4, &[V(a), V(0), V(meta)]);
                expect(&mut c, 1);
                check(&mut c, wide, meta, &metadata(attrs as u32, 4), 0x77);
                expect_dword(&mut c, wide, meta + 36, 0x77777777);
                last(&mut c, wide, base, 0);
            }
        }
        VfsFixture::Enumeration => {
            text(&mut data, 0x2a40, "probe\\CAFé.TXT", unicode);
            text(&mut data, 0x2ac0, "probe\\Sub", unicode);
            text(&mut data, 0x2bc0, "probe\\café.txt", unicode);
            make_file(&mut c, wide, base, a, saved, 4, transfer);
            make_file(&mut c, wide, base, other, saved, 4, transfer);
            make_file(&mut c, wide, base, b, saved, 0, transfer);
            call(&mut c, wide, base, 0, &[V(sub), V(0)]);
            expect(&mut c, 1);
            make_file(&mut c, wide, base, nested, saved, 0, transfer);
            make_file(&mut c, wide, base, z, saved, 0, transfer);
            call(&mut c, wide, base, 5, &[V(query), V(out)]);
            pointer(&mut c, wide, 0x70000000);
            store(&mut c, wide, saved);
            find(&mut c, wide, out, "CAFé.TXT", 0x80, 4, unicode);
            for (name, attrs) in [("readme", 0x80), ("Sub", 0x10), ("zeta.txt", 0x80)] {
                call(&mut c, wide, base, 6, &[M(saved), V(out)]);
                expect(&mut c, 1);
                find(&mut c, wide, out, name, attrs, 0, unicode);
            }
            call(&mut c, wide, base, 6, &[M(saved), V(out)]);
            expect(&mut c, 0);
            last(&mut c, wide, base, 18);
            find(&mut c, wide, out, "zeta.txt", 0x80, 0, unicode);
            call(&mut c, wide, base, 7, &[M(saved)]);
            expect(&mut c, 1);
        }
        VfsFixture::Snapshot | VfsFixture::Retry | VfsFixture::TypedHandles => {
            text(&mut data, 0x2a40, "probe\\alpha", unicode);
            text(&mut data, 0x2a80, "probe\\bravo", unicode);
            text(&mut data, 0x2b00, "probe\\zeta", unicode);
            make_file(&mut c, wide, base, a, saved, 0, transfer);
            make_file(&mut c, wide, base, z, saved, 0, transfer);
            if matches!(kind, VfsFixture::Retry) {
                call(&mut c, wide, base, 5, &[V(query), V(1)]);
                pointer(&mut c, wide, invalid);
                last(&mut c, wide, base, 998);
            }
            call(&mut c, wide, base, 5, &[V(query), V(out)]);
            pointer(&mut c, wide, 0x70000000);
            store(&mut c, wide, saved);
            find(&mut c, wide, out, "alpha", 0x80, 0, unicode);
            if matches!(kind, VfsFixture::Snapshot) {
                make_file(&mut c, wide, base, b, saved + 8, 0, transfer);
                call(&mut c, wide, base, 3, &[V(z), V(2)]);
                expect(&mut c, 1);
                call(&mut c, wide, base, 2, &[V(b)]);
                expect(&mut c, 0x80);
            }
            if matches!(kind, VfsFixture::Retry) {
                call(&mut c, wide, base, 6, &[M(saved), V(1)]);
                expect(&mut c, 0);
                last(&mut c, wide, base, 998);
                find(&mut c, wide, out, "alpha", 0x80, 0, unicode);
            }
            if matches!(kind, VfsFixture::TypedHandles) {
                call(&mut c, wide, base, 15, &[M(saved)]);
                expect(&mut c, 0);
                last(&mut c, wide, base, 6);
                call(
                    &mut c,
                    wide,
                    base,
                    12,
                    &[V(a), V(0x80000000), V(3), V(0), V(3), V(0x80), V(0)],
                );
                store(&mut c, wide, saved + 8);
                call(&mut c, wide, base, 7, &[M(saved + 8)]);
                expect(&mut c, 0);
                last(&mut c, wide, base, 6);
                call(
                    &mut c,
                    wide,
                    base,
                    14,
                    &[M(saved + 8), V(readout), V(0), V(meta), V(0)],
                );
                expect(&mut c, 1);
                expect_dword(&mut c, wide, meta, 0);
                call(&mut c, wide, base, 15, &[M(saved + 8)]);
                expect(&mut c, 1);
            }
            call(&mut c, wide, base, 6, &[M(saved), V(out)]);
            expect(&mut c, 1);
            find(&mut c, wide, out, "zeta", 0x80, 0, unicode);
            call(&mut c, wide, base, 6, &[M(saved), V(out)]);
            expect(&mut c, 0);
            last(&mut c, wide, base, 18);
            call(&mut c, wide, base, 7, &[M(saved)]);
            expect(&mut c, 1);
            call(&mut c, wide, base, 6, &[M(saved), V(out)]);
            expect(&mut c, 0);
            last(&mut c, wide, base, 6);
            if matches!(kind, VfsFixture::Snapshot) {
                call(&mut c, wide, base, 2, &[V(z)]);
                expect(&mut c, 2);
            }
            if matches!(kind, VfsFixture::TypedHandles) {
                call(&mut c, wide, base, 5, &[V(query), V(out)]);
                pointer(&mut c, wide, 0x70000004);
                store(&mut c, wide, saved);
                call(&mut c, wide, base, 7, &[M(saved)]);
                expect(&mut c, 1);
            }
        }
        VfsFixture::Wildcard => {
            for (rva, value) in [
                (0x2a40, "probe\\a.txt"),
                (0x2a80, "probe\\ab.txt"),
                (0x2b00, "probe\\abc.txt"),
                (0x2b40, "probe\\readme"),
                (0x2b80, "probe\\a?.txt"),
                (0x2bc0, "probe\\*."),
            ] {
                text(&mut data, rva, value, unicode);
            }
            for path in [a, b, z, nested] {
                make_file(&mut c, wide, base, path, saved, 0, transfer);
            }
            call(&mut c, wide, base, 5, &[V(query), V(out)]);
            store(&mut c, wide, saved);
            find(&mut c, wide, out, "a.txt", 0x80, 0, unicode);
            call(&mut c, wide, base, 6, &[M(saved), V(out)]);
            expect(&mut c, 1);
            find(&mut c, wide, out, "ab.txt", 0x80, 0, unicode);
            call(&mut c, wide, base, 6, &[M(saved), V(out)]);
            expect(&mut c, 0);
            last(&mut c, wide, base, 18);
            call(&mut c, wide, base, 7, &[M(saved)]);
            expect(&mut c, 1);
            call(&mut c, wide, base, 5, &[V(other), V(out)]);
            store(&mut c, wide, saved);
            find(&mut c, wide, out, "readme", 0x80, 0, unicode);
            call(&mut c, wide, base, 6, &[M(saved), V(out)]);
            expect(&mut c, 0);
            last(&mut c, wide, base, 18);
            call(&mut c, wide, base, 7, &[M(saved)]);
            expect(&mut c, 1);
        }
        VfsFixture::CurrentDirectory => {
            call(&mut c, wide, base, 10, &[V(dir)]);
            expect(&mut c, 1);
            poison(&mut c, wide, out);
            call(&mut c, wide, base, 11, &[V(64), V(out)]);
            expect(&mut c, 18);
            string(&mut c, wide, out, "C:\\workspace\\probe", unicode);
            text(&mut data, 0x2a40, "relative.bin", unicode);
            make_file(&mut c, wide, base, a, saved, 0, transfer);
            call(&mut c, wide, base, 2, &[V(a)]);
            expect(&mut c, 0x80);
            call(&mut c, wide, base, 10, &[V(missing)]);
            expect(&mut c, 0);
            last(&mut c, wide, base, 3);
            call(&mut c, wide, base, 11, &[V(64), V(out)]);
            expect(&mut c, 18);
            string(&mut c, wide, out, "C:\\workspace\\probe", unicode);
            call(&mut c, wide, base, 1, &[V(dot)]);
            expect(&mut c, 0);
            last(&mut c, wide, base, 5);
            call(&mut c, wide, base, 10, &[V(parent)]);
            expect(&mut c, 1);
            poison(&mut c, wide, out);
            call(&mut c, wide, base, 11, &[V(64), V(out)]);
            expect(&mut c, 12);
            string(&mut c, wide, out, "C:\\workspace", unicode);
            text(&mut data, 0x2bc0, "probe\\relative.bin", unicode);
            call(&mut c, wide, base, 2, &[V(other)]);
            expect(&mut c, 0x80);
        }
        VfsFixture::Paths => {
            text(&mut data, 0x2a40, "..\\workspace\\café.txt", unicode);
            call(&mut c, wide, base, 8, &[V(a), V(0), V(out), V(part)]);
            expect(&mut c, 22);
            expect_dword(&mut c, wide, out, 0x77777777);
            expect_dword(&mut c, wide, part, 0x77777777);
            call(&mut c, wide, base, 8, &[V(a), V(64), V(out), V(part)]);
            expect(&mut c, 21);
            string(&mut c, wide, out, "C:\\workspace\\café.txt", unicode);
            if wide {
                c.push(0x48);
            }
            load(&mut c, wide, part);
            pointer(&mut c, wide, out + 13 * if unicode { 2 } else { 1 });
            call(&mut c, wide, base, 2, &[V(a)]);
            expect(&mut c, u32::MAX);
            last(&mut c, wide, base, 2);
            poison(&mut c, wide, out);
            call(&mut c, wide, base, 9, &[V(dot), V(out), V(64)]);
            expect(&mut c, 1);
            string(&mut c, wide, out, ".", unicode);
            call(&mut c, wide, base, 9, &[V(missing), V(out), V(64)]);
            expect(&mut c, 0);
            last(&mut c, wide, base, 2);
        }
        VfsFixture::Missing => {
            call(&mut c, wide, base, 2, &[V(missing)]);
            expect(&mut c, u32::MAX);
            last(&mut c, wide, base, 2);
            call(&mut c, wide, base, 4, &[V(missing), V(0), V(meta)]);
            expect(&mut c, 0);
            last(&mut c, wide, base, 2);
            expect_dword(&mut c, wide, meta, 0x77777777);
            text(&mut data, 0x2a40, "nomatch*", unicode);
            call(&mut c, wide, base, 5, &[V(a), V(out)]);
            pointer(&mut c, wide, invalid);
            last(&mut c, wide, base, 2);
            expect_dword(&mut c, wide, out, 0x77777777);
            call(&mut c, wide, base, 6, &[V(0x123), V(out)]);
            expect(&mut c, 0);
            last(&mut c, wide, base, 6);
            call(&mut c, wide, base, 7, &[V(0x123)]);
            expect(&mut c, 0);
            last(&mut c, wide, base, 6);
            call(&mut c, wide, base, 1, &[V(missing)]);
            expect(&mut c, 0);
            last(&mut c, wide, base, 3);
            call(&mut c, wide, base, 0, &[V(a), V(0)]);
            expect(&mut c, 0);
            last(&mut c, wide, base, 123);
        }
        VfsFixture::MaskUnsupported => {
            text(&mut data, 0x2b80, "probe\\[ab]*", unicode);
            call(&mut c, wide, base, 5, &[V(query), V(out)]);
        }
        VfsFixture::SecurityUnsupported => call(&mut c, wide, base, 0, &[V(sub), V(1)]),
        VfsFixture::ShortNameUnsupported => {
            text(&mut data, 0x2a40, "PROBE~1", unicode);
            call(&mut c, wide, base, 9, &[V(a), V(out), V(64)]);
        }
    }
    call(&mut c, wide, base, 17, &[V(0x12345678)]);
    last(&mut c, wide, base, 0x12345678);
    c.push(0xb8);
    c.extend(17u32.to_le_bytes());
    if wide {
        c.extend([0x48, 0x83, 0xc4, 0x58]);
    }
    c.push(0xc3);
    assert!(
        c.len() < 0x1000,
        "VFS generated code exceeded owned text section"
    );
    data[0x200..0x200 + c.len()].copy_from_slice(&c);
    data
}
