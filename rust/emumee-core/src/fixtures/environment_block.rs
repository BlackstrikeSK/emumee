//! Real process environment snapshots and exact owned frees from native callers.
use super::winhttp::{
    Arg::{Memory as M, Value as V},
    call, expect_dword, load, store, write_dword,
};
use super::{ApiFixture, api_probe, put16, put32, put64};
use crate::pe::Architecture;
#[derive(Clone, Copy, Debug)]
pub enum EnvironmentBlockFixture {
    Snapshot,
    Empty,
    FreeErrors,
    Quota,
    Live,
    RetiredReallocation,
    Write,
    Protect,
    Free,
    Recommit,
    RetiredRead,
    RetiredExecute,
}
const NAMES: [&str; 24] = [
    "USERPROFILE",
    "USERNAME",
    "COMPUTERNAME",
    "USERDOMAIN",
    "HOMEDRIVE",
    "HOMEPATH",
    "SYSTEMDRIVE",
    "SYSTEMROOT",
    "WINDIR",
    "OS",
    "NUMBER_OF_PROCESSORS",
    "PUBLIC",
    "PROGRAMDATA",
    "PROGRAMFILES",
    "PROGRAMFILES(X86)",
    "PROGRAMW6432",
    "COMMONPROGRAMFILES",
    "COMMONPROGRAMFILES(X86)",
    "COMMONPROGRAMW6432",
    "PATH",
    "TEMP",
    "TMP",
    "APPDATA",
    "LOCALAPPDATA",
];
fn expect(c: &mut Vec<u8>, value: u32) {
    c.push(0x3d);
    c.extend(value.to_le_bytes());
    c.extend([0x74, 1, 0xcc]);
}
fn last(c: &mut Vec<u8>, wide: bool, base: u64, value: u32) {
    call(c, wide, base, 5, &[]);
    expect(c, value);
}
fn text(data: &mut [u8], rva: usize, value: &str) {
    let bytes: Vec<_> = value
        .encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect();
    assert!(bytes.len() <= 64);
    data[rva - 0xe00..rva - 0xe00 + bytes.len()].copy_from_slice(&bytes);
}
fn pointed(c: &mut Vec<u8>, wide: bool, pointer: u64, bytes: &[u8]) {
    for (index, chunk) in bytes.chunks(4).enumerate() {
        if wide {
            c.push(0x48);
        }
        load(c, wide, pointer);
        c.extend([0x8b, 0x80]);
        c.extend((index as u32 * 4).to_le_bytes());
        let mut d = [0; 4];
        d[..chunk.len()].copy_from_slice(chunk);
        expect(c, u32::from_le_bytes(d));
    }
}
fn save(c: &mut Vec<u8>, wide: bool, pointer: u64) {
    c.extend([0x85, 0xc0, 0x75, 1, 0xcc]);
    store(c, wide, pointer);
    if wide {
        expect_dword(c, true, pointer + 4, 1);
    }
    expect_dword(c, wide, pointer + 8, 0x77777777);
}
fn equal(c: &mut Vec<u8>, wide: bool, pointer: u64) {
    if wide {
        c.extend([0x48, 0xba]);
        c.extend(pointer.to_le_bytes());
        c.extend([0x48, 0x8b, 0x12, 0x48, 0x39, 0xd0]);
    } else {
        c.extend([0x8b, 0x15]);
        c.extend((pointer as u32).to_le_bytes());
        c.extend([0x39, 0xd0]);
    }
    c.extend([0x74, 1, 0xcc]);
}
fn counter(c: &mut Vec<u8>, wide: bool, address: u64, start: usize) {
    if wide {
        c.extend([0x48, 0xba]);
        c.extend(address.to_le_bytes());
        c.extend([0xff, 0x02, 0x83, 0x3a, 64]);
    } else {
        c.extend([0xff, 0x05]);
        c.extend((address as u32).to_le_bytes());
        c.extend([0x83, 0x3d]);
        c.extend((address as u32).to_le_bytes());
        c.push(64);
    }
    c.extend([0x0f, 0x85]);
    let end = c.len() + 4;
    c.extend((start as i32 - end as i32).to_le_bytes());
}
fn array(c: &mut Vec<u8>, wide: bool, count: u64, pointers: u64, write: bool) {
    if wide {
        c.extend([0x48, 0xba]);
        c.extend(count.to_le_bytes());
        c.extend([0x8b, 0x0a, 0x48, 0xba]);
        c.extend(pointers.to_le_bytes());
        c.extend(if write {
            [0x48, 0x89, 0x04, 0xca]
        } else {
            [0x48, 0x8b, 0x04, 0xca]
        });
    } else {
        c.extend([0x8b, 0x0d]);
        c.extend((count as u32).to_le_bytes());
        c.extend(if write {
            [0x89, 0x04, 0x8d]
        } else {
            [0x8b, 0x04, 0x8d]
        });
        c.extend((pointers as u32).to_le_bytes());
    }
}
pub fn environment_block_probe(
    architecture: Architecture,
    kind: EnvironmentBlockFixture,
    unicode: bool,
) -> Vec<u8> {
    let wide = architecture == Architecture::X64;
    let base = if wide { 0x140000000u64 } else { 0x400000 };
    let width = if wide { 8usize } else { 4 };
    let template = api_probe(architecture, ApiFixture::Unsupported);
    let mut data = vec![0; 0x4200];
    data[..0x200].copy_from_slice(&template[..0x200]);
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
    let other = if unicode { "A" } else { "W" };
    let names = [
        format!("GetEnvironmentStrings{suffix}"),
        format!("FreeEnvironmentStrings{suffix}"),
        format!("FreeEnvironmentStrings{other}"),
        "SetEnvironmentVariableW".into(),
        "SetLastError".into(),
        "GetLastError".into(),
        "VirtualFree".into(),
        "VirtualProtect".into(),
        "VirtualAlloc".into(),
    ];
    assert!(0x1380 + (names.len() + 1) * width < 0x1500);
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
        data[raw + 2..raw + 2 + name.len()].copy_from_slice(name.as_bytes());
    }
    for (index, name) in NAMES.iter().enumerate() {
        text(&mut data, 0x2a00 + index * 64, name);
    }
    text(&mut data, 0x3100, "PROBE");
    text(&mut data, 0x3140, "é😀");
    text(&mut data, 0x3180, "changed");
    data[0x2600..0x2a00].fill(0x77);
    let h = base + 0x3400;
    let second = base + 0x3420;
    let count = base + 0x3440;
    let old = base + 0x3460;
    let pointers = base + 0x3600;
    let expected: Vec<u8> = if unicode {
        "PROBE=é😀\0\0"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect()
    } else {
        b"PROBE=\x82?\0\0".to_vec()
    };
    let changed: Vec<u8> = if unicode {
        "PROBE=changed\0\0"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect()
    } else {
        b"PROBE=changed\0\0".to_vec()
    };
    let mut c = Vec::new();
    if wide {
        c.extend([0x48, 0x83, 0xec, 0x58]);
    }
    // Explicit known generated names: caller builds an empty environment through
    // real SetEnvironmentVariable, avoiding an implementation-derived byte oracle.
    for (index, _) in NAMES.iter().enumerate() {
        call(
            &mut c,
            wide,
            base,
            3,
            &[V(base + 0x2a00 + index as u64 * 64), V(0)],
        );
        expect(&mut c, 1);
    }
    if !matches!(kind, EnvironmentBlockFixture::Empty) {
        call(&mut c, wide, base, 3, &[V(base + 0x3100), V(base + 0x3140)]);
        expect(&mut c, 1);
    }
    call(&mut c, wide, base, 4, &[V(0x12345678)]);
    if matches!(kind, EnvironmentBlockFixture::Quota) {
        write_dword(&mut c, wide, count, 0);
        let start = c.len();
        call(&mut c, wide, base, 0, &[]);
        c.extend([0x85, 0xc0, 0x75, 1, 0xcc]);
        array(&mut c, wide, count, pointers, true);
        counter(&mut c, wide, count, start);
        last(&mut c, wide, base, 0x12345678);
        call(&mut c, wide, base, 0, &[]);
        expect(&mut c, 0);
        last(&mut c, wide, base, 8);
        call(&mut c, wide, base, 4, &[V(0x12345678)]);
        write_dword(&mut c, wide, count, 0);
        let start = c.len();
        array(&mut c, wide, count, pointers, false);
        store(&mut c, wide, h);
        call(&mut c, wide, base, 1, &[M(h)]);
        expect(&mut c, 1);
        counter(&mut c, wide, count, start);
    } else {
        call(&mut c, wide, base, 0, &[]);
        save(&mut c, wide, h);
        last(&mut c, wide, base, 0x12345678);
        pointed(
            &mut c,
            wide,
            h,
            if matches!(kind, EnvironmentBlockFixture::Empty) {
                if unicode { b"\0\0\0\0" } else { b"\0\0" }
            } else {
                &expected
            },
        );
        match kind {
            EnvironmentBlockFixture::Snapshot => {
                call(&mut c, wide, base, 3, &[V(base + 0x3100), V(base + 0x3180)]);
                expect(&mut c, 1);
                call(&mut c, wide, base, 4, &[V(0x12345678)]);
                call(&mut c, wide, base, 0, &[]);
                save(&mut c, wide, second);
                pointed(&mut c, wide, h, &expected);
                pointed(&mut c, wide, second, &changed);
                call(&mut c, wide, base, 1, &[M(h)]);
                expect(&mut c, 1);
                call(&mut c, wide, base, 1, &[M(second)]);
                expect(&mut c, 1);
            }
            EnvironmentBlockFixture::Empty => {
                call(&mut c, wide, base, 1, &[M(h)]);
                expect(&mut c, 1);
            }
            EnvironmentBlockFixture::FreeErrors => {
                for index in [2, 1] {
                    call(
                        &mut c,
                        wide,
                        base,
                        index,
                        &[if index == 2 { M(h) } else { V(0) }],
                    );
                    expect(&mut c, 0);
                    last(&mut c, wide, base, 87);
                    pointed(&mut c, wide, h, &expected);
                }
                if wide {
                    c.push(0x48);
                }
                load(&mut c, wide, h);
                if wide {
                    c.extend([0x48, 0x83, 0xc0, 1]);
                } else {
                    c.extend([0x83, 0xc0, 1]);
                }
                store(&mut c, wide, second);
                call(&mut c, wide, base, 1, &[M(second)]);
                expect(&mut c, 0);
                last(&mut c, wide, base, 87);
                pointed(&mut c, wide, h, &expected);
                if wide {
                    call(&mut c, true, base, 1, &[V(0x30000000)]);
                    expect(&mut c, 0);
                    last(&mut c, true, base, 87);
                }
                call(&mut c, wide, base, 4, &[V(0x12345678)]);
                call(&mut c, wide, base, 1, &[M(h)]);
                expect(&mut c, 1);
                last(&mut c, wide, base, 0x12345678);
                call(&mut c, wide, base, 1, &[M(h)]);
                expect(&mut c, 0);
                last(&mut c, wide, base, 87);
                call(&mut c, wide, base, 4, &[V(0x12345678)]);
            }
            EnvironmentBlockFixture::Live => {}
            EnvironmentBlockFixture::RetiredReallocation => {
                call(&mut c, wide, base, 1, &[M(h)]);
                expect(&mut c, 1);
                call(&mut c, wide, base, 8, &[M(h), V(4096), V(0x3000), V(4)]);
                equal(&mut c, wide, h);
                call(&mut c, wide, base, 1, &[M(h)]);
                expect(&mut c, 0);
                last(&mut c, wide, base, 87);
                call(&mut c, wide, base, 6, &[M(h), V(0), V(0x8000)]);
                expect(&mut c, 1);
                call(&mut c, wide, base, 4, &[V(0x12345678)]);
            }
            EnvironmentBlockFixture::Write => {
                if wide {
                    c.push(0x48);
                }
                load(&mut c, wide, h);
                c.extend([0xc6, 0x00, 0x41]);
            }
            EnvironmentBlockFixture::Protect => {
                call(&mut c, wide, base, 7, &[M(h), V(4096), V(4), V(old)])
            }
            EnvironmentBlockFixture::Free => call(&mut c, wide, base, 6, &[M(h), V(0), V(0x8000)]),
            EnvironmentBlockFixture::Recommit => {
                call(&mut c, wide, base, 8, &[M(h), V(4096), V(0x1000), V(4)])
            }
            EnvironmentBlockFixture::RetiredRead | EnvironmentBlockFixture::RetiredExecute => {
                call(&mut c, wide, base, 1, &[M(h)]);
                expect(&mut c, 1);
                if wide {
                    c.push(0x48);
                }
                load(&mut c, wide, h);
                c.extend(if matches!(kind, EnvironmentBlockFixture::RetiredRead) {
                    [0x8a, 0x00]
                } else {
                    [0xff, 0xd0]
                });
            }
            EnvironmentBlockFixture::Quota => unreachable!(),
        }
    }
    last(&mut c, wide, base, 0x12345678);
    c.push(0xb8);
    c.extend(17u32.to_le_bytes());
    if wide {
        c.extend([0x48, 0x83, 0xc4, 0x58]);
    }
    c.push(0xc3);
    assert!(
        c.len() < 0x1000,
        "Environment block fixture exceeded owned text section"
    );
    data[0x200..0x200 + c.len()].copy_from_slice(&c);
    data
}
