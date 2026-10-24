//! Owned Stdcall registry callers verify guest output and LSTATUS directly.
use super::winhttp::{
    Arg::{Memory as M, Value as V},
    call, expect_dword, load, write_dword,
};
use super::{ApiFixture, api_probe, put16, put32, put64};
use crate::pe::Architecture;
use crate::registry::{HKCU, KEY_ALL_ACCESS, KEY_READ, REG_BINARY, REG_DWORD, REG_SZ, encode_text};

#[derive(Clone, Copy, Debug)]
pub enum RegistryFixture {
    Lifecycle,
    Enumeration,
    SmallBuffer,
    DefaultValue,
    InvalidHandle,
    ClosedHandle,
    ReadOnly,
    Options,
}
fn expect(code: &mut Vec<u8>, value: u32) {
    code.push(0x3d);
    code.extend(value.to_le_bytes());
    code.extend([0x74, 1, 0xcc]);
}
fn poison(code: &mut Vec<u8>, wide: bool, address: u64, count: usize) {
    for index in 0..count {
        write_dword(code, wide, address + index as u64 * 4, 0x77777777);
    }
}
fn intact(code: &mut Vec<u8>, wide: bool, address: u64) {
    expect_dword(code, wide, address, 0x77777777);
}
fn create(
    code: &mut Vec<u8>,
    wide: bool,
    base: u64,
    root: u64,
    path: u64,
    handle: u64,
    disposition: u64,
) {
    call(
        code,
        wide,
        base,
        0,
        &[
            V(root),
            V(path),
            V(0),
            V(0),
            V(0),
            V(KEY_ALL_ACCESS.into()),
            V(0),
            V(handle),
            V(disposition),
        ],
    );
    expect(code, 0);
    expect_dword(code, wide, disposition, 1);
    // A pointer-width output must not overrun the HKEY slot. x64 handles also
    // overwrite the high half of its poisoned 64-bit output with zero.
    if wide {
        expect_dword(code, wide, handle + 4, 0);
    }
    intact(code, wide, handle + if wide { 8 } else { 4 });
    load(code, wide, handle);
    code.extend([0x85, 0xc0, 0x75, 1, 0xcc]);
}
/// `unicode` selects A/W registry APIs independently of PE architecture.
pub fn registry_probe(architecture: Architecture, kind: RegistryFixture, unicode: bool) -> Vec<u8> {
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
    put16(&mut data, 0x98 + 68, 3);
    put16(&mut data, 0x96, 0x22);
    put32(&mut data, dd + 8, 0x2000);
    put32(&mut data, dd + 12, 60);
    // Import directory: advapi32 (twelve functions), kernel32 (two), sentinel.
    put32(&mut data, 0x1200, 0x2180);
    put32(&mut data, 0x120c, 0x2040);
    put32(&mut data, 0x1210, 0x2080);
    let width = if wide { 8 } else { 4 };
    put32(&mut data, 0x1214, 0x2180 + 13 * width);
    put32(&mut data, 0x1220, 0x2060);
    put32(&mut data, 0x1224, 0x2080 + 13 * width);
    data[0x1240..0x124d].copy_from_slice(b"advapi32.dll\0");
    data[0x1260..0x126d].copy_from_slice(b"kernel32.dll\0");
    let suffix = if unicode { "W" } else { "A" };
    let imports = [
        format!("RegCreateKeyEx{suffix}"),
        format!("RegOpenKeyEx{suffix}"),
        format!("RegSetValueEx{suffix}"),
        format!("RegQueryValueEx{suffix}"),
        format!("RegGetValue{suffix}"),
        "RegCloseKey".into(),
        format!("RegDeleteKey{suffix}"),
        format!("RegCreateKey{suffix}"),
        format!("RegOpenKey{suffix}"),
        format!("RegEnumValue{suffix}"),
        format!("RegEnumKeyEx{suffix}"),
        format!("RegQueryInfoKey{suffix}"),
        String::new(),
        "SetLastError".into(),
        "GetLastError".into(),
    ];
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
        data[raw + 2..raw + 2 + name.len()].copy_from_slice(name.as_bytes());
    }
    let path = base + 0x2a00;
    let name = base + 0x2a80;
    let string = base + 0x2b00;
    let binary = base + 0x2b40;
    let h = base + 0x2c00;
    let other = base + 0x2c10;
    let disposition = base + 0x2c20;
    let size = base + 0x2c30;
    let value_type = base + 0x2c40;
    let output = base + 0x2d00;
    let path_bytes = encode_text("Software\\EmumeeRegistryFixture", unicode, true);
    data[0x1c00..0x1c00 + path_bytes.len()].copy_from_slice(&path_bytes);
    let name_bytes = encode_text("Raw", unicode, true);
    data[0x1c80..0x1c80 + name_bytes.len()].copy_from_slice(&name_bytes);
    let string_bytes = encode_text("Abc", unicode, false);
    data[0x1d00..0x1d00 + string_bytes.len()].copy_from_slice(&string_bytes);
    data[0x1d40..0x1d44].copy_from_slice(&[0xf0, 0x00, 0x80, 0xff]);
    let root = if wide { 0xffffffff80000001 } else { HKCU };
    let mut c = Vec::new();
    if wide {
        c.extend([0x48, 0x83, 0xec, 0x68]);
    }
    poison(&mut c, wide, h, 8);
    poison(&mut c, wide, output, 8);
    poison(&mut c, wide, size, 1);
    poison(&mut c, wide, value_type, 1);
    call(&mut c, wide, base, 13, &[V(0x12345678)]);
    if matches!(kind, RegistryFixture::InvalidHandle) {
        call(
            &mut c,
            wide,
            base,
            3,
            &[
                V(0x11223344),
                V(name),
                V(0),
                V(value_type),
                V(output),
                V(size),
            ],
        );
        expect(&mut c, 6);
        intact(&mut c, wide, size);
        intact(&mut c, wide, output);
    } else if matches!(kind, RegistryFixture::Options) {
        // The adapter must stop here; no successful return is fabricated.
        call(
            &mut c,
            wide,
            base,
            0,
            &[
                V(root),
                V(path),
                V(0),
                V(0),
                V(1),
                V(KEY_ALL_ACCESS.into()),
                V(0),
                V(h),
                V(disposition),
            ],
        );
        c.push(0xcc);
    } else {
        create(&mut c, wide, base, root, path, h, disposition);
        match kind {
            RegistryFixture::Enumeration => {
                let name_size = base + 0x2c50;
                let class_size = base + 0x2c60;
                let info = base + 0x2c80;
                let name_output = base + 0x2d40;
                let class_output = base + 0x2d80;
                poison(&mut c, wide, name_output, 4);
                poison(&mut c, wide, class_output, 2);
                call(
                    &mut c,
                    wide,
                    base,
                    2,
                    &[M(h), V(name), V(0), V(REG_BINARY.into()), V(binary), V(4)],
                );
                expect(&mut c, 0);
                call(
                    &mut c,
                    wide,
                    base,
                    0,
                    &[
                        M(h),
                        V(name),
                        V(0),
                        V(0),
                        V(0),
                        V(KEY_ALL_ACCESS.into()),
                        V(0),
                        V(other),
                        V(disposition),
                    ],
                );
                expect(&mut c, 0);
                expect_dword(&mut c, wide, disposition, 1);
                call(&mut c, wide, base, 5, &[M(other)]);
                expect(&mut c, 0);
                write_dword(&mut c, wide, name_size, 1);
                write_dword(&mut c, wide, size, 32);
                call(
                    &mut c,
                    wide,
                    base,
                    9,
                    &[
                        M(h),
                        V(0),
                        V(name_output),
                        V(name_size),
                        V(0),
                        V(value_type),
                        V(output),
                        V(size),
                    ],
                );
                expect(&mut c, 234);
                expect_dword(&mut c, wide, name_size, 1);
                expect_dword(&mut c, wide, size, 4);
                expect_dword(&mut c, wide, value_type, REG_BINARY);
                intact(&mut c, wide, name_output);
                intact(&mut c, wide, output);
                write_dword(&mut c, wide, name_size, 16);
                write_dword(&mut c, wide, size, 2);
                call(
                    &mut c,
                    wide,
                    base,
                    9,
                    &[
                        M(h),
                        V(0),
                        V(name_output),
                        V(name_size),
                        V(0),
                        V(value_type),
                        V(output),
                        V(size),
                    ],
                );
                expect(&mut c, 234);
                expect_dword(&mut c, wide, name_size, 3);
                expect_dword(&mut c, wide, size, 4);
                expect_dword(
                    &mut c,
                    wide,
                    name_output,
                    if unicode { 0x00610052 } else { 0x00776152 },
                );
                if unicode {
                    expect_dword(&mut c, wide, name_output + 4, 0x77);
                }
                intact(&mut c, wide, output);
                write_dword(&mut c, wide, name_size, 16);
                call(
                    &mut c,
                    wide,
                    base,
                    9,
                    &[
                        M(h),
                        V(0),
                        V(name_output),
                        V(name_size),
                        V(0),
                        V(value_type),
                        V(output),
                        V(size),
                    ],
                );
                expect(&mut c, 0);
                expect_dword(&mut c, wide, name_size, 3);
                expect_dword(&mut c, wide, output, 0xff8000f0);
                intact(&mut c, wide, output + 4);
                write_dword(&mut c, wide, name_size, 16);
                call(
                    &mut c,
                    wide,
                    base,
                    9,
                    &[
                        M(h),
                        V(1),
                        V(name_output),
                        V(name_size),
                        V(0),
                        V(0),
                        V(0),
                        V(0),
                    ],
                );
                expect(&mut c, 259);
                expect_dword(&mut c, wide, name_size, 16);
                write_dword(&mut c, wide, class_size, 1);
                call(
                    &mut c,
                    wide,
                    base,
                    10,
                    &[
                        M(h),
                        V(0),
                        V(name_output),
                        V(name_size),
                        V(0),
                        V(class_output),
                        V(class_size),
                        V(0),
                    ],
                );
                expect(&mut c, 0);
                expect_dword(&mut c, wide, name_size, 3);
                expect_dword(&mut c, wide, class_size, 0);
                expect_dword(
                    &mut c,
                    wide,
                    class_output,
                    if unicode { 0x77770000 } else { 0x77777700 },
                );
                write_dword(&mut c, wide, name_size, 16);
                call(
                    &mut c,
                    wide,
                    base,
                    10,
                    &[
                        M(h),
                        V(1),
                        V(name_output),
                        V(name_size),
                        V(0),
                        V(0),
                        V(0),
                        V(0),
                    ],
                );
                expect(&mut c, 259);
                write_dword(&mut c, wide, class_size, 1);
                call(
                    &mut c,
                    wide,
                    base,
                    11,
                    &[
                        M(h),
                        V(class_output),
                        V(class_size),
                        V(0),
                        V(info),
                        V(info + 4),
                        V(info + 8),
                        V(info + 12),
                        V(info + 16),
                        V(info + 20),
                        V(0),
                        V(0),
                    ],
                );
                expect(&mut c, 0);
                for (offset, expected) in [(0, 1), (4, 3), (8, 0), (12, 1), (16, 3), (20, 4)] {
                    expect_dword(&mut c, wide, info + offset, expected);
                }
                expect_dword(&mut c, wide, class_size, 0);
                call(&mut c, wide, base, 5, &[M(h)]);
                expect(&mut c, 0);
            }
            RegistryFixture::Lifecycle => {
                call(
                    &mut c,
                    wide,
                    base,
                    2,
                    &[M(h), V(name), V(0), V(REG_BINARY.into()), V(binary), V(4)],
                );
                expect(&mut c, 0);
                write_dword(&mut c, wide, size, 32);
                call(
                    &mut c,
                    wide,
                    base,
                    3,
                    &[M(h), V(name), V(0), V(value_type), V(output), V(size)],
                );
                expect(&mut c, 0);
                expect_dword(&mut c, wide, value_type, REG_BINARY);
                expect_dword(&mut c, wide, size, 4);
                expect_dword(&mut c, wide, output, 0xff8000f0);
                intact(&mut c, wide, output + 4);
                call(
                    &mut c,
                    wide,
                    base,
                    2,
                    &[
                        M(h),
                        V(name),
                        V(0),
                        V(REG_SZ.into()),
                        V(string),
                        V(string_bytes.len() as u64),
                    ],
                );
                expect(&mut c, 0);
                poison(&mut c, wide, output, 3);
                write_dword(&mut c, wide, size, 32);
                call(
                    &mut c,
                    wide,
                    base,
                    3,
                    &[M(h), V(name), V(0), V(value_type), V(output), V(size)],
                );
                expect(&mut c, 0);
                expect_dword(&mut c, wide, size, string_bytes.len() as u32);
                expect_dword(&mut c, wide, value_type, REG_SZ);
                expect_dword(
                    &mut c,
                    wide,
                    output,
                    if unicode { 0x00620041 } else { 0x77636241 },
                );
                if unicode {
                    expect_dword(&mut c, wide, output + 4, 0x77770063);
                }
                call(&mut c, wide, base, 5, &[M(h)]);
                expect(&mut c, 0);
                call(
                    &mut c,
                    wide,
                    base,
                    1,
                    &[V(root), V(path), V(0), V(KEY_READ.into()), V(other)],
                );
                expect(&mut c, 0);
                if wide {
                    expect_dword(&mut c, wide, other + 4, 0);
                }
                intact(&mut c, wide, other + if wide { 8 } else { 4 });
                write_dword(&mut c, wide, size, 32);
                call(
                    &mut c,
                    wide,
                    base,
                    4,
                    &[
                        M(other),
                        V(0),
                        V(name),
                        V(0xffff),
                        V(value_type),
                        V(output),
                        V(size),
                    ],
                );
                expect(&mut c, 0);
                expect_dword(&mut c, wide, size, if unicode { 8 } else { 4 });
                expect_dword(
                    &mut c,
                    wide,
                    output,
                    if unicode { 0x00620041 } else { 0x00636241 },
                );
                if unicode {
                    expect_dword(&mut c, wide, output + 4, 0x63);
                }
                call(&mut c, wide, base, 6, &[V(root), V(path)]);
                expect(&mut c, 0);
                call(
                    &mut c,
                    wide,
                    base,
                    3,
                    &[M(other), V(name), V(0), V(0), V(0), V(size)],
                );
                expect(&mut c, 1018);
                call(&mut c, wide, base, 5, &[M(other)]);
                expect(&mut c, 0);
                poison(&mut c, wide, other, 2);
                call(
                    &mut c,
                    wide,
                    base,
                    1,
                    &[V(root), V(path), V(0), V(KEY_READ.into()), V(other)],
                );
                expect(&mut c, 2);
                intact(&mut c, wide, other);
            }
            RegistryFixture::SmallBuffer => {
                call(
                    &mut c,
                    wide,
                    base,
                    2,
                    &[M(h), V(name), V(0), V(REG_BINARY.into()), V(binary), V(4)],
                );
                expect(&mut c, 0);
                write_dword(&mut c, wide, size, 0);
                call(
                    &mut c,
                    wide,
                    base,
                    3,
                    &[M(h), V(name), V(0), V(value_type), V(0), V(size)],
                );
                expect(&mut c, 0);
                expect_dword(&mut c, wide, size, 4);
                write_dword(&mut c, wide, size, 2);
                call(
                    &mut c,
                    wide,
                    base,
                    3,
                    &[M(h), V(name), V(0), V(value_type), V(output), V(size)],
                );
                expect(&mut c, 234);
                expect_dword(&mut c, wide, size, 4);
                expect_dword(&mut c, wide, value_type, REG_BINARY);
                intact(&mut c, wide, output);
                call(
                    &mut c,
                    wide,
                    base,
                    3,
                    &[M(h), V(name), V(0), V(value_type), V(output), V(size)],
                );
                expect(&mut c, 0);
                expect_dword(&mut c, wide, output, 0xff8000f0);
                intact(&mut c, wide, output + 4);
                call(&mut c, wide, base, 5, &[M(h)]);
                expect(&mut c, 0);
            }
            RegistryFixture::DefaultValue => {
                call(
                    &mut c,
                    wide,
                    base,
                    2,
                    &[M(h), V(0), V(0), V(REG_DWORD.into()), V(binary), V(4)],
                );
                expect(&mut c, 0);
                write_dword(&mut c, wide, size, 32);
                call(
                    &mut c,
                    wide,
                    base,
                    3,
                    &[M(h), V(0), V(0), V(value_type), V(output), V(size)],
                );
                expect(&mut c, 0);
                expect_dword(&mut c, wide, value_type, REG_DWORD);
                expect_dword(&mut c, wide, size, 4);
                expect_dword(&mut c, wide, output, 0xff8000f0);
                intact(&mut c, wide, output + 4);
                call(&mut c, wide, base, 5, &[M(h)]);
                expect(&mut c, 0);
            }
            RegistryFixture::ClosedHandle => {
                call(&mut c, wide, base, 5, &[M(h)]);
                expect(&mut c, 0);
                call(
                    &mut c,
                    wide,
                    base,
                    3,
                    &[M(h), V(name), V(0), V(value_type), V(output), V(size)],
                );
                expect(&mut c, 6);
                intact(&mut c, wide, output);
                call(&mut c, wide, base, 5, &[M(h)]);
                expect(&mut c, 6);
            }
            RegistryFixture::ReadOnly => {
                call(&mut c, wide, base, 5, &[M(h)]);
                expect(&mut c, 0);
                call(
                    &mut c,
                    wide,
                    base,
                    1,
                    &[V(root), V(path), V(0), V(KEY_READ.into()), V(other)],
                );
                expect(&mut c, 0);
                call(
                    &mut c,
                    wide,
                    base,
                    2,
                    &[
                        M(other),
                        V(name),
                        V(0),
                        V(REG_BINARY.into()),
                        V(binary),
                        V(4),
                    ],
                );
                expect(&mut c, 5);
                call(
                    &mut c,
                    wide,
                    base,
                    3,
                    &[M(other), V(name), V(0), V(0), V(0), V(size)],
                );
                expect(&mut c, 2);
                call(&mut c, wide, base, 5, &[M(other)]);
                expect(&mut c, 0);
            }
            RegistryFixture::InvalidHandle | RegistryFixture::Options => unreachable!(),
        }
    }
    call(&mut c, wide, base, 14, &[]);
    expect(&mut c, 0x12345678);
    c.extend([0xb8, 17, 0, 0, 0]);
    if wide {
        c.extend([0x48, 0x83, 0xc4, 0x68]);
    }
    c.push(0xc3);
    assert!(c.len() <= 0x1000);
    data[0x200..0x200 + c.len()].copy_from_slice(&c);
    data
}
