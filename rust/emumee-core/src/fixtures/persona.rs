//! Harmless Stdcall callers exercise persona/environment effects in guest bytes.
use super::winhttp::{
    Arg::{Memory as M, Value as V},
    call, expect_dword, load, store, write_dword,
};
use super::{ApiFixture, api_probe, put16, put32, put64};
use crate::{pe::Architecture, persona::Encoding};
#[derive(Clone, Copy, Debug)]
pub enum PersonaFixture {
    Variable,
    Mutation,
    Expansion,
    Directories,
    Identity,
    CommandLine,
    CommandFree,
    CommandProtect,
    CommandRecommit,
    BlocksUnsupported,
    CwdUnsupported,
}
fn expect(code: &mut Vec<u8>, value: u32) {
    code.push(0x3d);
    code.extend(value.to_le_bytes());
    code.extend([0x74, 1, 0xcc]);
}
fn error(code: &mut Vec<u8>, wide: bool, base: u64, value: u32) {
    call(code, wide, base, 16, &[]);
    expect(code, value);
}
fn sentinel(code: &mut Vec<u8>, wide: bool, base: u64) {
    call(code, wide, base, 15, &[V(0x12345678)]);
}
fn poison(code: &mut Vec<u8>, wide: bool, address: u64, size: usize) {
    for offset in (0..size.div_ceil(4) * 4 + 4).step_by(4) {
        write_dword(code, wide, address + offset as u64, 0x77777777);
    }
}
fn expect_bytes(code: &mut Vec<u8>, wide: bool, address: u64, bytes: &[u8]) {
    for (index, chunk) in bytes.chunks(4).enumerate() {
        let mut value = [0x77; 4];
        value[..chunk.len()].copy_from_slice(chunk);
        expect_dword(
            code,
            wide,
            address + index as u64 * 4,
            u32::from_le_bytes(value),
        );
    }
    expect_dword(
        code,
        wide,
        address + bytes.len().div_ceil(4) as u64 * 4,
        0x77777777,
    );
}
fn text(data: &mut [u8], rva: usize, text: &str, encoding: Encoding) {
    let bytes = encoding.encode(text, true);
    let at = rva - 0xe00;
    data[at..at + bytes.len()].copy_from_slice(&bytes);
}
fn pointer_equal(code: &mut Vec<u8>, wide: bool, saved: u64) {
    if wide {
        code.extend([0x48, 0xba]);
        code.extend(saved.to_le_bytes());
        code.extend([0x48, 0x8b, 0x12, 0x48, 0x39, 0xd0]);
    } else {
        code.extend([0x8b, 0x15]);
        code.extend((saved as u32).to_le_bytes());
        code.extend([0x39, 0xd0]);
    }
    code.extend([0x74, 1, 0xcc]);
}
fn pointed_bytes(code: &mut Vec<u8>, wide: bool, pointer: u64, bytes: &[u8]) {
    for (index, chunk) in bytes.chunks(4).enumerate() {
        if wide {
            code.push(0x48);
        }
        load(code, wide, pointer);
        code.extend([0x8b, 0x80]);
        code.extend((index as u32 * 4).to_le_bytes());
        let mut value = [0; 4];
        value[..chunk.len()].copy_from_slice(chunk);
        expect(code, u32::from_le_bytes(value));
    }
}
pub fn persona_probe(architecture: Architecture, kind: PersonaFixture, unicode: bool) -> Vec<u8> {
    let wide = architecture == Architecture::X64;
    let base = if wide { 0x140000000u64 } else { 0x400000 };
    let ansi = if unicode {
        Encoding::Utf16
    } else {
        Encoding::Cp1252
    };
    let env = if unicode {
        Encoding::Utf16
    } else {
        Encoding::Cp437
    };
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
    let width = if wide { 8 } else { 4 };
    put32(&mut data, 0x1200, 0x2180);
    put32(&mut data, 0x120c, 0x2040);
    put32(&mut data, 0x1210, 0x2080);
    put32(&mut data, 0x1214, 0x2180 + 20 * width);
    put32(&mut data, 0x1220, 0x2060);
    put32(&mut data, 0x1224, 0x2080 + 20 * width);
    data[0x1240..0x124d].copy_from_slice(b"kernel32.dll\0");
    data[0x1260..0x126d].copy_from_slice(b"advapi32.dll\0");
    let suffix = if unicode { "W" } else { "A" };
    let imports = [
        format!("GetEnvironmentVariable{suffix}"),
        format!("SetEnvironmentVariable{suffix}"),
        format!("ExpandEnvironmentStrings{suffix}"),
        format!("GetCurrentDirectory{suffix}"),
        format!("GetWindowsDirectory{suffix}"),
        format!("GetSystemDirectory{suffix}"),
        format!("GetTempPath{suffix}"),
        format!("GetComputerName{suffix}"),
        format!("GetComputerNameEx{suffix}"),
        format!("GetCommandLine{suffix}"),
        "VirtualFree".into(),
        "VirtualProtect".into(),
        "VirtualAlloc".into(),
        format!("GetEnvironmentStrings{suffix}"),
        format!("SetCurrentDirectory{suffix}"),
        "SetLastError".into(),
        "GetLastError".into(),
        "SetEnvironmentVariableW".into(),
        "GetEnvironmentVariableA".into(),
        String::new(),
        format!("GetUserName{suffix}"),
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
    text(&mut data, 0x2a00, "CASE", env);
    text(&mut data, 0x2a20, "case", env);
    text(&mut data, 0x2a40, "ABSENT", env);
    text(&mut data, 0x2a60, "USERNAME", env);
    text(&mut data, 0x2a80, "TMP", env);
    text(&mut data, 0x2ac0, "CASE", Encoding::Utf16);
    text(&mut data, 0x2ae0, "CASE", Encoding::Cp437);
    text(&mut data, 0x2b00, "é😀", Encoding::Utf16);
    text(
        &mut data,
        0x2b20,
        if matches!(kind, PersonaFixture::Expansion) {
            "%USERNAME%"
        } else {
            "é😀"
        },
        env,
    );
    text(&mut data, 0x2b60, "%USERNAME%|%UNKNOWN%", env);
    text(&mut data, 0x2b90, "%CASE%", env);
    text(&mut data, 0x2bc0, r"D:\T", env);
    text(
        &mut data,
        0x2be0,
        if matches!(kind, PersonaFixture::CwdUnsupported) {
            r"C:relative"
        } else {
            r"C:\workspace"
        },
        ansi,
    );
    let name = base + 0x2a00;
    let mixed = base + 0x2a20;
    let missing = base + 0x2a40;
    let user = base + 0x2a60;
    let tmp = base + 0x2a80;
    let value = base + 0x2b20;
    let expansion = base + 0x2b60;
    let h = base + 0x2c00;
    let size = base + 0x2c10;
    let old = base + 0x2c20;
    let output = base + 0x2d00;
    let mut c = Vec::new();
    if wide {
        c.extend([0x48, 0x83, 0xec, 0x48]);
    }
    sentinel(&mut c, wide, base);
    match kind {
        PersonaFixture::Variable => {
            call(
                &mut c,
                wide,
                base,
                17,
                &[V(base + 0x2ac0), V(base + 0x2b00)],
            );
            expect(&mut c, 1);
            error(&mut c, wide, base, 0x12345678);
            let expected = env.encode("é😀", true);
            let required = (expected.len() / env.width()) as u32;
            call(&mut c, wide, base, 0, &[V(mixed), V(0), V(0)]);
            expect(&mut c, required);
            error(&mut c, wide, base, 122);
            poison(&mut c, wide, output, 16);
            call(&mut c, wide, base, 0, &[V(mixed), V(output), V(1)]);
            expect(&mut c, required);
            error(&mut c, wide, base, 122);
            expect_dword(&mut c, wide, output, 0x77777777);
            call(
                &mut c,
                wide,
                base,
                0,
                &[V(name), V(output), V(required.into())],
            );
            expect(&mut c, required - 1);
            error(&mut c, wide, base, 0);
            expect_bytes(&mut c, wide, output, &expected);
            poison(&mut c, wide, output, 8);
            call(&mut c, wide, base, 18, &[V(base + 0x2ae0), V(output), V(3)]);
            expect(&mut c, 2);
            expect_bytes(&mut c, wide, output, &[0x82, b'?', 0]);
            call(&mut c, wide, base, 0, &[V(missing), V(output), V(16)]);
            expect(&mut c, 0);
            error(&mut c, wide, base, 203);
            call(&mut c, wide, base, 0, &[V(0), V(output), V(16)]);
            expect(&mut c, 0);
            error(&mut c, wide, base, 87);
            call(&mut c, wide, base, 0, &[V(name), V(base + 0x1000), V(16)]);
            expect(&mut c, 0);
            error(&mut c, wide, base, 998);
        }
        PersonaFixture::Mutation => {
            call(&mut c, wide, base, 1, &[V(name), V(value)]);
            expect(&mut c, 1);
            error(&mut c, wide, base, 0x12345678);
            call(&mut c, wide, base, 1, &[V(mixed), V(base + 0x2b40)]);
            expect(&mut c, 1);
            poison(&mut c, wide, output, 16);
            call(&mut c, wide, base, 0, &[V(name), V(output), V(16)]);
            expect(&mut c, 0);
            error(&mut c, wide, base, 0);
            expect_bytes(&mut c, wide, output, &env.encode("", true));
            call(&mut c, wide, base, 1, &[V(name), V(0)]);
            expect(&mut c, 1);
            call(&mut c, wide, base, 0, &[V(name), V(output), V(16)]);
            expect(&mut c, 0);
            error(&mut c, wide, base, 203);
            poison(&mut c, wide, output, 16);
            call(&mut c, wide, base, 0, &[V(user), V(output), V(16)]);
            expect(&mut c, 4);
            error(&mut c, wide, base, 0);
            expect_bytes(&mut c, wide, output, &env.encode("Alex", true));
        }
        PersonaFixture::Expansion => {
            let expected = env.encode("Alex|%UNKNOWN%", true);
            let required = (expected.len() / env.width()) as u32;
            call(&mut c, wide, base, 2, &[V(expansion), V(0), V(0)]);
            expect(&mut c, required);
            error(&mut c, wide, base, 0x12345678);
            poison(&mut c, wide, output, expected.len());
            call(&mut c, wide, base, 2, &[V(expansion), V(output), V(1)]);
            expect(&mut c, required);
            expect_dword(&mut c, wide, output, 0x77777777);
            call(
                &mut c,
                wide,
                base,
                2,
                &[V(expansion), V(output), V(required.into())],
            );
            expect(&mut c, required);
            expect_bytes(&mut c, wide, output, &expected);
            error(&mut c, wide, base, 0x12345678);
            call(&mut c, wide, base, 1, &[V(name), V(value)]);
            expect(&mut c, 1);
            let expected = env.encode("%USERNAME%", true);
            poison(&mut c, wide, output, expected.len());
            call(&mut c, wide, base, 2, &[V(base + 0x2b90), V(output), V(32)]);
            expect(&mut c, (expected.len() / env.width()) as u32);
            expect_bytes(&mut c, wide, output, &expected);
            error(&mut c, wide, base, 0x12345678);
        }
        PersonaFixture::Directories => {
            let current = ansi.encode(r"C:\workspace", true);
            let required = (current.len() / ansi.width()) as u32;
            call(&mut c, wide, base, 3, &[V(0), V(0)]);
            expect(&mut c, required);
            error(&mut c, wide, base, 0x12345678);
            for (index, expected, reversed) in [
                (3, r"C:\workspace", true),
                (4, r"C:\Windows", false),
                (5, r"C:\Windows\System32", false),
                (6, "C:\\Users\\Alex\\AppData\\Local\\Temp\\", true),
            ] {
                let bytes = ansi.encode(expected, true);
                poison(&mut c, wide, output, bytes.len());
                if reversed {
                    call(&mut c, wide, base, index, &[V(128), V(output)]);
                } else {
                    call(&mut c, wide, base, index, &[V(output), V(128)]);
                }
                expect(&mut c, (bytes.len() / ansi.width()) as u32 - 1);
                expect_bytes(&mut c, wide, output, &bytes);
            }
            call(&mut c, wide, base, 1, &[V(tmp), V(base + 0x2bc0)]);
            expect(&mut c, 1);
            let expected = ansi.encode("D:\\T\\", true);
            poison(&mut c, wide, output, expected.len());
            call(&mut c, wide, base, 6, &[V(128), V(output)]);
            expect(&mut c, 5);
            expect_bytes(&mut c, wide, output, &expected);
            error(&mut c, wide, base, 0);
        }
        PersonaFixture::Identity => {
            let computer = ansi.encode("DESKTOP-7F4M2Q9", true);
            let required = (computer.len() / ansi.width()) as u32;
            write_dword(&mut c, wide, size, 1);
            poison(&mut c, wide, output, computer.len());
            call(&mut c, wide, base, 7, &[V(output), V(size)]);
            expect(&mut c, 0);
            error(&mut c, wide, base, 111);
            expect_dword(&mut c, wide, size, required);
            expect_dword(&mut c, wide, output, 0x77777777);
            call(&mut c, wide, base, 7, &[V(output), V(size)]);
            expect(&mut c, 1);
            expect_dword(&mut c, wide, size, required - 1);
            expect_bytes(&mut c, wide, output, &computer);
            error(&mut c, wide, base, 0);
            write_dword(&mut c, wide, size, 1);
            poison(&mut c, wide, output, 16);
            call(&mut c, wide, base, 20, &[V(output), V(size)]);
            expect(&mut c, 0);
            error(&mut c, wide, base, 122);
            expect_dword(&mut c, wide, size, 5);
            call(&mut c, wide, base, 20, &[V(output), V(size)]);
            expect(&mut c, 1);
            expect_dword(&mut c, wide, size, 5);
            expect_bytes(&mut c, wide, output, &ansi.encode("Alex", true));
            write_dword(&mut c, wide, size, 0);
            call(&mut c, wide, base, 8, &[V(3), V(0), V(size)]);
            expect(&mut c, 0);
            error(&mut c, wide, base, 234);
            expect_dword(&mut c, wide, size, required);
            write_dword(&mut c, wide, size, 16);
            poison(&mut c, wide, output, 16);
            call(&mut c, wide, base, 8, &[V(2), V(output), V(size)]);
            expect(&mut c, 1);
            expect_dword(&mut c, wide, size, 0);
            expect_bytes(&mut c, wide, output, &ansi.encode("", true));
            error(&mut c, wide, base, 0);
        }
        PersonaFixture::CommandLine
        | PersonaFixture::CommandFree
        | PersonaFixture::CommandProtect
        | PersonaFixture::CommandRecommit => {
            poison(&mut c, wide, h, 8);
            call(&mut c, wide, base, 9, &[]);
            if wide {
                c.push(0x48);
            }
            c.extend([0x85, 0xc0, 0x75, 1, 0xcc]);
            store(&mut c, wide, h);
            expect_dword(&mut c, wide, h + if wide { 8 } else { 4 }, 0x77777777);
            if wide {
                expect_dword(&mut c, wide, h + 4, 0);
            }
            match kind {
                PersonaFixture::CommandFree => {
                    call(&mut c, wide, base, 10, &[M(h), V(0), V(0x8000)])
                }
                PersonaFixture::CommandProtect => {
                    call(&mut c, wide, base, 11, &[M(h), V(1), V(4), V(old)])
                }
                PersonaFixture::CommandRecommit => {
                    call(&mut c, wide, base, 12, &[M(h), V(1), V(0x1000), V(4)])
                }
                _ => {
                    call(&mut c, wide, base, 9, &[]);
                    pointer_equal(&mut c, wide, h);
                    let expected = ansi.encode(r"C:\workspace\generated-fixture.exe", true);
                    pointed_bytes(&mut c, wide, h, &expected);
                    error(&mut c, wide, base, 0x12345678);
                    call(&mut c, wide, base, 0, &[V(user), M(h), V(64)]);
                    expect(&mut c, 0);
                    error(&mut c, wide, base, 998);
                    call(&mut c, wide, base, 9, &[]);
                    pointer_equal(&mut c, wide, h);
                    pointed_bytes(&mut c, wide, h, &expected);
                }
            }
        }
        PersonaFixture::BlocksUnsupported => {
            call(&mut c, wide, base, 13, &[]);
            store(&mut c, wide, h);
            call(&mut c, wide, base, 10, &[M(h), V(0), V(0x8000)]);
        }
        PersonaFixture::CwdUnsupported => call(&mut c, wide, base, 14, &[V(base + 0x2be0)]),
    }
    if matches!(
        kind,
        PersonaFixture::CommandFree
            | PersonaFixture::CommandProtect
            | PersonaFixture::CommandRecommit
            | PersonaFixture::BlocksUnsupported
            | PersonaFixture::CwdUnsupported
    ) {
        c.push(0xcc);
    }
    c.extend([0xb8, 17, 0, 0, 0]);
    if wide {
        c.extend([0x48, 0x83, 0xc4, 0x48]);
    }
    c.push(0xc3);
    assert!(
        c.len() <= 0x1000,
        "persona caller exceeded owned text section"
    );
    data[0x200..0x200 + c.len()].copy_from_slice(&c);
    data
}
