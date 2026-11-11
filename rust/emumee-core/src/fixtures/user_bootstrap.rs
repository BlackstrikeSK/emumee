use super::winhttp::{
    Arg::{Memory, Value},
    call, load, store, write_dword,
};
use super::{UserRuntimeFixture, put32, put64, user_runtime_probe};
use crate::pe::Architecture;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootstrapFixture {
    Basic,
    Mutation,
    Protect,
    Free,
}

fn expect(code: &mut Vec<u8>, value: u32) {
    code.push(0x3d);
    code.extend(value.to_le_bytes());
    code.extend([0x74, 1, 0xcc]);
}

fn segment(code: &mut Vec<u8>, wide: bool, offset: u32) {
    if wide {
        code.extend([0x65, 0x48, 0x8b, 4, 0x25]);
    } else {
        code.extend([0x64, 0xa1]);
    }
    code.extend(offset.to_le_bytes());
}

fn field(code: &mut Vec<u8>, wide: bool, saved: u64, offset: u32, pointer: bool) {
    load(code, wide, saved);
    if wide && pointer {
        code.push(0x48);
    }
    code.extend([0x8b, 0x80]);
    code.extend(offset.to_le_bytes());
}

fn equal_saved(code: &mut Vec<u8>, wide: bool, saved: u64) {
    if wide {
        code.extend([0x48, 0xb9]);
        code.extend(saved.to_le_bytes());
        code.extend([0x48, 0x8b, 9, 0x48, 0x39, 0xc8]);
    } else {
        code.extend([0x3b, 5]);
        code.extend((saved as u32).to_le_bytes());
    }
    code.extend([0x74, 1, 0xcc]);
}

fn compare_text(code: &mut Vec<u8>, wide: bool, environment: bool) {
    let start = code.len();
    code.extend([0x66, 0x8b, 0x10, 0x66, 0x3b, 0x11, 0x74, 1, 0xcc]);
    if wide {
        code.push(0x48);
    }
    code.extend([0x83, 0xc0, 2]);
    if wide {
        code.push(0x48);
    }
    code.extend([0x83, 0xc1, 2, 0x66, 0x85, 0xd2, 0x75]);
    code.push((start as isize - (code.len() + 1) as isize) as i8 as u8);
    if environment {
        code.extend([0x66, 0x83, 0x38, 0, 0x75]);
        code.push((start as isize - (code.len() + 1) as isize) as i8 as u8);
        code.extend([0x66, 0x83, 0x39, 0, 0x74, 1, 0xcc]);
    }
}

fn second_pointer(code: &mut Vec<u8>, wide: bool, address: u64, indirect: bool) {
    if wide {
        code.extend([0x48, 0xb9]);
        code.extend(address.to_le_bytes());
    } else {
        code.push(0xb9);
        code.extend((address as u32).to_le_bytes());
    }
    if indirect {
        if wide {
            code.push(0x48);
        }
        code.extend([0x8b, 9]);
    }
}

fn check_length(code: &mut Vec<u8>, wide: bool, parameters: u64, offset: u32) {
    field(
        code,
        wide,
        parameters,
        offset + if wide { 8 } else { 4 },
        true,
    );
    code.extend([0x31, 0xc9]);
    let start = code.len();
    code.extend([0x66, 0x83, 0x38, 0, 0x74, if wide { 9 } else { 8 }]);
    if wide {
        code.push(0x48);
    }
    code.extend([0x83, 0xc0, 2, 0x83, 0xc1, 2, 0xeb]);
    code.push((start as isize - (code.len() + 1) as isize) as i8 as u8);
    load(code, wide, parameters);
    code.extend([0x0f, 0xb7, 0x90]);
    code.extend((offset + 2).to_le_bytes());
    code.extend([0x0f, 0xb7, 0x80]);
    code.extend(offset.to_le_bytes());
    code.extend([0x39, 0xc8, 0x74, 1, 0xcc, 0x39, 0xd0, 0x76, 1, 0xcc]);
}

pub fn user_bootstrap_probe(
    architecture: Architecture,
    kind: BootstrapFixture,
    dll: bool,
) -> Vec<u8> {
    let wide = architecture == Architecture::X64;
    let width = architecture.width();
    let base = if wide { 0x140000000u64 } else { 0x400000u64 };
    let mut bytes = user_runtime_probe(architecture, UserRuntimeFixture::Process);
    if dll {
        bytes[0x96..0x98].copy_from_slice(&0x2022u16.to_le_bytes());
    }
    bytes[0x1280..0x1400].fill(0);
    let names = [
        "GetCommandLineW",
        "GetCurrentProcessId",
        "GetCurrentThreadId",
        "GetLastError",
        "SetLastError",
        "GetEnvironmentStringsW",
        "FreeEnvironmentStringsW",
        "SetEnvironmentVariableW",
        "GetCurrentDirectoryW",
        "SetCurrentDirectoryW",
        "VirtualProtect",
        "VirtualFree",
        "GetModuleFileNameW",
        "GetVersion",
        "GetStdHandle",
        "GetCurrentProcess",
        "WriteProcessMemory",
        "GetSystemInfo",
        "GetStartupInfoW",
    ];
    for (index, name) in names.iter().enumerate() {
        let rva = 0x2300 + index * 64;
        for address in [0x1280, 0x1380] {
            if wide {
                put64(&mut bytes, address + index * width, rva as u64);
            } else {
                put32(&mut bytes, address + index * width, rva as u32);
            }
        }
        let raw = rva - 0xe00;
        bytes[raw..raw + 64].fill(0);
        bytes[raw + 2..raw + 2 + name.len()].copy_from_slice(name.as_bytes());
    }
    for (offset, text) in [
        (0x2b00, "C:\\"),
        (0x2b40, "BOOTSTRAP_VALUE"),
        (0x2b80, "changed"),
    ] {
        let value = crate::persona::Encoding::Utf16.encode(text, true);
        bytes[offset - 0xe00..offset - 0xe00 + value.len()].copy_from_slice(&value);
    }
    let teb = base + 0x2e00;
    let peb = teb + 8;
    let parameters = peb + 8;
    let saved = parameters + 8;
    let snapshot = saved + 8;
    let output = base + 0x2d00;
    let mut code = vec![];
    if wide {
        code.extend([0x48, 0x83, 0xec, 0x48]);
    }
    segment(&mut code, wide, if wide { 0x30 } else { 0x18 });
    store(&mut code, wide, teb);
    if matches!(kind, BootstrapFixture::Protect | BootstrapFixture::Free) {
        if kind == BootstrapFixture::Protect {
            call(
                &mut code,
                wide,
                base,
                10,
                &[Memory(teb), Value(4096), Value(2), Value(output)],
            );
        } else {
            call(
                &mut code,
                wide,
                base,
                11,
                &[Memory(teb), Value(0), Value(0x8000)],
            );
        }
        code.push(0xcc);
    } else {
        field(&mut code, wide, teb, if wide { 0x30 } else { 0x18 }, true);
        equal_saved(&mut code, wide, teb);
        field(&mut code, wide, teb, 0, true);
        expect(&mut code, u32::MAX);
        field(&mut code, wide, teb, if wide { 0x60 } else { 0x30 }, true);
        store(&mut code, wide, peb);
        field(&mut code, wide, peb, if wide { 0x10 } else { 8 }, true);
        store(&mut code, wide, saved);
        if wide {
            code.extend([0x48, 0xb8]);
            code.extend(base.to_le_bytes());
        } else {
            code.push(0xb8);
            code.extend((base as u32).to_le_bytes());
        }
        equal_saved(&mut code, wide, saved);
        field(&mut code, wide, peb, if wide { 0x20 } else { 0x10 }, true);
        store(&mut code, wide, parameters);
        for (offset, value) in [(0, 0x1000), (4, if wide { 0xf0 } else { 0x90 }), (8, 1)] {
            field(&mut code, wide, parameters, offset, false);
            expect(&mut code, value);
        }
        for offset in if wide {
            [0x38, 0x60, 0x70]
        } else {
            [0x24, 0x38, 0x40]
        } {
            check_length(&mut code, wide, parameters, offset);
        }
        check_length(&mut code, wide, parameters, if wide { 0xc0 } else { 0x78 });
        call(&mut code, wide, base, 18, &[Value(output)]);
        load(&mut code, wide, output + 2 * width as u64);
        store(&mut code, wide, snapshot);
        field(
            &mut code,
            wide,
            parameters,
            if wide { 0xc8 } else { 0x7c },
            true,
        );
        equal_saved(&mut code, wide, snapshot);
        call(&mut code, wide, base, 13, &[]);
        code.extend([0xc1, 0xe8, 16]);
        store(&mut code, wide, saved);
        field(&mut code, wide, peb, if wide { 0x120 } else { 0xac }, false);
        equal_saved(&mut code, wide, saved);
        field(&mut code, wide, peb, if wide { 0x118 } else { 0xa4 }, false);
        expect(&mut code, 10);
        call(&mut code, wide, base, 17, &[Value(output)]);
        if wide {
            code.extend([0x48, 0xb8]);
            code.extend((output + 32).to_le_bytes());
            code.extend([0x8b, 0]);
        } else {
            code.push(0xa1);
            code.extend(((output + 20) as u32).to_le_bytes());
        }
        store(&mut code, wide, saved);
        field(&mut code, wide, peb, if wide { 0xb8 } else { 0x64 }, false);
        equal_saved(&mut code, wide, saved);
        for (index, offset) in [
            (1, if wide { 0x40 } else { 0x20 }),
            (2, if wide { 0x48 } else { 0x24 }),
        ] {
            call(&mut code, wide, base, index, &[]);
            store(&mut code, wide, saved);
            field(&mut code, wide, teb, offset, true);
            equal_saved(&mut code, wide, saved);
        }
        for (offset, condition) in [(width as u32, 0x72), (2 * width as u32, 0x73)] {
            field(&mut code, wide, teb, offset, true);
            if wide {
                code.extend([0x48, 0x89, 0xe1, 0x48, 0x39, 0xc1]);
            } else {
                code.extend([0x89, 0xe1, 0x39, 0xc1]);
            }
            code.extend([condition, 1, 0xcc]);
        }
        call(&mut code, wide, base, 0, &[]);
        store(&mut code, wide, saved);
        field(
            &mut code,
            wide,
            parameters,
            if wide { 0x78 } else { 0x44 },
            true,
        );
        equal_saved(&mut code, wide, saved);
        call(
            &mut code,
            wide,
            base,
            12,
            &[Value(0), Value(output), Value(128)],
        );
        field(
            &mut code,
            wide,
            parameters,
            if wide { 0x68 } else { 0x3c },
            true,
        );
        second_pointer(&mut code, wide, output, false);
        compare_text(&mut code, wide, false);
        for (index, selector) in [u32::MAX - 9, u32::MAX - 10, u32::MAX - 11]
            .into_iter()
            .enumerate()
        {
            call(&mut code, wide, base, 14, &[Value(selector as u64)]);
            store(&mut code, wide, saved);
            field(
                &mut code,
                wide,
                parameters,
                if wide { 0x20 } else { 0x18 } + index as u32 * width as u32,
                true,
            );
            equal_saved(&mut code, wide, saved);
        }
        call(&mut code, wide, base, 3, &[]);
        expect(&mut code, 0);
        let error = if wide { 0x68u32 } else { 0x34u32 };
        code.extend([
            if wide { 0x65 } else { 0x64 },
            0xc7,
            if wide { 4 } else { 5 },
        ]);
        if wide {
            code.push(0x25);
        }
        code.extend(error.to_le_bytes());
        code.extend(0x12345678u32.to_le_bytes());
        call(&mut code, wide, base, 3, &[]);
        expect(&mut code, 0x12345678);
        call(&mut code, wide, base, 4, &[Value(0x87654321)]);
        field(&mut code, wide, teb, error, false);
        expect(&mut code, 0x87654321);
        code.extend([
            if wide { 0x65 } else { 0x64 },
            0xc6,
            if wide { 4 } else { 5 },
        ]);
        if wide {
            code.push(0x25);
        }
        code.extend((error + 1).to_le_bytes());
        code.push(0xab);
        call(&mut code, wide, base, 3, &[]);
        expect(&mut code, 0x8765ab21);
        if wide {
            code.extend([0x48, 0xb8]);
            code.extend(0x0011223344556677u64.to_le_bytes());
            code.extend([0x65, 0x48, 0x89, 4, 0x25]);
            code.extend((error - 2).to_le_bytes());
        } else {
            code.extend([0x64, 0xc7, 5]);
            code.extend((error - 2).to_le_bytes());
            code.extend(0x66778899u32.to_le_bytes());
        }
        call(&mut code, wide, base, 3, &[]);
        expect(&mut code, if wide { 0x22334455 } else { 0x87656677 });
        load(&mut code, wide, peb);
        if wide {
            code.extend([0x65, 0x48, 0x89, 4, 0x25]);
            code.extend(0x60u32.to_le_bytes());
        } else {
            code.extend([0x64, 0xa3]);
            code.extend(0x30u32.to_le_bytes());
        }
        write_dword(&mut code, wide, output, 0xabcdef12);
        call(&mut code, wide, base, 15, &[]);
        store(&mut code, wide, snapshot);
        load(&mut code, wide, teb);
        if wide {
            code.push(0x48);
        }
        code.extend([0x05]);
        code.extend(error.to_le_bytes());
        store(&mut code, wide, saved);
        call(
            &mut code,
            wide,
            base,
            16,
            &[
                Memory(snapshot),
                Memory(saved),
                Value(output),
                Value(4),
                Value(output + 16),
            ],
        );
        expect(&mut code, 1);
        call(&mut code, wide, base, 3, &[]);
        expect(&mut code, 0xabcdef12);
        if kind == BootstrapFixture::Mutation {
            call(
                &mut code,
                wide,
                base,
                7,
                &[Value(base + 0x2b40), Value(base + 0x2b80)],
            );
            expect(&mut code, 1);
            call(&mut code, wide, base, 9, &[Value(base + 0x2b00)]);
            expect(&mut code, 1);
        }
        call(&mut code, wide, base, 8, &[Value(128), Value(output)]);
        field(
            &mut code,
            wide,
            parameters,
            if wide { 0x40 } else { 0x28 },
            true,
        );
        second_pointer(&mut code, wide, output, false);
        compare_text(&mut code, wide, false);
        call(&mut code, wide, base, 5, &[]);
        store(&mut code, wide, snapshot);
        field(
            &mut code,
            wide,
            parameters,
            if wide { 0x80 } else { 0x48 },
            true,
        );
        second_pointer(&mut code, wide, snapshot, true);
        compare_text(&mut code, wide, true);
        call(&mut code, wide, base, 6, &[Memory(snapshot)]);
        expect(&mut code, 1);
        code.extend([0xb8, 1, 0, 0, 0]);
        if wide {
            code.extend([0x48, 0x83, 0xc4, 0x48, 0xc3]);
        } else if dll {
            code.extend([0xc2, 12, 0]);
        } else {
            code.push(0xc3);
        }
    }
    assert!(code.len() < 0x1000);
    bytes[0x200..0x1200].fill(0);
    bytes[0x200..0x200 + code.len()].copy_from_slice(&code);
    bytes
}
