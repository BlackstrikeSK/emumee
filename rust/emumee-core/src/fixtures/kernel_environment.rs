//! Owned native driver callers, including data-only IAT and dynamic data lookup.
use super::winhttp::{
    Arg::{Memory as M, Value as V},
    call,
};
use super::{ApiFixture, api_probe, put16, put32, put64};
use crate::pe::Architecture;
#[derive(Clone, Copy, Debug)]
pub enum EnvironmentFixture {
    Identity,
    NullOutput,
    BadOutput,
    ReadonlyOutput,
    CrossPageOutput,
    Limits,
    DataOnly,
    GlobalWrite,
    GlobalCall,
    ApiGlobalWrite,
}
impl EnvironmentFixture {
    pub fn negative(self) -> bool {
        !matches!(
            self,
            Self::Identity | Self::NullOutput | Self::Limits | Self::DataOnly
        )
    }
}
fn load(code: &mut Vec<u8>, wide: bool, address: u64) {
    if wide {
        code.push(0x48);
    }
    code.push(0xa1);
    if wide {
        code.extend(address.to_le_bytes());
    } else {
        code.extend((address as u32).to_le_bytes());
    }
}
fn expect(code: &mut Vec<u8>, value: u32) {
    code.push(0x3d);
    code.extend(value.to_le_bytes());
    code.extend([0x74, 1, 0xcc]);
}
fn expect_ptr(code: &mut Vec<u8>, wide: bool, value: u64) {
    if wide {
        code.extend([0x48, 0xba]);
        code.extend(value.to_le_bytes());
        code.extend([0x48, 0x39, 0xd0, 0x74, 1, 0xcc]);
    } else {
        expect(code, value as u32);
    }
}
fn global(code: &mut Vec<u8>, wide: bool, base: u64, index: usize, byte: bool, value: u64) {
    load(
        code,
        wide,
        base + 0x2080 + index as u64 * if wide { 8 } else { 4 },
    );
    if byte {
        code.extend([0x0f, 0xb6, 0]);
        expect(code, value as u32);
    } else {
        if wide {
            code.push(0x48);
        }
        code.extend([0x8b, 0]);
        expect_ptr(code, wide, value);
    }
}
pub fn kernel_environment_probe(architecture: Architecture, kind: EnvironmentFixture) -> Vec<u8> {
    let wide = architecture == Architecture::X64;
    let width = architecture.width();
    let base = if wide { 0x140000000u64 } else { 0x400000 };
    let highest = if wide {
        0x7fff_fffe_ffffu64
    } else {
        0x7ffe_ffff
    };
    let original = api_probe(architecture, ApiFixture::PoolLifecycle);
    let mut data = vec![0; 0x3200];
    data[..0x200].copy_from_slice(&original[..0x200]);
    let table = 0x98 + if wide { 0xf0 } else { 0xe0 };
    let dd = 0x98 + if wide { 112 } else { 96 };
    for (at, value) in [
        (0x98 + 4, 0x1000),
        (0x98 + 8, 0x2000),
        (0x98 + 56, 0x4000),
        (table + 8, 0x1000),
        (table + 16, 0x1000),
        (table + 40 + 8, 0x2000),
        (table + 40 + 16, 0x2000),
        (table + 40 + 20, 0x1200),
        (dd + 8, 0x2000),
        (dd + 12, 40),
        (0x1200, 0x2180),
        (0x120c, 0x2040),
        (0x1210, 0x2080),
    ] {
        put32(&mut data, at, value);
    }
    data[0x1240..0x124d].copy_from_slice(b"ntoskrnl.exe\0");
    let all = &[
        "KeQueryActiveProcessorCountEx",
        "KeGetCurrentProcessorNumberEx",
        "KeGetCurrentProcessorNumber",
        "KeNumberProcessors",
        "MmHighestUserAddress",
        "MmUserProbeAddress",
        "MmGetSystemRoutineAddress",
        "RtlMoveMemory",
        "KdDebuggerEnabled",
        "KdDebuggerNotPresent",
    ][..];
    let names = if matches!(kind, EnvironmentFixture::DataOnly) {
        &all[3..6]
    } else {
        all
    };
    for (index, name) in names.iter().enumerate() {
        let rva = 0x2300 + index as u32 * 64;
        for raw in [0x1280, 0x1380] {
            if wide {
                put64(&mut data, raw + index * width, rva.into());
            } else {
                put32(&mut data, raw + index * width, rva);
            }
        }
        let raw = 0x1500 + index * 64;
        data[raw + 2..raw + 2 + name.len()].copy_from_slice(name.as_bytes());
    }
    data[0x1d00..0x1d04].copy_from_slice(b"API!");
    data[0x1e00..0x1e0c].fill(0xcc);
    data[0x31fc..].fill(0xcc);
    for (at, buffer, name) in [
        (0x1f00, 0x2d80, "MmHighestUserAddress"),
        (0x1f20, 0x2e00, "MmUserProbeAddress"),
    ] {
        let bytes: Vec<_> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
        put16(&mut data, at, bytes.len() as u16);
        put16(&mut data, at + 2, bytes.len() as u16);
        if wide {
            put64(&mut data, at + 8, base + buffer);
        } else {
            put32(&mut data, at + 4, (base + buffer) as u32);
        }
        let raw = buffer as usize - 0xe00;
        data[raw..raw + bytes.len()].copy_from_slice(&bytes);
    }
    let mut code = Vec::new();
    if wide {
        code.extend([0x48, 0x83, 0xec, 0x68]);
    }
    match kind {
        EnvironmentFixture::Identity => {
            for (group, value) in [
                (0, 12),
                (1, 0),
                (65535, 12),
                (65534, 0),
                (0x10000, 12),
                (u32::MAX as u64, 12),
            ] {
                call(&mut code, wide, base, 0, &[V(group)]);
                expect(&mut code, value);
            }
            call(&mut code, wide, base, 1, &[V(base + 0x2c04)]);
            expect(&mut code, 0);
            for (at, value) in [(0x2c00, 0xcccccccc), (0x2c04, 0), (0x2c08, 0xcccccccc)] {
                // DWORD loads deliberately do not read past the four-byte ABI output.
                code.push(0xa1);
                if wide {
                    code.extend((base + at).to_le_bytes());
                } else {
                    code.extend(((base + at) as u32).to_le_bytes());
                }
                expect(&mut code, value);
            }
            call(&mut code, wide, base, 2, &[]);
            expect(&mut code, 0);
            global(&mut code, wide, base, 3, true, 12);
            // CPUID and kernel topology must describe the same configured CPU.
            code.extend([
                0x53, 0xb8, 1, 0, 0, 0, 0x0f, 0xa2, 0x89, 0xd8, 0xc1, 0xe8, 16, 0x25, 255, 0, 0, 0,
                0x5b,
            ]);
            expect(&mut code, 12);
            global(&mut code, wide, base, 8, true, 0);
            global(&mut code, wide, base, 9, true, 1);
        }
        EnvironmentFixture::NullOutput => {
            call(&mut code, wide, base, 1, &[V(0)]);
            expect(&mut code, 0);
        }
        EnvironmentFixture::BadOutput
        | EnvironmentFixture::ReadonlyOutput
        | EnvironmentFixture::CrossPageOutput => {
            let output = match kind {
                EnvironmentFixture::BadOutput => 0xdeadbeef,
                EnvironmentFixture::ReadonlyOutput => base + 0x1000,
                _ => base + 0x3ffe,
            };
            call(&mut code, wide, base, 1, &[V(output)]);
        }
        EnvironmentFixture::Limits | EnvironmentFixture::DataOnly => {
            let offset = if matches!(kind, EnvironmentFixture::DataOnly) {
                0
            } else {
                3
            };
            global(&mut code, wide, base, offset, true, 12);
            global(&mut code, wide, base, offset + 1, false, highest);
            global(&mut code, wide, base, offset + 2, false, highest + 1);
            if matches!(kind, EnvironmentFixture::Limits) {
                for (header, index) in [(0x2d00, 4), (0x2d20, 5)] {
                    call(&mut code, wide, base, 6, &[V(base + header)]);
                    let iat = base + 0x2080 + index * width as u64;
                    if wide {
                        code.extend([0x48, 0xba]);
                        code.extend(iat.to_le_bytes());
                        code.extend([0x48, 0x8b, 0x12, 0x48, 0x39, 0xd0]);
                    } else {
                        code.extend([0x8b, 0x15]);
                        code.extend((iat as u32).to_le_bytes());
                        code.extend([0x39, 0xd0]);
                    }
                    code.extend([0x74, 1, 0xcc]);
                }
            }
        }
        EnvironmentFixture::GlobalWrite | EnvironmentFixture::GlobalCall => {
            load(&mut code, wide, base + 0x2080 + 4 * width as u64);
            if matches!(kind, EnvironmentFixture::GlobalWrite) {
                code.extend([0xc7, 0]);
                code.extend(*b"FAIL");
            } else {
                code.extend([0xff, 0xd0]);
            }
        }
        EnvironmentFixture::ApiGlobalWrite => call(
            &mut code,
            wide,
            base,
            7,
            &[M(base + 0x2080 + 4 * width as u64), V(base + 0x2b00), V(4)],
        ),
    }
    if kind.negative() {
        code.push(0xcc);
    }
    code.extend([0xb8, 1, 0, 0, 0]);
    if wide {
        code.extend([0x48, 0x83, 0xc4, 0x68]);
    }
    code.push(0xc3);
    assert!(code.len() <= 0x1000);
    data[0x200..0x200 + code.len()].copy_from_slice(&code);
    data
}
