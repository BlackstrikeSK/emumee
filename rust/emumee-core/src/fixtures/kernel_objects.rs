//! Owned native callers prove borrowed identities and transient ref ownership.
use super::winhttp::{
    Arg::{Memory as M, Value as V},
    call, store,
};
use super::{ApiFixture, api_probe, put16, put32, put64};
use crate::{kernel_layout::KernelLayout, kernel_objects::Kind, pe::Architecture};
#[derive(Clone, Copy, Debug)]
pub enum ObjectFixture {
    Lifecycle,
    DataOnly,
    KernelMismatch,
    UserMismatch,
    UserAccess,
    Mode,
    Underflow,
    Foreign,
    Irql,
    GlobalWrite,
    GlobalCall,
    IdentityRead,
    IdentityCall,
    TypeRead,
    TypeCall,
    ApiIdentityRead,
    ApiIdentityWrite,
    ByHandle,
}
impl ObjectFixture {
    pub fn negative(self) -> bool {
        !matches!(
            self,
            Self::Lifecycle | Self::DataOnly | Self::KernelMismatch | Self::UserMismatch
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
fn deref(code: &mut Vec<u8>, wide: bool) {
    if wide {
        code.push(0x48);
    }
    code.extend([0x8b, 0]);
}
fn expect(code: &mut Vec<u8>, value: u32) {
    code.push(0x3d);
    code.extend(value.to_le_bytes());
    code.extend([0x74, 1, 0xcc]);
}
fn expect_pointer(code: &mut Vec<u8>, wide: bool, value: u64) {
    if wide {
        code.extend([0x48, 0xba]);
        code.extend(value.to_le_bytes());
        code.extend([0x48, 0x39, 0xd0, 0x74, 1, 0xcc]);
    } else {
        expect(code, value as u32);
    }
}
fn fast(code: &mut Vec<u8>, wide: bool, base: u64, index: usize, slot: u64) {
    if wide {
        call(code, wide, base, index, &[M(slot)]);
    } else {
        code.extend([0x8b, 0x0d]);
        code.extend((slot as u32).to_le_bytes());
        code.extend([0xff, 0x15]);
        code.extend(((base + 0x2080) as u32 + index as u32 * 4).to_le_bytes());
    }
}
pub fn kernel_objects_probe(architecture: Architecture, kind: ObjectFixture) -> Vec<u8> {
    let wide = architecture == Architecture::X64;
    let width = architecture.width();
    let base = if wide { 0x140000000u64 } else { 0x400000 };
    let layout = KernelLayout::for_architecture(architecture);
    let system = layout.driver_object + 0x3000;
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
        "PsInitialSystemProcess",
        "PsProcessType",
        "IoDriverObjectType",
        "IoGetCurrentProcess",
        "PsGetCurrentProcessId",
        "ObReferenceObjectByPointer",
        "ObfReferenceObject",
        "ObfDereferenceObject",
        "MmGetSystemRoutineAddress",
        "RtlMoveMemory",
        "KeRaiseIrql",
        "ObReferenceObjectByHandle",
        "PsThreadType",
        "IoFileObjectType",
        "MmSectionObjectType",
        "ExEventObjectType",
        "ExSemaphoreObjectType",
        "SeTokenObjectType",
        "TmEnlistmentObjectType",
        "TmResourceManagerObjectType",
        "TmTransactionManagerObjectType",
        "TmTransactionObjectType",
    ][..];
    let types: Vec<_> = std::iter::once("PsInitialSystemProcess")
        .chain(Kind::ALL.into_iter().map(Kind::export))
        .collect();
    let names = if matches!(kind, ObjectFixture::DataOnly) {
        types.as_slice()
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
    data[0x1e00..0x1e80].fill(0xcc);
    let text: Vec<_> = "PsInitialSystemProcess"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    put16(&mut data, 0x1f00, text.len() as u16);
    put16(&mut data, 0x1f02, text.len() as u16);
    if wide {
        put64(&mut data, 0x1f08, base + 0x2d80);
    } else {
        put32(&mut data, 0x1f04, (base + 0x2d80) as u32);
    }
    data[0x1f80..0x1f80 + text.len()].copy_from_slice(&text);
    let mut code = Vec::new();
    if wide {
        code.extend([0x48, 0x83, 0xec, 0x68, 0x48, 0x89, 0xc8]);
    } else {
        code.extend([0x8b, 0x44, 0x24, 4]);
    }
    store(&mut code, wide, base + 0x2c80);
    if matches!(kind, ObjectFixture::DataOnly) {
        for index in 0..13 {
            load(&mut code, wide, base + 0x2080 + index as u64 * width as u64);
            deref(&mut code, wide);
            expect_pointer(
                &mut code,
                wide,
                if index == 0 {
                    system
                } else {
                    layout.driver_object + 0x10000 + (index as u64 - 1) * 4096
                },
            );
        }
    } else {
        for (index, slot) in [(0, 0x2c00), (1, 0x2c08), (2, 0x2c10)] {
            load(&mut code, wide, base + 0x2080 + index * width as u64);
            deref(&mut code, wide);
            store(&mut code, wide, base + slot);
        }
        match kind {
            ObjectFixture::Lifecycle => {
                call(&mut code, wide, base, 3, &[]);
                expect_pointer(&mut code, wide, system);
                call(&mut code, wide, base, 4, &[]);
                expect(&mut code, 4);
                call(&mut code, wide, base, 8, &[V(base + 0x2d00)]);
                let iat = base + 0x2080;
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
                call(
                    &mut code,
                    wide,
                    base,
                    5,
                    &[M(base + 0x2c00), V(0), M(base + 0x2c08), V(0)],
                );
                expect(&mut code, 0);
                fast(&mut code, wide, base, 6, base + 0x2c00);
                fast(&mut code, wide, base, 7, base + 0x2c00);
                fast(&mut code, wide, base, 7, base + 0x2c00);
                load(&mut code, wide, base + 0x2c80);
                expect_pointer(&mut code, wide, layout.driver_object);
                fast(&mut code, wide, base, 6, base + 0x2c80);
                fast(&mut code, wide, base, 7, base + 0x2c80);
            }
            ObjectFixture::KernelMismatch
            | ObjectFixture::UserMismatch
            | ObjectFixture::UserAccess
            | ObjectFixture::Mode
            | ObjectFixture::Foreign
            | ObjectFixture::Irql => {
                if matches!(kind, ObjectFixture::Irql) {
                    call(&mut code, wide, base, 10, &[V(3), V(base + 0x2d40)]);
                }
                let object = if matches!(kind, ObjectFixture::Foreign) {
                    V(0xdeadbeef)
                } else {
                    M(base + 0x2c00)
                };
                let selected = if matches!(
                    kind,
                    ObjectFixture::KernelMismatch | ObjectFixture::UserMismatch
                ) {
                    base + 0x2c10
                } else {
                    base + 0x2c08
                };
                let mode = if matches!(
                    kind,
                    ObjectFixture::UserMismatch | ObjectFixture::UserAccess
                ) {
                    1
                } else if matches!(kind, ObjectFixture::Mode) {
                    2
                } else {
                    0
                };
                call(
                    &mut code,
                    wide,
                    base,
                    5,
                    &[object, V(0), M(selected), V(mode)],
                );
                if matches!(kind, ObjectFixture::KernelMismatch) {
                    expect(&mut code, 0);
                    fast(&mut code, wide, base, 7, base + 0x2c00);
                }
                if matches!(kind, ObjectFixture::UserMismatch) {
                    expect(&mut code, 0xc0000024);
                }
            }
            ObjectFixture::Underflow => fast(&mut code, wide, base, 7, base + 0x2c00),
            ObjectFixture::GlobalWrite | ObjectFixture::GlobalCall => {
                load(&mut code, wide, base + 0x2080);
                if matches!(kind, ObjectFixture::GlobalWrite) {
                    code.extend([0xc7, 0]);
                    code.extend(*b"FAIL");
                } else {
                    code.extend([0xff, 0xd0]);
                }
            }
            ObjectFixture::IdentityRead
            | ObjectFixture::IdentityCall
            | ObjectFixture::TypeRead
            | ObjectFixture::TypeCall => {
                load(
                    &mut code,
                    wide,
                    base + if matches!(kind, ObjectFixture::TypeRead | ObjectFixture::TypeCall) {
                        0x2c08
                    } else {
                        0x2c00
                    },
                );
                if matches!(kind, ObjectFixture::IdentityRead | ObjectFixture::TypeRead) {
                    deref(&mut code, wide);
                } else {
                    code.extend([0xff, 0xd0]);
                }
            }
            ObjectFixture::ApiIdentityRead => call(
                &mut code,
                wide,
                base,
                9,
                &[V(base + 0x2c40), M(base + 0x2c00), V(4)],
            ),
            ObjectFixture::ApiIdentityWrite => call(
                &mut code,
                wide,
                base,
                9,
                &[M(base + 0x2c00), V(base + 0x2b00), V(4)],
            ),
            ObjectFixture::ByHandle => call(
                &mut code,
                wide,
                base,
                11,
                &[
                    V(0xdeadbeef),
                    V(0),
                    M(base + 0x2c08),
                    V(0),
                    V(base + 0x2c40),
                    V(0),
                ],
            ),
            ObjectFixture::DataOnly => unreachable!(),
        }
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
