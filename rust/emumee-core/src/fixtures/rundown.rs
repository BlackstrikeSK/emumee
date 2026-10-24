//! Owned driver callers exercise real ABI and opaque rundown lifetime guards.
use super::winhttp::{
    Arg::{Memory as M, Value as V},
    call, store,
};
use super::{ApiFixture, api_probe, put32, put64};
use crate::pe::Architecture;
#[derive(Clone, Copy, Debug)]
pub enum RundownFixture {
    Lifecycle,
    Free,
    Zero,
    BlockedWait,
    BlockedFree,
    Underflow,
    InvalidPointer,
    DoubleFree,
    PoolFree,
    BodyRead,
    BodyWrite,
    BodyCall,
    ApiRead,
    ApiWrite,
    IrqlAllocate,
    IrqlAccess,
    IrqlTeardown,
    UnsupportedPool,
    Reenable,
}
impl RundownFixture {
    pub fn negative(self) -> bool {
        !matches!(self, Self::Lifecycle | Self::Free | Self::Zero)
    }
}
fn fast(code: &mut Vec<u8>, wide: bool, base: u64, index: usize, args: &[super::winhttp::Arg]) {
    if wide {
        call(code, wide, base, index, args);
        return;
    }
    assert!(args.len() <= 2);
    for (position, arg) in args.iter().enumerate() {
        match arg {
            V(value) => {
                code.push(if position == 0 { 0xb9 } else { 0xba });
                code.extend((*value as u32).to_le_bytes());
            }
            M(address) => {
                code.extend(if position == 0 {
                    [0x8b, 0x0d]
                } else {
                    [0x8b, 0x15]
                });
                code.extend((*address as u32).to_le_bytes());
            }
        }
    }
    code.extend([0xff, 0x15]);
    code.extend(((base + 0x2080) as u32 + index as u32 * 4).to_le_bytes());
}
fn expect(code: &mut Vec<u8>, value: u32) {
    code.push(0x3d);
    code.extend(value.to_le_bytes());
    code.extend([0x74, 1, 0xcc]);
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
pub fn rundown_probe(architecture: Architecture, kind: RundownFixture) -> Vec<u8> {
    let wide = architecture == Architecture::X64;
    let width = architecture.width();
    let base = if wide { 0x140000000u64 } else { 0x400000 };
    let expected = if wide {
        0xffffb00000000000u64
    } else {
        0xe0000000
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
    let names = [
        "ExAllocateCacheAwareRundownProtection",
        "ExAcquireRundownProtectionCacheAwareEx",
        "ExReleaseRundownProtectionCacheAwareEx",
        "ExWaitForRundownProtectionReleaseCacheAware",
        "ExFreeCacheAwareRundownProtection",
        "ExAcquireRundownProtectionCacheAware",
        "ExReleaseRundownProtectionCacheAware",
        "ExFreePoolWithTag",
        "RtlMoveMemory",
        "KeRaiseIrql",
        "ExReInitializeRundownProtectionCacheAware",
    ];
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
    let slot = base + 0x2c00;
    let mut code = Vec::new();
    if wide {
        code.extend([0x48, 0x83, 0xec, 0x68]);
    }
    if matches!(kind, RundownFixture::InvalidPointer) {
        fast(&mut code, wide, base, 5, &[V(0xdeadbeef)]);
    } else {
        if matches!(kind, RundownFixture::IrqlAllocate) {
            call(&mut code, wide, base, 9, &[V(2), V(base + 0x2d00)]);
        }
        call(
            &mut code,
            wide,
            base,
            0,
            &[
                V(if matches!(kind, RundownFixture::UnsupportedPool) {
                    1
                } else {
                    0x600
                }),
                V(1),
            ],
        );
        store(&mut code, wide, slot);
        if wide {
            code.extend([0x48, 0xba]);
            code.extend(expected.to_le_bytes());
            code.extend([0x48, 0x39, 0xd0, 0x74, 1, 0xcc]);
        } else {
            expect(&mut code, expected as u32);
        }
        match kind {
            RundownFixture::Lifecycle | RundownFixture::Free => {
                fast(&mut code, wide, base, 1, &[M(slot), V(3)]);
                expect(&mut code, 1);
                fast(&mut code, wide, base, 2, &[M(slot), V(3)]);
                fast(&mut code, wide, base, 3, &[M(slot)]);
                fast(&mut code, wide, base, 5, &[M(slot)]);
                expect(&mut code, 0);
                if matches!(kind, RundownFixture::Free) {
                    call(&mut code, wide, base, 4, &[M(slot)]);
                }
            }
            RundownFixture::Zero => {
                fast(&mut code, wide, base, 1, &[M(slot), V(0)]);
                expect(&mut code, 1);
                fast(&mut code, wide, base, 2, &[M(slot), V(0)]);
                fast(&mut code, wide, base, 5, &[M(slot)]);
                expect(&mut code, 1);
                fast(&mut code, wide, base, 6, &[M(slot)]);
                call(&mut code, wide, base, 4, &[M(slot)]);
            }
            RundownFixture::BlockedWait | RundownFixture::BlockedFree => {
                fast(&mut code, wide, base, 1, &[M(slot), V(3)]);
                expect(&mut code, 1);
                if matches!(kind, RundownFixture::BlockedWait) {
                    fast(&mut code, wide, base, 3, &[M(slot)]);
                } else {
                    call(&mut code, wide, base, 4, &[M(slot)]);
                }
            }
            RundownFixture::Underflow => {
                fast(&mut code, wide, base, 5, &[M(slot)]);
                expect(&mut code, 1);
                fast(&mut code, wide, base, 2, &[M(slot), V(2)]);
            }
            RundownFixture::DoubleFree => {
                call(&mut code, wide, base, 4, &[M(slot)]);
                call(&mut code, wide, base, 4, &[M(slot)]);
            }
            RundownFixture::PoolFree => call(&mut code, wide, base, 7, &[M(slot), V(1)]),
            RundownFixture::BodyRead | RundownFixture::BodyWrite | RundownFixture::BodyCall => {
                load(&mut code, wide, slot);
                match kind {
                    RundownFixture::BodyRead => {
                        if wide {
                            code.push(0x48);
                        }
                        code.extend([0x8b, 0]);
                    }
                    RundownFixture::BodyWrite => {
                        code.extend([0xc7, 0]);
                        code.extend(*b"FAIL");
                    }
                    RundownFixture::BodyCall => code.extend([0xff, 0xd0]),
                    _ => unreachable!(),
                }
            }
            RundownFixture::ApiRead => {
                call(&mut code, wide, base, 8, &[V(base + 0x2d00), M(slot), V(4)])
            }
            RundownFixture::ApiWrite => {
                call(&mut code, wide, base, 8, &[M(slot), V(base + 0x2b00), V(4)])
            }
            RundownFixture::IrqlAccess => {
                call(&mut code, wide, base, 9, &[V(3), V(base + 0x2d00)]);
                fast(&mut code, wide, base, 5, &[M(slot)]);
            }
            RundownFixture::IrqlTeardown => {
                call(&mut code, wide, base, 9, &[V(2), V(base + 0x2d00)]);
                fast(&mut code, wide, base, 3, &[M(slot)]);
            }
            RundownFixture::Reenable => {
                fast(&mut code, wide, base, 3, &[M(slot)]);
                // The baseline does not implement this export: it must stop,
                // without clearing running_down or pretending to reenable.
                fast(&mut code, wide, base, 10, &[M(slot)]);
            }
            RundownFixture::IrqlAllocate | RundownFixture::UnsupportedPool => {}
            RundownFixture::InvalidPointer => unreachable!(),
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
