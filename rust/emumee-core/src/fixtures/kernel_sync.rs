//! Owned pointer-word and actual IRQL programs. No real driver bytes.
use super::winhttp::{Arg::Value as V, call, expect_dword, write_dword};
use super::{ApiFixture, api_probe, put32, put64};
use crate::pe::Architecture;
#[derive(Clone, Copy, Debug)]
pub enum SyncFixture {
    Rundown,
    Push,
    PushFlagWidth,
    Irql,
    NativeIrql,
    RundownBlocked,
    RundownRelease,
    RundownOverflow,
    PushBlocked,
    PushRelease,
    PushTamper,
    PushFlags,
    PushApcs,
    Unaligned,
    ReadOnly,
    InvalidRange,
    HighIrql,
    InvalidRaise,
    InvalidLower,
    LowerAlias,
}
impl SyncFixture {
    pub fn error(self) -> Option<&'static str> {
        Some(match self {
            Self::Rundown
            | Self::Push
            | Self::PushFlagWidth
            | Self::Irql
            | Self::NativeIrql
            | Self::LowerAlias => {
                return None;
            }
            Self::RundownBlocked => "Blocked rundown wait requires kernel thread scheduling",
            Self::RundownRelease => "Rundown release without a reference",
            Self::RundownOverflow => "Rundown reference count overflow",
            Self::PushBlocked => "Blocked push-lock acquisition requires kernel thread scheduling",
            Self::PushRelease | Self::PushTamper => {
                "Exclusive push-lock release without exclusive ownership"
            }
            Self::PushFlags => "Unsupported push-lock flags",
            Self::PushApcs => "Push-lock operation requires disabled normal kernel APCs",
            Self::Unaligned => "Synchronization word is not pointer aligned",
            Self::ReadOnly | Self::InvalidRange => "range",
            Self::HighIrql => "Synchronization operation above supported IRQL",
            Self::InvalidRaise => "Invalid IRQL raise",
            Self::InvalidLower => "Invalid IRQL lower",
        })
    }
}
const NAMES: [&str; 17] = [
    "ExInitializeRundownProtection",
    "ExAcquireRundownProtection",
    "ExReleaseRundownProtection",
    "ExWaitForRundownProtectionRelease",
    "ExInitializePushLock",
    "ExAcquirePushLockExclusiveEx",
    "ExReleasePushLockExclusiveEx",
    "KfRaiseIrql",
    "KfLowerIrql",
    "KeAreAllApcsDisabled",
    "KeAreApcsDisabled",
    "ExGetPreviousMode",
    "KeEnterCriticalRegion",
    "KeLeaveCriticalRegion",
    "KeGetCurrentIrql",
    "KeLowerIrql",
    "KeRaiseIrql",
];
fn invoke(code: &mut Vec<u8>, wide: bool, base: u64, index: usize, args: &[u64]) {
    let fast = matches!(index,0..=3|5..=8|15);
    if !wide && fast {
        // Every call checks ESP against the real preserved root ESI afterwards.
        for (at, arg) in args.iter().enumerate() {
            code.push(if at == 0 { 0xb9 } else { 0xba });
            code.extend((*arg as u32).to_le_bytes());
        }
        code.extend([0xff, 0x15]);
        code.extend(((base + 0x2080) as u32 + index as u32 * 4).to_le_bytes());
    } else {
        call(
            code,
            wide,
            base,
            index,
            &args.iter().copied().map(V).collect::<Vec<_>>(),
        );
    }
    if !wide {
        code.extend([0x39, 0xf4, 0x74, 1, 0xcc]);
    }
}
fn expect(code: &mut Vec<u8>, value: u32) {
    code.push(0x3d);
    code.extend(value.to_le_bytes());
    code.extend([0x74, 1, 0xcc]);
}
fn word(code: &mut Vec<u8>, wide: bool, address: u64, value: u64) {
    write_dword(code, wide, address, value as u32);
    if wide {
        write_dword(code, wide, address + 4, (value >> 32) as u32);
    }
}
fn check(code: &mut Vec<u8>, wide: bool, address: u64, value: u64) {
    expect_dword(code, wide, address, value as u32);
    if wide {
        expect_dword(code, wide, address + 4, (value >> 32) as u32);
    }
}
pub fn kernel_sync_probe(architecture: Architecture, kind: SyncFixture) -> Vec<u8> {
    let wide = architecture == Architecture::X64;
    let width = architecture.width();
    let base = if wide { 0x140000000u64 } else { 0x400000 };
    let source = api_probe(architecture, ApiFixture::PoolLifecycle);
    let mut data = vec![0; 0x3200];
    data[..0x200].copy_from_slice(&source[..0x200]);
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
    for (index, name) in NAMES.iter().enumerate() {
        let rva = 0x2300 + index as u32 * 64;
        for raw in [0x1280, 0x1380] {
            if wide {
                put64(&mut data, raw + index * width, rva.into());
            } else {
                put32(&mut data, raw + index * width, rva);
            }
        }
        let at = 0x1500 + index * 64;
        data[at + 2..at + 2 + name.len()].copy_from_slice(name.as_bytes());
    }
    // Native subsystem and nonzero entry are inherited from the owned pool PE.
    let a = base + 0x3000;
    let mut c = if wide {
        vec![0x48, 0x83, 0xec, 0x68]
    } else {
        vec![0x56, 0x89, 0xe6]
    };
    word(&mut c, wide, a, 0x77777777);
    word(&mut c, wide, a + 8, 0x66554433);
    match kind {
        SyncFixture::Rundown => {
            invoke(&mut c, wide, base, 0, &[a]);
            check(&mut c, wide, a, 0);
            for expected in [2, 4] {
                invoke(&mut c, wide, base, 1, &[a]);
                expect(&mut c, 1);
                check(&mut c, wide, a, expected);
            }
            for expected in [2, 0] {
                invoke(&mut c, wide, base, 2, &[a]);
                check(&mut c, wide, a, expected);
            }
            invoke(&mut c, wide, base, 3, &[a]);
            check(&mut c, wide, a, 1);
            invoke(&mut c, wide, base, 3, &[a]);
            check(&mut c, wide, a, 1);
            invoke(&mut c, wide, base, 1, &[a]);
            expect(&mut c, 0);
            check(&mut c, wide, a, 1);
        }
        SyncFixture::Push
        | SyncFixture::PushFlagWidth
        | SyncFixture::PushBlocked
        | SyncFixture::PushRelease
        | SyncFixture::PushTamper
        | SyncFixture::PushFlags
        | SyncFixture::PushApcs => {
            invoke(&mut c, wide, base, 4, &[a]);
            check(&mut c, wide, a, 0);
            if !matches!(kind, SyncFixture::PushApcs) {
                invoke(&mut c, wide, base, 12, &[]);
            }
            if matches!(kind, SyncFixture::PushRelease) {
                invoke(&mut c, wide, base, 6, &[a, 0]);
            } else {
                invoke(
                    &mut c,
                    wide,
                    base,
                    5,
                    &[
                        a,
                        if matches!(kind, SyncFixture::PushFlagWidth) {
                            1u64 << 32
                        } else {
                            u64::from(matches!(kind, SyncFixture::PushFlags))
                        },
                    ],
                );
                check(&mut c, wide, a, 1);
            }
            if matches!(kind, SyncFixture::PushBlocked) {
                invoke(&mut c, wide, base, 5, &[a, 0]);
            }
            if matches!(kind, SyncFixture::PushTamper) {
                word(&mut c, wide, a, 2);
            }
            invoke(
                &mut c,
                wide,
                base,
                6,
                &[
                    a,
                    if matches!(kind, SyncFixture::PushFlagWidth) {
                        1u64 << 32
                    } else {
                        0
                    },
                ],
            );
            check(&mut c, wide, a, 0);
            invoke(&mut c, wide, base, 13, &[]);
        }
        SyncFixture::Irql | SyncFixture::LowerAlias => {
            invoke(&mut c, wide, base, 11, &[]);
            expect(&mut c, 0);
            for i in [9, 10, 14] {
                invoke(&mut c, wide, base, i, &[]);
                expect(&mut c, 0);
            }
            invoke(&mut c, wide, base, 12, &[]);
            invoke(&mut c, wide, base, 9, &[]);
            expect(&mut c, 0);
            invoke(&mut c, wide, base, 10, &[]);
            expect(&mut c, 1);
            invoke(&mut c, wide, base, 13, &[]);
            invoke(&mut c, wide, base, 7, &[2]);
            expect(&mut c, 0);
            for i in [9, 10] {
                invoke(&mut c, wide, base, i, &[]);
                expect(&mut c, 1);
            }
            invoke(&mut c, wide, base, 14, &[]);
            expect(&mut c, 2);
            invoke(
                &mut c,
                wide,
                base,
                if matches!(kind, SyncFixture::LowerAlias) {
                    15
                } else {
                    8
                },
                &[0],
            );
            invoke(&mut c, wide, base, 14, &[]);
            expect(&mut c, 0);
        }
        SyncFixture::NativeIrql => {
            if wide {
                c.extend([0xb8, 2, 0, 0, 0, 0x44, 0x0f, 0x22, 0xc0]);
            } else {
                c.extend([0x64, 0xc6, 5, 0x24, 0, 0, 0, 2]);
            }
            invoke(&mut c, wide, base, 14, &[]);
            expect(&mut c, 2);
            invoke(&mut c, wide, base, 9, &[]);
            expect(&mut c, 1);
            invoke(&mut c, wide, base, 8, &[0]);
        }
        SyncFixture::RundownBlocked => {
            invoke(&mut c, wide, base, 0, &[a]);
            invoke(&mut c, wide, base, 1, &[a]);
            invoke(&mut c, wide, base, 3, &[a]);
        }
        SyncFixture::RundownRelease => {
            invoke(&mut c, wide, base, 0, &[a]);
            invoke(&mut c, wide, base, 2, &[a]);
        }
        SyncFixture::RundownOverflow => {
            word(
                &mut c,
                wide,
                a,
                if wide {
                    u64::MAX - 1
                } else {
                    u32::MAX as u64 - 1
                },
            );
            invoke(&mut c, wide, base, 1, &[a]);
        }
        SyncFixture::Unaligned => invoke(&mut c, wide, base, 0, &[a + 1]),
        SyncFixture::ReadOnly => invoke(&mut c, wide, base, 0, &[base + 0x1000]),
        SyncFixture::InvalidRange => invoke(
            &mut c,
            wide,
            base,
            0,
            &[if wide { u64::MAX - 7 } else { 0xfffffffc }],
        ),
        SyncFixture::HighIrql => {
            invoke(&mut c, wide, base, 7, &[2]);
            invoke(&mut c, wide, base, 3, &[a]);
        }
        SyncFixture::InvalidRaise => invoke(&mut c, wide, base, 7, &[if wide { 16 } else { 32 }]),
        SyncFixture::InvalidLower => invoke(&mut c, wide, base, 8, &[1]),
    }
    if kind.error().is_some() {
        c.push(0xcc);
    } else {
        check(&mut c, wide, a + 8, 0x66554433);
        c.extend([0xb8, 1, 0, 0, 0]);
        if wide {
            c.extend([0x48, 0x83, 0xc4, 0x68]);
        } else {
            c.push(0x5e);
        }
        c.push(0xc3);
    }
    assert!(c.len() < 0x1000);
    data[0x200..0x200 + c.len()].copy_from_slice(&c);
    data
}
