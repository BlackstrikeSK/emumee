//! Owned programs for real scheduler delay and wait-all/any continuations.
use super::winhttp::{
    Arg::{Memory as M, Value as V},
    call,
};
use super::{ApiFixture, api_probe, put32, put64};
use crate::{kernel_layout::KernelLayout, pe::Architecture};
#[derive(Clone, Copy, Debug)]
pub enum WaitFixture {
    DelayRelative,
    DelayAbsolute,
    DelayZero,
    DelayChild,
    DelayMode,
    DelayAlertable,
    DelayIrql,
    DelayUnreadable,
    Any,
    All,
    AllBlocked,
    Mixed,
    Timeout,
    Poll,
    Four,
    CountZero,
    Count65,
    Type,
    Duplicate,
    UserMode,
    Alertable,
    MissingBlocks,
    ReadonlyBlocks,
    BadArray,
    Unknown,
    Irql,
    Tamper,
}
impl WaitFixture {
    pub fn negative(self) -> bool {
        matches!(
            self,
            Self::DelayMode
                | Self::DelayAlertable
                | Self::DelayIrql
                | Self::DelayUnreadable
                | Self::CountZero
                | Self::Count65
                | Self::Type
                | Self::Duplicate
                | Self::UserMode
                | Self::Alertable
                | Self::MissingBlocks
                | Self::ReadonlyBlocks
                | Self::BadArray
                | Self::Unknown
                | Self::Irql
                | Self::Tamper
        )
    }
    pub fn child(self) -> bool {
        matches!(self, Self::DelayChild | Self::AllBlocked | Self::Mixed)
    }
    pub fn delay(self) -> bool {
        matches!(
            self,
            Self::DelayRelative
                | Self::DelayAbsolute
                | Self::DelayZero
                | Self::DelayChild
                | Self::DelayMode
                | Self::DelayAlertable
                | Self::DelayIrql
                | Self::DelayUnreadable
        )
    }
}
fn expect(code: &mut Vec<u8>, value: u32) {
    code.push(0x3d);
    code.extend(value.to_le_bytes());
    code.extend([0x74, 1, 0xcc]);
}
fn pointer(code: &mut Vec<u8>, wide: bool, address: u64) {
    if wide {
        code.push(0x48);
    }
    code.push(0xb8);
    if wide {
        code.extend(address.to_le_bytes());
    } else {
        code.extend((address as u32).to_le_bytes());
    }
}
fn load(code: &mut Vec<u8>, wide: bool, address: u64) {
    pointer(code, wide, address);
    code.extend([0x8b, 0]);
}
fn prologue(code: &mut Vec<u8>, wide: bool) {
    code.push(0x53);
    if wide {
        code.extend([0x48, 0x83, 0xec, 0x60]);
    }
}
fn returned(code: &mut Vec<u8>, wide: bool, child: bool) {
    if wide {
        code.extend([0x48, 0x83, 0xc4, 0x60]);
    }
    code.push(0x5b);
    if child && !wide {
        code.extend([0xc2, 4, 0]);
    } else {
        code.push(0xc3);
    }
}
fn child_call(
    code: &mut Vec<u8>,
    wide: bool,
    base: u64,
    index: usize,
    args: &[super::winhttp::Arg],
) {
    call(code, wide, base, index, args);
    if wide {
        let end = code.len();
        assert_eq!(&code[end - 6..end - 4], &[0xff, 0x15]);
        let displacement =
            i32::try_from(0x2080i64 + index as i64 * 8 - 0x1c00 - end as i64).unwrap();
        code[end - 4..].copy_from_slice(&displacement.to_le_bytes());
    }
}
pub fn kernel_waits_probe(architecture: Architecture, kind: WaitFixture) -> Vec<u8> {
    let wide = architecture == Architecture::X64;
    let width = architecture.width();
    let base = if wide { 0x140000000u64 } else { 0x400000 };
    let layout = KernelLayout::for_architecture(architecture);
    let original = api_probe(architecture, ApiFixture::PoolLifecycle);
    let mut data = vec![0u8; 0x3200];
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
        "KeInitializeEvent",
        "KeWaitForMultipleObjects",
        "KeDelayExecutionThread",
        "PsCreateSystemThread",
        "KeSetEvent",
        "PsTerminateSystemThread",
        "ZwClose",
        "KeRaiseIrql",
        "KeGetCurrentThread",
        "KeQuerySystemTime",
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
    let events = [base + 0x2c00, base + 0x2c40, base + 0x2c80, base + 0x2cc0];
    let signal0 = matches!(
        kind,
        WaitFixture::All
            | WaitFixture::AllBlocked
            | WaitFixture::Four
            | WaitFixture::Duplicate
            | WaitFixture::MissingBlocks
            | WaitFixture::ReadonlyBlocks
            | WaitFixture::Tamper
    );
    let signal1 = matches!(
        kind,
        WaitFixture::Any | WaitFixture::All | WaitFixture::Four
    );
    for (index, address) in events.iter().enumerate() {
        let raw = 0x2100 + index * width;
        if wide {
            put64(&mut data, raw, *address);
        } else {
            put32(&mut data, raw, *address as u32);
        }
    }
    if matches!(kind, WaitFixture::Duplicate) {
        if wide {
            put64(&mut data, 0x2100 + width, events[0]);
        } else {
            put32(&mut data, 0x2100 + width, events[0] as u32);
        }
    }
    if matches!(kind, WaitFixture::Unknown) {
        if wide {
            put64(&mut data, 0x2100, base + 0x2b00);
        } else {
            put32(&mut data, 0x2100, (base + 0x2b00) as u32);
        }
    }
    if matches!(kind, WaitFixture::Mixed) {
        if wide {
            put64(&mut data, 0x2100 + width, layout.thread_object(2).unwrap());
        } else {
            put32(
                &mut data,
                0x2100 + width,
                layout.thread_object(2).unwrap() as u32,
            );
        }
    }
    let interval = if matches!(kind, WaitFixture::DelayZero | WaitFixture::Poll) {
        0
    } else {
        -10000i64
    };
    data[0x2140..0x2148].copy_from_slice(&interval.to_le_bytes());
    data[0x1d00..0x1d04].copy_from_slice(b"COLD");
    let mut root = Vec::new();
    prologue(&mut root, wide);
    for (index, address) in events.iter().enumerate() {
        let signal = match index {
            0 => signal0,
            1 => signal1,
            _ => matches!(kind, WaitFixture::Four),
        };
        call(
            &mut root,
            wide,
            base,
            0,
            &[V(*address), V(1), V(u64::from(signal))],
        );
    }
    if kind.child() {
        call(
            &mut root,
            wide,
            base,
            3,
            &[
                V(base + 0x2f60),
                V(0x1fffff),
                V(0),
                V(0),
                V(0),
                V(base + 0x1c00),
                V(0),
            ],
        );
        expect(&mut root, 0);
    }
    if matches!(kind, WaitFixture::DelayAbsolute) {
        call(&mut root, wide, base, 9, &[V(base + 0x2f40)]);
        pointer(&mut root, wide, base + 0x2f40);
        root.extend([0x81, 0]);
        root.extend(10000u32.to_le_bytes());
        root.extend([0x83, 0x50, 4, 0]);
    }
    if matches!(kind, WaitFixture::DelayIrql | WaitFixture::Irql) {
        call(&mut root, wide, base, 7, &[V(2), V(base + 0x2f80)]);
    }
    if matches!(kind, WaitFixture::Tamper) {
        pointer(&mut root, wide, events[0] + 4);
        root.extend([0xc7, 0, 0, 0, 0, 0]);
    }
    if kind.delay() {
        call(
            &mut root,
            wide,
            base,
            2,
            &[
                V(u64::from(matches!(kind, WaitFixture::DelayMode))),
                V(u64::from(matches!(kind, WaitFixture::DelayAlertable))),
                V(if matches!(kind, WaitFixture::DelayUnreadable) {
                    base + 0x3ffc
                } else {
                    base + 0x2f40
                }),
            ],
        );
        if !kind.negative() {
            expect(&mut root, 0);
        }
    } else {
        let count = match kind {
            WaitFixture::CountZero => 0,
            WaitFixture::Count65 => 65,
            WaitFixture::Four | WaitFixture::MissingBlocks | WaitFixture::ReadonlyBlocks => 4,
            _ => 2,
        };
        let all = matches!(
            kind,
            WaitFixture::All | WaitFixture::AllBlocked | WaitFixture::Mixed | WaitFixture::Four
        );
        let timeout = if matches!(
            kind,
            WaitFixture::Timeout | WaitFixture::Poll | WaitFixture::Irql
        ) {
            base + 0x2f40
        } else {
            0
        };
        let blocks = match kind {
            WaitFixture::Four => base + 0x2e00,
            WaitFixture::ReadonlyBlocks => base + 0x1000,
            _ => 0,
        };
        call(
            &mut root,
            wide,
            base,
            1,
            &[
                V(count),
                V(if matches!(kind, WaitFixture::BadArray) {
                    base + 0x3ffc
                } else {
                    base + 0x2f00
                }),
                V(if matches!(kind, WaitFixture::Type) {
                    2
                } else {
                    u64::from(!all)
                }),
                V(0),
                V(u64::from(matches!(kind, WaitFixture::UserMode))),
                V(u64::from(matches!(kind, WaitFixture::Alertable))),
                V(timeout),
                V(blocks),
            ],
        );
        if !kind.negative() {
            expect(
                &mut root,
                match kind {
                    WaitFixture::Any => 1,
                    WaitFixture::Timeout | WaitFixture::Poll => 0x102,
                    _ => 0,
                },
            );
        }
    }
    if kind.negative() {
        root.push(0xcc);
    } else {
        if matches!(kind, WaitFixture::DelayChild) {
            load(&mut root, wide, base + 0x2b00);
            expect(&mut root, u32::from_le_bytes(*b"DONE"));
        }
        if matches!(
            kind,
            WaitFixture::Any
                | WaitFixture::All
                | WaitFixture::AllBlocked
                | WaitFixture::Four
                | WaitFixture::Mixed
        ) {
            for address in events.iter().take(if matches!(kind, WaitFixture::Four) {
                4
            } else {
                2
            }) {
                load(&mut root, wide, *address + 4);
                expect(&mut root, 0);
            }
        }
        if kind.child() {
            call(&mut root, wide, base, 6, &[M(base + 0x2f60)]);
            expect(&mut root, 0);
        }
    }
    pointer(&mut root, wide, base + 0x2b00);
    root.extend([0xc7, 0]);
    root.extend(*b"DONE");
    root.extend([0xb8, 1, 0, 0, 0]);
    returned(&mut root, wide, false);
    assert!(root.len() <= 0xc00);
    data[0x200..0x200 + root.len()].copy_from_slice(&root);
    let mut child = Vec::new();
    prologue(&mut child, wide);
    if matches!(kind, WaitFixture::DelayChild) {
        pointer(&mut child, wide, base + 0x2b00);
        child.extend([0xc7, 0]);
        child.extend(*b"DONE");
    } else {
        child_call(
            &mut child,
            wide,
            base,
            4,
            &[
                V(if matches!(kind, WaitFixture::AllBlocked) {
                    events[1]
                } else {
                    events[0]
                }),
                V(0),
                V(0),
            ],
        );
    }
    child_call(&mut child, wide, base, 5, &[V(0x76543210)]);
    child.extend([0x0f, 0x0b]);
    assert!(child.len() <= 0x400);
    data[0xe00..0xe00 + child.len()].copy_from_slice(&child);
    data
}
