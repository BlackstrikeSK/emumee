//! Owned processor rendezvous programs. Every perCPU row comes from actual guest
//! instructions and API outputs; root code verifies the rows before returning.
use super::winhttp::{
    Arg::{Memory as M, Value as V},
    call, store,
};
use super::{ApiFixture, api_probe, put32, put64};
use crate::{
    ipi::{STACK_SIZE, processor_layout},
    kernel_layout::KernelLayout,
    pe::Architecture,
};
#[derive(Clone, Copy, Debug)]
pub enum IpiFixture {
    Basic,
    One,
    Four,
    Twelve,
    GroupBoundary,
    Barrier,
    Repeat,
    Wide,
    Background,
    ChildCaller,
    MsrIsolation,
    Fault,
    Invalid,
    Nested,
    Terminate,
    Irql,
    Budget,
    HighIrql,
    Marker,
    ControlMutation,
    DescriptorMutation,
    UnownedMsr,
    LowerWait,
    LowerDelay,
    LowerMutex,
    LowerCreate,
    PcrIrql,
}
impl IpiFixture {
    pub fn logical(self) -> u32 {
        match self {
            Self::One => 1,
            Self::Four => 4,
            Self::GroupBoundary => 64,
            _ => 12,
        }
    }
    pub fn negative(self, architecture: Architecture) -> bool {
        matches!(
            self,
            Self::Fault
                | Self::Invalid
                | Self::Nested
                | Self::Terminate
                | Self::Irql
                | Self::Budget
                | Self::HighIrql
                | Self::Marker
                | Self::ControlMutation
                | Self::DescriptorMutation
                | Self::UnownedMsr
                | Self::LowerWait
                | Self::LowerDelay
                | Self::LowerMutex
                | Self::LowerCreate
                | Self::PcrIrql
        ) || matches!(self, Self::GroupBoundary) && architecture == Architecture::X86
    }
    pub fn repeated(self) -> bool {
        matches!(self, Self::Repeat | Self::MsrIsolation)
    }
    pub fn barrier(self) -> bool {
        matches!(self, Self::Barrier | Self::Budget | Self::MsrIsolation)
    }
    pub fn child(self) -> bool {
        matches!(self, Self::Background | Self::ChildCaller) || self.lowered_scheduler_probe()
    }
    pub fn lowered_scheduler_probe(self) -> bool {
        matches!(
            self,
            Self::LowerWait | Self::LowerDelay | Self::LowerMutex | Self::LowerCreate
        )
    }
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
fn expect_pointer(code: &mut Vec<u8>, wide: bool, value: u64) {
    if wide {
        code.extend([0x48, 0xba]);
        code.extend(value.to_le_bytes());
        code.extend([0x48, 0x39, 0xd0, 0x74, 1, 0xcc]);
    } else {
        expect(code, value as u32);
    }
}
fn at_call(
    code: &mut Vec<u8>,
    wide: bool,
    base: u64,
    index: usize,
    args: &[super::winhttp::Arg],
    origin: u32,
) {
    call(code, wide, base, index, args);
    if wide {
        let end = code.len();
        assert_eq!(&code[end - 6..end - 4], &[0xff, 0x15]);
        let displacement =
            i32::try_from(0x2080i64 + index as i64 * 8 - origin as i64 - end as i64).unwrap();
        code[end - 4..].copy_from_slice(&displacement.to_le_bytes());
    }
}
fn root_prologue(code: &mut Vec<u8>, wide: bool) {
    code.extend([0x53, 0x56]);
    if wide {
        code.extend([0x48, 0x83, 0xec, 0x68]);
    }
}
fn root_return(code: &mut Vec<u8>, wide: bool) {
    if wide {
        code.extend([0x48, 0x83, 0xc4, 0x68]);
    }
    code.extend([0x5e, 0x5b, 0xc3]);
}
fn check_sp(code: &mut Vec<u8>, wide: bool, base: u64, slot: u64) {
    if wide {
        let next = 0x1000 + code.len() + 7;
        code.extend([0x48, 0x3b, 0x25]);
        code.extend(
            ((slot - base) as i64 - next as i64)
                .try_into()
                .map(i32::to_le_bytes)
                .unwrap(),
        );
    } else {
        code.extend([0x3b, 0x25]);
        code.extend((slot as u32).to_le_bytes());
    }
    code.extend([0x74, 1, 0xcc]);
}
fn verify_rows(
    code: &mut Vec<u8>,
    wide: bool,
    table: u64,
    logical: u32,
    caller: u64,
    kind: IpiFixture,
    second: bool,
) {
    if wide {
        code.push(0x48);
    }
    code.push(0xbb);
    if wide {
        code.extend(table.to_le_bytes());
    } else {
        code.extend((table as u32).to_le_bytes());
    }
    code.push(0xb9);
    code.extend(logical.to_le_bytes());
    code.extend([0x31, 0xd2]);
    let start = code.len();
    for offset in [0, 8, 0x10, 0x14] {
        if offset == 0 {
            code.extend([0x39, 0x13]);
        } else {
            code.extend([0x39, 0x53, offset]);
        }
        code.extend([0x74, 1, 0xcc]);
    }
    for offset in [0xc, 0x2c] {
        if matches!(kind, IpiFixture::MsrIsolation) && second {
            code.extend([0x8d, 0x82, 0x80, 0, 0, 0, 0x39, 0x43, offset]);
        } else {
            code.extend([0x39, 0x53, offset]);
        }
        code.extend([0x74, 1, 0xcc]);
    }
    code.extend([0x83, 0x7b, 4, if wide { 14 } else { 29 }, 0x74, 1, 0xcc]);
    if wide {
        code.extend([0x83, 0x7b, 0x58, 14, 0x74, 1, 0xcc]);
    }
    code.extend([0x89, 0xd0, 0xc1, 0xe0, 16, 0x39, 0x43, 0x28, 0x74, 1, 0xcc]);
    code.extend([0x83, 0x7b, 0x30, 0, 0x74, 1, 0xcc, 0x81, 0x7b, 0x34]);
    code.extend(0x80050033u32.to_le_bytes());
    code.extend([0x74, 1, 0xcc, 0xf6, 0x43, 0x3c, 0x20, 0x75, 1, 0xcc]);
    let architecture = if wide {
        Architecture::X64
    } else {
        Architecture::X86
    };
    let parked = processor_layout(architecture, 1)
        .unwrap()
        .parked_thread
        .unwrap()
        - 4096;
    pointer(code, wide, parked);
    code.extend([0x89, 0xd6]);
    if wide {
        code.push(0x48);
    }
    code.extend([0xc1, 0xe6, 12]);
    if wide {
        code.push(0x48);
    }
    code.extend([0x01, 0xf0, 0x85, 0xd2, 0x75, if wide { 10 } else { 5 }]);
    pointer(code, wide, caller);
    if wide {
        code.push(0x48);
    }
    code.extend([0x39, 0x43, 0x18, 0x74, 1, 0xcc]);
    let stack = processor_layout(architecture, 0).unwrap().stack + STACK_SIZE
        - if wide { 0x170 } else { 0x10c };
    pointer(code, wide, stack);
    code.extend([0x89, 0xd6]);
    if wide {
        code.push(0x48);
    }
    code.extend([0xc1, 0xe6, 17]);
    if wide {
        code.push(0x48);
    }
    code.extend([0x01, 0xf0]);
    if wide {
        code.push(0x48);
    }
    code.extend([0x39, 0x43, 0x20, 0x74, 1, 0xcc]);
    let value = if matches!(kind, IpiFixture::Wide) && wide {
        0x1234567800001234u64
    } else {
        0x1234
    };
    pointer(code, wide, value);
    code.extend([0x89, 0xd6]);
    if wide {
        code.push(0x48);
    }
    code.extend([0x01, 0xf0]);
    if wide {
        code.push(0x48);
    }
    code.extend([0x39, 0x43, 0x40, 0x74, 1, 0xcc]);
    if matches!(kind, IpiFixture::MsrIsolation) {
        code.extend([
            0x8d, 0x82, 0x80, 0, 0, 0, 0x39, 0x43, 0x50, 0x74, 1, 0xcc, 0x8d, 0x82, 0, 1, 0, 0,
            0x39, 0x43, 0x54, 0x74, 1, 0xcc,
        ]);
    }
    if wide {
        code.push(0x48);
    }
    code.extend([
        0x81, 0xc3, 0x80, 0, 0, 0, 0xff, 0xc2, 0xff, 0xc9, 0x0f, 0x85,
    ]);
    let next = code.len() + 4;
    code.extend(
        i32::try_from(start as i64 - next as i64)
            .unwrap()
            .to_le_bytes(),
    );
}
pub fn ipi_probe(architecture: Architecture, kind: IpiFixture) -> Vec<u8> {
    let wide = architecture == Architecture::X64;
    let width = architecture.width();
    let logical = kind.logical();
    let base = if wide { 0x140000000u64 } else { 0x400000 };
    let layout = KernelLayout::for_architecture(architecture);
    let original = api_probe(architecture, ApiFixture::PoolLifecycle);
    let mut data = vec![0u8; 0x9200];
    data[..0x200].copy_from_slice(&original[..0x200]);
    let table = 0x98 + if wide { 0xf0 } else { 0xe0 };
    let dd = 0x98 + if wide { 112 } else { 96 };
    for (at, value) in [
        (0x98 + 4, 0x1000),
        (0x98 + 8, 0x8000),
        (0x98 + 56, 0xa000),
        (table + 8, 0x1000),
        (table + 16, 0x1000),
        (table + 40 + 8, 0x8000),
        (table + 40 + 16, 0x8000),
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
        "KeIpiGenericCall",
        "KeGetCurrentProcessorNumberEx",
        "KeGetCurrentIrql",
        "KeInitializeEvent",
        "PsCreateSystemThread",
        "KeWaitForSingleObject",
        "KeSetEvent",
        "PsTerminateSystemThread",
        "ZwClose",
        "KeQueryActiveProcessorCountEx",
        "KeNumberProcessors",
        "KeGetCurrentThread",
        "KeRaiseIrql",
        "KeLowerIrql",
        "KeDelayExecutionThread",
        "KeAcquireGuardedMutex",
        "KeInitializeGuardedMutex",
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
    put64(&mut data, 0x82c0, (-100i64) as u64);
    let mut root = Vec::new();
    root_prologue(&mut root, wide);
    call(&mut root, wide, base, 9, &[V(0)]);
    expect(&mut root, logical);
    load(&mut root, wide, base + 0x2080 + 10 * width as u64);
    root.extend([0x0f, 0xb6, 0]);
    expect(&mut root, logical.min(64));
    if kind.child() {
        for address in [base + 0x9200, base + 0x9240] {
            call(&mut root, wide, base, 3, &[V(address), V(0), V(0)]);
        }
        call(
            &mut root,
            wide,
            base,
            4,
            &[
                V(base + 0x9080),
                V(0x1fffff),
                V(0),
                V(0),
                V(0),
                V(base + 0x1e00),
                V(0),
            ],
        );
        expect(&mut root, 0);
        call(
            &mut root,
            wide,
            base,
            5,
            &[V(base + 0x9200), V(0), V(0), V(0), V(0)],
        );
        expect(&mut root, 0);
    }
    if matches!(kind, IpiFixture::LowerMutex) {
        call(&mut root, wide, base, 16, &[V(base + 0x9300)]);
    }
    if !matches!(kind, IpiFixture::ChildCaller) {
        let marker = if wide {
            0x1122334455667788u64
        } else {
            0xaabbccdd
        };
        if wide {
            root.push(0x48);
        }
        root.push(0xbb);
        if wide {
            root.extend(marker.to_le_bytes());
        } else {
            root.extend((marker as u32).to_le_bytes());
        }
        if wide {
            root.extend([0x48, 0x89, 0xe0]);
        } else {
            root.extend([0x89, 0xe0]);
        }
        store(&mut root, wide, base + 0x9040);
        if matches!(kind, IpiFixture::HighIrql) {
            call(
                &mut root,
                wide,
                base,
                12,
                &[V(if wide { 14 } else { 29 }), V(base + 0x90a0)],
            );
        }
        let routine = if matches!(kind, IpiFixture::Invalid) {
            base + 0x9000
        } else if matches!(kind, IpiFixture::Marker) {
            layout.return_marker + 0x200
        } else {
            base + 0x1800
        };
        call(&mut root, wide, base, 0, &[V(routine), V(base + 0x4000)]);
        store(&mut root, wide, base + 0x9000);
        if !kind.negative(architecture) {
            expect_pointer(
                &mut root,
                wide,
                if matches!(kind, IpiFixture::Wide) && wide {
                    0x1234567800001234
                } else {
                    0x1234
                },
            );
            if wide {
                root.extend([0x48, 0x89, 0xd8]);
            } else {
                root.extend([0x89, 0xd8]);
            }
            expect_pointer(&mut root, wide, marker);
            check_sp(&mut root, wide, base, base + 0x9040);
        }
        if kind.repeated() {
            pointer(&mut root, wide, base + 0x9100);
            root.extend([0xc7, 0, 0, 0, 0, 0]);
            call(
                &mut root,
                wide,
                base,
                0,
                &[V(base + 0x1800), V(base + 0x6000)],
            );
            store(&mut root, wide, base + 0x9010);
            expect_pointer(&mut root, wide, 0x1234);
        }
    }
    if matches!(kind, IpiFixture::Background) {
        call(&mut root, wide, base, 6, &[V(base + 0x9240), V(0), V(0)]);
        call(
            &mut root,
            wide,
            base,
            5,
            &[V(layout.thread_object(2).unwrap()), V(0), V(0), V(0), V(0)],
        );
        expect(&mut root, 0);
    }
    if kind.child() {
        call(&mut root, wide, base, 8, &[M(base + 0x9080)]);
        expect(&mut root, 0);
    }
    if kind.negative(architecture) {
        root.push(0xcc);
    } else {
        call(&mut root, wide, base, 1, &[V(0)]);
        expect(&mut root, 0);
        call(&mut root, wide, base, 2, &[]);
        expect(&mut root, 0);
        call(&mut root, wide, base, 11, &[]);
        expect_pointer(&mut root, wide, layout.root_thread);
        let caller = if matches!(kind, IpiFixture::ChildCaller) {
            layout.thread_object(2).unwrap()
        } else {
            layout.root_thread
        };
        verify_rows(&mut root, wide, base + 0x4000, logical, caller, kind, false);
        if kind.repeated() {
            verify_rows(&mut root, wide, base + 0x6000, logical, caller, kind, true);
        }
        if matches!(kind, IpiFixture::MsrIsolation) {
            root.extend([0xb9, 3, 1, 0, 0xc0, 0x0f, 0x32]);
            expect(&mut root, 0x80);
            root.extend([0xb9, 0x3b, 0, 0, 0, 0x0f, 0x32]);
            expect(&mut root, 0x100);
        }
    }
    root.extend([0xb8, 1, 0, 0, 0]);
    root_return(&mut root, wide);
    assert!(root.len() <= 0x800);
    data[0x200..0x200 + root.len()].copy_from_slice(&root);
    let mut callback = Vec::new();
    if wide {
        callback.extend([0x48, 0x89, 0xcb, 0x48, 0x83, 0xec, 0x68]);
    } else {
        callback.extend([0x8b, 0x5c, 0x24, 4]);
    }
    at_call(&mut callback, wide, base, 1, &[V(0)], 0x1800);
    callback.extend([0x89, 0xc7]);
    if wide {
        callback.push(0x48);
    }
    callback.extend([0xc1, 0xe7, 7]);
    if wide {
        callback.push(0x48);
    }
    callback.extend([0x01, 0xdf, 0x89, 7]);
    if wide {
        callback.push(0x48);
    }
    callback.extend([0x89, 0x67, 0x20]);
    at_call(&mut callback, wide, base, 2, &[], 0x1800);
    callback.extend([
        0x89, 0x47, 4, 0xb8, 0x0b, 0, 0, 0, 0x31, 0xc9, 0x0f, 0xa2, 0x89, 0x57, 8, 0x0f, 0x01,
        0xf9, 0x89, 0x4f, 0x0c, 0xb8, 1, 0, 0, 0, 0x31, 0xc9, 0x0f, 0xa2, 0xc1, 0xeb, 24, 0x89,
        0x5f, 0x14,
    ]);
    if wide {
        callback.extend([
            0x65, 0x8b, 4, 0x25, 0xa4, 1, 0, 0, 0x89, 0x47, 0x10, 0x65, 0x48, 0x8b, 4, 0x25, 0x88,
            1, 0, 0, 0x48, 0x89, 0x47, 0x18, 0x48, 0x8d, 0x4f, 0x28,
        ]);
    } else {
        callback.extend([
            0x64, 0x0f, 0xb6, 5, 0x51, 0, 0, 0, 0x89, 0x47, 0x10, 0x64, 0xa1, 0x24, 1, 0, 0, 0x89,
            0x47, 0x18, 0x8d, 0x47, 0x28, 0x50,
        ]);
    }
    at_call(&mut callback, wide, base, 1, &[], 0x1800);
    callback.extend([
        0xb9, 3, 1, 0, 0xc0, 0x0f, 0x32, 0x89, 0x47, 0x2c, 0x9c, 0x58, 0x25, 0, 2, 0, 0, 0x89,
        0x47, 0x30, 0x0f, 0x20, 0xc0, 0x89, 0x47, 0x34, 0x0f, 0x20, 0xe0, 0x89, 0x47, 0x3c,
    ]);
    if wide {
        callback.extend([0x44, 0x0f, 0x20, 0xc0, 0x89, 0x47, 0x58]);
    }
    if matches!(kind, IpiFixture::MsrIsolation) {
        callback.extend([
            0x8b, 7, 0x05, 0x80, 0, 0, 0, 0x31, 0xd2, 0xb9, 3, 1, 0, 0xc0, 0x0f, 0x30, 0x8b, 7,
            0x05, 0, 1, 0, 0, 0x31, 0xd2, 0xb9, 0x3b, 0, 0, 0, 0x0f, 0x30,
        ]);
    }
    if kind.barrier() {
        pointer(&mut callback, wide, base + 0x9100);
        callback.extend([0xf0, 0xff, 0, 0x81, 0x38]);
        callback.extend(logical.to_le_bytes());
        callback.extend([0x75, 0xf8]);
    }
    if matches!(kind, IpiFixture::MsrIsolation) {
        callback.extend([
            // Keep post-switch proofs outside the8-byte ULONG_PTR result at40.
            0x0f, 0x01, 0xf9, 0x89, 0x4f, 0x50, 0xb9, 0x3b, 0, 0, 0, 0x0f, 0x32, 0x89, 0x47, 0x54,
        ]);
    }
    if kind.lowered_scheduler_probe() {
        // Lower real architectural IRQL without updating the API shadow. The
        // next actual gate must refuse before touching the caller scheduler.
        if wide {
            callback.extend([0x31, 0xc0, 0x44, 0x0f, 0x22, 0xc0]);
        } else {
            callback.extend([0x64, 0xc6, 5, 0x24, 0, 0, 0, 0]);
        }
        match kind {
            IpiFixture::LowerWait => at_call(
                &mut callback,
                wide,
                base,
                5,
                &[V(base + 0x9240), V(0), V(0), V(0), V(0)],
                0x1800,
            ),
            IpiFixture::LowerDelay => at_call(
                &mut callback,
                wide,
                base,
                14,
                &[V(0), V(0), V(base + 0x90c0)],
                0x1800,
            ),
            IpiFixture::LowerMutex => {
                at_call(&mut callback, wide, base, 15, &[V(base + 0x9300)], 0x1800)
            }
            IpiFixture::LowerCreate => at_call(
                &mut callback,
                wide,
                base,
                4,
                &[
                    V(base + 0x9088),
                    V(0x1fffff),
                    V(0),
                    V(0),
                    V(0),
                    V(base + 0x1e00),
                    V(0),
                ],
                0x1800,
            ),
            _ => unreachable!(),
        }
    }
    if matches!(kind, IpiFixture::ControlMutation) {
        callback.extend([0x0f, 0x20, 0xe0, 0x0d, 0x10, 0, 0, 0, 0x0f, 0x22, 0xe0]);
    }
    if matches!(kind, IpiFixture::DescriptorMutation) {
        pointer(
            &mut callback,
            wide,
            KernelLayout::for_architecture(architecture).descriptor_tables + 0x30,
        );
        callback.extend([0xc6, 0, 0]);
    }
    if matches!(kind, IpiFixture::UnownedMsr) {
        callback.extend([0xb9, 0x1b, 0, 0, 0, 0x0f, 0x32]);
    }
    if matches!(kind, IpiFixture::Fault) {
        callback.extend([0x83, 0x3f, 1, 0x75, 2, 0x0f, 0x0b]);
    }
    if matches!(kind, IpiFixture::Nested) {
        at_call(
            &mut callback,
            wide,
            base,
            0,
            &[V(base + 0x1800), V(base + 0x4000)],
            0x1800,
        );
    }
    if matches!(kind, IpiFixture::Terminate) {
        at_call(&mut callback, wide, base, 7, &[V(0)], 0x1800);
    }
    if matches!(kind, IpiFixture::PcrIrql) {
        if wide {
            callback.extend([0x65, 0xc6, 0x04, 0x25, 0x50, 0, 0, 0, 0]);
        } else {
            callback.extend([0x64, 0xc6, 5, 0x24, 0, 0, 0, 0]);
        }
        at_call(&mut callback, wide, base, 1, &[V(0)], 0x1800);
    }
    if matches!(kind, IpiFixture::Irql) {
        if wide {
            callback.extend([0x31, 0xc0, 0x44, 0x0f, 0x22, 0xc0]);
        } else {
            callback.extend([0x64, 0xc6, 5, 0x24, 0, 0, 0, 0]);
        }
    }
    callback.extend([0x8b, 7]);
    if wide {
        callback.push(0x48);
    }
    callback.push(0xba);
    let result = if matches!(kind, IpiFixture::Wide) && wide {
        0x1234567800001234u64
    } else {
        0x1234
    };
    if wide {
        callback.extend(result.to_le_bytes());
        callback.extend([
            0x48, 0x01, 0xd0, 0x48, 0x89, 0x47, 0x40, 0x48, 0x83, 0xc4, 0x68, 0xc3,
        ]);
    } else {
        callback.extend((result as u32).to_le_bytes());
        callback.extend([0x01, 0xd0, 0x89, 0x47, 0x40, 0xc2, 4, 0]);
    }
    assert!(callback.len() <= 0x600);
    data[0xa00..0xa00 + callback.len()].copy_from_slice(&callback);
    let mut child = Vec::new();
    if wide {
        child.extend([0x48, 0x83, 0xec, 0x68]);
    }
    if matches!(kind, IpiFixture::ChildCaller) {
        at_call(
            &mut child,
            wide,
            base,
            0,
            &[V(base + 0x1800), V(base + 0x4000)],
            0x1e00,
        );
        store(&mut child, wide, base + 0x9000);
        expect(&mut child, 0x1234);
        at_call(
            &mut child,
            wide,
            base,
            6,
            &[V(base + 0x9200), V(0), V(0)],
            0x1e00,
        );
    } else {
        at_call(
            &mut child,
            wide,
            base,
            6,
            &[V(base + 0x9200), V(0), V(0)],
            0x1e00,
        );
        at_call(
            &mut child,
            wide,
            base,
            5,
            &[V(base + 0x9240), V(0), V(0), V(0), V(0)],
            0x1e00,
        );
    }
    at_call(&mut child, wide, base, 7, &[V(0)], 0x1e00);
    child.extend([0x0f, 0x0b]);
    assert!(child.len() <= 0x200);
    data[0x1000..0x1000 + child.len()].copy_from_slice(&child);
    data
}
