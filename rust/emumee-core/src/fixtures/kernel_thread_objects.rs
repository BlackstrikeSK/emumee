//! Actual guest-created child execution, handle references and body guards.
use super::winhttp::{
    Arg::{Memory as M, Value as V},
    call, store,
};
use super::{ApiFixture, api_probe, put32, put64};
use crate::{kernel_layout::KernelLayout, pe::Architecture};
#[derive(Clone, Copy, Debug)]
pub enum ThreadObjectFixture {
    Lifecycle,
    ObjectAttributes,
    ObjectAttributesNamed,
    ChildReturn,
    Priority,
    PriorityInvalid,
    PriorityForeign,
    CloseAfterExit,
    InvalidHandle,
    ClosedHandle,
    TypeMismatch,
    UserTypeMismatch,
    KernelAccess,
    UserMode,
    ReadonlyOutput,
    InformationOutput,
    Irql,
    ForeignHandle,
    ReleasedWait,
    ReleasedReference,
    ReleasedRead,
    RootHeader,
    RootPrivateCross,
    RootPreviousPageCross,
    RootHeaderWrite,
    RootApiWrite,
    RootTerminate,
    HeaderReadBenchmark,
    OrdinaryReadBenchmark,
}
impl ThreadObjectFixture {
    pub fn negative(self) -> bool {
        matches!(
            self,
            Self::PriorityInvalid
                | Self::ObjectAttributesNamed
                | Self::PriorityForeign
                | Self::UserMode
                | Self::ReadonlyOutput
                | Self::InformationOutput
                | Self::Irql
                | Self::ForeignHandle
                | Self::ReleasedWait
                | Self::ReleasedReference
                | Self::ReleasedRead
                | Self::RootPrivateCross
                | Self::RootPreviousPageCross
                | Self::RootHeaderWrite
                | Self::RootApiWrite
                | Self::RootTerminate
        )
    }
    pub fn root_only(self) -> bool {
        matches!(
            self,
            Self::RootHeader
                | Self::RootPrivateCross
                | Self::RootPreviousPageCross
                | Self::RootHeaderWrite
                | Self::RootApiWrite
                | Self::RootTerminate
                | Self::HeaderReadBenchmark
                | Self::OrdinaryReadBenchmark
        )
    }
    pub fn benchmark(self) -> bool {
        matches!(
            self,
            Self::HeaderReadBenchmark | Self::OrdinaryReadBenchmark
        )
    }
}
/// The shared ABI argument emitter defaults to codeRVA0x1000. Child code is
/// deliberately placed atRVA0x1c00, so compute the trailing IAT displacement
/// from that explicit code origin. The emitter always ends in one six-byte
/// indirect CALL; no opcode scanning or driver instruction patching occurs.
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
        let next = 0x1c00i64 + end as i64;
        let target = 0x2080i64 + index as i64 * 8;
        let displacement = i32::try_from(target - next).unwrap();
        code[end - 4..].copy_from_slice(&displacement.to_le_bytes());
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
pub fn kernel_thread_objects_probe(
    architecture: Architecture,
    kind: ThreadObjectFixture,
) -> Vec<u8> {
    let wide = architecture == Architecture::X64;
    let width = architecture.width();
    let base = if wide { 0x140000000u64 } else { 0x400000 };
    let layout = KernelLayout::for_architecture(architecture);
    let child_object = layout.thread_object(2).unwrap();
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
        "KeInitializeEvent",
        "PsCreateSystemThread",
        "ObReferenceObjectByHandle",
        "ZwClose",
        "KeSetEvent",
        "KeWaitForSingleObject",
        "PsTerminateSystemThread",
        "ObfDereferenceObject",
        "ObfReferenceObject",
        "PsThreadType",
        "PsProcessType",
        "KeGetCurrentThread",
        "KeGetCurrentProcessorNumber",
        "KeRaiseIrql",
        "RtlMoveMemory",
        "ObReferenceObjectByPointer",
        "KeSetActualBasePriorityThread",
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
    data[0x1e00..0x1e50].fill(0xcc);
    if matches!(
        kind,
        ThreadObjectFixture::ObjectAttributes | ThreadObjectFixture::ObjectAttributesNamed
    ) {
        // Mapped .data RVA 0x2e00 has raw offset 0x2000. An x64 unnamed
        // OBJECT_ATTRIBUTES has Length=48 and OBJ_KERNEL_HANDLE; the named
        // negative changes only ObjectName, requiring an explicit refusal.
        assert!(wide);
        put32(&mut data, 0x2000, 48);
        put32(&mut data, 0x2018, 0x200);
        if matches!(kind, ThreadObjectFixture::ObjectAttributesNamed) {
            put64(&mut data, 0x2010, base + 0x2f00);
        }
    }
    let mut root = Vec::new();
    prologue(&mut root, wide);
    if kind.root_only() {
        call(&mut root, wide, base, 11, &[]);
        expect_pointer(&mut root, wide, layout.root_thread);
        store(&mut root, wide, base + 0x2c08);
        match kind {
            ThreadObjectFixture::RootHeader => {
                load(&mut root, wide, base + 0x2c08);
                root.extend([0x8b, 0x40, 4]);
                expect(&mut root, 0);
                load(&mut root, wide, base + 0x2c08);
                root.extend([0x0f, 0xb6, 0]);
                expect(&mut root, 6);
                load(&mut root, wide, base + 0x2c08);
                root.extend([0x0f, 0xb6, 0x40, 2]);
                expect(&mut root, if wide { 6 } else { 4 });
                call(&mut root, wide, base, 12, &[]);
                expect(&mut root, 0);
            }
            ThreadObjectFixture::RootPrivateCross => {
                load(&mut root, wide, base + 0x2c08);
                if wide {
                    root.push(0x48);
                }
                root.extend([0x83, 0xc0, 4]);
                if wide {
                    root.extend([0x48, 0x8b, 0]);
                } else {
                    root.extend([0xdd, 0]);
                }
            }
            ThreadObjectFixture::RootPreviousPageCross => {
                // Explicit guest SSE precondition for this owned16-byte read.
                root.extend([0x0f, 0x20, 0xe0, 0x0d, 0, 6, 0, 0, 0x0f, 0x22, 0xe0]);
                load(&mut root, wide, base + 0x2c08);
                if wide {
                    root.push(0x48);
                }
                root.extend([0x83, 0xe8, 4, 0xf3, 0x0f, 0x6f, 0]);
            }
            ThreadObjectFixture::RootHeaderWrite => {
                load(&mut root, wide, base + 0x2c08);
                root.extend([0xc7, 0]);
                root.extend(*b"FAIL");
            }
            ThreadObjectFixture::RootTerminate => call(&mut root, wide, base, 6, &[V(0x12345678)]),
            ThreadObjectFixture::RootApiWrite => call(
                &mut root,
                wide,
                base,
                14,
                &[M(base + 0x2c08), V(base + 0x2b00), V(4)],
            ),
            ThreadObjectFixture::HeaderReadBenchmark
            | ThreadObjectFixture::OrdinaryReadBenchmark => {
                if wide {
                    root.push(0x48);
                }
                root.push(0xbb);
                let address = if matches!(kind, ThreadObjectFixture::HeaderReadBenchmark) {
                    layout.root_thread
                } else {
                    base + 0x2f00
                };
                if wide {
                    root.extend(address.to_le_bytes());
                } else {
                    root.extend((address as u32).to_le_bytes());
                }
                root.extend([0xb9]);
                root.extend(10000u32.to_le_bytes());
                let start = root.len();
                root.extend([0x8b, 0x43, 4, 0x85, 0xc0, 0x74, 1, 0xcc, 0xff, 0xc9, 0x75]);
                let next = root.len() + 1;
                root.push((start as isize - next as isize) as i8 as u8);
            }
            _ => unreachable!(),
        }
    } else {
        for (index, slot) in [(9, 0x2c10), (10, 0x2c18)] {
            load(&mut root, wide, base + 0x2080 + index * width as u64);
            if wide {
                root.push(0x48);
            }
            root.extend([0x8b, 0]);
            store(&mut root, wide, base + slot);
        }
        for event in [0x2d00, 0x2d40] {
            call(&mut root, wide, base, 0, &[V(base + event), V(0), V(0)]);
        }
        call(
            &mut root,
            wide,
            base,
            1,
            &[
                V(base + 0x2c00),
                V(if matches!(kind, ThreadObjectFixture::KernelAccess) {
                    0
                } else {
                    0x1fffff
                }),
                V(
                    if matches!(
                        kind,
                        ThreadObjectFixture::ObjectAttributes
                            | ThreadObjectFixture::ObjectAttributesNamed
                    ) {
                        base + 0x2e00
                    } else {
                        0
                    },
                ),
                V(0),
                V(base + 0x2c50),
                V(base + 0x1c00),
                V(0),
            ],
        );
        expect(&mut root, 0);
        call(
            &mut root,
            wide,
            base,
            5,
            &[V(base + 0x2d40), V(0), V(0), V(0), V(0)],
        );
        expect(&mut root, 0);
        if matches!(kind, ThreadObjectFixture::Irql) {
            call(&mut root, wide, base, 13, &[V(1), V(base + 0x2f20)]);
        }
        let handle = if matches!(kind, ThreadObjectFixture::InvalidHandle) {
            V((if wide {
                0xffff_ffff_8000_0000u64
            } else {
                0x8000_0000
            }) + 12)
        } else if matches!(kind, ThreadObjectFixture::ForeignHandle) {
            V(0xdeadbeef)
        } else {
            M(base + 0x2c00)
        };
        let selected = if matches!(
            kind,
            ThreadObjectFixture::TypeMismatch | ThreadObjectFixture::UserTypeMismatch
        ) {
            base + 0x2c18
        } else {
            base + 0x2c10
        };
        let mode = if matches!(
            kind,
            ThreadObjectFixture::UserMode | ThreadObjectFixture::UserTypeMismatch
        ) {
            1
        } else {
            0
        };
        let output = if matches!(kind, ThreadObjectFixture::ReadonlyOutput) {
            base + 0x1000
        } else {
            base + 0x2c08
        };
        let info = if matches!(kind, ThreadObjectFixture::InformationOutput) {
            base + 0x2c40
        } else {
            0
        };
        call(
            &mut root,
            wide,
            base,
            2,
            &[
                handle,
                V(0x100000),
                M(selected),
                V(mode),
                V(output),
                V(info),
            ],
        );
        if matches!(
            kind,
            ThreadObjectFixture::InvalidHandle
                | ThreadObjectFixture::TypeMismatch
                | ThreadObjectFixture::UserTypeMismatch
        ) {
            expect(
                &mut root,
                if matches!(kind, ThreadObjectFixture::InvalidHandle) {
                    0xc0000008
                } else {
                    0xc0000024
                },
            );
            load(&mut root, wide, base + 0x2c08);
            expect_pointer(
                &mut root,
                wide,
                if wide {
                    u64::MAX / 255 * 0xcc
                } else {
                    0xcccccccc
                },
            );
            call(
                &mut root,
                wide,
                base,
                2,
                &[
                    M(base + 0x2c00),
                    V(0),
                    M(base + 0x2c10),
                    V(0),
                    V(base + 0x2c08),
                    V(0),
                ],
            );
        }
        if !matches!(
            kind,
            ThreadObjectFixture::UserMode
                | ThreadObjectFixture::ReadonlyOutput
                | ThreadObjectFixture::InformationOutput
                | ThreadObjectFixture::Irql
                | ThreadObjectFixture::ForeignHandle
        ) {
            expect(&mut root, 0);
            load(&mut root, wide, base + 0x2c08);
            expect_pointer(&mut root, wide, child_object);
            if !matches!(kind, ThreadObjectFixture::CloseAfterExit) {
                call(&mut root, wide, base, 3, &[M(base + 0x2c00)]);
                expect(&mut root, 0);
            }
            if matches!(kind, ThreadObjectFixture::ClosedHandle) {
                call(
                    &mut root,
                    wide,
                    base,
                    2,
                    &[
                        M(base + 0x2c00),
                        V(0),
                        M(base + 0x2c10),
                        V(0),
                        V(base + 0x2c30),
                        V(0),
                    ],
                );
                expect(&mut root, 0xc0000008);
                load(&mut root, wide, base + 0x2c30);
                expect_pointer(
                    &mut root,
                    wide,
                    if wide {
                        u64::MAX / 255 * 0xcc
                    } else {
                        0xcccccccc
                    },
                );
            }
            call(
                &mut root,
                wide,
                base,
                5,
                &[M(base + 0x2c08), V(0), V(0), V(0), V(base + 0x2f00)],
            );
            expect(&mut root, 0x102);
            call(&mut root, wide, base, 4, &[V(base + 0x2d00), V(0), V(0)]);
            for _ in 0..2 {
                call(
                    &mut root,
                    wide,
                    base,
                    5,
                    &[M(base + 0x2c08), V(0), V(0), V(0), V(0)],
                );
                expect(&mut root, 0);
            }
            load(&mut root, wide, base + 0x2c08);
            root.extend([0x8b, 0x40, 4]);
            expect(&mut root, 1);
            if matches!(kind, ThreadObjectFixture::CloseAfterExit) {
                call(&mut root, wide, base, 3, &[M(base + 0x2c00)]);
                expect(&mut root, 0);
            }
            fast(&mut root, wide, base, 8, base + 0x2c08);
            fast(&mut root, wide, base, 7, base + 0x2c08);
            fast(&mut root, wide, base, 7, base + 0x2c08);
            match kind {
                ThreadObjectFixture::ReleasedWait => call(
                    &mut root,
                    wide,
                    base,
                    5,
                    &[M(base + 0x2c08), V(0), V(0), V(0), V(0)],
                ),
                ThreadObjectFixture::ReleasedReference => call(
                    &mut root,
                    wide,
                    base,
                    15,
                    &[M(base + 0x2c08), V(0), V(0), V(0)],
                ),
                ThreadObjectFixture::ReleasedRead => {
                    load(&mut root, wide, base + 0x2c08);
                    root.extend([0x8b, 0]);
                }
                _ => {}
            }
        }
    }
    if kind.negative() {
        root.push(0xcc);
    }
    root.extend([0xb8, 1, 0, 0, 0]);
    returned(&mut root, wide, false);
    assert!(root.len() <= 0xc00);
    data[0x200..0x200 + root.len()].copy_from_slice(&root);
    let mut child = Vec::new();
    prologue(&mut child, wide);
    child_call(&mut child, wide, base, 11, &[]);
    if matches!(kind, ThreadObjectFixture::Priority) {
        // Feed the actual KeGetCurrentThread result into the setter, so this
        // fixture checks guest pointer dataflow as well as object identity.
        store(&mut child, wide, base + 0x2c60);
    }
    expect_pointer(&mut child, wide, child_object);
    child_call(&mut child, wide, base, 12, &[]);
    expect(&mut child, 0);
    if matches!(
        kind,
        ThreadObjectFixture::Priority
            | ThreadObjectFixture::PriorityInvalid
            | ThreadObjectFixture::PriorityForeign
    ) {
        child_call(
            &mut child,
            wide,
            base,
            16,
            &[
                if matches!(kind, ThreadObjectFixture::Priority) {
                    M(base + 0x2c60)
                } else {
                    V(if matches!(kind, ThreadObjectFixture::PriorityForeign) {
                        base + 0x2c30
                    } else {
                        child_object
                    })
                },
                V(if matches!(kind, ThreadObjectFixture::PriorityInvalid) {
                    0
                } else {
                    15
                }),
            ],
        );
        if matches!(kind, ThreadObjectFixture::Priority) {
            expect(&mut child, 8); // Existing child base priority is the native return.
        }
    }
    child_call(&mut child, wide, base, 4, &[V(base + 0x2d40), V(0), V(0)]);
    child_call(
        &mut child,
        wide,
        base,
        5,
        &[V(base + 0x2d00), V(0), V(0), V(0), V(0)],
    );
    expect(&mut child, 0);
    if matches!(kind, ThreadObjectFixture::ChildReturn) {
        child.extend([0x31, 0xc0]);
        returned(&mut child, wide, true);
    } else {
        child_call(&mut child, wide, base, 6, &[V(0x11223344)]);
        child.extend([0x0f, 0x0b]);
    }
    assert!(child.len() <= 0x400);
    data[0xe00..0xe00 + child.len()].copy_from_slice(&child);
    data
}
