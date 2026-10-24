//! Actual native query and half-open lookup programs over owned mapped modules.
use super::winhttp::{
    Arg::{Memory as M, Value as V},
    call, expect_dword, load, store, write_dword,
};
use super::{ApiFixture, api_probe, put32, put64};
use crate::pe::Architecture;
#[derive(Clone, Copy, Debug)]
pub enum ModuleFixture {
    Standard,
    Extended,
    RelocatedExtended,
    AliasStandard,
    AliasExtended,
    OptionalLength,
    Short,
    PcOnly,
    QueuedLockPc,
    ReadOnlyOutput,
    ReadOnlyLength,
    UnmappedOutput,
    UnmappedLength,
    NullOutput,
    Overlap,
    UnknownTime,
    UnknownDebugger,
    UnknownCi,
    UnknownProcess,
    HighIrql,
    MissingProvenance,
}
impl ModuleFixture {
    pub fn error(self) -> Option<&'static str> {
        Some(match self {
            Self::Standard
            | Self::Extended
            | Self::RelocatedExtended
            | Self::AliasStandard
            | Self::AliasExtended
            | Self::OptionalLength
            | Self::Short
            | Self::PcOnly
            | Self::QueuedLockPc => return None,
            Self::ReadOnlyOutput
            | Self::ReadOnlyLength
            | Self::UnmappedOutput
            | Self::UnmappedLength
            | Self::NullOutput => "range",
            Self::Overlap => "outputs overlap",
            Self::UnknownTime | Self::UnknownDebugger | Self::UnknownCi | Self::UnknownProcess => {
                "outside the modeled 11/77 module profile"
            }
            Self::HighIrql => "requires supported PASSIVE_LEVEL",
            Self::MissingProvenance => "lacks explicit guest path/header provenance",
        })
    }
    pub fn extended(self) -> bool {
        !matches!(self, Self::Standard | Self::AliasStandard)
    }
    pub fn query_calls(self) -> u64 {
        if matches!(self, Self::PcOnly | Self::QueuedLockPc) {
            0
        } else if self.error().is_some() || matches!(self, Self::Short) {
            1
        } else {
            2
        }
    }
    pub fn api_calls(self) -> u64 {
        self.query_calls()
            + if self.error().is_none() {
                if matches!(self, Self::QueuedLockPc) {
                    4
                } else {
                    3
                }
            } else if matches!(self, Self::HighIrql | Self::MissingProvenance) {
                1
            } else {
                0
            }
    }
}
fn expect(c: &mut Vec<u8>, v: u32) {
    c.push(0x3d);
    c.extend(v.to_le_bytes());
    c.extend([0x74, 1, 0xcc]);
}
fn ptr(c: &mut Vec<u8>, wide: bool, value: u64) {
    if wide {
        c.extend([0x48, 0xba]);
        c.extend(value.to_le_bytes());
        c.extend([0x48, 0x39, 0xd0, 0x74, 1, 0xcc]);
    } else {
        expect(c, value as u32);
    }
}
fn load_ptr(c: &mut Vec<u8>, wide: bool, address: u64) {
    if wide {
        c.push(0x48);
    }
    c.push(0xa1);
    if wide {
        c.extend(address.to_le_bytes());
    } else {
        c.extend((address as u32).to_le_bytes());
    }
}
fn invocation(c: &mut Vec<u8>, wide: bool, base: u64, index: usize, args: &[u64]) {
    call(
        c,
        wide,
        base,
        index,
        &args.iter().copied().map(V).collect::<Vec<_>>(),
    );
}
fn path(c: &mut Vec<u8>, wide: bool, address: u64, value: &str) {
    let mut bytes = value.as_bytes().to_vec();
    bytes.push(0);
    while bytes.len() % 4 != 0 {
        bytes.push(0);
    }
    for (index, part) in bytes.chunks_exact(4).enumerate() {
        expect_dword(
            c,
            wide,
            address + index as u64 * 4,
            u32::from_le_bytes(part.try_into().unwrap()),
        );
    }
}
pub fn kernel_modules_probe(architecture: Architecture, kind: ModuleFixture) -> Vec<u8> {
    let wide = architecture == Architecture::X64;
    let w = architecture.width();
    let base = if wide { 0x140000000u64 } else { 0x400000 };
    let nt = if wide {
        0xfffff80000400000u64
    } else {
        0x80400000
    };
    let cng = if wide {
        0xfffff80002400000u64
    } else {
        0x82400000
    };
    let source = api_probe(architecture, ApiFixture::PoolLifecycle);
    let mut data = vec![0; 0x5200];
    data[..0x200].copy_from_slice(&source[..0x200]);
    let table = 0x98 + if wide { 0xf0 } else { 0xe0 };
    let dd = 0x98 + if wide { 112 } else { 96 };
    for (at, value) in [
        (0x88, 0x12345678),
        (0x98 + 64, 0x98765432),
        (0x98 + 4, 0x1000),
        (0x98 + 8, 0x4000),
        (0x98 + 56, 0x6000),
        (table + 8, 0x1000),
        (table + 16, 0x1000),
        (table + 40 + 8, 0x4000),
        (table + 40 + 16, 0x4000),
        (table + 40 + 20, 0x1200),
        (dd + 8, 0x2000),
        (dd + 12, 60),
        (0x1200, 0x2180),
        (0x120c, 0x2040),
        (0x1210, 0x2080),
        (0x1214, 0x21f0),
        (0x1220, 0x2060),
        (0x1224, 0x20f0),
    ] {
        put32(&mut data, at, value);
    }
    data[0x1240..0x124d].copy_from_slice(b"ntoskrnl.exe\0");
    data[0x1260..0x1268].copy_from_slice(b"cng.sys\0");
    if matches!(kind, ModuleFixture::RelocatedExtended) {
        let preferred = base + 0x200000;
        if wide {
            put64(&mut data, 0x98 + 24, preferred);
            put64(&mut data, 0x1b00, preferred + 0x1000);
        } else {
            put32(&mut data, 0x98 + 28, preferred as u32);
            put32(&mut data, 0x1b00, (preferred + 0x1000) as u32);
        }
        put32(&mut data, dd + 5 * 8, 0x5000);
        put32(&mut data, dd + 5 * 8 + 4, 12);
        put32(&mut data, 0x4200, 0x2000);
        put32(&mut data, 0x4204, 12);
        data[0x4208..0x420a]
            .copy_from_slice(&(if wide { 0xa900u16 } else { 0x3900 }).to_le_bytes());
    }
    let names = [
        "ZwQuerySystemInformation",
        "NtQuerySystemInformation",
        "RtlPcToFileHeader",
        "KeRaiseIrql",
    ];
    for (index, name) in names.iter().enumerate() {
        let rva = 0x2400 + index as u32 * 64;
        for at in [0x1280, 0x1380] {
            if wide {
                put64(&mut data, at + index * w, rva.into());
            } else {
                put32(&mut data, at + index * w, rva);
            }
        }
        let at = 0x1600 + index * 64;
        data[at + 2..at + 2 + name.len()].copy_from_slice(name.as_bytes());
    }
    for at in [0x12f0, 0x13f0] {
        if wide {
            put64(&mut data, at, 0x2300);
        } else {
            put32(&mut data, at, 0x2300);
        }
    }
    data[0x1502..0x1512].copy_from_slice(b"BCryptFinishHash");
    let extended = kind.extended();
    let stride = if extended {
        if wide { 320 } else { 300 }
    } else if wide {
        296
    } else {
        284
    };
    let required = 11 * stride + if extended { 2 } else { w };
    let output = base + 0x3000;
    let length = base + 0x2800;
    let slot = base + 0x2820;
    let mut c = if wide {
        vec![0x48, 0x83, 0xec, 0x68]
    } else {
        Vec::new()
    };
    write_dword(&mut c, wide, length, 0x77777777);
    write_dword(&mut c, wide, length + 4, 0x77777777);
    write_dword(&mut c, wide, output, 0x77777777);
    write_dword(&mut c, wide, output + required as u64, 0x77777777);
    if matches!(kind, ModuleFixture::RelocatedExtended) {
        load_ptr(&mut c, wide, base + 0x2900);
        ptr(&mut c, wide, base + 0x1000);
    }
    let class = match kind {
        ModuleFixture::UnknownTime => 3,
        ModuleFixture::UnknownDebugger => 35,
        ModuleFixture::UnknownCi => 103,
        ModuleFixture::UnknownProcess => 5,
        _ => {
            if extended {
                77
            } else {
                11
            }
        }
    };
    let query_index = usize::from(matches!(
        kind,
        ModuleFixture::AliasStandard | ModuleFixture::AliasExtended
    ));
    if matches!(kind, ModuleFixture::MissingProvenance) {
        invocation(&mut c, wide, base, 2, &[base + 0x1000, slot]);
        ptr(&mut c, wide, base);
    }
    if matches!(kind, ModuleFixture::HighIrql) {
        invocation(&mut c, wide, base, 3, &[1, slot]);
    }
    if kind.error().is_some() {
        let destination = match kind {
            ModuleFixture::ReadOnlyOutput => base + 0x1000,
            ModuleFixture::UnmappedOutput => 0x7fff0000,
            ModuleFixture::NullOutput => 0,
            _ => output,
        };
        let returned = match kind {
            ModuleFixture::ReadOnlyLength => base + 0x1000,
            ModuleFixture::UnmappedLength => 0x7fff0000,
            ModuleFixture::Overlap => output + 4,
            _ => length,
        };
        invocation(
            &mut c,
            wide,
            base,
            query_index,
            &[class, destination, required as u64, returned],
        );
        c.push(0xcc);
    } else {
        if !matches!(kind, ModuleFixture::PcOnly | ModuleFixture::QueuedLockPc) {
            invocation(
                &mut c,
                wide,
                base,
                query_index,
                &[
                    class,
                    if matches!(kind, ModuleFixture::Short) {
                        0x7fff0000
                    } else {
                        0
                    },
                    if matches!(kind, ModuleFixture::Short) {
                        1
                    } else {
                        0
                    },
                    length,
                ],
            );
            expect(&mut c, 0xc0000004);
            expect_dword(&mut c, wide, length, required as u32);
            expect_dword(&mut c, wide, length + 4, 0x77777777);
            if !matches!(kind, ModuleFixture::Short) {
                invocation(
                    &mut c,
                    wide,
                    base,
                    query_index,
                    &[
                        class,
                        output,
                        required as u64,
                        if matches!(kind, ModuleFixture::OptionalLength) {
                            0
                        } else {
                            length
                        },
                    ],
                );
                expect(&mut c, 0);
                if !extended {
                    expect_dword(&mut c, wide, output, 11);
                }
                for (index, (expected, filename)) in [
                    (nt, r"C:\Windows\system32\ntoskrnl.exe"),
                    (nt + 0x1000000, r"C:\Windows\system32\hal.dll"),
                    (base, r"C:\emumee\generated-fixture.exe"),
                    (cng, r"C:\Windows\system32\drivers\cng.sys"),
                    (cng + 0x1000000, r"C:\Windows\system32\ci.dll"),
                ]
                .into_iter()
                .enumerate()
                {
                    let cursor = output
                        + if extended {
                            (index * stride) as u64
                        } else {
                            (w + index * stride) as u64
                        };
                    let row = cursor + if extended { w as u64 } else { 0 };
                    if extended {
                        expect_dword(&mut c, wide, cursor, stride as u32);
                    }
                    load_ptr(&mut c, wide, row + 2 * w as u64);
                    ptr(&mut c, wide, expected);
                    // Every returned base dereferences genuine accepted guest PE headers.
                    c.push(0x0f);
                    c.extend([0xb7, 0]);
                    expect(&mut c, 0x5a4d);
                    load(&mut c, wide, row + 3 * w as u64);
                    c.extend([0x89, 0xc2]);
                    load(&mut c, wide, expected + 0xd0);
                    c.extend([0x39, 0xd0, 0x74, 1, 0xcc]);
                    expect_dword(&mut c, wide, row + 3 * w as u64 + 4, 0);
                    expect_dword(
                        &mut c,
                        wide,
                        row + 3 * w as u64 + 8,
                        (index as u32) | ((index as u32) << 16),
                    );
                    let basename = filename.rfind('\\').unwrap() + 1;
                    expect_dword(
                        &mut c,
                        wide,
                        row + 3 * w as u64 + 12,
                        1 | ((basename as u32) << 16),
                    );
                    path(&mut c, wide, row + 3 * w as u64 + 16, filename);
                    if extended {
                        let tail = row + if wide { 296 } else { 284 };
                        expect_dword(&mut c, wide, tail, if index == 2 { 0x98765432 } else { 0 });
                        expect_dword(
                            &mut c,
                            wide,
                            tail + 4,
                            if index == 2 { 0x12345678 } else { 0 },
                        );
                        load_ptr(&mut c, wide, cursor + stride as u64 - w as u64);
                        ptr(
                            &mut c,
                            wide,
                            expected
                                + if index == 2 && matches!(kind, ModuleFixture::RelocatedExtended)
                                {
                                    0x200000
                                } else {
                                    0
                                },
                        );
                    }
                }
                if extended {
                    expect_dword(&mut c, wide, output + 11 * stride as u64, 0x77770000);
                }
            } else {
                expect_dword(&mut c, wide, output, 0x77777777);
            }
            expect_dword(&mut c, wide, output + required as u64, 0x77777777);
        }
        for (pc, expected) in [(base + 0x1000, base), (base + 0x6000, 0), (nt + 0x1000, nt)] {
            invocation(&mut c, wide, base, 2, &[pc, slot]);
            ptr(&mut c, wide, expected);
            load_ptr(&mut c, wide, slot);
            ptr(&mut c, wide, expected);
        }
        if matches!(kind, ModuleFixture::QueuedLockPc) {
            assert!(wide);
            let queue_slot = base + 0x2840;
            // Load KPCR.Prcb.LockQueue through the actual GS context and then
            // its first lock backing pointer. The lookup receives that guest
            // pointer, not a fixture-encoded ntoskrnl address.
            c.extend([0x65, 0x48, 0x8b, 0x04, 0x25, 0x28, 0, 0, 0]);
            c.extend([0x48, 0x8b, 0x40, 0x08]);
            store(&mut c, wide, queue_slot);
            call(&mut c, wide, base, 2, &[M(queue_slot), V(slot)]);
            ptr(&mut c, wide, nt);
            load_ptr(&mut c, wide, slot);
            ptr(&mut c, wide, nt);
        }
        c.extend([0xb8, 1, 0, 0, 0]);
        if wide {
            c.extend([0x48, 0x83, 0xc4, 0x68]);
        }
        c.push(0xc3);
    }
    assert!(c.len() < 0x1000);
    data[0x200..0x200 + c.len()].copy_from_slice(&c);
    data
}
