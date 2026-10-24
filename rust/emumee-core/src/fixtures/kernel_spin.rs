//! Actual API spin-word, native-IRQL and cooperative exclusion controls.
use super::winhttp::{
    Arg::{Memory as M, Value as V},
    call, expect_dword, load, store, write_dword,
};
use super::{ApiFixture, api_probe, put32, put64};
use crate::pe::Architecture;
#[derive(Clone, Copy, Debug)]
pub enum SpinFixture {
    Basic,
    Nested,
    OldApc,
    Critical,
    Pool,
    ReusedPool,
    Scheduler,
    NativeQuantum,
    ApcQuantum,
    IpiRestored,
    Recursive,
    ReleaseUnowned,
    SavedIrql,
    OutOfOrder,
    HeldExit,
    HeldFree,
    LowerHeld,
    DirectLowerHeld,
    DirectWrite,
    ApiWrite,
    Readonly,
    Unaligned,
    InvalidRange,
    Paged,
    UnsupportedBacking,
    AliasFirst,
    AliasAfter,
    LiteralAlias,
    HighIrql,
    IpiWhileHeld,
    ReuseUninitialized,
    NativeBudget,
    HeldBudget,
}
impl SpinFixture {
    pub fn budget(self) -> bool {
        matches!(self, Self::NativeBudget | Self::HeldBudget)
    }
    pub fn scheduler(self) -> bool {
        matches!(
            self,
            Self::Scheduler
                | Self::NativeQuantum
                | Self::ApcQuantum
                | Self::NativeBudget
                | Self::HeldBudget
        )
    }
    pub fn error(self) -> Option<&'static str> {
        Some(match self {
            Self::Recursive => "busy or recursive spin acquisition",
            Self::ReleaseUnowned => "release without a spin owner",
            Self::SavedIrql => "saved/current IRQL mismatch",
            Self::OutOfOrder => "out-of-order spin release",
            Self::HeldExit => "thread exit while owning a spin lock",
            Self::HeldFree => "memory release overlaps a held spin lock",
            Self::LowerHeld | Self::DirectLowerHeld => "owner lowered below DISPATCH_LEVEL",
            Self::DirectWrite => "Direct guest mutation of an initialized spin word",
            Self::ApiWrite => "API mutation of an initialized spin word",
            Self::Readonly | Self::InvalidRange => "API guest range",
            Self::Unaligned => "null or unaligned word",
            Self::Paged => "Spin backing cannot be paged Pool",
            Self::UnsupportedBacking => "outside initialized guest-image/nonpaged-Pool profile",
            Self::AliasFirst => "unsupported MDL alias",
            Self::AliasAfter => "MDL alias/descriptor overlaps an initialized spin word",
            Self::LiteralAlias => "Unsupported Windows API",
            Self::HighIrql => "acquisition above DISPATCH_LEVEL",
            Self::IpiWhileHeld => "IPI entry while holding a spin lock",
            Self::ReuseUninitialized => "uninitialized or retired spin lock",
            _ => return None,
        })
    }
}
fn names(wide: bool) -> [&'static str; 24] {
    [
        "KeInitializeSpinLock",
        if wide {
            "KeAcquireSpinLockRaiseToDpc"
        } else {
            "KfAcquireSpinLock"
        },
        if wide {
            "KeReleaseSpinLock"
        } else {
            "KfReleaseSpinLock"
        },
        "ExAllocatePoolWithTag",
        "ExFreePoolWithTag",
        "KeGetCurrentIrql",
        "KfLowerIrql",
        "KeEnterCriticalRegion",
        "KeLeaveCriticalRegion",
        "KeAreApcsDisabled",
        "PsCreateSystemThread",
        "PsTerminateSystemThread",
        "ZwClose",
        "IoAllocateMdl",
        "MmBuildMdlForNonPagedPool",
        "MmMapLockedPagesSpecifyCache",
        if wide {
            "KfAcquireSpinLock"
        } else {
            "KeAcquireSpinLockRaiseToDpc"
        },
        "KeIpiGenericCall",
        "RtlZeroMemory",
        "",
        "SetLastError",
        "GetLastError",
        "VirtualAlloc",
        "",
    ]
}
struct Program {
    code: Vec<u8>,
    wide: bool,
    base: u64,
    rva: u64,
}
impl Program {
    fn call(&mut self, index: usize, args: &[super::winhttp::Arg]) {
        if !self.wide && matches!(index, 1 | 2 | 6) {
            for (position, arg) in args.iter().enumerate() {
                assert!(position < 2);
                match arg {
                    V(value) => {
                        self.code.push(if position == 0 { 0xb9 } else { 0xba });
                        self.code.extend((*value as u32).to_le_bytes());
                    }
                    M(address) => {
                        self.code.extend(if position == 0 {
                            [0x8b, 0x0d]
                        } else {
                            [0x8b, 0x15]
                        });
                        self.code.extend((*address as u32).to_le_bytes());
                    }
                }
            }
            self.code.extend([0xff, 0x15]);
            self.code
                .extend(((self.base + 0x2080) as u32 + index as u32 * 4).to_le_bytes());
        } else {
            call(&mut self.code, self.wide, self.base, index, args);
            if self.wide {
                let end = self.code.len();
                let displacement = 0x2080i64 + index as i64 * 8 - (self.rva as i64 + end as i64);
                self.code[end - 4..end]
                    .copy_from_slice(&i32::try_from(displacement).unwrap().to_le_bytes());
            }
        }
        if !self.wide {
            self.code.extend([0x39, 0xf4, 0x74, 1, 0xcc]);
        }
    }
    fn expect(&mut self, value: u32) {
        self.code.push(0x3d);
        self.code.extend(value.to_le_bytes());
        self.code.extend([0x74, 1, 0xcc]);
    }
    fn word(&mut self, address: u64, value: u64) {
        write_dword(&mut self.code, self.wide, address, value as u32);
        if self.wide {
            write_dword(&mut self.code, self.wide, address + 4, (value >> 32) as u32);
        }
    }
    fn check(&mut self, address: u64, value: u64) {
        expect_dword(&mut self.code, self.wide, address, value as u32);
        if self.wide {
            expect_dword(&mut self.code, self.wide, address + 4, (value >> 32) as u32);
        }
    }
    fn irql(&mut self, value: u8) {
        if self.wide {
            self.code
                .extend([0xb8, value, 0, 0, 0, 0x44, 0x0f, 0x22, 0xc0]);
        } else {
            self.code.extend([0x64, 0xc6, 5, 0x24, 0, 0, 0, value]);
        }
    }
    fn prologue(&mut self) {
        if self.wide {
            self.code.extend([0x48, 0x83, 0xec, 0x68]);
        } else {
            self.code.extend([0x56, 0x89, 0xe6]);
        }
    }
    fn returned(&mut self) {
        self.code.extend([0xb8, 17, 0, 0, 0]);
        if self.wide {
            self.code.extend([0x48, 0x83, 0xc4, 0x68]);
        } else {
            self.code.push(0x5e);
        }
        self.code.push(0xc3);
    }
    fn loop_cpu(&mut self) {
        self.code
            .extend([0xb9, 0x20, 3, 0, 0, 0xff, 0xc9, 0x75, 0xfc]);
    }
    fn poll_child(&mut self, marker: u64) {
        self.code.extend([0xb9, 0xd0, 7, 0, 0]);
        let start = self.code.len();
        load(&mut self.code, self.wide, marker);
        self.code.push(0x3d);
        self.code.extend(0x4348494cu32.to_le_bytes());
        self.code.extend([0x74, 5, 0xff, 0xc9, 0x75]);
        let back = start as i64 - (self.code.len() as i64 + 1);
        self.code.push(i8::try_from(back).unwrap() as u8);
        self.code.push(0xcc);
        self.code.extend([0x81, 0xfb]);
        self.code.extend(0x13572468u32.to_le_bytes());
        self.code.extend([0x74, 1, 0xcc]);
    }
    fn save(&mut self, slot: u64) {
        store(&mut self.code, self.wide, slot);
    }
    fn pointer_check(&mut self, slot: u64, value: u64) {
        if self.wide {
            self.code.push(0x48);
        }
        load(&mut self.code, self.wide, slot);
        if self.wide {
            self.code.extend([0x48, 0xba]);
            self.code.extend(value.to_le_bytes());
            self.code.extend([0x48, 0x39, 0xd0, 0x74, 1, 0xcc]);
        } else {
            self.expect(value as u32);
        }
    }
}
pub fn kernel_spin_probe(arch: Architecture, kind: SpinFixture) -> Vec<u8> {
    let wide = arch == Architecture::X64;
    let width = arch.width();
    let base = if wide { 0x140000000u64 } else { 0x400000 };
    let original = api_probe(arch, ApiFixture::PoolLifecycle);
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
        (dd + 12, 60),
        (0x1200, 0x2180),
        (0x120c, 0x2040),
        (0x1210, 0x2080),
        (0x1214, 0x2180 + 20 * width as u32),
        (0x1220, 0x2060),
        (0x1224, 0x2080 + 20 * width as u32),
    ] {
        put32(&mut data, at, value);
    }
    data[0x1240..0x124d].copy_from_slice(b"ntoskrnl.exe\0");
    data[0x1260..0x126d].copy_from_slice(b"kernel32.dll\0");
    for (index, name) in names(wide).iter().enumerate() {
        if name.is_empty() {
            continue;
        }
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
    let a = base + 0x2c00;
    let b = a + 0x10;
    let saved = a + 0x40;
    let saved2 = a + 0x50;
    let marker = a + 0x60;
    let handle = a + 0x70;
    let mut p = Program {
        code: Vec::new(),
        wide,
        base,
        rva: 0x1000,
    };
    p.prologue();
    p.call(20, &[V(0x12345678)]);
    use SpinFixture::*;
    if kind.scheduler() {
        p.word(marker, 0);
        p.word(a, 0x77777777);
        p.word(a + width as u64, 0x66554433);
        if matches!(kind, Scheduler | HeldBudget) {
            p.call(0, &[V(a)]);
        }
        p.call(
            10,
            &[
                V(handle),
                V(0x1fffff),
                V(0),
                V(0),
                V(0),
                V(base + 0x1c00),
                V(marker),
            ],
        );
        p.expect(0);
        p.code.push(0xbb);
        p.code.extend(0x13572468u32.to_le_bytes());
        if matches!(kind, Scheduler | HeldBudget) {
            p.call(1, &[V(a)]);
            p.expect(0);
            p.check(a, 1);
        } else {
            p.irql(if matches!(kind, ApcQuantum) { 1 } else { 2 });
        }
        if kind.budget() {
            p.code.extend([0xeb, 0xfe]);
        } else {
            p.loop_cpu();
            p.check(
                marker,
                if matches!(kind, ApcQuantum) {
                    0x4348494c
                } else {
                    0
                },
            );
            p.call(5, &[]);
            p.expect(if matches!(kind, ApcQuantum) { 1 } else { 2 });
            if matches!(kind, Scheduler) {
                p.call(2, &[V(a), V(0)]);
                p.check(a, 0);
            } else {
                p.irql(0);
            }
            p.poll_child(marker);
            p.call(12, &[M(handle)]);
            p.expect(0);
            p.check(a + width as u64, 0x66554433);
        }
    } else if matches!(
        kind,
        Pool | ReusedPool | HeldFree | Paged | AliasFirst | AliasAfter | ReuseUninitialized
    ) {
        p.call(
            3,
            &[
                V(if matches!(kind, Paged) { 1 } else { 512 }),
                V(32),
                V(u32::from_le_bytes(*b"Spin").into()),
            ],
        );
        p.save(saved);
        let poolbase = if wide { 0xffffb00000000000 } else { 0xe0000000 };
        p.pointer_check(saved, poolbase);
        if matches!(kind, AliasFirst) {
            p.call(13, &[M(saved), V(32), V(0), V(0), V(0)]);
            p.save(saved2);
            p.call(14, &[M(saved2)]);
            p.call(15, &[M(saved2), V(1), V(1), V(0), V(0), V(0)]);
            p.call(0, &[M(saved)]);
        } else {
            p.call(0, &[M(saved)]);
            if matches!(kind, AliasAfter) {
                p.call(13, &[M(saved), V(32), V(0), V(0), V(0)]);
            } else if !matches!(kind, Paged) {
                p.call(1, &[M(saved)]);
                p.expect(0);
                p.call(5, &[]);
                p.expect(2);
                if matches!(kind, HeldFree) {
                    p.call(4, &[M(saved), V(u32::from_le_bytes(*b"Spin").into())]);
                } else {
                    p.call(2, &[M(saved), V(0)]);
                    p.call(4, &[M(saved), V(u32::from_le_bytes(*b"Spin").into())]);
                    if matches!(kind, ReusedPool | ReuseUninitialized) {
                        p.call(3, &[V(512), V(32), V(u32::from_le_bytes(*b"Spin").into())]);
                        p.save(saved);
                        p.pointer_check(saved, poolbase);
                        if matches!(kind, ReusedPool) {
                            p.call(0, &[M(saved)]);
                        }
                        p.call(1, &[M(saved)]);
                        if matches!(kind, ReusedPool) {
                            p.expect(0);
                            p.call(2, &[M(saved), V(0)]);
                            p.call(4, &[M(saved), V(u32::from_le_bytes(*b"Spin").into())]);
                        }
                    }
                }
            }
        }
    } else if matches!(
        kind,
        Readonly | Unaligned | InvalidRange | UnsupportedBacking | LiteralAlias
    ) {
        match kind {
            Readonly => p.call(0, &[V(base + 0x1000)]),
            Unaligned => p.call(0, &[V(a + 1)]),
            InvalidRange => p.call(0, &[V(base + 0x4000)]),
            LiteralAlias => p.call(16, &[V(a)]),
            UnsupportedBacking => {
                p.call(22, &[V(0), V(4096), V(0x3000), V(4)]);
                p.save(saved);
                p.call(0, &[M(saved)]);
            }
            _ => unreachable!(),
        }
    } else {
        p.word(a, 0x77777777);
        p.word(a + width as u64, 0x66554433);
        if matches!(kind, OldApc) {
            p.irql(1);
        }
        if matches!(kind, Critical | IpiRestored) {
            p.call(7, &[]);
        }
        p.call(0, &[V(a)]);
        p.check(a, 0);
        p.check(a + width as u64, 0x66554433);
        if matches!(kind, ReleaseUnowned) {
            p.call(2, &[V(a), V(0)]);
        } else if matches!(kind, ApiWrite) {
            p.call(18, &[V(a), V(width as u64)]);
        } else {
            if matches!(kind, HighIrql) {
                p.irql(3);
            }
            p.call(1, &[V(a)]);
            p.expect(u32::from(matches!(kind, OldApc)));
            p.check(a, 1);
            p.call(5, &[]);
            p.expect(2);
            match kind {
                Recursive => p.call(1, &[V(a)]),
                SavedIrql => p.call(2, &[V(a), V(1)]),
                LowerHeld => p.call(6, &[V(0)]),
                DirectLowerHeld => {
                    p.irql(0);
                    p.call(5, &[]);
                }
                DirectWrite => p.word(a, 0),
                IpiWhileHeld => p.call(17, &[V(base + 0x1c00), V(0xbeef)]),
                HeldExit => {}
                Nested | OutOfOrder => {
                    p.word(b, 0x55555555);
                    p.call(0, &[V(b)]);
                    p.call(1, &[V(b)]);
                    p.expect(2);
                    p.check(b, 1);
                    if matches!(kind, OutOfOrder) {
                        p.call(2, &[V(a), V(0)]);
                    } else {
                        p.call(2, &[V(b), V(2)]);
                        p.check(b, 0);
                        p.call(2, &[V(a), V(0)]);
                    }
                }
                _ => {
                    p.call(2, &[V(a), V(u64::from(matches!(kind, OldApc)))]);
                    p.check(a, 0);
                    p.call(5, &[]);
                    p.expect(u32::from(matches!(kind, OldApc)));
                    if matches!(kind, OldApc) {
                        p.call(6, &[V(0)]);
                    }
                    if matches!(kind, Critical | IpiRestored) {
                        if matches!(kind, IpiRestored) {
                            p.call(17, &[V(base + 0x1c00), V(0xbeef)]);
                            p.expect(0xbeef);
                            p.call(5, &[]);
                            p.expect(0);
                        }
                        p.call(9, &[]);
                        p.expect(1);
                        p.call(8, &[]);
                        p.call(9, &[]);
                        p.expect(0);
                    }
                }
            }
        }
    }
    p.call(21, &[]);
    p.expect(0x12345678);
    p.returned();
    assert!(p.code.len() <= 0xc00, "{arch:?} {kind:?}");
    data[0x200..0x200 + p.code.len()].copy_from_slice(&p.code);
    let mut child = Program {
        code: Vec::new(),
        wide,
        base,
        rva: 0x1c00,
    };
    if matches!(kind, IpiRestored | IpiWhileHeld) {
        child.code = if wide {
            vec![0x89, 0xc8, 0xc3]
        } else {
            vec![0x8b, 0x44, 0x24, 4, 0xc2, 4, 0]
        };
    } else {
        child.prologue();
        child.call(20, &[V(0x87654321)]);
        write_dword(&mut child.code, wide, marker, 0x4348494c);
        child.call(11, &[V(0)]);
        child.code.extend([0x0f, 0x0b]);
    }
    assert!(child.code.len() <= 0x400);
    data[0xe00..0xe00 + child.code.len()].copy_from_slice(&child.code);
    data
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn complete_architecture_specific_spin_fastcall_stdcall_iats_and_separate_child_programs() {
        for arch in [Architecture::X86, Architecture::X64] {
            for kind in [
                SpinFixture::Basic,
                SpinFixture::Nested,
                SpinFixture::OldApc,
                SpinFixture::Critical,
                SpinFixture::Pool,
                SpinFixture::ReusedPool,
                SpinFixture::Scheduler,
                SpinFixture::NativeQuantum,
                SpinFixture::ApcQuantum,
                SpinFixture::IpiRestored,
                SpinFixture::Recursive,
                SpinFixture::ReleaseUnowned,
                SpinFixture::SavedIrql,
                SpinFixture::OutOfOrder,
                SpinFixture::HeldExit,
                SpinFixture::HeldFree,
                SpinFixture::LowerHeld,
                SpinFixture::DirectLowerHeld,
                SpinFixture::DirectWrite,
                SpinFixture::ApiWrite,
                SpinFixture::Readonly,
                SpinFixture::Unaligned,
                SpinFixture::InvalidRange,
                SpinFixture::Paged,
                SpinFixture::UnsupportedBacking,
                SpinFixture::AliasFirst,
                SpinFixture::AliasAfter,
                SpinFixture::LiteralAlias,
                SpinFixture::HighIrql,
                SpinFixture::IpiWhileHeld,
                SpinFixture::ReuseUninitialized,
                SpinFixture::NativeBudget,
                SpinFixture::HeldBudget,
            ] {
                let bytes = kernel_spin_probe(arch, kind);
                let pe = crate::pe::PeImage::parse(&bytes, "spin.sys").unwrap();
                assert_eq!(pe.sample.kind, crate::pe::Kind::Driver);
                assert_eq!(pe.imports.len(), 22);
                for name in names(arch == Architecture::X64)
                    .iter()
                    .filter(|n| !n.is_empty())
                {
                    assert!(
                        pe.imports
                            .iter()
                            .any(|i| i.name == crate::pe::ImportName::Name((*name).into())),
                        "{arch:?} {kind:?} {name}"
                    );
                }
                assert_eq!(pe.sections[0].virtual_size, 0x1000);
                assert_eq!(pe.sections[1].rva, 0x2000);
            }
        }
    }
}
