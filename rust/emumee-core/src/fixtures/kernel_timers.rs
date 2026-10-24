//! Literal harmless timer/dispatcher/clock callers; no real driver input.
use super::winhttp::{
    Arg,
    Arg::{Memory as M, Value as V},
    call, expect_dword, load, store, write_dword,
};
use super::{ApiFixture, api_probe, put32, put64};
use crate::pe::Architecture;
#[derive(Clone, Copy, Debug)]
pub enum TimerFixture {
    Initialize,
    Relative,
    Synchronization,
    AbsolutePast,
    AbsoluteFuture,
    LargeDue,
    Replacement,
    Periodic,
    Polling,
    MixedAny,
    MixedAll,
    Child,
    DpcCancel,
    PoolLifetime,
    DueDpc,
    PendingDpc,
    DpcRead,
    DpcWait,
    Reinitialize,
    NegativePeriod,
    UnknownDpc,
    Readonly,
    Paged,
    DirectWrite,
    ApiWrite,
    InsertedFree,
    AliasAfter,
    HighIrql,
    DpcRoutine,
    BudgetPending,
}
impl TimerFixture {
    pub fn budget(self) -> bool {
        matches!(self, Self::BudgetPending)
    }
    pub fn error(self) -> Option<&'static str> {
        Some(match self {
            Self::DueDpc | Self::DpcRead | Self::DpcWait => "EXCEPTION",
            Self::PendingDpc => "Inserted timer DPC requires callback scheduling",
            Self::Reinitialize => "reinitializing inserted/waited timer",
            Self::NegativePeriod => "negative timer period",
            Self::UnknownDpc => "uninitialized timer DPC",
            Self::Readonly => "API guest range",
            Self::Paged => "cannot be paged Pool",
            Self::DirectWrite => "Direct guest mutation of initialized timer/DPC metadata",
            Self::ApiWrite => "API mutation of initialized timer/DPC metadata",
            Self::InsertedFree => "memory release overlaps inserted/waited timer",
            Self::AliasAfter => "MDL alias/descriptor overlaps initialized timer/DPC metadata",
            Self::HighIrql => "at or below DISPATCH_LEVEL",
            Self::DpcRoutine => "actual executable guest image provenance",
            _ => return None,
        })
    }
    pub fn dpc(self) -> bool {
        matches!(
            self,
            Self::Initialize
                | Self::DpcCancel
                | Self::DueDpc
                | Self::PendingDpc
                | Self::DpcRead
                | Self::DpcWait
                | Self::DpcRoutine
                | Self::BudgetPending
        )
    }
}
const NAMES: [&str; 22] = [
    "KeInitializeTimer",
    "KeInitializeTimerEx",
    "KeInitializeDpc",
    "KeSetTimer",
    "KeSetTimerEx",
    "KeCancelTimer",
    "KeWaitForSingleObject",
    "KeWaitForMultipleObjects",
    "KeDelayExecutionThread",
    "KeInitializeEvent",
    "PsCreateSystemThread",
    "PsTerminateSystemThread",
    "ZwClose",
    "ExAllocatePoolWithTag",
    "ExFreePoolWithTag",
    "RtlZeroMemory",
    "IoAllocateMdl",
    "KeGetCurrentIrql",
    "",
    "SetLastError",
    "GetLastError",
    "",
];
struct Program {
    code: Vec<u8>,
    wide: bool,
    base: u64,
    rva: u64,
}
impl Program {
    fn call(&mut self, index: usize, args: &[Arg]) {
        call(&mut self.code, self.wide, self.base, index, args);
        if self.wide && self.rva != 0x1000 {
            let end = self.code.len();
            let disp = 0x2080i64 + index as i64 * 8 - self.rva as i64 - end as i64;
            self.code[end - 4..end].copy_from_slice(&i32::try_from(disp).unwrap().to_le_bytes());
        }
        if !self.wide {
            self.code.extend([0x39, 0xf4, 0x74, 1, 0xcc]);
        }
    }
    fn set(&mut self, timer: Arg, due: i64, period: Option<i32>, dpc: u64) {
        let mut args = vec![timer, V(due as u64)];
        if !self.wide {
            args[1] = V(due as u32 as u64);
            args.push(V((due as u64 >> 32) as u32 as u64));
        }
        if let Some(period) = period {
            args.push(V(period as u32 as u64));
        }
        args.push(V(dpc));
        self.call(if period.is_some() { 4 } else { 3 }, &args);
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
    fn check32(&mut self, address: u64, value: u32) {
        expect_dword(&mut self.code, self.wide, address, value);
    }
    fn pointer_check(&mut self, address: u64, value: u64) {
        self.check(address, value);
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
    fn delay(&mut self, timeout: u64, ticks: i64) {
        // LARGE_INTEGER is eight bytes on both ABIs, independent of pointers.
        write_dword(&mut self.code, self.wide, timeout, ticks as u32);
        write_dword(
            &mut self.code,
            self.wide,
            timeout + 4,
            ((ticks as u64) >> 32) as u32,
        );
        self.call(8, &[V(0), V(0), V(timeout)]);
        self.expect(0);
    }
    fn wait(&mut self, timer: Arg, timeout: u64, expected: u32) {
        self.call(6, &[timer, V(0), V(0), V(0), V(timeout)]);
        self.expect(expected);
    }
    fn poll_signal(&mut self, timer: u64) {
        self.code.extend([0xb9, 0x10, 0x27, 0, 0]);
        let start = self.code.len();
        load(&mut self.code, self.wide, timer + 4);
        self.code.extend([0x83, 0xf8, 1, 0x74, 5, 0xff, 0xc9, 0x75]);
        let back = start as i64 - self.code.len() as i64 - 1;
        self.code.push(i8::try_from(back).unwrap() as u8);
        self.code.push(0xcc);
    }
    fn irql(&mut self, value: u8) {
        if self.wide {
            self.code
                .extend([0xb8, value, 0, 0, 0, 0x44, 0x0f, 0x22, 0xc0]);
        } else {
            self.code.extend([0x64, 0xc6, 5, 0x24, 0, 0, 0, value]);
        }
    }
}
pub fn kernel_timer_probe(arch: Architecture, kind: TimerFixture) -> Vec<u8> {
    let wide = arch == Architecture::X64;
    let width = arch.width();
    let base = if wide { 0x140000000u64 } else { 0x400000 };
    let mut data = vec![0; 0x3200];
    let original = api_probe(arch, ApiFixture::PoolLifecycle);
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
        (0x1214, 0x2180 + 19 * width as u32),
        (0x1220, 0x2060),
        (0x1224, 0x2080 + 19 * width as u32),
    ] {
        put32(&mut data, at, value);
    }
    data[0x1240..0x124d].copy_from_slice(b"ntoskrnl.exe\0");
    data[0x1260..0x126d].copy_from_slice(b"kernel32.dll\0");
    for (index, name) in NAMES.iter().enumerate() {
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
    let timer = base + 0x2b00;
    let second = base + 0x2b80;
    let dpc = base + 0x2c00;
    let event = base + 0x2c80;
    let marker = base + 0x2d00;
    let timeout = base + 0x2d10;
    let array = base + 0x2d20;
    let handle = base + 0x2d40;
    let saved = base + 0x2d50;
    let size = if wide { 64 } else { 40 };
    let mut p = Program {
        code: Vec::new(),
        wide,
        base,
        rva: 0x1000,
    };
    p.prologue();
    p.call(19, &[V(0x12345678)]);
    p.word(marker, 0);
    p.word(timeout, 0);
    p.word(timer + size, 0x66554433);
    use TimerFixture::*;
    if matches!(kind, Readonly) {
        p.call(0, &[V(base + 0x1000)]);
    } else if matches!(kind, Paged | PoolLifetime | InsertedFree) {
        p.call(
            13,
            &[
                V(if matches!(kind, Paged) { 1 } else { 512 }),
                V(128),
                V(u32::from_le_bytes(*b"Time").into()),
            ],
        );
        store(&mut p.code, wide, saved);
        p.pointer_check(saved, if wide { 0xffffb00000000000 } else { 0xe0000000 });
        p.call(0, &[M(saved)]);
        if !matches!(kind, Paged) {
            p.set(M(saved), -1_000_000, None, 0);
            p.expect(0);
            if matches!(kind, PoolLifetime) {
                p.call(5, &[M(saved)]);
                p.expect(1);
            }
            p.call(14, &[M(saved), V(u32::from_le_bytes(*b"Time").into())]);
            if matches!(kind, PoolLifetime) {
                p.call(
                    13,
                    &[V(512), V(128), V(u32::from_le_bytes(*b"Time").into())],
                );
                store(&mut p.code, wide, saved);
                p.pointer_check(saved, if wide { 0xffffb00000000000 } else { 0xe0000000 });
                p.call(0, &[M(saved)]);
                p.call(14, &[M(saved), V(u32::from_le_bytes(*b"Time").into())]);
            }
        }
    } else if matches!(kind, DpcRoutine) {
        p.call(2, &[V(dpc), V(marker), V(marker)]);
    } else {
        let synchronization = matches!(kind, Synchronization | Periodic | MixedAll);
        let init_args = if synchronization {
            vec![V(timer), V(1)]
        } else {
            vec![V(timer)]
        };
        p.call(if synchronization { 1 } else { 0 }, &init_args);
        let header = if wide { 0x00100008 } else { 0x000a0008 };
        p.check32(timer, header + u32::from(synchronization));
        p.check32(timer + 4, 0);
        p.pointer_check(timer + 8, timer + 8);
        p.pointer_check(timer + 8 + width as u64, timer + 8);
        p.check(timer + size, 0x66554433);
        if kind.dpc() {
            p.call(2, &[V(dpc), V(base + 0x1c00), V(marker)]);
            p.check32(dpc, 0x113);
            p.pointer_check(dpc + if wide { 24 } else { 12 }, base + 0x1c00);
            p.pointer_check(dpc + if wide { 32 } else { 16 }, marker);
        }
        match kind {
            Initialize => {
                p.call(1, &[V(second), V(1)]);
                p.check32(second, if wide { 0x00100009 } else { 0x000a0009 });
                p.call(5, &[V(timer)]);
                p.expect(0);
            }
            Relative | Synchronization | AbsolutePast | AbsoluteFuture => {
                let due = match kind {
                    AbsolutePast => 0,
                    AbsoluteFuture => 133000000000100000,
                    _ => -10_000,
                };
                p.set(V(timer), due, None, 0);
                p.expect(0);
                p.wait(V(timer), 0, 0);
                p.check32(timer + 4, u32::from(!matches!(kind, Synchronization)));
                p.wait(
                    V(timer),
                    timeout,
                    if matches!(kind, Synchronization) {
                        0x102
                    } else {
                        0
                    },
                );
                p.call(5, &[V(timer)]);
                p.expect(0);
            }
            LargeDue => {
                p.set(V(timer), -0x100000001, None, 0);
                p.expect(0);
                p.call(5, &[V(timer)]);
                p.expect(1);
            }
            Replacement => {
                p.set(V(timer), -1_000_000, None, 0);
                p.expect(0);
                p.set(V(timer), -2_000_000, None, 0);
                p.expect(1);
                p.call(5, &[V(timer)]);
                p.expect(1);
                p.call(5, &[V(timer)]);
                p.expect(0);
            }
            Periodic => {
                p.set(V(timer), -10_000, Some(1), 0);
                p.expect(0);
                p.wait(V(timer), 0, 0);
                p.check32(timer + 4, 0);
                p.delay(timeout, -35_000);
                p.check32(timer + 4, 1);
                p.call(5, &[V(timer)]);
                p.expect(1);
                p.check32(timer + 4, 1);
            }
            Polling => {
                p.set(V(timer), -200, None, 0);
                p.expect(0);
                p.poll_signal(timer);
                p.call(5, &[V(timer)]);
                p.expect(0);
            }
            MixedAny => {
                p.call(0, &[V(second)]);
                p.word(array, timer);
                p.word(array + width as u64, second);
                p.set(V(timer), -20_000, None, 0);
                p.expect(0);
                p.set(V(second), -10_000, None, 0);
                p.expect(0);
                p.call(7, &[V(2), V(array), V(1), V(0), V(0), V(0), V(0), V(0)]);
                p.expect(1);
                p.wait(V(timer), 0, 0);
            }
            MixedAll => {
                p.call(9, &[V(event), V(1), V(1)]);
                p.word(array, timer);
                p.word(array + width as u64, event);
                p.set(V(timer), -10_000, None, 0);
                p.expect(0);
                p.call(7, &[V(2), V(array), V(0), V(0), V(0), V(0), V(0), V(0)]);
                p.expect(0);
                p.check32(timer + 4, 0);
                p.check32(event + 4, 0);
                p.wait(V(event), timeout, 0x102);
            }
            Child => {
                p.set(V(timer), -20_000, None, 0);
                p.expect(0);
                p.call(
                    10,
                    &[
                        V(handle),
                        V(0x1fffff),
                        V(0),
                        V(0),
                        V(0),
                        V(base + 0x1c00),
                        V(0),
                    ],
                );
                p.expect(0);
                p.delay(timeout, -30_000);
                p.check32(marker, 0x4348494c);
                p.call(12, &[M(handle)]);
                p.expect(0);
            }
            DpcCancel => {
                p.set(V(timer), -10_000_000, None, dpc);
                p.expect(0);
                p.call(5, &[V(timer)]);
                p.expect(1);
                p.check32(marker, 0);
            }
            DueDpc => {
                p.set(V(timer), 0, None, dpc);
                p.expect(0);
            }
            PendingDpc | BudgetPending => {
                p.set(V(timer), -10_000_000, None, dpc);
                p.expect(0);
                if matches!(kind, BudgetPending) {
                    p.code.extend([0xeb, 0xfe]);
                }
            }
            DpcRead => {
                p.set(V(timer), -200, None, dpc);
                p.expect(0);
                p.poll_signal(timer);
            }
            DpcWait => {
                p.set(V(timer), -10_000, None, dpc);
                p.expect(0);
                p.wait(V(timer), 0, 0);
            }
            Reinitialize => {
                p.set(V(timer), -1_000_000, None, 0);
                p.expect(0);
                p.call(0, &[V(timer)]);
            }
            NegativePeriod => {
                p.set(V(timer), -10_000, Some(-1), 0);
                p.expect(0);
            }
            UnknownDpc => {
                p.set(V(timer), -10_000, None, dpc);
                p.expect(0);
            }
            DirectWrite => write_dword(&mut p.code, wide, timer + 4, 1),
            ApiWrite => p.call(15, &[V(timer), V(size)]),
            AliasAfter => p.call(16, &[V(timer), V(size), V(0), V(0), V(0)]),
            HighIrql => {
                p.irql(3);
                p.set(V(timer), -10_000, None, 0);
                p.expect(0);
            }
            _ => unreachable!(),
        }
        if !matches!(kind, Child) {
            p.check32(marker, 0);
        }
        p.check(timer + size, 0x66554433);
    }
    p.call(20, &[]);
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
    if matches!(kind, Child) {
        child.prologue();
        child.call(19, &[V(0x87654321)]);
        child.wait(V(timer), 0, 0);
        write_dword(&mut child.code, wide, marker, 0x4348494c);
        child.call(11, &[V(0)]);
        child.code.extend([0x0f, 0x0b]);
    } else {
        write_dword(&mut child.code, wide, marker, 0xdeadc0de);
        if wide {
            child.code.push(0xc3);
        } else {
            child.code.extend([0xc2, 16, 0]);
        }
    }
    assert!(child.code.len() <= 0x400);
    data[0xe00..0xe00 + child.code.len()].copy_from_slice(&child.code);
    data
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn literal_timer_dpc_large_due_two_dll_iats_are_complete_and_driver_scoped() {
        for arch in [Architecture::X86, Architecture::X64] {
            for kind in [
                TimerFixture::Initialize,
                TimerFixture::LargeDue,
                TimerFixture::MixedAll,
                TimerFixture::Child,
                TimerFixture::BudgetPending,
                TimerFixture::PoolLifetime,
                TimerFixture::DpcWait,
            ] {
                let bytes = kernel_timer_probe(arch, kind);
                let pe = crate::pe::PeImage::parse(&bytes, "timers.sys").unwrap();
                assert_eq!(pe.sample.kind, crate::pe::Kind::Driver);
                assert_eq!(pe.imports.len(), 20);
                for name in NAMES.iter().filter(|n| !n.is_empty()) {
                    assert!(
                        pe.imports
                            .iter()
                            .any(|i| i.name == crate::pe::ImportName::Name((*name).into())),
                        "{arch:?} {kind:?} {name}"
                    );
                }
            }
        }
    }
}
