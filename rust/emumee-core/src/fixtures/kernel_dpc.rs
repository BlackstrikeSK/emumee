//! Literal generated CPU0 DPC callbacks. No external sample or host payload.
use super::winhttp::{
    Arg,
    Arg::{Memory as M, Value as V},
    call, expect_dword, load, store, write_dword,
};
use super::{ApiFixture, api_probe, put32, put64};
use crate::pe::Architecture;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DpcFixture {
    Basic,
    Duplicate,
    Fifo,
    Remove,
    Elevated,
    CallbackQueue,
    Timer,
    TimerWait,
    TimerRead,
    TimerCancel,
    TimerReplacement,
    Periodic,
    VoidContext,
    RootFault,
    RootBudget,
    RunningRequeue,
    WrongReturn,
    IrqlReturn,
    CallbackFault,
    CallbackBudget,
    Protect,
    Free,
    Recommit,
    OpaqueRead,
    ThreadParked,
}
impl DpcFixture {
    pub const ALL: [Self; 25] = [
        Self::Basic,
        Self::Duplicate,
        Self::Fifo,
        Self::Remove,
        Self::Elevated,
        Self::CallbackQueue,
        Self::Timer,
        Self::TimerWait,
        Self::TimerRead,
        Self::TimerCancel,
        Self::TimerReplacement,
        Self::Periodic,
        Self::VoidContext,
        Self::RootFault,
        Self::RootBudget,
        Self::RunningRequeue,
        Self::WrongReturn,
        Self::IrqlReturn,
        Self::CallbackFault,
        Self::CallbackBudget,
        Self::Protect,
        Self::Free,
        Self::Recommit,
        Self::OpaqueRead,
        Self::ThreadParked,
    ];
    pub fn budget(self) -> bool {
        matches!(self, Self::RootBudget | Self::CallbackBudget)
    }
    pub fn error(self) -> Option<&'static str> {
        Some(match self {
            Self::RunningRequeue => "requeue of running DPC",
            Self::WrongReturn => "stack ABI",
            Self::IrqlReturn => "DPC",
            Self::CallbackFault | Self::RootFault => "INSN_INVALID",
            Self::Protect | Self::Free | Self::Recommit => "owned DPC environment",
            Self::OpaqueRead => "READ_PROT",
            _ => return None,
        })
    }
}
// One genuine NTOS import table plus one Kernel32 table; two explicit null slots.
const NAMES: [&str; 25] = [
    "KeInitializeDpc",
    "KeInsertQueueDpc",
    "KeRemoveQueueDpc",
    "KeGetCurrentIrql",
    "KeInitializeTimer",
    "KeSetTimer",
    "KeSetTimerEx",
    "KeCancelTimer",
    "KeWaitForSingleObject",
    "KeDelayExecutionThread",
    "KeInitializeEvent",
    "KeSetEvent",
    "PsCreateSystemThread",
    "PsTerminateSystemThread",
    "ZwClose",
    "PsGetCurrentThread",
    "PsGetCurrentThreadId",
    "RtlZeroMemory",
    "",
    "SetLastError",
    "GetLastError",
    "VirtualProtect",
    "VirtualFree",
    "VirtualAlloc",
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
            self.code[end - 4..end].copy_from_slice(
                &i32::try_from(0x2080i64 + index as i64 * 8 - self.rva as i64 - end as i64)
                    .unwrap()
                    .to_le_bytes(),
            );
        }
        if !self.wide {
            self.code.extend([0x39, 0xf4, 0x74, 1, 0xcc]);
        }
    }
    fn prologue(&mut self) {
        if self.wide {
            self.code.extend([0x48, 0x83, 0xec, 0x68]);
        } else {
            self.code.extend([0x56, 0x89, 0xe6]);
        }
    }
    fn end(&mut self, value: u32, callback: bool) {
        self.code.push(0xb8);
        self.code.extend(value.to_le_bytes());
        if self.wide {
            self.code.extend([0x48, 0x83, 0xc4, 0x68]);
        } else {
            self.code.push(0x5e);
        }
        if callback && !self.wide {
            self.code.extend([0xc2, 16, 0]);
        } else {
            self.code.push(0xc3);
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
            write_dword(&mut self.code, true, address + 4, (value >> 32) as u32);
        }
    }
    fn check(&mut self, address: u64, value: u64) {
        expect_dword(&mut self.code, self.wide, address, value as u32);
        if self.wide {
            expect_dword(&mut self.code, true, address + 4, (value >> 32) as u32);
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
    fn queue(&mut self, dpc: u64, a: u64, b: u64, expected: u32) {
        self.call(1, &[V(dpc), V(a), V(b)]);
        self.expect(expected);
    }
    fn set(&mut self, timer: u64, due: i64, period: Option<u32>, dpc: u64) {
        let mut args = vec![V(timer), V(due as u64)];
        if !self.wide {
            args[1] = V(due as u32 as u64);
            args.push(V((due as u64 >> 32) as u32 as u64));
        }
        if let Some(period) = period {
            args.push(V(period.into()));
        }
        args.push(V(dpc));
        self.call(if period.is_some() { 6 } else { 5 }, &args);
        self.expect(0);
    }
    fn delay(&mut self, timeout: u64, ticks: i64) {
        write_dword(&mut self.code, self.wide, timeout, ticks as u32);
        write_dword(
            &mut self.code,
            self.wide,
            timeout + 4,
            (ticks as u64 >> 32) as u32,
        );
        self.call(9, &[V(0), V(0), V(timeout)]);
        self.expect(0);
    }
    fn capture_argument(&mut self, index: usize, address: u64) {
        if self.wide {
            match index {
                0 => self.code.extend([0x48, 0x89, 0xc8]),
                1 => self.code.extend([0x48, 0x89, 0xd0]),
                2 => self.code.extend([0x4c, 0x89, 0xc0]),
                3 => self.code.extend([0x4c, 0x89, 0xc8]),
                _ => unreachable!(),
            }
        } else {
            self.code.extend([0x8b, 0x44, 0x24, 8 + index as u8 * 4]);
        }
        store(&mut self.code, self.wide, address);
    }
}
pub fn kernel_dpc_probe(arch: Architecture, kind: DpcFixture) -> Vec<u8> {
    kernel_dpc_probe_mode(arch, kind, false)
}
/// The exact CallbackBudget image with only its PE entry RVA redirected to
/// the callback's EB FE loop. This exercises the same loop PC with no queued
/// or active DPC, and is generated for measurement rather than guest behavior.
pub fn kernel_dpc_idle_budget_probe(arch: Architecture) -> Vec<u8> {
    kernel_dpc_probe_mode(arch, DpcFixture::CallbackBudget, true)
}
fn kernel_dpc_probe_mode(arch: Architecture, kind: DpcFixture, idle_entry: bool) -> Vec<u8> {
    assert!(!idle_entry || kind == DpcFixture::CallbackBudget);
    let wide = arch == Architecture::X64;
    let width = arch.width();
    let base = if wide { 0x140000000u64 } else { 0x400000 };
    let mut data = vec![0; 0x4200];
    let original = api_probe(arch, ApiFixture::PoolLifecycle);
    data[..0x200].copy_from_slice(&original[..0x200]);
    let table = 0x98 + if wide { 0xf0 } else { 0xe0 };
    let dd = 0x98 + if wide { 112 } else { 96 };
    for (at, value) in [
        (0x98 + 4, 0x1000),
        (0x98 + 8, 0x3000),
        (0x98 + 56, 0x5000),
        (table + 8, 0x1000),
        (table + 16, 0x1000),
        (table + 40 + 8, 0x3000),
        (table + 40 + 16, 0x3000),
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
                put64(&mut data, raw + index * width, rva.into())
            } else {
                put32(&mut data, raw + index * width, rva)
            }
        }
        let at = 0x1500 + index * 64;
        data[at + 2..at + 2 + name.len()].copy_from_slice(name.as_bytes());
    }
    let dpc = base + 0x2d00;
    let second = dpc + 0x80;
    let timer = base + 0x2e00;
    let timeout = timer + 0x80;
    let marker = base + 0x2f00;
    let captures = base + 0x3000;
    let tid = base + 0x3060;
    let thread = tid + 8;
    let handle = tid + 16;
    let poison = tid + 32;
    let event = base + 0x3100;
    let first_arg = if wide { 0xfedcba9876543210 } else { 0x76543210 };
    let second_arg = if wide { 0xabcdef0187654321 } else { 0x87654321 };
    let context = if wide { 0x8765432112345678 } else { 0x12345678 };
    let layout = crate::kernel_layout::KernelLayout::for_architecture(arch);
    let env = if wide { 0xffffc50000000000 } else { 0xc5000000 };
    let mut p = Program {
        code: Vec::new(),
        wide,
        base,
        rva: 0x1000,
    };
    p.prologue();
    p.call(19, &[V(0x12345678)]);
    p.word(marker, 0);
    p.word(poison, 0x66554433);
    p.call(15, &[]);
    store(&mut p.code, wide, thread);
    p.call(16, &[]);
    store(&mut p.code, wide, tid);
    p.call(0, &[V(dpc), V(base + 0x1900), V(context)]);
    p.call(0, &[V(second), V(base + 0x1c00), V(context)]);
    use DpcFixture::*;
    match kind {
        Protect => p.call(21, &[V(env + 4096), V(4096), V(2), V(poison)]),
        Free => p.call(22, &[V(env), V(0), V(0x8000)]),
        Recommit => p.call(23, &[V(env + 4096), V(4096), V(0x1000), V(4)]),
        Timer | TimerWait | TimerRead | TimerCancel | TimerReplacement | Periodic | OpaqueRead => {
            p.call(4, &[V(timer)]);
            let due = if matches!(kind, Timer | OpaqueRead) {
                0
            } else {
                -10_000
            };
            p.set(
                timer,
                due,
                if kind == Periodic { Some(1) } else { None },
                dpc,
            );
            if kind == TimerCancel {
                p.call(7, &[V(timer)]);
                p.expect(1);
                p.delay(timeout, -20_000);
                p.check(marker, 0);
            } else if kind == TimerReplacement {
                p.set(timer, -100_000, None, 0);
                p.code.truncate(p.code.len() - 8);
                p.expect(1);
                p.delay(timeout, -20_000);
                p.check(marker, 0);
                p.call(7, &[V(timer)]);
                p.expect(1);
            } else if kind == TimerWait {
                p.word(timeout, 0);
                p.call(8, &[V(timer), V(0), V(0), V(0), V(0)]);
                p.expect(0);
            } else if kind == TimerRead {
                p.delay(timeout, -20_000);
                load(&mut p.code, wide, timer + 4);
                p.expect(1);
            } else if kind == Periodic {
                p.delay(timeout, -10_010);
                p.call(7, &[V(timer)]);
                p.expect(1);
            } else if kind != OpaqueRead {
                p.check(marker, 1);
            }
        }
        RootFault | RootBudget => {
            p.call(4, &[V(timer)]);
            p.set(timer, -1, None, dpc); /* expiry is flushed when real root marker is observed */
        }
        Remove => {
            p.irql(2);
            p.queue(dpc, first_arg, second_arg, 1);
            p.call(2, &[V(dpc)]);
            p.expect(1);
            p.call(2, &[V(dpc)]);
            p.expect(0);
            p.irql(0);
            p.check(marker, 0);
        }
        Duplicate | Fifo | Elevated => {
            p.irql(2);
            p.queue(dpc, first_arg, second_arg, 1);
            if kind == Duplicate {
                p.queue(dpc, 9, 8, 0);
            }
            if kind == Fifo {
                p.queue(second, 7, 8, 1);
            }
            p.check(marker, 0);
            p.irql(0);
            p.check(marker, if kind == Fifo { 2 } else { 1 });
        }
        ThreadParked => {
            p.call(10, &[V(event), V(0), V(0)]);
            p.call(
                12,
                &[
                    V(handle),
                    V(0x1fffff),
                    V(0),
                    V(0),
                    V(0),
                    V(base + 0x1e00),
                    V(marker),
                ],
            );
            p.expect(0);
            // Let the created child reach its real event wait before queueing
            // the callback that signals it.
            p.delay(timeout, -10_000);
            p.queue(dpc, first_arg, second_arg, 1);
            // A kernel thread handle is not a KEVENT/KTHREAD pointer. Block
            // the root caller so the signaled child can finish genuinely.
            p.delay(timeout, -10_000);
            p.expect(0);
            p.check(marker, 3);
            p.call(14, &[M(handle)]);
            p.expect(0);
        }
        _ => {
            if kind == VoidContext {
                p.code.extend([
                    0xbf, 0x88, 0x77, 0x66, 0x55, 0xb8, 0x44, 0x33, 0x22, 0x11, 0x66, 0x0f, 0x6e,
                    0xc0,
                ]);
            }
            p.queue(dpc, first_arg, second_arg, 1);
            if kind == VoidContext {
                p.code.extend([
                    0x81, 0xff, 0x88, 0x77, 0x66, 0x55, 0x74, 1, 0xcc, 0x66, 0x0f, 0x7e, 0xc0,
                ]);
                p.expect(0x11223344);
            }
            if !matches!(
                kind,
                RunningRequeue | WrongReturn | IrqlReturn | CallbackFault | CallbackBudget
            ) {
                p.check(marker, if kind == CallbackQueue { 2 } else { 1 });
            }
        }
    }
    if matches!(kind, Basic | Duplicate | Elevated | VoidContext) {
        for (index, value) in [dpc, context, first_arg, second_arg]
            .into_iter()
            .enumerate()
        {
            p.check(captures + index as u64 * 8, value);
        }
        p.check(thread, layout.root_thread);
    }
    p.check(poison, 0x66554433);
    p.call(20, &[]);
    p.expect(0x12345678);
    p.end(17, false);
    assert!(p.code.len() <= 0x900, "{arch:?} {kind:?} root too large");
    data[0x200..0x200 + p.code.len()].copy_from_slice(&p.code);
    let mut callback = Program {
        code: Vec::new(),
        wide,
        base,
        rva: 0x1900,
    };
    callback.prologue();
    for index in 0..4 {
        callback.capture_argument(index, captures + index as u64 * 8);
    }
    callback.call(3, &[]);
    callback.expect(2);
    callback.call(15, &[]);
    store(&mut callback.code, wide, captures + 0x30);
    callback.call(16, &[]);
    store(&mut callback.code, wide, captures + 0x38);
    callback.check(captures + 0x30, layout.root_thread);
    callback.check(captures + 0x38, 0x1004);
    callback.call(20, &[]);
    callback.expect(0x12345678);
    callback.call(19, &[V(0x87654321)]);
    // The caller later proves LastError restored; exact native caller RAX must
    // retain InsertQueueDpc TRUE rather than the callback's arbitrary VOID EAX.
    callback.word(marker, 1);
    match kind {
        CallbackQueue => callback.queue(second, 7, 8, 1),
        RunningRequeue => callback.queue(dpc, 9, 8, 1),
        CallbackFault | RootFault => callback.code.extend([0x0f, 0x0b]),
        CallbackBudget | RootBudget => {
            if idle_entry {
                let loop_rva = u32::try_from(callback.rva + callback.code.len() as u64).unwrap();
                put32(&mut data, 0x98 + 16, loop_rva);
            }
            callback.code.extend([0xeb, 0xfe]);
        }
        OpaqueRead => {
            if wide {
                callback.code.push(0x48);
            }
            callback.code.push(0xa1);
            callback
                .code
                .extend_from_slice(&(captures + 16).to_le_bytes()[..width]);
            callback.code.extend([0x8b, 0x00]);
        }
        ThreadParked => {
            callback.call(11, &[V(event), V(0), V(0)]);
            callback.expect(0);
            callback.check(marker, 1);
        }
        VoidContext => {
            callback.code.extend([
                0xbf, 0x44, 0x33, 0x22, 0x11, 0xb8, 0x99, 0x99, 0x99, 0x99, 0x66, 0x0f, 0x6e, 0xc0,
            ]);
        }
        IrqlReturn => callback.irql(1),
        _ => {}
    }
    callback.end(0xdeadbeef, true);
    if kind == WrongReturn {
        if wide {
            callback.code.pop();
            callback.code.extend([0xc2, 8, 0]);
        } else {
            let n = callback.code.len();
            callback.code[n - 2..].copy_from_slice(&[12, 0]);
        }
    }
    assert!(callback.code.len() <= 0x300);
    data[0xb00..0xb00 + callback.code.len()].copy_from_slice(&callback.code);
    let mut second_code = Program {
        code: Vec::new(),
        wide,
        base,
        rva: 0x1c00,
    };
    second_code.prologue();
    second_code.check(marker, 1);
    second_code.word(marker, 2);
    second_code.call(3, &[]);
    second_code.expect(2);
    second_code.end(0xeeeeeeee, true);
    assert!(second_code.code.len() <= 0x200);
    data[0xe00..0xe00 + second_code.code.len()].copy_from_slice(&second_code.code);
    let mut child = Program {
        code: Vec::new(),
        wide,
        base,
        rva: 0x1e00,
    };
    child.prologue();
    child.call(8, &[V(event), V(0), V(0), V(0), V(0)]);
    child.expect(0);
    child.check(marker, 1);
    child.word(marker, 3);
    child.call(13, &[V(0)]);
    child.code.extend([0x0f, 0x0b]);
    assert!(child.code.len() <= 0x200);
    data[0x1000..0x1000 + child.code.len()].copy_from_slice(&child.code);
    data
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_literal_dpc_driver_has_all_exact_imports_and_separate_routines() {
        for arch in [Architecture::X86, Architecture::X64] {
            for kind in DpcFixture::ALL {
                let bytes = kernel_dpc_probe(arch, kind);
                let pe = crate::pe::PeImage::parse(&bytes, "dpc.sys").unwrap();
                assert_eq!(pe.sample.kind, crate::pe::Kind::Driver);
                assert_eq!(pe.imports.len(), 23);
                for name in NAMES.iter().filter(|n| !n.is_empty()) {
                    assert!(
                        pe.imports
                            .iter()
                            .any(|i| i.name == crate::pe::ImportName::Name((*name).into())),
                        "{arch:?} {kind:?} {name}"
                    );
                }
                assert_ne!(&bytes[0xb00..0xb10], &bytes[0xe00..0xe10]);
            }
        }
    }
}
