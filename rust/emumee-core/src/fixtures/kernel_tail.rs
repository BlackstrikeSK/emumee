//! Generated x64 kernel tail diagnostics. These are harmless source fixtures:
//! they contain no submitted bytes and cannot authorize a real driver run.
use super::{
    ApiFixture, api_probe, put16, put32, put64,
    winhttp::{
        Arg::{Memory as M, Value as V},
        call, expect_dword, load, write_dword,
    },
};
use crate::pe::Architecture;

#[derive(Clone, Copy, Debug)]
pub enum TailDiagnostic {
    SchedulerZeroOwner,
    FileEventMutex,
    WaitManyMutexHandoff,
    GuestOwnerZeroed,
    GuestWriteBurst,
}

const BASE: u64 = 0x140000000;
const MUTEX: u64 = BASE + 0x2b00;
const EVENT0: u64 = BASE + 0x2c00;
const EVENT1: u64 = BASE + 0x2c40;
const WAIT_OBJECTS: u64 = BASE + 0x2d00;
const WAITER_HANDLE: u64 = BASE + 0x2d40;
const LOGGER_HANDLE: u64 = BASE + 0x2d48;
const WAITER_STARTED: u64 = BASE + 0x2d80;
const WAITER_GO: u64 = BASE + 0x2d88;
const WAITER_ACQUIRED: u64 = BASE + 0x2d90;
const LOGGER_STARTED: u64 = BASE + 0x2da0;
const LOGGER_WOKE: u64 = BASE + 0x2db0;
const FILE_HANDLE: u64 = BASE + 0x2e00;
const IOSB: u64 = BASE + 0x2e20;
const POOL_POINTER: u64 = BASE + 0x2e60;
const OBJECT_ATTRIBUTES: u64 = BASE + 0x2e80;
const UNICODE_STRING: u64 = BASE + 0x2ec0;
const FILE_PATH: u64 = BASE + 0x2f00;
const FILE_BYTES: u64 = BASE + 0x3000;

struct Program(Vec<u8>);
impl Program {
    fn new() -> Self {
        // A normal x64 entry stack with 0x88 bytes for fifteen API arguments.
        Self(vec![0x48, 0x81, 0xec, 0x88, 0, 0, 0])
    }
    fn call(&mut self, index: usize, args: &[super::winhttp::Arg]) {
        call(&mut self.0, true, BASE, index, args);
    }
    fn status(&mut self, status: u32) {
        self.0.push(0x3d);
        self.0.extend(status.to_le_bytes());
        self.0.extend([0x74, 1, 0xcc]);
    }
    fn set(&mut self, address: u64, value: u32) {
        write_dword(&mut self.0, true, address, value);
    }
    fn word(&mut self, address: u64, value: u32) {
        expect_dword(&mut self.0, true, address, value);
    }
    fn wait_flag(&mut self, address: u64) {
        let start = self.0.len();
        load(&mut self.0, true, address);
        self.0.extend([0x85, 0xc0, 0x74]);
        self.0
            .push((start as isize - (self.0.len() + 1) as isize) as i8 as u8);
    }
    fn root_return(&mut self) {
        self.0.extend([0x48, 0x81, 0xc4, 0x88, 0, 0, 0]);
        self.0.extend([0xb8, 1, 0, 0, 0, 0xc3]);
    }
    fn at(&mut self, offset: usize) {
        assert!(self.0.len() <= offset && offset < 0x1000);
        self.0.resize(offset, 0xcc);
        self.0.extend([0x48, 0x81, 0xec, 0x88, 0, 0, 0]);
    }
    fn terminate(&mut self) {
        self.call(4, &[V(0)]);
        self.0.push(0xcc);
    }
    fn create(&mut self, handle: u64, routine_rva: u64) {
        self.call(
            3,
            &[
                V(handle),
                V(0x1fffff),
                V(0),
                V(0),
                V(0),
                V(BASE + routine_rva),
                V(0),
            ],
        );
        self.status(0);
    }
}

fn raw(rva: u64) -> usize {
    (rva - BASE - 0xe00) as usize
}

pub fn kernel_tail_probe(kind: TailDiagnostic) -> Vec<u8> {
    let original = api_probe(Architecture::X64, ApiFixture::PoolLifecycle);
    let mut data = vec![0u8; 0x5200];
    data[..0x200].copy_from_slice(&original[..0x200]);
    let section = 0x98 + 0xf0;
    let dd = 0x98 + 112;
    for (at, value) in [
        (0x98 + 4, 0x1000),
        (0x98 + 8, 0x4000),
        (0x98 + 56, 0x6000),
        (section + 8, 0x1000),
        (section + 16, 0x1000),
        (section + 40 + 8, 0x4000),
        (section + 40 + 16, 0x4000),
        (section + 40 + 20, 0x1200),
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
        "KeInitializeGuardedMutex",
        "KeAcquireGuardedMutex",
        "KeReleaseGuardedMutex",
        "PsCreateSystemThread",
        "PsTerminateSystemThread",
        "KeInitializeEvent",
        "KeWaitForMultipleObjects",
        "KeSetEvent",
        "IoCreateFileEx",
        "ZwWriteFile",
        "ZwFlushBuffersFile",
        "ZwClose",
        "ExAllocatePoolWithTag",
        "ExFreePoolWithTag",
        "KeGetCurrentIrql",
    ];
    for (index, name) in names.iter().enumerate() {
        let rva = 0x2300 + index as u32 * 64;
        for table in [0x1280, 0x1380] {
            put64(&mut data, table + index * 8, rva.into());
        }
        let at = 0x1500 + index * 64;
        data[at + 2..at + 2 + name.len()].copy_from_slice(name.as_bytes());
    }
    put64(&mut data, raw(WAIT_OBJECTS), EVENT0);
    put64(&mut data, raw(WAIT_OBJECTS + 8), EVENT1);
    let path = r"C:\Users\Morgan\Downloads\nt-file.bin"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    put16(&mut data, raw(UNICODE_STRING), path.len() as u16);
    put16(&mut data, raw(UNICODE_STRING) + 2, 32766);
    put64(&mut data, raw(UNICODE_STRING) + 8, FILE_PATH);
    data[raw(FILE_PATH)..raw(FILE_PATH) + path.len()].copy_from_slice(&path);
    put32(&mut data, raw(OBJECT_ATTRIBUTES), 48);
    put64(&mut data, raw(OBJECT_ATTRIBUTES) + 16, UNICODE_STRING);
    put32(&mut data, raw(OBJECT_ATTRIBUTES) + 24, 0x240);
    data[raw(FILE_BYTES)..raw(FILE_BYTES) + 4].copy_from_slice(b"TAIL");

    let mut p = Program::new();
    match kind {
        TailDiagnostic::SchedulerZeroOwner => {
            p.create(WAITER_HANDLE, 0x1500);
            p.call(1, &[V(MUTEX)]);
            p.0.push(0xcc); // Refusal must precede this instruction.
            p.at(0x500);
            p.terminate();
        }
        TailDiagnostic::FileEventMutex => {
            p.call(12, &[V(0x600), V(4), V(0x4c494154)]);
            p.0.extend([0x48, 0x85, 0xc0, 0x75, 1, 0xcc]);
            p.0.extend([0x48, 0xa3]);
            p.0.extend(POOL_POINTER.to_le_bytes());
            p.0.extend([0xc7, 0x00, b'T', b'A', b'I', b'L']);
            p.call(
                8,
                &[
                    V(FILE_HANDLE),
                    V(0xc0010000),
                    V(OBJECT_ATTRIBUTES),
                    V(IOSB),
                    V(0),
                    V(0x80),
                    V(7),
                    V(3),
                    V(0x60),
                    V(0),
                    V(0),
                    V(0),
                    V(0),
                    V(0),
                    V(0),
                ],
            );
            p.status(0);
            p.call(
                9,
                &[
                    M(FILE_HANDLE),
                    V(0),
                    V(0),
                    V(0),
                    V(IOSB),
                    M(POOL_POINTER),
                    V(4),
                    V(0),
                    V(0),
                ],
            );
            p.status(0);
            p.call(10, &[M(FILE_HANDLE), V(IOSB)]);
            p.status(0);
            p.call(11, &[M(FILE_HANDLE)]);
            p.status(0);
            p.call(13, &[M(POOL_POINTER), V(0x4c494154)]);
            p.call(5, &[V(EVENT0), V(1), V(0)]);
            p.call(7, &[V(EVENT0), V(0), V(0)]);
            p.call(0, &[V(MUTEX)]);
            p.call(1, &[V(MUTEX)]);
            p.call(2, &[V(MUTEX)]);
            p.word(MUTEX, 1);
            p.root_return();
        }
        TailDiagnostic::WaitManyMutexHandoff => {
            p.call(0, &[V(MUTEX)]);
            p.call(5, &[V(EVENT0), V(1), V(0)]);
            p.call(5, &[V(EVENT1), V(1), V(0)]);
            p.create(WAITER_HANDLE, 0x1500);
            p.create(LOGGER_HANDLE, 0x1800);
            p.call(1, &[V(MUTEX)]);
            p.set(WAITER_GO, 1);
            p.wait_flag(WAITER_STARTED);
            p.wait_flag(LOGGER_STARTED);
            p.call(7, &[V(EVENT0), V(0), V(0)]);
            p.call(2, &[V(MUTEX)]);
            p.wait_flag(WAITER_ACQUIRED);
            p.wait_flag(LOGGER_WOKE);
            p.root_return();
            p.at(0x500);
            p.set(WAITER_STARTED, 1);
            p.wait_flag(WAITER_GO);
            p.call(1, &[V(MUTEX)]);
            p.set(WAITER_ACQUIRED, 1);
            p.call(2, &[V(MUTEX)]);
            p.terminate();
            p.at(0x800);
            p.set(LOGGER_STARTED, 1);
            p.call(
                6,
                &[V(2), V(WAIT_OBJECTS), V(1), V(0), V(0), V(0), V(0), V(0)],
            );
            p.status(0);
            p.set(LOGGER_WOKE, 1);
            p.terminate();
        }
        TailDiagnostic::GuestOwnerZeroed => {
            p.call(0, &[V(MUTEX)]);
            p.create(WAITER_HANDLE, 0x1500);
            p.call(1, &[V(MUTEX)]);
            p.set(MUTEX, 0);
            p.set(MUTEX + 8, 0);
            p.set(MUTEX + 12, 0);
            p.call(1, &[V(MUTEX)]);
            p.0.push(0xcc); // Guest corruption must not gain the lock.
            p.at(0x500);
            p.terminate();
        }
        TailDiagnostic::GuestWriteBurst => {
            p.call(0, &[V(MUTEX)]);
            p.0.extend([0xb9, 0x2c, 0x01, 0, 0]); // mov ecx, 300
            let loop_start = p.0.len();
            p.set(MUTEX + 12, 0);
            p.0.extend([0xff, 0xc9, 0x75]); // dec ecx; jnz loop_start
            p.0.push((loop_start as isize - (p.0.len() + 1) as isize) as i8 as u8);
            p.root_return();
        }
    }
    assert!(p.0.len() <= 0x1000);
    data[0x200..0x1200].fill(0xcc);
    data[0x200..0x200 + p.0.len()].copy_from_slice(&p.0);
    data
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn generated_tail_programs_are_x64_drivers_with_bounded_imports() {
        for kind in [
            TailDiagnostic::SchedulerZeroOwner,
            TailDiagnostic::FileEventMutex,
            TailDiagnostic::WaitManyMutexHandoff,
            TailDiagnostic::GuestOwnerZeroed,
            TailDiagnostic::GuestWriteBurst,
        ] {
            let bytes = kernel_tail_probe(kind);
            let image = crate::pe::PeImage::parse(&bytes, "generated-tail.sys").unwrap();
            assert_eq!(image.sample.kind, crate::pe::Kind::Driver);
            assert_eq!(image.sample.architecture, Architecture::X64);
            assert_eq!(image.entry_rva, 0x1000);
            assert_eq!(image.imports.len(), 15);
        }
    }
}
