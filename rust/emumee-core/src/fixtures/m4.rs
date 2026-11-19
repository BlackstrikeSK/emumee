//! Trusted synthetic callers requiring actual user-thread context transfers.
use super::winhttp::{
    Arg::{Memory as M, Value as V},
    call, load, store,
};
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum M4Fixture {
    Signal,
    Quantum,
    Deadlock,
    Timeout,
}

pub use super::winhttp::Arg as M4Arg;
/// Small deterministic emitter for guest controls, with a real RVA prefix so
/// the existing IAT call emitter computes the correct RIP-relative displacement.
pub struct M4Code {
    pub bytes: Vec<u8>,
    arch: Architecture,
    prefix: usize,
}
impl M4Code {
    pub fn new(arch: Architecture, rva: usize) -> Self {
        Self {
            bytes: vec![0; rva - 0x1000],
            arch,
            prefix: rva - 0x1000,
        }
    }
    pub fn base(&self) -> u64 {
        if self.arch == Architecture::X64 {
            0x140000000
        } else {
            0x400000
        }
    }
    pub fn call(&mut self, index: usize, args: &[M4Arg]) {
        let base = self.base();
        call(
            &mut self.bytes,
            self.arch == Architecture::X64,
            base,
            index,
            args,
        );
    }
    pub fn store(&mut self, address: u64) {
        store(&mut self.bytes, self.arch == Architecture::X64, address);
    }
    pub fn load(&mut self, address: u64) {
        load(&mut self.bytes, self.arch == Architecture::X64, address);
    }
    pub fn expect(&mut self, value: u32) {
        expect(&mut self.bytes, value);
    }
    pub fn prologue(&mut self) {
        if self.arch == Architecture::X64 {
            self.bytes.extend([0x48, 0x83, 0xec, 0x48]);
        }
    }
    pub fn epilogue(&mut self, result: u32, argc: u16) {
        self.bytes.push(0xb8);
        self.bytes.extend(result.to_le_bytes());
        if self.arch == Architecture::X64 {
            self.bytes.extend([0x48, 0x83, 0xc4, 0x48, 0xc3]);
        } else if argc != 0 {
            self.bytes.push(0xc2);
            self.bytes.extend((argc * 4).to_le_bytes());
        } else {
            self.bytes.push(0xc3);
        }
    }
    pub fn finish(self) -> Vec<u8> {
        self.bytes[self.prefix..].to_vec()
    }
}
pub fn m4_custom_probe(
    arch: Architecture,
    names: &[&str],
    root: &[u8],
    child: &[u8],
    callback: &[u8],
) -> Vec<u8> {
    assert!(
        names.len() <= 13 && root.len() < 0x800 && child.len() < 0x700 && callback.len() < 0x100
    );
    let mut bytes = m3_thread_probe(arch, M3ThreadFixture::Return);
    for index in 0..13 {
        let name = names.get(index).copied().unwrap_or("GetLastError");
        let raw = 0x2300 + index * 64 - 0xe00;
        bytes[raw..raw + 64].fill(0);
        bytes[raw + 2..raw + 2 + name.len()].copy_from_slice(name.as_bytes());
    }
    let dd = 0x98 + if arch == Architecture::X64 { 112 } else { 96 };
    bytes[dd + 9 * 8..dd + 10 * 8].fill(0);
    bytes[0x200..0x1200].fill(0);
    bytes[0x200..0x200 + root.len()].copy_from_slice(root);
    bytes[0xa00..0xa00 + child.len()].copy_from_slice(child);
    bytes[0x1100..0x1100 + callback.len()].copy_from_slice(callback);
    bytes
}
fn expect(code: &mut Vec<u8>, value: u32) {
    code.push(0x3d);
    code.extend(value.to_le_bytes());
    code.extend([0x74, 1, 0xcc]);
}
pub fn m4_probe(arch: Architecture, kind: M4Fixture) -> Vec<u8> {
    let wide = arch == Architecture::X64;
    let base = if wide { 0x140000000u64 } else { 0x400000 };
    let mut bytes = m3_thread_probe(arch, M3ThreadFixture::Return);
    for (index, name) in [
        "CreateThread",
        "CreateEventW",
        "SetEvent",
        "WaitForSingleObject",
        "Sleep",
        "TlsAlloc",
        "TlsSetValue",
        "TlsGetValue",
        "GetExitCodeThread",
        "CloseHandle",
        "ResumeThread",
        "SetLastError",
        "GetLastError",
    ]
    .iter()
    .enumerate()
    {
        let raw = 0x2300 + index * 64 - 0xe00;
        bytes[raw..raw + 64].fill(0);
        bytes[raw + 2..raw + 2 + name.len()].copy_from_slice(name.as_bytes());
    }
    // M4 controls intentionally omit static callbacks; M3 independently tests
    // static TLS/notifications. These probes exercise dynamic TLS and LastError.
    let dd = 0x98 + if wide { 112 } else { 96 };
    bytes[dd + 9 * 8..dd + 10 * 8].fill(0);
    bytes[0x200..0x1200].fill(0);
    let event = base + 0x3f00;
    let thread = base + 0x3f10;
    let slot = base + 0x3f20;
    let flag = base + 0x3f30;
    let mut root = vec![];
    if wide {
        root.extend([0x48, 0x83, 0xec, 0x48]);
    }
    call(&mut root, wide, base, 1, &[V(0), V(0), V(0), V(0)]);
    store(&mut root, wide, event);
    call(&mut root, wide, base, 5, &[]);
    store(&mut root, wide, slot);
    call(&mut root, wide, base, 6, &[M(slot), V(99)]);
    expect(&mut root, 1);
    call(&mut root, wide, base, 11, &[V(123)]);
    if kind != M4Fixture::Timeout {
        call(
            &mut root,
            wide,
            base,
            0,
            &[V(0), V(0), V(base + 0x1800), V(0), V(0), V(0)],
        );
        store(&mut root, wide, thread);
        call(&mut root, wide, base, 12, &[]);
        expect(&mut root, 0); // CreateThread resets root error
        if kind == M4Fixture::Quantum {
            call(&mut root, wide, base, 11, &[V(1)]);
            store(&mut root, wide, flag);
            // SetLastError returns zero. Store an explicit nonzero flag.
            root.push(0xb8);
            root.extend(1u32.to_le_bytes());
            store(&mut root, wide, flag);
        } else if kind == M4Fixture::Signal {
            call(&mut root, wide, base, 2, &[M(event)]);
            expect(&mut root, 1);
        }
        call(&mut root, wide, base, 3, &[M(thread), V(u32::MAX as u64)]);
        expect(&mut root, 0);
        call(&mut root, wide, base, 7, &[M(slot)]);
        expect(&mut root, 99);
        call(&mut root, wide, base, 8, &[M(thread), V(base + 0x3f40)]);
        expect(&mut root, 1);
        load(&mut root, wide, base + 0x3f40);
        expect(&mut root, 42);
    } else {
        call(&mut root, wide, base, 3, &[M(event), V(1000)]);
        expect(&mut root, 0x102);
    }
    root.push(0xb8);
    root.extend(1u32.to_le_bytes());
    if wide {
        root.extend([0x48, 0x83, 0xc4, 0x48]);
    }
    root.push(0xc3);
    assert!(root.len() < 0x800);
    bytes[0x200..0x200 + root.len()].copy_from_slice(&root);
    let mut child = vec![0; 0x800];
    if wide {
        child.extend([0x48, 0x83, 0xec, 0x48]);
    }
    call(&mut child, wide, base, 7, &[M(slot)]);
    expect(&mut child, 0);
    call(&mut child, wide, base, 6, &[M(slot), V(222)]);
    expect(&mut child, 1);
    call(&mut child, wide, base, 11, &[V(222)]);
    if kind == M4Fixture::Quantum {
        let loop_at = child.len();
        load(&mut child, wide, flag);
        child.extend([0x85, 0xc0, 0x0f, 0x84]);
        let next = child.len() + 4;
        child.extend(((loop_at as i32) - (next as i32)).to_le_bytes());
    } else {
        call(&mut child, wide, base, 3, &[M(event), V(u32::MAX as u64)]);
        expect(&mut child, 0);
    }
    call(&mut child, wide, base, 12, &[]);
    expect(&mut child, 222);
    child.push(0xb8);
    child.extend(42u32.to_le_bytes());
    if wide {
        child.extend([0x48, 0x83, 0xc4, 0x48, 0xc3]);
    } else {
        child.extend([0xc2, 4, 0]);
    }
    bytes[0xa00..0xa00 + child.len() - 0x800].copy_from_slice(&child[0x800..]);
    bytes
}
