//! Guest instruction assertions for the Win32 Global/Local, heap validation,
//! address-probe and region-query allocation families. Every outcome is decided
//! by guest instructions; a mismatch raises a breakpoint inside the guest.
use super::m4::M4Code as Code;
use super::winhttp::Arg::{Memory as M, Value as V};
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WinAllocFixture {
    Global,
    Local,
    Probe,
    RtlSize,
    ForeignFree,
    InteriorFree,
    OwnedFree,
    BadFlags,
}

/// Scratch cells inside the fixture's own writable data.
const P: u64 = 0x3f00;
const Q: u64 = 0x3f10;
const H: u64 = 0x3f20;
const MBI: u64 = 0x3f40;

fn pointer_load(code: &mut Code, wide: bool, address: u64) {
    if wide {
        code.bytes.push(0x48);
    }
    code.load(address);
}
fn pointer_store(code: &mut Code, wide: bool, address: u64) {
    code.store(address);
    let _ = wide;
}
fn same(code: &mut Code, wide: bool, saved: u64) {
    if wide {
        code.bytes.extend([0x48, 0xb9]);
        code.bytes.extend(saved.to_le_bytes());
        code.bytes.extend([0x48, 0x3b, 1]);
    } else {
        code.bytes.extend([0x3b, 5]);
        code.bytes.extend((saved as u32).to_le_bytes());
    }
    code.bytes.extend([0x74, 1, 0xcc]);
}
fn nonzero(code: &mut Code) {
    code.bytes.extend([0x85, 0xc0, 0x75, 1, 0xcc]);
}
fn zero(code: &mut Code) {
    code.bytes.extend([0x85, 0xc0, 0x74, 1, 0xcc]);
}
/// Every modeled block starts a private reservation, so it is page aligned.
fn aligned(code: &mut Code) {
    code.bytes.push(0xa9);
    code.bytes.extend(0xfffu32.to_le_bytes());
    code.bytes.extend([0x74, 1, 0xcc]);
}
/// Compares bytes relative to the pointer already in the accumulator.
fn bytes_at(code: &mut Code, expected: &[(u32, u8)]) {
    for (offset, byte) in expected {
        code.bytes.extend([0x80, 0xb8]);
        code.bytes.extend(offset.to_le_bytes());
        code.bytes.extend([*byte, 0x74, 1, 0xcc]);
    }
}
fn write_byte(code: &mut Code, value: u8) {
    code.bytes.extend([0xc6, 0, value]);
}
fn increment(code: &mut Code, wide: bool) {
    if wide {
        code.bytes.push(0x48);
    }
    code.bytes.extend([0xff, 0xc0]);
}
fn dword_at(code: &mut Code, wide: bool, address: u64, value: u32) {
    code.load(address);
    code.bytes.push(0x3d);
    code.bytes.extend(value.to_le_bytes());
    code.bytes.extend([0x74, 1, 0xcc]);
    let _ = wide;
}
pub fn win_alloc_probe(arch: Architecture, kind: WinAllocFixture) -> Vec<u8> {
    let wide = arch == Architecture::X64;
    let width = arch.width();
    let mut root = Code::new(arch, 0x1000);
    let base = root.base();
    let (p, q, h, mbi) = (base + P, base + Q, base + H, base + MBI);
    let size = if wide { 48u32 } else { 28 };
    root.prologue();
    match kind {
        WinAllocFixture::Global => {
            // GMEM_MOVEABLE never relocates here, so its handle is its pointer.
            root.call(1, &[V(0x42), V(100)]);
            nonzero(&mut root);
            aligned(&mut root);
            pointer_store(&mut root, wide, p);
            bytes_at(&mut root, &[(0, 0), (99, 0)]);
            root.call(2, &[M(p)]);
            root.expect(100);
            root.call(3, &[M(p)]);
            root.expect(0);
            root.call(4, &[M(p)]);
            same(&mut root, wide, p);
            root.call(5, &[M(p)]);
            same(&mut root, wide, p);
            root.call(6, &[M(p)]);
            root.expect(0);
            root.call(0, &[]);
            pointer_store(&mut root, wide, h);
            root.call(8, &[M(h), V(0), M(p)]);
            root.expect(1);
            root.call(8, &[M(h), V(0), V(0)]);
            root.expect(1);
            root.call(8, &[V(0), V(0), M(p)]);
            root.expect(0);
            root.call(8, &[M(h), V(2), M(p)]);
            root.expect(0);
            root.call(12, &[M(h), V(1), V(0), V(0)]);
            root.expect(1);
            root.call(12, &[M(h), V(7), V(0), V(0)]);
            root.expect(0);
            root.call(7, &[M(p)]);
            root.expect(0);
            root.call(2, &[M(p)]);
            root.expect(0);
            root.call(3, &[M(p)]);
            root.expect(0x8000);
            root.call(4, &[M(p)]);
            root.expect(0);
            root.call(8, &[M(h), V(0), M(p)]);
            root.expect(0);
            // The local family shares the same process heap.
            root.call(9, &[V(0x40), V(16)]);
            nonzero(&mut root);
            pointer_store(&mut root, wide, q);
            root.call(10, &[M(q)]);
            same(&mut root, wide, q);
            root.call(2, &[M(q)]);
            root.expect(16);
            root.call(11, &[M(q)]);
            root.expect(0);
            root.call(11, &[V(0)]);
            root.expect(0);
        }
        WinAllocFixture::Local => {
            root.call(1, &[V(0x40), V(64)]);
            nonzero(&mut root);
            pointer_store(&mut root, wide, p);
            write_byte(&mut root, b'A');
            root.call(4, &[M(p)]);
            root.expect(64);
            // Shrinking keeps the block, its address and its bytes.
            root.call(2, &[M(p), V(32), V(0)]);
            same(&mut root, wide, p);
            root.call(4, &[M(p)]);
            root.expect(32);
            // Without LMEM_MOVEABLE a grow that cannot stay in place fails and
            // leaves the original block untouched.
            root.call(2, &[M(p), V(8192), V(0)]);
            zero(&mut root);
            root.call(4, &[M(p)]);
            root.expect(32);
            root.call(2, &[M(p), V(8192), V(2)]);
            nonzero(&mut root);
            pointer_store(&mut root, wide, q);
            root.call(4, &[M(q)]);
            root.expect(8192);
            pointer_load(&mut root, wide, q);
            bytes_at(&mut root, &[(0, b'A'), (8191, 0)]);
            root.call(4, &[M(p)]);
            root.expect(0);
            root.call(5, &[M(q)]);
            same(&mut root, wide, q);
            root.call(3, &[M(q)]);
            root.expect(0);
        }
        WinAllocFixture::Probe => {
            root.call(2, &[V(base + 0x3c00), V(4)]);
            root.expect(0);
            root.call(2, &[V(0), V(4)]);
            root.expect(1);
            // A zero byte count is refused, exactly as the frozen baseline does.
            root.call(2, &[V(base + 0x3c00), V(0)]);
            root.expect(1);
            root.call(2, &[V(0x5000), V(4)]);
            root.expect(1);
            root.call(3, &[V(base + 0x3c00), V(4)]);
            root.expect(0);
            // Executable image bytes are not writable.
            root.call(3, &[V(base + 0x1000), V(4)]);
            root.expect(1);
            root.call(4, &[V(base + 0x3c00), V(100)]);
            root.expect(0);
            root.call(4, &[V(0x5000), V(10)]);
            root.expect(1);
            root.call(5, &[V(base + 0x3c10), V(100)]);
            root.expect(0);
            root.call(5, &[V(base + 0x3c00), V(0)]);
            root.expect(1);
            root.call(7, &[V(u64::MAX), V(0), V(8192), V(0x3000), V(4), V(0)]);
            nonzero(&mut root);
            pointer_store(&mut root, wide, q);
            root.call(6, &[M(q), V(mbi), V(size as u64)]);
            root.expect(size);
            pointer_load(&mut root, wide, mbi);
            same(&mut root, wide, q);
            pointer_load(&mut root, wide, mbi + width as u64);
            same(&mut root, wide, q);
            let fields = if wide { [16, 24, 32, 36, 40] } else { [8, 12, 16, 20, 24] };
            dword_at(&mut root, wide, mbi + fields[0], 4);
            dword_at(&mut root, wide, mbi + fields[1], 8192);
            dword_at(&mut root, wide, mbi + fields[2], 0x1000);
            dword_at(&mut root, wide, mbi + fields[3], 4);
            dword_at(&mut root, wide, mbi + fields[4], 0x20000);
            root.call(6, &[M(q), V(mbi), V(size as u64 - 1)]);
            root.expect(0);
            root.call(6, &[M(q), V(0), V(size as u64)]);
            root.expect(0);
            // A foreign process handle and an unknown node are both refused.
            root.call(7, &[V(5), V(0), V(8192), V(0x3000), V(4), V(0)]);
            zero(&mut root);
            root.call(7, &[V(u64::MAX), V(0), V(8192), V(0x3000), V(4), V(7)]);
            zero(&mut root);
            root.call(8, &[M(q), V(0), V(0x8000)]);
            root.expect(1);
            root.call(6, &[M(q), V(mbi), V(size as u64)]);
            root.expect(size);
            dword_at(&mut root, wide, mbi + fields[2], 0x10000);
            dword_at(&mut root, wide, mbi + fields[3], 1);
        }
        WinAllocFixture::RtlSize => {
            root.call(0, &[]);
            pointer_store(&mut root, wide, h);
            root.call(1, &[M(h), V(0), V(48)]);
            nonzero(&mut root);
            pointer_store(&mut root, wide, p);
            root.call(10, &[M(h), V(0), M(p)]);
            root.expect(48);
            // A null heap matches the block's own heap.
            root.call(10, &[V(0), V(0), M(p)]);
            root.expect(48);
            root.call(10, &[M(h), V(2), M(p)]);
            root.expect(0xffffffff);
            root.call(10, &[M(h), V(0), V(0)]);
            root.expect(0xffffffff);
            pointer_load(&mut root, wide, p);
            increment(&mut root, wide);
            pointer_store(&mut root, wide, q);
            root.call(10, &[M(h), V(0), M(q)]);
            root.expect(0xffffffff);
            root.call(3, &[M(h), V(0), M(p)]);
            root.expect(1);
            root.call(10, &[M(h), V(0), M(p)]);
            root.expect(0xffffffff);
        }
        WinAllocFixture::ForeignFree => {
            root.call(1, &[V(0), V(0), V(0)]);
            nonzero(&mut root);
            pointer_store(&mut root, wide, h);
            root.call(2, &[M(h), V(0), V(16)]);
            nonzero(&mut root);
            pointer_store(&mut root, wide, p);
            root.call(3, &[M(p)]);
        }
        WinAllocFixture::InteriorFree => {
            root.call(1, &[V(0), V(64)]);
            nonzero(&mut root);
            increment(&mut root, wide);
            pointer_store(&mut root, wide, p);
            root.call(2, &[M(p)]);
        }
        WinAllocFixture::OwnedFree => {
            root.call(10, &[]);
            pointer_store(&mut root, wide, p);
            root.call(1, &[M(p)]);
        }
        WinAllocFixture::BadFlags => {
            root.call(1, &[V(0x100), V(16)]);
        }
    }
    root.epilogue(1, 0);
    let names: &[&str] = match kind {
        WinAllocFixture::Global => &[
            "GetProcessHeap",
            "GlobalAlloc",
            "GlobalSize",
            "GlobalFlags",
            "GlobalHandle",
            "GlobalLock",
            "GlobalUnlock",
            "GlobalFree",
            "HeapValidate",
            "LocalAlloc",
            "LocalLock",
            "LocalFree",
            "HeapSetInformation",
        ],
        WinAllocFixture::Local => &[
            "GetProcessHeap",
            "LocalAlloc",
            "LocalReAlloc",
            "LocalFree",
            "GlobalSize",
            "LocalLock",
            "GlobalFlags",
        ],
        WinAllocFixture::Probe => &[
            "GetProcessHeap",
            "GlobalAlloc",
            "IsBadReadPtr",
            "IsBadWritePtr",
            "IsBadStringPtrA",
            "IsBadStringPtrW",
            "VirtualQuery",
            "VirtualAllocExNuma",
            "VirtualFree",
        ],
        WinAllocFixture::RtlSize => &[
            "GetProcessHeap",
            "HeapAlloc",
            "GlobalSize",
            "HeapFree",
            "HeapValidate",
            "GlobalAlloc",
            "GlobalFree",
            "LocalAlloc",
            "LocalFree",
            "GetLastError",
            "RtlSizeHeap",
        ],
        WinAllocFixture::ForeignFree => &[
            "GetProcessHeap",
            "HeapCreate",
            "HeapAlloc",
            "GlobalFree",
            "HeapFree",
        ],
        WinAllocFixture::InteriorFree => &["GetProcessHeap", "GlobalAlloc", "GlobalFree"],
        WinAllocFixture::OwnedFree => &[
            "GetProcessHeap",
            "GlobalFree",
            "GlobalAlloc",
            "GlobalSize",
            "HeapValidate",
            "LocalAlloc",
            "LocalFree",
            "VirtualFree",
            "GetLastError",
            "GetLastError",
            "__p__acmdln",
        ],
        WinAllocFixture::BadFlags => &["GetProcessHeap", "GlobalAlloc"],
    };
    let mut bytes = m4_custom_probe(arch, names, &root.finish(), &[], &[]);
    // RtlSizeHeap and the CRT accessor live in a second import descriptor whose
    // thunks start at slot ten; slot nine terminates the first one.
    if matches!(kind, WinAllocFixture::RtlSize | WinAllocFixture::OwnedFree) {
        let module: &[u8] = if kind == WinAllocFixture::RtlSize {
            b"ntdll.dll\0"
        } else {
            b"msvcrt.dll\0"
        };
        let dd = 0x98 + if wide { 112 } else { 96 };
        put32(&mut bytes, dd + 12, 60);
        put32(&mut bytes, 0x1214, 0x2180 + 10 * width as u32);
        put32(&mut bytes, 0x1220, 0x2280);
        put32(&mut bytes, 0x1224, 0x2080 + 10 * width as u32);
        bytes[0x1228..0x123c].fill(0);
        bytes[0x1480..0x1480 + module.len()].copy_from_slice(module);
        for raw in [0x1280, 0x1380] {
            bytes[raw + 9 * width..raw + 10 * width].fill(0);
            bytes[raw + 13 * width..raw + 14 * width].fill(0);
        }
    }
    for (rva, value) in [
        (0x3c00, b"abc\0".as_slice()),
        (0x3c10, b"a\0b\0\0\0"),
    ] {
        bytes[rva - 0xe00..rva - 0xe00 + value.len()].copy_from_slice(value);
    }
    bytes
}
