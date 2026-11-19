//! Instruction-built CRT data callers. Imported data, accessors and dynamic
//! lookup must observe one mutable guest cell; callbacks inspect actual bytes.
use super::m4::M4Code as Code;
use super::winhttp::Arg::{Memory as M, Value as V};
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrtDataFixture {
    Alias,
    Thread,
    Parent,
    Child,
    Release,
    Protect,
    Free,
    Nx,
    Long,
}

fn pointer_load(code: &mut Code, wide: bool, address: u64) {
    if wide {
        code.bytes.push(0x48);
    }
    code.load(address);
}
fn dereference(code: &mut Code, wide: bool) {
    if wide {
        code.bytes.push(0x48);
    }
    code.bytes.extend([0x8b, 0]);
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
fn text(code: &mut Code, expected: &[u8]) {
    for (offset, byte) in expected.iter().enumerate() {
        code.bytes.extend([0x80, 0xb8]);
        code.bytes.extend((offset as u32).to_le_bytes());
        code.bytes.extend([*byte, 0x74, 1, 0xcc]);
    }
}
fn point_to(code: &mut Code, wide: bool, address: u64) {
    if wide {
        code.bytes.extend([0x48, 0xba]);
        code.bytes.extend(address.to_le_bytes());
        code.bytes.extend([0x48, 0x89, 0x10]);
    } else {
        code.bytes.extend([0xc7, 0]);
        code.bytes.extend((address as u32).to_le_bytes());
    }
}
pub fn crt_data_probe(arch: Architecture, kind: CrtDataFixture) -> Vec<u8> {
    let wide = arch == Architecture::X64;
    let width = arch.width();
    let mut root = Code::new(arch, 0x1000);
    let mut thread = Code::new(arch, 0x1800);
    let base = root.base();
    let cell = base + 0x3f00;
    let handle = cell + 16;
    root.prologue();
    pointer_load(&mut root, wide, base + 0x2080 + 10 * width as u64);
    root.store(cell);
    root.call(11, &[]);
    same(&mut root, wide, cell);
    dereference(&mut root, wide);
    if kind == CrtDataFixture::Child {
        text(&mut root, b"C:\\emumee\\child.exe child-only\0");
    } else if kind == CrtDataFixture::Long {
        text(&mut root, b"C:\\emumee\\sample.exe ");
        for (offset, byte) in [(5020u32, b'x'), (5021, 0)] {
            // prefix is 21 bytes; the argument contains exactly 5,000 x bytes.
            root.bytes.extend([0x80, 0xb8]);
            root.bytes.extend(offset.to_le_bytes());
            root.bytes.extend([byte, 0x74, 1, 0xcc]);
        }
    } else {
        text(
            &mut root,
            "C:\\emumee\\sample.exe two words é😀\0".as_bytes(),
        );
    }
    if kind == CrtDataFixture::Child {
        pointer_load(&mut root, wide, cell);
        point_to(&mut root, wide, base + 0x3c80);
        root.epilogue(42, 0);
    } else if matches!(
        kind,
        CrtDataFixture::Release
            | CrtDataFixture::Protect
            | CrtDataFixture::Free
            | CrtDataFixture::Nx
    ) {
        match kind {
            CrtDataFixture::Release => root.call(2, &[M(cell), V(0), V(0x8000)]),
            CrtDataFixture::Protect => root.call(3, &[M(cell), V(4096), V(0x40), V(cell + 32)]),
            CrtDataFixture::Free => {
                root.call(12, &[M(cell)]);
                if !wide {
                    root.bytes.extend([0x83, 0xc4, 4]);
                }
            }
            _ => {
                pointer_load(&mut root, wide, cell);
                root.bytes.extend([0xff, 0xd0]);
            }
        }
        root.epilogue(1, 0);
    } else {
        // Both the pointed-to bytes and the pointer cell are guest mutable.
        root.bytes.extend([0xc6, 0, b'*']);
        root.call(11, &[]);
        same(&mut root, wide, cell);
        dereference(&mut root, wide);
        text(&mut root, b"*");
        pointer_load(&mut root, wide, cell);
        point_to(&mut root, wide, base + 0x3c80);
        root.call(0, &[V(base + 0x3c00)]);
        root.store(handle);
        root.call(1, &[M(handle), V(base + 0x3c20)]);
        same(&mut root, wide, cell);
        dereference(&mut root, wide);
        text(&mut root, b"mutated\0");
        if kind == CrtDataFixture::Thread {
            root.call(4, &[V(0), V(0), V(base + 0x1800), V(0), V(0), V(0)]);
            root.store(handle + 8);
            root.call(5, &[M(handle + 8), V(u32::MAX as u64)]);
            root.expect(0);
            root.load(cell + 40);
            root.expect(0x7155);
            root.call(6, &[M(handle + 8)]);
            root.expect(1);
        } else if kind == CrtDataFixture::Parent {
            // Child maps the same virtual DLL address in an independent space.
            // Its mutation must not replace the parent's pointer value.
            if wide {
                root.bytes.extend([0x48, 0x83, 0xec, 0x20]);
            }
            root.call(
                8,
                &[
                    V(base + 0x3ca0),
                    V(base + 0x3cc0),
                    V(0),
                    V(0),
                    V(0),
                    V(0),
                    V(0),
                    V(0),
                    V(base + 0x3d00),
                    V(base + 0x3e00),
                ],
            );
            root.expect(1);
            root.call(5, &[M(base + 0x3e00), V(u32::MAX as u64)]);
            root.expect(0);
            if wide {
                root.bytes.extend([0x48, 0x83, 0xc4, 0x20]);
            }
        }
        root.call(7, &[M(handle)]);
        root.expect(1);
        root.call(11, &[]);
        same(&mut root, wide, cell);
        dereference(&mut root, wide);
        text(&mut root, b"mutated\0");
        root.epilogue(1, 0);
    }
    thread.prologue();
    thread.call(11, &[]);
    same(&mut thread, wide, cell);
    dereference(&mut thread, wide);
    text(&mut thread, b"mutated\0");
    thread.bytes.push(0xb8);
    thread.bytes.extend(0x7155u32.to_le_bytes());
    thread.store(cell + 40);
    thread.epilogue(0, 1);
    let names = [
        "LoadLibraryA",
        "GetProcAddress",
        "VirtualFree",
        "VirtualProtect",
        "CreateThread",
        "WaitForSingleObject",
        "CloseHandle",
        "FreeLibrary",
        "CreateProcessA",
        "GetLastError",
        "_acmdln",
        "__p__acmdln",
        "free",
    ];
    let mut bytes = m4_custom_probe(arch, &names, &root.finish(), &thread.finish(), &[]);
    let dd = 0x98 + if wide { 112 } else { 96 };
    put32(&mut bytes, dd + 12, 60);
    put32(&mut bytes, 0x1214, 0x2180 + 10 * width as u32);
    put32(&mut bytes, 0x1220, 0x2280);
    put32(&mut bytes, 0x1224, 0x2080 + 10 * width as u32);
    bytes[0x1228..0x123c].fill(0);
    bytes[0x1480..0x148b].copy_from_slice(b"msvcrt.dll\0");
    for raw in [0x1280, 0x1380] {
        bytes[raw + 9 * width..raw + 10 * width].fill(0);
        bytes[raw + 13 * width..raw + 14 * width].fill(0);
    }
    for (rva, value) in [
        (0x3c00, b"msvcrt.dll\0".as_slice()),
        (0x3c20, b"_acmdln\0"),
        (0x3c80, b"mutated\0"),
        (0x3ca0, b"C:\\emumee\\child.exe\0"),
        (0x3cc0, b"C:\\emumee\\child.exe child-only\0"),
    ] {
        bytes[rva - 0xe00..rva - 0xe00 + value.len()].copy_from_slice(value);
    }
    bytes
}
