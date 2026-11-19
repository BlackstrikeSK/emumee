//! Guest instruction assertions for CRT file streams over the virtual file
//! system: open, read, position, write and close, plus their refusals.
use super::m4::M4Code as Code;
use super::winhttp::Arg::{Memory as M, Value as V};
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrtFileFixture {
    Streams,
    Output,
    BadMode,
    BadClose,
    WriteOnlyRead,
}

const PATH: u64 = 0x3c00;
const W_PATH: u64 = 0x3c20;
const MODE_READ: u64 = 0x3c50;
const W_MODE: u64 = 0x3c60;
const OUT_PATH: u64 = 0x3c70;
const MODE_WRITE: u64 = 0x3c90;
const MODE_BAD: u64 = 0x3ca0;
const GREETING: u64 = 0x3cb0;
const BUFFER: u64 = 0x3e00;
const SAVED: u64 = 0x3f00;

fn bytes_at(code: &mut Code, expected: &[(u32, u8)]) {
    for (offset, byte) in expected {
        code.bytes.extend([0x80, 0xb8]);
        code.bytes.extend(offset.to_le_bytes());
        code.bytes.extend([*byte, 0x74, 1, 0xcc]);
    }
}
fn address_of(code: &mut Code, wide: bool, address: u64) {
    if wide {
        code.bytes.extend([0x48, 0xb8]);
        code.bytes.extend(address.to_le_bytes());
    } else {
        code.bytes.push(0xb8);
        code.bytes.extend((address as u32).to_le_bytes());
    }
}
fn nonzero(code: &mut Code) {
    code.bytes.extend([0x85, 0xc0, 0x75, 1, 0xcc]);
}
fn cdecl(code: &mut Code, wide: bool, index: usize, args: &[super::winhttp::Arg]) {
    code.call(index, args);
    if !wide && !args.is_empty() {
        code.bytes.extend([0x83, 0xc4, (args.len() * 4) as u8]);
    }
}
pub fn crt_file_probe(arch: Architecture, kind: CrtFileFixture) -> Vec<u8> {
    let wide = arch == Architecture::X64;
    let mut root = Code::new(arch, 0x1000);
    let base = root.base();
    let at = |rva: u64| base + rva;
    root.prologue();
    match kind {
        CrtFileFixture::Streams => {
            cdecl(&mut root, wide, 0, &[V(at(PATH)), V(at(MODE_READ))]);
            nonzero(&mut root);
            root.store(at(SAVED));
            // The first opened stream takes the first descriptor after the
            // three standard ones.
            cdecl(&mut root, wide, 8, &[M(at(SAVED))]);
            root.expect(3);
            cdecl(&mut root, wide, 3, &[V(at(BUFFER)), V(1), V(5), M(at(SAVED))]);
            root.expect(5);
            address_of(&mut root, wide, at(BUFFER));
            bytes_at(&mut root, &[(0, b'h'), (4, b'o')]);
            cdecl(&mut root, wide, 5, &[M(at(SAVED))]);
            root.expect(5);
            cdecl(&mut root, wide, 4, &[M(at(SAVED)), V(0), V(0)]);
            root.expect(0);
            cdecl(&mut root, wide, 5, &[M(at(SAVED))]);
            root.expect(0);
            // Items, not bytes: two items of two bytes each.
            cdecl(&mut root, wide, 3, &[V(at(BUFFER)), V(2), V(2), M(at(SAVED))]);
            root.expect(2);
            cdecl(&mut root, wide, 4, &[M(at(SAVED)), V(6), V(0)]);
            root.expect(0);
            cdecl(&mut root, wide, 3, &[V(at(BUFFER)), V(1), V(5), M(at(SAVED))]);
            root.expect(5);
            address_of(&mut root, wide, at(BUFFER));
            bytes_at(&mut root, &[(0, b'w'), (4, b'd')]);
            // Reading past the end returns a short count.
            cdecl(&mut root, wide, 3, &[V(at(BUFFER)), V(1), V(8), M(at(SAVED))]);
            root.expect(0);
            cdecl(&mut root, wide, 6, &[M(at(SAVED))]);
            root.expect(0);
            cdecl(&mut root, wide, 2, &[M(at(SAVED))]);
            root.expect(0);
        }
        CrtFileFixture::Output => {
            cdecl(&mut root, wide, 0, &[V(at(OUT_PATH)), V(at(MODE_WRITE))]);
            nonzero(&mut root);
            root.store(at(SAVED));
            cdecl(&mut root, wide, 7, &[V(u64::from(b'A')), M(at(SAVED))]);
            root.expect(u32::from(b'A'));
            cdecl(&mut root, wide, 5, &[M(at(SAVED))]);
            root.expect(1);
            cdecl(&mut root, wide, 2, &[M(at(SAVED))]);
            root.expect(0);
            // The wide spelling opens the same virtual file system.
            cdecl(&mut root, wide, 1, &[V(at(W_PATH)), V(at(W_MODE))]);
            nonzero(&mut root);
            root.store(at(SAVED));
            cdecl(&mut root, wide, 2, &[M(at(SAVED))]);
            root.expect(0);
            cdecl(&mut root, wide, 9, &[V(at(GREETING))]);
            nonzero(&mut root);
        }
        CrtFileFixture::BadMode => {
            cdecl(&mut root, wide, 0, &[V(at(PATH)), V(at(MODE_BAD))]);
        }
        CrtFileFixture::BadClose => {
            cdecl(&mut root, wide, 2, &[V(0)]);
            root.expect(0xffffffff);
            cdecl(&mut root, wide, 2, &[V(at(BUFFER))]);
        }
        CrtFileFixture::WriteOnlyRead => {
            cdecl(&mut root, wide, 0, &[V(at(OUT_PATH)), V(at(MODE_WRITE))]);
            nonzero(&mut root);
            root.store(at(SAVED));
            cdecl(&mut root, wide, 3, &[V(at(BUFFER)), V(1), V(4), M(at(SAVED))]);
        }
    }
    root.epilogue(1, 0);
    let names: &[&str] = &[
        "fopen", "_wfopen", "fclose", "fread", "fseek", "ftell", "fflush", "fputc", "_fileno",
        "puts",
    ];
    let mut bytes = m4_custom_probe(arch, names, &root.finish(), &[], &[]);
    bytes[0x1440..0x1450].fill(0);
    bytes[0x1440..0x144b].copy_from_slice(b"msvcrt.dll\0");
    let wide_text = |text: &str| -> Vec<u8> {
        let mut out: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        out.extend([0, 0]);
        out
    };
    let narrow = |text: &str| -> Vec<u8> {
        let mut out = text.as_bytes().to_vec();
        out.push(0);
        out
    };
    for (rva, value) in [
        (PATH, narrow(r"C:\emumee\data.txt")),
        (W_PATH, wide_text(r"C:\emumee\data.txt")),
        (MODE_READ, narrow("rb")),
        (W_MODE, wide_text("rb")),
        (OUT_PATH, narrow(r"C:\emumee\out.txt")),
        (MODE_WRITE, narrow("wb")),
        (MODE_BAD, narrow("q")),
        (GREETING, narrow("hi")),
    ] {
        let raw = (rva - 0xe00) as usize;
        bytes[raw..raw + value.len()].copy_from_slice(&value);
    }
    bytes
}
