//! Guest instruction assertions for the Win32 lstr, character-type,
//! case-mapping and address-text models.
use super::m4::M4Code as Code;
use super::winhttp::Arg::{Memory as M, Value as V};
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WinTextFixture {
    Copy,
    Map,
    Message,
    BadType,
    BadFlags,
    MessageModule,
}

const ALPHA: u64 = 0x3c00;
const BETA: u64 = 0x3c10;
const UPPER: u64 = 0x3c20;
const DIGITS: u64 = 0x3c30;
const W_ALPHA: u64 = 0x3c40;
const W_UPPER: u64 = 0x3c60;
const W_PHA: u64 = 0x3c70;
const ADDRESS: u64 = 0x3c80;
const DEST_A: u64 = 0x3e00;
const DEST_B: u64 = 0x3e40;
const DEST_C: u64 = 0x3e80;
const W_DEST: u64 = 0x3f00;
const W_DEST_B: u64 = 0x3f40;
const TYPES: u64 = 0x3fc0;
const LENGTH: u64 = 0x3fd0;
const TEMPLATE: u64 = 0x3ca0;
const INSERT: u64 = 0x3cc0;
const ARRAY: u64 = 0x3cd0;
const CELL: u64 = 0x3ce0;

fn expect_pointer(code: &mut Code, wide: bool, value: u64) {
    if wide {
        code.bytes.extend([0x48, 0xb9]);
        code.bytes.extend(value.to_le_bytes());
        code.bytes.extend([0x48, 0x39, 0xc8]);
    } else {
        code.bytes.push(0xb9);
        code.bytes.extend((value as u32).to_le_bytes());
        code.bytes.extend([0x39, 0xc8]);
    }
    code.bytes.extend([0x74, 1, 0xcc]);
}
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
fn dword_at(code: &mut Code, address: u64, value: u32) {
    code.load(address);
    code.bytes.push(0x3d);
    code.bytes.extend(value.to_le_bytes());
    code.bytes.extend([0x74, 1, 0xcc]);
}
/// Compares the word at an absolute address without reading its neighbour.
fn word_at(code: &mut Code, wide: bool, address: u64, value: u16) {
    address_of(code, wide, address);
    code.bytes.extend([0x66, 0x81, 0x38]);
    code.bytes.extend(value.to_le_bytes());
    code.bytes.extend([0x74, 1, 0xcc]);
}
pub fn win_text_probe(arch: Architecture, kind: WinTextFixture) -> Vec<u8> {
    let wide = arch == Architecture::X64;
    let mut root = Code::new(arch, 0x1000);
    let base = root.base();
    let at = |rva: u64| base + rva;
    root.prologue();
    match kind {
        WinTextFixture::Copy => {
            root.call(0, &[V(at(DEST_A)), V(at(ALPHA))]);
            expect_pointer(&mut root, wide, at(DEST_A));
            bytes_at(&mut root, &[(0, b'a'), (4, b'a'), (5, 0)]);
            root.call(2, &[V(at(DEST_A)), V(at(BETA))]);
            bytes_at(&mut root, &[(5, b'B'), (8, b'A'), (9, 0)]);
            root.call(4, &[V(at(DEST_B)), V(at(ALPHA)), V(3)]);
            bytes_at(&mut root, &[(0, b'a'), (1, b'l'), (2, 0)]);
            root.call(1, &[V(at(W_DEST)), V(at(W_ALPHA))]);
            bytes_at(&mut root, &[(0, b'a'), (8, b'a'), (10, 0)]);
            root.call(3, &[V(at(W_DEST)), V(at(W_PHA))]);
            bytes_at(&mut root, &[(10, b'p'), (14, b'a'), (16, 0)]);
            root.call(5, &[V(at(W_DEST_B)), V(at(W_ALPHA)), V(3)]);
            bytes_at(&mut root, &[(0, b'a'), (2, b'l'), (4, 0)]);
            // Ordinal comparison reports the sign, not just equality.
            root.call(6, &[V(at(ALPHA)), V(at(UPPER))]);
            root.expect(1);
            root.call(6, &[V(at(ALPHA)), V(at(ALPHA))]);
            root.expect(0);
            root.call(7, &[V(at(ALPHA)), V(at(UPPER))]);
            root.expect(0);
            root.call(8, &[V(at(W_ALPHA)), V(at(W_UPPER))]);
            root.expect(0);
        }
        WinTextFixture::Map => {
            // CT_CTYPE1 for a digit: numeric, hex digit and defined.
            root.call(0, &[V(0), V(1), V(at(DIGITS)), V(3), V(at(TYPES))]);
            root.expect(1);
            word_at(&mut root, wide, at(TYPES), 0x284);
            // The wide spelling takes no locale.
            root.call(1, &[V(1), V(at(W_ALPHA)), V(1), V(at(TYPES) + 8)]);
            root.expect(1);
            word_at(&mut root, wide, at(TYPES) + 8, 0x382);
            // LCMAP_UPPERCASE and LCMAP_LOWERCASE copy the terminator when the
            // source length was determined by scanning.
            root.call(
                2,
                &[V(0), V(0x200), V(at(ALPHA)), V(u64::MAX), V(at(DEST_C)), V(16)],
            );
            root.expect(6);
            address_of(&mut root, wide, at(DEST_C));
            bytes_at(&mut root, &[(0, b'A'), (4, b'A'), (5, 0)]);
            // A zero capacity is a length query.
            root.call(
                2,
                &[V(0), V(0x200), V(at(ALPHA)), V(u64::MAX), V(0), V(0)],
            );
            root.expect(6);
            root.call(
                3,
                &[V(0), V(0x100), V(at(W_UPPER)), V(u64::MAX), V(at(W_DEST)), V(16)],
            );
            root.expect(6);
            address_of(&mut root, wide, at(W_DEST));
            bytes_at(&mut root, &[(0, b'a'), (8, b'a'), (10, 0)]);
            root.call(
                4,
                &[
                    V(0),
                    V(0x200),
                    V(at(W_ALPHA)),
                    V(u64::MAX),
                    V(at(W_DEST_B)),
                    V(16),
                    V(0),
                    V(0),
                    V(0),
                ],
            );
            root.expect(6);
            address_of(&mut root, wide, at(W_DEST_B));
            bytes_at(&mut root, &[(0, b'A'), (8, b'A'), (10, 0)]);
            // An address with no port, then the required length it reports.
            root.call(10, &[V(at(ADDRESS)), V(0), V(at(W_DEST)), V(at(LENGTH))]);
            root.expect(0);
            address_of(&mut root, wide, at(W_DEST));
            bytes_at(
                &mut root,
                &[(0, b'1'), (2, b'9'), (6, b'.'), (22, b'0'), (24, 0)],
            );
            dword_at(&mut root, at(LENGTH), 13);
        }
        WinTextFixture::Message => {
            // One persona system message, with its control escapes expanded.
            root.call(
                6,
                &[V(0x1200), V(0), V(2), V(0), V(at(W_DEST)), V(64), V(0)],
            );
            root.expect(44);
            address_of(&mut root, wide, at(W_DEST));
            bytes_at(
                &mut root,
                &[(0, b'T'), (2, b'h'), (4, b'e'), (84, 13), (86, 10), (88, 0)],
            );
            // An unmodeled identifier reports no message rather than inventing one.
            root.call(
                6,
                &[V(0x1200), V(0), V(0x4242), V(0), V(at(W_DEST)), V(64), V(0)],
            );
            root.expect(0);
            root.call(9, &[]);
            root.expect(317);
            // A buffer that is too small still receives what fits.
            root.call(
                6,
                &[V(0x1200), V(0), V(2), V(0), V(at(W_DEST_B)), V(8), V(0)],
            );
            root.expect(0);
            root.call(9, &[]);
            root.expect(122);
            address_of(&mut root, wide, at(W_DEST_B));
            bytes_at(&mut root, &[(0, b'T'), (12, b's'), (14, 0)]);
            // A caller template with one insert taken from an argument array.
            root.call(
                6,
                &[
                    V(0x2400),
                    V(at(TEMPLATE)),
                    V(0),
                    V(0),
                    V(at(W_DEST)),
                    V(64),
                    V(at(ARRAY)),
                ],
            );
            root.expect(5);
            address_of(&mut root, wide, at(W_DEST));
            bytes_at(
                &mut root,
                &[(0, b'a'), (2, b' '), (4, b'Z'), (6, b' '), (8, b'b'), (10, 0)],
            );
            // An allocated buffer comes from the process heap the local family
            // frees, so the documented LocalFree contract holds.
            root.call(
                6,
                &[V(0x1300), V(0), V(2), V(0), V(at(CELL)), V(64), V(0)],
            );
            root.expect(44);
            root.call(7, &[M(at(CELL))]);
            root.expect(128);
            root.call(8, &[M(at(CELL))]);
            root.expect(0);
            // The low byte is an output width this profile does not model.
            root.call(
                6,
                &[V(0x1240), V(0), V(2), V(0), V(at(W_DEST)), V(64), V(0)],
            );
            root.expect(0);
            root.call(9, &[]);
            root.expect(87);
        }
        WinTextFixture::MessageModule => {
            root.call(
                6,
                &[V(0x800), V(0), V(2), V(0), V(at(W_DEST)), V(64), V(0)],
            );
        }
        WinTextFixture::BadType => {
            root.call(0, &[V(0), V(2), V(at(DIGITS)), V(3), V(at(TYPES))]);
        }
        WinTextFixture::BadFlags => {
            root.call(
                3,
                &[V(0), V(0x400), V(at(W_ALPHA)), V(u64::MAX), V(at(W_DEST)), V(16)],
            );
        }
    }
    root.epilogue(1, 0);
    let names: &[&str] = match kind {
        WinTextFixture::Copy => &[
            "lstrcpyA",
            "lstrcpyW",
            "lstrcatA",
            "lstrcatW",
            "lstrcpynA",
            "lstrcpynW",
            "lstrcmpA",
            "lstrcmpiA",
            "lstrcmpiW",
        ],
        WinTextFixture::Map | WinTextFixture::BadType | WinTextFixture::BadFlags => &[
            "GetStringTypeA",
            "GetStringTypeWW",
            "LCMapStringA",
            "LCMapStringW",
            "LCMapStringEx",
            "lstrcmpW",
            "GetLastError",
            "GetLastError",
            "GetLastError",
            "GetLastError",
            "RtlIpv4AddressToStringExW",
        ],
        WinTextFixture::Message | WinTextFixture::MessageModule => &[
            "GetStringTypeA",
            "GetStringTypeWW",
            "LCMapStringA",
            "LCMapStringW",
            "LCMapStringEx",
            "lstrcmpW",
            "FormatMessageW",
            "GlobalSize",
            "LocalFree",
            "GetLastError",
        ],
    };
    let mut bytes = m4_custom_probe(arch, names, &root.finish(), &[], &[]);
    if matches!(kind, WinTextFixture::Map | WinTextFixture::BadType | WinTextFixture::BadFlags) {
        let width = arch.width();
        let dd = 0x98 + if wide { 112 } else { 96 };
        put32(&mut bytes, dd + 12, 60);
        put32(&mut bytes, 0x1214, 0x2180 + 10 * width as u32);
        put32(&mut bytes, 0x1220, 0x2280);
        put32(&mut bytes, 0x1224, 0x2080 + 10 * width as u32);
        bytes[0x1228..0x123c].fill(0);
        bytes[0x1480..0x1490].fill(0);
        bytes[0x1480..0x148a].copy_from_slice(b"ntdll.dll\0");
        for raw in [0x1280, 0x1380] {
            bytes[raw + 9 * width..raw + 10 * width].fill(0);
            bytes[raw + 13 * width..raw + 14 * width].fill(0);
        }
    }
    let wide_text = |text: &str| -> Vec<u8> {
        let mut out: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        out.extend([0, 0]);
        out
    };
    for (rva, value) in [
        (ALPHA, b"alpha\0".to_vec()),
        (BETA, b"BETA\0".to_vec()),
        (UPPER, b"ALPHA\0".to_vec()),
        (DIGITS, b"123\0".to_vec()),
        (W_ALPHA, wide_text("alpha")),
        (W_UPPER, wide_text("ALPHA")),
        (W_PHA, wide_text("pha")),
        (ADDRESS, vec![192, 168, 0, 10]),
        (LENGTH, 32u32.to_le_bytes().to_vec()),
        (TEMPLATE, wide_text("a %1 b")),
        (INSERT, wide_text("Z")),
        (
            ARRAY,
            (base + INSERT).to_le_bytes()[..arch.width()].to_vec(),
        ),
    ] {
        let raw = (rva - 0xe00) as usize;
        bytes[raw..raw + value.len()].copy_from_slice(&value);
    }
    bytes
}
