//! Guest instruction assertions for the legacy CRT string, case, span,
//! tokenizer, radix, conversion, clock-text and locale models.
use super::m4::M4Code as Code;
use super::winhttp::Arg::Value as V;
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrtTextFixture {
    Text,
    Fold,
    Convert,
    Clock,
    /// Source-only: the CRT date and time strings follow the run's own persona
    /// clock, so a contained replay cannot reproduce the same bytes.
    ClockText,
    BadLocale,
    NullString,
}

/// Read-only constants and writable scratch inside the fixture's own data.
const ALPHA: u64 = 0x3c00;
const BETA: u64 = 0x3c10;
const VOWELS: u64 = 0x3c20;
const PHA: u64 = 0x3c30;
const W_ALPHA: u64 = 0x3c40;
const W_VOWELS: u64 = 0x3c60;
const W_PHA: u64 = 0x3c70;
const DIGITS: u64 = 0x3c80;
const NEGATIVE: u64 = 0x3c90;
const UPPER: u64 = 0x3ca0;
const W_UPPER: u64 = 0x3cb0;
const C_LOCALE: u64 = 0x3cc0;
const W_C_LOCALE: u64 = 0x3cd0;
const PERSONA: u64 = 0x3ce0;
const UNSUPPORTED: u64 = 0x3cf0;
const W_TOKENS: u64 = 0x3d00;
const W_SEPARATORS: u64 = 0x3d20;
const NARROW_MIXED: u64 = 0x3d30;
const W_MIXED: u64 = 0x3d40;
const DEST_A: u64 = 0x3e00;
const DEST_B: u64 = 0x3e40;
const DEST_C: u64 = 0x3e80;
const W_DEST: u64 = 0x3f00;
const COUNT: u64 = 0x3fc0;

fn nonzero(code: &mut Code) {
    code.bytes.extend([0x85, 0xc0, 0x75, 1, 0xcc]);
}
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
/// Compares bytes relative to the pointer already in the accumulator.
fn bytes_at(code: &mut Code, expected: &[(u32, u8)]) {
    for (offset, byte) in expected {
        code.bytes.extend([0x80, 0xb8]);
        code.bytes.extend(offset.to_le_bytes());
        code.bytes.extend([*byte, 0x74, 1, 0xcc]);
    }
}
/// Requires an ASCII digit at the offset, without pinning its value.
fn digit_at(code: &mut Code, offset: u32) {
    for (byte, jump) in [(0x30u8, 0x73u8), (0x39, 0x76)] {
        code.bytes.extend([0x80, 0xb8]);
        code.bytes.extend(offset.to_le_bytes());
        code.bytes.extend([byte, jump, 1, 0xcc]);
    }
}
/// Loads an absolute address into the accumulator so byte checks can follow.
fn address_of(code: &mut Code, wide: bool, address: u64) {
    if wide {
        code.bytes.extend([0x48, 0xb8]);
        code.bytes.extend(address.to_le_bytes());
    } else {
        code.bytes.push(0xb8);
        code.bytes.extend((address as u32).to_le_bytes());
    }
}
/// Compares the dword stored at an absolute address.
fn dword_at(code: &mut Code, address: u64, value: u32) {
    code.load(address);
    code.bytes.push(0x3d);
    code.bytes.extend(value.to_le_bytes());
    code.bytes.extend([0x74, 1, 0xcc]);
}
/// Calls a CDECL import and restores the stack the caller pushed on x86.
fn cdecl(code: &mut Code, wide: bool, index: usize, args: &[super::winhttp::Arg]) {
    code.call(index, args);
    if !wide && !args.is_empty() {
        code.bytes.extend([0x83, 0xc4, (args.len() * 4) as u8]);
    }
}
pub fn crt_text_probe(arch: Architecture, kind: CrtTextFixture) -> Vec<u8> {
    let wide = arch == Architecture::X64;
    let mut root = Code::new(arch, 0x1000);
    let base = root.base();
    let at = |rva: u64| base + rva;
    root.prologue();
    match kind {
        CrtTextFixture::Text => {
            // strcat appends and keeps the destination pointer.
            cdecl(&mut root, wide, 0, &[V(at(DEST_A)), V(at(BETA))]);
            expect_pointer(&mut root, wide, at(DEST_A));
            bytes_at(
                &mut root,
                &[(0, b'a'), (4, b'a'), (5, b'B'), (8, b'A'), (9, 0)],
            );
            // strncat appends exactly the requested count.
            cdecl(&mut root, wide, 2, &[V(at(DEST_A)), V(at(ALPHA)), V(2)]);
            bytes_at(&mut root, &[(9, b'a'), (10, b'l'), (11, 0)]);
            // wcscat works in code units.
            cdecl(&mut root, wide, 1, &[V(at(W_DEST)), V(at(W_PHA))]);
            expect_pointer(&mut root, wide, at(W_DEST));
            bytes_at(
                &mut root,
                &[(0, b'a'), (2, b'l'), (4, b'p'), (8, b'a'), (10, 0)],
            );
            // strncat_s refuses a result that cannot fit, then succeeds.
            cdecl(
                &mut root,
                wide,
                3,
                &[V(at(DEST_B)), V(4), V(at(ALPHA)), V(5)],
            );
            root.expect(34);
            cdecl(
                &mut root,
                wide,
                3,
                &[V(at(DEST_B)), V(16), V(at(ALPHA)), V(5)],
            );
            root.expect(0);
            address_of(&mut root, wide, at(DEST_B));
            bytes_at(&mut root, &[(0, b'a'), (4, b'a'), (5, 0)]);
            // strncpy_s reports ERANGE, success and STRUNCATE in turn.
            cdecl(
                &mut root,
                wide,
                4,
                &[V(at(DEST_C)), V(4), V(at(ALPHA)), V(5)],
            );
            root.expect(34);
            cdecl(
                &mut root,
                wide,
                4,
                &[V(at(DEST_C)), V(8), V(at(ALPHA)), V(5)],
            );
            root.expect(0);
            cdecl(
                &mut root,
                wide,
                4,
                &[V(at(DEST_C)), V(4), V(at(ALPHA)), V(u64::MAX)],
            );
            root.expect(80);
            // Spans and searches.
            cdecl(&mut root, wide, 5, &[V(at(ALPHA)), V(at(VOWELS))]);
            root.expect(0);
            cdecl(&mut root, wide, 5, &[V(at(BETA)), V(at(VOWELS))]);
            root.expect(4);
            cdecl(&mut root, wide, 6, &[V(at(W_ALPHA)), V(at(W_VOWELS))]);
            root.expect(0);
            cdecl(&mut root, wide, 7, &[V(at(W_ALPHA)), V(at(W_VOWELS))]);
            root.expect(1);
            cdecl(&mut root, wide, 8, &[V(at(DEST_A)), V(at(BETA))]);
            expect_pointer(&mut root, wide, at(DEST_A) + 5);
            cdecl(&mut root, wide, 9, &[V(at(W_ALPHA)), V(at(W_PHA))]);
            expect_pointer(&mut root, wide, at(W_ALPHA) + 4);
            // In-place case mapping.
            cdecl(&mut root, wide, 10, &[V(at(NARROW_MIXED))]);
            expect_pointer(&mut root, wide, at(NARROW_MIXED));
            bytes_at(&mut root, &[(0, b'm'), (2, b'x'), (4, b'd'), (5, 0)]);
            cdecl(&mut root, wide, 11, &[V(at(NARROW_MIXED))]);
            bytes_at(&mut root, &[(0, b'M'), (2, b'X'), (4, b'D'), (5, 0)]);
            cdecl(&mut root, wide, 12, &[V(at(W_MIXED))]);
            bytes_at(&mut root, &[(0, b'M'), (2, b'I'), (4, b'X'), (6, 0)]);
        }
        CrtTextFixture::Fold => {
            for index in [0usize, 1] {
                cdecl(&mut root, wide, index, &[V(at(ALPHA)), V(at(UPPER))]);
                root.expect(0);
                cdecl(&mut root, wide, index, &[V(at(ALPHA)), V(at(BETA))]);
                root.expect(0xffffffff);
            }
            cdecl(&mut root, wide, 2, &[V(at(W_ALPHA)), V(at(W_UPPER))]);
            root.expect(0);
            cdecl(&mut root, wide, 3, &[V(at(ALPHA)), V(at(UPPER)), V(5)]);
            root.expect(0);
            cdecl(&mut root, wide, 4, &[V(at(W_ALPHA)), V(at(W_UPPER)), V(3)]);
            root.expect(0);
            cdecl(&mut root, wide, 5, &[V(at(ALPHA)), V(at(UPPER)), V(5)]);
            root.expect(0);
            cdecl(&mut root, wide, 5, &[V(at(ALPHA)), V(at(BETA)), V(1)]);
            root.expect(0xffffffff);
            // Case mapping stays inside the invariant range.
            cdecl(&mut root, wide, 6, &[V(u64::from(b'A'))]);
            root.expect(u32::from(b'a'));
            cdecl(&mut root, wide, 7, &[V(u64::from(b'a'))]);
            root.expect(u32::from(b'A'));
            // A bracket has no case: the frozen reference would set bit five.
            cdecl(&mut root, wide, 6, &[V(0x5b)]);
            root.expect(0x5b);
            cdecl(&mut root, wide, 8, &[V(0x3b1)]);
            root.expect(0x391);
            cdecl(&mut root, wide, 9, &[V(u64::from(b'7'))]);
            root.expect(1);
            cdecl(&mut root, wide, 9, &[V(u64::from(b'x'))]);
            root.expect(0);
        }
        CrtTextFixture::Convert => {
            cdecl(&mut root, wide, 0, &[V(at(DIGITS))]);
            root.expect(123);
            cdecl(&mut root, wide, 0, &[V(at(NEGATIVE))]);
            root.expect(0xffffffd3);
            cdecl(&mut root, wide, 1, &[V(255), V(at(DEST_A)), V(16)]);
            expect_pointer(&mut root, wide, at(DEST_A));
            bytes_at(&mut root, &[(0, b'f'), (1, b'f'), (2, 0)]);
            cdecl(&mut root, wide, 2, &[V(0xfffffff7), V(at(DEST_B)), V(10)]);
            bytes_at(&mut root, &[(0, b'-'), (1, b'9'), (2, 0)]);
            cdecl(&mut root, wide, 3, &[V(255), V(at(W_DEST)), V(16)]);
            bytes_at(&mut root, &[(0, b'f'), (2, b'f'), (4, 0)]);
            cdecl(&mut root, wide, 4, &[V(0xffffffff), V(at(W_DEST)), V(10)]);
            bytes_at(&mut root, &[(0, b'4'), (18, b'5'), (20, 0)]);
            cdecl(&mut root, wide, 5, &[V(at(DEST_C)), V(at(W_ALPHA)), V(10)]);
            root.expect(5);
            address_of(&mut root, wide, at(DEST_C));
            bytes_at(&mut root, &[(0, b'a'), (4, b'a'), (5, 0)]);
            cdecl(
                &mut root,
                wide,
                6,
                &[V(at(COUNT)), V(at(W_DEST)), V(8), V(at(ALPHA)), V(5)],
            );
            root.expect(0);
            dword_at(&mut root, at(COUNT), 6);
            address_of(&mut root, wide, at(W_DEST));
            bytes_at(&mut root, &[(0, b'a'), (2, b'l'), (8, b'a'), (10, 0)]);
            cdecl(&mut root, wide, 7, &[V(at(W_DEST)), V(at(ALPHA)), V(2)]);
            root.expect(1);
            address_of(&mut root, wide, at(W_DEST));
            bytes_at(&mut root, &[(0, b'a'), (1, 0)]);
            // The legacy two-argument tokenizer keeps its own continuation.
            cdecl(&mut root, wide, 8, &[V(at(W_TOKENS)), V(at(W_SEPARATORS))]);
            expect_pointer(&mut root, wide, at(W_TOKENS));
            bytes_at(&mut root, &[(0, b'a'), (2, 0)]);
            cdecl(&mut root, wide, 8, &[V(0), V(at(W_SEPARATORS))]);
            expect_pointer(&mut root, wide, at(W_TOKENS) + 4);
            cdecl(&mut root, wide, 8, &[V(0), V(at(W_SEPARATORS))]);
            expect_pointer(&mut root, wide, at(W_TOKENS) + 8);
            cdecl(&mut root, wide, 8, &[V(0), V(at(W_SEPARATORS))]);
            root.expect(0);
        }
        CrtTextFixture::ClockText => {
            // The CRT date and time strings come from the run's own persona
            // clock, so the control pins their exact shape, not one date.
            cdecl(&mut root, wide, 0, &[V(at(DEST_A))]);
            expect_pointer(&mut root, wide, at(DEST_A));
            bytes_at(&mut root, &[(2, b'/'), (5, b'/'), (8, 0)]);
            for offset in [0, 1, 3, 4, 6, 7] {
                digit_at(&mut root, offset);
            }
            cdecl(&mut root, wide, 1, &[V(at(DEST_B))]);
            bytes_at(&mut root, &[(2, b':'), (5, b':'), (8, 0)]);
            for offset in [0, 1, 3, 4, 6, 7] {
                digit_at(&mut root, offset);
            }
        }
        CrtTextFixture::Clock => {
            // Locale categories are process state; only C and the persona
            // locale exist.
            cdecl(&mut root, wide, 2, &[V(0), V(at(C_LOCALE))]);
            nonzero(&mut root);
            bytes_at(&mut root, &[(0, b'C'), (1, 0)]);
            cdecl(&mut root, wide, 2, &[V(5), V(0)]);
            bytes_at(&mut root, &[(0, b'C'), (1, 0)]);
            cdecl(&mut root, wide, 2, &[V(0), V(at(PERSONA))]);
            bytes_at(&mut root, &[(0, b'e'), (2, b'-'), (4, b'S'), (5, 0)]);
            cdecl(&mut root, wide, 2, &[V(2), V(0)]);
            bytes_at(&mut root, &[(0, b'e'), (4, b'S'), (5, 0)]);
            cdecl(&mut root, wide, 3, &[V(0), V(at(W_C_LOCALE))]);
            bytes_at(&mut root, &[(0, b'C'), (2, 0)]);
        }
        CrtTextFixture::BadLocale => {
            cdecl(&mut root, wide, 2, &[V(0), V(at(UNSUPPORTED))]);
        }
        CrtTextFixture::NullString => {
            cdecl(&mut root, wide, 0, &[V(0), V(at(ALPHA))]);
        }
    }
    root.epilogue(1, 0);
    let names: &[&str] = match kind {
        CrtTextFixture::Text => &[
            "strcat",
            "wcscat",
            "strncat",
            "strncat_s",
            "strncpy_s",
            "strcspn",
            "wcscspn",
            "wcsspn",
            "strstr",
            "wcsstr",
            "_strlwr",
            "_strupr",
            "_wcsupr",
        ],
        CrtTextFixture::Fold => &[
            "_stricmp",
            "_strcmpi",
            "_wcsicmp",
            "_strnicmp",
            "_wcsnicmp",
            "_memicmp",
            "tolower",
            "toupper",
            "towupper",
            "isdigit",
        ],
        CrtTextFixture::Convert => &[
            "atoi",
            "_itoa",
            "_ltoa",
            "_itow",
            "_ultow",
            "wcstombs",
            "mbstowcs_s",
            "mbtowc",
            "wcstok",
        ],
        CrtTextFixture::Clock | CrtTextFixture::ClockText | CrtTextFixture::BadLocale => {
            &["_strdate", "_strtime", "setlocale", "_wsetlocale"]
        }
        CrtTextFixture::NullString => &["strcat"],
    };
    let mut bytes = m4_custom_probe(arch, names, &root.finish(), &[], &[]);
    bytes[0x1440..0x1450].fill(0);
    bytes[0x1440..0x144b].copy_from_slice(b"msvcrt.dll\0");
    let wide_text = |text: &str| -> Vec<u8> {
        let mut out: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        out.extend([0, 0]);
        out
    };
    for (rva, value) in [
        (ALPHA, b"alpha\0".to_vec()),
        (BETA, b"BETA\0".to_vec()),
        (VOWELS, b"aeiou\0".to_vec()),
        (PHA, b"pha\0".to_vec()),
        (W_ALPHA, wide_text("alpha")),
        (W_VOWELS, wide_text("aeiou")),
        (W_PHA, wide_text("pha")),
        (DIGITS, b"123\0".to_vec()),
        (NEGATIVE, b"-45\0".to_vec()),
        (UPPER, b"ALPHA\0".to_vec()),
        (W_UPPER, wide_text("ALPHA")),
        (C_LOCALE, b"C\0".to_vec()),
        (W_C_LOCALE, wide_text("C")),
        (PERSONA, b"en-US\0".to_vec()),
        (UNSUPPORTED, b"ja-JP\0".to_vec()),
        (W_TOKENS, wide_text("a,b;c")),
        (W_SEPARATORS, wide_text(",;")),
        (NARROW_MIXED, b"MiXeD\0".to_vec()),
        (W_MIXED, wide_text("mix")),
        (DEST_A, b"alpha\0".to_vec()),
        (DEST_B, b"\0".to_vec()),
        (DEST_C, b"\0".to_vec()),
        (W_DEST, wide_text("al")),
    ] {
        let raw = (rva - 0xe00) as usize;
        bytes[raw..raw + value.len()].copy_from_slice(&value);
    }
    bytes
}
