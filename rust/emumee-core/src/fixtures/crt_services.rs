//! Guest instruction assertions for narrow CRT formatting, scanning and the
//! remaining CRT runtime services.
use super::m4::M4Code as Code;
use super::winhttp::Arg::Value as V;
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrtServiceFixture {
    Format,
    Scan,
    Services,
    /// Source-only: the CRT epoch seconds follow the run's own persona clock,
    /// so a contained replay cannot reproduce the same value.
    EpochTime,
    ThrowUnsupported,
    FloatUnsupported,
    ControlUnsupported,
}

const FORMAT_A: u64 = 0x3c00;
const FORMAT_B: u64 = 0x3c20;
const FORMAT_C: u64 = 0x3c30;
const W_FORMAT: u64 = 0x3c40;
const ALPHA: u64 = 0x3c60;
const INPUT: u64 = 0x3c70;
const SCAN_FORMAT: u64 = 0x3c80;
const COMMAND: u64 = 0x3c90;
const LIST: u64 = 0x3cc0;
const DEST_A: u64 = 0x3e00;
const DEST_B: u64 = 0x3e40;
const DEST_C: u64 = 0x3e80;
const W_DEST: u64 = 0x3f00;
const NUMBER: u64 = 0x3f80;
const TEXT: u64 = 0x3f90;
const CONTROL: u64 = 0x3fb0;
const TIME: u64 = 0x3fc0;
const SAVED: u64 = 0x3fd0;

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
/// Loads the dword at an absolute address through a register, so the same
/// encoding works on both architectures.
fn load_through(code: &mut Code, wide: bool, address: u64) {
    if wide {
        code.bytes.extend([0x48, 0xb9]);
        code.bytes.extend(address.to_le_bytes());
    } else {
        code.bytes.push(0xb9);
        code.bytes.extend((address as u32).to_le_bytes());
    }
    code.bytes.extend([0x8b, 1]);
}
/// Compares the accumulator with the dword at an absolute address.
fn equals_dword_at(code: &mut Code, wide: bool, address: u64) {
    if wide {
        code.bytes.extend([0x48, 0xba]);
        code.bytes.extend(address.to_le_bytes());
    } else {
        code.bytes.push(0xba);
        code.bytes.extend((address as u32).to_le_bytes());
    }
    code.bytes.extend([0x3b, 2, 0x74, 1, 0xcc]);
}
/// Requires the accumulator to fall inside an inclusive unsigned range.
fn within(code: &mut Code, low: u32, high: u32) {
    code.bytes.push(0x3d);
    code.bytes.extend(low.to_le_bytes());
    code.bytes.extend([0x73, 1, 0xcc]);
    code.bytes.push(0x3d);
    code.bytes.extend(high.to_le_bytes());
    code.bytes.extend([0x76, 1, 0xcc]);
}
fn cdecl(code: &mut Code, wide: bool, index: usize, args: &[super::winhttp::Arg]) {
    code.call(index, args);
    if !wide && !args.is_empty() {
        code.bytes.extend([0x83, 0xc4, (args.len() * 4) as u8]);
    }
}
pub fn crt_service_probe(arch: Architecture, kind: CrtServiceFixture) -> Vec<u8> {
    let wide = arch == Architecture::X64;
    let width = arch.width() as u64;
    let mut root = Code::new(arch, 0x1000);
    let base = root.base();
    let at = |rva: u64| base + rva;
    root.prologue();
    match kind {
        CrtServiceFixture::Format => {
            // sprintf renders every modeled conversion and returns the length.
            cdecl(
                &mut root,
                wide,
                0,
                &[V(at(DEST_A)), V(at(FORMAT_A)), V(42), V(at(ALPHA))],
            );
            root.expect(12);
            address_of(&mut root, wide, at(DEST_A));
            bytes_at(
                &mut root,
                &[(0, b'n'), (2, b'4'), (3, b'2'), (7, b'a'), (11, b'a'), (12, 0)],
            );
            // A counted write that does not fit reports truncation.
            cdecl(
                &mut root,
                wide,
                1,
                &[V(at(DEST_B)), V(4), V(at(FORMAT_B)), V(12345)],
            );
            root.expect(0xffffffff);
            address_of(&mut root, wide, at(DEST_B));
            bytes_at(&mut root, &[(0, b'1'), (3, b'4')]);
            cdecl(
                &mut root,
                wide,
                1,
                &[V(at(DEST_B)), V(16), V(at(FORMAT_C)), V(255)],
            );
            root.expect(2);
            address_of(&mut root, wide, at(DEST_B));
            bytes_at(&mut root, &[(0, b'f'), (1, b'f'), (2, 0)]);
            // The variadic-list forms read their arguments from guest memory.
            cdecl(
                &mut root,
                wide,
                2,
                &[V(at(DEST_C)), V(16), V(at(FORMAT_A)), V(at(LIST))],
            );
            root.expect(12);
            address_of(&mut root, wide, at(DEST_C));
            bytes_at(&mut root, &[(0, b'n'), (2, b'4'), (3, b'2'), (7, b'a')]);
            cdecl(
                &mut root,
                wide,
                3,
                &[V(at(W_DEST)), V(16), V(at(W_FORMAT)), V(9)],
            );
            root.expect(1);
            address_of(&mut root, wide, at(W_DEST));
            bytes_at(&mut root, &[(0, b'9'), (2, 0)]);
        }
        CrtServiceFixture::Scan => {
            cdecl(
                &mut root,
                wide,
                4,
                &[V(at(INPUT)), V(at(SCAN_FORMAT)), V(at(NUMBER)), V(at(TEXT))],
            );
            root.expect(2);
            dword_at(&mut root, at(NUMBER), 42);
            address_of(&mut root, wide, at(TEXT));
            bytes_at(&mut root, &[(0, b'a'), (1, b'b'), (2, b'c'), (3, 0)]);
            // A format that cannot match anything assigns nothing.
            cdecl(
                &mut root,
                wide,
                4,
                &[V(at(ALPHA)), V(at(SCAN_FORMAT)), V(at(NUMBER)), V(at(TEXT))],
            );
            root.expect(0);
        }
        CrtServiceFixture::Services => {
            // The documented Microsoft generator, not a counter.
            cdecl(&mut root, wide, 1, &[V(1)]);
            cdecl(&mut root, wide, 0, &[]);
            root.expect(41);
            cdecl(&mut root, wide, 0, &[]);
            root.expect(18467);
            cdecl(&mut root, wide, 1, &[V(1)]);
            cdecl(&mut root, wide, 0, &[]);
            root.expect(41);
            cdecl(&mut root, wide, 6, &[V(0xfffffffb)]);
            root.expect(5);
            cdecl(&mut root, wide, 6, &[V(5)]);
            root.expect(5);
            // Known signals report SIG_IGN; everything else SIG_ERR.
            cdecl(&mut root, wide, 2, &[V(2), V(1)]);
            root.expect(1);
            cdecl(&mut root, wide, 2, &[V(99), V(0)]);
            root.expect(0xffffffff);
            // No command processor exists.
            cdecl(&mut root, wide, 3, &[V(at(COMMAND))]);
            root.expect(0xffffffff);
            // Elapsed milliseconds start at the first reading.
            cdecl(&mut root, wide, 5, &[]);
            root.expect(0);
            // A query reports the default control word for this architecture.
            cdecl(&mut root, wide, 7, &[V(0), V(0)]);
            root.expect(if wide { 0x8001f } else { 0x9001f });
            cdecl(&mut root, wide, 8, &[V(at(CONTROL)), V(0), V(0)]);
            root.expect(0);
            dword_at(&mut root, at(CONTROL), if wide { 0x8001f } else { 0x9001f });
            // Exception filters decline or accept exactly as the frozen
            // handlers do, and no exception is ever in flight.
            cdecl(&mut root, wide, 9, &[V(0), V(0)]);
            root.expect(0);
            cdecl(&mut root, wide, 10, &[V(0), V(0)]);
            root.expect(1);
            cdecl(&mut root, wide, 11, &[]);
            root.expect(0);
        }
        CrtServiceFixture::EpochTime => {
            // The CRT epoch seconds come from the run's own persona clock. The
            // control proves the value is a plausible epoch second, that the
            // written output matches the returned value, and that a second
            // reading agrees.
            cdecl(&mut root, wide, 4, &[V(at(TIME))]);
            within(&mut root, 1_600_000_000, 4_000_000_000);
            root.store(at(SAVED));
            load_through(&mut root, wide, at(TIME));
            equals_dword_at(&mut root, wide, at(SAVED));
            cdecl(&mut root, wide, 4, &[V(0)]);
            equals_dword_at(&mut root, wide, at(SAVED));
        }
        CrtServiceFixture::ThrowUnsupported => {
            root.call(9, &[V(0), V(0)]);
        }
        CrtServiceFixture::FloatUnsupported => {
            cdecl(&mut root, wide, 10, &[]);
        }
        CrtServiceFixture::ControlUnsupported => {
            cdecl(&mut root, wide, 7, &[V(0x200), V(0x300)]);
        }
    }
    root.epilogue(1, 0);
    let names: &[&str] = match kind {
        CrtServiceFixture::Format | CrtServiceFixture::Scan => {
            &["sprintf", "_snprintf", "_vsnprintf", "_snwprintf", "sscanf"]
        }
        CrtServiceFixture::Services
        | CrtServiceFixture::EpochTime
        | CrtServiceFixture::ThrowUnsupported
        | CrtServiceFixture::FloatUnsupported
        | CrtServiceFixture::ControlUnsupported => &[
            "rand",
            "srand",
            "signal",
            "system",
            "time",
            "clock",
            "abs",
            "_controlfp",
            "_controlfp_s",
            "_XcptFilter",
            "_seh_filter_exe",
            "__current_exception",
            "_ftol",
        ],
    };
    let names: Vec<&str> = if kind == CrtServiceFixture::ThrowUnsupported {
        let mut names = names.to_vec();
        names[9] = "_CxxThrowException";
        names
    } else if kind == CrtServiceFixture::FloatUnsupported {
        let mut names = names.to_vec();
        names[10] = "_ftol";
        names
    } else {
        names.to_vec()
    };
    let mut bytes = m4_custom_probe(arch, &names, &root.finish(), &[], &[]);
    bytes[0x1440..0x1450].fill(0);
    bytes[0x1440..0x144b].copy_from_slice(b"msvcrt.dll\0");
    let wide_text = |text: &str| -> Vec<u8> {
        let mut out: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        out.extend([0, 0]);
        out
    };
    // The variadic list holds pointer-width slots, as the real list does.
    let mut list = Vec::new();
    for value in [42u64, ALPHA + if arch == Architecture::X64 { 0x140000000 } else { 0x400000 }] {
        list.extend_from_slice(&value.to_le_bytes()[..width as usize]);
    }
    for (rva, value) in [
        (FORMAT_A, b"n=%d s=%s\0".to_vec()),
        (FORMAT_B, b"%d\0".to_vec()),
        (FORMAT_C, b"%x\0".to_vec()),
        (W_FORMAT, wide_text("%d")),
        (ALPHA, b"alpha\0".to_vec()),
        (INPUT, b"42 abc\0".to_vec()),
        (SCAN_FORMAT, b"%d %s\0".to_vec()),
        (COMMAND, b"cmd.exe /c echo hi\0".to_vec()),
        (LIST, list),
    ] {
        let raw = (rva - 0xe00) as usize;
        bytes[raw..raw + value.len()].copy_from_slice(&value);
    }
    bytes
}
