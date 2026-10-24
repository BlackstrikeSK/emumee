//! A real registered C exception scope around the generated DbgPrompt call.
use super::*;

pub(super) fn probe(read_only: bool) -> Vec<u8> {
    let mut image = counted_driver(Architecture::X64, 1);
    image.resize(0x2200, 0);
    let table = 0x98 + 0xf0;
    for (i, raw) in [(0, 0x200), (1, 0x1200)] {
        let s = table + i * 40;
        put32(&mut image, s + 8, 0x1000);
        put32(&mut image, s + 16, 0x1000);
        put32(&mut image, s + 20, raw);
    }
    image[0x200..0x1200].fill(0xcc);
    image[0x1200..].fill(0);
    let dd = 0x98 + 112;
    for (at, value) in [
        (dd + 8, 0x2000),
        (dd + 12, 40),
        (dd + 24, 0x2c00),
        (dd + 28, 12),
    ] {
        put32(&mut image, at, value);
    }
    for (i, v) in [0x2180, 0, 0, 0x2040, 0x2080].into_iter().enumerate() {
        put32(&mut image, 0x1200 + 4 * i, v);
    }
    image[0x1240..0x1240 + 13].copy_from_slice(b"ntoskrnl.exe\0");
    for (i, (rva, name)) in [(0x2500, "DbgPrompt"), (0x2540, "__C_specific_handler")]
        .into_iter()
        .enumerate()
    {
        put64(&mut image, 0x1380 + 8 * i, rva);
        put64(&mut image, 0x1280 + 8 * i, rva);
        let at = rva as usize - 0x2000 + 0x1202;
        image[at..at + name.len()].copy_from_slice(name.as_bytes());
    }
    image[0x1d00..0x1d0f].copy_from_slice(b"Rust no input?\0");
    image[0x1d40..0x1d60].fill(0x52);
    let mut code = vec![0x48, 0x83, 0xec, 0x48];
    for (prefix, target) in [
        ([0x48, 0x8d, 0x0d], 0x2b00i32),
        ([0x48, 0x8d, 0x15], if read_only { 0x1000 } else { 0x2b40 }),
    ] {
        code.extend(prefix);
        code.extend((target - (0x1000 + code.len() + 4) as i32).to_le_bytes());
    }
    code.extend([0x41, 0xb8, 32, 0, 0, 0]);
    let call_rva = 0x1000 + code.len() as u32;
    code.extend([0xff, 0x15]);
    code.extend((0x2080i32 - (0x1000 + code.len() + 4) as i32).to_le_bytes());
    // A normal return must fail this test; only the registered catch returns.
    code.extend([0x90, 0x0f, 0x0b]);
    let catch = 0x1000 + code.len() as u32;
    code.push(0x3d);
    code.extend(0x80000003u32.to_le_bytes());
    code.extend([0x74, 2, 0x0f, 0x0b]);
    code.extend([0x8b, 0x05]);
    code.extend((0x2b40i32 - (0x1000 + code.len() + 4) as i32).to_le_bytes());
    code.extend([0x48, 0x83, 0xc4, 0x48, 0xc3]);
    let end = 0x1000 + code.len() as u32;
    image[0x200..0x200 + code.len()].copy_from_slice(&code);
    image[0xc00..0xc06].copy_from_slice(&[0xff, 0x25, 0x82, 6, 0, 0]); // JMP [IAT 2088]
    for (i, v) in [0x1000, end, 0x2c40].into_iter().enumerate() {
        put32(&mut image, 0x1e00 + i * 4, v);
    }
    image[0x1e40..0x1e48].copy_from_slice(&[0x19, 4, 1, 0, 4, 0x82, 0, 0]);
    for (i, v) in [0x1a00, 1, call_rva, catch, 1, catch]
        .into_iter()
        .enumerate()
    {
        put32(&mut image, 0x1e48 + 4 * i, v);
    }
    image
}
