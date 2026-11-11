use super::*;

fn jump(code: &mut Vec<u8>, condition: u8) -> usize {
    code.extend([0x0f, condition]);
    let at = code.len();
    code.extend([0; 4]);
    at
}
fn patch(code: &mut [u8], at: usize, target: usize) {
    code[at..at + 4].copy_from_slice(&((target as i32) - (at as i32 + 4)).to_le_bytes());
}
fn rex(code: &mut Vec<u8>, wide: bool) {
    if wide {
        code.push(0x48);
    }
}

/// Find kernel32 through actual PEB.Ldr links, parse its PE named exports,
/// compare the resolved entry to the static IAT, then call it.
pub fn m3_provider_probe(architecture: Architecture) -> Vec<u8> {
    let wide = architecture == Architecture::X64;
    let base = if wide { 0x140000000u64 } else { 0x400000 };
    let mut bytes = user_bootstrap_probe(architecture, BootstrapFixture::Basic, false);
    let mut code = vec![0x53, 0x56, 0x57];
    if wide {
        code.extend([0x48, 0x83, 0xec, 0x20]);
    }
    segment(&mut code, wide, if wide { 0x60 } else { 0x30 });
    rex(&mut code, wide);
    code.extend([0x8b, 0x40, if wide { 0x18 } else { 0x0c }]);
    rex(&mut code, wide);
    code.extend([0x8d, 0x78, if wide { 0x10 } else { 0x0c }]); // head
    rex(&mut code, wide);
    code.extend([0x8b, 0x37]); // first link
    let module_loop = code.len();
    rex(&mut code, wide);
    code.extend([0x39, 0xfe, 0x75, 1, 0xcc]); // head reached => missing
    rex(&mut code, wide);
    code.extend([0x8b, 0x46, if wide { 0x60 } else { 0x30 }]);
    let mut next = vec![];
    for (offset, word) in ["ke", "rn", "el", "32"].iter().enumerate() {
        code.extend([0x81, 0x78, (offset * 4) as u8]);
        for unit in word.encode_utf16() {
            code.extend(unit.to_le_bytes());
        }
        next.push(jump(&mut code, 0x85));
    }
    let found = jump(&mut code, 0x84);
    let advance = code.len();
    for at in next {
        patch(&mut code, at, advance);
    }
    rex(&mut code, wide);
    code.extend([0x8b, 0x36]);
    code.extend([0xe9]);
    let back = code.len();
    code.extend([0; 4]);
    patch(&mut code, back, module_loop);
    let target = code.len();
    patch(&mut code, found, target);
    rex(&mut code, wide);
    code.extend([0x8b, 0x5e, if wide { 0x30 } else { 0x18 }]); // image base
    code.extend([0x8b, 0x43, 0x3c]);
    rex(&mut code, wide);
    code.extend([0x01, 0xd8]);
    code.extend([0x8b, 0x80]);
    code.extend((if wide { 0x88u32 } else { 0x78 }).to_le_bytes());
    rex(&mut code, wide);
    code.extend([0x01, 0xd8]);
    code.extend([0x8b, 0x48, 24, 0x8b, 0x50, 32]);
    rex(&mut code, wide);
    code.extend([0x01, 0xda]);
    code.extend([0x8b, 0x78, 36]);
    rex(&mut code, wide);
    code.extend([0x01, 0xdf]);
    code.extend([0x8b, 0x70, 28]);
    rex(&mut code, wide);
    code.extend([0x01, 0xde]);
    let name_loop = code.len();
    code.extend([0x85, 0xc9, 0x75, 1, 0xcc, 0x83, 0xe9, 1, 0x8b, 4, 0x8a]);
    rex(&mut code, wide);
    code.extend([0x01, 0xd8]);
    for (index, chunk) in b"GetCurrentProcessId\0".chunks(4).enumerate() {
        code.extend([0x81, 0x78, (index * 4) as u8]);
        code.extend(chunk);
        let at = jump(&mut code, 0x85);
        patch(&mut code, at, name_loop);
    }
    code.extend([0x0f, 0xb7, 4, 0x4f, 0x8b, 4, 0x86]);
    rex(&mut code, wide);
    code.extend([0x01, 0xd8]);
    if wide {
        code.extend([0x48, 0xba]);
        code.extend((base + 0x2088).to_le_bytes());
    } else {
        code.push(0xba);
        code.extend(((base + 0x2084) as u32).to_le_bytes());
    }
    rex(&mut code, wide);
    code.extend([0x3b, 2, 0x74, 1, 0xcc, 0xff, 0xd0]);
    code.push(0x3d);
    code.extend(1024u32.to_le_bytes());
    checked(&mut code);
    code.extend([0xb8, 1, 0, 0, 0]);
    if wide {
        code.extend([0x48, 0x83, 0xc4, 0x20]);
    }
    code.extend([0x5f, 0x5e, 0x5b, 0xc3]);
    assert!(code.len() < 0x1000);
    bytes[0x200..0x1200].fill(0);
    bytes[0x200..0x200 + code.len()].copy_from_slice(&code);
    bytes
}

fn segment(code: &mut Vec<u8>, wide: bool, offset: u32) {
    code.extend(if wide {
        vec![0x65, 0x48, 0x8b, 4, 0x25]
    } else {
        vec![0x64, 0xa1]
    });
    code.extend(offset.to_le_bytes());
}
fn block(code: &mut Vec<u8>, wide: bool, index: u64) {
    segment(code, wide, if wide { 0x58 } else { 0x2c });
    if wide {
        code.extend([0x48, 0xb9]);
        code.extend(index.to_le_bytes());
        code.extend([0x8b, 9, 0x48, 0x8b, 4, 0xc8]);
    } else {
        code.extend([0x8b, 0x0d]);
        code.extend((index as u32).to_le_bytes());
        code.extend([0x8b, 4, 0x88]);
    }
}
fn checked(code: &mut Vec<u8>) {
    code.extend([0x74, 1, 0xcc]);
}
pub fn m3_storage_probe(architecture: Architecture, readonly_index: bool) -> Vec<u8> {
    let wide = architecture == Architecture::X64;
    let width = architecture.width();
    let base = if wide { 0x140000000u64 } else { 0x400000 };
    let mut bytes = user_bootstrap_probe(architecture, BootstrapFixture::Basic, false);
    let directories = 0x98 + if wide { 112 } else { 96 };
    put32(&mut bytes, directories + 9 * 8, 0x3e00);
    put32(
        &mut bytes,
        directories + 9 * 8 + 4,
        if wide { 40 } else { 24 },
    );
    for (ordinal, address) in [base + 0x3d00, base + 0x3d04, base + 0x3d40, base + 0x3d80]
        .into_iter()
        .enumerate()
    {
        bytes[0x3000 + ordinal * width..0x3000 + (ordinal + 1) * width]
            .copy_from_slice(&address.to_le_bytes()[..width]);
    }
    put32(&mut bytes, 0x3000 + 4 * width, 20);
    put32(&mut bytes, 0x3004 + 4 * width, 0x00500000);
    put32(&mut bytes, 0x2f00, 0x12345678);
    bytes[0x2f80..0x2f80 + width].copy_from_slice(&(base + 0x1f00).to_le_bytes()[..width]);
    let mut callback = vec![];
    block(&mut callback, wide, base + 0x3d40);
    callback.extend([0xc7, 0x40, 4]);
    callback.extend(0x55667788u32.to_le_bytes());
    callback.extend(if wide { vec![0xc3] } else { vec![0xc2, 12, 0] });
    assert!(bytes[0xf00..0x1200].iter().all(|byte| *byte == 0));
    bytes[0x1100..0x1100 + callback.len()].copy_from_slice(&callback);
    let mut entry = vec![];
    block(&mut entry, wide, base + 0x3d40);
    entry.extend([0xa8, 15]);
    checked(&mut entry);
    entry.extend([0x81, 0x38]);
    entry.extend(0x12345678u32.to_le_bytes());
    checked(&mut entry);
    entry.extend([0x81, 0x78, 4]);
    entry.extend(0x55667788u32.to_le_bytes());
    checked(&mut entry);
    for offset in [8, 12, 16, 20] {
        entry.extend([0x83, 0x78, offset, 0]);
        checked(&mut entry);
    }
    segment(&mut entry, wide, if wide { 0x60 } else { 0x30 });
    if wide {
        entry.push(0x48);
    }
    entry.extend([0x8b, 0x40, if wide { 0x18 } else { 0xc }]);
    if wide {
        entry.push(0x48);
    }
    entry.extend([0x85, 0xc0, 0x75, 1, 0xcc]);
    if wide {
        entry.push(0x48);
    }
    entry.extend([0x8b, 0x40, if wide { 0x10 } else { 0xc }]);
    if wide {
        entry.push(0x48);
    }
    entry.extend([0x8b, 0x40, (6 * width) as u8]);
    if wide {
        entry.extend([0x48, 0xb9]);
        entry.extend(base.to_le_bytes());
        entry.extend([0x48, 0x39, 0xc8]);
    } else {
        entry.push(0x3d);
        entry.extend((base as u32).to_le_bytes());
    }
    checked(&mut entry);
    entry.push(0xe9);
    entry.extend((0x1000i32 - (0x1d00 + entry.len() as i32 + 4)).to_le_bytes());
    bytes[0xf00..0xf00 + entry.len()].copy_from_slice(&entry);
    put32(&mut bytes, 0x98 + 16, 0x1d00);
    if readonly_index {
        put32(
            &mut bytes,
            0x98 + if wide { 0xf0 } else { 0xe0 } + 76,
            0x40000040,
        );
    }
    bytes
}
