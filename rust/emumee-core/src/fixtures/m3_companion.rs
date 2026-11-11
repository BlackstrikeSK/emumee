//! Supplied DLL proving its own static TLS through process/thread callbacks.
use super::*;

/// Add an ordinary named import to an owned single-import-directory root.
pub fn m3_link_tls_companion(architecture: Architecture, mut root: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
    let width = architecture.width();
    let directories = 0x98 + if width == 8 { 112 } else { 96 };
    put32(&mut root, directories + 12, 60);
    root[0x1214..0x123c].fill(0);
    put32(&mut root, 0x1214, 0x3f40);
    put32(&mut root, 0x1220, 0x3f80);
    put32(&mut root, 0x1224, 0x3f60);
    root[0x3140..0x3140 + width].copy_from_slice(&0x3fc0u64.to_le_bytes()[..width]);
    root[0x3160..0x3160 + width].copy_from_slice(&0x3fc0u64.to_le_bytes()[..width]);
    root[0x3180..0x3188].copy_from_slice(b"tls.dll\0");
    root[0x31c2..0x31c8].copy_from_slice(b"Alpha\0");
    (root, m3_tls_companion(architecture))
}

fn equal(code: &mut Vec<u8>) {
    code.extend([0x74, 1, 0xcc]);
}
fn block(code: &mut Vec<u8>, wide: bool, index: u64) {
    code.extend(if wide {
        vec![0x65, 0x48, 0x8b, 4, 0x25, 0x58, 0, 0, 0, 0x48, 0xb9]
    } else {
        vec![0x64, 0xa1, 0x2c, 0, 0, 0, 0x8b, 0x0d]
    });
    code.extend(
        index.to_le_bytes()[..if wide { 8 } else { 4 }]
            .iter()
            .copied(),
    );
    code.extend(if wide {
        vec![0x8b, 9, 0x48, 0x8b, 4, 0xc8]
    } else {
        vec![0x8b, 4, 0x88]
    });
}
fn id(code: &mut Vec<u8>, wide: bool) {
    code.extend(if wide {
        vec![0x65, 0x8b, 0x0c, 0x25, 0x48, 0, 0, 0]
    } else {
        vec![0x64, 0x8b, 0x0d, 0x24, 0, 0, 0]
    });
}
pub fn m3_tls_companion(architecture: Architecture) -> Vec<u8> {
    companion_at(
        architecture,
        if architecture == Architecture::X64 {
            0x150000000
        } else {
            0x500000
        },
        "tls.dll",
    )
}
pub(super) fn companion_at(architecture: Architecture, base: u64, module: &str) -> Vec<u8> {
    let wide = architecture == Architecture::X64;
    let width = architecture.width();
    let mut bytes =
        crate::provider::image(architecture, base, module, &[("Alpha", base + 0x1300)]).unwrap();
    put32(&mut bytes, 0x98 + 16, 0x1100);
    let sections = 0x98 + if wide { 0xf0 } else { 0xe0 };
    put32(&mut bytes, sections + 40 + 36, 0xc0000040);
    let directories = 0x98 + if wide { 112 } else { 96 };
    put32(&mut bytes, directories + 9 * 8, 0x5000);
    put32(
        &mut bytes,
        directories + 9 * 8 + 4,
        if wide { 40 } else { 24 },
    );
    for (index, value) in [base + 0x5200, base + 0x5204, base + 0x5100, base + 0x5300]
        .iter()
        .enumerate()
    {
        bytes[0x4200 + index * width..0x4200 + (index + 1) * width]
            .copy_from_slice(&value.to_le_bytes()[..width]);
    }
    put32(&mut bytes, 0x4200 + 4 * width, 20);
    put32(&mut bytes, 0x4204 + 4 * width, 0x00500000);
    put32(&mut bytes, 0x4400, 0xabcdef01);
    bytes[0x4500..0x4500 + width].copy_from_slice(&(base + 0x1200).to_le_bytes()[..width]);
    let mut callback = vec![];
    block(&mut callback, wide, base + 0x5100);
    callback.extend([0x81, 0x38]);
    callback.extend(0xabcdef01u32.to_le_bytes());
    equal(&mut callback);
    for offset in [8, 12, 16, 20] {
        callback.extend([0x83, 0x78, offset, 0]);
        equal(&mut callback);
    }
    id(&mut callback, wide);
    callback.extend([0x89, 0x48, 4]);
    callback.extend(if wide { vec![0xc3] } else { vec![0xc2, 12, 0] });
    assert!(callback.len() < 256);
    bytes[0x400..0x400 + callback.len()].copy_from_slice(&callback);
    let mut entry = vec![];
    if wide {
        entry.extend([0x48, 0xb8]);
        entry.extend(base.to_le_bytes());
        entry.extend([0x48, 0x39, 0xc1]);
    } else {
        entry.extend([0x81, 0x7c, 0x24, 4]);
        entry.extend((base as u32).to_le_bytes());
    }
    equal(&mut entry);
    if wide {
        entry.extend([0x83, 0xfa, 2]);
    } else {
        entry.extend([0x83, 0x7c, 0x24, 8, 2]);
    }
    entry.extend([0x0f, 0x83]);
    let thread = entry.len();
    entry.extend([0; 4]);
    if wide {
        entry.extend([0x49, 0x83, 0xf8, 1]);
    } else {
        entry.extend([0x83, 0x7c, 0x24, 12, 1]);
    }
    equal(&mut entry);
    entry.push(0xe9);
    let joined = entry.len();
    entry.extend([0; 4]);
    let target = entry.len();
    entry[thread..thread + 4].copy_from_slice(&((target - thread - 4) as u32).to_le_bytes());
    if wide {
        entry.extend([0x49, 0x83, 0xf8, 0]);
    } else {
        entry.extend([0x83, 0x7c, 0x24, 12, 0]);
    }
    equal(&mut entry);
    let target = entry.len();
    entry[joined..joined + 4].copy_from_slice(&((target - joined - 4) as u32).to_le_bytes());
    block(&mut entry, wide, base + 0x5100);
    id(&mut entry, wide);
    entry.extend([0x39, 0x48, 4]);
    equal(&mut entry);
    entry.extend([0xb8, 1, 0, 0, 0]);
    entry.extend(if wide { vec![0xc3] } else { vec![0xc2, 12, 0] });
    assert!(entry.len() < 256);
    bytes[0x300..0x300 + entry.len()].copy_from_slice(&entry);
    bytes[0x500..0x506].copy_from_slice(&[0xb8, 42, 0, 0, 0, 0xc3]);
    bytes
}
