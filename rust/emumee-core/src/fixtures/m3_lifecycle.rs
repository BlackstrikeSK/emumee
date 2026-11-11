//! Process-exit controls with real static TLS callback storage reads.
use super::winhttp::{Arg::Value, call};
use super::*;

pub fn m3_exit_probe(architecture: Architecture, forced: bool, loop_detach: bool) -> Vec<u8> {
    let wide = architecture == Architecture::X64;
    let base: u64 = if wide { 0x140000000 } else { 0x400000 };
    let mut bytes = m3_storage_probe(architecture, false);
    let raw = 0x2300 + 15 * 64 - 0xe00;
    bytes[raw..raw + 64].fill(0);
    let name = if forced {
        "TerminateProcess"
    } else {
        "ExitProcess"
    };
    bytes[raw + 2..raw + 2 + name.len()].copy_from_slice(name.as_bytes());
    let mut entry = vec![];
    if wide {
        entry.extend([0x48, 0x83, 0xec, 0x28]);
    }
    let arguments = if forced {
        vec![
            Value(if wide { u64::MAX } else { u32::MAX as u64 }),
            Value(73),
        ]
    } else {
        vec![Value(73)]
    };
    call(&mut entry, wide, base, 15, &arguments);
    entry.push(0xcc);
    bytes[0x200..0x1100].fill(0);
    bytes[0x200..0x200 + entry.len()].copy_from_slice(&entry);
    put32(&mut bytes, 0x98 + 16, 0x1000);
    let mut callback = if wide {
        vec![0x65, 0x48, 0x8b, 4, 0x25, 0x58, 0, 0, 0, 0x48, 0xb9]
    } else {
        vec![0x64, 0xa1, 0x2c, 0, 0, 0, 0x8b, 0x0d]
    };
    callback.extend(
        (base + 0x3d40).to_le_bytes()[..architecture.width()]
            .iter()
            .copied(),
    );
    callback.extend(if wide {
        vec![0x8b, 9, 0x48, 0x8b, 4, 0xc8]
    } else {
        vec![0x8b, 4, 0x88]
    });
    callback.extend([0x81, 0x38]);
    callback.extend(0x12345678u32.to_le_bytes());
    callback.extend([0x74, 1, 0xcc]);
    if loop_detach {
        callback.extend(if wide {
            vec![0x85, 0xd2]
        } else {
            vec![0x83, 0x7c, 0x24, 8, 0]
        });
        callback.extend([0x75, 2, 0xeb, 0xfe]);
    }
    callback.extend(if wide { vec![0xc3] } else { vec![0xc2, 12, 0] });
    bytes[0x1100..0x1200].fill(0);
    bytes[0x1100..0x1100 + callback.len()].copy_from_slice(&callback);
    bytes
}
