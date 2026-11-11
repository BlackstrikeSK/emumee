//! Nested CRT callback walks using distinct real guest tables and caller frames.
use super::winhttp::{Arg::Value, call};
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum M3CallbackFixture {
    Normal,
    Fault,
    Budget,
    BadStack,
    Nonvolatile,
    InvalidTarget,
}
pub fn m3_callback_probe(architecture: Architecture, kind: M3CallbackFixture) -> Vec<u8> {
    let wide = architecture == Architecture::X64;
    let base = if wide { 0x140000000u64 } else { 0x400000 };
    let width = architecture.width();
    let mut bytes = crt_startup_probe(architecture, StartupFixture::InitializersVoid);
    let mut outer = vec![0; 0x800];
    if wide {
        outer.extend([0x48, 0x83, 0xec, 0x28]);
    }
    call(
        &mut outer,
        wide,
        base,
        8,
        &[Value(base + 0x2f80), Value(base + 0x2f80 + width as u64)],
    );
    if wide {
        outer.extend([0x48, 0x83, 0xc4, 0x28]);
    } else {
        outer.extend([0x83, 0xc4, 8]);
    }
    outer.extend([0x31, 0xc0, 0xc3]);
    bytes[0xa00..0xb00].fill(0);
    bytes[0xa00..0xa00 + outer.len() - 0x800].copy_from_slice(&outer[0x800..]);
    let target = if kind == M3CallbackFixture::InvalidTarget {
        base + 0x2f00
    } else {
        base + 0x1a00
    };
    bytes[0x2180..0x2180 + width].copy_from_slice(&target.to_le_bytes()[..width]);
    match kind {
        M3CallbackFixture::Fault => bytes[0xc00..0xc02].copy_from_slice(&[0x0f, 0x0b]),
        M3CallbackFixture::Budget => bytes[0xc00..0xc02].copy_from_slice(&[0xeb, 0xfe]),
        M3CallbackFixture::BadStack => bytes[0xc00..0xc03].copy_from_slice(&[0xc2, 4, 0]),
        M3CallbackFixture::Nonvolatile => {
            bytes[0xc00..0xc06].copy_from_slice(&[0xbb, 0x12, 0x34, 0x56, 0x78, 0xc3])
        }
        _ => {}
    }
    bytes
}
