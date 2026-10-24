//! Owned URLMon call fixture; URLs are matched only by an offline broker.
use super::{ApiFixture, api_probe, put16};
use crate::pe::Architecture;
#[derive(Clone, Copy, Debug)]
pub enum DownloadFixture {
    Ansi,
    Wide,
    Miss,
    Callback,
    MissingParent,
    NullUrl,
}
pub fn download_probe(architecture: Architecture, fixture: DownloadFixture) -> Vec<u8> {
    let wide = architecture == Architecture::X64;
    let unicode = matches!(fixture, DownloadFixture::Wide);
    let base = if wide { 0x140000000u64 } else { 0x400000 };
    let mut data = api_probe(architecture, ApiFixture::Unsupported);
    put16(&mut data, 0x98 + 68, 3);
    put16(&mut data, 0x96, 0x22);
    data[0x440..0x460].fill(0);
    data[0x440..0x44b].copy_from_slice(b"urlmon.dll\0");
    data[0x702..0x740].fill(0);
    let name = if unicode {
        b"URLDownloadToFileW"
    } else {
        b"URLDownloadToFileA"
    };
    data[0x702..0x702 + name.len()].copy_from_slice(name);
    let url = if matches!(fixture, DownloadFixture::Miss) {
        "https://fixture.invalid/payload?unmatched"
    } else {
        "https://fixture.invalid/payload"
    };
    let path = if matches!(fixture, DownloadFixture::MissingParent) {
        "c:\\missing\\payload.bin"
    } else {
        "c:\\workspace\\payload.bin"
    };
    for (raw, text) in [(0xd00, url), (0xe00, path)] {
        if unicode {
            for (index, unit) in text.encode_utf16().chain([0]).enumerate() {
                data[raw + index * 2..raw + index * 2 + 2].copy_from_slice(&unit.to_le_bytes());
            }
        } else {
            data[raw..raw + text.len()].copy_from_slice(text.as_bytes());
            data[raw + text.len()] = 0;
        }
    }
    let url = if matches!(fixture, DownloadFixture::NullUrl) {
        0
    } else {
        base + 0x2900
    };
    let callback = u64::from(matches!(fixture, DownloadFixture::Callback));
    let args = [0, url, base + 0x2a00, 0, callback];
    let mut code = Vec::new();
    if wide {
        code.extend([0x48, 0x83, 0xec, 0x38]);
        for (index, value) in args.into_iter().enumerate() {
            if index < 4 {
                code.extend([[0x48, 0xb9], [0x48, 0xba], [0x49, 0xb8], [0x49, 0xb9]][index]);
                code.extend(value.to_le_bytes());
            } else {
                code.extend([0x48, 0xb8]);
                code.extend(value.to_le_bytes());
                code.extend([0x48, 0x89, 0x44, 0x24, 0x20]);
            }
        }
        let next = 0x1000 + code.len() + 6;
        code.extend([0xff, 0x15]);
        code.extend((0x2080i32 - next as i32).to_le_bytes());
        code.extend([0x48, 0x83, 0xc4, 0x38, 0xc3]);
    } else {
        for value in args.into_iter().rev() {
            code.push(0x68);
            code.extend((value as u32).to_le_bytes());
        }
        code.extend([0xff, 0x15]);
        code.extend(((base + 0x2080) as u32).to_le_bytes());
        code.push(0xc3);
    }
    assert!(code.len() <= 0x200);
    data[0x200..0x400].fill(0);
    data[0x200..0x200 + code.len()].copy_from_slice(&code);
    data
}
