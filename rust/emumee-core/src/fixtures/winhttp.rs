//! Owned WinHTTP programs using returned handles and actual guest output data.
use super::{ApiFixture, api_probe, put16, put32, put64};
use crate::pe::Architecture;
#[derive(Clone, Copy, Debug)]
pub enum WinHttpFixture {
    Normal,
    BeforeReceive,
    BadReadBuffer,
    BadAvailable,
    CloseParent,
    Miss,
    Async,
    QueryStatus,
    QuerySmall,
    QueryCustom,
    QueryRaw,
    Empty,
    Upload,
    UploadEarly,
    UploadBadCount,
    UploadOverrun,
    UploadIncomplete,
    UploadClosed,
    Chunked,
    ChunkedSplit,
    ChunkedIncomplete,
    ChunkedMalformed,
    ChunkedZero,
}
impl WinHttpFixture {
    pub fn chunked(self) -> bool {
        matches!(
            self,
            Self::Chunked
                | Self::ChunkedSplit
                | Self::ChunkedIncomplete
                | Self::ChunkedMalformed
                | Self::ChunkedZero
        )
    }
    pub fn upload(self) -> bool {
        matches!(
            self,
            Self::Upload
                | Self::UploadEarly
                | Self::UploadBadCount
                | Self::UploadOverrun
                | Self::UploadIncomplete
                | Self::UploadClosed
        )
    }
}
pub(super) enum Arg {
    Value(u64),
    Memory(u64),
}
pub(super) fn call(code: &mut Vec<u8>, wide: bool, base: u64, index: usize, args: &[Arg]) {
    if wide {
        for (position, arg) in args.iter().enumerate() {
            match arg {
                Arg::Value(value) => {
                    code.extend([0x48, 0xb8]);
                    code.extend(value.to_le_bytes());
                }
                Arg::Memory(address) => {
                    code.extend([0x48, 0xa1]);
                    code.extend(address.to_le_bytes());
                }
            }
            if position < 4 {
                code.extend(
                    [
                        [0x48, 0x89, 0xc1],
                        [0x48, 0x89, 0xc2],
                        [0x49, 0x89, 0xc0],
                        [0x49, 0x89, 0xc1],
                    ][position],
                );
            } else {
                code.extend([0x48, 0x89, 0x44, 0x24, (32 + (position - 4) * 8) as u8]);
            }
        }
        let next = 0x1000 + code.len() + 6;
        code.extend([0xff, 0x15]);
        code.extend((0x2080i32 + index as i32 * 8 - next as i32).to_le_bytes());
    } else {
        for arg in args.iter().rev() {
            match arg {
                Arg::Value(value) => {
                    code.push(0x68);
                    code.extend((*value as u32).to_le_bytes());
                }
                Arg::Memory(address) => {
                    code.extend([0xff, 0x35]);
                    code.extend((*address as u32).to_le_bytes());
                }
            }
        }
        code.extend([0xff, 0x15]);
        code.extend(((base + 0x2080) as u32 + index as u32 * 4).to_le_bytes());
    }
}
pub(super) fn store(code: &mut Vec<u8>, wide: bool, address: u64) {
    if wide {
        code.push(0x48);
    }
    code.push(0xa3);
    if wide {
        code.extend(address.to_le_bytes());
    } else {
        code.extend((address as u32).to_le_bytes());
    }
}
pub(super) fn load(code: &mut Vec<u8>, wide: bool, address: u64) {
    code.push(0xa1);
    if wide {
        code.extend(address.to_le_bytes());
    } else {
        code.extend((address as u32).to_le_bytes());
    }
}
pub(super) fn success(code: &mut Vec<u8>) {
    code.extend([0x85, 0xc0, 0x75, 1, 0xcc]);
}
pub(super) fn failure(code: &mut Vec<u8>) {
    code.extend([0x85, 0xc0, 0x74, 1, 0xcc]);
}
pub(super) fn write_dword(code: &mut Vec<u8>, wide: bool, address: u64, value: u32) {
    code.push(0xb8);
    code.extend(value.to_le_bytes());
    code.push(0xa3);
    if wide {
        code.extend(address.to_le_bytes());
    } else {
        code.extend((address as u32).to_le_bytes());
    }
}
pub(super) fn expect_dword(code: &mut Vec<u8>, wide: bool, address: u64, value: u32) {
    load(code, wide, address);
    code.push(0x3d);
    code.extend(value.to_le_bytes());
    code.extend([0x74, 1, 0xcc]);
}
pub fn winhttp_probe(architecture: Architecture, fixture: WinHttpFixture) -> Vec<u8> {
    use Arg::{Memory as M, Value as V};
    let wide = architecture == Architecture::X64;
    let base = if wide { 0x140000000u64 } else { 0x400000 };
    let original = api_probe(architecture, ApiFixture::Unsupported);
    let mut data = vec![0; 0x2200];
    data[..0x200].copy_from_slice(&original[..0x200]);
    data[0x1200..0x2200].copy_from_slice(&original[0x400..0x1400]);
    let table = 0x98 + if wide { 0xf0 } else { 0xe0 };
    put32(&mut data, 0x98 + 4, 0x1000);
    put32(&mut data, table + 8, 0x1000);
    put32(&mut data, table + 16, 0x1000);
    put32(&mut data, table + 40 + 20, 0x1200);
    put16(&mut data, 0x98 + 68, 3);
    put16(&mut data, 0x96, 0x22);
    data[0x1240..0x1260].fill(0);
    data[0x1240..0x124c].copy_from_slice(b"winhttp.dll\0");
    put32(&mut data, 0x1200, 0x2180);
    data[0x1280..0x1300].fill(0);
    data[0x1380..0x1400].fill(0);
    data[0x1500..0x1780].fill(0);
    for (index, name) in [
        "WinHttpOpen",
        "WinHttpConnect",
        "WinHttpOpenRequest",
        "WinHttpSendRequest",
        "WinHttpReceiveResponse",
        "WinHttpQueryDataAvailable",
        "WinHttpReadData",
        "WinHttpCloseHandle",
        "WinHttpQueryHeaders",
        "WinHttpWriteData",
    ]
    .iter()
    .enumerate()
    {
        let rva = 0x2300 + index as u32 * 64;
        for raw in [0x1280, 0x1380] {
            if wide {
                put64(&mut data, raw + index * 8, rva as u64);
            } else {
                put32(&mut data, raw + index * 4, rva);
            }
        }
        let raw = 0x1500 + index * 64;
        data[raw + 2..raw + 2 + name.len()].copy_from_slice(name.as_bytes());
    }
    for (rva, text) in [
        (0x2900, "Owned WinHTTP fixture"),
        (0x2980, "fixture.invalid"),
        (
            0x2a00,
            if fixture.upload() || fixture.chunked() {
                "POST"
            } else {
                "GET"
            },
        ),
        (0x2c40, "Set-Cookie"),
        (
            0x2a80,
            if matches!(fixture, WinHttpFixture::Miss) {
                "/payload?unmatched"
            } else {
                "/payload"
            },
        ),
    ] {
        let raw = rva - 0x2000 + 0x1200;
        for (i, unit) in text.encode_utf16().chain([0]).enumerate() {
            put16(&mut data, raw + i * 2, unit);
        }
    }
    let session = base + 0x2b00;
    let connection = base + 0x2b08;
    let request = base + 0x2b10;
    let result = base + 0x2b18;
    let count = base + 0x2d00;
    let buffer = base + 0x2e00;
    data[0x1f80..0x1f88].copy_from_slice(b"RUSTBODY");
    if fixture.chunked() {
        let wire = if matches!(fixture, WinHttpFixture::ChunkedMalformed) {
            &b"X\r\nRUST\r\n0\r\n\r\n"[..]
        } else {
            &b"4\r\nRUST\r\n4\r\nBODY\r\n0\r\n\r\n"[..]
        };
        data[0x1f80..0x1f80 + wire.len()].copy_from_slice(wire);
        for (index, unit) in "Transfer-Encoding: chunked\r\n"
            .encode_utf16()
            .chain([0])
            .enumerate()
        {
            put16(&mut data, 0x1fc0 + index * 2, unit);
        }
    }
    if matches!(fixture, WinHttpFixture::Empty) {
        put32(&mut data, 0x2000, 0x11223344);
        put32(&mut data, 0x1f00, 0x77777777);
    }
    let mut code = if wide {
        vec![0x48, 0x83, 0xec, 0x48]
    } else {
        Vec::new()
    };
    call(
        &mut code,
        wide,
        base,
        0,
        &[
            V(base + 0x2900),
            V(1),
            V(0),
            V(0),
            V(if matches!(fixture, WinHttpFixture::Async) {
                0x10000000
            } else {
                0
            }),
        ],
    );
    success(&mut code);
    store(&mut code, wide, session);
    call(
        &mut code,
        wide,
        base,
        1,
        &[M(session), V(base + 0x2980), V(443), V(0)],
    );
    success(&mut code);
    store(&mut code, wide, connection);
    call(
        &mut code,
        wide,
        base,
        2,
        &[
            M(connection),
            V(base + 0x2a00),
            V(base + 0x2a80),
            V(0),
            V(0),
            V(0),
            V(0x00800000),
        ],
    );
    success(&mut code);
    store(&mut code, wide, request);
    call(
        &mut code,
        wide,
        base,
        3,
        &[
            M(request),
            V(if fixture.chunked() { base + 0x2dc0 } else { 0 }),
            V(if fixture.chunked() {
                u32::MAX as u64
            } else {
                0
            }),
            V(if fixture.upload() { base + 0x2d80 } else { 0 }),
            V(if fixture.upload() { 4 } else { 0 }),
            V(if fixture.chunked() {
                u32::MAX as u64
            } else if fixture.upload() {
                8
            } else {
                0
            }),
            V(0),
        ],
    );
    if matches!(fixture, WinHttpFixture::Miss) {
        failure(&mut code);
        store(&mut code, wide, result);
    } else {
        success(&mut code);
        if fixture.chunked() {
            if matches!(fixture, WinHttpFixture::ChunkedZero) {
                write_dword(&mut code, wide, count, 0x77777777);
                call(
                    &mut code,
                    wide,
                    base,
                    9,
                    &[M(request), V(base + 0x2d80), V(0), V(count)],
                );
                failure(&mut code);
                expect_dword(&mut code, wide, count, 0x77777777);
            }
            let spans = if matches!(fixture, WinHttpFixture::ChunkedSplit) {
                (0..23).map(|offset| (offset, 1)).collect::<Vec<_>>()
            } else if matches!(fixture, WinHttpFixture::ChunkedMalformed) {
                vec![(0, 14)]
            } else if matches!(fixture, WinHttpFixture::ChunkedIncomplete) {
                vec![(0, 9), (9, 9)]
            } else {
                vec![(0, 9), (9, 9), (18, 5)]
            };
            for (offset, length) in spans {
                write_dword(&mut code, wide, count, 0x77777777);
                call(
                    &mut code,
                    wide,
                    base,
                    9,
                    &[M(request), V(base + 0x2d80 + offset), V(length), V(count)],
                );
                success(&mut code);
                expect_dword(&mut code, wide, count, length as u32);
            }
            if matches!(fixture, WinHttpFixture::ChunkedIncomplete) {
                call(&mut code, wide, base, 4, &[M(request), V(0)]);
                failure(&mut code);
                store(&mut code, wide, result);
            }
        }
        if fixture.upload() {
            if matches!(fixture, WinHttpFixture::UploadIncomplete) {
                call(&mut code, wide, base, 4, &[M(request), V(0)]);
                failure(&mut code);
                store(&mut code, wide, result);
            } else if matches!(fixture, WinHttpFixture::UploadClosed) {
                call(&mut code, wide, base, 7, &[M(session)]);
                success(&mut code);
                write_dword(&mut code, wide, count, 0x77777777);
                call(
                    &mut code,
                    wide,
                    base,
                    9,
                    &[M(request), V(base + 0x2d84), V(4), V(count)],
                );
                failure(&mut code);
                expect_dword(&mut code, wide, count, 0);
                store(&mut code, wide, result);
            } else {
                if matches!(fixture, WinHttpFixture::UploadEarly) {
                    call(&mut code, wide, base, 4, &[M(request), V(0)]);
                    failure(&mut code);
                }
                if matches!(fixture, WinHttpFixture::UploadBadCount) {
                    call(
                        &mut code,
                        wide,
                        base,
                        9,
                        &[M(request), V(base + 0x2d84), V(4), V(base + 0x1000)],
                    );
                    failure(&mut code);
                }
                if matches!(fixture, WinHttpFixture::UploadOverrun) {
                    write_dword(&mut code, wide, count, 0x77777777);
                    call(
                        &mut code,
                        wide,
                        base,
                        9,
                        &[M(request), V(base + 0x2d84), V(5), V(count)],
                    );
                    failure(&mut code);
                    expect_dword(&mut code, wide, count, 0);
                }
                write_dword(&mut code, wide, count, 0x77777777);
                call(
                    &mut code,
                    wide,
                    base,
                    9,
                    &[M(request), V(base + 0x2d84), V(4), V(count)],
                );
                success(&mut code);
                expect_dword(&mut code, wide, count, 4);
            }
        }
        if !matches!(
            fixture,
            WinHttpFixture::UploadIncomplete
                | WinHttpFixture::UploadClosed
                | WinHttpFixture::ChunkedIncomplete
        ) {
            if matches!(fixture, WinHttpFixture::BeforeReceive) {
                write_dword(&mut code, wide, count, 0x77777777);
                call(
                    &mut code,
                    wide,
                    base,
                    6,
                    &[M(request), V(buffer), V(4), V(count)],
                );
                failure(&mut code);
                expect_dword(&mut code, wide, count, 0);
            }
            call(&mut code, wide, base, 4, &[M(request), V(0)]);
            success(&mut code);
            let header_buffer = base + 0x2c00;
            let header_length = base + 0x2c20;
            let header_index = base + 0x2c24;
            if matches!(
                fixture,
                WinHttpFixture::QueryStatus | WinHttpFixture::QuerySmall
            ) {
                write_dword(
                    &mut code,
                    wide,
                    header_length,
                    if matches!(fixture, WinHttpFixture::QuerySmall) {
                        0
                    } else {
                        64
                    },
                );
                if matches!(fixture, WinHttpFixture::QuerySmall) {
                    call(
                        &mut code,
                        wide,
                        base,
                        8,
                        &[
                            M(request),
                            V(0x20000013),
                            V(0),
                            V(0),
                            V(header_length),
                            V(0),
                        ],
                    );
                    failure(&mut code);
                    expect_dword(&mut code, wide, header_length, 4);
                }
                call(
                    &mut code,
                    wide,
                    base,
                    8,
                    &[
                        M(request),
                        V(0x20000013),
                        V(0),
                        V(header_buffer),
                        V(header_length),
                        V(0),
                    ],
                );
                success(&mut code);
                expect_dword(&mut code, wide, header_buffer, 200);
                expect_dword(&mut code, wide, header_length, 4);
            }
            if matches!(fixture, WinHttpFixture::QueryCustom) {
                for (index, prefix) in [(1, 0x006e006fu32), (2, 0x00770074)] {
                    write_dword(&mut code, wide, header_length, 64);
                    call(
                        &mut code,
                        wide,
                        base,
                        8,
                        &[
                            M(request),
                            V(65535),
                            V(base + 0x2c40),
                            V(base + 0x2c80),
                            V(header_length),
                            V(header_index),
                        ],
                    );
                    success(&mut code);
                    expect_dword(&mut code, wide, base + 0x2c80, prefix);
                    expect_dword(&mut code, wide, header_length, 6);
                    expect_dword(&mut code, wide, header_index, index);
                }
                write_dword(&mut code, wide, header_length, 64);
                call(
                    &mut code,
                    wide,
                    base,
                    8,
                    &[
                        M(request),
                        V(65535),
                        V(base + 0x2c40),
                        V(base + 0x2c80),
                        V(header_length),
                        V(header_index),
                    ],
                );
                failure(&mut code);
                expect_dword(&mut code, wide, header_index, 2);
                expect_dword(&mut code, wide, base + 0x2c80, 0x00770074);
            }
            if matches!(fixture, WinHttpFixture::QueryRaw) {
                write_dword(&mut code, wide, header_length, 256);
                call(
                    &mut code,
                    wide,
                    base,
                    8,
                    &[
                        M(request),
                        V(22),
                        V(0),
                        V(base + 0x2c80),
                        V(header_length),
                        V(0),
                    ],
                );
                success(&mut code);
                expect_dword(&mut code, wide, base + 0x2c80, 0x00540048);
                expect_dword(&mut code, wide, header_length, 106);
            }
            if matches!(fixture, WinHttpFixture::CloseParent) {
                call(&mut code, wide, base, 7, &[M(session)]);
                success(&mut code);
                write_dword(&mut code, wide, count, 0x77777777);
                call(
                    &mut code,
                    wide,
                    base,
                    6,
                    &[M(request), V(buffer), V(4), V(count)],
                );
                failure(&mut code);
                expect_dword(&mut code, wide, count, 0);
            } else {
                if matches!(fixture, WinHttpFixture::BadReadBuffer) {
                    write_dword(&mut code, wide, count, 0x77777777);
                    call(
                        &mut code,
                        wide,
                        base,
                        6,
                        &[M(request), V(base + 0x1000), V(4), V(count)],
                    );
                    failure(&mut code);
                    expect_dword(&mut code, wide, count, 0);
                }
                call(
                    &mut code,
                    wide,
                    base,
                    5,
                    &[
                        M(request),
                        V(if matches!(fixture, WinHttpFixture::BadAvailable) {
                            base + 0x1000
                        } else {
                            count
                        }),
                    ],
                );
                if matches!(fixture, WinHttpFixture::BadAvailable) {
                    failure(&mut code);
                } else {
                    success(&mut code);
                }
                if matches!(fixture, WinHttpFixture::Empty) {
                    write_dword(&mut code, wide, count, 0x77777777);
                }
                call(
                    &mut code,
                    wide,
                    base,
                    6,
                    &[M(request), V(buffer), V(4), V(count)],
                );
                success(&mut code);
                load(&mut code, wide, count);
                let expected = if matches!(fixture, WinHttpFixture::Empty) {
                    0u32
                } else {
                    4
                };
                code.push(0x3d);
                code.extend(expected.to_le_bytes());
                code.extend([0x74, 1, 0xcc]);
                if matches!(fixture, WinHttpFixture::Empty) {
                    expect_dword(&mut code, wide, buffer, 0x11223344);
                    code.extend([0x31, 0xc0]);
                } else {
                    load(&mut code, wide, buffer);
                }
                store(&mut code, wide, result);
            }
        }
    }
    if !matches!(
        fixture,
        WinHttpFixture::CloseParent | WinHttpFixture::UploadClosed
    ) {
        call(&mut code, wide, base, 7, &[M(request)]);
        success(&mut code);
        call(&mut code, wide, base, 7, &[M(connection)]);
        success(&mut code);
        call(&mut code, wide, base, 7, &[M(session)]);
        success(&mut code);
    }
    load(&mut code, wide, result);
    if wide {
        code.extend([0x48, 0x83, 0xc4, 0x48]);
    }
    code.push(0xc3);
    assert!(code.len() <= 0x1000);
    data[0x200..0x200 + code.len()].copy_from_slice(&code);
    data
}
