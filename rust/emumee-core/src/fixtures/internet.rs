//! Owned A/W WinINet callers check real 64 KiB guest stream reads and EOF.
use super::winhttp::{
    Arg::{Memory as M, Value as V},
    call, expect_dword, failure, store, success, write_dword,
};
use super::{ApiFixture, api_probe, put16, put32, put64};
use crate::pe::Architecture;
#[derive(Clone, Copy, Debug)]
pub enum InternetFixture {
    Ansi,
    Wide,
    Split,
    Empty,
    Miss,
    Closed,
    BadRead,
    BadCount,
    NullAvailable,
    Flags,
    Async,
    StreamA,
    StreamW,
    StreamZero,
    StreamLinked,
    StreamFull,
    StreamEmpty,
    StreamBadCount,
    StreamExcess,
    StreamBadStruct,
    StreamIncomplete,
    StreamClosed,

    PostA,
    PostW,
    SendWideLength,
    SendBeforeRead,
    QueryA,
    QueryW,
    QuerySmallA,
    QuerySmallW,
    QueryCustomA,
    QueryCustomW,
    QueryNull,
    QueryReadOnly,
    QueryMissing,
}
impl InternetFixture {
    pub fn stream(self) -> bool {
        matches!(
            self,
            Self::StreamA
                | Self::StreamW
                | Self::StreamZero
                | Self::StreamLinked
                | Self::StreamFull
                | Self::StreamEmpty
                | Self::StreamBadCount
                | Self::StreamExcess
                | Self::StreamBadStruct
                | Self::StreamIncomplete
                | Self::StreamClosed
        )
    }
    pub fn empty_post(self) -> bool {
        matches!(self, Self::StreamEmpty)
    }
    pub fn send(self) -> bool {
        self.stream()
            || matches!(
                self,
                Self::PostA | Self::PostW | Self::SendWideLength | Self::SendBeforeRead
            )
    }
    pub fn unicode(self) -> bool {
        !matches!(
            self,
            Self::StreamA
                | Self::Ansi
                | Self::PostA
                | Self::QueryA
                | Self::QuerySmallA
                | Self::QueryCustomA
        )
    }
    pub fn query(self) -> bool {
        matches!(
            self,
            Self::QueryA
                | Self::QueryW
                | Self::QuerySmallA
                | Self::QuerySmallW
                | Self::QueryCustomA
                | Self::QueryCustomW
                | Self::QueryNull
                | Self::QueryReadOnly
                | Self::QueryMissing
        )
    }
}
pub fn internet_probe(architecture: Architecture, kind: InternetFixture) -> Vec<u8> {
    let wide = architecture == Architecture::X64;
    let unicode = kind.unicode();
    let base = if wide { 0x140000000u64 } else { 0x400000 };
    let original = api_probe(architecture, ApiFixture::Unsupported);
    let mut data = vec![0; 0x13200];
    data[..0x200].copy_from_slice(&original[..0x200]);
    let table = 0x98 + if wide { 0xf0 } else { 0xe0 };
    let dd = 0x98 + if wide { 112 } else { 96 };
    put32(&mut data, 0x98 + 4, 0x1000);
    put32(&mut data, 0x98 + 8, 0x12000);
    put32(&mut data, 0x98 + 56, 0x14000);
    put32(&mut data, table + 8, 0x1000);
    put32(&mut data, table + 16, 0x1000);
    put32(&mut data, table + 40 + 8, 0x12000);
    put32(&mut data, table + 40 + 16, 0x12000);
    put32(&mut data, table + 40 + 20, 0x1200);
    put16(&mut data, 0x98 + 68, 3);
    put16(&mut data, 0x96, 0x22);
    put32(&mut data, dd + 8, 0x2000);
    put32(&mut data, dd + 12, 40);
    put32(&mut data, 0x1200, 0x2180);
    put32(&mut data, 0x120c, 0x2040);
    put32(&mut data, 0x1210, 0x2080);
    data[0x1240..0x124c].copy_from_slice(b"wininet.dll\0");
    for (i, name) in [
        if unicode {
            "InternetOpenW"
        } else {
            "InternetOpenA"
        },
        if unicode {
            "InternetOpenUrlW"
        } else {
            "InternetOpenUrlA"
        },
        "InternetReadFile",
        "InternetQueryDataAvailable",
        "InternetCloseHandle",
        if unicode {
            "InternetConnectW"
        } else {
            "InternetConnectA"
        },
        if unicode {
            "HttpOpenRequestW"
        } else {
            "HttpOpenRequestA"
        },
        if unicode {
            "HttpSendRequestW"
        } else {
            "HttpSendRequestA"
        },
        if unicode {
            "HttpQueryInfoW"
        } else {
            "HttpQueryInfoA"
        },
        if unicode {
            "HttpSendRequestExW"
        } else {
            "HttpSendRequestExA"
        },
        "InternetWriteFile",
        if unicode {
            "HttpEndRequestW"
        } else {
            "HttpEndRequestA"
        },
    ]
    .iter()
    .enumerate()
    {
        let rva = 0x2300 + i as u32 * 64;
        for raw in [0x1280, 0x1380] {
            if wide {
                put64(&mut data, raw + i * 8, rva as u64)
            } else {
                put32(&mut data, raw + i * 4, rva)
            }
        }
        let raw = 0x1500 + i * 64;
        data[raw + 2..raw + 2 + name.len()].copy_from_slice(name.as_bytes());
    }
    for (rva, value) in [
        (0x2700, "Owned WinINet fixture"),
        (0x2800, "fixture.invalid"),
        (0x2840, "POST"),
        (0x2880, "/payload"),
        (0x2d00, "X-Case: Exact\r\n"),
        (
            0x2780,
            if matches!(kind, InternetFixture::Miss) {
                "https://fixture.invalid/absent"
            } else {
                "https://fixture.invalid/payload"
            },
        ),
    ] {
        let bytes: Vec<u8> = if unicode {
            value
                .encode_utf16()
                .chain([0])
                .flat_map(u16::to_le_bytes)
                .collect()
        } else {
            value.as_bytes().iter().copied().chain([0]).collect()
        };
        let raw = 0x1200 + rva - 0x2000;
        data[raw..raw + bytes.len()].copy_from_slice(&bytes);
    }
    data[0x1f80..0x1f88].copy_from_slice(b"RUSTBODY");
    data[0x1fc0..0x1fc4].copy_from_slice(b"FAIL");
    if kind.stream() {
        let width = architecture.width();
        let size = if wide { 56 } else { 40 };
        let h = if wide { 16 } else { 8 };
        let b = if wide { 32 } else { 20 };
        let raw = 0x2000;
        put32(
            &mut data,
            raw,
            if matches!(kind, InternetFixture::StreamBadStruct) {
                size as u32 - 4
            } else {
                size as u32
            },
        );
        for (off, value) in [
            (
                width,
                if matches!(kind, InternetFixture::StreamLinked) {
                    base + 0x2e80
                } else {
                    0
                },
            ),
            (h, base + 0x2d00),
            (b, base + 0x2d80),
        ] {
            if wide {
                put64(&mut data, raw + off, value)
            } else {
                put32(&mut data, raw + off, value as u32)
            }
        }
        put32(&mut data, raw + h + width, 15);
        put32(
            &mut data,
            raw + b + width,
            if matches!(kind, InternetFixture::StreamFull) {
                8
            } else {
                4
            },
        );
        put32(&mut data, raw + b + width + 4, 8);
        let raw = 0x2080;
        put32(&mut data, raw, size as u32);
        if wide {
            put64(&mut data, raw + b, base + 0x2dc0)
        } else {
            put32(&mut data, raw + b, (base + 0x2dc0) as u32)
        };
        put32(&mut data, raw + b + width, 4);
        put32(&mut data, raw + b + width + 4, 4);
    }

    let session = base + 0x2a00;
    let stream = base + 0x2a10;
    let count = base + 0x2a20;
    let buffer = base + 0x3000;
    let sentinel = base + 0x2b00;
    let mut c = Vec::new();
    if wide {
        c.extend([0x48, 0x83, 0xec, 0x48]);
    }
    call(
        &mut c,
        wide,
        base,
        0,
        &[
            V(base + 0x2700),
            V(1),
            V(0),
            V(0),
            V(if matches!(kind, InternetFixture::Async) {
                0x10000000
            } else {
                0
            }),
        ],
    );
    success(&mut c);
    store(&mut c, wide, session);
    if kind.send() {
        call(
            &mut c,
            wide,
            base,
            5,
            &[
                M(session),
                V(base + 0x2800),
                V(443),
                V(0),
                V(0),
                V(3),
                V(0),
                V(0),
            ],
        );
        success(&mut c);
        store(&mut c, wide, stream);
        call(
            &mut c,
            wide,
            base,
            6,
            &[
                M(stream),
                V(base + 0x2840),
                V(base + 0x2880),
                V(0),
                V(0),
                V(0),
                V(0x00800000),
                V(0),
            ],
        );
        success(&mut c);
        store(&mut c, wide, stream);
        if kind.stream() {
            stream_calls(&mut c, wide, base, session, stream, count, kind);
        } else {
            if matches!(kind, InternetFixture::SendWideLength) {
                call(
                    &mut c,
                    wide,
                    base,
                    7,
                    &[
                        M(stream),
                        V(base + 0x2d00),
                        V(u32::MAX as u64),
                        V(base + 0x2d80),
                        V(8),
                    ],
                );
                failure(&mut c);
            }
            call(
                &mut c,
                wide,
                base,
                7,
                &[
                    M(stream),
                    V(base + 0x2d00),
                    V(if unicode { 15 } else { u32::MAX as u64 }),
                    V(base + 0x2d80),
                    V(8),
                ],
            );
            success(&mut c);
        }
        // Preserve the stream handle while leaving a successful return value in eax.
    } else {
        call(
            &mut c,
            wide,
            base,
            1,
            &[
                M(session),
                V(base + 0x2780),
                V(0),
                V(0),
                V(if matches!(kind, InternetFixture::Flags) {
                    0x80000000
                } else {
                    0
                }),
                V(0),
            ],
        );
    }
    if matches!(kind, InternetFixture::Miss) {
        failure(&mut c);
    } else {
        success(&mut c);
        if !kind.send() {
            store(&mut c, wide, stream);
        }
        if matches!(kind, InternetFixture::SendBeforeRead) {
            call(
                &mut c,
                wide,
                base,
                7,
                &[M(stream), V(base + 0x2d00), V(15), V(base + 0x2d80), V(8)],
            );
            failure(&mut c);
        }
        if kind.query() {
            queries(&mut c, wide, unicode, base, stream, kind);
        }
        if matches!(kind, InternetFixture::Closed) {
            call(&mut c, wide, base, 4, &[M(session)]);
            success(&mut c);
        }
        write_dword(&mut c, wide, count, 77);
        if matches!(
            kind,
            InternetFixture::Closed | InternetFixture::BadRead | InternetFixture::BadCount
        ) {
            call(
                &mut c,
                wide,
                base,
                2,
                &[
                    M(stream),
                    V(if matches!(kind, InternetFixture::BadRead) {
                        base + 0x1000
                    } else {
                        buffer
                    }),
                    V(4),
                    V(if matches!(kind, InternetFixture::BadCount) {
                        0
                    } else {
                        count
                    }),
                ],
            );
            failure(&mut c);
            expect_dword(
                &mut c,
                wide,
                count,
                if matches!(kind, InternetFixture::BadCount) {
                    77
                } else {
                    0
                },
            );
        }
        if !matches!(
            kind,
            InternetFixture::Closed
                | InternetFixture::StreamClosed
                | InternetFixture::StreamBadStruct
        ) {
            call(
                &mut c,
                wide,
                base,
                3,
                &[
                    M(stream),
                    V(if matches!(kind, InternetFixture::NullAvailable) {
                        0
                    } else {
                        count
                    }),
                    V(0),
                    V(0),
                ],
            );
            success(&mut c);
            if !matches!(kind, InternetFixture::NullAvailable) {
                expect_dword(
                    &mut c,
                    wide,
                    count,
                    if matches!(kind, InternetFixture::Empty) {
                        0
                    } else {
                        65536
                    },
                );
            }
            if !matches!(kind, InternetFixture::Empty) {
                if matches!(kind, InternetFixture::Split) {
                    call(
                        &mut c,
                        wide,
                        base,
                        2,
                        &[M(stream), V(buffer), V(3), V(count)],
                    );
                    success(&mut c);
                    expect_dword(&mut c, wide, count, 3);
                }
                let offset = if matches!(kind, InternetFixture::Split) {
                    3
                } else {
                    0
                };
                call(
                    &mut c,
                    wide,
                    base,
                    2,
                    &[M(stream), V(buffer + offset), V(65536 - offset), V(count)],
                );
                success(&mut c);
                expect_dword(&mut c, wide, count, (65536 - offset) as u32);
                expect_dword(&mut c, wide, buffer, 0x03020100);
                expect_dword(&mut c, wide, buffer + 65532, 0xfffefdfc);
            }
            write_dword(&mut c, wide, sentinel, 0x77777777);
            write_dword(&mut c, wide, count, 77);
            call(
                &mut c,
                wide,
                base,
                2,
                &[M(stream), V(sentinel), V(4), V(count)],
            );
            success(&mut c);
            expect_dword(&mut c, wide, count, 0);
            expect_dword(&mut c, wide, sentinel, 0x77777777);
            call(&mut c, wide, base, 3, &[M(stream), V(count), V(0), V(0)]);
            success(&mut c);
            expect_dword(&mut c, wide, count, 0);
            call(&mut c, wide, base, 4, &[M(stream)]);
            success(&mut c);
            call(&mut c, wide, base, 4, &[M(session)]);
            success(&mut c);
        }
    }
    c.push(0xb8);
    c.extend(
        (if matches!(kind, InternetFixture::Miss) {
            0u32
        } else {
            1u32
        })
        .to_le_bytes(),
    );
    if wide {
        c.extend([0x48, 0x83, 0xc4, 0x48]);
    }
    c.push(0xc3);
    assert!(c.len() <= 0x1000);
    data[0x200..0x200 + c.len()].copy_from_slice(&c);
    data
}

fn queries(
    c: &mut Vec<u8>,
    wide: bool,
    unicode: bool,
    base: u64,
    stream: u64,
    kind: InternetFixture,
) {
    let buffer = base + 0x2c00;
    let length = base + 0x2a30;
    let index = base + 0x2a40;
    write_dword(c, wide, index, 0);
    write_dword(c, wide, length, 64);
    if matches!(
        kind,
        InternetFixture::QueryCustomA | InternetFixture::QueryCustomW
    ) {
        for n in 0..3 {
            let mut bytes: Vec<u8> = if unicode {
                "Set-Cookie"
                    .encode_utf16()
                    .chain([0])
                    .flat_map(u16::to_le_bytes)
                    .collect()
            } else {
                b"Set-Cookie\0".to_vec()
            };
            bytes.resize(bytes.len().div_ceil(4) * 4, 0);
            for (i, chunk) in bytes.chunks_exact(4).enumerate() {
                write_dword(
                    c,
                    wide,
                    buffer + (i * 4) as u64,
                    u32::from_le_bytes(chunk.try_into().unwrap()),
                );
            }
            write_dword(c, wide, length, 64);
            call(
                c,
                wide,
                base,
                8,
                &[M(stream), V(65535), V(buffer), V(length), V(index)],
            );
            if n == 2 {
                failure(c);
                expect_dword(c, wide, length, 64);
                expect_dword(c, wide, index, 2);
                expect_dword(
                    c,
                    wide,
                    buffer,
                    if unicode { 0x00650053 } else { 0x2d746553 },
                );
            } else {
                success(c);
                expect_dword(c, wide, length, if unicode { 6 } else { 3 });
                expect_dword(c, wide, index, n + 1);
                expect_dword(
                    c,
                    wide,
                    buffer,
                    if unicode {
                        if n == 0 { 0x006e006f } else { 0x00770074 }
                    } else if n == 0 {
                        0x00656e6f
                    } else {
                        0x006f7774
                    },
                );
            }
        }
    } else {
        if matches!(
            kind,
            InternetFixture::QuerySmallA
                | InternetFixture::QuerySmallW
                | InternetFixture::QueryNull
                | InternetFixture::QueryReadOnly
                | InternetFixture::QueryMissing
        ) {
            write_dword(c, wide, buffer, 0x77777777);
            if matches!(
                kind,
                InternetFixture::QuerySmallA
                    | InternetFixture::QuerySmallW
                    | InternetFixture::QueryNull
            ) {
                write_dword(c, wide, length, 1);
            }
            call(
                c,
                wide,
                base,
                8,
                &[
                    M(stream),
                    V(if matches!(kind, InternetFixture::QueryMissing) {
                        5
                    } else {
                        19
                    }),
                    V(if matches!(kind, InternetFixture::QueryNull) {
                        0
                    } else if matches!(kind, InternetFixture::QueryReadOnly) {
                        base + 0x1000
                    } else {
                        buffer
                    }),
                    V(length),
                    V(index),
                ],
            );
            failure(c);
            expect_dword(c, wide, index, 0);
            expect_dword(c, wide, buffer, 0x77777777);
            expect_dword(
                c,
                wide,
                length,
                if matches!(
                    kind,
                    InternetFixture::QueryMissing | InternetFixture::QueryReadOnly
                ) {
                    64
                } else if unicode {
                    8
                } else {
                    4
                },
            );
        }
        write_dword(c, wide, length, 64);
        call(
            c,
            wide,
            base,
            8,
            &[M(stream), V(19), V(buffer), V(length), V(index)],
        );
        success(c);
        expect_dword(c, wide, length, if unicode { 6 } else { 3 });
        expect_dword(
            c,
            wide,
            buffer,
            if unicode { 0x00300032 } else { 0x00303032 },
        );
        expect_dword(c, wide, index, 0);
        write_dword(c, wide, length, 4);
        call(
            c,
            wide,
            base,
            8,
            &[
                M(stream),
                V(19 | 0x20000000),
                V(buffer),
                V(length),
                V(index),
            ],
        );
        success(c);
        expect_dword(c, wide, buffer, 200);
        expect_dword(c, wide, length, 4);
    }
}

fn stream_calls(
    c: &mut Vec<u8>,
    wide: bool,
    base: u64,
    session: u64,
    stream: u64,
    count: u64,
    kind: InternetFixture,
) {
    call(
        c,
        wide,
        base,
        9,
        &[
            M(stream),
            V(if kind.empty_post() { 0 } else { base + 0x2e00 }),
            V(0),
            V(0),
            V(0),
        ],
    );
    if matches!(kind, InternetFixture::StreamBadStruct) {
        failure(c);
        call(c, wide, base, 4, &[M(stream)]);
        success(c);
        call(c, wide, base, 4, &[M(session)]);
        success(c);
        return;
    }
    success(c);
    if matches!(kind, InternetFixture::StreamIncomplete) {
        call(c, wide, base, 11, &[M(stream), V(0), V(0), V(0)]);
        success(c);
        return;
    }
    if matches!(kind, InternetFixture::StreamClosed) {
        call(c, wide, base, 4, &[M(session)]);
        success(c);
        write_dword(c, wide, count, 77);
        call(
            c,
            wide,
            base,
            10,
            &[M(stream), V(base + 0x2d84), V(4), V(count)],
        );
        failure(c);
        expect_dword(c, wide, count, 0);
        c.extend([0xb8, 1, 0, 0, 0]);
        return;
    }
    if !matches!(
        kind,
        InternetFixture::StreamFull | InternetFixture::StreamEmpty
    ) {
        if matches!(
            kind,
            InternetFixture::StreamZero
                | InternetFixture::StreamBadCount
                | InternetFixture::StreamExcess
        ) {
            write_dword(c, wide, count, 77);
            call(
                c,
                wide,
                base,
                10,
                &[
                    M(stream),
                    V(base + 0x2d84),
                    V(if matches!(kind, InternetFixture::StreamZero) {
                        0
                    } else if matches!(kind, InternetFixture::StreamExcess) {
                        5
                    } else {
                        4
                    }),
                    V(if matches!(kind, InternetFixture::StreamBadCount) {
                        0
                    } else {
                        count
                    }),
                ],
            );
            failure(c);
            expect_dword(
                c,
                wide,
                count,
                if matches!(kind, InternetFixture::StreamExcess) {
                    0
                } else {
                    77
                },
            );
        }
        call(
            c,
            wide,
            base,
            10,
            &[M(stream), V(base + 0x2d84), V(4), V(count)],
        );
        success(c);
        expect_dword(c, wide, count, 4);
    }
    call(c, wide, base, 11, &[M(stream), V(0), V(0), V(0)]);
    success(c);
}
