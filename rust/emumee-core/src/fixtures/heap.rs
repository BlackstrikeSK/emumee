//! Owned guest heap callers. Results are checked by guest instructions, not a
//! host-side substitution for allocation pointers or copied bytes.
use super::winhttp::{
    Arg::{Memory as M, Value as V},
    call, failure, load, store, success,
};
use super::{ApiFixture, api_probe, put16, put32, put64};
use crate::pe::Architecture;
#[derive(Clone, Copy, Debug)]
pub enum HeapFixture {
    Lifecycle,
    Resize,
    Move,
    InPlace,
    Executable,
    Nx,
    Freed,
    WrongOwner,
    DoubleFree,
    VirtualFree,
    Flags,
    Fixed,
    Zero,
}
fn expect(code: &mut Vec<u8>, value: u32) {
    code.push(0x3d);
    code.extend(value.to_le_bytes());
    code.extend([0x74, 1, 0xcc]);
}
fn indirect(code: &mut Vec<u8>, wide: bool, address: u64, offset: u32, write: Option<u32>) {
    if wide {
        code.push(0x48);
    }
    load(code, wide, address);
    if let Some(value) = write {
        code.extend([0xc7, 0x80]);
        code.extend(offset.to_le_bytes());
        code.extend(value.to_le_bytes());
    } else {
        code.extend([0x8b, 0x80]);
        code.extend(offset.to_le_bytes());
    }
}
pub fn heap_probe(architecture: Architecture, kind: HeapFixture) -> Vec<u8> {
    let wide = architecture == Architecture::X64;
    let base = if wide { 0x140000000u64 } else { 0x400000 };
    let original = api_probe(architecture, ApiFixture::Unsupported);
    let mut data = vec![0; 0x2200];
    data[..0x200].copy_from_slice(&original[..0x200]);
    let table = 0x98 + if wide { 0xf0 } else { 0xe0 };
    put32(&mut data, 0x98 + 4, 0x1000);
    put32(&mut data, table + 8, 0x1000);
    put32(&mut data, table + 16, 0x1000);
    put32(&mut data, table + 40 + 20, 0x1200);
    put32(&mut data, table + 40 + 8, 0x1000);
    put32(&mut data, table + 40 + 16, 0x1000);
    put16(&mut data, 0x98 + 68, 3);
    put16(&mut data, 0x96, 0x22);
    let dd = 0x98 + if wide { 112 } else { 96 };
    put32(&mut data, dd + 8, 0x2000);
    put32(&mut data, dd + 12, 40);
    put32(&mut data, 0x1200, 0x2180);
    put32(&mut data, 0x120c, 0x2040);
    put32(&mut data, 0x1210, 0x2080);
    data[0x1240..0x124d].copy_from_slice(b"kernel32.dll\0");
    for (i, name) in [
        "GetProcessHeap",
        "HeapCreate",
        "HeapAlloc",
        "HeapReAlloc",
        "HeapSize",
        "HeapFree",
        "HeapDestroy",
        "SetLastError",
        "GetLastError",
        "VirtualFree",
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
    let h = base + 0x2900;
    let p = base + 0x2910;
    let q = base + 0x2920;
    let value = 0x54535552;
    let mut c = Vec::new();
    if wide {
        c.extend([0x48, 0x83, 0xec, 0x48]);
    }
    call(&mut c, wide, base, 0, &[]);
    success(&mut c);
    store(&mut c, wide, h);
    if matches!(
        kind,
        HeapFixture::Executable
            | HeapFixture::WrongOwner
            | HeapFixture::Freed
            | HeapFixture::Lifecycle
            | HeapFixture::Fixed
    ) {
        call(
            &mut c,
            wide,
            base,
            1,
            &[
                V(if matches!(kind, HeapFixture::Executable) {
                    0x40000
                } else {
                    0
                }),
                V(0),
                V(if matches!(kind, HeapFixture::Fixed) {
                    4096
                } else {
                    0
                }),
            ],
        );
        success(&mut c);
        if !matches!(kind, HeapFixture::WrongOwner) {
            store(&mut c, wide, h);
        }
    }
    call(
        &mut c,
        wide,
        base,
        2,
        &[
            M(h),
            V(if matches!(kind, HeapFixture::Flags) {
                4
            } else {
                8
            }),
            V(if matches!(kind, HeapFixture::Zero) {
                0
            } else {
                16
            }),
        ],
    );
    success(&mut c);
    store(&mut c, wide, p);
    if matches!(kind, HeapFixture::Zero) {
        call(&mut c, wide, base, 4, &[M(h), V(0), M(p)]);
        expect(&mut c, 0);
    } else {
        indirect(&mut c, wide, p, 0, None);
        expect(&mut c, 0);
        indirect(&mut c, wide, p, 0, Some(value));
    }
    match kind {
        HeapFixture::Resize | HeapFixture::Move | HeapFixture::InPlace => {
            call(&mut c, wide, base, 7, &[V(77)]);
            let size = if matches!(kind, HeapFixture::Resize) {
                32
            } else {
                8192
            };
            call(
                &mut c,
                wide,
                base,
                3,
                &[
                    M(h),
                    V(if matches!(kind, HeapFixture::InPlace) {
                        16
                    } else {
                        8
                    }),
                    M(p),
                    V(size),
                ],
            );
            if matches!(kind, HeapFixture::InPlace) {
                failure(&mut c);
                call(&mut c, wide, base, 8, &[]);
                expect(&mut c, 77);
            } else {
                success(&mut c);
                store(&mut c, wide, q);
                if matches!(kind, HeapFixture::Resize) {
                    if wide {
                        c.push(0x48);
                    }
                    load(&mut c, wide, q);
                    if wide {
                        c.extend([0x48, 0x3b, 0x05]);
                        let next = 0x1000 + c.len() + 4;
                        c.extend(((p - base) as i32 - next as i32).to_le_bytes());
                    } else {
                        c.extend([0x3b, 0x05]);
                        c.extend((p as u32).to_le_bytes());
                    }
                    c.extend([0x74, 1, 0xcc]);
                } else {
                    if wide {
                        c.push(0x48);
                    }
                    load(&mut c, wide, q);
                    if wide {
                        c.extend([0x48, 0x3b, 0x05]);
                        let next = 0x1000 + c.len() + 4;
                        c.extend(((p - base) as i32 - next as i32).to_le_bytes());
                    } else {
                        c.extend([0x3b, 0x05]);
                        c.extend((p as u32).to_le_bytes());
                    }
                    c.extend([0x75, 1, 0xcc]);
                }
                indirect(&mut c, wide, q, 0, None);
                expect(&mut c, value);
                indirect(&mut c, wide, q, 16, None);
                expect(&mut c, 0);
                if wide {
                    c.push(0x48);
                }
                load(&mut c, wide, q);
                store(&mut c, wide, p);
            }
            indirect(&mut c, wide, p, 0, None);
            expect(&mut c, value);
            call(&mut c, wide, base, 4, &[M(h), V(0), M(p)]);
            expect(
                &mut c,
                if matches!(kind, HeapFixture::InPlace) {
                    16
                } else {
                    size as u32
                },
            );
        }
        HeapFixture::Executable | HeapFixture::Nx => {
            indirect(&mut c, wide, p, 0, Some(0x000011b8));
            indirect(&mut c, wide, p, 4, Some(0x0000c300));
            if wide {
                c.push(0x48);
            }
            load(&mut c, wide, p);
            c.extend([0xff, 0xd0]);
            expect(&mut c, 17);
        }
        HeapFixture::Freed => {
            call(&mut c, wide, base, 6, &[M(h)]);
            success(&mut c);
            indirect(&mut c, wide, p, 0, None);
        }
        HeapFixture::WrongOwner => {
            call(&mut c, wide, base, 1, &[V(0), V(0), V(0)]);
            store(&mut c, wide, q);
            call(&mut c, wide, base, 5, &[M(q), V(0), M(p)]);
        }
        HeapFixture::VirtualFree => {
            call(&mut c, wide, base, 9, &[M(p), V(0), V(0x8000)]);
        }
        _ => {}
    }
    call(&mut c, wide, base, 5, &[M(h), V(0), M(p)]);
    success(&mut c);
    if matches!(kind, HeapFixture::DoubleFree) {
        call(&mut c, wide, base, 5, &[M(h), V(0), M(p)]);
    }
    call(&mut c, wide, base, 5, &[M(h), V(0), V(0)]);
    success(&mut c);
    if matches!(kind, HeapFixture::Lifecycle | HeapFixture::Executable) {
        call(&mut c, wide, base, 6, &[M(h)]);
        success(&mut c);
    }
    // The native return proves all preceding guest checks ran without a trap.
    c.extend([0xb8, 1, 0, 0, 0]);
    if wide {
        c.extend([0x48, 0x83, 0xc4, 0x48]);
    }
    c.push(0xc3);
    assert!(c.len() <= 0x1000);
    data[0x200..0x200 + c.len()].copy_from_slice(&c);
    data
}
