//! Guest-only thread controls with direct TEB/static TLS and dynamic-slot checks.
use super::winhttp::{
    Arg::{Memory as M, Value as V},
    call, load, store,
};
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum M3ThreadFixture {
    Return,
    Exit,
    Terminate,
    Suspended,
    Budget,
    Fault,
}
fn expect(code: &mut Vec<u8>, value: u32) {
    code.push(0x3d);
    code.extend(value.to_le_bytes());
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
pub fn m3_thread_probe(architecture: Architecture, kind: M3ThreadFixture) -> Vec<u8> {
    let wide = architecture == Architecture::X64;
    let base = if wide { 0x140000000u64 } else { 0x400000 };
    let mut bytes = m3_storage_probe(architecture, false);
    for (index, name) in [
        "CreateThread",
        "GetCurrentProcessId",
        "GetCurrentThreadId",
        "GetLastError",
        "SetLastError",
        "TlsAlloc",
        "TlsSetValue",
        "TlsGetValue",
        "GetExitCodeThread",
        "CloseHandle",
        "ResumeThread",
        "ExitThread",
        "TerminateThread",
    ]
    .iter()
    .enumerate()
    {
        let raw = 0x2300 + index * 64 - 0xe00;
        bytes[raw..raw + 64].fill(0);
        bytes[raw + 2..raw + 2 + name.len()].copy_from_slice(name.as_bytes());
    }
    put32(&mut bytes, 0x98 + 16, 0x1000);
    bytes[0x200..0x1200].fill(0);
    let mut parent = vec![];
    if wide {
        parent.extend([0x48, 0x83, 0xec, 0x48]);
    }
    call(&mut parent, wide, base, 5, &[]);
    store(&mut parent, wide, base + 0x3f00);
    call(&mut parent, wide, base, 6, &[M(base + 0x3f00), V(99)]);
    expect(&mut parent, 1);
    call(
        &mut parent,
        wide,
        base,
        0,
        &[
            V(0),
            V(0),
            V(base + 0x1800),
            V(42),
            V(if kind == M3ThreadFixture::Suspended {
                4
            } else {
                0
            }),
            V(base + 0x3f08),
        ],
    );
    parent.extend([0x85, 0xc0, 0x75, 1, 0xcc]);
    store(&mut parent, wide, base + 0x3f10);
    if kind == M3ThreadFixture::Suspended {
        call(
            &mut parent,
            wide,
            base,
            8,
            &[M(base + 0x3f10), V(base + 0x3f18)],
        );
        expect(&mut parent, 1);
        load(&mut parent, wide, base + 0x3f18);
        expect(&mut parent, 259);
        call(&mut parent, wide, base, 10, &[M(base + 0x3f10)]);
        expect(&mut parent, 1);
    }
    call(&mut parent, wide, base, 3, &[]);
    expect(&mut parent, 0);
    call(
        &mut parent,
        wide,
        base,
        8,
        &[M(base + 0x3f10), V(base + 0x3f18)],
    );
    expect(&mut parent, 1);
    // All mutable output is in the same guest image; dword reads use a native
    // absolute pointer on x64 as well, rather than truncating the image base.
    load(&mut parent, wide, base + 0x3f18);
    expect(
        &mut parent,
        match kind {
            M3ThreadFixture::Exit => 73,
            M3ThreadFixture::Terminate => 74,
            _ => 42,
        },
    );
    call(&mut parent, wide, base, 2, &[]);
    expect(&mut parent, 1);
    call(&mut parent, wide, base, 7, &[M(base + 0x3f00)]);
    expect(&mut parent, 99);
    block(&mut parent, wide, base + 0x3d40);
    parent.extend([0x81, 0x38]);
    parent.extend(0x12345678u32.to_le_bytes());
    parent.extend([0x74, 1, 0xcc]);
    parent.extend([0x83, 0x78, 4, 1, 0x74, 1, 0xcc]);
    load(&mut parent, wide, base + 0x3e80);
    expect(
        &mut parent,
        if kind == M3ThreadFixture::Terminate {
            0x23
        } else {
            0x234
        },
    );
    call(&mut parent, wide, base, 9, &[M(base + 0x3f10)]);
    expect(&mut parent, 1);
    call(
        &mut parent,
        wide,
        base,
        8,
        &[M(base + 0x3f10), V(base + 0x3f18)],
    );
    expect(&mut parent, 0);
    parent.extend([0xb8, 42, 0, 0, 0]);
    if wide {
        parent.extend([0x48, 0x83, 0xc4, 0x48]);
    }
    parent.push(0xc3);
    assert!(parent.len() < 0x800);
    bytes[0x200..0x200 + parent.len()].copy_from_slice(&parent);
    // Padding lets the common IAT emitter calculate RIP-relative calls for
    // the real child RVA 0x1800, independently of the parent program length.
    let mut child = vec![0; 0x800];
    if wide {
        child.extend([0x83, 0xf9, 42, 0x74, 1, 0xcc, 0x48, 0x83, 0xec, 0x48]);
    } else {
        child.extend([0x83, 0x7c, 0x24, 4, 42, 0x74, 1, 0xcc]);
    }
    call(&mut child, wide, base, 2, &[]);
    expect(&mut child, 2);
    call(&mut child, wide, base, 7, &[M(base + 0x3f00)]);
    expect(&mut child, 0);
    call(&mut child, wide, base, 4, &[V(222)]);
    block(&mut child, wide, base + 0x3d40);
    child.extend([0x83, 0x78, 4, 2, 0x74, 1, 0xcc, 0xc7, 0]);
    child.extend(0x87654321u32.to_le_bytes());
    match kind {
        M3ThreadFixture::Exit => call(&mut child, wide, base, 11, &[V(73)]),
        M3ThreadFixture::Terminate => call(
            &mut child,
            wide,
            base,
            12,
            &[
                V(if wide {
                    u64::MAX - 1
                } else {
                    u32::MAX as u64 - 1
                }),
                V(74),
            ],
        ),
        M3ThreadFixture::Budget => child.extend([0xeb, 0xfe]),
        M3ThreadFixture::Fault => child.extend([0x0f, 0x0b]),
        _ => {}
    }
    child.extend([0xb8, 42, 0, 0, 0]);
    if wide {
        child.extend([0x48, 0x83, 0xc4, 0x48, 0xc3]);
    } else {
        child.extend([0xc2, 4, 0]);
    }
    assert!(child.len() - 0x800 < 0x700);
    bytes[0xa00..0xa00 + child.len() - 0x800].copy_from_slice(&child[0x800..]);
    let mut callback = vec![];
    if !wide {
        callback.extend([0x8b, 0x54, 0x24, 8]);
    }
    if wide {
        callback.extend([0x49, 0xb8]);
        callback.extend((base + 0x3e80).to_le_bytes());
        callback.extend([0x41, 0x8b, 8]);
    } else {
        callback.extend([0x8b, 0x0d]);
        callback.extend(((base + 0x3e80) as u32).to_le_bytes());
    }
    callback.extend([0xc1, 0xe1, 4, 0x83, 0xc2, 1, 0x09, 0xd1]);
    if wide {
        callback.extend([0x41, 0x89, 8]);
    } else {
        callback.extend([0x89, 0x0d]);
        callback.extend(((base + 0x3e80) as u32).to_le_bytes());
    }
    block(&mut callback, wide, base + 0x3d40);
    callback.extend(if wide {
        vec![0x65, 0x8b, 0x14, 0x25, 0x48, 0, 0, 0]
    } else {
        vec![0x64, 0x8b, 0x15, 0x24, 0, 0, 0]
    });
    callback.extend([0x89, 0x50, 4]);
    callback.extend(if wide { vec![0xc3] } else { vec![0xc2, 12, 0] });
    assert!(callback.len() < 0x100);
    bytes[0x1100..0x1100 + callback.len()].copy_from_slice(&callback);
    bytes
}
