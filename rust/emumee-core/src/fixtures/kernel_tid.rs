//! Actual root/created/IPI caller identities, using the shared thread lifetime.
use super::winhttp::{
    Arg,
    Arg::{Memory as M, Value as V},
    call, load, store, write_dword,
};
use super::{ThreadObjectFixture, kernel_thread_objects_probe, put32, put64};
use crate::pe::Architecture;
fn invoke(c: &mut Vec<u8>, wide: bool, base: u64, origin: u32, index: usize, args: &[Arg]) {
    call(c, wide, base, index, args);
    if wide {
        let end = c.len();
        let delta = 0x2080i64 + index as i64 * 8 - i64::from(origin) - end as i64;
        c[end - 4..].copy_from_slice(&i32::try_from(delta).unwrap().to_le_bytes());
    }
}
fn expect(c: &mut Vec<u8>, wide: bool, value: u64) {
    if wide {
        c.extend([0x48, 0xba]);
        c.extend(value.to_le_bytes());
        c.extend([0x48, 0x39, 0xd0]);
    } else {
        c.push(0x3d);
        c.extend((value as u32).to_le_bytes());
    }
    c.extend([0x74, 1, 0xcc]);
}
fn prologue(c: &mut Vec<u8>, wide: bool) {
    if wide {
        c.extend([0x48, 0x83, 0xec, 0x48]);
    }
}
fn returned(c: &mut Vec<u8>, wide: bool, callback: bool) {
    if wide {
        c.extend([0x48, 0x83, 0xc4, 0x48]);
    }
    if callback && !wide {
        c.extend([0xc2, 4, 0]);
    } else {
        c.push(0xc3);
    }
}
pub fn kernel_tid_probe(arch: Architecture) -> Vec<u8> {
    let mut data = kernel_thread_objects_probe(arch, ThreadObjectFixture::Lifecycle);
    let wide = arch == Architecture::X64;
    let width = arch.width();
    let base = if wide { 0x140000000u64 } else { 0x400000 };
    data[0x1280..0x1900].fill(0);
    let names = [
        "PsGetCurrentThreadId",
        "PsCreateSystemThread",
        "PsTerminateSystemThread",
        "ZwClose",
        "KeIpiGenericCall",
    ];
    for (i, name) in names.iter().enumerate() {
        let rva = 0x2300 + i as u32 * 64;
        for raw in [0x1280, 0x1380] {
            if wide {
                put64(&mut data, raw + i * width, u64::from(rva));
            } else {
                put32(&mut data, raw + i * width, rva);
            }
        }
        let raw = 0x1500 + i * 64;
        data[raw + 2..raw + 2 + name.len()].copy_from_slice(name.as_bytes());
    }
    data[0x1e00..0x1f00].fill(0);
    let handle = base + 0x2c00;
    let client = base + 0x2c10;
    let flag = base + 0x2c30;
    let child_tid = base + 0x2c48;
    let mut root = Vec::new();
    prologue(&mut root, wide);
    invoke(&mut root, wide, base, 0x1000, 0, &[]);
    expect(&mut root, wide, 0x1004);
    invoke(
        &mut root,
        wide,
        base,
        0x1000,
        1,
        &[
            V(handle),
            V(0x1fffff),
            V(0),
            V(0),
            V(client),
            V(base + 0x1c00),
            V(0),
        ],
    );
    expect(&mut root, wide, 0);
    let loop_at = root.len();
    root.extend([0xba]);
    if wide {
        root.pop();
        root.extend([0x48, 0xba]);
        root.extend(flag.to_le_bytes());
    } else {
        root.extend((flag as u32).to_le_bytes());
    }
    root.extend([0x83, 0x3a, 1, 0x0f, 0x85]);
    let next = root.len() + 4;
    root.extend(
        i32::try_from(loop_at as i64 - next as i64)
            .unwrap()
            .to_le_bytes(),
    );
    load(&mut root, wide, client);
    expect(&mut root, wide, 4);
    load(&mut root, wide, client + width as u64);
    expect(&mut root, wide, 0x1008);
    invoke(&mut root, wide, base, 0x1000, 0, &[]);
    expect(&mut root, wide, 0x1004);
    invoke(&mut root, wide, base, 0x1000, 3, &[M(handle)]);
    expect(&mut root, wide, 0);
    invoke(
        &mut root,
        wide,
        base,
        0x1000,
        4,
        &[V(base + 0x1d00), V(0xc0ffee)],
    );
    expect(&mut root, wide, 0x1004);
    root.push(0xb8);
    root.extend(17u32.to_le_bytes());
    returned(&mut root, wide, false);
    let mut child = Vec::new();
    prologue(&mut child, wide);
    invoke(&mut child, wide, base, 0x1c00, 0, &[]);
    expect(&mut child, wide, 0x1008);
    store(&mut child, wide, child_tid);
    load(&mut child, wide, client + width as u64);
    if wide {
        child.extend([0x48, 0xba]);
        child.extend(child_tid.to_le_bytes());
        child.extend([0x48, 0x3b, 0x02]);
    } else {
        child.push(0xba);
        child.extend((child_tid as u32).to_le_bytes());
        child.extend([0x3b, 0x02]);
    }
    child.extend([0x74, 1, 0xcc]);
    write_dword(&mut child, wide, flag, 1);
    invoke(&mut child, wide, base, 0x1c00, 2, &[V(0)]);
    child.push(0xcc);
    let mut callback = Vec::new();
    prologue(&mut callback, wide);
    invoke(&mut callback, wide, base, 0x1d00, 0, &[]);
    returned(&mut callback, wide, true);
    assert!(root.len() < 0xc00 && child.len() < 0x100 && callback.len() < 0x100);
    data[0x200..0x1200].fill(0);
    data[0x200..0x200 + root.len()].copy_from_slice(&root);
    data[0xe00..0xe00 + child.len()].copy_from_slice(&child);
    data[0xf00..0xf00 + callback.len()].copy_from_slice(&callback);
    data
}
