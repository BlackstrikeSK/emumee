//! Nested guest threads exercise aggregate TLS admission without partial state.
use super::winhttp::{
    Arg::{Memory as M, Value as V},
    call, load, store,
};
use super::*;

fn equal(code: &mut Vec<u8>, value: u32) {
    code.push(0x3d);
    code.extend(value.to_le_bytes());
    code.extend([0x74, 1, 0xcc]);
}
fn create(code: &mut Vec<u8>, wide: bool, base: u64, parameter: super::winhttp::Arg) {
    call(
        code,
        wide,
        base,
        0,
        &[V(0), V(0), V(base + 0x1800), parameter, V(0), V(0)],
    );
}
fn close(code: &mut Vec<u8>, wide: bool, base: u64) {
    store(code, wide, base + 0x3f28);
    call(code, wide, base, 9, &[M(base + 0x3f28)]);
    equal(code, 1);
}
pub fn m3_tls_quota_probe(architecture: Architecture) -> (Vec<u8>, Vec<(String, Vec<u8>)>) {
    let wide = architecture == Architecture::X64;
    let width = architecture.width();
    let base = if wide { 0x140000000u64 } else { 0x400000 };
    let mut root = m3_thread_probe(architecture, M3ThreadFixture::Return);
    let first = root[0x1200..0x1214].to_vec();
    root[0x2600..0x2800].fill(0);
    root[0x2600..0x2614].copy_from_slice(&first);
    let directories = 0x98 + if wide { 112 } else { 96 };
    put32(&mut root, directories + 8, 0x3400);
    put32(&mut root, directories + 12, 18 * 20);
    let mut companions = Vec::new();
    for index in 0..16usize {
        let name = format!("tls{index:02}.dll");
        let descriptor = 0x2600 + (index + 1) * 20;
        let ilt = 0x3600 + index * 16;
        let iat = 0x3800 + index * 16;
        let module = 0x3a00 + index * 16;
        put32(&mut root, descriptor, ilt as u32);
        put32(&mut root, descriptor + 12, module as u32);
        put32(&mut root, descriptor + 16, iat as u32);
        for rva in [ilt, iat] {
            root[rva - 0xe00..rva - 0xe00 + 2 * width].fill(0);
            root[rva - 0xe00..rva - 0xe00 + width]
                .copy_from_slice(&0x3b80u64.to_le_bytes()[..width]);
        }
        root[module - 0xe00..module - 0xe00 + 16].fill(0);
        root[module - 0xe00..module - 0xe00 + name.len()].copy_from_slice(name.as_bytes());
        let preferred = if wide { 0x150000000 } else { 0x500000 } + index as u64 * 0x10000;
        let mut bytes = super::m3_companion::companion_at(architecture, preferred, &name);
        put32(&mut bytes, 0x4200 + 4 * width, 1024 * 1024 - 4);
        companions.push((name, bytes));
    }
    root[0x2d80..0x2d88].fill(0);
    root[0x2d82..0x2d88].copy_from_slice(b"Alpha\0");
    put32(&mut root, 0x3000 + 4 * width, 1024 * 1024 - 4);
    root[0x200..0x1100].fill(0);
    let mut parent = Vec::new();
    if wide {
        parent.extend([0x48, 0x83, 0xec, 0x48]);
    }
    create(&mut parent, wide, base, V(4));
    parent.extend([0x85, 0xc0, 0x75, 1, 0xcc]);
    close(&mut parent, wide, base);
    load(&mut parent, wide, base + 0x3f30);
    equal(&mut parent, 1);
    parent.extend([0xb8, 42, 0, 0, 0]);
    if wide {
        parent.extend([0x48, 0x83, 0xc4, 0x48]);
    }
    parent.push(0xc3);
    root[0x200..0x200 + parent.len()].copy_from_slice(&parent);
    let mut child = vec![0; 0x800];
    if wide {
        child.extend([0x89, 0xc8, 0x48, 0x83, 0xec, 0x48]);
    } else {
        child.extend([0x8b, 0x44, 0x24, 4]);
    }
    child.extend([0x83, 0xe8, 1]);
    store(&mut child, wide, base + 0x3f20);
    create(&mut child, wide, base, M(base + 0x3f20));
    child.extend([0x85, 0xc0, 0x0f, 0x85]);
    let success = child.len();
    child.extend([0; 4]);
    call(&mut child, wide, base, 3, &[]);
    equal(&mut child, 8);
    if wide {
        child.extend([0x48, 0xb8]);
        child.extend((base + 0x3f30).to_le_bytes());
        child.extend([0xff, 0]);
    } else {
        child.extend([0xff, 5]);
        child.extend(((base + 0x3f30) as u32).to_le_bytes());
    }
    child.push(0xe9);
    let done = child.len();
    child.extend([0; 4]);
    let target = child.len();
    child[success..success + 4].copy_from_slice(&((target - success - 4) as u32).to_le_bytes());
    close(&mut child, wide, base);
    let target = child.len();
    child[done..done + 4].copy_from_slice(&((target - done - 4) as u32).to_le_bytes());
    child.extend([0xb8, 42, 0, 0, 0]);
    if wide {
        child.extend([0x48, 0x83, 0xc4, 0x48, 0xc3]);
    } else {
        child.extend([0xc2, 4, 0]);
    }
    assert!(child.len() - 0x800 < 0x700);
    root[0xa00..0xa00 + child.len() - 0x800].copy_from_slice(&child[0x800..]);
    (root, companions)
}
