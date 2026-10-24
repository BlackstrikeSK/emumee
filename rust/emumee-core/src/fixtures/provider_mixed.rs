//! Owned driver import/provider rebinding controls; no genuine driver bytes.
use super::winhttp::{
    Arg::{Memory as M, Value as V},
    call, store,
};
use super::{ApiFixture, api_probe, put16, put32, put64};
use crate::pe::Architecture;
#[derive(Clone, Copy, Debug)]
pub enum ProviderMixedFixture {
    Lifecycle,
    UnmodeledCode,
}
pub const ROUTINES: [&str; 19] = [
    "IoAllocateMdl",
    "MmBuildMdlForNonPagedPool",
    "IoFreeMdl",
    "MmGetPhysicalAddress",
    "MmMapLockedPagesSpecifyCache",
    "MmUnmapLockedPages",
    "ExAllocateCacheAwareRundownProtection",
    "ExFreeCacheAwareRundownProtection",
    "ExAcquireRundownProtectionCacheAware",
    "ExAcquireRundownProtectionCacheAwareEx",
    "ExReleaseRundownProtectionCacheAware",
    "ExReleaseRundownProtectionCacheAwareEx",
    "ExWaitForRundownProtectionReleaseCacheAware",
    "KeRegisterBugCheckReasonCallback",
    "KeDeregisterBugCheckReasonCallback",
    "ExCreateCallback",
    "ExRegisterCallback",
    "ExUnregisterCallback",
    "ExNotifyCallback",
];
fn fast(code: &mut Vec<u8>, wide: bool, base: u64, index: usize, args: &[super::winhttp::Arg]) {
    if wide {
        call(code, wide, base, index, args);
        return;
    }
    assert!(args.len() <= 2);
    for (at, arg) in args.iter().enumerate() {
        match arg {
            V(value) => {
                code.push(if at == 0 { 0xb9 } else { 0xba });
                code.extend((*value as u32).to_le_bytes());
            }
            M(address) => {
                code.extend(if at == 0 { [0x8b, 0x0d] } else { [0x8b, 0x15] });
                code.extend((*address as u32).to_le_bytes());
            }
        }
    }
    code.extend([0xff, 0x15]);
    code.extend(((base + 0x2080) as u32 + index as u32 * 4).to_le_bytes());
}
fn expect(code: &mut Vec<u8>, value: u32) {
    code.push(0x3d);
    code.extend(value.to_le_bytes());
    code.extend([0x74, 1, 0xcc]);
}
fn load(code: &mut Vec<u8>, wide: bool, address: u64) {
    if wide {
        code.push(0x48);
    }
    code.push(0xa1);
    if wide {
        code.extend(address.to_le_bytes());
    } else {
        code.extend((address as u32).to_le_bytes());
    }
}
fn compare_pointer(code: &mut Vec<u8>, wide: bool, slot: u64) {
    // Save the real resolver result, read the rebound static import, compare.
    if wide {
        code.extend([0x48, 0x89, 0xc2]);
    } else {
        code.extend([0x89, 0xc2]);
    }
    load(code, wide, slot);
    if wide {
        code.push(0x48);
    }
    code.extend([0x39, 0xd0, 0x74, 1, 0xcc]);
    if wide {
        code.push(0x48);
    }
    code.extend([0x85, 0xc0, 0x75, 1, 0xcc]);
}
fn unicode(data: &mut [u8], wide: bool, base: u64, index: usize, name: &str) -> u64 {
    let descriptor = 0x3000 + index * 16;
    let string = 0x3400 + index * 128;
    let value = name
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    assert!(value.len() < 126);
    let at = descriptor - 0xe00;
    put16(data, at, value.len() as u16);
    put16(data, at + 2, value.len() as u16);
    if wide {
        put64(data, at + 8, base + string as u64);
    } else {
        put32(data, at + 4, (base + string as u64) as u32);
    }
    data[string - 0xe00..string - 0xe00 + value.len()].copy_from_slice(&value);
    base + descriptor as u64
}
pub fn provider_mixed_probe(architecture: Architecture, kind: ProviderMixedFixture) -> Vec<u8> {
    let wide = architecture == Architecture::X64;
    let width = architecture.width();
    let base = if wide { 0x140000000u64 } else { 0x400000 };
    let original = api_probe(architecture, ApiFixture::PoolLifecycle);
    let mut data = vec![0; 0x5200];
    data[..0x200].copy_from_slice(&original[..0x200]);
    let table = 0x98 + if wide { 0xf0 } else { 0xe0 };
    let dd = 0x98 + if wide { 112 } else { 96 };
    for (at, value) in [
        (0x98 + 4, 0x1000),
        (0x98 + 8, 0x4000),
        (0x98 + 56, 0x6000),
        (table + 8, 0x1000),
        (table + 16, 0x1000),
        (table + 40 + 8, 0x4000),
        (table + 40 + 16, 0x4000),
        (table + 40 + 20, 0x1200),
        (dd + 8, 0x2000),
        (dd + 12, 40),
        (0x1200, 0x2180),
        (0x120c, 0x2040),
        (0x1210, 0x2080),
    ] {
        put32(&mut data, at, value);
    }
    data[0x1240..0x124d].copy_from_slice(b"ntoskrnl.exe\0");
    let mut names = vec!["MmGetSystemRoutineAddress"];
    names.extend(ROUTINES);
    names.extend(["ExAllocatePoolWithTag", "ExFreePoolWithTag"]);
    for (index, name) in names.iter().enumerate() {
        let rva = 0x2300 + index as u32 * 64;
        for raw in [0x1280, 0x1380] {
            if wide {
                put64(&mut data, raw + index * width, rva.into());
            } else {
                put32(&mut data, raw + index * width, rva);
            }
        }
        let raw = 0x1500 + index * 64;
        data[raw + 2..raw + 2 + name.len()].copy_from_slice(name.as_bytes());
    }
    data[0x4500..0x4506].copy_from_slice(b"owned\0"); // RVA5300 component.
    data[0x1100] = 0xc3; // RVA1f00 routine must be executable, never invoked.
    let mut code = Vec::new();
    if wide {
        code.extend([0x48, 0x83, 0xec, 0x68]);
    }
    for (index, name) in ROUTINES.iter().enumerate() {
        let string = unicode(&mut data, wide, base, index, name);
        call(&mut code, wide, base, 0, &[V(string)]);
        compare_pointer(
            &mut code,
            wide,
            base + 0x2080 + (index + 1) as u64 * width as u64,
        );
    }
    let tag = 0x4d697865u64;
    call(&mut code, wide, base, 20, &[V(512), V(0x3000), V(tag)]);
    store(&mut code, wide, base + 0x5000);
    call(
        &mut code,
        wide,
        base,
        1,
        &[M(base + 0x5000), V(0x1000), V(0), V(0), V(0)],
    );
    store(&mut code, wide, base + 0x5008);
    call(&mut code, wide, base, 2, &[M(base + 0x5008)]);
    call(&mut code, wide, base, 4, &[M(base + 0x5000)]);
    code.extend([0x85, 0xc0, 0x75, 1, 0xcc]);
    call(
        &mut code,
        wide,
        base,
        5,
        &[M(base + 0x5008), V(1), V(1), V(0), V(0), V(0)],
    );
    store(&mut code, wide, base + 0x5010);
    load(&mut code, wide, base + 0x5000);
    code.extend([0xc7, 0, 0x78, 0x56, 0x34, 0x12]);
    load(&mut code, wide, base + 0x5010);
    code.extend([0x81, 0x38, 0x78, 0x56, 0x34, 0x12, 0x74, 1, 0xcc]);
    call(
        &mut code,
        wide,
        base,
        6,
        &[M(base + 0x5010), M(base + 0x5008)],
    );
    call(&mut code, wide, base, 3, &[M(base + 0x5008)]);
    call(&mut code, wide, base, 21, &[M(base + 0x5000), V(tag)]);
    call(&mut code, wide, base, 7, &[V(0x600), V(tag)]);
    store(&mut code, wide, base + 0x5018);
    fast(&mut code, wide, base, 10, &[M(base + 0x5018), V(3)]);
    expect(&mut code, 1);
    fast(&mut code, wide, base, 12, &[M(base + 0x5018), V(3)]);
    fast(&mut code, wide, base, 9, &[M(base + 0x5018)]);
    expect(&mut code, 1);
    fast(&mut code, wide, base, 11, &[M(base + 0x5018)]);
    fast(&mut code, wide, base, 13, &[M(base + 0x5018)]);
    fast(&mut code, wide, base, 9, &[M(base + 0x5018)]);
    expect(&mut code, 0);
    call(&mut code, wide, base, 8, &[M(base + 0x5018)]);
    call(
        &mut code,
        wide,
        base,
        14,
        &[V(base + 0x5200), V(base + 0x1f00), V(2), V(base + 0x5300)],
    );
    expect(&mut code, 1);
    call(&mut code, wide, base, 15, &[V(base + 0x5200)]);
    expect(&mut code, 1);
    if matches!(kind, ProviderMixedFixture::UnmodeledCode) {
        let string = unicode(&mut data, wide, base, 19, "KeInsertQueueDpc");
        call(&mut code, wide, base, 0, &[V(string)]);
        if wide {
            code.extend([0x48, 0x85, 0xc0, 0x75, 1, 0xcc, 0xff, 0xd0, 0xcc]);
        } else {
            expect(&mut code, 0);
        }
    }
    code.extend([0xb8, 1, 0, 0, 0]);
    if wide {
        code.extend([0x48, 0x83, 0xc4, 0x68]);
    }
    code.push(0xc3);
    assert!(code.len() < 0xf00);
    data[0x200..0x200 + code.len()].copy_from_slice(&code);
    data
}
