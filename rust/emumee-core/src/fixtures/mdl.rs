//! Owned driver programs check MDL geometry, alias bytes and negative controls.
use super::winhttp::{
    Arg::{Memory as M, Value as V},
    call, store,
};
use super::{ApiFixture, api_probe, put32, put64};
use crate::pe::Architecture;

#[derive(Clone, Copy, Debug)]
pub enum MdlFixture {
    Lifecycle,
    Alias,
    ReadOnlyCpu,
    ReadOnlyApi,
    Nx,
    Unmapped,
    FreeActive,
    PoolFreeActive,
    Flags,
    Geometry,
    Unbuilt,
}

fn load_pointer(code: &mut Vec<u8>, wide: bool, address: u64) {
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
fn expect_dword(code: &mut Vec<u8>, value: u32) {
    code.push(0x3d);
    code.extend(value.to_le_bytes());
    code.extend([0x74, 1, 0xcc]);
}
fn expect_pointer(code: &mut Vec<u8>, wide: bool, value: u64) {
    if wide {
        code.extend([0x48, 0xba]);
        code.extend(value.to_le_bytes());
        code.extend([0x48, 0x39, 0xd0, 0x74, 1, 0xcc]);
    } else {
        expect_dword(code, value as u32);
    }
}
fn read_field(code: &mut Vec<u8>, wide: bool, slot: u64, offset: u32, pointer: bool) {
    load_pointer(code, wide, slot);
    if wide && pointer {
        code.push(0x48);
    }
    code.extend([0x8b, 0x80]);
    code.extend(offset.to_le_bytes());
}
fn write_field(code: &mut Vec<u8>, wide: bool, slot: u64, offset: u32, value: u32) {
    load_pointer(code, wide, slot);
    code.extend([0xc7, 0x80]);
    code.extend(offset.to_le_bytes());
    code.extend(value.to_le_bytes());
}
fn check_geometry(code: &mut Vec<u8>, wide: bool, slot: u64, source: u64, built: bool) {
    let (width, header, start, mapped, process) = if wide {
        (8, 48, 32, 24, 16)
    } else {
        (4, 28, 16, 12, 8)
    };
    read_field(code, wide, slot, 0, true);
    expect_pointer(code, wide, 0);
    read_field(code, wide, slot, process, true);
    expect_pointer(code, wide, 0);
    read_field(code, wide, slot, width, false);
    expect_dword(code, header + 3 * width + if built { 4 << 16 } else { 0 });
    read_field(code, wide, slot, start, true);
    expect_pointer(code, wide, source);
    read_field(code, wide, slot, start + width, false);
    expect_dword(code, 0x2000);
    read_field(code, wide, slot, start + width + 4, false);
    expect_dword(code, 0x123);
    read_field(code, wide, slot, mapped, true);
    expect_pointer(code, wide, if built { source + 0x123 } else { 0 });
    for index in 0..3 {
        read_field(code, wide, slot, header + index * width, true);
        expect_pointer(code, wide, if built { 256 + index as u64 } else { 0 });
    }
}

/// Driver subsystem1 is preserved from the kernel pool fixture header. The
/// import module remains ntoskrnl.exe; never reclassify these as user targets.
pub fn mdl_probe(architecture: Architecture, kind: MdlFixture) -> Vec<u8> {
    let wide = architecture == Architecture::X64;
    let base = if wide { 0x140000000u64 } else { 0x400000 };
    let pool_base = if wide {
        0xffffb00000000000u64
    } else {
        0xe0000000
    };
    let width = architecture.width();
    let original = api_probe(architecture, ApiFixture::PoolLifecycle);
    let mut data = vec![0; 0x3200];
    data[..0x200].copy_from_slice(&original[..0x200]);
    let table = 0x98 + if wide { 0xf0 } else { 0xe0 };
    let dd = 0x98 + if wide { 112 } else { 96 };
    put32(&mut data, 0x98 + 4, 0x1000);
    put32(&mut data, 0x98 + 8, 0x2000);
    put32(&mut data, 0x98 + 56, 0x4000);
    put32(&mut data, table + 8, 0x1000);
    put32(&mut data, table + 16, 0x1000);
    put32(&mut data, table + 40 + 8, 0x2000);
    put32(&mut data, table + 40 + 16, 0x2000);
    put32(&mut data, table + 40 + 20, 0x1200);
    put32(&mut data, dd + 8, 0x2000);
    put32(&mut data, dd + 12, 40);
    put32(&mut data, 0x1200, 0x2180);
    put32(&mut data, 0x120c, 0x2040);
    put32(&mut data, 0x1210, 0x2080);
    data[0x1240..0x124d].copy_from_slice(b"ntoskrnl.exe\0");
    let imports = [
        "ExAllocatePool2",
        "IoAllocateMdl",
        "MmBuildMdlForNonPagedPool",
        "IoFreeMdl",
        "MmGetPhysicalAddress",
        "MmMapLockedPagesSpecifyCache",
        "MmUnmapLockedPages",
        "RtlMoveMemory",
        "ExFreePoolWithTag",
    ];
    for (index, name) in imports.iter().enumerate() {
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
    data[0x1c00..0x1c04].copy_from_slice(b"API!");
    let pool = base + 0x2c00;
    let buffer = base + 0x2c10;
    let mdl = base + 0x2c20;
    let alias = base + 0x2c30;
    let mut code = Vec::new();
    if wide {
        code.extend([0x48, 0x83, 0xec, 0x68]);
    }
    let allocate = if wide {
        vec![V(0x40), V(0x4000), V(1)]
    } else {
        vec![V(0x40), V(0), V(0x4000), V(1)]
    };
    call(&mut code, wide, base, 0, &allocate);
    store(&mut code, wide, pool);
    expect_pointer(&mut code, wide, pool_base);
    load_pointer(&mut code, wide, pool);
    if wide {
        code.push(0x48);
    }
    code.push(0x05);
    code.extend(0x123u32.to_le_bytes());
    store(&mut code, wide, buffer);
    write_field(&mut code, wide, buffer, 0, u32::from_le_bytes(*b"EMU!"));
    call(
        &mut code,
        wide,
        base,
        1,
        &[M(buffer), V(0x2000), V(0), V(0), V(0)],
    );
    store(&mut code, wide, mdl);
    expect_pointer(&mut code, wide, pool_base + 0x4000);
    check_geometry(&mut code, wide, mdl, pool_base, false);
    if matches!(kind, MdlFixture::Geometry) {
        write_field(&mut code, wide, mdl, if wide { 40 } else { 20 }, 0x1000);
        call(&mut code, wide, base, 2, &[M(mdl)]);
        code.push(0xcc);
    } else if matches!(kind, MdlFixture::Unbuilt) {
        call(
            &mut code,
            wide,
            base,
            5,
            &[M(mdl), V(1), V(1), V(0), V(0), V(0)],
        );
        code.push(0xcc);
    } else {
        call(&mut code, wide, base, 2, &[M(mdl)]);
        check_geometry(&mut code, wide, mdl, pool_base, true);
        call(&mut code, wide, base, 4, &[M(buffer)]);
        expect_pointer(&mut code, wide, 256 * 4096 + 0x123);
        if !matches!(kind, MdlFixture::Lifecycle) {
            let priority = if matches!(kind, MdlFixture::Flags) {
                1
            } else if matches!(kind, MdlFixture::ReadOnlyCpu | MdlFixture::ReadOnlyApi) {
                0x80000000
            } else {
                0
            };
            call(
                &mut code,
                wide,
                base,
                5,
                &[M(mdl), V(1), V(1), V(0), V(0), V(priority)],
            );
            store(&mut code, wide, alias);
            expect_pointer(&mut code, wide, 0x40000123);
            call(&mut code, wide, base, 4, &[M(alias)]);
            expect_pointer(&mut code, wide, 256 * 4096 + 0x123);
            match kind {
                MdlFixture::Nx => {
                    load_pointer(&mut code, wide, alias);
                    code.extend([0xff, 0xd0, 0xcc]);
                }
                MdlFixture::FreeActive => {
                    call(&mut code, wide, base, 3, &[M(mdl)]);
                    code.push(0xcc);
                }
                MdlFixture::PoolFreeActive => {
                    call(&mut code, wide, base, 8, &[M(pool), V(1)]);
                    code.push(0xcc);
                }
                MdlFixture::ReadOnlyApi => {
                    call(
                        &mut code,
                        wide,
                        base,
                        7,
                        &[M(alias), V(base + 0x2a00), V(4)],
                    );
                    code.push(0xcc);
                }
                MdlFixture::ReadOnlyCpu => {
                    write_field(&mut code, wide, alias, 0, u32::from_le_bytes(*b"CPU!"));
                    code.push(0xcc);
                }
                MdlFixture::Alias | MdlFixture::Unmapped => {
                    write_field(&mut code, wide, alias, 0, u32::from_le_bytes(*b"CPU!"));
                    read_field(&mut code, wide, buffer, 0, false);
                    expect_dword(&mut code, u32::from_le_bytes(*b"CPU!"));
                    call(
                        &mut code,
                        wide,
                        base,
                        7,
                        &[M(buffer), V(base + 0x2a00), V(4)],
                    );
                    read_field(&mut code, wide, alias, 0, false);
                    expect_dword(&mut code, u32::from_le_bytes(*b"API!"));
                    call(&mut code, wide, base, 6, &[M(alias), M(mdl)]);
                    call(&mut code, wide, base, 3, &[M(mdl)]);
                    call(&mut code, wide, base, 8, &[M(pool), V(1)]);
                    if matches!(kind, MdlFixture::Unmapped) {
                        read_field(&mut code, wide, alias, 0, false);
                        code.push(0xcc);
                    }
                }
                MdlFixture::Flags => code.push(0xcc),
                _ => unreachable!("nonmapping cases handled above"),
            }
        } else {
            call(&mut code, wide, base, 3, &[M(mdl)]);
            read_field(&mut code, wide, buffer, 0, false);
            expect_dword(&mut code, u32::from_le_bytes(*b"EMU!"));
            call(&mut code, wide, base, 8, &[M(pool), V(1)]);
        }
    }
    code.extend([0xb8, 1, 0, 0, 0]);
    if wide {
        code.extend([0x48, 0x83, 0xc4, 0x68]);
    }
    code.push(0xc3);
    assert!(
        code.len() <= 0x1000,
        "Owned MDL program exceeds text section"
    );
    data[0x200..0x200 + code.len()].copy_from_slice(&code);
    data
}
