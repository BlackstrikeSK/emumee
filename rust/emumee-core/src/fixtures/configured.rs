//! Closed generated programs for actual nondefault native configuration.
use super::winhttp::{
    Arg::{Memory as M, Value as V},
    call, expect_dword, load, store, write_dword,
};
use super::{ApiFixture, api_probe, put16, put32, put64};
use crate::{pe::Architecture, persona::Encoding};
#[derive(Clone, Copy, Debug)]
pub enum ConfiguredFixture {
    User,
    Empty,
    Kernel,
    Ipi,
}
impl ConfiguredFixture {
    /// The IPI root verifies callback0x1234, then returns1; other roots return17.
    pub fn expected_return(self) -> u64 {
        if matches!(self, Self::Ipi) { 1 } else { 17 }
    }
    pub fn kernel(self) -> bool {
        matches!(self, Self::Kernel | Self::Ipi)
    }
}
pub fn configured_document(kind: ConfiguredFixture) -> Vec<u8> {
    let mut p = serde_json::json!({"hostname":"RUST-MACHINE","user_name":"Morgan","current_dir":"C:\\Users\\Morgan\\Downloads","windows_build":26100,"physical_memory_mb":8192,"available_memory_mb":4096,"clock_utc":"2026-10-18T12:00:00Z","uptime_ms":543210,"utc_offset_minutes":120,"cpu":{"brand":"Configured Synthetic CPU","cores":3,"threads_per_core":2,"base_mhz":3200,"max_mhz":4200},"registry_keys":[{"path":"HKEY_CURRENT_USER\\Software\\Configured","values":[{"name":"Seed","type":"REG_BINARY","data":"hex:01 02 fe ff"}]}],"virtual_files":[{"path":"C:\\Users\\Morgan\\Downloads\\MiXeD.bin","base64":"AQIDBA=="}]} );
    if matches!(kind, ConfiguredFixture::Empty) {
        p["registry_keys"] = serde_json::json!([]);
        p["virtual_files"] = serde_json::json!([]);
    }
    if matches!(kind, ConfiguredFixture::Ipi) {
        p["cpu"]["cores"] = serde_json::json!(4);
        p["cpu"]["threads_per_core"] = serde_json::json!(1);
    }
    serde_json::to_vec(&p).expect("generated fixed persona document")
}
fn expect(c: &mut Vec<u8>, value: u32) {
    c.push(0x3d);
    c.extend(value.to_le_bytes());
    c.extend([0x74, 1, 0xcc]);
}
fn string(data: &mut [u8], rva: usize, s: &str, e: Encoding) {
    let bytes = e.encode(s, true);
    data[rva - 0xe00..rva - 0xe00 + bytes.len()].copy_from_slice(&bytes);
}
fn poison(c: &mut Vec<u8>, wide: bool, address: u64, bytes: usize) {
    for i in (0..bytes.div_ceil(4) * 4 + 4).step_by(4) {
        write_dword(c, wide, address + i as u64, 0x77777777);
    }
}
fn bytes(c: &mut Vec<u8>, wide: bool, address: u64, value: &[u8]) {
    for (index, part) in value.chunks(4).enumerate() {
        let mut word = [0x77; 4];
        word[..part.len()].copy_from_slice(part);
        expect_dword(
            c,
            wide,
            address + index as u64 * 4,
            u32::from_le_bytes(word),
        );
    }
    expect_dword(
        c,
        wide,
        address + value.len().div_ceil(4) as u64 * 4,
        0x77777777,
    );
}
fn pointed(c: &mut Vec<u8>, wide: bool, slot: u64, value: &[u8]) {
    for (index, part) in value.chunks(4).enumerate() {
        if wide {
            c.push(0x48);
        }
        load(c, wide, slot);
        c.extend([0x8b, 0x80]);
        c.extend((index as u32 * 4).to_le_bytes());
        let mut word = [0; 4];
        word[..part.len()].copy_from_slice(part);
        if part.len() < 4 {
            c.push(0x25);
            c.extend(((1u32 << (part.len() * 8)) - 1).to_le_bytes());
        }
        expect(c, u32::from_le_bytes(word));
    }
}
fn skeleton(architecture: Architecture, kernel: bool, names: &[String], first: usize) -> Vec<u8> {
    let wide = architecture == Architecture::X64;
    let width = architecture.width();
    let original = api_probe(
        architecture,
        if kernel {
            ApiFixture::PoolLifecycle
        } else {
            ApiFixture::Unsupported
        },
    );
    let mut data = vec![0; 0x3200];
    data[..0x200].copy_from_slice(&original[..0x200]);
    let table = 0x98 + if wide { 0xf0 } else { 0xe0 };
    let dd = 0x98 + if wide { 112 } else { 96 };
    for (at, v) in [
        (0x98 + 4, 0x1000),
        (0x98 + 8, 0x2000),
        (0x98 + 56, 0x4000),
        (table + 8, 0x1000),
        (table + 16, 0x1000),
        (table + 40 + 8, 0x2000),
        (table + 40 + 16, 0x2000),
        (table + 40 + 20, 0x1200),
        (dd + 8, 0x2000),
        (dd + 12, if kernel { 40 } else { 60 }),
        (0x1200, 0x2180),
        (0x120c, 0x2040),
        (0x1210, 0x2080),
    ] {
        put32(&mut data, at, v);
    }
    if kernel {
        data[0x1240..0x124d].copy_from_slice(b"ntoskrnl.exe\0");
    } else {
        put16(&mut data, 0x98 + 68, 3);
        put16(&mut data, 0x96, 0x22);
        data[0x1240..0x124d].copy_from_slice(b"kernel32.dll\0");
        put32(
            &mut data,
            0x1214,
            0x2180 + (first as u32 + 1) * width as u32,
        );
        put32(&mut data, 0x1220, 0x2060);
        put32(
            &mut data,
            0x1224,
            0x2080 + (first as u32 + 1) * width as u32,
        );
        data[0x1260..0x126d].copy_from_slice(b"advapi32.dll\0");
    }
    for (index, name) in names.iter().enumerate() {
        if name.is_empty() {
            continue;
        }
        let rva = 0x2300 + index as u32 * 64;
        for raw in [0x1280, 0x1380] {
            if wide {
                put64(&mut data, raw + index * width, rva.into());
            } else {
                put32(&mut data, raw + index * width, rva);
            }
        }
        let raw = 0x1500 + index * 64;
        assert!(raw + 2 + name.len() < 0x1c00);
        data[raw + 2..raw + 2 + name.len()].copy_from_slice(name.as_bytes());
    }
    assert!(0x1380 + (names.len() + 1) * width < 0x1500);
    data
}
pub fn configured_probe(
    architecture: Architecture,
    kind: ConfiguredFixture,
    unicode: bool,
) -> Vec<u8> {
    if matches!(kind, ConfiguredFixture::Ipi) {
        return super::ipi_probe(architecture, super::IpiFixture::Four);
    }
    if matches!(kind, ConfiguredFixture::Kernel) {
        return kernel(architecture);
    }
    let wide = architecture == Architecture::X64;
    let base = if wide { 0x140000000u64 } else { 0x400000 };
    let e = if unicode {
        Encoding::Utf16
    } else {
        Encoding::Cp1252
    };
    let env = if unicode {
        Encoding::Utf16
    } else {
        Encoding::Cp437
    };
    let suffix = if unicode { "W" } else { "A" };
    let names = vec![
        format!("GetComputerName{suffix}"),
        format!("GetCurrentDirectory{suffix}"),
        format!("GetEnvironmentVariable{suffix}"),
        format!("GetCommandLine{suffix}"),
        format!("CreateFile{suffix}"),
        "ReadFile".into(),
        "CloseHandle".into(),
        "SetLastError".into(),
        "GetLastError".into(),
        format!("GetEnvironmentStrings{suffix}"),
        format!("FreeEnvironmentStrings{suffix}"),
        String::new(),
        format!("GetUserName{suffix}"),
        format!("RegOpenKeyEx{suffix}"),
        format!("RegQueryValueEx{suffix}"),
        "RegCloseKey".into(),
    ];
    let mut data = skeleton(architecture, false, &names, 11);
    for (rva, s, enc) in [
        (0x2900, "TOKEN", env),
        (0x2920, "MiXeD.bin", e),
        (0x2960, "Software\\Configured", e),
        (0x29c0, "Seed", e),
    ] {
        string(&mut data, rva, s, enc);
    }
    let count = base + 0x2c00;
    let handle = base + 0x2c20;
    let command = base + 0x2c40;
    let ty = base + 0x2c60;
    let output = base + 0x2d00;
    let mut c = Vec::new();
    if wide {
        c.extend([0x48, 0x83, 0xec, 0x68]);
    }
    poison(&mut c, wide, output, 32);
    write_dword(&mut c, wide, count, 96);
    call(&mut c, wide, base, 0, &[V(output), V(count)]);
    expect(&mut c, 1);
    expect_dword(&mut c, wide, count, 12);
    bytes(&mut c, wide, output, &e.encode("RUST-MACHINE", true));
    poison(&mut c, wide, output, 16);
    write_dword(&mut c, wide, count, 96);
    call(&mut c, wide, base, 12, &[V(output), V(count)]);
    expect(&mut c, 1);
    expect_dword(&mut c, wide, count, 7);
    bytes(&mut c, wide, output, &e.encode("Morgan", true));
    poison(&mut c, wide, output, 56);
    call(&mut c, wide, base, 1, &[V(96), V(output)]);
    expect(&mut c, 25);
    bytes(
        &mut c,
        wide,
        output,
        &e.encode(r"C:\Users\Morgan\Downloads", true),
    );
    poison(&mut c, wide, output, 8);
    call(&mut c, wide, base, 2, &[V(base + 0x2900), V(output), V(96)]);
    expect(&mut c, 1);
    bytes(&mut c, wide, output, &env.encode("é", true));
    call(&mut c, wide, base, 3, &[]);
    store(&mut c, wide, command);
    call(&mut c, wide, base, 3, &[]);
    if wide {
        c.extend([0x48, 0xba]);
        c.extend(command.to_le_bytes());
        c.extend([0x48, 0x3b, 0x02]);
    } else {
        c.extend([0x3b, 0x05]);
        c.extend((command as u32).to_le_bytes());
    }
    c.extend([0x74, 1, 0xcc]);
    pointed(
        &mut c,
        wide,
        command,
        &e.encode(
            "C:\\Users\\Morgan\\Downloads\\configured-probe.exe \"two words\"",
            true,
        ),
    );
    call(&mut c, wide, base, 7, &[V(0x12345678)]);
    call(&mut c, wide, base, 9, &[]);
    store(&mut c, wide, base + 0x2c80);
    pointed(
        &mut c,
        wide,
        base + 0x2c80,
        &env.encode(r"USERPROFILE=C:\Users\Morgan", true),
    );
    call(&mut c, wide, base, 10, &[M(base + 0x2c80)]);
    expect(&mut c, 1);
    call(&mut c, wide, base, 8, &[]);
    expect(&mut c, 0x12345678);
    call(
        &mut c,
        wide,
        base,
        4,
        &[
            V(base + 0x2920),
            V(0x80000000),
            V(7),
            V(0),
            V(3),
            V(0x80),
            V(0),
        ],
    );
    store(&mut c, wide, handle);
    if matches!(kind, ConfiguredFixture::Empty) {
        expect(&mut c, u32::MAX);
        call(&mut c, wide, base, 8, &[]);
        expect(&mut c, 2);
    } else {
        poison(&mut c, wide, output, 16);
        call(
            &mut c,
            wide,
            base,
            5,
            &[M(handle), V(output), V(4), V(count), V(0)],
        );
        expect(&mut c, 1);
        expect_dword(&mut c, wide, count, 4);
        bytes(&mut c, wide, output, &[1, 2, 3, 4]);
        call(&mut c, wide, base, 6, &[M(handle)]);
        expect(&mut c, 1);
    }
    call(&mut c, wide, base, 7, &[V(0x12345678)]);
    poison(&mut c, wide, handle, 16);
    call(
        &mut c,
        wide,
        base,
        13,
        &[V(0x80000001), V(base + 0x2960), V(0), V(0x20019), V(handle)],
    );
    if matches!(kind, ConfiguredFixture::Empty) {
        expect(&mut c, 2);
        expect_dword(&mut c, wide, handle, 0x77777777);
    } else {
        expect(&mut c, 0);
        if wide {
            expect_dword(&mut c, wide, handle + 4, 0);
        }
        expect_dword(
            &mut c,
            wide,
            handle + architecture.width() as u64,
            0x77777777,
        );
        poison(&mut c, wide, output, 16);
        write_dword(&mut c, wide, count, 16);
        call(
            &mut c,
            wide,
            base,
            14,
            &[
                M(handle),
                V(base + 0x29c0),
                V(0),
                V(ty),
                V(output),
                V(count),
            ],
        );
        expect(&mut c, 0);
        expect_dword(&mut c, wide, ty, 3);
        expect_dword(&mut c, wide, count, 4);
        bytes(&mut c, wide, output, &[1, 2, 254, 255]);
        call(&mut c, wide, base, 15, &[M(handle)]);
        expect(&mut c, 0);
    }
    call(&mut c, wide, base, 8, &[]);
    expect(&mut c, 0x12345678);
    c.push(0xb8);
    c.extend(17u32.to_le_bytes());
    if wide {
        c.extend([0x48, 0x83, 0xc4, 0x68]);
    }
    c.push(0xc3);
    assert!(c.len() <= 0x1000);
    data[0x200..0x200 + c.len()].copy_from_slice(&c);
    data
}
fn kernel(architecture: Architecture) -> Vec<u8> {
    let wide = architecture == Architecture::X64;
    let base = if wide { 0x140000000u64 } else { 0x400000 };
    let names = [
        "KeQueryActiveProcessorCountEx",
        "KeGetCurrentProcessorNumberEx",
        "KeNumberProcessors",
        "KeQuerySystemTime",
    ]
    .map(str::to_owned);
    let mut data = skeleton(architecture, true, &names, 0);
    let mut c = Vec::new();
    if wide {
        c.extend([0x48, 0x83, 0xec, 0x68]);
    }
    call(&mut c, wide, base, 0, &[V(0xffff)]);
    expect(&mut c, 6);
    poison(&mut c, wide, base + 0x2c00, 12);
    call(&mut c, wide, base, 1, &[V(base + 0x2c04)]);
    expect(&mut c, 0);
    expect_dword(&mut c, wide, base + 0x2c00, 0x77777777);
    expect_dword(&mut c, wide, base + 0x2c04, 0);
    expect_dword(&mut c, wide, base + 0x2c08, 0x77777777);
    if wide {
        c.push(0x48);
    }
    load(
        &mut c,
        wide,
        base + 0x2080 + 2 * architecture.width() as u64,
    );
    c.extend([0x0f, 0xb6, 0]);
    expect(&mut c, 6);
    c.extend([
        0x53, 0xb8, 1, 0, 0, 0, 0x0f, 0xa2, 0x89, 0xd8, 0xc1, 0xe8, 16, 0x25, 255, 0, 0, 0, 0x5b,
    ]);
    expect(&mut c, 6);
    for (offset, value) in [(0x260, 26100), (0x2e8, 8192 * 256), (0x3c0, 6)] {
        expect_dword(&mut c, wide, 0x7ffe0000 + offset, value);
    }
    call(&mut c, wide, base, 3, &[V(base + 0x2c20)]);
    if wide {
        c.push(0x48);
    }
    load(&mut c, wide, base + 0x2c20);
    if wide {
        c.extend([0x48, 0xba]);
        c.extend(0x7ffe0014u64.to_le_bytes());
        c.extend([0x48, 0x3b, 0x02]);
    } else {
        c.extend([0x3b, 0x05]);
        c.extend(0x7ffe0014u32.to_le_bytes());
    }
    c.extend([0x74, 1, 0xcc]);
    c.push(0xb8);
    c.extend(17u32.to_le_bytes());
    if wide {
        c.extend([0x48, 0x83, 0xc4, 0x68]);
    }
    c.push(0xc3);
    assert!(c.len() <= 0x1000);
    data[0x200..0x200 + c.len()].copy_from_slice(&c);
    data
}
