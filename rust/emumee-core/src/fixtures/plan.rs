//! Compiler-owned programs for the plan installation proof, never host input.
use super::winhttp::{
    Arg::{Memory as M, Value as V},
    call, load, store, write_dword,
};
use super::{PersonaFixture, persona_probe, put32, put64};
use crate::pe::Architecture;
pub fn installed_plan_probe(arch: Architecture, command: &str) -> Vec<u8> {
    assert!(command.len() < 512, "Compiler-owned command too large");
    // Reuse only a generated PE layout, replacing its complete import/caller area.
    let mut data = persona_probe(arch, PersonaFixture::Identity, false);
    let wide = arch == Architecture::X64;
    let width = arch.width();
    let base = if wide { 0x140000000u64 } else { 0x400000 };
    let names = [
        "GetComputerNameA",
        "GetEnvironmentVariableA",
        "GetCommandLineA",
        "CreateFileA",
        "ReadFile",
        "CloseHandle",
        "GetTickCount",
    ];
    data[0x1200..0x1240].fill(0);
    put32(&mut data, 0x1200, 0x2180);
    put32(&mut data, 0x120c, 0x2040);
    put32(&mut data, 0x1210, 0x2080);
    data[0x1280..0x1500].fill(0);
    for (i, name) in names.iter().enumerate() {
        let rva = 0x2300 + i as u32 * 64;
        for raw in [0x1280, 0x1380] {
            if wide {
                put64(&mut data, raw + i * width, rva.into());
            } else {
                put32(&mut data, raw + i * width, rva);
            }
        }
        let raw = 0x1500 + i * 64;
        data[raw..raw + 64].fill(0);
        data[raw + 2..raw + 2 + name.len()].copy_from_slice(name.as_bytes());
    }
    let out = base + 0x2d00;
    let size = base + 0x2d80;
    let saved = base + 0x2da0;
    for (rva, text) in [
        (0x2a00, "PLAN_TOKEN"),
        (0x2a40, r"C:\Users\Alex\Downloads\Guest.dat"),
    ] {
        let at = rva - 0xe00;
        data[at..at + text.len() + 1].fill(0);
        data[at..at + text.len()].copy_from_slice(text.as_bytes());
    }
    let mut c = Vec::new();
    if wide {
        c.extend([0x48, 0x83, 0xec, 0x48]);
    }
    // Actual CPUID/time observations fail if the adapter runs fixture defaults.
    c.extend([0xb8]);
    c.extend(1u32.to_le_bytes());
    c.extend([0x31, 0xc9, 0x0f, 0xa2, 0x3d]);
    c.extend(0x000806e9u32.to_le_bytes());
    c.extend([0x74, 1, 0xcc]);
    c.extend([0x89, 0xd8, 0x25]);
    c.extend(0x00ff0000u32.to_le_bytes());
    c.push(0x3d);
    c.extend(0x00040000u32.to_le_bytes());
    c.extend([0x74, 1, 0xcc]);
    call(&mut c, wide, base, 6, &[]);
    c.push(0x3d);
    // GetTickCount uses the existing coarse16ms guest clock view. The actual
    // installed uptime remains543210ms; its observable tick count is543200.
    c.extend(543200u32.to_le_bytes());
    c.extend([0x74, 1, 0xcc]);
    write_dword(&mut c, wide, size, 64);
    call(&mut c, wide, base, 0, &[V(out), V(size)]);
    c.extend([0x85, 0xc0, 0x75, 1, 0xcc]);
    load(&mut c, wide, out);
    store(&mut c, wide, saved);
    call(&mut c, wide, base, 1, &[V(base + 0x2a00), V(out), V(64)]);
    c.extend([0x83, 0xf8, 4, 0x74, 1, 0xcc]);
    load(&mut c, wide, out);
    // Absolute memory XOR via a register avoids RIP-relative addressing.
    if wide {
        c.extend([0x48, 0xba]);
        c.extend(saved.to_le_bytes());
    } else {
        c.push(0xba);
        c.extend((saved as u32).to_le_bytes());
    }
    c.extend([0x33, 0x02]);
    store(&mut c, wide, saved);
    call(&mut c, wide, base, 2, &[]);
    // Read each actual command-line byte. Wrong argv/quoting must not pass.
    for (i, b) in command.bytes().chain([0]).enumerate() {
        c.extend([0x80, 0xb8]);
        c.extend((i as u32).to_le_bytes());
        c.push(b);
        c.extend([0x74, 1, 0xcc]);
    }
    call(
        &mut c,
        wide,
        base,
        3,
        &[
            V(base + 0x2a40),
            V(0x80000000),
            V(1),
            V(0),
            V(3),
            V(0),
            V(0),
        ],
    );
    store(&mut c, wide, size + 8);
    call(
        &mut c,
        wide,
        base,
        4,
        &[M(size + 8), V(out), V(4), V(size), V(0)],
    );
    c.extend([0x85, 0xc0, 0x75, 1, 0xcc]);
    load(&mut c, wide, out);
    if wide {
        c.extend([0x48, 0xba]);
        c.extend(saved.to_le_bytes());
    } else {
        c.push(0xba);
        c.extend((saved as u32).to_le_bytes());
    }
    c.extend([0x33, 0x02]);
    store(&mut c, wide, saved);
    call(&mut c, wide, base, 5, &[M(size + 8)]);
    load(&mut c, wide, saved);
    if wide {
        c.extend([0x48, 0x83, 0xc4, 0x48]);
    }
    c.push(0xc3);
    assert!(c.len() < 0x1000);
    data[0x200..0x1200].fill(0);
    data[0x200..0x200 + c.len()].copy_from_slice(&c);
    data
}
