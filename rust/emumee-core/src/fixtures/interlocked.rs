//! Real IAT/dynamic calls checked against separately generated reference cases.
use super::m6::Probe;
use super::winhttp::Arg::{Memory as M, Value as V};
use crate::pe::Architecture;

pub struct InterlockedFixtureCase {
    pub old: u32,
    pub arguments: Vec<u64>,
    pub result: u32,
    pub new: u32,
}

fn dump(p: &mut Probe, create: usize, write: usize, close: usize) {
    let path = p.ascii(r"C:\Users\Alex\Downloads\interlocked-memory.bin");
    let handle = p.scratch(8);
    let count = p.scratch(8);
    p.call(
        create,
        &[V(path), V(0x40000000), V(0), V(0), V(2), V(0x80), V(0)],
    );
    p.save(handle);
    p.call(
        write,
        &[M(handle), V(0x26000000), V(0x10000), V(count), V(0)],
    );
    p.eax(1);
    p.dword(count, 0x10000);
    p.call(close, &[M(handle)]);
    p.eax(1);
}

pub fn interlocked_probe(
    architecture: Architecture,
    export: &str,
    cases: &[InterlockedFixtureCase],
    fatal: bool,
    protection: Option<u32>,
) -> Vec<u8> {
    assert!(!cases.is_empty() && cases.len() <= 4);
    assert!(!fatal || cases.len() == 1);
    let mut names = [
        "VirtualAlloc",
        "SetLastError",
        "GetLastError",
        "VirtualProtect",
        "CreateFileA",
        "WriteFile",
        "CloseHandle",
    ]
    .iter()
    .map(|n| (*n).to_string())
    .collect::<Vec<_>>();
    names.extend([
        export.to_string(),
        format!("{export}A"),
        format!("{export}W"),
    ]);
    let mut p = Probe::new(architecture, false, &[("kernel32.dll", names)]);
    p.call(0, &[V(0x26000000), V(0x10000), V(0x3000), V(4)]);
    p.rax(0x26000000);
    p.fill_words(0x26000000, 0x4000, 0xa5a5a5a5);
    for case in cases {
        assert_eq!(case.arguments[0], 0x26000020);
        for index in 0..if fatal { 1 } else { 3 } {
            p.set_dword(0x26000020, case.old);
            if let Some(protection) = protection {
                let old = p.scratch(8);
                p.call(
                    3,
                    &[V(0x26000000), V(0x10000), V(protection.into()), V(old)],
                );
                p.eax(1);
            }
            p.call(1, &[V(0x12345678)]);
            let args = case.arguments.iter().copied().map(V).collect::<Vec<_>>();
            p.call(7 + index, &args);
            if fatal {
                return p.finish();
            }
            p.rax(case.result.into());
            p.dword(0x26000020, case.new);
            p.call(2, &[]);
            p.eax(0x12345678);
        }
    }
    dump(&mut p, 4, 5, 6);
    p.finish()
}

pub fn interlocked_dynamic_probe(
    architecture: Architecture,
    cases: &[(String, InterlockedFixtureCase)],
) -> Vec<u8> {
    assert_eq!(cases.len(), 5);
    let names = [
        "VirtualAlloc",
        "SetLastError",
        "GetLastError",
        "CreateFileA",
        "WriteFile",
        "CloseHandle",
        "LoadLibraryA",
        "GetProcAddress",
        "FreeLibrary",
    ]
    .iter()
    .map(|n| (*n).to_string())
    .collect();
    let mut p = Probe::new(architecture, false, &[("kernel32.dll", names)]);
    p.call(0, &[V(0x26000000), V(0x10000), V(0x3000), V(4)]);
    p.rax(0x26000000);
    p.fill_words(0x26000000, 0x4000, 0xa5a5a5a5);
    let dll = p.ascii("kernel32.dll");
    let module = p.scratch(8);
    let function = p.scratch(8);
    p.call(6, &[V(dll)]);
    p.nonzero();
    p.save(module);
    for (export, case) in cases {
        for suffix in ["", "A", "W"] {
            let name = p.ascii(&format!("{export}{suffix}"));
            p.call(7, &[M(module), V(name)]);
            p.nonzero();
            p.save(function);
            p.set_dword(0x26000020, case.old);
            p.call(1, &[V(0x12345678)]);
            let args = case.arguments.iter().copied().map(V).collect::<Vec<_>>();
            p.call_pointer(function, &args);
            p.rax(case.result.into());
            p.dword(0x26000020, case.new);
            p.call(2, &[]);
            p.eax(0x12345678);
        }
    }
    p.call(8, &[M(module)]);
    p.eax(1);
    dump(&mut p, 3, 4, 5);
    p.finish()
}
