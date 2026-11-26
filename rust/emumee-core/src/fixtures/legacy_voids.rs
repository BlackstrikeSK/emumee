//! Void calls with independently seeded return registers and a full arena.
use super::m6::Probe;
use super::winhttp::Arg::{Memory as M, Value as V};
use crate::pe::Architecture;

pub struct LegacyVoidFixture {
    pub export: String,
    pub argc: usize,
}

pub fn legacy_void_probe(
    architecture: Architecture,
    module: &str,
    calls: &[LegacyVoidFixture],
    mode: u8,
) -> Vec<u8> {
    assert!(!calls.is_empty() && calls.len() <= 4 && mode <= 2);
    let mut targets = Vec::new();
    for call in calls {
        assert!(call.argc <= 12);
        for suffix in ["", "A", "W"] {
            targets.push((format!("{}{suffix}", call.export), call.argc));
        }
    }
    let helpers = [
        "VirtualAlloc",
        "SetLastError",
        "GetLastError",
        "CreateFileA",
        "WriteFile",
        "CloseHandle",
    ];
    let mut groups = vec![(
        "kernel32.dll",
        helpers.iter().map(|s| (*s).to_string()).collect::<Vec<_>>(),
    )];
    let dll = format!("{module}.dll");
    if module == "kernel32" {
        groups[0].1.extend(targets.iter().map(|(s, _)| s.clone()));
    } else {
        groups.push((&dll, targets.iter().map(|(s, _)| s.clone()).collect()));
    }
    let mut p = Probe::new(architecture, false, &groups);
    let buffer = 0x26000000;
    p.call(0, &[V(buffer), V(0x10000), V(0x3000), V(4)]);
    p.rax(buffer);
    p.fill_words(buffer, 0x4000, 0xa5a5a5a5);
    let mask = if architecture == Architecture::X86 {
        u32::MAX as u64
    } else {
        u64::MAX
    };
    let argument = match mode {
        0 => 0,
        1 => mask,
        _ => buffer,
    };
    let seed = match mode {
        0 => 0,
        1 => mask,
        _ => 0x12345678,
    };
    for (index, (_, argc)) in targets.iter().enumerate() {
        p.call(1, &[V(0x12345678)]);
        let args = (0..*argc).map(|_| V(argument)).collect::<Vec<_>>();
        p.call_seeded(helpers.len() + index, &args, seed);
        p.rax(seed);
        p.call(2, &[]);
        p.eax(0x12345678);
    }
    let path = p.ascii(r"C:\Users\Alex\Downloads\void-memory.bin");
    let handle = p.scratch(8);
    let count = p.scratch(8);
    p.call(
        3,
        &[V(path), V(0x40000000), V(0), V(0), V(2), V(0x80), V(0)],
    );
    p.save(handle);
    p.call(4, &[M(handle), V(buffer), V(0x10000), V(count), V(0)]);
    p.eax(1);
    p.dword(count, 0x10000);
    p.call(5, &[M(handle)]);
    p.eax(1);
    p.finish()
}

pub fn legacy_void_dynamic_probe(architecture: Architecture) -> Vec<u8> {
    let mut p = Probe::new(
        architecture,
        false,
        &[
            (
                "kernel32.dll",
                vec![
                    "LoadLibraryA".into(),
                    "GetProcAddress".into(),
                    "FreeLibrary".into(),
                    "SetLastError".into(),
                ],
            ),
            ("comctl32.dll", vec!["InitCommonControls".into()]),
        ],
    );
    p.call_seeded(4, &[], 0x12345678);
    p.rax(0x12345678);
    let dll = p.ascii("comctl32.dll");
    let handle = p.scratch(8);
    let function = p.scratch(8);
    p.call(0, &[V(dll)]);
    p.nonzero();
    p.save(handle);
    let mask = if architecture == Architecture::X86 {
        u32::MAX as u64
    } else {
        u64::MAX
    };
    for name in ["InitCommonControlsA", "InitCommonControlsW"] {
        let symbol = p.ascii(name);
        p.call(1, &[M(handle), V(symbol)]);
        p.nonzero();
        p.save(function);
        p.call(3, &[V(0x12345678)]);
        p.call_pointer_seeded(function, &[], mask);
        p.rax(mask);
    }
    p.call(2, &[M(handle)]);
    p.eax(1);
    p.finish()
}
