//! Imported legacy-placeholder calls with a complete preserved-memory canary.
use super::m6::Probe;
use super::winhttp::Arg::Value as V;
use crate::pe::Architecture;

pub struct LegacyLiteralFixture {
    pub export: String,
    pub argc: usize,
    pub value: u32,
    pub width_aliases: bool,
}

#[derive(Clone, Copy, Debug)]
pub enum LegacyLiteralArguments {
    Zero,
    Poison,
    Arena,
}

pub fn legacy_literal_probe(
    architecture: Architecture,
    module: &str,
    calls: &[LegacyLiteralFixture],
    arguments: LegacyLiteralArguments,
) -> Vec<u8> {
    assert!(!calls.is_empty() && calls.len() <= 4);
    let helpers = [
        "VirtualAlloc",
        "SetLastError",
        "GetLastError",
        "CreateFileA",
        "WriteFile",
        "CloseHandle",
    ];
    let mut targets = Vec::new();
    for call in calls {
        assert!(call.argc <= 12);
        targets.push((call.export.clone(), call));
        if call.width_aliases {
            targets.push((format!("{}A", call.export), call));
            targets.push((format!("{}W", call.export), call));
        }
    }
    let mut groups = vec![(
        "kernel32.dll",
        helpers.iter().map(|s| (*s).to_string()).collect::<Vec<_>>(),
    )];
    let dll = format!("{module}.dll");
    if module == "kernel32" {
        groups[0]
            .1
            .extend(targets.iter().map(|(name, _)| name.clone()));
    } else {
        groups.push((&dll, targets.iter().map(|(name, _)| name.clone()).collect()));
    }
    let mut p = Probe::new(architecture, false, &groups);
    let buffer = 0x26000000;
    p.call(0, &[V(buffer), V(0x10000), V(0x3000), V(4)]);
    p.rax(buffer);
    p.fill_words(buffer, 0x4000, 0xa5a5a5a5);
    let argument = match arguments {
        LegacyLiteralArguments::Poison => {
            if architecture == Architecture::X64 {
                u64::MAX
            } else {
                u32::MAX as u64
            }
        }
        LegacyLiteralArguments::Zero => 0,
        LegacyLiteralArguments::Arena => buffer,
    };
    for (index, (_, call)) in targets.iter().enumerate() {
        p.call(1, &[V(0x12345678)]);
        let args = (0..call.argc).map(|_| V(argument)).collect::<Vec<_>>();
        p.call(helpers.len() + index, &args);
        p.rax(u64::from(call.value));
        p.call(2, &[]);
        p.eax(0x12345678);
    }
    let path = p.ascii(r"C:\Users\Alex\Downloads\literal-memory.bin");
    let handle = p.scratch(8);
    let count = p.scratch(8);
    p.call(
        3,
        &[V(path), V(0x40000000), V(0), V(0), V(2), V(0x80), V(0)],
    );
    p.save(handle);
    p.call(
        4,
        &[
            super::winhttp::Arg::Memory(handle),
            V(buffer),
            V(0x10000),
            V(count),
            V(0),
        ],
    );
    p.eax(1);
    p.dword(count, 0x10000);
    p.call(5, &[super::winhttp::Arg::Memory(handle)]);
    p.eax(1);
    p.finish()
}

/// Neither width alias is imported: it must exist in the finite provider's
/// dynamic export namespace and return an actual callable guest gate.
pub fn legacy_literal_dynamic_probe(architecture: Architecture) -> Vec<u8> {
    legacy_scalar_dynamic_probe(architecture, "gdi32", "GetMapMode")
}

pub fn legacy_local_dynamic_probe(architecture: Architecture) -> Vec<u8> {
    legacy_scalar_dynamic_probe(architecture, "comctl32", "InitCommonControlsEx")
}

fn legacy_scalar_dynamic_probe(architecture: Architecture, module: &str, export: &str) -> Vec<u8> {
    let dll = format!("{module}.dll");
    use super::winhttp::Arg::Memory as M;
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
            (&dll, vec![export.into()]),
        ],
    );
    p.call(4, &[V(0)]);
    p.rax(1);
    let module = p.ascii(&dll);
    let handle = p.scratch(8);
    let function = p.scratch(8);
    p.call(0, &[V(module)]);
    p.nonzero();
    p.save(handle);
    for name in [format!("{export}A"), format!("{export}W")] {
        let symbol = p.ascii(&name);
        p.call(1, &[M(handle), V(symbol)]);
        p.nonzero();
        p.save(function);
        p.call(3, &[V(0x12345678)]);
        p.call_pointer(function, &[V(0)]);
        p.rax(1);
    }
    p.call(2, &[M(handle)]);
    p.eax(1);
    p.finish()
}
