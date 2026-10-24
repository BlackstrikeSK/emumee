//! Harmless native counted-string/key callers; values are configured literals.
use super::winhttp::{
    Arg::{Memory as M, Value as V},
    call, expect_dword, load, store, write_dword,
};
use super::{ApiFixture, api_probe, put16, put32, put64};
use crate::pe::Architecture;
#[derive(Clone, Copy, Debug)]
pub enum NativeRegistryFixture {
    Basic,
    Full,
    Retry,
    Relative,
    Roots,
    Missing,
    Rights,
    TypedClose,
    Default,
    Counted,
    Sid,
    InvalidClass,
    Truncated,
    ClassUnsupported,
    AttributesUnsupported,
    BadOutput,
    QueryReadonly,
    OutputOverlap,
    IrqlOpen,
    IrqlQuery,
    IrqlClose,
}
impl NativeRegistryFixture {
    pub fn negative(self) -> bool {
        matches!(
            self,
            Self::ClassUnsupported
                | Self::AttributesUnsupported
                | Self::BadOutput
                | Self::QueryReadonly
                | Self::OutputOverlap
                | Self::IrqlOpen
                | Self::IrqlQuery
                | Self::IrqlClose
        )
    }
    pub fn error(self) -> Option<&'static str> {
        Some(match self {
            Self::ClassUnsupported => "valid native value information class is not modeled",
            Self::AttributesUnsupported => {
                "Native registry object attributes/security profile unsupported"
            }
            Self::BadOutput | Self::QueryReadonly => "API guest range",
            Self::IrqlOpen | Self::IrqlQuery | Self::IrqlClose => {
                "Native registry/handle API requires PASSIVE_LEVEL"
            }
            Self::OutputOverlap => "Overlapping native registry outputs are not modeled",
            _ => return None,
        })
    }
}
pub fn native_registry_document() -> Vec<u8> {
    let mut value: serde_json::Value = serde_json::from_slice(&super::configured_document(
        super::ConfiguredFixture::Kernel,
    ))
    .unwrap();
    value["virtual_files"] = serde_json::json!([]);
    value["registry_keys"] = serde_json::json!([
        {"path":"HKLM\\Guest","values":[{"name":"MiXeD","type":"REG_BINARY","data":"hex:52 55 53 54"},{"name":"default","type":"REG_DWORD","data":42}]},
        {"path":"HKLM\\Guest\\Child","values":[]},
        {"path":"HKU\\S-1-5-18\\Actual","values":[{"name":"MiXeD","type":"REG_SZ","data":"Guest"}]},
        {"path":"HKCU\\OnlyCurrent","values":[]}
    ]);
    serde_json::to_vec(&value).unwrap()
}
fn expect(c: &mut Vec<u8>, value: u32) {
    c.push(0x3d);
    c.extend(value.to_le_bytes());
    c.extend([0x74, 1, 0xcc]);
}
fn pointed(c: &mut Vec<u8>, wide: bool, at: u64, bytes: &[u8]) {
    for (index, part) in bytes.chunks(4).enumerate() {
        let mut word = [0x77; 4];
        word[..part.len()].copy_from_slice(part);
        expect_dword(c, wide, at + index as u64 * 4, u32::from_le_bytes(word));
    }
    expect_dword(c, wide, at + bytes.len().div_ceil(4) as u64 * 4, 0x77777777);
}
fn poison(c: &mut Vec<u8>, wide: bool, address: u64, words: usize) {
    for i in 0..words {
        write_dword(c, wide, address + i as u64 * 4, 0x77777777);
    }
}
fn text(
    data: &mut [u8],
    wide: bool,
    base: u64,
    descriptor: usize,
    buffer: usize,
    s: &str,
    tail: bool,
) {
    let raw = descriptor - 0xe00;
    let bytes = s
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    put16(data, raw, bytes.len() as u16);
    put16(data, raw + 2, bytes.len() as u16);
    if wide {
        put64(
            data,
            raw + 8,
            if bytes.is_empty() {
                0
            } else {
                base + buffer as u64
            },
        );
    } else {
        put32(
            data,
            raw + 4,
            if bytes.is_empty() {
                0
            } else {
                (base + buffer as u64) as u32
            },
        );
    }
    data[buffer - 0xe00..buffer - 0xe00 + bytes.len()].copy_from_slice(&bytes);
    if tail {
        data[buffer - 0xe00 + bytes.len()..buffer - 0xe00 + bytes.len() + 8]
            .copy_from_slice(&[0x58, 0, 0x58, 0, 0x58, 0, 0x58, 0]);
    }
}
fn oa(data: &mut [u8], wide: bool, base: u64, rva: usize, name: usize, flags: u32) {
    let raw = rva - 0xe00;
    put32(data, raw, if wide { 48 } else { 24 });
    if wide {
        put64(data, raw + 16, base + name as u64);
        put32(data, raw + 24, flags);
    } else {
        put32(data, raw + 8, (base + name as u64) as u32);
        put32(data, raw + 12, flags);
    }
}
fn raise_actual_irql(code: &mut Vec<u8>, wide: bool) {
    if wide {
        code.extend([0xb8, 2, 0, 0, 0, 0x44, 0x0f, 0x22, 0xc0]);
    } else {
        code.extend([0x64, 0xc6, 5, 0x24, 0, 0, 0, 2]);
    }
}
struct QueryCheck {
    handle: u64,
    name: u64,
    class: u32,
    capacity: u32,
    output: u64,
    returned: u64,
    status: u32,
    required: Option<u32>,
}
struct Program {
    code: Vec<u8>,
    wide: bool,
    base: u64,
}
impl Program {
    fn call(&mut self, index: usize, args: &[super::winhttp::Arg]) {
        call(&mut self.code, self.wide, self.base, index, args);
    }
    fn expect(&mut self, value: u32) {
        expect(&mut self.code, value);
    }
    fn open(&mut self, oa: u64, slot: u64, access: u32, status: u32) {
        poison(&mut self.code, self.wide, slot, 3);
        self.call(0, &[V(slot), V(access.into()), V(oa)]);
        self.expect(status);
        if status == 0 {
            if self.wide {
                expect_dword(&mut self.code, self.wide, slot + 4, 0xffffffff);
            }
            expect_dword(
                &mut self.code,
                self.wide,
                slot + if self.wide { 8 } else { 4 },
                0x77777777,
            );
        } else {
            expect_dword(&mut self.code, self.wide, slot, 0x77777777);
        }
    }
    fn query(&mut self, request: QueryCheck) {
        let QueryCheck {
            handle,
            name,
            class,
            capacity,
            output,
            returned,
            status,
            required,
        } = request;
        poison(&mut self.code, self.wide, output, 20);
        write_dword(&mut self.code, self.wide, returned, 0x77777777);
        self.call(
            1,
            &[
                M(handle),
                V(name),
                V(class.into()),
                V(output),
                V(capacity.into()),
                V(returned),
            ],
        );
        self.expect(status);
        expect_dword(
            &mut self.code,
            self.wide,
            returned,
            required.unwrap_or(0x77777777),
        );
    }
    fn close(&mut self, slot: u64, status: u32) {
        self.call(2, &[M(slot)]);
        self.expect(status);
    }
}
pub fn native_registry_probe(architecture: Architecture, kind: NativeRegistryFixture) -> Vec<u8> {
    let wide = architecture == Architecture::X64;
    let width = architecture.width();
    let base = if wide { 0x140000000u64 } else { 0x400000 };
    let original = api_probe(architecture, ApiFixture::PoolLifecycle);
    let mut data = vec![0; 0x3200];
    data[..0x200].copy_from_slice(&original[..0x200]);
    let table = 0x98 + if wide { 0xf0 } else { 0xe0 };
    let dd = 0x98 + if wide { 112 } else { 96 };
    for (at, value) in [
        (0x98 + 4, 0x1000),
        (0x98 + 8, 0x2000),
        (0x98 + 56, 0x4000),
        (table + 8, 0x1000),
        (table + 16, 0x1000),
        (table + 40 + 8, 0x2000),
        (table + 40 + 16, 0x2000),
        (table + 40 + 20, 0x1200),
        (dd + 8, 0x2000),
        (dd + 12, 60),
        (0x1200, 0x2180),
        (0x120c, 0x2040),
        (0x1210, 0x2080),
        (0x1214, 0x2180 + 6 * width as u32),
        (0x1220, 0x2060),
        (0x1224, 0x2080 + 6 * width as u32),
    ] {
        put32(&mut data, at, value);
    }
    data[0x1240..0x124d].copy_from_slice(b"ntoskrnl.exe\0");
    data[0x1260..0x126d].copy_from_slice(b"kernel32.dll\0");
    let names = [
        "ZwOpenKey",
        "ZwQueryValueKey",
        "ZwClose",
        "PsCreateSystemThread",
        "PsTerminateSystemThread",
        "",
        "SetLastError",
        "GetLastError",
    ];
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
        let at = 0x1500 + index * 64;
        data[at + 2..at + 2 + name.len()].copy_from_slice(name.as_bytes());
    }
    let object = match kind {
        NativeRegistryFixture::Roots => r"\Registry\Machine",
        NativeRegistryFixture::Sid => r"\Registry\User\S-1-5-18\Actual",
        NativeRegistryFixture::Missing => r"\Registry\Machine\Absent",
        _ => r"\Registry\Machine\Guest",
    };
    let other = if matches!(kind, NativeRegistryFixture::Sid) {
        r"\Registry\User\S-1-5-18\OnlyCurrent"
    } else if matches!(kind, NativeRegistryFixture::Missing) {
        r"\Registry\Machine\Absent\Child"
    } else {
        r"\Registry\User\S-1-5-18\Actual"
    };
    text(
        &mut data,
        wide,
        base,
        0x2a80,
        0x2b00,
        object,
        matches!(kind, NativeRegistryFixture::Counted),
    );
    text(
        &mut data,
        wide,
        base,
        0x2aa0,
        0x2ba0,
        if matches!(kind, NativeRegistryFixture::Default) {
            ""
        } else {
            "mixed"
        },
        matches!(kind, NativeRegistryFixture::Counted),
    );
    text(&mut data, wide, base, 0x2ac0, 0x2be0, "ABSENT", false);
    text(&mut data, wide, base, 0x2ae0, 0x2f00, other, false);
    text(&mut data, wide, base, 0x2e00, 0x2bc0, "Child", false);
    oa(
        &mut data,
        wide,
        base,
        0x2a00,
        0x2a80,
        if matches!(kind, NativeRegistryFixture::AttributesUnsupported) {
            0x1240
        } else {
            0x240
        },
    );
    oa(&mut data, wide, base, 0x2a40, 0x2ae0, 0x240);
    let h = base + 0x2c00;
    let next = base + 0x2c20;
    let thread = base + 0x2c40;
    let returned = base + 0x2c60;
    let output = base + 0x2d00;
    let name = base + 0x2aa0;
    let attributes = base + 0x2a00;
    let mut p = Program {
        code: Vec::new(),
        wide,
        base,
    };
    if wide {
        p.code.extend([0x48, 0x83, 0xec, 0x68]);
    }
    p.call(6, &[V(0x12345678)]);
    if matches!(kind, NativeRegistryFixture::IrqlOpen) {
        raise_actual_irql(&mut p.code, wide);
    }
    if matches!(kind, NativeRegistryFixture::BadOutput) {
        p.call(0, &[V(base + 0x1000), V(0x20019), V(attributes)]);
    } else {
        let missing = matches!(kind, NativeRegistryFixture::Missing);
        p.open(
            attributes,
            h,
            if matches!(kind, NativeRegistryFixture::Rights) {
                2
            } else {
                0x80000000
            },
            if missing { 0xc0000034 } else { 0 },
        );
        if missing {
            p.open(base + 0x2a40, next, 0x20019, 0xc000003a);
        } else {
            match kind {
                NativeRegistryFixture::IrqlQuery => {
                    poison(&mut p.code, wide, output, 20);
                    write_dword(&mut p.code, wide, returned, 0x77777777);
                    raise_actual_irql(&mut p.code, wide);
                    p.call(1, &[M(h), V(name), V(2), V(output), V(80), V(returned)]);
                }
                NativeRegistryFixture::IrqlClose => {
                    raise_actual_irql(&mut p.code, wide);
                    p.close(h, 0);
                }
                NativeRegistryFixture::Retry => {
                    for (capacity, status) in [
                        (0, 0xc0000023),
                        (11, 0xc0000023),
                        (12, 0x80000005),
                        (14, 0x80000005),
                        (16, 0),
                    ] {
                        p.query(QueryCheck {
                            handle: h,
                            name,
                            class: 2,
                            capacity,
                            output,
                            returned,
                            status,
                            required: Some(16),
                        });
                        if capacity < 12 {
                            expect_dword(&mut p.code, wide, output, 0x77777777);
                        } else {
                            let mut bytes = vec![];
                            bytes.extend(0u32.to_le_bytes());
                            bytes.extend(3u32.to_le_bytes());
                            bytes.extend(4u32.to_le_bytes());
                            bytes.extend(b"RUST");
                            bytes.truncate(capacity as usize);
                            pointed(&mut p.code, wide, output, &bytes);
                        }
                    }
                }
                NativeRegistryFixture::Full => {
                    p.query(QueryCheck {
                        handle: h,
                        name,
                        class: 1,
                        capacity: 80,
                        output,
                        returned,
                        status: 0,
                        required: Some(36),
                    });
                    let mut bytes = vec![];
                    for value in [0u32, 3, 32, 4, 10] {
                        bytes.extend(value.to_le_bytes());
                    }
                    bytes.extend("MiXeD".encode_utf16().flat_map(u16::to_le_bytes));
                    bytes.extend([0, 0]);
                    bytes.extend(b"RUST");
                    pointed(&mut p.code, wide, output, &bytes);
                }
                NativeRegistryFixture::Relative => {
                    if wide {
                        p.code.push(0x48);
                    }
                    load(&mut p.code, wide, h);
                    store(&mut p.code, wide, attributes + if wide { 8 } else { 4 });
                    if wide {
                        p.code.extend([0x48, 0xb8]);
                        p.code.extend((base + 0x2e00).to_le_bytes());
                    } else {
                        p.code.push(0xb8);
                        p.code.extend(((base + 0x2e00) as u32).to_le_bytes());
                    }
                    store(&mut p.code, wide, attributes + if wide { 16 } else { 8 });
                    p.open(attributes, next, 0x20019, 0);
                    p.close(next, 0);
                }
                NativeRegistryFixture::Roots => {
                    p.open(base + 0x2a40, next, 0x20019, 0);
                    p.query(QueryCheck {
                        handle: next,
                        name,
                        class: 2,
                        capacity: 80,
                        output,
                        returned,
                        status: 0,
                        required: Some(24),
                    });
                    expect_dword(&mut p.code, wide, output + 4, 1);
                    expect_dword(&mut p.code, wide, output + 8, 12);
                    pointed(
                        &mut p.code,
                        wide,
                        output + 12,
                        &"Guest\0"
                            .encode_utf16()
                            .flat_map(u16::to_le_bytes)
                            .collect::<Vec<_>>(),
                    );
                    p.close(next, 0);
                }
                NativeRegistryFixture::Rights => {
                    p.query(QueryCheck {
                        handle: h,
                        name,
                        class: 2,
                        capacity: 80,
                        output,
                        returned,
                        status: 0xc0000022,
                        required: None,
                    });
                    expect_dword(&mut p.code, wide, output, 0x77777777);
                }
                NativeRegistryFixture::TypedClose => {
                    p.call(
                        3,
                        &[
                            V(thread),
                            V(0x1fffff),
                            V(0),
                            V(0),
                            V(0),
                            V(base + 0x1e00),
                            V(0),
                        ],
                    );
                    p.expect(0);
                    p.query(QueryCheck {
                        handle: thread,
                        name,
                        class: 2,
                        capacity: 80,
                        output,
                        returned,
                        status: 0xc0000024,
                        required: None,
                    });
                    expect_dword(&mut p.code, wide, output, 0x77777777);
                    p.close(h, 0);
                    p.close(thread, 0);
                    p.close(thread, 0xc0000008);
                }
                NativeRegistryFixture::Default => {
                    p.query(QueryCheck {
                        handle: h,
                        name,
                        class: 2,
                        capacity: 80,
                        output,
                        returned,
                        status: 0,
                        required: Some(16),
                    });
                    let mut bytes = vec![];
                    for value in [0u32, 4, 4, 42] {
                        bytes.extend(value.to_le_bytes());
                    }
                    pointed(&mut p.code, wide, output, &bytes);
                }
                NativeRegistryFixture::Sid => {
                    p.query(QueryCheck {
                        handle: h,
                        name,
                        class: 2,
                        capacity: 80,
                        output,
                        returned,
                        status: 0,
                        required: Some(24),
                    });
                    p.open(base + 0x2a40, next, 0x20019, 0xc0000034);
                }
                NativeRegistryFixture::InvalidClass => {
                    p.query(QueryCheck {
                        handle: h,
                        name,
                        class: 6,
                        capacity: 80,
                        output,
                        returned,
                        status: 0xc000000d,
                        required: None,
                    });
                    expect_dword(&mut p.code, wide, output, 0x77777777);
                }
                NativeRegistryFixture::Truncated => {
                    write_dword(&mut p.code, wide, returned, 0x77777777);
                    p.call(
                        1,
                        &[V(0x80010000), V(name), V(2), V(output), V(80), V(returned)],
                    );
                    p.expect(if wide { 0xc0000008 } else { 0 });
                    if wide {
                        expect_dword(&mut p.code, wide, returned, 0x77777777);
                    }
                    p.call(2, &[V(if wide { 0x80010000 } else { 0x80050000 })]);
                    p.expect(0xc0000008);
                }
                NativeRegistryFixture::ClassUnsupported => {
                    p.call(1, &[M(h), V(name), V(3), V(output), V(80), V(returned)])
                }
                NativeRegistryFixture::QueryReadonly => p.call(
                    1,
                    &[M(h), V(name), V(2), V(base + 0x1000), V(80), V(returned)],
                ),
                NativeRegistryFixture::OutputOverlap => {
                    p.call(1, &[M(h), V(name), V(2), V(output), V(80), V(output + 4)])
                }
                _ => {
                    p.query(QueryCheck {
                        handle: h,
                        name,
                        class: 2,
                        capacity: 80,
                        output,
                        returned,
                        status: 0,
                        required: Some(16),
                    });
                    let mut bytes = vec![];
                    for value in [0u32, 3, 4] {
                        bytes.extend(value.to_le_bytes());
                    }
                    bytes.extend(b"RUST");
                    pointed(&mut p.code, wide, output, &bytes);
                    if matches!(kind, NativeRegistryFixture::Basic) {
                        p.query(QueryCheck {
                            handle: h,
                            name: base + 0x2ac0,
                            class: 2,
                            capacity: 80,
                            output,
                            returned,
                            status: 0xc0000034,
                            required: None,
                        });
                        expect_dword(&mut p.code, wide, output, 0x77777777);
                    }
                }
            }
            if !kind.negative() && !matches!(kind, NativeRegistryFixture::TypedClose) {
                p.close(h, 0);
                p.close(h, 0xc0000008);
            }
        }
    }
    p.call(7, &[]);
    p.expect(0x12345678);
    p.code.push(0xb8);
    p.code.extend(17u32.to_le_bytes());
    if wide {
        p.code.extend([0x48, 0x83, 0xc4, 0x68]);
    }
    p.code.push(0xc3);
    assert!(p.code.len() < 0xe00);
    data[0x200..0x200 + p.code.len()].copy_from_slice(&p.code);
    let mut child = Vec::new();
    if wide {
        child.extend([0x48, 0x83, 0xec, 0x28]);
    }
    call(&mut child, wide, base, 4, &[V(0)]);
    if wide {
        let end = child.len();
        let displacement = i32::try_from(0x2080i64 + 4 * 8 - 0x1e00 - end as i64).unwrap();
        child[end - 4..].copy_from_slice(&displacement.to_le_bytes());
    }
    child.extend([0x0f, 0x0b]);
    data[0x1000..0x1000 + child.len()].copy_from_slice(&child);
    data
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_registry_fixtures_keep_both_import_tables_and_programs_within_their_sections() {
        use NativeRegistryFixture::*;
        for arch in [Architecture::X86, Architecture::X64] {
            for kind in [
                Basic,
                Full,
                Retry,
                Relative,
                Roots,
                Missing,
                Rights,
                TypedClose,
                Default,
                Counted,
                Sid,
                InvalidClass,
                Truncated,
                ClassUnsupported,
                AttributesUnsupported,
                BadOutput,
                QueryReadonly,
                OutputOverlap,
                IrqlOpen,
                IrqlQuery,
                IrqlClose,
            ] {
                let bytes = native_registry_probe(arch, kind);
                let image = crate::pe::PeImage::parse(&bytes, "native-registry.sys").unwrap();
                assert_eq!(
                    image.sample.kind,
                    crate::pe::Kind::Driver,
                    "{arch:?} {kind:?}"
                );
                assert_eq!(image.imports.len(), 7, "{arch:?} {kind:?}");
                for (name, module) in [
                    ("ZwOpenKey", "ntoskrnl.exe"),
                    ("ZwQueryValueKey", "ntoskrnl.exe"),
                    ("ZwClose", "ntoskrnl.exe"),
                    ("PsCreateSystemThread", "ntoskrnl.exe"),
                    ("PsTerminateSystemThread", "ntoskrnl.exe"),
                    ("SetLastError", "kernel32.dll"),
                    ("GetLastError", "kernel32.dll"),
                ] {
                    assert!(
                        image
                            .imports
                            .iter()
                            .any(|i| i.module.eq_ignore_ascii_case(module)
                                && i.name == crate::pe::ImportName::Name(name.into())),
                        "{arch:?} {kind:?}: {name}"
                    );
                }
                assert_eq!(image.sections[0].rva, 0x1000);
                assert_eq!(image.sections[0].virtual_size, 0x1000);
                assert_eq!(image.sections[1].rva, 0x2000);
            }
        }
    }
}
