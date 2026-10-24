//! Harmless NTOS callers for actual borrowed/owned Unicode and bounded CRT.
use super::winhttp::{
    Arg::{Memory as M, Value as V},
    call, expect_dword, load, store, write_dword,
};
use super::{ApiFixture, api_probe, put16, put32, put64};
use crate::pe::Architecture;
#[derive(Clone, Copy, Debug)]
pub enum RtlFixture {
    Strings,
    Init,
    FlagsEmpty,
    Counted,
    InvalidDescriptor,
    Overflow,
    Lifecycle,
    GenericFree,
    FormatSecure,
    FormatSecureSmall,
    FormatList,
    FormatListExact,
    FormatListSmall,
    BorrowedFree,
    InteriorFree,
    StaleFree,
    SameTagReuse,
    ReadonlyOutput,
    CrossPageOutput,
    IrqlDuplicate,
    IrqlFree,
    IrqlPagedRead,
    FormatUnsupported,
    ReadonlyFormat,
    RetiredRead,
    RetiredExecute,
}
impl RtlFixture {
    pub fn error(self) -> Option<&'static str> {
        Some(match self {
            Self::BorrowedFree | Self::InteriorFree | Self::StaleFree | Self::SameTagReuse => {
                "actual live owned duplicate buffer"
            }
            Self::ReadonlyOutput | Self::CrossPageOutput | Self::ReadonlyFormat => {
                "API guest range"
            }
            Self::IrqlDuplicate => "duplication requires IRQL<=APC_LEVEL",
            Self::IrqlFree => "release requires IRQL<=APC_LEVEL",
            Self::IrqlPagedRead => "paged Pool access above APC_LEVEL",
            Self::FormatUnsupported => "format conversion is not modeled",
            Self::RetiredRead => "READ_UNMAPPED",
            Self::RetiredExecute => "FETCH_UNMAPPED",
            _ => return None,
        })
    }
    pub fn negative(self) -> bool {
        self.error().is_some()
    }
    pub fn formatting(self) -> bool {
        matches!(
            self,
            Self::FormatSecure
                | Self::FormatSecureSmall
                | Self::FormatList
                | Self::FormatListExact
                | Self::FormatListSmall
                | Self::FormatUnsupported
                | Self::ReadonlyFormat
        )
    }
}
fn expect(code: &mut Vec<u8>, value: u32) {
    code.push(0x3d);
    code.extend(value.to_le_bytes());
    code.extend([0x74, 1, 0xcc]);
}
fn poison(code: &mut Vec<u8>, wide: bool, address: u64, words: usize) {
    for n in 0..words {
        write_dword(code, wide, address + n as u64 * 4, 0x77777777);
    }
}
fn irql(code: &mut Vec<u8>, wide: bool) {
    if wide {
        code.extend([0xb8, 2, 0, 0, 0, 0x44, 0x0f, 0x22, 0xc0]);
    } else {
        code.extend([0x64, 0xc6, 5, 0x24, 0, 0, 0, 2]);
    }
}
fn bytes_at(code: &mut Vec<u8>, wide: bool, address: u64, bytes: &[u8], fill: u8) {
    for (i, part) in bytes.chunks(4).enumerate() {
        let mut word = [fill; 4];
        word[..part.len()].copy_from_slice(part);
        expect_dword(code, wide, address + i as u64 * 4, u32::from_le_bytes(word));
    }
    expect_dword(
        code,
        wide,
        address + bytes.len().div_ceil(4) as u64 * 4,
        0x77777777,
    );
}
fn pointed(code: &mut Vec<u8>, wide: bool, slot: u64, bytes: &[u8]) {
    for (i, part) in bytes.chunks(4).enumerate() {
        if wide {
            code.push(0x48);
        }
        load(code, wide, slot);
        code.extend([0x8b, 0x80]);
        code.extend((i as u32 * 4).to_le_bytes());
        let mut word = [0xcd; 4];
        word[..part.len()].copy_from_slice(part);
        expect(code, u32::from_le_bytes(word));
    }
}
struct Program {
    code: Vec<u8>,
    wide: bool,
    base: u64,
}
impl Program {
    fn call(&mut self, index: usize, args: &[super::winhttp::Arg]) {
        call(&mut self.code, self.wide, self.base, index, args);
        if !self.wide {
            if (3..=6).contains(&index) {
                self.code.extend([0x83, 0xc4, (args.len() * 4) as u8]);
            }
            self.code.extend([0x39, 0xf4, 0x74, 1, 0xcc]);
        }
    }
    fn status(&mut self, value: u32) {
        expect(&mut self.code, value);
    }
    fn wide_pointer(&mut self, slot: u64, value: u64) {
        write_dword(&mut self.code, self.wide, slot, value as u32);
        if self.wide {
            write_dword(&mut self.code, self.wide, slot + 4, (value >> 32) as u32);
        }
    }
    fn save(&mut self, from: u64, to: u64) {
        if self.wide {
            self.code.push(0x48);
        }
        load(&mut self.code, self.wide, from);
        store(&mut self.code, self.wide, to);
    }
    fn equal_pointer(&mut self, left: u64, right: u64) {
        if self.wide {
            self.code.push(0x48);
        }
        load(&mut self.code, self.wide, left);
        if self.wide {
            self.code.extend([0x48, 0xb9]);
            self.code.extend(right.to_le_bytes());
            self.code.extend([0x48, 0x3b, 0x01]);
        } else {
            self.code.extend([0x3b, 0x05]);
            self.code.extend((right as u32).to_le_bytes());
        }
        self.code.extend([0x74, 1, 0xcc]);
    }
    fn dup(&mut self, flags: u32, source: u64, out: u64, status: u32) {
        poison(&mut self.code, self.wide, out, 5);
        self.call(1, &[V(flags.into()), V(source), V(out)]);
        self.status(status);
    }
    fn zero(&mut self, descriptor: u64) {
        for n in 0..if self.wide { 4 } else { 2 } {
            expect_dword(&mut self.code, self.wide, descriptor + n * 4, 0);
        }
        expect_dword(
            &mut self.code,
            self.wide,
            descriptor + if self.wide { 16 } else { 8 },
            0x77777777,
        );
    }
}
pub fn kernel_rtl_probe(architecture: Architecture, kind: RtlFixture) -> Vec<u8> {
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
        (0x1214, 0x2180 + 10 * width as u32),
        (0x1220, 0x2060),
        (0x1224, 0x2080 + 10 * width as u32),
    ] {
        put32(&mut data, at, value);
    }
    data[0x1240..0x124d].copy_from_slice(b"ntoskrnl.exe\0");
    data[0x1260..0x126d].copy_from_slice(b"kernel32.dll\0");
    let names = [
        "RtlInitUnicodeString",
        "RtlDuplicateUnicodeString",
        "RtlFreeUnicodeString",
        "wcslen",
        "strchr",
        "swprintf_s",
        "_vsnwprintf",
        "ExFreePoolWithTag",
        "ExAllocatePoolWithTag",
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
    let raw: Vec<u8> = if matches!(kind, RtlFixture::Counted) {
        vec![0, 0, 0, 0xd8, 0x42, 0]
    } else {
        b"R\0U\0S\0T\0".to_vec()
    };
    data[0x1d00..0x1d00 + raw.len()].copy_from_slice(&raw); // RVA2b00
    let source = base + 0x2a00;
    let output = base + 0x2a20;
    let saved_desc = base + 0x2a40;
    let saved = base + 0x2a80;
    let ptr = if wide { 8 } else { 4 };
    put16(&mut data, 0x1c00, raw.len() as u16);
    put16(&mut data, 0x1c02, raw.len() as u16);
    if wide {
        put64(&mut data, 0x1c08, base + 0x2b00);
    } else {
        put32(&mut data, 0x1c04, (base + 0x2b00) as u32);
    }
    data[0x1d80..0x1d84].copy_from_slice(&[0x41, 0xff, 0, 0x42]);
    let format = if matches!(kind, RtlFixture::FormatUnsupported) {
        "%f\0"
    } else {
        "%d %I64u %s %p\0"
    };
    let format_bytes: Vec<u8> = format.encode_utf16().flat_map(u16::to_le_bytes).collect();
    data[0x1e00..0x1e00 + format_bytes.len()].copy_from_slice(&format_bytes);
    data[0x1e80..0x1e88].copy_from_slice(b"e\0m\0u\0\0\0");
    let expected = format!(
        "-464 4294967338 emu {}",
        if wide { "0000000140000000" } else { "00400000" }
    );
    let va: Vec<u64> = if wide {
        vec![0xfffffe30, 0x10000002a, base + 0x2c80, base]
    } else {
        vec![0xfffffe30, 42, 1, base + 0x2c80, base]
    };
    for (i, value) in va.iter().enumerate() {
        if wide {
            put64(&mut data, 0x1f00 + i * 8, *value);
        } else {
            put32(&mut data, 0x1f00 + i * 4, *value as u32);
        }
    }
    let mut p = Program {
        code: Vec::new(),
        wide,
        base,
    };
    if wide {
        p.code.extend([0x48, 0x83, 0xec, 0x68]);
    } else {
        p.code.extend([0x56, 0x89, 0xe6]);
    }
    p.call(10, &[V(0x12345678)]);
    if kind.formatting() {
        let legacy = matches!(
            kind,
            RtlFixture::FormatList | RtlFixture::FormatListExact | RtlFixture::FormatListSmall
        );
        let count = if matches!(
            kind,
            RtlFixture::FormatSecureSmall | RtlFixture::FormatListSmall
        ) {
            3
        } else if matches!(kind, RtlFixture::FormatListExact) {
            expected.len() as u64
        } else {
            64
        };
        let destination = if matches!(kind, RtlFixture::ReadonlyFormat) {
            base + 0x1000
        } else {
            base + 0x2e00
        };
        if destination == base + 0x2e00 {
            poison(&mut p.code, wide, destination, 34);
        }
        if legacy {
            p.call(
                6,
                &[V(destination), V(count), V(base + 0x2c00), V(base + 0x2d00)],
            );
        } else {
            let mut arguments = vec![V(destination), V(count), V(base + 0x2c00)];
            arguments.extend(va.into_iter().map(V));
            p.call(5, &arguments);
        }
        if !kind.negative() {
            let short = count < expected.len() as u64;
            p.status(if short {
                u32::MAX
            } else {
                expected.len() as u32
            });
            let mut want: Vec<u16> = expected.encode_utf16().take(count as usize).collect();
            if count > expected.len() as u64 {
                want.push(0);
            }
            if short && !legacy {
                want[0] = 0;
            }
            let bytes: Vec<u8> = want.into_iter().flat_map(u16::to_le_bytes).collect();
            bytes_at(&mut p.code, wide, destination, &bytes, 0x77);
        }
    } else {
        match kind {
            RtlFixture::Strings => {
                // Preserve real UTF16 units, including one unpaired unit.
                for (i, value) in [0xd83du16, 0xde00, 0xd800, 0].iter().enumerate() {
                    write_dword(
                        &mut p.code,
                        wide,
                        base + 0x2b00 + i as u64 * 2,
                        u32::from(*value),
                    );
                }
                p.call(3, &[V(base + 0x2b00)]);
                p.status(3);
                for (value, wanted) in [(u64::MAX, base + 0x2b81), (0, base + 0x2b82), (0x42, 0)] {
                    p.call(4, &[V(base + 0x2b80), V(value)]);
                    if wide {
                        store(&mut p.code, wide, saved);
                        expect_dword(&mut p.code, wide, saved, wanted as u32);
                        expect_dword(&mut p.code, wide, saved + 4, (wanted >> 32) as u32);
                    } else {
                        p.status(wanted as u32);
                    }
                }
            }
            RtlFixture::Init | RtlFixture::BorrowedFree => {
                poison(&mut p.code, wide, output, 5);
                p.call(0, &[V(output), V(base + 0x2b00)]);
                expect_dword(
                    &mut p.code,
                    wide,
                    output,
                    (((raw.len() + 2) as u32) << 16) | raw.len() as u32,
                );
                expect_dword(&mut p.code, wide, output + ptr, (base + 0x2b00) as u32);
                if wide {
                    expect_dword(
                        &mut p.code,
                        wide,
                        output + ptr + 4,
                        ((base + 0x2b00) >> 32) as u32,
                    );
                    expect_dword(&mut p.code, wide, output + 4, 0);
                }
                if matches!(kind, RtlFixture::BorrowedFree) {
                    p.call(2, &[V(output)]);
                } else {
                    p.call(0, &[V(output), V(0)]);
                    p.zero(output);
                }
            }
            RtlFixture::FlagsEmpty => {
                write_dword(&mut p.code, wide, source, 0);
                p.wide_pointer(source + ptr, 0);
                for flags in 0..=4 {
                    let valid = matches!(flags, 0 | 1 | 3);
                    p.dup(flags, source, output, if valid { 0 } else { 0xc000000d });
                    if flags == 3 {
                        expect_dword(&mut p.code, wide, output, 2 << 16);
                        p.save(output + ptr, saved);
                        pointed(&mut p.code, wide, saved, &[0, 0]);
                        p.call(2, &[V(output)]);
                        p.zero(output);
                    } else if valid {
                        p.zero(output);
                    } else {
                        for n in 0..if wide { 4 } else { 2 } {
                            expect_dword(&mut p.code, wide, output + n * 4, 0x77777777);
                        }
                    }
                }
            }
            RtlFixture::InvalidDescriptor | RtlFixture::Overflow => {
                if matches!(kind, RtlFixture::InvalidDescriptor) {
                    write_dword(&mut p.code, wide, source, (4 << 16) | 3);
                } else {
                    write_dword(&mut p.code, wide, source, 0xfffefffe);
                    p.wide_pointer(source + ptr, 1);
                }
                p.dup(1, source, output, 0xc000000d);
                for n in 0..if wide { 4 } else { 2 } {
                    expect_dword(&mut p.code, wide, output + n * 4, 0x77777777);
                }
            }
            RtlFixture::ReadonlyOutput
            | RtlFixture::CrossPageOutput
            | RtlFixture::IrqlDuplicate => {
                if matches!(kind, RtlFixture::IrqlDuplicate) {
                    irql(&mut p.code, wide);
                }
                p.call(
                    1,
                    &[
                        V(1),
                        V(source),
                        V(if matches!(kind, RtlFixture::ReadonlyOutput) {
                            base + 0x1000
                        } else if matches!(kind, RtlFixture::CrossPageOutput) {
                            base + 0x3ffc
                        } else {
                            output
                        }),
                    ],
                );
            }
            _ => {
                p.dup(1, source, output, 0);
                expect_dword(
                    &mut p.code,
                    wide,
                    output,
                    (((raw.len() + 2) as u32) << 16) | raw.len() as u32,
                );
                if wide {
                    expect_dword(&mut p.code, wide, output + ptr + 4, 0xffffb000);
                }
                p.save(output + ptr, saved);
                let mut payload = raw.clone();
                payload.extend([0, 0]);
                pointed(&mut p.code, wide, saved, &payload);
                if matches!(kind, RtlFixture::StaleFree | RtlFixture::Lifecycle) {
                    poison(&mut p.code, wide, saved_desc, 5);
                    write_dword(
                        &mut p.code,
                        wide,
                        saved_desc,
                        (((raw.len() + 2) as u32) << 16) | raw.len() as u32,
                    );
                    if wide {
                        write_dword(&mut p.code, wide, saved_desc + 4, 0);
                    }
                    p.save(saved, saved_desc + ptr);
                }
                if matches!(kind, RtlFixture::InteriorFree) {
                    if wide {
                        p.code.push(0x48);
                    }
                    load(&mut p.code, wide, saved);
                    if wide {
                        p.code.push(0x48);
                    }
                    p.code.extend([0x83, 0xc0, 2]);
                    store(&mut p.code, wide, output + ptr);
                    p.call(2, &[V(output)]);
                } else if matches!(kind, RtlFixture::GenericFree | RtlFixture::SameTagReuse) {
                    p.call(7, &[M(saved), V(u32::from_le_bytes(*b"Ustr").into())]);
                    if matches!(kind, RtlFixture::SameTagReuse) {
                        p.call(
                            8,
                            &[
                                V(1),
                                V((raw.len() + 2) as u64),
                                V(u32::from_le_bytes(*b"Ustr").into()),
                            ],
                        );
                        store(&mut p.code, wide, base + 0x2aa0);
                        p.equal_pointer(saved, base + 0x2aa0);
                        p.call(2, &[V(output)]);
                    }
                } else if matches!(kind, RtlFixture::IrqlFree | RtlFixture::IrqlPagedRead) {
                    irql(&mut p.code, wide);
                    if matches!(kind, RtlFixture::IrqlFree) {
                        p.call(2, &[V(output)]);
                    } else {
                        p.call(3, &[M(saved)]);
                    }
                } else if matches!(kind, RtlFixture::Lifecycle) {
                    // A copied descriptor authorizes the same actual live buffer.
                    p.call(2, &[V(saved_desc)]);
                    p.zero(saved_desc);
                    expect_dword(
                        &mut p.code,
                        wide,
                        output,
                        (((raw.len() + 2) as u32) << 16) | raw.len() as u32,
                    );
                    p.call(0, &[V(output), V(0)]);
                    p.zero(output);
                    p.call(2, &[V(output)]);
                    p.zero(output);
                } else {
                    p.call(2, &[V(output)]);
                    p.zero(output);
                    if matches!(kind, RtlFixture::StaleFree) {
                        p.call(2, &[V(saved_desc)]);
                    } else if matches!(kind, RtlFixture::RetiredRead | RtlFixture::RetiredExecute) {
                        if wide {
                            p.code.push(0x48);
                        }
                        load(&mut p.code, wide, saved);
                        p.code.extend(if matches!(kind, RtlFixture::RetiredRead) {
                            &[0x8b, 0][..]
                        } else {
                            &[0xff, 0xd0][..]
                        });
                    } else {
                        p.call(2, &[V(output)]);
                        p.zero(output);
                    }
                }
            }
        }
    }
    p.call(11, &[]);
    p.status(0x12345678);
    p.code.extend([0xb8, 17, 0, 0, 0]);
    if wide {
        p.code.extend([0x48, 0x83, 0xc4, 0x68]);
    } else {
        p.code.push(0x5e);
    }
    p.code.push(0xc3);
    assert!(p.code.len() <= 0x1000);
    data[0x200..0x200 + p.code.len()].copy_from_slice(&p.code);
    data
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn all_rtl_fixture_imports_and_program_sections_are_complete_in_both_abis() {
        use RtlFixture::*;
        for arch in [Architecture::X86, Architecture::X64] {
            for kind in [
                Strings,
                Init,
                FlagsEmpty,
                Counted,
                InvalidDescriptor,
                Overflow,
                Lifecycle,
                GenericFree,
                FormatSecure,
                FormatSecureSmall,
                FormatList,
                FormatListExact,
                FormatListSmall,
                BorrowedFree,
                InteriorFree,
                StaleFree,
                SameTagReuse,
                ReadonlyOutput,
                CrossPageOutput,
                IrqlDuplicate,
                IrqlFree,
                IrqlPagedRead,
                FormatUnsupported,
                ReadonlyFormat,
                RetiredRead,
                RetiredExecute,
            ] {
                let bytes = kernel_rtl_probe(arch, kind);
                let image = crate::pe::PeImage::parse(&bytes, "kernel-rtl.sys").unwrap();
                assert_eq!(
                    image.sample.kind,
                    crate::pe::Kind::Driver,
                    "{arch:?} {kind:?}"
                );
                assert_eq!(image.imports.len(), 11, "{arch:?} {kind:?}");
                for name in [
                    "RtlInitUnicodeString",
                    "RtlDuplicateUnicodeString",
                    "RtlFreeUnicodeString",
                    "wcslen",
                    "strchr",
                    "swprintf_s",
                    "_vsnwprintf",
                    "ExFreePoolWithTag",
                    "ExAllocatePoolWithTag",
                ] {
                    assert!(
                        image
                            .imports
                            .iter()
                            .any(|i| i.module.eq_ignore_ascii_case("ntoskrnl.exe")
                                && i.name == crate::pe::ImportName::Name(name.into())),
                        "{arch:?} {kind:?}: {name}"
                    );
                }
                for name in ["SetLastError", "GetLastError"] {
                    assert!(
                        image
                            .imports
                            .iter()
                            .any(|i| i.module.eq_ignore_ascii_case("kernel32.dll")
                                && i.name == crate::pe::ImportName::Name(name.into())),
                        "{arch:?} {kind:?}: {name}"
                    );
                }
                assert_eq!(image.sections[0].virtual_size, 0x1000);
                assert_eq!(image.sections[1].rva, 0x2000);
            }
        }
    }
}
