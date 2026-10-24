//! Generated signed-time conversion programs; no external/sample bytes.
use super::winhttp::{
    Arg::{Memory as M, Value as V},
    call, expect_dword, load, store, write_dword,
};
use super::{ApiFixture, api_probe, put32, put64};
use crate::pe::Architecture;
#[derive(Clone, Copy, Debug)]
pub enum TimeFixture {
    Local,
    Fields,
    Signed,
    Bounds,
    AliasLocal,
    PartialLocal,
    AliasFields,
    PartialFields,
    ResidentHigh,
    ConfiguredPositive,
    ConfiguredNegative,
    LocalOverflow,
    CalendarLow,
    CalendarHigh,
    ReadonlyLocal,
    ReadonlyFields,
    CrossPageLocal,
    CrossPageFields,
    UnmappedInput,
    PagedInput,
    PagedOutput,
}
impl TimeFixture {
    pub fn configured_offset(self) -> Option<i32> {
        match self {
            Self::ConfiguredPositive => Some(120),
            Self::ConfiguredNegative => Some(-90),
            _ => None,
        }
    }
    pub fn error(self) -> Option<&'static str> {
        Some(match self {
            Self::LocalOverflow => "signed local time overflow",
            Self::CalendarLow | Self::CalendarHigh => "calendar outside legacy year1..9999 profile",
            Self::ReadonlyLocal
            | Self::ReadonlyFields
            | Self::CrossPageLocal
            | Self::CrossPageFields
            | Self::UnmappedInput => "API guest range",
            Self::PagedInput | Self::PagedOutput => "paged Pool access above APC_LEVEL",
            _ => return None,
        })
    }
    pub fn irql(self) -> u8 {
        match self {
            Self::ResidentHigh => 15,
            Self::PagedInput | Self::PagedOutput => 2,
            _ => 0,
        }
    }
}
const TICKS: i64 = 133_537_247_981_234_567;
fn fields(values: [i16; 8]) -> Vec<u8> {
    values.into_iter().flat_map(i16::to_le_bytes).collect()
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
            self.code.extend([0x39, 0xf4, 0x74, 1, 0xcc]);
        }
    }
    fn expect(&mut self, value: u32) {
        self.code.push(0x3d);
        self.code.extend(value.to_le_bytes());
        self.code.extend([0x74, 1, 0xcc]);
    }
    fn input(&mut self, address: u64, ticks: i64) {
        let value = ticks as u64;
        write_dword(&mut self.code, self.wide, address, value as u32);
        write_dword(&mut self.code, self.wide, address + 4, (value >> 32) as u32);
    }
    fn poison(&mut self, address: u64) {
        for n in 0..5 {
            write_dword(&mut self.code, self.wide, address + n * 4, 0x77777777);
        }
    }
    fn check(&mut self, address: u64, bytes: &[u8]) {
        assert_eq!(bytes.len() % 4, 0);
        for (index, part) in bytes.chunks_exact(4).enumerate() {
            expect_dword(
                &mut self.code,
                self.wide,
                address + index as u64 * 4,
                u32::from_le_bytes(part.try_into().unwrap()),
            );
        }
        expect_dword(
            &mut self.code,
            self.wide,
            address + bytes.len() as u64,
            0x77777777,
        );
    }
    fn irql(&mut self, value: u8) {
        if self.wide {
            self.code
                .extend([0xb8, value, 0, 0, 0, 0x44, 0x0f, 0x22, 0xc0]);
        } else {
            self.code.extend([0x64, 0xc6, 5, 0x24, 0, 0, 0, value]);
        }
    }
    fn convert(&mut self, input: u64, output: u64, ticks: i64, expected: &[u8], index: usize) {
        self.poison(output);
        self.input(input, ticks);
        self.call(index, &[V(input), V(output)]);
        self.check(output, expected);
    }
}
pub fn kernel_time_probe(architecture: Architecture, kind: TimeFixture) -> Vec<u8> {
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
        (0x1214, 0x2180 + 5 * width as u32),
        (0x1220, 0x2060),
        (0x1224, 0x2080 + 5 * width as u32),
    ] {
        put32(&mut data, at, value);
    }
    data[0x1240..0x124d].copy_from_slice(b"ntoskrnl.exe\0");
    data[0x1260..0x126d].copy_from_slice(b"kernel32.dll\0");
    let names = [
        "ExSystemTimeToLocalTime",
        "RtlTimeToTimeFields",
        "ExAllocatePoolWithTag",
        "ExFreePoolWithTag",
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
    let input = base + 0x2a00;
    let output = base + 0x2a40;
    let saved = base + 0x2a80;
    let mut p = Program {
        code: Vec::new(),
        wide,
        base,
    };
    if wide {
        p.code.extend([0x48, 0x83, 0xec, 0x48]);
    } else {
        p.code.extend([0x56, 0x89, 0xe6]);
    }
    p.call(5, &[V(0x12345678)]);
    use TimeFixture::*;
    match kind {
        Local | ResidentHigh | ConfiguredPositive | ConfiguredNegative => {
            let offset = kind.configured_offset().unwrap_or(-240);
            if kind.irql() != 0 {
                p.irql(kind.irql());
            }
            let localized = TICKS + i64::from(offset) * 600_000_000;
            p.convert(input, output, TICKS, &localized.to_le_bytes(), 0);
            let expected = match offset {
                120 => [2024, 3, 1, 1, 59, 58, 123, 5],
                -90 => [2024, 2, 29, 22, 29, 58, 123, 4],
                _ => [2024, 2, 29, 19, 59, 58, 123, 4],
            };
            p.poison(input);
            p.call(1, &[V(output), V(input)]);
            p.check(input, &fields(expected));
        }
        Fields => {
            for (ticks, expected) in [
                (TICKS, [2024, 2, 29, 23, 59, 58, 123, 4]),
                (94_405_824_000_000_007, [1900, 3, 1, 0, 0, 0, 0, 4]),
                (125_962_560_000_000_007, [2000, 2, 29, 0, 0, 0, 0, 2]),
                (157_520_160_000_000_007, [2100, 3, 1, 0, 0, 0, 0, 1]),
            ] {
                p.convert(input, output, ticks, &fields(expected), 1);
            }
        }
        Signed => {
            for (ticks, expected) in [
                (0, [1601, 1, 1, 0, 0, 0, 0, 1]),
                (-1, [1600, 12, 31, 23, 59, 59, 999, 0]),
                (-10_001, [1600, 12, 31, 23, 59, 59, 998, 0]),
            ] {
                p.convert(input, output, ticks, &fields(expected), 1);
            }
        }
        Bounds => {
            p.convert(
                input,
                output,
                -504_911_232_000_000_000,
                &fields([1, 1, 1, 0, 0, 0, 0, 1]),
                1,
            );
            p.convert(
                input,
                output,
                2_650_467_743_999_999_999,
                &fields([9999, 12, 31, 23, 59, 59, 999, 5]),
                1,
            );
        }
        AliasLocal | PartialLocal | AliasFields | PartialFields => {
            let delta = if matches!(kind, PartialLocal | PartialFields) {
                4
            } else {
                0
            };
            let dest = input + delta;
            let is_fields = matches!(kind, AliasFields | PartialFields);
            p.poison(input);
            p.poison(input + 16);
            p.input(input, TICKS);
            p.call(usize::from(is_fields), &[V(input), V(dest)]);
            if is_fields {
                p.check(dest, &fields([2024, 2, 29, 23, 59, 58, 123, 4]));
            } else {
                p.check(dest, &(TICKS - 144_000_000_000).to_le_bytes());
            }
        }
        PagedInput | PagedOutput => {
            p.poison(output);
            p.input(input, 0);
            p.call(2, &[V(1), V(16), V(u32::from_le_bytes(*b"Time").into())]);
            store(&mut p.code, wide, saved);
            if wide {
                p.code.push(0x48);
            }
            load(&mut p.code, wide, saved);
            p.code
                .extend([0xc7, 0, 0, 0, 0, 0, 0xc7, 0x40, 4, 0, 0, 0, 0]);
            p.irql(2);
            if matches!(kind, PagedInput) {
                p.call(1, &[M(saved), V(output)]);
            } else {
                p.call(1, &[V(input), M(saved)]);
            }
        }
        _ => {
            p.poison(output);
            let ticks = match kind {
                LocalOverflow => i64::MIN,
                CalendarLow => -504_911_232_000_000_001,
                CalendarHigh => 2_650_467_744_000_000_000,
                _ => TICKS,
            };
            p.input(input, ticks);
            let is_local = matches!(kind, LocalOverflow | ReadonlyLocal | CrossPageLocal);
            let dest = match kind {
                ReadonlyLocal | ReadonlyFields => base + 0x1000,
                CrossPageLocal | CrossPageFields => base + 0x3ffc,
                _ => output,
            };
            let source = if matches!(kind, UnmappedInput) {
                base + 0x4000
            } else {
                input
            };
            p.call(usize::from(!is_local), &[V(source), V(dest)]);
        }
    }
    p.call(6, &[]);
    p.expect(0x12345678);
    p.code.extend([0xb8, 17, 0, 0, 0]);
    if wide {
        p.code.extend([0x48, 0x83, 0xc4, 0x48]);
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
    fn every_generated_conversion_program_has_complete_two_dll_imports_and_driver_layout() {
        for arch in [Architecture::X86, Architecture::X64] {
            for kind in [
                TimeFixture::Local,
                TimeFixture::Fields,
                TimeFixture::Signed,
                TimeFixture::Bounds,
                TimeFixture::AliasLocal,
                TimeFixture::PartialLocal,
                TimeFixture::AliasFields,
                TimeFixture::PartialFields,
                TimeFixture::ResidentHigh,
                TimeFixture::ConfiguredPositive,
                TimeFixture::ConfiguredNegative,
                TimeFixture::LocalOverflow,
                TimeFixture::CalendarLow,
                TimeFixture::CalendarHigh,
                TimeFixture::ReadonlyLocal,
                TimeFixture::ReadonlyFields,
                TimeFixture::CrossPageLocal,
                TimeFixture::CrossPageFields,
                TimeFixture::UnmappedInput,
                TimeFixture::PagedInput,
                TimeFixture::PagedOutput,
            ] {
                let bytes = kernel_time_probe(arch, kind);
                let image = crate::pe::PeImage::parse(&bytes, "kernel-time.sys").unwrap();
                assert_eq!(
                    image.sample.kind,
                    crate::pe::Kind::Driver,
                    "{arch:?} {kind:?}"
                );
                assert_eq!(image.imports.len(), 6, "{arch:?} {kind:?}");
                for (module, name) in [
                    ("ntoskrnl.exe", "ExSystemTimeToLocalTime"),
                    ("ntoskrnl.exe", "RtlTimeToTimeFields"),
                    ("ntoskrnl.exe", "ExAllocatePoolWithTag"),
                    ("ntoskrnl.exe", "ExFreePoolWithTag"),
                    ("kernel32.dll", "SetLastError"),
                    ("kernel32.dll", "GetLastError"),
                ] {
                    assert!(
                        image
                            .imports
                            .iter()
                            .any(|i| i.module.eq_ignore_ascii_case(module)
                                && i.name == crate::pe::ImportName::Name(name.into())),
                        "{arch:?} {kind:?} {module}/{name}"
                    );
                }
                assert_eq!(image.sections[0].virtual_size, 0x1000);
                assert_eq!(image.sections[1].rva, 0x2000);
            }
        }
    }
}
