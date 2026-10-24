//! Owned native/Win32 file callers. All paths and bytes are generated literals.
use super::winhttp::{
    Arg::{Memory as M, Value as V},
    call, expect_dword, load, store, write_dword,
};
use super::{ApiFixture, api_probe, put16, put32, put64};
use crate::pe::Architecture;
#[derive(Clone, Copy, Debug)]
pub enum NativeFilesFixture {
    Basic,
    Supersede,
    CreateCollision,
    Overwrite,
    OverwriteIf,
    OpenExisting,
    Directory,
    DirectoryTrailing,
    DirectoryInteriorEmpty,
    FileTrailing,
    Offsets,
    Sharing,
    TypedClose,
    Readonly,
    Missing,
    Unlink,
    SeedRead,
    UserCoherence,
    Bounds,
    Async,
    Event,
    Apc,
    Key,
    Ea,
    Security,
    Context,
    BadLength,
    OddUnicode,
    ReadonlyHandle,
    ReadonlyIosb,
    ReadonlyRead,
    Overlap,
    CrossBoundary,
    HighIrql,
    FileReference,
    SeedWrite,
}
impl NativeFilesFixture {
    pub fn error(self) -> Option<&'static str> {
        Some(match self {
            Self::Async => "asynchronous native files",
            Self::Event | Self::Apc | Self::Key => "event/APC/key asynchronous",
            Self::Ea | Self::Context => "EA/type/options/context unsupported",
            Self::Security => "object attributes/security unsupported",
            Self::BadLength => "UNICODE_STRING length",
            Self::OddUnicode => "strict UTF-16",
            Self::ReadonlyHandle
            | Self::ReadonlyIosb
            | Self::ReadonlyRead
            | Self::CrossBoundary => "range",
            Self::Overlap => "outputs overlap",
            Self::HighIrql => "Native files require PASSIVE_LEVEL",
            Self::FileReference => "Foreign process/file kernel handle reference profile",
            Self::DirectoryInteriorEmpty | Self::FileTrailing => "ambiguous native path component",
            _ => return None,
        })
    }
    pub fn initial_open_succeeds(self) -> bool {
        matches!(
            self,
            Self::Event | Self::Apc | Self::Key | Self::ReadonlyRead | Self::FileReference
        )
    }
}
pub fn native_files_document() -> Vec<u8> {
    let mut p: serde_json::Value = serde_json::from_slice(&super::configured_document(
        super::ConfiguredFixture::Kernel,
    ))
    .unwrap();
    p["registry_keys"] = serde_json::json!([]);
    p["virtual_files"] =
        serde_json::json!([{"path":"C:\\Users\\Morgan\\Downloads\\seed.bin","base64":"U0VFRA=="}]);
    serde_json::to_vec(&p).unwrap()
}
fn expect(c: &mut Vec<u8>, v: u32) {
    c.push(0x3d);
    c.extend(v.to_le_bytes());
    c.extend([0x74, 1, 0xcc]);
}
fn text(data: &mut [u8], wide: bool, base: u64, descriptor: usize, buffer: usize, s: &str) {
    let bytes = s
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    put16(data, descriptor - 0xe00, bytes.len() as u16);
    put16(data, descriptor - 0xe00 + 2, 32766);
    if wide {
        put64(data, descriptor - 0xe00 + 8, base + buffer as u64);
    } else {
        put32(data, descriptor - 0xe00 + 4, (base + buffer as u64) as u32);
    }
    data[buffer - 0xe00..buffer - 0xe00 + bytes.len()].copy_from_slice(&bytes);
}
fn oa(data: &mut [u8], wide: bool, base: u64, address: usize, name: usize) {
    let raw = address - 0xe00;
    put32(data, raw, if wide { 48 } else { 24 });
    if wide {
        put64(data, raw + 16, base + name as u64);
        put32(data, raw + 24, 0x240);
    } else {
        put32(data, raw + 8, (base + name as u64) as u32);
        put32(data, raw + 12, 0x240);
    }
}
struct Program {
    code: Vec<u8>,
    wide: bool,
    base: u64,
    h: u64,
    other: u64,
    ios: u64,
    offset: u64,
    input: u64,
    output: u64,
    oa: u64,
    alternate: u64,
}
impl Program {
    fn call(&mut self, i: usize, args: &[super::winhttp::Arg]) {
        call(&mut self.code, self.wide, self.base, i, args);
    }
    fn status(&mut self, value: u32) {
        expect(&mut self.code, value);
    }
    fn word(&mut self, address: u64, value: u32) {
        expect_dword(&mut self.code, self.wide, address, value);
    }
    fn set(&mut self, address: u64, value: u32) {
        write_dword(&mut self.code, self.wide, address, value);
    }
    fn poison_iosb(&mut self) {
        for i in 0..if self.wide { 5 } else { 3 } {
            self.set(self.ios + i * 4, 0x77777777);
        }
    }
    fn check_iosb(&mut self, status: u32, information: u32) {
        self.word(self.ios, status);
        if self.wide {
            self.word(self.ios + 4, 0);
            self.word(self.ios + 12, 0);
        }
        self.word(self.ios + if self.wide { 8 } else { 4 }, information);
        self.word(self.ios + if self.wide { 16 } else { 8 }, 0x77777777);
    }
    fn create(
        &mut self,
        slot: u64,
        oa: u64,
        (access, disp, options, attributes): (u32, u32, u32, u32),
        (status, information): (u32, u32),
    ) {
        self.set(slot, 0x77777777);
        if self.wide {
            self.set(slot + 4, 0x77777777);
        }
        self.poison_iosb();
        self.call(
            0,
            &[
                V(slot),
                V(access.into()),
                V(oa),
                V(self.ios),
                V(0),
                V(attributes.into()),
                V(7),
                V(disp.into()),
                V(options.into()),
                V(0),
                V(0),
                V(0),
                V(0),
                V(0),
                V(0),
            ],
        );
        self.status(status);
        self.check_iosb(status, information);
        if status != 0 {
            self.word(slot, 0x77777777);
        } else if self.wide {
            self.word(slot + 4, 0xffffffff);
        }
    }
    fn transfer(
        &mut self,
        write: bool,
        slot: u64,
        count: u32,
        offset: bool,
        status: u32,
        information: u32,
    ) {
        self.poison_iosb();
        self.call(
            if write { 2 } else { 1 },
            &[
                M(slot),
                V(0),
                V(0),
                V(0),
                V(self.ios),
                V(if write { self.input } else { self.output }),
                V(count.into()),
                V(if offset { self.offset } else { 0 }),
                V(0),
            ],
        );
        self.status(status);
        self.check_iosb(status, information);
    }
    fn close(&mut self, slot: u64, alias: bool, status: u32) {
        self.call(if alias { 5 } else { 4 }, &[M(slot)]);
        self.status(status);
    }
    fn position(&mut self, value: i64) {
        self.set(self.offset, value as u32);
        self.set(self.offset + 4, (value as u64 >> 32) as u32);
    }
}
pub fn native_files_probe(architecture: Architecture, kind: NativeFilesFixture) -> Vec<u8> {
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
        (dd + 12, 60),
        (0x1200, 0x2180),
        (0x120c, 0x2040),
        (0x1210, 0x2080),
        (0x1214, 0x2180 + 8 * width as u32),
        (0x1220, 0x2060),
        (0x1224, 0x2080 + 8 * width as u32),
    ] {
        put32(&mut data, at, value);
    }
    data[0x1240..0x124d].copy_from_slice(b"ntoskrnl.exe\0");
    data[0x1260..0x126d].copy_from_slice(b"kernel32.dll\0");
    let names = [
        "IoCreateFileEx",
        "ZwReadFile",
        "ZwWriteFile",
        "ZwFlushBuffersFile",
        "ZwClose",
        "NtClose",
        "ObReferenceObjectByHandle",
        "",
        "CreateFileW",
        "ReadFile",
        "WriteFile",
        "CloseHandle",
        "DeleteFileW",
        "SetFilePointer",
        "SetLastError",
        "GetLastError",
    ];
    for (index, name) in names.iter().enumerate() {
        if name.is_empty() {
            continue;
        }
        let rva = 0x2400 + index as u32 * 64;
        for raw in [0x1280, 0x1380] {
            if wide {
                put64(&mut data, raw + index * width, rva.into());
            } else {
                put32(&mut data, raw + index * width, rva);
            }
        }
        let raw = 0x1600 + index * 64;
        data[raw + 2..raw + 2 + name.len()].copy_from_slice(name.as_bytes());
    }
    let file = match kind {
        NativeFilesFixture::SeedRead | NativeFilesFixture::SeedWrite => {
            r"C:\Users\Morgan\Downloads\seed.bin"
        }
        NativeFilesFixture::DirectoryTrailing => r"C:\Users\Morgan\Downloads\Logs\",
        NativeFilesFixture::DirectoryInteriorEmpty => r"C:\Users\Morgan\Downloads\\Logs\",
        NativeFilesFixture::FileTrailing => r"C:\Users\Morgan\Downloads\file.bin\",
        _ => r"C:\Users\Morgan\Downloads\nt-file.bin",
    };
    text(&mut data, wide, base, 0x2a80, 0x2b00, file);
    text(
        &mut data,
        wide,
        base,
        0x2aa0,
        0x2b80,
        if matches!(
            kind,
            NativeFilesFixture::Directory | NativeFilesFixture::DirectoryTrailing
        ) {
            "child.bin"
        } else {
            r"C:\Users\Morgan\Downloads\absent\file.bin"
        },
    );
    oa(&mut data, wide, base, 0x2a00, 0x2a80);
    oa(&mut data, wide, base, 0x2a40, 0x2aa0);
    let file_wide = file
        .encode_utf16()
        .chain(Some(0))
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    data[0x2100..0x2100 + file_wide.len()].copy_from_slice(&file_wide);
    data[0x1f00..0x1f04].copy_from_slice(b"RUST");
    if matches!(kind, NativeFilesFixture::BadLength) {
        put16(&mut data, 0x1c80, 3);
    }
    if matches!(kind, NativeFilesFixture::OddUnicode) {
        put16(&mut data, 0x1c80, 2);
        put16(&mut data, 0x1d00, 0xd800);
    }
    if matches!(kind, NativeFilesFixture::Security) {
        if wide {
            put64(&mut data, 0x1c00 + 32, 0x123);
        } else {
            put32(&mut data, 0x1c00 + 16, 0x123);
        }
    }
    let mut p = Program {
        code: Vec::new(),
        wide,
        base,
        h: base + 0x2c00,
        other: base + 0x2c20,
        ios: base + 0x2c40,
        offset: base + 0x2c60,
        input: base + 0x2d00,
        output: base + 0x2d40,
        oa: base + 0x2a00,
        alternate: base + 0x2a40,
    };
    if wide {
        p.code.extend([0x48, 0x81, 0xec, 0x88, 0, 0, 0]);
    }
    if matches!(kind, NativeFilesFixture::HighIrql) {
        if wide {
            p.code.extend([0xb8, 2, 0, 0, 0, 0x44, 0x0f, 0x22, 0xc0]);
        } else {
            p.code.extend([0x64, 0xc6, 5, 0x24, 0, 0, 0, 2]);
        }
    }
    if kind.error().is_some() && !kind.initial_open_succeeds() {
        let mut slot = p.h;
        let mut ios = p.ios;
        if matches!(kind, NativeFilesFixture::ReadonlyHandle) {
            slot = base + 0x1000;
        }
        if matches!(kind, NativeFilesFixture::ReadonlyIosb) {
            ios = base + 0x1000;
        }
        if matches!(kind, NativeFilesFixture::Overlap) {
            ios = slot;
        }
        if matches!(kind, NativeFilesFixture::CrossBoundary) {
            ios = base + 0x6000 - 4;
        }
        p.call(
            0,
            &[
                V(slot),
                V(0xc0010000),
                V(p.oa),
                V(ios),
                V(0),
                V(0x80),
                V(7),
                V(3),
                V(if matches!(kind, NativeFilesFixture::Async) {
                    0x40
                } else if matches!(kind, NativeFilesFixture::DirectoryInteriorEmpty) {
                    0x21
                } else {
                    0x60
                }),
                V(if matches!(kind, NativeFilesFixture::Ea) {
                    p.input
                } else {
                    0
                }),
                V(0),
                V(0),
                V(0),
                V(0),
                V(if matches!(kind, NativeFilesFixture::Context) {
                    p.input
                } else {
                    0
                }),
            ],
        );
        p.code.push(0xcc);
    } else if matches!(
        kind,
        NativeFilesFixture::Supersede
            | NativeFilesFixture::CreateCollision
            | NativeFilesFixture::Overwrite
            | NativeFilesFixture::OverwriteIf
            | NativeFilesFixture::OpenExisting
    ) {
        p.create(p.h, p.oa, (0xc0010000, 3, 0x60, 0x80), (0, 2));
        p.transfer(true, p.h, 4, false, 0, 4);
        p.close(p.h, false, 0);
        let disposition = match kind {
            NativeFilesFixture::Supersede => 0,
            NativeFilesFixture::CreateCollision => 2,
            NativeFilesFixture::Overwrite => 4,
            NativeFilesFixture::OverwriteIf => 5,
            _ => 1,
        };
        p.create(
            p.h,
            p.oa,
            (0xc0010000, disposition, 0x60, 0x80),
            (
                if disposition == 2 { 0xc0000035 } else { 0 },
                match disposition {
                    0 => 0,
                    2 => 4,
                    4 | 5 => 3,
                    _ => 1,
                },
            ),
        );
        if disposition != 2 {
            p.transfer(
                false,
                p.h,
                4,
                false,
                if [0, 4, 5].contains(&disposition) {
                    0xc0000011
                } else {
                    0
                },
                if [0, 4, 5].contains(&disposition) {
                    0
                } else {
                    4
                },
            );
            p.close(p.h, true, 0);
        }
    } else if matches!(
        kind,
        NativeFilesFixture::Directory | NativeFilesFixture::DirectoryTrailing
    ) {
        p.create(p.h, p.oa, (0xc0010000, 2, 0x21, 0x10), (0, 2));
        if wide {
            p.code.push(0x48);
        }
        load(&mut p.code, wide, p.h);
        store(&mut p.code, wide, p.alternate + if wide { 8 } else { 4 });
        p.create(p.other, p.alternate, (0xc0010000, 3, 0x60, 0x80), (0, 2));
        p.transfer(true, p.other, 4, false, 0, 4);
        p.transfer(false, p.h, 1, false, 0xc00000ba, 0);
        p.close(p.other, false, 0);
        p.close(p.h, true, 0);
    } else if matches!(kind, NativeFilesFixture::Missing) {
        p.create(p.h, p.oa, (0xc0010000, 1, 0x60, 0x80), (0xc0000034, 5));
        p.create(
            p.h,
            p.alternate,
            (0xc0010000, 3, 0x60, 0x80),
            (0xc000003a, 5),
        );
    } else {
        let seed_read = matches!(kind, NativeFilesFixture::SeedRead);
        let seed_write = matches!(kind, NativeFilesFixture::SeedWrite);
        let seed = seed_read || seed_write;
        p.create(
            p.h,
            p.oa,
            (
                if seed_read { 0x80000000 } else { 0xc0010000 },
                if seed_read { 1 } else { 3 },
                0x60,
                0x80,
            ),
            (0, if seed { 1 } else { 2 }),
        );
        if kind.initial_open_succeeds() {
            if matches!(kind, NativeFilesFixture::FileReference) {
                p.call(6, &[M(p.h), V(0), V(0), V(0), V(p.output), V(0)]);
            } else {
                p.call(
                    1,
                    &[
                        M(p.h),
                        V(if matches!(kind, NativeFilesFixture::Event) {
                            1
                        } else {
                            0
                        }),
                        V(if matches!(kind, NativeFilesFixture::Apc) {
                            p.input
                        } else {
                            0
                        }),
                        V(0),
                        V(p.ios),
                        V(if matches!(kind, NativeFilesFixture::ReadonlyRead) {
                            base + 0x1000
                        } else {
                            p.output
                        }),
                        V(1),
                        V(0),
                        V(if matches!(kind, NativeFilesFixture::Key) {
                            p.input
                        } else {
                            0
                        }),
                    ],
                );
            }
            p.code.push(0xcc);
        } else if seed_read {
            p.transfer(false, p.h, 4, false, 0, 4);
            p.word(p.output, u32::from_le_bytes(*b"SEED"));
            p.close(p.h, false, 0);
        } else if seed_write {
            p.transfer(true, p.h, 4, false, 0, 4);
            p.transfer(false, p.h, 4, true, 0, 4);
            p.word(p.output, u32::from_le_bytes(*b"RUST"));
            p.close(p.h, false, 0);
        } else if matches!(kind, NativeFilesFixture::Readonly) {
            p.close(p.h, false, 0);
            p.create(p.h, p.oa, (0xc0010000, 5, 0x60, 1), (0, 3));
            p.close(p.h, false, 0);
            p.create(p.h, p.oa, (0xc0010000, 1, 0x60, 0x80), (0xc0000022, 0));
        } else if matches!(kind, NativeFilesFixture::Sharing) {
            p.transfer(true, p.h, 4, false, 0, 4);
            p.call(
                8,
                &[
                    V(base + 0x2f00),
                    V(0x80000000),
                    V(1),
                    V(0),
                    V(3),
                    V(0x80),
                    V(0),
                ],
            );
            p.status(u32::MAX);
            p.close(p.h, false, 0);
        } else if matches!(kind, NativeFilesFixture::Bounds) {
            p.position(32 * 1024 * 1024);
            p.transfer(true, p.h, 0, true, 0, 0);
            p.transfer(true, p.h, 1, true, 0xc000000d, 0);
            p.close(p.h, false, 0);
        } else if matches!(kind, NativeFilesFixture::TypedClose) {
            p.close(p.h, true, 0);
            p.close(p.h, false, 0xc0000008);
            if wide {
                expect_dword(&mut p.code, wide, p.h + 4, 0xffffffff);
                p.code.extend([0xa1]);
                p.code.extend(p.h.to_le_bytes());
                store(&mut p.code, wide, p.other);
                p.close(p.other, false, 0xc0000008);
            }
        } else if matches!(kind, NativeFilesFixture::UserCoherence) {
            p.call(
                8,
                &[
                    V(base + 0x2f00),
                    V(0xc0000000),
                    V(7),
                    V(0),
                    V(3),
                    V(0x80),
                    V(0),
                ],
            );
            store(&mut p.code, wide, p.other);
            p.call(10, &[M(p.other), V(p.input), V(4), V(p.output + 32), V(0)]);
            p.status(1);
            p.transfer(false, p.h, 4, false, 0, 4);
            p.word(p.output, u32::from_le_bytes(*b"RUST"));
            p.call(11, &[M(p.other)]);
            p.status(1);
            p.close(p.h, false, 0);
        } else {
            p.transfer(true, p.h, 4, false, 0, 4);
            if matches!(kind, NativeFilesFixture::Unlink) {
                p.call(12, &[V(base + 0x2f00)]);
                p.status(1);
            }
            p.position(0);
            p.transfer(false, p.h, 4, true, 0, 4);
            p.word(p.output, u32::from_le_bytes(*b"RUST"));
            p.transfer(false, p.h, 1, false, 0xc0000011, 0);
            if matches!(kind, NativeFilesFixture::Offsets) {
                p.position(-1);
                p.transfer(true, p.h, 4, true, 0, 4);
                p.position(0);
                p.transfer(false, p.h, 8, true, 0, 8);
                p.word(p.output, u32::from_le_bytes(*b"RUST"));
                p.word(p.output + 4, u32::from_le_bytes(*b"RUST"));
                p.position(-2);
                p.transfer(false, p.h, 0, true, 0, 0);
            }
            p.poison_iosb();
            p.call(3, &[M(p.h), V(p.ios)]);
            p.status(0);
            p.check_iosb(0, 0);
            p.close(p.h, false, 0);
        }
    }
    if wide {
        p.code.extend([0x48, 0x81, 0xc4, 0x88, 0, 0, 0]);
    }
    p.code.extend([0xb8, 1, 0, 0, 0, 0xc3]);
    assert!(
        p.code.len() <= 0x1000,
        "owned native-file code exceeds text section: {}",
        p.code.len()
    );
    data[0x200..0x200 + p.code.len()].copy_from_slice(&p.code);
    data
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_owned_native_file_program_has_checked_imports_and_driver_target_for_both_abis() {
        for architecture in [Architecture::X86, Architecture::X64] {
            for kind in [
                NativeFilesFixture::Basic,
                NativeFilesFixture::Supersede,
                NativeFilesFixture::CreateCollision,
                NativeFilesFixture::Overwrite,
                NativeFilesFixture::OverwriteIf,
                NativeFilesFixture::OpenExisting,
                NativeFilesFixture::Directory,
                NativeFilesFixture::DirectoryTrailing,
                NativeFilesFixture::DirectoryInteriorEmpty,
                NativeFilesFixture::FileTrailing,
                NativeFilesFixture::Offsets,
                NativeFilesFixture::Sharing,
                NativeFilesFixture::TypedClose,
                NativeFilesFixture::Readonly,
                NativeFilesFixture::Missing,
                NativeFilesFixture::Unlink,
                NativeFilesFixture::SeedRead,
                NativeFilesFixture::UserCoherence,
                NativeFilesFixture::Bounds,
                NativeFilesFixture::Async,
                NativeFilesFixture::Event,
                NativeFilesFixture::Apc,
                NativeFilesFixture::Key,
                NativeFilesFixture::Ea,
                NativeFilesFixture::Security,
                NativeFilesFixture::Context,
                NativeFilesFixture::BadLength,
                NativeFilesFixture::OddUnicode,
                NativeFilesFixture::ReadonlyHandle,
                NativeFilesFixture::ReadonlyIosb,
                NativeFilesFixture::ReadonlyRead,
                NativeFilesFixture::Overlap,
                NativeFilesFixture::CrossBoundary,
                NativeFilesFixture::HighIrql,
                NativeFilesFixture::FileReference,
                NativeFilesFixture::SeedWrite,
            ] {
                let bytes = native_files_probe(architecture, kind);
                let pe = crate::pe::PeImage::parse(&bytes, "native-file-fixture.sys").unwrap();
                assert_eq!(pe.sample.kind, crate::pe::Kind::Driver);
                assert_eq!(pe.sample.architecture, architecture);
                assert!(
                    pe.imports
                        .iter()
                        .any(|i| i.name == crate::pe::ImportName::Name("IoCreateFileEx".into()))
                );
                assert_eq!(pe.entry_rva, 0x1000);
            }
        }
    }
}
