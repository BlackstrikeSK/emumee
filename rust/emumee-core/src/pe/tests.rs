use super::*;
use crate::fixtures;

#[test]
fn pe_imports_all_frozen_relocation_forms_match_characterized_legacy_words() {
    for architecture in [Architecture::X86, Architecture::X64] {
        for kind in [1u16, 2, 3, 4, 10] {
            for negative in [false, true] {
                let mut data = fixtures::counted_driver(architecture, 1);
                data[0x400..0x408]
                    .copy_from_slice(&[0x34, 0x12, 0x78, 0x56, 0xaa, 0xbb, 0xcc, 0xdd]);
                let directories = 0x98
                    + if architecture == Architecture::X64 {
                        112
                    } else {
                        96
                    };
                let rva = if kind == 4 { 0x12000 } else { 0x2000 };
                if kind == 4 {
                    put32(&mut data, table(architecture) + 40 + 12, rva);
                    put32(&mut data, 0x98 + 56, rva + 0x1000);
                }
                put32(&mut data, directories + 5 * 8, rva + 0x80);
                put32(&mut data, directories + 5 * 8 + 4, 12);
                put32(&mut data, 0x480, rva);
                put32(&mut data, 0x484, 12);
                data[0x488..0x48a].copy_from_slice(&(kind << 12).to_le_bytes());
                data[0x48a..0x48c]
                    .copy_from_slice(&(if kind == 4 { 0xfabcu16 } else { 0 }).to_le_bytes());
                let pe = PeImage::parse(&data, "reloc.sys").unwrap();
                let base = if negative {
                    pe.image_base - 0x10000
                } else {
                    pe.image_base + 0x10000
                };
                let image = pe.materialize(&data, base).unwrap();
                let (width, expected) = match (kind, negative) {
                    (1, false) => (2, 1u64),
                    (1, true) => (2, 0xffff),
                    (2, _) => (2, 0x1234),
                    (3, false) => (4, 0x56791234),
                    (3, true) => (4, 0x56771234),
                    (4, false) => (2, 0x1236),
                    (4, true) => (2, 0x1234),
                    (10, false) => (8, 0xddccbbaa56791234),
                    (10, true) => (8, 0xddccbbaa56771234),
                    _ => unreachable!(),
                };
                assert_eq!(
                    &image[rva as usize..rva as usize + width],
                    &expected.to_le_bytes()[..width]
                );
                if let Ok(root) = std::env::var("EMUMEE_USER_TEST_FIXTURES") {
                    let directory = std::path::PathBuf::from(root)
                        .join(format!("{architecture:?}-relocations-{kind}-{negative}"));
                    std::fs::create_dir_all(&directory).unwrap();
                    std::fs::write(directory.join("reloc.sys"), &data).unwrap();
                    std::fs::write(
                        directory.join("rust-value.bin"),
                        &image[rva as usize..rva as usize + width],
                    )
                    .unwrap();
                    std::fs::write(
                        directory.join("placement.json"),
                        format!("{{\"base\":{base},\"width\":{width},\"rva\":{rva}}}"),
                    )
                    .unwrap();
                }
                let mut missing = data.clone();
                missing[0x488..0x48a].copy_from_slice(&0u16.to_le_bytes());
                missing[0x48a..0x48c].copy_from_slice(&0x4000u16.to_le_bytes());
                let missing_pe = PeImage::parse(&missing, "reloc.sys").unwrap();
                assert!(
                    missing_pe
                        .materialize(&missing, base)
                        .unwrap_err()
                        .to_string()
                        .contains("HIGHADJ relocation has no addend")
                );
                put32(&mut missing, 0x484, 10);
                assert!(
                    PeImage::parse(&missing, "reloc.sys")
                        .unwrap()
                        .materialize(&missing, base)
                        .unwrap_err()
                        .to_string()
                        .contains("invalid relocation block")
                );
            }
        }
    }
}

#[test]
fn pe_imports_reject_malformed_names_hints_ordinals_iats_and_descriptors() {
    for architecture in [Architecture::X86, Architecture::X64] {
        for case in [
            "module",
            "empty",
            "hint",
            "ordinal",
            "iat_gap",
            "iat_end",
            "descriptor",
            "alias",
            "partial_alias",
        ] {
            let mut data = fixtures::api_probe(architecture, fixtures::ApiFixture::Unsupported);
            let directories = 0x98
                + if architecture == Architecture::X64 {
                    112
                } else {
                    96
                };
            match case {
                "module" => data[0x440] = b' ',
                "empty" => data[0x702] = 0,
                "hint" => {
                    let value = 0x2fffu64;
                    data[0x4d0..0x4d0 + architecture.width()]
                        .copy_from_slice(&value.to_le_bytes()[..architecture.width()]);
                }
                "ordinal" => {
                    let value = (1u64 << (architecture.width() * 8 - 1)) | 0x10001;
                    data[0x4d0..0x4d0 + architecture.width()]
                        .copy_from_slice(&value.to_le_bytes()[..architecture.width()]);
                }
                "iat_gap" => put32(&mut data, 0x410, 0x1800),
                "iat_end" => put32(&mut data, 0x410, 0x2fff),
                "descriptor" => put32(&mut data, directories + 12, 20),
                "alias" | "partial_alias" => {
                    let descriptor = data[0x400..0x414].to_vec();
                    data[0x414..0x428].copy_from_slice(&descriptor);
                    data[0x428..0x43c].fill(0);
                    put32(&mut data, directories + 12, 60);
                    if case == "partial_alias" {
                        put32(&mut data, 0x424, 0x2081);
                    }
                }
                _ => unreachable!(),
            }
            if let Ok(root) = std::env::var("EMUMEE_USER_TEST_FIXTURES") {
                let directory = std::path::PathBuf::from(root)
                    .join(format!("{architecture:?}-imports-invalid-{case}"));
                std::fs::create_dir_all(&directory).unwrap();
                std::fs::write(directory.join("imports.exe"), &data).unwrap();
            }
            assert!(
                PeImage::parse(&data, "imports.exe").is_err(),
                "{architecture:?}/{case}"
            );
        }
        let mut data = fixtures::api_probe(architecture, fixtures::ApiFixture::Unsupported);
        put32(&mut data, 0x400, 0);
        let lookup = data[0x4d0..0x4d0 + architecture.width() * 2].to_vec();
        data[0x480..0x480 + lookup.len()].copy_from_slice(&lookup);
        let pe = PeImage::parse(&data, "imports.exe").unwrap();
        assert_eq!(pe.imports.len(), 1);
        assert_eq!(pe.imports[0].iat_rva, 0x2080);
        let mut adjacent = fixtures::api_probe(architecture, fixtures::ApiFixture::Unsupported);
        put32(&mut adjacent, table(architecture) + 8, 0x1000);
        put32(&mut adjacent, 0x410, 0x1ffe);
        assert!(PeImage::parse(&adjacent, "adjacent.exe").is_ok());
    }
}

#[test]
fn pe_imports_highlow_dir64_positive_negative_and_malformed_relocations() {
    for architecture in [Architecture::X86, Architecture::X64] {
        let data = fixtures::relocating_driver(architecture);
        let pe = PeImage::parse(&data, "reloc.sys").unwrap();
        let width = architecture.width();
        for base in [
            pe.image_base - 0x10000,
            pe.image_base,
            pe.image_base + 0x10000,
        ] {
            let image = pe.materialize(&data, base).unwrap();
            let mut value = [0; 8];
            value[..width].copy_from_slice(&image[0x2000..0x2000 + width]);
            assert_eq!(u64::from_le_bytes(value), base + 0x1180);
        }
        let block = if architecture == Architecture::X64 {
            0x480
        } else {
            0x48c
        };
        for case in ["size", "page", "type", "gap", "end", "overflow", "stripped"] {
            let mut bad = data.clone();
            match case {
                "size" => put32(&mut bad, block + 4, 9),
                "page" => put32(&mut bad, block, 0x2001),
                "type" => bad[block + 8..block + 10].copy_from_slice(&0x5000u16.to_le_bytes()),
                "gap" => {
                    put32(&mut bad, block, 0x1000);
                    let kind = if width == 8 { 0xa800u16 } else { 0x3800 };
                    bad[block + 8..block + 10].copy_from_slice(&kind.to_le_bytes());
                }
                "end" => {
                    let kind = if width == 8 { 0xafffu16 } else { 0x3fff };
                    bad[block + 8..block + 10].copy_from_slice(&kind.to_le_bytes());
                }
                "overflow" => put32(&mut bad, block, 0xfffff000),
                "stripped" => bad[0x96] |= 1,
                _ => unreachable!(),
            }
            let bad_pe = PeImage::parse(&bad, "reloc.sys").unwrap();
            assert!(
                bad_pe.materialize(&bad, pe.image_base + 0x10000).is_err(),
                "{architecture:?}/{case}"
            );
        }
    }
}

fn put32(data: &mut [u8], offset: usize, value: u32) {
    data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn table(architecture: Architecture) -> usize {
    0x98 + if architecture == Architecture::X64 {
        0xf0
    } else {
        0xe0
    }
}

#[test]
fn pe_layout_rejects_misaligned_overlapping_and_overflowing_ranges() {
    for architecture in [Architecture::X86, Architecture::X64] {
        let section = table(architecture);
        for (offset, value) in [
            (0x98 + 60, 0x1ff),
            (0x98 + 32, 0x2000),
            (section + 20, 0x201),
            (section + 40 + 12, 0x1000),
            (section + 40 + 8, u32::MAX),
            (section + 40 + 20, 0xffff_fe00),
            (0x98 + 56, 0x2000),
        ] {
            let mut data = fixtures::counted_driver(architecture, 1);
            put32(&mut data, offset, value);
            assert!(
                PeImage::parse(&data, "layout.sys").is_err(),
                "{architecture:?}: accepted offset {offset:#x} = {value:#x}"
            );
        }
    }
}

#[test]
fn pe_layout_exact_raw_lengths_do_not_expose_virtual_zero_fill_as_file_bytes() {
    for architecture in [Architecture::X86, Architecture::X64] {
        for raw_size in [0, 1, 0x1ff, 0x200] {
            let mut data = fixtures::counted_driver(architecture, 1);
            put32(&mut data, table(architecture) + 16, raw_size);
            let pe = PeImage::parse(&data, "layout.sys").unwrap();
            let image = pe.materialize(&data, pe.image_base).unwrap();
            let end = 0x1000 + raw_size as usize;
            assert_eq!(&image[0x1000..end], &data[0x200..0x200 + raw_size as usize]);
            assert!(image[end..0x2000].iter().all(|byte| *byte == 0));
            assert!(pe.rva(&data, end as u32, 1).is_err());
        }
    }
}

#[test]
fn pe_layout_raw_aliases_are_independent_virtual_copies() {
    for architecture in [Architecture::X86, Architecture::X64] {
        for raw_offset in [0, 0x200] {
            let mut data = fixtures::counted_driver(architecture, 1);
            let section = table(architecture);
            put32(&mut data, section + 40 + 20, raw_offset);
            let pe = PeImage::parse(&data, "layout.sys").unwrap();
            let mut image = pe.materialize(&data, pe.image_base).unwrap();
            let source = raw_offset as usize;
            assert_eq!(&image[0x2000..0x2200], &data[source..source + 0x200]);
            image[0x2000] ^= 0xff;
            assert_eq!(image[0x1000], data[0x200]);
            assert_eq!(image[0], data[0]);
        }
    }
}

#[test]
fn pe_layout_materializes_headers_raw_tails_zero_fill_and_gaps() {
    for architecture in [Architecture::X86, Architecture::X64] {
        for virtual_size in [0, 1, 0x100, 0x200, 0x900] {
            let mut data = fixtures::counted_driver(architecture, 1);
            let section = table(architecture);
            put32(&mut data, section + 8, virtual_size);
            put32(&mut data, section + 40 + 12, 0x3000);
            put32(&mut data, 0x98 + 56, 0x5000);
            let pe = PeImage::parse(&data, "layout.sys").unwrap();
            let image = pe.materialize(&data, pe.image_base).unwrap();
            assert_eq!(&image[..0x200], &data[..0x200]);
            assert_eq!(&image[0x1000..0x1200], &data[0x200..0x400]);
            assert!(image[0x1200..0x3000].iter().all(|byte| *byte == 0));
            assert_eq!(&image[0x3000..0x3200], &data[0x400..0x600]);
            assert!(image[0x3200..].iter().all(|byte| *byte == 0));
            assert!(pe.rva(&data, 0x1200, 1).is_err());
            assert!(pe.rva(&data, 0x2000, 1).is_err());
            assert!(pe.rva(&data, u32::MAX, usize::MAX).is_err());
        }
    }
}

#[test]
fn pe_layout_materialization_refuses_invalid_address_placement() {
    for architecture in [Architecture::X86, Architecture::X64] {
        let data = fixtures::relocating_driver(architecture);
        let pe = PeImage::parse(&data, "layout.sys").unwrap();
        for base in [0, pe.image_base + 1, u64::MAX - 4095] {
            assert!(
                pe.materialize(&data, base).is_err(),
                "{architecture:?}/{base:#x}"
            );
        }
        if architecture == Architecture::X86 {
            assert!(pe.materialize(&data, 0xffff_f000).is_err());
            assert!(pe.materialize(&data, 0xffff_0000).is_ok());
        } else {
            assert!(pe.materialize(&data, 0xffff_f801_0000_0000).is_ok());
        }
    }
}

#[test]
fn pe_layout_truncated_and_mutated_materialization_never_panics() {
    for architecture in [Architecture::X86, Architecture::X64] {
        let data = fixtures::counted_driver(architecture, 1);
        let pe = PeImage::parse(&data, "layout.sys").unwrap();
        for end in 0..data.len() {
            assert!(PeImage::parse(&data[..end], "layout.sys").is_err());
            assert!(pe.materialize(&data[..end], pe.image_base).is_err());
        }
        for field in ["headers", "image", "section", "virtual"] {
            let mut pe = PeImage::parse(&data, "layout.sys").unwrap();
            match field {
                "headers" => pe.headers_size = pe.image_size + 1,
                "image" => pe.image_size = MAX_IMAGE + 4096,
                "virtual" => pe.sections[0].virtual_size = u32::MAX,
                _ => pe.sections[0].rva = u32::MAX,
            }
            assert!(pe.materialize(&data, pe.image_base).is_err(), "{field}");
        }
    }
}
