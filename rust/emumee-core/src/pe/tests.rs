use super::*;
use crate::fixtures;

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
