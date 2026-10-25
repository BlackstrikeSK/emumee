use super::*;

fn put16(data: &mut [u8], at: usize, value: u16) {
    data[at..at + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(data: &mut [u8], at: usize, value: u32) {
    data[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(data: &mut [u8], at: usize, value: u64) {
    data[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

fn elf64() -> Vec<u8> {
    let mut data = vec![0; 0x120];
    data[..4].copy_from_slice(b"\x7fELF");
    data[4] = 2;
    data[5] = 1;
    data[6] = 1;
    data[7] = 3;
    put16(&mut data, 16, 2);
    put16(&mut data, 18, 62);
    put32(&mut data, 20, 1);
    put64(&mut data, 24, 0x400100);
    put64(&mut data, 32, 64);
    put16(&mut data, 52, 64);
    put16(&mut data, 54, 56);
    put16(&mut data, 56, 2);
    put32(&mut data, 64, PT_LOAD);
    put32(&mut data, 68, 5);
    put64(&mut data, 72, 0x100);
    put64(&mut data, 80, 0x400100);
    put64(&mut data, 96, 4);
    put64(&mut data, 104, 8);
    put64(&mut data, 112, 0x100);
    put32(&mut data, 120, PT_INTERP);
    put64(&mut data, 128, 0x108);
    put64(&mut data, 152, 11);
    data[0x100..0x104].copy_from_slice(&[0x31, 0xc0, 0x0f, 0x05]);
    data[0x108..0x113].copy_from_slice(b"/lib/ld.so\0");
    data
}

fn elf32() -> Vec<u8> {
    let mut data = vec![0; 0x90];
    data[..4].copy_from_slice(b"\x7fELF");
    data[4] = 1;
    data[5] = 1;
    data[6] = 1;
    put16(&mut data, 16, 3);
    put16(&mut data, 18, 3);
    put32(&mut data, 20, 1);
    put32(&mut data, 24, 0x8048082);
    put32(&mut data, 28, 52);
    put16(&mut data, 40, 52);
    put16(&mut data, 42, 32);
    put16(&mut data, 44, 1);
    put32(&mut data, 52, PT_LOAD);
    put32(&mut data, 56, 0x80);
    put32(&mut data, 60, 0x8048080);
    put32(&mut data, 68, 4);
    put32(&mut data, 72, 8);
    put32(&mut data, 76, 5);
    put32(&mut data, 80, 0x80);
    data[0x80..0x84].copy_from_slice(&[0x31, 0xc0, 0xcd, 0x80]);
    data
}

fn static_elf64() -> Vec<u8> {
    let mut data = elf64();
    put16(&mut data, 56, 1);
    put64(&mut data, 72, 0);
    put64(&mut data, 80, 0x400000);
    let size = data.len() as u64;
    put64(&mut data, 96, size);
    put64(&mut data, 104, size);
    put64(&mut data, 112, 0x1000);
    data
}

fn pie_with_relative_relocation() -> Vec<u8> {
    let mut data = vec![0; 0x1100];
    data[..4].copy_from_slice(b"\x7fELF");
    data[4] = 2;
    data[5] = 1;
    data[6] = 1;
    put16(&mut data, 16, 3);
    put16(&mut data, 18, 62);
    put32(&mut data, 20, 1);
    put64(&mut data, 24, 0x100);
    put64(&mut data, 32, 64);
    put16(&mut data, 52, 64);
    put16(&mut data, 54, 56);
    put16(&mut data, 56, 3);
    put32(&mut data, 64, PT_LOAD);
    put32(&mut data, 68, 5);
    put64(&mut data, 96, 0x200);
    put64(&mut data, 104, 0x200);
    put64(&mut data, 112, 0x1000);
    put32(&mut data, 120, PT_LOAD);
    put32(&mut data, 124, 6);
    put64(&mut data, 128, 0x1000);
    put64(&mut data, 136, 0x1000);
    put64(&mut data, 152, 0x100);
    put64(&mut data, 160, 0x100);
    put64(&mut data, 168, 0x1000);
    put32(&mut data, 176, 2); // PT_DYNAMIC
    put32(&mut data, 180, 6);
    put64(&mut data, 184, 0x1000);
    put64(&mut data, 192, 0x1000);
    put64(&mut data, 208, 64);
    put64(&mut data, 216, 64);
    put64(&mut data, 224, 8);
    put64(&mut data, 0x1000, 7); // DT_RELA
    put64(&mut data, 0x1008, 0x1080);
    put64(&mut data, 0x1010, 8); // DT_RELASZ
    put64(&mut data, 0x1018, 24);
    put64(&mut data, 0x1020, 9); // DT_RELAENT
    put64(&mut data, 0x1028, 24);
    put64(&mut data, 0x1080, 0x10a0);
    put64(&mut data, 0x1088, 8); // R_X86_64_RELATIVE, symbol 0
    put64(&mut data, 0x1090, 0x150);
    data[0x100..0x102].copy_from_slice(&[0xeb, 0xfe]);
    data
}

fn static_i386() -> Vec<u8> {
    let mut data = vec![0; 0x200];
    data[..4].copy_from_slice(b"\x7fELF");
    data[4] = 1;
    data[5] = 1;
    data[6] = 1;
    put16(&mut data, 16, 2);
    put16(&mut data, 18, 3);
    put32(&mut data, 20, 1);
    put32(&mut data, 24, 0x8048100);
    put32(&mut data, 28, 52);
    put16(&mut data, 40, 52);
    put16(&mut data, 42, 32);
    put16(&mut data, 44, 1);
    put32(&mut data, 52, PT_LOAD);
    put32(&mut data, 60, 0x8048000);
    put32(&mut data, 68, 0x200);
    put32(&mut data, 72, 0x200);
    put32(&mut data, 76, 5);
    put32(&mut data, 80, 0x1000);
    data[0x100..0x102].copy_from_slice(&[0xeb, 0xfe]);
    data
}

#[test]
fn inspects_elf64_segments_and_interpreter_without_sections() {
    let image = ElfImage::parse(&elf64(), "sample").unwrap();
    assert_eq!(image.sample.architecture, Architecture::X64);
    assert_eq!(image.sample.kind, Kind::Executable);
    assert_eq!(image.sample.interpreter.as_deref(), Some("/lib/ld.so"));
    assert_eq!(image.sample.load_segments, 1);
    assert!(image.sample.entry_in_executable_segment);
    assert_eq!(image.program_headers[0].memory_size, 8);
}

#[test]
fn inspects_elf32_dynamic_object_without_sections() {
    let image = ElfImage::parse(&elf32(), "library.so").unwrap();
    assert_eq!(image.sample.architecture, Architecture::X86);
    assert_eq!(image.sample.kind, Kind::Dynamic);
    assert!(image.sample.entry_in_executable_segment);
    assert_eq!(image.sample.interpreter, None);
}

#[test]
fn admits_only_bounded_static_x64_load_geometry() {
    let data = static_elf64();
    let plan = StaticLoadPlan::parse(&data).unwrap();
    assert_eq!(plan.entry, 0x400100);
    assert_eq!(plan.program_header_address, 0x400040);
    assert_eq!(plan.segments[0].page_start, 0x400000);
    assert_eq!(plan.segments[0].page_size, 4096);
    assert!(StaticLoadPlan::parse(&elf64()).is_err());
    assert!(StaticLoadPlan::parse(&elf32()).is_err());

    let mut bad = data.clone();
    put32(&mut bad, 68, 7);
    assert!(StaticLoadPlan::parse(&bad).is_err(), "writable executable");
    let mut bad = data.clone();
    put16(&mut bad, 56, 2);
    put32(&mut bad, 120, PT_LOAD);
    put32(&mut bad, 124, 4);
    put64(&mut bad, 128, 0x100);
    put64(&mut bad, 136, 0x400100);
    put64(&mut bad, 152, 4);
    put64(&mut bad, 160, 8);
    put64(&mut bad, 168, 0x1000);
    assert!(StaticLoadPlan::parse(&bad).is_err(), "overlapping map");
    let mut bad = elf64();
    put16(&mut bad, 56, 1);
    assert!(
        StaticLoadPlan::parse(&bad).is_err(),
        "unmapped program headers"
    );
}

#[test]
fn admits_bounded_pie_relative_relocations_and_rejects_unsafe_targets() {
    let data = pie_with_relative_relocation();
    let plan = PieLoadPlan::parse(&data).unwrap();
    assert_eq!(plan.image.entry, 0x1_0000_0100);
    assert_eq!(plan.image.program_header_address, 0x1_0000_0040);
    assert_eq!(plan.relocations.len(), 1);
    assert_eq!(plan.relocations[0].target, 0x1_0000_10a0);
    assert_eq!(plan.relocations[0].value, 0x1_0000_0150);
    let mut wrong_type = data.clone();
    put64(&mut wrong_type, 0x1088, 1);
    assert!(PieLoadPlan::parse(&wrong_type).is_err());
    let mut code_target = data.clone();
    put64(&mut code_target, 0x1080, 0x100);
    assert!(PieLoadPlan::parse(&code_target).is_err());
    let mut dependency = data;
    put64(&mut dependency, 0x1000, 1); // DT_NEEDED
    assert!(PieLoadPlan::parse(&dependency).is_err());
}

#[test]
fn admits_static_i386_with_mapped_headers_and_rejects_high_maps() {
    let data = static_i386();
    let plan = Static32LoadPlan::parse(&data).unwrap();
    assert_eq!(plan.image.entry, 0x8048100);
    assert_eq!(plan.image.program_header_address, 0x8048034);
    let mut high = data;
    put32(&mut high, 60, 0xbfff0000);
    put32(&mut high, 24, 0xbfff0100);
    assert!(Static32LoadPlan::parse(&high).is_err());
}

#[test]
fn rejects_malformed_headers_and_ranges() {
    for size in [0, 4, 16, 51, 63, 175] {
        assert!(
            ElfImage::parse(&elf64()[..size], "short").is_err(),
            "{size}"
        );
    }
    let mut bad = elf64();
    bad[5] = 2;
    assert!(ElfImage::parse(&bad, "big-endian").is_err());
    let mut bad = elf64();
    put16(&mut bad, 18, 3);
    assert!(ElfImage::parse(&bad, "wrong-machine").is_err());
    let mut bad = elf64();
    put16(&mut bad, 56, u16::MAX);
    assert!(ElfImage::parse(&bad, "extended-count").is_err());
    let mut bad = elf64();
    put64(&mut bad, 32, u64::MAX);
    assert!(ElfImage::parse(&bad, "table-overflow").is_err());
    let mut bad = elf64();
    put32(&mut bad, 120, 4);
    put64(&mut bad, 128, u64::MAX);
    assert!(ElfImage::parse(&bad, "note-out-of-file").is_err());
    let mut bad = elf64();
    put64(&mut bad, 96, 9);
    assert!(ElfImage::parse(&bad, "segment-out-of-file").is_err());
    let mut bad = elf64();
    put64(&mut bad, 104, 3);
    assert!(ElfImage::parse(&bad, "file-larger-than-memory").is_err());
    let mut bad = elf64();
    put64(&mut bad, 80, u64::MAX);
    assert!(ElfImage::parse(&bad, "address-overflow").is_err());
    let mut bad = elf64();
    put64(&mut bad, 112, 3);
    assert!(ElfImage::parse(&bad, "alignment").is_err());
    let mut bad = elf64();
    data_interpreter_with_no_terminator(&mut bad);
    assert!(ElfImage::parse(&bad, "interpreter").is_err());
    let mut bad = elf64();
    put16(&mut bad, 56, 3);
    put32(&mut bad, 176, PT_INTERP);
    put64(&mut bad, 184, 0x108);
    put64(&mut bad, 208, 11);
    assert!(ElfImage::parse(&bad, "duplicate-interpreter").is_err());
    let mut bad = elf64();
    put32(&mut bad, 120, PT_LOAD);
    assert!(ElfImage::parse(&bad, "second-load").is_err());
}

fn data_interpreter_with_no_terminator(data: &mut [u8]) {
    data[0x112] = b'x';
}
