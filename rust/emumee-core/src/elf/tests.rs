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
