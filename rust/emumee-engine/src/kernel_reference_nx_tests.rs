//! Generated-only proof of a read-only, non-executable reference page.
//! This module is test-only and is not wired into general driver admission.
use unicorn_engine::{
    RegisterX86, Unicorn,
    unicorn_const::{Arch, Mode, Prot},
};

#[test]
fn generated_reference_page_allows_guest_reads_but_denies_guest_writes_and_fetches() {
    const REFERENCE: u64 = 0x10000;
    const PROBE: u64 = 0x20000;
    const RELOCATED_POINTER: u64 = 0x1_8000_1234;
    let mut engine = Unicorn::new(Arch::X86, Mode::MODE_64).unwrap();
    engine
        .mem_map(REFERENCE, 4096, Prot::READ | Prot::WRITE)
        .unwrap();
    let mut generated = vec![0x90; 512];
    generated[0x100..0x108].copy_from_slice(&RELOCATED_POINTER.to_le_bytes());
    engine.mem_write(REFERENCE, &generated).unwrap();
    engine.mem_protect(REFERENCE, 4096, Prot::READ).unwrap();
    engine
        .mem_map(PROBE, 4096, Prot::READ | Prot::WRITE)
        .unwrap();
    let region = engine
        .mem_regions()
        .unwrap()
        .into_iter()
        .find(|r| r.begin == REFERENCE)
        .unwrap();
    assert_eq!(region.perms, Prot::READ.0 as u32);

    // mov rax, qword ptr [REFERENCE + 0x100] executes only on the probe page.
    let mut read = vec![0x48, 0xa1];
    read.extend((REFERENCE + 0x100).to_le_bytes());
    engine.mem_write(PROBE, &read).unwrap();
    engine
        .mem_protect(PROBE, 4096, Prot::READ | Prot::EXEC)
        .unwrap();
    engine
        .emu_start(PROBE, PROBE + read.len() as u64, 0, 1)
        .unwrap();
    assert_eq!(
        engine.reg_read(RegisterX86::RAX).unwrap(),
        RELOCATED_POINTER
    );

    // mov qword ptr [REFERENCE + 0x100], rax must fault on the read-only page.
    engine
        .mem_protect(PROBE, 4096, Prot::READ | Prot::WRITE)
        .unwrap();
    let mut write = vec![0x48, 0xa3];
    write.extend((REFERENCE + 0x100).to_le_bytes());
    engine.mem_write(PROBE, &write).unwrap();
    engine
        .mem_protect(PROBE, 4096, Prot::READ | Prot::EXEC)
        .unwrap();
    assert!(
        engine
            .emu_start(PROBE, PROBE + write.len() as u64, 0, 1)
            .is_err()
    );
    assert_eq!(
        engine.mem_read_as_vec(REFERENCE + 0x100, 8).unwrap(),
        RELOCATED_POINTER.to_le_bytes()
    );

    // Even harmless generated NOP bytes in the reference page cannot be fetched.
    assert!(engine.emu_start(REFERENCE, REFERENCE + 1, 0, 1).is_err());
}
