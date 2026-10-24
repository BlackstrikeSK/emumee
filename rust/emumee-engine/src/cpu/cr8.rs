//! Correct the pinned backend's guest MOV CR8 v_tpr/cr[8] split. Register/API
//! accesses use cr[8], while its native instruction helper uses another field.
//! Execute the exact guest instruction semantics here; never rewrite guest code.
use super::*;
use anyhow::Context as _;
pub(super) fn observe(engine: &mut Unicorn<Trace>, pc: u64, size: u32) -> Result<bool> {
    if engine.get_data().architecture != Architecture::X64 {
        return Ok(false);
    }
    ensure!(
        (1..=15).contains(&size),
        "Invalid native control instruction size"
    );
    let mut bytes = [0u8; 15];
    uc(engine.mem_read(pc, &mut bytes[..size as usize]))?;
    let mut at = 0usize;
    while at < size as usize
        && (matches!(
            bytes[at],
            0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 | 0x66 | 0x67 | 0xf2 | 0xf3
        ) || (0x40..=0x4f).contains(&bytes[at]))
    {
        at += 1;
    }
    if at + 3 != size as usize || bytes[at] != 0x0f || !matches!(bytes[at + 1], 0x20 | 0x22) {
        return Ok(false);
    }
    let rex = if at > 0 && (0x40..=0x4f).contains(&bytes[at - 1]) {
        bytes[at - 1]
    } else {
        0
    };
    let control = ((bytes[at + 2] >> 3) & 7) | ((rex & 4) << 1);
    if control != 8 {
        return Ok(false);
    }
    let next = pc
        .checked_add(u64::from(size))
        .context("MOV CR8 instruction address overflow")?;
    ensure!(
        engine.get_data().apis.kernel_mode
            && engine.get_data().kernel_cpu.is_some()
            && uc(engine.reg_read(RegisterX86::CS))? & 3 == 0,
        "MOV CR8 requires an initialized CPL0 driver context"
    );
    let registers = [
        RegisterX86::RAX,
        RegisterX86::RCX,
        RegisterX86::RDX,
        RegisterX86::RBX,
        RegisterX86::RSP,
        RegisterX86::RBP,
        RegisterX86::RSI,
        RegisterX86::RDI,
        RegisterX86::R8,
        RegisterX86::R9,
        RegisterX86::R10,
        RegisterX86::R11,
        RegisterX86::R12,
        RegisterX86::R13,
        RegisterX86::R14,
        RegisterX86::R15,
    ];
    // For MOV CRx, x86 treats ModRM.mod as register form even if its bits differ.
    // REX.B extends the actual GPR operand, independently of REX.R selectingCR8.
    let register = registers[((bytes[at + 2] & 7) | ((rex & 1) << 3)) as usize];
    if bytes[at + 1] == 0x22 {
        let value = uc(engine.reg_read(register))?;
        ensure!(value <= 15, "MOV CR8 value has reserved bits set");
        let pcr = crate::kernel_cpu::current_pcr(engine)?;
        ensure!(
            engine
                .get_data()
                .apis
                .memory
                .allows(pcr + 0x50, 1, Permissions::WRITE),
            "MOV CR8 owned PCR IRQL backing is unavailable"
        );
        let critical = engine.get_data().apis.kernel.save().1;
        crate::cpu::write(engine, pcr + 0x50, &[value as u8])?;
        uc(engine.reg_write(RegisterX86::CR8, value))?;
        engine
            .get_data_mut()
            .apis
            .kernel
            .restore((value as u8, critical));
        engine.get_data_mut().cpu.report.cr8_writes += 1;
    } else {
        let value = uc(engine.reg_read(RegisterX86::CR8))?;
        ensure!(value <= 15, "Owned CR8 contains reserved bits");
        uc(engine.reg_write(register, value))?;
        engine.get_data_mut().cpu.report.cr8_reads += 1;
    }
    uc(engine.reg_write(RegisterX86::RIP, next))?;
    Ok(true)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn actual_cpl3_selector_refuses_the_decoded_move_before_register_pcr_or_api_mutation() {
        let mut engine = crate::new_engine(Architecture::X64).unwrap();
        engine.get_data_mut().apis.kernel_mode = true;
        crate::kernel_cpu::initialize(&mut engine).unwrap();
        uc(engine.mem_map(0x1000, 4096, Prot::ALL)).unwrap();
        engine
            .get_data_mut()
            .apis
            .memory
            .map(
                0x1000,
                4096,
                Permissions::ALL,
                None,
                "owned CPL3 CR8 preflight probe",
            )
            .unwrap();
        crate::cpu::write(&mut engine, 0x1000, &[0x44, 0x0f, 0x22, 0xc0]).unwrap();
        let layout = emumee_core::kernel_layout::KernelLayout::for_architecture(Architecture::X64);
        crate::cpu::write(
            &mut engine,
            layout.descriptor_tables + 0x20,
            &0x00affa000000ffffu64.to_le_bytes(),
        )
        .unwrap();
        uc(engine.reg_write(RegisterX86::CS, 0x23)).unwrap();
        assert_eq!(uc(engine.reg_read(RegisterX86::CS)).unwrap() & 3, 3);
        uc(engine.reg_write(RegisterX86::RAX, 13)).unwrap();
        uc(engine.reg_write(RegisterX86::RIP, 0x1000)).unwrap();
        assert!(
            observe(&mut engine, 0x1000, 4)
                .unwrap_err()
                .to_string()
                .contains("initialized CPL0 driver")
        );
        assert_eq!(uc(engine.reg_read(RegisterX86::RIP)).unwrap(), 0x1000);
        assert_eq!(uc(engine.reg_read(RegisterX86::RAX)).unwrap(), 13);
        assert_eq!(uc(engine.reg_read(RegisterX86::CR8)).unwrap(), 0);
        assert_eq!(engine.get_data().apis.kernel.save().0, 0);
        assert_eq!(engine.get_data().cpu.report.cr8_writes, 0);
        assert_eq!(
            uc(engine.mem_read_as_vec(layout.pcr + 0x50, 1)).unwrap(),
            [0]
        );
    }
}
