//! Guest kernel boot context with virtual TLB mappings, not host kernel access.
use super::*;
use unicorn_engine::{TlbType, uc_reg_read, uc_reg_write, uc_x86_mmr, uc_x86_msr};
pub(crate) mod ipi_processors;
const EFER: u32 = 0xc0000080;
#[derive(Clone, Debug, Serialize)]
pub struct Registers {
    pub cr0: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub cs: u64,
    pub ss: u64,
    pub flags: u64,
    pub efer: u64,
    pub star: u64,
    pub fmask: u64,
}
#[derive(Debug, Serialize)]
pub struct KernelCpuReport {
    pub initial: Registers,
    pub current: Registers,
    pub pcr: u64,
    pub prcb: u64,
    pub gdt: u64,
    pub idt: u64,
    pub current_thread: u64,
    pub pcr_current_thread: u64,
    pub pcr_irql: u8,
    pub system_entry_attempts: u64,
    pub system_entry_tail: Vec<SystemEntry>,
    pub tracked_msr_write_observations: u64,
    pub msr_context_repairs: u64,
    pub tracked_msrs: Vec<MsrValue>,
    pub scope: &'static str,
}
pub(crate) struct KernelCpu {
    initial: Registers,
    pcr: u64,
    tables: u64,
    attempts: u64,
    entries: std::collections::VecDeque<SystemEntry>,
    pending_msr: Option<u32>,
    msr_version: u64,
    msr_repairs: u64,
    msrs: std::collections::BTreeMap<u32, u64>,
    processors: ipi_processors::State,
}
pub(crate) fn current_pcr(engine: &Unicorn<Trace>) -> Result<u64> {
    engine
        .get_data()
        .kernel_cpu
        .as_ref()
        .map(|context| context.pcr)
        .ok_or_else(|| anyhow!("Kernel processor context is not initialized"))
}
#[derive(Clone, Debug, Serialize)]
pub struct MsrValue {
    pub index: u32,
    pub value: u64,
}
#[derive(Clone, Debug, Serialize)]
pub struct SystemEntry {
    pub instruction: &'static str,
    pub pc: u64,
    pub target: Option<u64>,
    pub accepted: bool,
    pub error: Option<String>,
}
fn status(result: uc_error) -> Result<()> {
    ensure!(
        result == uc_error::OK,
        "Unicorn kernel register operation: {result:?}"
    );
    Ok(())
}
fn write_msr(engine: &Unicorn<Trace>, rid: u32, value: u64) -> Result<()> {
    let register = uc_x86_msr { rid, value };
    // SAFETY: the pinned header defines UC_X86_REG_MSR as uc_x86_msr. The
    // generated repr(C) struct has the exact size/alignment and lives for the call.
    status(unsafe {
        uc_reg_write(
            engine.get_handle(),
            RegisterX86::MSR as i32,
            (&raw const register).cast(),
        )
    })
}
fn read_msr(engine: &Unicorn<Trace>, rid: u32) -> Result<u64> {
    let mut register = uc_x86_msr { rid, value: 0 };
    // SAFETY: rid is the required input field; Unicorn writes only this live,
    // correctly aligned uc_x86_msr. It is not a scalar register buffer.
    status(unsafe {
        uc_reg_read(
            engine.get_handle(),
            RegisterX86::MSR as i32,
            (&raw mut register).cast(),
        )
    })?;
    Ok(register.value)
}
fn table(engine: &mut Unicorn<Trace>, register: RegisterX86, base: u64, limit: u32) -> Result<()> {
    let value = uc_x86_mmr {
        selector: 0,
        base,
        limit,
        flags: 0,
    };
    // SAFETY: GDTR/IDTR require the full generated uc_x86_mmr, including padding.
    // Neither scalar reg_write nor the binding's10-byte reg_read_long is used.
    status(unsafe {
        uc_reg_write(
            engine.get_handle(),
            register as i32,
            (&raw const value).cast(),
        )
    })
}
fn registers(engine: &Unicorn<Trace>) -> Result<Registers> {
    Ok(Registers {
        cr0: uc(engine.reg_read(RegisterX86::CR0))?,
        cr3: uc(engine.reg_read(RegisterX86::CR3))?,
        cr4: uc(engine.reg_read(RegisterX86::CR4))?,
        cs: uc(engine.reg_read(RegisterX86::CS))?,
        ss: uc(engine.reg_read(RegisterX86::SS))?,
        flags: uc(engine.reg_read(RegisterX86::EFLAGS))?,
        efer: read_msr(engine, EFER)?,
        star: read_msr(engine, 0xc0000081)?,
        fmask: read_msr(engine, 0xc0000084)?,
    })
}
fn map(engine: &mut Unicorn<Trace>, base: u64, size: u64, tag: &'static str) -> Result<()> {
    uc(engine.mem_map(base, size, Prot::READ | Prot::WRITE))?;
    engine
        .get_data_mut()
        .apis
        .memory
        .map(base, size, Permissions::RW, Some(4), tag)?;
    engine
        .get_data_mut()
        .cpu
        .cache
        .invalidate(base, size as usize);
    Ok(())
}
fn pointer(engine: &mut Unicorn<Trace>, address: u64, value: u64) -> Result<()> {
    let width = engine.get_data().architecture.width();
    cpu::write(engine, address, &value.to_le_bytes()[..width])
}
pub(crate) fn initialize(engine: &mut Unicorn<Trace>) -> Result<()> {
    if !engine.get_data().apis.kernel_mode {
        return Ok(());
    }
    let wide = engine.get_data().architecture == Architecture::X64;
    let layout =
        emumee_core::kernel_layout::KernelLayout::for_architecture(engine.get_data().architecture);
    let pcr = layout.pcr;
    let tables = layout.descriptor_tables;
    uc(engine.ctl_set_tlb_type(TlbType::VIRTUAL))?;
    map(
        engine,
        tables,
        4 * 4096,
        "kernel descriptor/TSS/lock storage",
    )?;
    map(engine, pcr, 4096, "kernel processor context")?;
    let (code_selector, data_selector, code_descriptor) = if wide {
        (0x10, 0x18, 0x00af9a000000ffffu64)
    } else {
        (0x08, 0x10, 0x00cf9a000000ffffu64)
    };
    cpu::write(
        engine,
        tables + code_selector,
        &code_descriptor.to_le_bytes(),
    )?;
    cpu::write(
        engine,
        tables + data_selector,
        &0x00cf92000000ffffu64.to_le_bytes(),
    )?;
    if !wide {
        // 32-bit FS descriptor: byte-granular4KiB KPCR, present ring0 data.
        let descriptor = 0xfffu64
            | ((pcr & 0xffff) << 16)
            | (((pcr >> 16) & 255) << 32)
            | (0x92 << 40)
            | (0x4 << 52)
            | (((pcr >> 24) & 255) << 56);
        cpu::write(engine, tables + 0x30, &descriptor.to_le_bytes())?;
    }
    table(engine, RegisterX86::GDTR, tables, 0x3f)?;
    table(engine, RegisterX86::IDTR, tables + 4096, 4095)?;
    uc(engine.reg_write(RegisterX86::CS, code_selector))?;
    for register in [RegisterX86::SS, RegisterX86::DS, RegisterX86::ES] {
        uc(engine.reg_write(register, data_selector))?;
    }
    if wide {
        uc(engine.reg_write(RegisterX86::GS_BASE, pcr))?;
    } else {
        uc(engine.reg_write(RegisterX86::FS, 0x30))?;
    }
    let prcb = pcr + if wide { 0x180 } else { 0x120 };
    if wide {
        // The x64 trap entries load the kernel handler MXCSR from GS:180.
        cpu::write(engine,prcb,&0x1f80u32.to_le_bytes())?;
        let lock_storage = engine
            .get_data()
            .kernel_lock_storage
            .unwrap_or(tables + 12288);
        for (offset, value) in [
            (0, tables),
            (8, tables + 8192),
            (0x18, pcr),
            (0x20, prcb),
            (0x38, tables + 4096),
        ] {
            pointer(engine, pcr + offset, value)?;
        }
        cpu::write(engine, pcr + 0x60, &[1, 0, 1, 0])?;
        let queues = prcb + 0x6f0;
        pointer(engine, pcr + 0x28, queues)?;
        for index in 0..17 {
            pointer(engine, queues + index * 16 + 8, lock_storage + index * 8)?;
        }
    } else {
        for (offset, value) in [
            (0x1c, pcr),
            (0x20, prcb),
            (0x38, tables + 4096),
            (0x3c, tables),
            (0x14, 1),
            (0x48, 1),
        ] {
            pointer(engine, pcr + offset, value)?;
        }
    }

    let cr4 = uc(engine.reg_read(RegisterX86::CR4))?;
    uc(engine.reg_write(RegisterX86::CR4, cr4 | 0x20))?;
    uc(engine.reg_write(RegisterX86::CR0, 0x80050033))?;
    let efer = read_msr(engine, EFER)? | 0x800 | if wide { 1 } else { 0 };
    write_msr(engine, EFER, efer)?;
    if wide {
        write_msr(engine, 0xc0000081, (0x23u64 << 48) | (0x10u64 << 32))?;
        write_msr(engine, 0xc0000084, 0x4700)?;
    }
    uc(engine.reg_write(RegisterX86::EFLAGS, 0x202))?;
    let initial = registers(engine)?;
    engine.get_data_mut().kernel_cpu = Some(KernelCpu {
        initial,
        pcr,
        tables,
        attempts: 0,
        entries: std::collections::VecDeque::new(),
        pending_msr: None,
        msr_version: 0,
        msr_repairs: 0,
        msrs: std::collections::BTreeMap::new(),
        processors: ipi_processors::State::default(),
    });
    sync(engine, threads::thread_address(engine))?;
    ipi_processors::capture_boot_seed(engine)
}
pub(crate) fn sync(engine: &mut Unicorn<Trace>, thread: u64) -> Result<()> {
    let Some(context) = engine.get_data().kernel_cpu.as_ref() else {
        return Ok(());
    };
    let pcr = context.pcr;
    let wide = engine.get_data().architecture == Architecture::X64;
    let irql = engine.get_data().apis.kernel.save().0;
    pointer(engine, pcr + if wide { 0x188 } else { 0x124 }, thread)?;
    cpu::write(engine, pcr + if wide { 0x50 } else { 0x24 }, &[irql])?;
    if wide {
        uc(engine.reg_write(RegisterX86::CR8, irql as u64))?;
    }
    Ok(())
}
pub(crate) fn report(engine: &Unicorn<Trace>) -> Result<Option<KernelCpuReport>> {
    let Some(context) = &engine.get_data().kernel_cpu else {
        return Ok(None);
    };
    let wide = engine.get_data().architecture == Architecture::X64;
    let mut thread = [0; 8];
    uc(engine.mem_read(
        context.pcr + if wide { 0x188 } else { 0x124 },
        &mut thread[..if wide { 8 } else { 4 }],
    ))?;
    let mut irql = [0];
    uc(engine.mem_read(context.pcr + if wide { 0x50 } else { 0x24 }, &mut irql))?;
    Ok(Some(KernelCpuReport {
        initial: context.initial.clone(),
        current: registers(engine)?,
        pcr: context.pcr,
        prcb: context.pcr
            + if engine.get_data().architecture == Architecture::X64 {
                0x180
            } else {
                0x120
            },
        gdt: context.tables,
        idt: context.tables + 4096,
        current_thread: threads::thread_address(engine),
        pcr_current_thread: u64::from_le_bytes(thread),
        pcr_irql: irql[0],
        system_entry_attempts: context.attempts,
        system_entry_tail: context.entries.iter().cloned().collect(),
        tracked_msr_write_observations: context.msr_version,
        msr_context_repairs: context.msr_repairs,
        tracked_msrs: context
            .msrs
            .iter()
            .map(|(&index, &value)| MsrValue { index, value })
            .collect(),
        scope: "Virtual-TLB CPL0 segments, KPCR/PRCB pointers, mirrored API IRQL and descriptor backing. Opaque thread identities; full ETHREAD/process/TSS/IDT delivery, physical paging and system-entry parity remain pending.",
    }))
}
/// The pinned backend includes these processor registers in its CPU-context
/// memcpy. Keep guest writes shared across our modeled threads on one processor.
/// TSC and other unmodeled MSR families are outside this initial tracked set.
pub(crate) fn before_msr_write(engine: &mut Unicorn<Trace>) -> Result<()> {
    let index = uc(engine.reg_read(RegisterX86::ECX))? as u32;
    if matches!(index,0x174..=0x176|0xc0000080..=0xc0000084|0xc0000100..=0xc0000103) {
        if let Some(context) = engine.get_data_mut().kernel_cpu.as_mut() {
            context.pending_msr = Some(index);
        }
    }
    Ok(())
}
#[inline]
pub(crate) fn has_pending_msr(engine: &Unicorn<Trace>) -> bool {
    engine
        .get_data()
        .kernel_cpu
        .as_ref()
        .is_some_and(|context| context.pending_msr.is_some())
}
pub(crate) fn complete_msr_write(engine: &mut Unicorn<Trace>) -> Result<()> {
    let index = engine
        .get_data_mut()
        .kernel_cpu
        .as_mut()
        .and_then(|context| context.pending_msr.take());
    if let Some(index) = index {
        // Observe only after the guest instruction actually executed. If it
        // faults, no later instruction/scheduler transition commits the write.
        let value = read_msr(engine, index)?;
        let context = engine.get_data_mut().kernel_cpu.as_mut().unwrap();
        context.msrs.insert(index, value);
        context.msr_version += 1;
    }
    Ok(())
}
pub(crate) fn msr_version(engine: &Unicorn<Trace>) -> u64 {
    engine
        .get_data()
        .kernel_cpu
        .as_ref()
        .map_or(0, |context| context.msr_version)
}
pub(crate) fn restore_msrs(engine: &mut Unicorn<Trace>, version: u64) -> Result<()> {
    if let Some(context) = engine.get_data().kernel_cpu.as_ref() {
        if version == context.msr_version {
            return Ok(());
        }
        for (&index, &value) in &context.msrs {
            write_msr(engine, index, value)?;
        }
    } else {
        return Ok(());
    }
    engine
        .get_data_mut()
        .kernel_cpu
        .as_mut()
        .unwrap()
        .msr_repairs += 1;
    Ok(())
}
pub(crate) fn tsc_aux(engine: &Unicorn<Trace>) -> Result<u64> {
    Ok(read_msr(engine, 0xc0000103)? as u32 as u64)
}
pub(crate) fn system_entry(
    engine: &mut Unicorn<Trace>,
    pc: u64,
    size: u32,
    name: &'static str,
) -> Result<()> {
    let mut target = None;
    let result = (|| -> Result<()> {
        ensure!(
            engine.get_data().apis.kernel_mode && engine.get_data().kernel_cpu.is_some(),
            "System-entry dispatch requires a modeled native kernel context"
        );
        ensure!(
            name == "SYSCALL" && engine.get_data().architecture == Architecture::X64,
            "Unmodeled {name} architectural entry/return delivery"
        );
        ensure!(
            read_msr(engine, EFER)? & 0x401 == 0x401,
            "SYSCALL requires EFER.SCE/LMA"
        );
        let address = read_msr(engine, 0xc0000082)?;
        target = Some(address);
        let selector = (read_msr(engine, 0xc0000081)? >> 32) & 0xfffc;
        ensure!(
            selector == 0x10 && uc(engine.reg_read(RegisterX86::CS))? == 0x10,
            "SYSCALL requires the modeled kernel selector pair"
        );
        ensure!(
            !(0x0000_8000_0000_0000..0xffff_8000_0000_0000).contains(&address),
            "SYSCALL has a noncanonical LSTAR target"
        );
        ensure!(
            !(engine.get_data().apis.base..engine.get_data().apis.end).contains(&address),
            "Windows syscall dispatch through modeled API gates is not implemented"
        );
        ensure!(
            engine
                .get_data()
                .apis
                .memory
                .allows(address, 1, Permissions::EXECUTE),
            "SYSCALL LSTAR is not executable guest code"
        );
        let flags = uc(engine.reg_read(RegisterX86::EFLAGS))?;
        let mask = read_msr(engine, 0xc0000084)?;
        uc(engine.reg_write(RegisterX86::RCX, pc + size as u64))?;
        uc(engine.reg_write(RegisterX86::R11, flags & !0x10000))?;
        uc(engine.reg_write(RegisterX86::EFLAGS, flags & !(mask | 0x10000)))?;
        uc(engine.reg_write(RegisterX86::CS, selector))?;
        uc(engine.reg_write(RegisterX86::SS, selector + 8))?;
        uc(engine.reg_write(RegisterX86::RIP, address))?;
        Ok(())
    })();
    if let Some(context) = engine.get_data_mut().kernel_cpu.as_mut() {
        context.attempts += 1;
        if context.entries.len() == 128 {
            context.entries.pop_front();
        }
        context.entries.push_back(SystemEntry {
            instruction: name,
            pc,
            target,
            accepted: result.is_ok(),
            error: result.as_ref().err().map(|error| format!("{error:#}")),
        });
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn descriptor_registers_use_native_struct_sizes_and_full_width_bases() {
        for architecture in [Architecture::X86, Architecture::X64] {
            let mut engine = crate::new_engine(architecture).unwrap();
            engine.get_data_mut().apis.kernel_mode = true;
            initialize(&mut engine).unwrap();
            let tables = emumee_core::kernel_layout::KernelLayout::for_architecture(architecture)
                .descriptor_tables;
            for (register, base, limit) in [
                (RegisterX86::GDTR, tables, 0x3f),
                (RegisterX86::IDTR, tables + 4096, 4095),
            ] {
                let mut value = uc_x86_mmr {
                    selector: 0,
                    base: 0,
                    limit: 0,
                    flags: 0,
                };
                // SAFETY: full-size generated descriptor register buffer, with
                // proper native alignment and lifetime, matching the pinned ABI.
                status(unsafe {
                    uc_reg_read(
                        engine.get_handle(),
                        register as i32,
                        (&raw mut value).cast(),
                    )
                })
                .unwrap();
                assert_eq!((value.base, value.limit), (base, limit));
            }
            let result = report(&engine).unwrap().unwrap();
            assert_eq!(result.current.efer & 0x800, 0x800);
            assert_eq!(result.current.cr4 & 0x20, 0x20);
        }
    }
}
