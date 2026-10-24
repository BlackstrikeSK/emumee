//! Guest-only processor environments and architectural ownership. Native Context
//! snapshots never replace authoritative perCPU committed MSRs/TSC adjustments.
use super::*;
use anyhow::Context as _;
use emumee_core::ipi::{ProcessorLayout, STACK_SIZE, processor_layout};
use std::collections::BTreeMap;
const KNOWN_MSRS: [u32; 12] = [
    0x174, 0x175, 0x176, 0xc0000080, 0xc0000081, 0xc0000082, 0xc0000083, 0xc0000084, 0xc0000100,
    0xc0000101, 0xc0000102, 0xc0000103,
];
pub(crate) fn owns_msr(index: u32) -> bool {
    KNOWN_MSRS.contains(&index) || matches!(index, 0x10 | 0x3b)
}
fn descriptor(engine: &Unicorn<Trace>, register: RegisterX86) -> Result<uc_x86_mmr> {
    let mut value = uc_x86_mmr {
        selector: 0,
        base: 0,
        limit: 0,
        flags: 0,
    };
    // SAFETY: the pinned Unicorn ABI defines GDTR/IDTR read buffers as the full
    // generated repr(C) uc_x86_mmr, with valid size/alignment for this live value.
    status(unsafe {
        uc_reg_read(
            engine.get_handle(),
            register as i32,
            (&raw mut value).cast(),
        )
    })?;
    Ok(value)
}
pub(crate) fn validate_profile(engine: &Unicorn<Trace>, thread: u64, level: u8) -> Result<()> {
    validate_member_return(engine, thread, level)?;
    let context = engine
        .get_data()
        .kernel_cpu
        .as_ref()
        .context("IPI profile lacks initialized kernel state")?;
    ensure!(
        uc(engine.reg_read(RegisterX86::CR0))? == context.initial.cr0
            && uc(engine.reg_read(RegisterX86::CR3))? == context.initial.cr3
            && uc(engine.reg_read(RegisterX86::CR4))? == context.initial.cr4,
        "IPI non-MSR control-register mutation is outside the initialized processor profile"
    );
    let gdt = descriptor(engine, RegisterX86::GDTR)?;
    let idt = descriptor(engine, RegisterX86::IDTR)?;
    ensure!(
        gdt.base == context.tables
            && gdt.limit == 0x3f
            && idt.base == context.tables + 4096
            && idt.limit == 4095,
        "IPI descriptor-table relocation is outside the owned processor profile"
    );
    let wide = engine.get_data().architecture == Architecture::X64;
    let code = if wide {
        0x00af9a000000ffffu64
    } else {
        0x00cf9a000000ffff
    };
    let code_slot = context.tables + if wide { 0x10 } else { 8 };
    let data_slot = context.tables + if wide { 0x18 } else { 0x10 };
    // Segment access sets the architectural accessed bit. Both exact forms are
    // owned, equivalent initialized descriptors; arbitrary changes are refused.
    for (slot, expected) in [(code_slot, code), (data_slot, 0x00cf92000000ffffu64)] {
        let value = u64::from_le_bytes(uc(engine.mem_read_as_vec(slot, 8))?.try_into().unwrap());
        ensure!(
            value & !(1u64 << 40) == expected,
            "IPI source segment descriptors differ from initialized ownership"
        );
    }
    if !wide {
        let pcr = context.pcr;
        let expected = 0xfffu64
            | ((pcr & 0xffff) << 16)
            | (((pcr >> 16) & 255) << 32)
            | (0x92 << 40)
            | (0x4 << 52)
            | (((pcr >> 24) & 255) << 56);
        let value = u64::from_le_bytes(
            uc(engine.mem_read_as_vec(context.tables + 0x30, 8))?
                .try_into()
                .unwrap(),
        );
        ensure!(
            value & !(1u64 << 40) == expected,
            "IPI owned FS descriptor was mutated"
        );
    }
    Ok(())
}
#[derive(Clone, Debug, Serialize)]
pub struct Processor {
    pub layout: ProcessorLayout,
    pub prepared: bool,
    pub msrs: BTreeMap<u32, u64>,
    pub msr_version: u64,
    pub tsc_offset: u64,
    pub tsc_adjust: u64,
}
#[derive(Default)]
pub(crate) struct State {
    seed: BTreeMap<u32, u64>,
    pub processors: BTreeMap<u32, Processor>,
    pub native_effect_failure: bool,
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub current_processor: u32,
    pub processors: Vec<Processor>,
    pub native_effect_failure: bool,
}
pub(crate) fn capture_boot_seed(engine: &mut Unicorn<Trace>) -> Result<()> {
    let architecture = engine.get_data().architecture;
    let mut seed = BTreeMap::new();
    for index in KNOWN_MSRS {
        seed.insert(index, read_msr(engine, index)?);
    }
    if architecture == Architecture::X86 {
        seed.insert(0xc0000100, processor_layout(architecture, 0).unwrap().pcr);
    }
    let context = engine
        .get_data_mut()
        .kernel_cpu
        .as_mut()
        .context("IPI processor seed lacks initialized kernel context")?;
    ensure!(
        context.processors.processors.is_empty(),
        "Processor boot seed already captured"
    );
    context.processors.seed = seed.clone();
    context.processors.processors.insert(
        0,
        Processor {
            layout: processor_layout(architecture, 0).unwrap(),
            prepared: false,
            msrs: seed,
            msr_version: 0,
            tsc_offset: 0,
            tsc_adjust: 0,
        },
    );
    Ok(())
}
fn require_ready(engine: &Unicorn<Trace>) -> Result<()> {
    let context = engine
        .get_data()
        .kernel_cpu
        .as_ref()
        .context("IPI processor operation lacks kernel context")?;
    ensure!(
        !context.processors.native_effect_failure,
        "IPI processor native effect failed; execution cannot resume"
    );
    ensure!(
        !context.processors.seed.is_empty(),
        "IPI processor boot state unavailable"
    );
    Ok(())
}
/// Prepare all bounded ranges in a cloned address model before the first native
/// effect. New parked Thread bodies are registered only after their owned page
/// exists; failure never becomes a completed broadcast or resumed caller.
pub(crate) fn prepare(engine: &mut Unicorn<Trace>, logical: u32) -> Result<()> {
    require_ready(engine)?;
    let architecture = engine.get_data().architecture;
    ensure!(
        logical > 0 && logical <= architecture.width() as u32 * 8,
        "IPI processor resources require one bounded group"
    );
    let layouts = (0..logical)
        .map(|processor| processor_layout(architecture, processor).unwrap())
        .filter(|layout| {
            !engine
                .get_data()
                .kernel_cpu
                .as_ref()
                .unwrap()
                .processors
                .processors
                .get(&layout.processor)
                .is_some_and(|row| row.prepared)
        })
        .collect::<Vec<_>>();
    let mut planned = engine.get_data().apis.memory.clone();
    for layout in &layouts {
        planned
            .map(
                layout.stack,
                STACK_SIZE,
                Permissions::RW,
                Some(4),
                "IPI processor callback stack",
            )
            .with_context(|| {
                format!(
                    "IPI processor{} stack preflight at0x{:x} size0x{:x}",
                    layout.processor, layout.stack, STACK_SIZE
                )
            })?;
        if layout.processor != 0 {
            planned
                .map(
                    layout.pcr,
                    4096,
                    Permissions::RW,
                    Some(4),
                    "IPI processor KPCR",
                )
                .with_context(|| {
                    format!(
                        "IPI processor{} PCR preflight at0x{:x} size0x{:x}",
                        layout.processor, layout.pcr, 4096
                    )
                })?;
            planned
                .map(
                    layout.parked_thread.unwrap(),
                    4096,
                    Permissions::RW,
                    Some(4),
                    "borrowed parked processor thread",
                )
                .with_context(|| {
                    format!(
                        "IPI processor{} parked Thread preflight at0x{:x} size0x{:x}",
                        layout.processor,
                        layout.parked_thread.unwrap(),
                        4096
                    )
                })?;
        } else {
            ensure!(
                planned.allows(layout.pcr, 4096, Permissions::RW),
                "Source processor KPCR backing is unavailable"
            );
        }
    }
    let seed = engine
        .get_data()
        .kernel_cpu
        .as_ref()
        .unwrap()
        .processors
        .seed
        .clone();
    let root_pcr = processor_layout(architecture, 0).unwrap().pcr;
    let pcr_bytes = uc(engine.mem_read_as_vec(root_pcr, 4096))?;
    engine
        .get_data_mut()
        .kernel_cpu
        .as_mut()
        .unwrap()
        .processors
        .native_effect_failure = true;
    for layout in layouts {
        map(
            engine,
            layout.stack,
            STACK_SIZE,
            "IPI processor callback stack",
        )?;
        if layout.processor != 0 {
            map(engine, layout.pcr, 4096, "IPI processor KPCR")?;
            map(
                engine,
                layout.parked_thread.unwrap(),
                4096,
                "borrowed parked processor thread",
            )?;
            crate::api::kernel_thread_objects::register_parked_processor(engine, layout.processor)?;
            cpu::write(engine, layout.pcr, &pcr_bytes)?;
            let wide = architecture == Architecture::X64;
            let prcb = layout.pcr + if wide { 0x180 } else { 0x120 };
            if wide {
                for (offset, value) in [(0x18, layout.pcr), (0x20, prcb), (0x28, prcb + 0x6f0)] {
                    pointer(engine, layout.pcr + offset, value)?;
                }
                cpu::write(engine, layout.pcr + 0x1a4, &layout.processor.to_le_bytes())?;
                cpu::write(engine, layout.pcr + 0x184, &[layout.processor as u8])?;
            } else {
                for (offset, value) in [(0x1c, layout.pcr), (0x20, prcb)] {
                    pointer(engine, layout.pcr + offset, value)?;
                }
                cpu::write(engine, layout.pcr + 0x51, &[layout.processor as u8])?;
                for offset in [0x14, 0x48] {
                    cpu::write(
                        engine,
                        layout.pcr + offset,
                        &(1u32 << layout.processor).to_le_bytes(),
                    )?;
                }
            }
            pointer(
                engine,
                layout.pcr + if wide { 0x188 } else { 0x124 },
                layout.parked_thread.unwrap(),
            )?;
            cpu::write(engine, layout.pcr + if wide { 0x50 } else { 0x24 }, &[0])?;
        }
        let mut msrs = seed.clone();
        msrs.insert(0xc0000103, layout.processor as u64);
        if architecture == Architecture::X64 {
            msrs.insert(0xc0000101, layout.pcr);
        } else {
            msrs.insert(0xc0000100, layout.pcr);
        }
        let existing = engine
            .get_data()
            .kernel_cpu
            .as_ref()
            .unwrap()
            .processors
            .processors
            .get(&layout.processor)
            .cloned();
        let mut row = existing.unwrap_or(Processor {
            layout,
            prepared: false,
            msrs,
            msr_version: 0,
            tsc_offset: 0,
            tsc_adjust: 0,
        });
        row.prepared = true;
        engine
            .get_data_mut()
            .kernel_cpu
            .as_mut()
            .unwrap()
            .processors
            .processors
            .insert(layout.processor, row);
    }
    engine
        .get_data_mut()
        .kernel_cpu
        .as_mut()
        .unwrap()
        .processors
        .native_effect_failure = false;
    Ok(())
}
fn stash(engine: &mut Unicorn<Trace>) -> Result<()> {
    ensure!(
        !has_pending_msr(engine),
        "Processor switch has an uncommitted guest MSR instruction"
    );
    let processor = engine.get_data().cpu.processor;
    let offset = engine.get_data().cpu.tsc_offset;
    let adjust = engine.get_data().cpu.tsc_adjust;
    let context = engine
        .get_data_mut()
        .kernel_cpu
        .as_mut()
        .context("Processor switch lacks kernel context")?;
    let row = context
        .processors
        .processors
        .get_mut(&processor)
        .context("Current logical processor has no owned architectural state")?;
    for (&index, &value) in &context.msrs {
        row.msrs.insert(index, value);
    }
    row.msr_version = context.msr_version;
    row.tsc_offset = offset;
    row.tsc_adjust = adjust;
    Ok(())
}
/// Call after restoring the selected native CPU Context. Model authority still
/// identifies the prior CPU, so stash() cannot import restored foreign MSRs.
pub(crate) fn activate(engine: &mut Unicorn<Trace>, processor: u32, thread: u64) -> Result<()> {
    require_ready(engine)?;
    stash(engine)?;
    let row = engine
        .get_data()
        .kernel_cpu
        .as_ref()
        .unwrap()
        .processors
        .processors
        .get(&processor)
        .cloned()
        .context("Selected IPI processor has no prepared architectural domain")?;
    ensure!(
        row.prepared,
        "Selected IPI processor resources were not prepared"
    );
    crate::api::kernel_thread_objects::validate_owned_thread(engine, thread)?;
    if processor != 0 {
        ensure!(
            row.layout.parked_thread == Some(thread),
            "Remote IPI processor does not own its parked System identity"
        );
    }
    engine
        .get_data_mut()
        .kernel_cpu
        .as_mut()
        .unwrap()
        .processors
        .native_effect_failure = true;
    for (&index, &value) in &row.msrs {
        write_msr(engine, index, value)?;
    }
    if engine.get_data().architecture == Architecture::X86 {
        let selector = uc(engine.reg_read(RegisterX86::FS))? as u16;
        ensure!(
            selector == 0x30,
            "IPI processor activation requires the owned FS selector"
        );
        let tables = engine.get_data().kernel_cpu.as_ref().unwrap().tables;
        let pcr = row.layout.pcr;
        // FS reload architecturally marks the owned descriptor accessed.
        // Publish that permitted initialized form before native selector reload
        // so the descriptor hook continues to reject every actual guest write.
        let descriptor = 0xfffu64
            | ((pcr & 0xffff) << 16)
            | (((pcr >> 16) & 255) << 32)
            | (0x93 << 40)
            | (0x4 << 52)
            | (((pcr >> 24) & 255) << 56);
        // Defined owned FS descriptor only. Guest/API writes to the descriptor
        // pages are guarded during IPI; this bounded mirror cannot target an
        // arbitrary address or accept guest-provided bytes.
        ensure!(
            engine
                .get_data()
                .apis
                .memory
                .allows(tables + 0x30, 8, Permissions::WRITE),
            "Owned IPI FS descriptor backing unavailable"
        );
        crate::api::reference_mapping::require_api_access(
            engine,
            tables + 0x30,
            8,
            Permissions::WRITE,
        )?;
        uc(engine.mem_write(tables + 0x30, &descriptor.to_le_bytes()))?;
        uc(engine.reg_write(RegisterX86::FS, 0x30))?;
    }
    engine.get_data_mut().cpu.processor = processor;
    engine.get_data_mut().cpu.tsc_offset = row.tsc_offset;
    engine.get_data_mut().cpu.tsc_adjust = row.tsc_adjust;
    let context = engine.get_data_mut().kernel_cpu.as_mut().unwrap();
    context.pcr = row.layout.pcr;
    context.msrs = row.msrs;
    context.msr_version = row.msr_version;
    context.msr_repairs += 1;
    sync(engine, thread)?;
    engine
        .get_data_mut()
        .kernel_cpu
        .as_mut()
        .unwrap()
        .processors
        .native_effect_failure = false;
    Ok(())
}
pub(crate) fn stack(engine: &Unicorn<Trace>, processor: u32) -> Result<(u64, u64)> {
    let row = engine
        .get_data()
        .kernel_cpu
        .as_ref()
        .and_then(|context| context.processors.processors.get(&processor))
        .filter(|row| row.prepared)
        .context("IPI callback stack is not prepared")?;
    Ok((row.layout.stack, STACK_SIZE))
}
pub(crate) fn thread(
    engine: &Unicorn<Trace>,
    processor: u32,
    source: u32,
    caller: u64,
) -> Result<u64> {
    if processor == source {
        return Ok(caller);
    }
    engine
        .get_data()
        .kernel_cpu
        .as_ref()
        .and_then(|context| context.processors.processors.get(&processor))
        .and_then(|row| row.layout.parked_thread)
        .context("IPI remote processor has no borrowed thread identity")
}
pub(crate) fn validate_member_return(
    engine: &Unicorn<Trace>,
    thread: u64,
    level: u8,
) -> Result<()> {
    let architecture = engine.get_data().architecture;
    let context = engine
        .get_data()
        .kernel_cpu
        .as_ref()
        .context("IPI return lacks processor context")?;
    let width = architecture.width();
    let mut pointer_bytes = [0u8; 8];
    uc(engine.mem_read(
        context.pcr + if width == 8 { 0x188 } else { 0x124 },
        &mut pointer_bytes[..width],
    ))?;
    let mut irql = [0u8];
    uc(engine.mem_read(
        context.pcr + if width == 8 { 0x50 } else { 0x24 },
        &mut irql,
    ))?;
    ensure!(
        u64::from_le_bytes(pointer_bytes) == thread
            && irql[0] == level
            && engine.get_data().apis.kernel.save().0 == level,
        "IPI callback returned with corrupted current-thread/IRQL context"
    );
    if architecture == Architecture::X64 {
        ensure!(
            uc(engine.reg_read(RegisterX86::CR8))? == level as u64
                && uc(engine.reg_read(RegisterX86::GS_BASE))? == context.pcr,
            "IPI callback returned with corrupted CR8/GS processor context"
        );
    } else {
        ensure!(
            uc(engine.reg_read(RegisterX86::FS))? == 0x30,
            "IPI callback returned with foreign FS selector"
        );
    }
    Ok(())
}
pub(crate) fn report(engine: &Unicorn<Trace>) -> Option<Report> {
    let context = engine.get_data().kernel_cpu.as_ref()?;
    let current = engine.get_data().cpu.processor;
    let mut rows = context
        .processors
        .processors
        .values()
        .cloned()
        .collect::<Vec<_>>();
    if let Some(row) = rows.iter_mut().find(|row| row.layout.processor == current) {
        for (&index, &value) in &context.msrs {
            row.msrs.insert(index, value);
        }
        row.msr_version = context.msr_version;
        row.tsc_offset = engine.get_data().cpu.tsc_offset;
        row.tsc_adjust = engine.get_data().cpu.tsc_adjust;
    }
    Some(Report {
        current_processor: current,
        processors: rows,
        native_effect_failure: context.processors.native_effect_failure,
    })
}
