//! Bounded native nonpresent physical queries over audited owned VTLB topology.
//! No host physical memory, native PTE publication or invented PFN allocation.
use super::*;
use emumee_core::kernel_physical::{self as core, Registers};

pub(super) mod owned;

#[derive(Default)]
pub(super) struct State {
    events: Vec<Event>,
    omitted: u64,
    #[cfg(test)]
    fail_before_spill: Option<usize>,
}
#[derive(Clone, Debug, Serialize)]
pub struct Event {
    pub instruction_ordinal: u64,
    pub raw_address: u64,
    pub paging_alias: u64,
    pub first_missing_level: u8,
    pub native_prefix_ranges: usize,
    pub stack_spills: usize,
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub events: Vec<Event>,
    pub omitted: u64,
    pub scope: &'static str,
    pub owned_queries: owned::Report,
}
pub(super) fn report(engine: &Unicorn<Trace>) -> Report {
    let state = &engine.get_data().apis.mdls.physical;
    Report {
        events: state.events.clone(),
        omitted: state.omitted,
        owned_queries: owned::report(engine),
        scope: if super::paging::enabled(engine) {
            "Owned synthetic root/table/data authority and guarded structural views. Configured x64 build26200 ordinary4KiB physical queries use actual entry words with native volatile-register, TEST-flag and ordered stack-spill projection. Unknown classification/logging, entry repair, large pages and foreign contexts are refused. No host physical RAM/CR3 or full native boot equivalence. Legacy ancestor0x23 and mapped-PFN fallbacks are disabled in this mode."
        } else {
            "Configured x64 build26200 nonpresent queries: owned virtual-TLB four-level4KiB topology, explicit ordinary ancestors0x23/missing0 profile, exact live-native/logical mapping-presence union audit in the target PML4 prefix and unchanged virtual paging context. Raw arguments retain classification semantics; low48-bit aliases select topology. Native registers/TEST flags and14 stack spills projected under nonaliasing/no-interleaving conditions. No frame allocation, guest PTE publication, hardware CR3/table reconstruction, arbitrary PTE attributes, large pages, positive-path native ABI, classification/logging producer or full native boot equivalence. Existing mapped positive synthetic-PFN behavior remains separate."
        },
    }
}
pub(super) fn enabled(engine: &Unicorn<Trace>) -> bool {
    let state = engine.get_data();
    state.apis.kernel_mode
        && state.architecture == Architecture::X64
        && state.machine.is_configured()
        && state.machine.windows_build() == 26200
}
fn merge(mut ranges: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    ranges.sort_unstable();
    let mut out: Vec<(u64, u64)> = Vec::new();
    for (begin, end) in ranges {
        if let Some(last) = out.last_mut() {
            if begin <= last.1.saturating_add(1) {
                last.1 = last.1.max(end);
                continue;
            }
        }
        out.push((begin, end));
    }
    out
}
fn audit(engine: &Unicorn<Trace>, address: u64) -> Result<usize> {
    let first = address & !((1u64 << 39) - 1);
    let last = first | ((1u64 << 39) - 1);
    let clip = |begin: u64, end: u64| {
        (begin <= last && end >= first).then_some((begin.max(first), end.min(last)))
    };
    let logical = merge(
        engine
            .get_data()
            .apis
            .memory
            .regions()
            .filter_map(|r| clip(r.base, r.base + r.size - 1))
            .collect(),
    );
    let native = merge(
        uc(engine.mem_regions())?
            .into_iter()
            .filter_map(|r| clip(r.begin, r.end))
            .collect(),
    );
    ensure!(
        logical == native,
        "Physical query native/logical mapping presence disagreement in PML4 prefix"
    );
    Ok(native.len())
}
fn registers(engine: &Unicorn<Trace>) -> Result<Registers> {
    let r = |reg| uc(engine.reg_read(reg));
    Ok(Registers {
        rax: r(RegisterX86::RAX)?,
        rbx: r(RegisterX86::RBX)?,
        rcx: r(RegisterX86::RCX)?,
        rdx: r(RegisterX86::RDX)?,
        rbp: r(RegisterX86::RBP)?,
        rsi: r(RegisterX86::RSI)?,
        rdi: r(RegisterX86::RDI)?,
        rsp: r(RegisterX86::RSP)?,
        r8: r(RegisterX86::R8)?,
        r9: r(RegisterX86::R9)?,
        r10: r(RegisterX86::R10)?,
        r11: r(RegisterX86::R11)?,
        r14: r(RegisterX86::R14)?,
        r15: r(RegisterX86::R15)?,
    })
}
pub(super) fn try_absent(engine: &mut Unicorn<Trace>, raw: u64) -> Result<Option<u64>> {
    crate::kernel_cpu::require_owned_four_level_paging(engine)?;
    ensure!(
        engine.get_data().apis.mdls.process == 4,
        "Physical query requires owned system-process identity"
    );
    let alias = core::paging_alias(raw);
    let native_ranges = audit(engine, alias)?;
    // This declares the current backend's owned ordinary hierarchy; it is not a
    // deduction about host/native PTE bytes. Future paging/attach/large-page
    // producers must replace this authority and invalidate the profile.
    let absent = core::absent_in_owned_space(&engine.get_data().apis.memory, raw)
        .map_err(|e| anyhow!("Physical query owned hierarchy: {e:?}"))?;
    let Some(absent) = absent else {
        ensure!(
            raw == alias,
            "Positive noncanonical physical-query alias lacks a native translation contract"
        );
        return Ok(None);
    };
    ensure!(
        !crate::ipi::active(engine) && !crate::threads::dpc::active(engine),
        "Nonpresent physical query requires an ordinary owned thread"
    );
    let thread = crate::threads::thread_address(engine);
    super::super::kernel_thread_objects::validate_owned_thread(engine, thread)?;
    let bounds = super::super::kernel_thread_objects::ordinary_stack_fields(engine, thread)?
        .ok_or_else(|| anyhow!("Nonpresent physical query requires an ordinary owned stack"))?;
    let before = registers(engine)?;
    ensure!(
        before.rsp >= bounds.limit + 0x78
            && before
                .rsp
                .checked_add(0x28)
                .is_some_and(|end| end <= bounds.base),
        "Physical query native stack exceeds owned bounds"
    );
    // No classification producer is admitted. The core therefore either takes
    // a path that never reads kernel_base or refuses before using it; zero here
    // is an unused argument, not a fabricated mapped kernel address.
    let projection = core::project_absent(
        absent,
        before,
        uc(engine.reg_read(RegisterX86::EFLAGS))?,
        0,
        None,
    )
    .map_err(|e| anyhow!("Physical query native precondition: {e:?}"))?;
    let native = uc(engine.mem_regions())?;
    ensure!(
        projection.pte_addresses.iter().all(|at| engine
            .get_data()
            .apis
            .memory
            .region(*at)
            .is_none()
            && native.iter().all(|r| r.begin > *at + 7 || r.end < *at)),
        "Physical query PTE view overlaps mapped guest data; owned profile unavailable"
    );
    let native_writable = merge(
        native
            .iter()
            .filter(|r| {
                r.perms & (Prot::READ.0 | Prot::WRITE.0) as u32
                    == (Prot::READ.0 | Prot::WRITE.0) as u32
            })
            .map(|r| (r.begin, r.end))
            .collect(),
    );
    for spill in &projection.spills {
        require(engine, spill.address, spill.bytes.len() as u64, P::WRITE)?;
        ensure!(
            native_writable
                .iter()
                .any(|(begin, end)| *begin <= spill.address
                    && *end >= spill.address + spill.bytes.len() as u64 - 1),
            "Physical query native stack write permissions disagree with owned writable stack"
        );
    }
    engine.get_data_mut().apis.mdls.poisoned = true;
    for (index, spill) in projection.spills.iter().enumerate() {
        #[cfg(test)]
        if engine.get_data().apis.mdls.physical.fail_before_spill == Some(index) {
            uc(engine.mem_unmap(spill.address & !4095, 4096))?;
        }
        crate::cpu::write(engine, spill.address, &spill.bytes)
            .with_context(|| format!("Physical query native spill {index} write failed"))?;
        ensure!(
            uc(engine.mem_read_as_vec(spill.address, spill.bytes.len()))? == spill.bytes,
            "Physical query stack write readback failed at spill {index}"
        );
    }
    let r = projection.registers;
    for (reg, value) in [
        (RegisterX86::RAX, r.rax),
        (RegisterX86::RCX, r.rcx),
        (RegisterX86::RDX, r.rdx),
        (RegisterX86::R8, r.r8),
        (RegisterX86::R9, r.r9),
        (RegisterX86::R10, r.r10),
        (RegisterX86::R11, r.r11),
        (RegisterX86::EFLAGS, projection.flags),
    ] {
        uc(engine.reg_write(reg, value))?;
        ensure!(
            uc(engine.reg_read(reg))? == value,
            "Physical query register readback failed"
        );
    }
    let ordinal = engine.get_data().instructions;
    let state = &mut engine.get_data_mut().apis.mdls;
    state.poisoned = false;
    if state.physical.events.len() < 256 {
        state.physical.events.push(Event {
            instruction_ordinal: ordinal,
            raw_address: raw,
            paging_alias: alias,
            first_missing_level: absent.first_missing_level,
            native_prefix_ranges: native_ranges,
            stack_spills: projection.spills.len(),
        });
    } else {
        state.physical.omitted = state.physical.omitted.saturating_add(1);
    }
    Ok(Some(0))
}

#[cfg(test)]
mod tests;
