//! Native publication of owned structural table views, never host page tables.
use super::*;
use crate::HookType;
use emumee_core::mdl::{ViewEffect, ViewPlan};

const FIRST: u64 = 0xffff_f680_0000_0000;
const LAST: u64 = FIRST + (1u64 << 39) - 1;
const MAX_ACCESS: usize = 65536;
const MAX_VIEWS: usize = 4096;

#[derive(Default)]
pub(super) struct State {
    pub(super) backing: BTreeMap<u64, Box<OwnedPage>>,
    #[cfg(test)]
    fail_after_map: bool,
}
pub(crate) fn enabled(engine: &Unicorn<Trace>) -> bool {
    engine.get_data().apis.mdls.model.physical().is_some()
}
fn merge(mut rows: Vec<(u64, u64, u32)>) -> Vec<(u64, u64, u32)> {
    rows.sort_unstable();
    let mut out: Vec<(u64, u64, u32)> = Vec::new();
    for (begin, end, bits) in rows {
        if let Some(last) = out.last_mut() {
            if last.2 == bits && last.1.checked_add(1) == Some(begin) {
                last.1 = end;
                continue;
            }
        }
        out.push((begin, end, bits));
    }
    out
}
/// Exact permission/presence agreement. Different region splitting is allowed;
/// host writes bypassing Unicorn protections do not establish guest access.
pub(super) fn audit(engine: &Unicorn<Trace>) -> Result<()> {
    ensure!(
        engine.get_data().apis.mdls.process == 4,
        "Owned paging requires system-process identity4"
    );
    let memory = &engine.get_data().apis.memory;
    ensure!(
        memory.regions().all(|r| r.owner.is_none_or(|id| id == 4)),
        "Owned paging contains an unqualified process mapping"
    );
    let logical = merge(
        memory
            .regions()
            .map(|r| (r.base, r.base + r.size - 1, u32::from(r.permissions.0)))
            .collect(),
    );
    let native = merge(
        uc(engine.mem_regions())?
            .into_iter()
            .map(|r| (r.begin, r.end, r.perms))
            .collect(),
    );
    ensure!(
        logical == native,
        "Owned paging native/logical mapping presence or permissions disagree"
    );
    Ok(())
}
pub(crate) fn require_context(engine: &Unicorn<Trace>) -> Result<()> {
    if let Some(authority) = engine.get_data().apis.mdls.model.physical() {
        crate::kernel_cpu::require_owned_four_level_paging(engine)?;
        ensure!(
            uc(engine.reg_read(RegisterX86::CR3))? == authority.cr3(),
            "Guest CR3 differs from owned root identity"
        );
        ensure!(
            engine.get_data().apis.mdls.process == 4,
            "Owned paging process context differs"
        );
    }
    Ok(())
}
/// Keep the virtual TLB and its declared hierarchy in one paging domain. An
/// idempotent MOV CR0/3/4 may flush native state; a different context requires a
/// producer we do not have. Other control mutations remain explicitly outside
/// this staged profile, rather than silently retaining stale table views.
pub(crate) fn control_write(engine: &Unicorn<Trace>, pc: u64, size: u32) -> Result<()> {
    if !enabled(engine) {
        return Ok(());
    }
    require_context(engine)?;
    ensure!(
        (1..=15).contains(&size),
        "Invalid owned control instruction size"
    );
    let bytes = uc(engine.mem_read_as_vec(pc, size as usize))?;
    let mut at = 0;
    while at < bytes.len()
        && (matches!(
            bytes[at],
            0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 | 0x66 | 0x67 | 0xf2 | 0xf3
        ) || (0x40..=0x4f).contains(&bytes[at]))
    {
        at += 1;
    }
    ensure!(
        at + 3 == bytes.len() && bytes[at..at + 2] == [0x0f, 0x22],
        "Owned paging control mutation lacks an admitted context producer"
    );
    let rex = if at > 0 && (0x40..=0x4f).contains(&bytes[at - 1]) {
        bytes[at - 1]
    } else {
        0
    };
    let control = ((bytes[at + 2] >> 3) & 7) | ((rex & 4) << 1);
    let register = match control {
        0 => RegisterX86::CR0,
        3 => RegisterX86::CR3,
        4 => RegisterX86::CR4,
        _ => anyhow::bail!("Unsupported owned paging control register"),
    };
    let gprs = [
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
    let source = gprs[((bytes[at + 2] & 7) | ((rex & 1) << 3)) as usize];
    ensure!(
        uc(engine.reg_read(source))? == uc(engine.reg_read(register))?,
        "Owned paging control mutation changes the admitted context"
    );
    Ok(())
}
/// Called after CPU mode setup, before its initial context/IPI seed is captured.
pub(crate) fn initialize(engine: &mut Unicorn<Trace>) -> Result<()> {
    ensure!(
        engine.get_data().architecture == Architecture::X64 && engine.get_data().apis.kernel_mode,
        "Owned paging requires x64 kernel mode"
    );
    audit(engine)?;
    let state = &engine.get_data().apis;
    let plan = state.mdls.model.prepare_owned_paging(&state.memory)?;
    engine.get_data_mut().apis.mdls.poisoned = true;
    uc(engine.reg_write(RegisterX86::CR3, plan.result))?;
    ensure!(
        uc(engine.reg_read(RegisterX86::CR3))? == plan.result,
        "Owned paging CR3 publication readback failed"
    );
    // The reserved span hook sees successful reads too, so protection/mapping
    // epochs refresh table bytes before a guest can consume a cached view.
    uc(engine.add_mem_hook(
        HookType::MEM_READ,
        FIRST,
        LAST,
        |engine, _, address, size, _| match read(engine, address, size) {
            Ok(handled) => handled,
            Err(error) => {
                engine.get_data_mut().apis.mdls.poisoned = true;
                engine.get_data_mut().apis.fault = Some(format!("Owned paging view: {error:#}"));
                let _ = engine.emu_stop();
                false
            }
        },
    ))?;
    let state = &mut engine.get_data_mut().apis;
    state.mdls.model = plan.state;
    state.memory = plan.memory;
    state.mdls.poisoned = false;
    Ok(())
}
pub(crate) fn register_clock(engine: &mut Unicorn<Trace>) -> Result<()> {
    if !enabled(engine) {
        return Ok(());
    }
    require_context(engine)?;
    audit(engine)?;
    ensure!(
        engine.get_data().clock_page.is_some()
            && engine.get_data().clock_aliases
                == [0x7ffe0000, 0xffff_f780_0000_0000, 0x000f_f780_0000_0000],
        "Owned paging clock alias producer is not initialized"
    );
    // time::initialize owns one retained aligned box mapped at these addresses.
    let state = &engine.get_data().apis;
    let plan = state.mdls.model.prepare_physical_transport(
        &state.memory,
        0x000f_f780_0000_0000,
        0xffff_f780_0000_0000,
    )?;
    let plan = plan.state.prepare_shared_physical_alias(
        &plan.memory,
        0xffff_f780_0000_0000,
        0x7ffe0000,
        1,
    )?;
    engine.get_data_mut().apis.mdls.model = plan.state;
    Ok(())
}
fn apply(engine: &mut Unicorn<Trace>, plan: ViewPlan) -> Result<bool> {
    let at = plan.address;
    // Preflight is pure. Once a native effect starts, a failure remains fatal
    // and every uncertain backing allocation stays retained until uc_close.
    engine.get_data_mut().apis.mdls.poisoned = true;
    match plan.effect {
        ViewEffect::Map => {
            ensure!(
                plan.bytes.len() == PAGE as usize
                    && engine.get_data().apis.mdls.paging.backing.len() < MAX_VIEWS
                    && !engine.get_data().apis.mdls.paging.backing.contains_key(&at),
                "Invalid new owned paging backing"
            );
            let bytes: [u8; 4096] = plan.bytes.as_slice().try_into()?;
            let backing = Box::new(OwnedPage::new(bytes));
            let pointer = backing.pointer();
            engine
                .get_data_mut()
                .apis
                .mdls
                .paging
                .backing
                .insert(at, backing);
            // SAFETY: exactly one aligned owned UnsafeCell page, retained before
            // mapping. uc_close precedes Trace destruction. Guest access is
            // single-threaded and read-only/NX; updates happen in paused hooks.
            uc(unsafe { engine.mem_map_ptr(at, PAGE, Prot::READ, pointer) })?;
            #[cfg(test)]
            ensure!(
                !engine.get_data().apis.mdls.paging.fail_after_map,
                "Injected paging failure after native map"
            );
        }
        ViewEffect::Refresh | ViewEffect::Rebind => {
            ensure!(
                plan.bytes.len() == PAGE as usize,
                "Invalid refreshed owned paging bytes"
            );
            let page = engine
                .get_data_mut()
                .apis
                .mdls
                .paging
                .backing
                .get_mut(&at)
                .context("Missing retained paging backing")?;
            // Unique native execution is paused; no Rust reference to shared
            // bytes exists across guest execution. Host pointer never comes
            // from a guest integer.
            page.bytes.get_mut().copy_from_slice(&plan.bytes);
        }
        ViewEffect::Unmap => {
            invalidate(engine, at, PAGE)?;
            uc(engine.mem_unmap(at, PAGE))?;
            ensure!(
                uc(engine.mem_regions())?
                    .iter()
                    .all(|r| r.begin > at + PAGE - 1 || r.end < at),
                "Owned view unmap readback disagrees"
            );
            engine.get_data_mut().apis.mdls.paging.backing.remove(&at);
        }
    }
    if !matches!(plan.effect, ViewEffect::Unmap) {
        ensure!(
            uc(engine.mem_read_as_vec(at, PAGE as usize))? == plan.bytes,
            "Owned paging bytes publication readback failed"
        );
    }
    let mapped = !matches!(plan.effect, ViewEffect::Unmap);
    let state = &mut engine.get_data_mut().apis;
    state.mdls.model = plan.state;
    state.memory = plan.memory;
    state.mdls.poisoned = false;
    Ok(mapped)
}
/// Both successful native-read hooks and the common unmapped-read handler call
/// this. No write/fetch access can create a structural view.
pub(crate) fn read(engine: &mut Unicorn<Trace>, address: u64, size: usize) -> Result<bool> {
    if !enabled(engine) || !(FIRST..=LAST).contains(&address) {
        return Ok(false);
    }
    ready(engine)?;
    require_context(engine)?;
    ensure!(
        size > 0
            && size <= MAX_ACCESS
            && address
                .checked_add(size as u64 - 1)
                .is_some_and(|end| end <= LAST),
        "Owned paging view access exceeds bounds"
    );
    audit(engine)?;
    let last = (address + size as u64 - 1) & !(PAGE - 1);
    let mut at = address & !(PAGE - 1);
    loop {
        let state = &engine.get_data().apis;
        let plan = state.mdls.model.prepare_physical_view(&state.memory, at)?;
        if !apply(engine, plan)? {
            return Ok(false);
        }
        if at == last {
            break;
        }
        at += PAGE;
    }
    Ok(true)
}

#[cfg(test)]
mod tests;
