use super::*;
use emumee_core::kernel_pfn as contract;
use std::cell::Cell;

#[derive(Default)]
pub(crate) struct State {
    pub(crate) requested: bool,
    initialized: bool,
    reads: u64,
    published: BTreeMap<u64, [u8; 8]>,
    #[cfg(test)]
    fail_after_write: bool,
    refused: Cell<bool>,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub requested: bool,
    pub initialized: bool,
    pub native_field_reads: u64,
    pub access_refused: bool,
    pub scope: &'static str,
}

pub(super) fn report(engine: &Unicorn<Trace>) -> Report {
    let state = &engine.get_data().apis.mdls.pfn;
    Report {
        requested: state.requested,
        initialized: state.initialized,
        native_field_reads: state.reads,
        access_refused: state.refused.get(),
        scope: "New modeled live non-root table PFN+8 backlinks through scalar MOV loads only; no root/data records, host memory, API copies or complete MMPFN records",
    }
}

pub(crate) fn failed(engine: &Unicorn<Trace>) -> bool {
    engine.get_data().apis.mdls.pfn.refused.get()
}

pub(crate) fn intersects(engine: &Unicorn<Trace>, address: u64, size: u64) -> bool {
    engine.get_data().apis.mdls.pfn.requested && contract::intersects(address, size)
}

pub(crate) fn require_change(engine: &Unicorn<Trace>, address: u64, size: u64) -> Result<()> {
    if intersects(engine, address, size) {
        engine.get_data().apis.mdls.pfn.refused.set(true);
        anyhow::bail!("Owned PFN metadata mapping or write is unsupported");
    }
    Ok(())
}

pub(crate) fn require_api_access(engine: &Unicorn<Trace>, address: u64, size: u64) -> Result<()> {
    if intersects(engine, address, size) {
        engine.get_data().apis.mdls.pfn.refused.set(true);
        anyhow::bail!("Owned PFN metadata API copies are not admitted");
    }
    Ok(())
}

pub(crate) fn initialize(engine: &mut Unicorn<Trace>) -> Result<()> {
    if !engine.get_data().apis.mdls.pfn.requested {
        return Ok(());
    }
    ensure!(
        engine.get_data().apis.mdls.owned_paging_requested,
        "PFN metadata requires owned paging"
    );
    ensure!(
        !engine.get_data().apis.mdls.pfn.initialized,
        "PFN metadata initialized twice"
    );
    paging::audit(engine)?;
    let mut memory = engine.get_data().apis.memory.clone();
    memory.map(
        contract::BASE,
        contract::LENGTH,
        P::READ,
        Some(4),
        contract::TAG,
    )?;
    engine.get_data_mut().apis.mdls.poisoned = true;
    uc(engine.mem_map(contract::BASE, contract::LENGTH, Prot::READ))?;
    uc(engine.add_mem_hook(
        crate::HookType::MEM_READ,
        1,
        0,
        |engine, _, address, size, _| match read(engine, address, size) {
            Ok(handled) => handled,
            Err(error) => {
                engine.get_data().apis.mdls.pfn.refused.set(true);
                engine.get_data_mut().apis.fault = Some(format!("Owned PFN metadata: {error:#}"));
                let _ = engine.emu_stop();
                false
            }
        },
    ))?;
    let state = &mut engine.get_data_mut().apis;
    state.memory = memory;
    state.mdls.pfn.initialized = true;
    paging::audit(engine)?;
    engine.get_data_mut().apis.mdls.poisoned = false;
    Ok(())
}

fn require_scalar_load(engine: &Unicorn<Trace>, size: usize) -> Result<()> {
    let pc = uc(engine.reg_read(RegisterX86::RIP))?;
    let mut at = 0u64;
    let mut word = false;
    let mut rex = 0u8;
    let mut next = || -> Result<u8> {
        ensure!(at < 15, "PFN load instruction exceeds decode bound");
        let mut byte = [0];
        uc(engine.mem_read(
            pc.checked_add(at).context("PFN load PC overflow")?,
            &mut byte,
        ))?;
        at += 1;
        Ok(byte[0])
    };
    let opcode = loop {
        let byte = next()?;
        match byte {
            0x66 if rex == 0 => word = true,
            0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 | 0x67 if rex == 0 => {}
            0x40..=0x4f => rex = byte,
            _ => break byte,
        }
    };
    let width = match opcode {
        0x8a => 1,
        0x8b if rex & 8 != 0 => 8,
        0x8b if word => 2,
        0x8b => 4,
        0x0f => match next()? {
            0xb6 | 0xbe => 1,
            0xb7 | 0xbf => 2,
            _ => anyhow::bail!("PFN metadata supports scalar MOV loads only"),
        },
        _ => anyhow::bail!("PFN metadata supports scalar MOV loads only"),
    };
    ensure!(
        next()? & 0xc0 != 0xc0 && size == width,
        "PFN native access differs from complete scalar operand width"
    );
    Ok(())
}

fn read(engine: &mut Unicorn<Trace>, address: u64, size: usize) -> Result<bool> {
    if !intersects(engine, address, size as u64) {
        return Ok(false);
    }
    ready(engine)?;
    require_scalar_load(engine, size)?;
    ensure!(
        engine.get_data().apis.mdls.pfn.initialized && !failed(engine),
        "PFN metadata is unavailable after refusal"
    );
    paging::require_context(engine)?;
    paging::audit(engine)?;
    let state = &engine.get_data().apis;
    let plan = state.mdls.model.prepare_physical_sync(&state.memory)?;
    let bytes = contract::read(
        plan.state.physical().context("PFN authority absent")?,
        address,
        size as u64,
    )?;
    let offset = address
        .checked_sub(contract::BASE)
        .context("PFN address below reservation")?;
    let field = contract::field_address(offset / contract::STRIDE)?;
    let whole: [u8; 8] = contract::read(plan.state.physical().unwrap(), field, 8)?
        .try_into()
        .unwrap();
    if let Some(previous) = engine.get_data().apis.mdls.pfn.published.get(&field) {
        ensure!(
            uc(engine.mem_read_as_vec(field, 8))? == *previous,
            "PFN metadata mirror diverged before publication"
        );
    }
    ensure!(bytes.len() == size, "PFN projection size mismatch");
    engine.get_data_mut().apis.mdls.poisoned = true;
    uc(engine.mem_write(field, &whole))?;
    #[cfg(test)]
    ensure!(
        !engine.get_data().apis.mdls.pfn.fail_after_write,
        "Injected PFN publication failure"
    );
    ensure!(
        uc(engine.mem_read_as_vec(field, 8))? == whole,
        "PFN metadata publication readback mismatch"
    );
    let state = &mut engine.get_data_mut().apis;
    state.mdls.model = plan.state;
    state.memory = plan.memory;
    state.mdls.pfn.published.insert(field, whole);
    state.mdls.pfn.reads = state
        .mdls
        .pfn
        .reads
        .checked_add(1)
        .context("PFN read counter overflow")?;
    state.mdls.poisoned = false;
    Ok(true)
}

#[cfg(test)]
mod tests;
