use super::*;
use emumee_core::kernel_physical::owned::{self as projection, Walk};

#[derive(Default)]
pub(crate) struct State {
    events: Vec<Event>,
    omitted: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct Event {
    pub instruction_ordinal: u64,
    pub walk: Walk,
    pub physical_address: u64,
    pub stack_spills: usize,
    pub structural_reads: usize,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub events: Vec<Event>,
    pub omitted: u64,
}

pub(super) fn report(engine: &Unicorn<Trace>) -> Report {
    let state = &engine.get_data().apis.mdls.owned_queries;
    Report {
        events: state.events.clone(),
        omitted: state.omitted,
    }
}

pub(in crate::api::mdl) fn query(engine: &mut Unicorn<Trace>, raw: u64) -> Result<u64> {
    ready(engine)?;
    ensure!(
        enabled(engine),
        "Owned physical-query ABI requires configured x64 build26200"
    );
    super::super::paging::require_context(engine)?;
    super::super::paging::audit(engine)?;
    ensure!(
        !crate::ipi::active(engine) && !crate::threads::dpc::active(engine),
        "Owned physical query requires an ordinary thread"
    );
    let thread = crate::threads::thread_address(engine);
    crate::api::kernel_thread_objects::validate_owned_thread(engine, thread)?;
    let bounds = crate::api::kernel_thread_objects::ordinary_stack_fields(engine, thread)?
        .context("Owned physical query requires an ordinary stack")?;
    let before = registers(engine)?;
    ensure!(
        before.rsp >= bounds.limit.saturating_add(0x78)
            && before
                .rsp
                .checked_add(0x28)
                .is_some_and(|last| last <= bounds.base),
        "Owned physical-query stack exceeds owned bounds"
    );
    let state = &engine.get_data().apis;
    let (plan, walk) = state.mdls.model.prepare_physical_walk(&state.memory, raw)?;
    let projected =
        projection::project(&walk, before, uc(engine.reg_read(RegisterX86::EFLAGS))?)
            .map_err(|error| anyhow!("Owned physical-query native precondition: {error:?}"))?;
    ensure!(
        projected.registers.rax == plan.result,
        "Owned walk and translation disagree"
    );
    for spill in &projected.spills {
        require(engine, spill.address, spill.bytes.len() as u64, P::WRITE)?;
    }
    let effects = (|| -> Result<()> {
        for (level, word) in walk.entries.iter().enumerate() {
            let Some(word) = word else { break };
            let address = projected.pte_addresses[3 - level];
            ensure!(
                super::super::paging::read(engine, address, 8)?,
                "Owned entry view absent"
            );
            ensure!(
                uc(engine.mem_read_as_vec(address, 8))? == word.to_le_bytes(),
                "Owned native entry readback differs from walk"
            );
        }
        let state = &engine.get_data().apis;
        let (current, actual) = state.mdls.model.prepare_physical_walk(&state.memory, raw)?;
        ensure!(
            actual == walk && current.result == plan.result,
            "Owned walk changed during publication"
        );
        engine.get_data_mut().apis.mdls.poisoned = true;
        for (index, spill) in projected.spills.iter().enumerate() {
            #[cfg(test)]
            if engine.get_data().apis.mdls.physical.fail_before_spill == Some(index) {
                uc(engine.mem_unmap(spill.address & !4095, 4096))?;
            }
            crate::cpu::write(engine, spill.address, &spill.bytes)
                .with_context(|| format!("Owned physical-query spill {index} failed"))?;
            ensure!(
                uc(engine.mem_read_as_vec(spill.address, spill.bytes.len()))? == spill.bytes,
                "Owned physical-query spill readback failed"
            );
        }
        let after = projected.registers;
        for (register, value) in [
            (RegisterX86::RAX, after.rax),
            (RegisterX86::RCX, after.rcx),
            (RegisterX86::RDX, after.rdx),
            (RegisterX86::R8, after.r8),
            (RegisterX86::R9, after.r9),
            (RegisterX86::R10, after.r10),
            (RegisterX86::R11, after.r11),
            (RegisterX86::EFLAGS, projected.flags),
        ] {
            uc(engine.reg_write(register, value))?;
            ensure!(
                uc(engine.reg_read(register))? == value,
                "Owned physical-query register readback failed"
            );
        }
        engine.get_data_mut().apis.mdls.model = current.state;
        Ok(())
    })();
    if let Err(error) = effects {
        engine.get_data_mut().apis.mdls.poisoned = true;
        return Err(error);
    }
    let ordinal = engine.get_data().instructions;
    let state = &mut engine.get_data_mut().apis.mdls;
    state.poisoned = false;
    if state.owned_queries.events.len() < 256 {
        state.owned_queries.events.push(Event {
            instruction_ordinal: ordinal,
            physical_address: projected.registers.rax,
            stack_spills: projected.spills.len(),
            structural_reads: walk.entries.iter().flatten().count(),
            walk,
        });
    } else {
        state.owned_queries.omitted = state.owned_queries.omitted.saturating_add(1);
    }
    Ok(projected.registers.rax)
}

#[cfg(test)]
mod tests;
