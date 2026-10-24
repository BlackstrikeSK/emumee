//! Apply validated guest memory plans to Unicorn; publish metadata only on success.
use super::*;
use anyhow::Context;
use emumee_core::virtual_memory::{self as vm, Change, Plan, VmError};
pub(super) fn apply(engine: &mut Unicorn<Trace>, plan: Plan) -> Result<u64> {
    for change in &plan.changes {
        let (base, size) = match *change {
            Change::Map { base, size }
            | Change::Protect { base, size, .. }
            | Change::Zero { base, size }
            | Change::Unmap { base, size } => (base, size),
        };
        kernel_spin::require_mapping_change(engine, base, size)?;
        crate::threads::timers::require_mapping_change(engine, base, size)?;
    }
    for change in &plan.changes {
        let (base, size) = match *change {
            Change::Map { base, size }
            | Change::Protect { base, size, .. }
            | Change::Zero { base, size }
            | Change::Unmap { base, size } => (base, size),
        };
        engine
            .get_data_mut()
            .cpu
            .cache
            .invalidate(base, size as usize);
        match *change {
            Change::Map { base, size } => uc(engine.mem_map(base, size, Prot::NONE))?,
            Change::Protect {
                base,
                size,
                permissions,
            } => {
                let mut prot = Prot::NONE;
                if permissions.contains(P::READ) {
                    prot |= Prot::READ;
                }
                if permissions.contains(P::WRITE) {
                    prot |= Prot::WRITE;
                }
                if permissions.contains(P::EXECUTE) {
                    prot |= Prot::EXEC;
                }
                if permissions.contains(P::WRITE) && permissions.contains(P::EXECUTE) {
                    crate::cpu::watch(engine, base, size)?;
                }
                uc(engine.mem_protect(base, size, prot))?;
            }
            Change::Zero { base, size } => {
                // Writes through the emulator API intentionally clear inaccessible
                // decommitted backing; guest instructions still cannot touch it.
                let zero = [0u8; 4096];
                for offset in (0..size).step_by(4096) {
                    crate::cpu::write(engine, base + offset, &zero)?;
                }
            }
            Change::Unmap { base, size } => uc(engine.mem_unmap(base, size))?,
        }
    }
    let state = &mut engine.get_data_mut().apis;
    state.memory = plan.memory;
    state.allocations = plan.state;
    Ok(plan.result)
}
fn finish(engine: &mut Unicorn<Trace>, plan: std::result::Result<Plan, VmError>) -> Result<u64> {
    match plan {
        Ok(plan) => apply(engine, plan),
        Err(error) => {
            engine.get_data_mut().apis.last_error = error.win32;
            Ok(0)
        }
    }
}
fn supported_protection(value: u32) -> Result<()> {
    // Guard/cache/copy-on-write behavior must not silently become ordinary pages.
    ensure!(
        value & !0xff == 0,
        "Virtual memory protection modifiers 0x{value:x} are not modeled"
    );
    Ok(())
}
pub(super) fn allocate(engine: &mut Unicorn<Trace>, args: &[u64]) -> Result<u64> {
    crate::threads::timers::require_mapping_change(engine, args[0], args[1])?;
    kernel_spin::require_mapping_change(engine, args[0], args[1])?;
    if args[0] != 0 {
        persona::require_allocation_change(engine, args[0], args[1])?;
        crt_stdio::require_allocation_change(engine, args[0], args[1])?;
    }
    let flags = args[2] as u32;
    ensure!(
        flags & !(vm::COMMIT | vm::RESERVE) == 0,
        "VirtualAlloc flags 0x{flags:x} are not modeled"
    );
    supported_protection(args[3] as u32)?;
    let state = &engine.get_data().apis;
    let plan = state
        .allocations
        .allocate(&state.memory, args[0], args[1], flags, args[3] as u32);
    finish(engine, plan)
}
pub(super) fn free(engine: &mut Unicorn<Trace>, args: &[u64]) -> Result<u64> {
    crate::threads::timers::require_mapping_change(engine, args[0], args[1])?;
    kernel_spin::require_mapping_change(engine, args[0], args[1])?;
    persona::require_allocation_change(engine, args[0], args[1])?;
    crt_stdio::require_allocation_change(engine, args[0], args[1])?;
    ensure!(
        !engine.get_data().apis.heaps.owns_mapping(args[0]),
        "VirtualFree cannot release a heap-owned reservation; use HeapFree"
    );
    let flags = args[2] as u32;
    ensure!(
        [vm::DECOMMIT, vm::RELEASE].contains(&flags),
        "VirtualFree flags 0x{flags:x} are not modeled"
    );
    let state = &engine.get_data().apis;
    let plan = state
        .allocations
        .free(&state.memory, args[0], args[1], flags);
    finish(engine, plan)
}
pub(super) fn protect(engine: &mut Unicorn<Trace>, args: &[u64]) -> Result<u64> {
    crate::threads::timers::require_mapping_change(engine, args[0], args[1])?;
    kernel_spin::require_mapping_change(engine, args[0], args[1])?;
    persona::require_allocation_change(engine, args[0], args[1])?;
    crt_stdio::require_allocation_change(engine, args[0], args[1])?;
    supported_protection(args[2] as u32)?;
    if !engine.get_data().apis.memory.allows(args[3], 4, P::WRITE) {
        engine.get_data_mut().apis.last_error = 998;
        return Ok(0);
    }
    let state = &engine.get_data().apis;
    let plan = state
        .allocations
        .protect(&state.memory, args[0], args[1], args[2] as u32);
    if let Ok(plan) = &plan {
        if !plan.memory.allows(args[3], 4, P::WRITE) {
            engine.get_data_mut().apis.last_error = 998;
            return Ok(0);
        }
        let old = plan
            .old_protection
            .context("Private protection plan lacks old protection")?;
        // Output is written only after every check has passed.
        crate::cpu::write(engine, args[3], &old.to_le_bytes())?;
    }
    finish(engine, plan)
}
