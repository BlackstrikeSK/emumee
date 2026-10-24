use super::*;
pub(super) fn call(engine: &mut Unicorn<Trace>, model: Model, args: &[u64]) -> Result<u64> {
    ensure!(
        engine.get_data().apis.kernel_mode,
        "Kernel pool requires a driver target"
    );
    let irql = engine.get_data().apis.kernel.save().0;
    if matches!(model, Model::PoolFree | Model::PoolFreeTagged) {
        let allocation = engine
            .get_data()
            .apis
            .pool
            .prepare_free(
                args[0],
                if matches!(model, Model::PoolFreeTagged) {
                    Some(args[1] as u32)
                } else {
                    None
                },
                irql,
            )?
            .clone();
        crate::threads::timers::require_pool_release(engine, allocation.base, allocation.mapped)?;
        crate::threads::require_event_pool_release(engine, allocation.base, allocation.mapped)?;
        kernel_spin::require_pool_release(engine, allocation.base, allocation.mapped)?;
        mdl::require_pool_release(engine, allocation.base, allocation.mapped)?;
        rundown::require_pool_release(engine, allocation.base, allocation.mapped)?;
        let mut memory = engine.get_data().apis.memory.clone();
        memory.unmap(allocation.base, allocation.mapped)?;
        engine
            .get_data_mut()
            .cpu
            .cache
            .invalidate(allocation.base, allocation.mapped as usize);
        uc(engine.mem_unmap(allocation.base, allocation.mapped))?;
        mdl::release_pool_backing(engine, allocation.base, allocation.mapped)?;
        let state = &mut engine.get_data_mut().apis;
        state.memory = memory;
        state.pool.commit_free(allocation.base);
        kernel_rtl::retire_pool(engine, &allocation)?;
        kernel_spin::retired_pool(engine, allocation.base, allocation.mapped)?;
        crate::threads::timers::retired_pool(engine, allocation.base, allocation.mapped)?;
        crate::threads::retire_event_pool(engine, allocation.base, allocation.mapped)?;
        return Ok(0);
    }
    let architecture = engine.get_data().architecture;
    let (flags, size, tag) = if matches!(model, Model::Pool2) {
        if architecture == Architecture::X86 {
            (args[0] | (args[1] << 32), args[2], args[3] as u32)
        } else {
            (args[0], args[1], args[2] as u32)
        }
    } else {
        // POOL_ZERO_ALLOCATION (0x400) is an orthogonal legacy POOL_TYPE
        // modifier.  It selects the zeroed form of the corresponding pool;
        // leave every other unmodeled modifier as an explicit refusal.
        ensure!(args[0] <= u32::MAX as u64, "Legacy pool type exceeds ULONG");
        let pool_type = args[0] as u32;
        let base_flags = match pool_type & !0x400 {
            0 => 0x80,
            1 => 0x100,
            512 => 0x40,
            _ => bail!("Legacy pool type/modifiers are not modeled"),
        };
        let flags = base_flags | if pool_type & 0x400 == 0 { 2 } else { 0 };
        (
            flags,
            args[1],
            if matches!(model, Model::PoolTagged) {
                args[2] as u32
            } else {
                u32::from_le_bytes(*b"None")
            },
        )
    };
    let state = &engine.get_data().apis;
    let Some(allocation) =
        state
            .pool
            .prepare(&state.memory, architecture, flags, size, tag, irql)?
    else {
        return Ok(0);
    };
    let mut memory = state.memory.clone();
    memory.map(
        allocation.base,
        allocation.mapped,
        allocation.permissions(),
        None,
        "kernel pool",
    )?;
    let prot = if allocation.executable {
        Prot::ALL
    } else {
        Prot::READ | Prot::WRITE
    };
    uc(engine.mem_map(allocation.base, allocation.mapped, prot))?;
    if allocation.executable {
        crate::cpu::watch(engine, allocation.base, allocation.mapped)?;
    }
    // A deterministic poison represents unspecified guest contents, never host bytes.
    if !allocation.zero_initialized {
        let poison = [0xcdu8; 4096];
        for offset in (0..allocation.mapped).step_by(4096) {
            crate::cpu::write(engine, allocation.base + offset, &poison)?;
        }
    }
    let address = allocation.base;
    let state = &mut engine.get_data_mut().apis;
    state.memory = memory;
    state.pool.commit_allocation(allocation);
    Ok(address)
}
