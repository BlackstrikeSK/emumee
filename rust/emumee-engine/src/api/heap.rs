//! Apply guest heap plans; never call a host allocator or expose a host pointer.
use super::*;
use emumee_core::heap::{HeapError, PROCESS_HEAP, Plan};
#[derive(Clone, Copy)]
pub(super) enum Call {
    Process,
    Create,
    Allocate,
    Reallocate,
    Size,
    Free,
    Destroy,
}
fn finish(
    engine: &mut Unicorn<Trace>,
    result: std::result::Result<Plan, HeapError>,
    set_error: bool,
) -> Result<u64> {
    let plan = match result {
        Ok(plan) => plan,
        Err(HeapError::Limit) => {
            if set_error {
                engine.get_data_mut().apis.last_error = 8;
            }
            return Ok(0);
        }
        Err(error) => return Err(error.into()),
    };
    let copy = if let Some((source, target, size)) = plan.copy {
        Some((target, read(engine, source, size)?))
    } else {
        None
    };
    let result = allocation::apply(engine, plan.memory)?;
    if let Some((target, data)) = copy {
        if !data.is_empty() {
            crate::cpu::write(engine, target, &data)?;
        }
    }
    if let Some((start, size)) = plan.zero {
        let block = [0u8; 4096];
        let mut offset = 0;
        while offset < size {
            let count = (size - offset).min(4096);
            crate::cpu::write(engine, start + offset, &block[..count as usize])?;
            offset += count;
        }
    }
    engine.get_data_mut().apis.heaps = plan.state;
    Ok(result)
}
pub(super) fn invoke(engine: &mut Unicorn<Trace>, args: &[u64], call: Call) -> Result<u64> {
    ensure!(
        !engine.get_data().apis.kernel_mode,
        "User heap API is outside the kernel target profile"
    );
    match call {
        Call::Process => Ok(PROCESS_HEAP),
        Call::Create => {
            match engine
                .get_data_mut()
                .apis
                .heaps
                .create(args[0] as u32, args[1], args[2])
            {
                Ok(handle) => Ok(handle),
                Err(HeapError::Limit) => {
                    engine.get_data_mut().apis.last_error = 8;
                    Ok(0)
                }
                Err(error) => Err(error.into()),
            }
        }
        Call::Size => Ok(engine
            .get_data()
            .apis
            .heaps
            .size(args[0], args[1] as u32, args[2])?),
        Call::Allocate => {
            let state = &engine.get_data().apis;
            let plan = state.heaps.allocate(
                &state.allocations,
                &state.memory,
                args[0],
                args[1] as u32,
                args[2],
            );
            finish(engine, plan, false)
        }
        Call::Reallocate => {
            let state = &engine.get_data().apis;
            let plan = state.heaps.reallocate(
                &state.allocations,
                &state.memory,
                args[0],
                args[1] as u32,
                args[2],
                args[3],
            );
            finish(engine, plan, false)
        }
        Call::Free => {
            let state = &engine.get_data().apis;
            let plan = state.heaps.free(
                &state.allocations,
                &state.memory,
                args[0],
                args[1] as u32,
                args[2],
            );
            finish(engine, plan, true)
        }
        Call::Destroy => {
            let state = &engine.get_data().apis;
            let plan = state
                .heaps
                .destroy(&state.allocations, &state.memory, args[0]);
            finish(engine, plan, true)
        }
    }
}
