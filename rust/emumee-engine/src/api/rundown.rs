//! Typed rundown APIs own opaque NX pool reservations, not Windows body bytes.
use super::*;
use anyhow::Context;
use emumee_core::rundown::{
    AllocationRequest, ApiDenial, Blocked, Effect, Operation, Plan, Rundowns,
};
use std::cell::RefCell;

#[derive(Clone, Copy)]
pub(super) enum Call {
    Allocate,
    Free,
    Acquire(bool),
    Release(bool),
    Wait,
}
/// Exact modeled routine names; provider publication must use these delegates.
pub(super) const ROUTINES: &[&str] = &[
    "ExAllocateCacheAwareRundownProtection",
    "ExFreeCacheAwareRundownProtection",
    "ExAcquireRundownProtectionCacheAware",
    "ExAcquireRundownProtectionCacheAwareEx",
    "ExReleaseRundownProtectionCacheAware",
    "ExReleaseRundownProtectionCacheAwareEx",
    "ExWaitForRundownProtectionReleaseCacheAware",
];
pub(super) fn definition(name: &str) -> Option<(Call, usize, C, T)> {
    Some(match name {
        "ExAllocateCacheAwareRundownProtection" => (Call::Allocate, 2, C::Stdcall, T::Pointer),
        "ExFreeCacheAwareRundownProtection" => (Call::Free, 1, C::Stdcall, T::Void),
        "ExAcquireRundownProtectionCacheAware" => (Call::Acquire(false), 1, C::Fastcall, T::U32),
        "ExAcquireRundownProtectionCacheAwareEx" => (Call::Acquire(true), 2, C::Fastcall, T::U32),
        "ExReleaseRundownProtectionCacheAware" => (Call::Release(false), 1, C::Fastcall, T::Void),
        "ExReleaseRundownProtectionCacheAwareEx" => (Call::Release(true), 2, C::Fastcall, T::Void),
        "ExWaitForRundownProtectionReleaseCacheAware" => (Call::Wait, 1, C::Fastcall, T::Void),
        _ => return None,
    })
}
pub(crate) struct State {
    model: RefCell<Rundowns>,
    native_effect_failure: bool,
    blocked: Vec<Blocked>,
}
impl State {
    pub fn new(architecture: Architecture) -> Self {
        Self {
            model: RefCell::new(Rundowns::new(architecture)),
            native_effect_failure: false,
            blocked: vec![],
        }
    }
}
#[derive(Debug, Serialize)]
pub struct ReferenceReport {
    pub address: u64,
    pub references: u64,
    pub running_down: bool,
    pub size: u64,
    pub mapped: u64,
    pub logical_cpus: u32,
    pub pool_type: u32,
    pub permissions: &'static str,
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub references: Vec<ReferenceReport>,
    pub api_denials: Vec<ApiDenial>,
    pub blocked_teardowns: Vec<Blocked>,
    pub native_effect_failure: bool,
    pub scope: &'static str,
}
pub(crate) fn report(engine: &Unicorn<Trace>) -> Report {
    let state = &engine.get_data().apis.rundown;
    let model = state.model.borrow();
    Report {
        references: model
            .records
            .iter()
            .map(|(address, record)| ReferenceReport {
                address: *address,
                references: record.references,
                running_down: record.running_down,
                size: record.allocation.requested,
                mapped: record.allocation.mapped,
                logical_cpus: record.logical_cpus,
                pool_type: record.pool_type,
                permissions: "---",
            })
            .collect(),
        api_denials: model.api_denials.clone(),
        blocked_teardowns: state.blocked.clone(),
        native_effect_failure: state.native_effect_failure,
        scope: "Opaque NX nonpaged-pool cache-aware rundown references on the modeled current CPU. Real contended waits require scheduler continuations; reinitialize/completed-state APIs and private Windows body layout remain unsupported.",
    }
}
pub(crate) fn completion_error(engine: &Unicorn<Trace>) -> Option<String> {
    let state = &engine.get_data().apis.rundown;
    if state.native_effect_failure {
        return Some("Cache-aware rundown native effect failed".to_owned());
    }
    if !state.blocked.is_empty() {
        return Some(
            "Blocked cache-aware rundown teardown requires kernel thread scheduling".to_owned(),
        );
    }
    None
}
pub(crate) fn require_api_access(
    engine: &Unicorn<Trace>,
    address: u64,
    size: u64,
    permissions: P,
) -> Result<()> {
    if permissions == P::NONE {
        return Ok(());
    }
    let access = if permissions.contains(P::WRITE) {
        "write"
    } else if permissions.contains(P::EXECUTE) {
        "execute"
    } else {
        "read"
    };
    engine
        .get_data()
        .apis
        .rundown
        .model
        .borrow_mut()
        .require_api_access(address, size, access)?;
    Ok(())
}
pub(crate) fn record_private_access(
    engine: &Unicorn<Trace>,
    address: u64,
    size: u64,
    access: &'static str,
) {
    let _ = engine
        .get_data()
        .apis
        .rundown
        .model
        .borrow_mut()
        .require_api_access(address, size, access);
}
pub(crate) fn require_pool_release(engine: &Unicorn<Trace>, base: u64, size: u64) -> Result<()> {
    engine
        .get_data()
        .apis
        .rundown
        .model
        .borrow()
        .require_pool_release(base, size)?;
    Ok(())
}
fn failure<T>(engine: &mut Unicorn<Trace>, error: anyhow::Error) -> Result<T> {
    engine.get_data_mut().apis.rundown.native_effect_failure = true;
    Err(error.context("Cache-aware rundown native effect failed; execution stopped"))
}
fn apply(engine: &mut Unicorn<Trace>, plan: Plan) -> Result<u64> {
    let effect = (|| -> Result<()> {
        if let Some(effect) = &plan.effect {
            match *effect {
                Effect::MapOpaque { address, size } => {
                    uc(engine.mem_map(address, size, Prot::NONE))?
                }
                Effect::Unmap { address, size } => {
                    mdl::require_pool_release(engine, address, size)?;
                    let end = address
                        .checked_add(size)
                        .context("Rundown native unmap overflow")?;
                    engine
                        .get_data_mut()
                        .cpu
                        .cache
                        .invalidate(address, size as usize);
                    uc(engine.ctl_remove_cache(address, end))?;
                    uc(engine.mem_unmap(address, size))?;
                    mdl::release_pool_backing(engine, address, size)?;
                }
            }
        }
        Ok(())
    })();
    if let Err(error) = effect {
        return failure(engine, error);
    }
    *engine.get_data().apis.rundown.model.borrow_mut() = plan.state;
    let state = &mut engine.get_data_mut().apis;
    state.memory = plan.memory;
    state.pool = plan.pool;
    if let Some(blocked) = plan.blocked {
        // Wait's running_down flag was set before the real blocking point in
        // the legacy baseline. Publish that state, but never a void completion.
        if state.rundown.blocked.len() < 1024 {
            state.rundown.blocked.push(blocked);
        }
        bail!("Blocked cache-aware rundown teardown requires kernel thread scheduling");
    }
    Ok(plan.result)
}
pub(super) fn call(engine: &mut Unicorn<Trace>, call: Call, args: &[u64]) -> Result<u64> {
    ensure!(
        engine.get_data().apis.kernel_mode,
        "Cache-aware rundown requires a driver target"
    );
    ensure!(
        !engine.get_data().apis.rundown.native_effect_failure,
        "Cache-aware rundown native effect failed; execution cannot resume"
    );
    let count = match call {
        Call::Allocate | Call::Acquire(true) | Call::Release(true) => 2,
        _ => 1,
    };
    ensure!(
        args.len() == count,
        "Cache-aware rundown argument count mismatch"
    );
    let plan = {
        let state = &engine.get_data().apis;
        let model = state.rundown.model.borrow();
        let irql = state.kernel.save().0;
        match call {
            Call::Allocate => {
                let profile = &engine.get_data().cpu.profile;
                let logical_cpus = profile
                    .cores
                    .checked_mul(profile.threads_per_core)
                    .context("Guest logical CPU count overflow")?;
                model.allocate(
                    &state.memory,
                    &state.pool,
                    AllocationRequest {
                        pool_type: args[0],
                        tag: args[1],
                        logical_cpus,
                        irql,
                    },
                )?
            }
            _ => {
                let operation = match call {
                    Call::Free => Operation::Free,
                    Call::Acquire(ex) => Operation::Acquire(if ex { args[1] as u32 } else { 1 }),
                    Call::Release(ex) => Operation::Release(if ex { args[1] as u32 } else { 1 }),
                    Call::Wait => Operation::Wait,
                    Call::Allocate => unreachable!(),
                };
                model.operation(&state.memory, &state.pool, args[0], operation, irql)?
            }
        }
    };
    apply(engine, plan)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn engine(architecture: Architecture) -> crate::NativeEngine {
        let mut engine = crate::new_engine(architecture).unwrap();
        engine.get_data_mut().apis.kernel_mode = true;
        engine
    }
    #[test]
    fn native_opaque_allocation_acquire_release_teardown_and_release_both_abis() {
        for architecture in [Architecture::X86, Architecture::X64] {
            let mut engine = engine(architecture);
            let address = call(&mut engine, Call::Allocate, &[0x600, 1]).unwrap();
            assert_ne!(address, 0);
            let regions = engine.mem_regions().unwrap();
            assert_eq!(
                regions
                    .iter()
                    .find(|region| region.begin == address)
                    .unwrap()
                    .perms,
                Prot::NONE.0 as u32
            );
            assert_eq!(
                call(&mut engine, Call::Acquire(true), &[address, 3]).unwrap(),
                1
            );
            assert_eq!(report(&engine).references[0].references, 3);
            call(&mut engine, Call::Release(true), &[address, 3]).unwrap();
            call(&mut engine, Call::Wait, &[address]).unwrap();
            assert_eq!(
                call(&mut engine, Call::Acquire(false), &[address]).unwrap(),
                0
            );
            call(&mut engine, Call::Free, &[address]).unwrap();
            assert!(report(&engine).references.is_empty());
            assert!(engine.mem_read_as_vec(address, 1).is_err());
            assert!(engine.get_data().apis.pool.allocations.is_empty());
        }
    }
    #[test]
    fn blocked_wait_preserves_running_down_and_does_not_complete_or_free() {
        let mut engine = engine(Architecture::X64);
        let address = call(&mut engine, Call::Allocate, &[0x600, 1]).unwrap();
        call(&mut engine, Call::Acquire(true), &[address, 3]).unwrap();
        assert!(call(&mut engine, Call::Wait, &[address]).is_err());
        let report = report(&engine);
        assert_eq!(report.references[0].references, 3);
        assert!(report.references[0].running_down);
        assert_eq!(report.blocked_teardowns.len(), 1);
        assert_eq!(engine.get_data().apis.pool.allocations.len(), 1);
        assert!(completion_error(&engine).is_some());
    }
    #[test]
    fn private_body_and_generic_pool_free_guards_cannot_bypass_typed_apis() {
        let mut engine = engine(Architecture::X86);
        let address = call(&mut engine, Call::Allocate, &[0x600, 1]).unwrap();
        assert!(require_api_access(&engine, address, 8, P::READ).is_err());
        assert!(require_api_access(&engine, address, 1, P::WRITE).is_err());
        require_api_access(&engine, address, 0, P::READ).unwrap();
        assert_eq!(report(&engine).api_denials.len(), 2);
        assert!(require_pool_release(&engine, address, 4096).is_err());
        assert!(call(&mut engine, Call::Release(false), &[address]).is_err());
        engine.get_data_mut().apis.kernel.restore((2, 0));
        assert!(call(&mut engine, Call::Free, &[address]).is_err());
    }
}
