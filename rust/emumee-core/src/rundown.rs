//! Cache-aware rundown bookkeeping on the modeled current CPU.
//!
//! Opaque provider-owned NX pool reservations expose no invented Windows body.
//! Contended teardown returns an explicit blocked plan, never a completed wait.
//! Reinitialization/completed-state exports are outside the legacy baseline.
use crate::{
    memory::{AddressSpace, Permissions as P},
    pe::Architecture,
    pool::{Allocation, Pool},
};
use serde::Serialize;
use std::collections::BTreeMap;
use thiserror::Error;
const LIMIT: usize = 1024;

#[derive(Debug, Error)]
#[error("Guest cache-aware rundown: {0}")]
pub struct RundownError(pub &'static str);
type Result<T> = std::result::Result<T, RundownError>;
#[derive(Clone, Debug, Serialize)]
pub struct Record {
    pub allocation: Allocation,
    pub pool_type: u32,
    pub logical_cpus: u32,
    pub references: u64,
    pub running_down: bool,
}
#[derive(Clone, Debug, Serialize)]
pub struct ApiDenial {
    pub offset: String,
    pub size: u64,
    pub access: &'static str,
}
#[derive(Clone, Debug, Serialize)]
pub struct Rundowns {
    architecture: Architecture,
    pub records: BTreeMap<u64, Record>,
    pub api_denials: Vec<ApiDenial>,
}
#[derive(Clone, Copy, Debug)]
pub struct AllocationRequest {
    pub pool_type: u64,
    pub tag: u64,
    pub logical_cpus: u32,
    pub irql: u8,
}
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub enum Teardown {
    Wait,
    Free,
}
#[derive(Clone, Copy, Debug)]
pub enum Operation {
    Acquire(u32),
    Release(u32),
    Wait,
    Free,
    Reinitialize,
    Completed,
}
#[derive(Clone, Debug, Serialize)]
pub struct Blocked {
    pub address: u64,
    pub operation: Teardown,
    pub references: u64,
}
#[derive(Clone, Debug)]
pub enum Effect {
    MapOpaque { address: u64, size: u64 },
    Unmap { address: u64, size: u64 },
}
pub struct Plan {
    pub state: Rundowns,
    pub memory: AddressSpace,
    pub pool: Pool,
    pub effect: Option<Effect>,
    pub result: u64,
    pub blocked: Option<Blocked>,
}
impl Rundowns {
    pub fn new(architecture: Architecture) -> Self {
        Self {
            architecture,
            records: BTreeMap::new(),
            api_denials: vec![],
        }
    }
    fn plan(&self, memory: &AddressSpace, pool: &Pool) -> Plan {
        Plan {
            state: self.clone(),
            memory: memory.clone(),
            pool: pool.clone(),
            effect: None,
            result: 0,
            blocked: None,
        }
    }
    pub fn allocate(
        &self,
        memory: &AddressSpace,
        pool: &Pool,
        request: AllocationRequest,
    ) -> Result<Plan> {
        if request.irql > 1 {
            return Err(RundownError("allocation above APC_LEVEL"));
        }
        let mut plan = self.plan(memory, pool);
        if self.records.len() >= LIMIT {
            return Ok(plan);
        }
        if !(1..=64).contains(&request.logical_cpus) {
            return Err(RundownError(
                "logical CPU count is outside the modeled profile",
            ));
        }
        let pool_type = request.pool_type as u32;
        if !matches!(pool_type & !0x500, 0x200 | 0x204) {
            return Err(RundownError(
                "only NX nonpaged pool types and cold/zero modifiers are modeled",
            ));
        }
        let size = 64 * (u64::from(request.logical_cpus) + 1);
        let flags = 0x40 | if pool_type & 0x400 == 0 { 2 } else { 0 };
        let Some(allocation) = pool
            .prepare(
                memory,
                self.architecture,
                flags,
                size,
                request.tag as u32,
                request.irql,
            )
            .map_err(|_| RundownError("rundown pool allocation profile is unsupported"))?
        else {
            return Ok(plan);
        };
        plan.memory
            .map(
                allocation.base,
                allocation.mapped,
                P::NONE,
                None,
                "private EX_RUNDOWN_REF_CACHE_AWARE",
            )
            .map_err(|_| RundownError("opaque rundown reservation could not be mapped"))?;
        plan.result = allocation.base;
        plan.effect = Some(Effect::MapOpaque {
            address: allocation.base,
            size: allocation.mapped,
        });
        plan.state.records.insert(
            allocation.base,
            Record {
                allocation: allocation.clone(),
                pool_type,
                logical_cpus: request.logical_cpus,
                references: 0,
                running_down: false,
            },
        );
        plan.pool.commit_allocation(allocation);
        Ok(plan)
    }
    pub fn operation(
        &self,
        memory: &AddressSpace,
        pool: &Pool,
        address: u64,
        operation: Operation,
        irql: u8,
    ) -> Result<Plan> {
        let record = self
            .records
            .get(&address)
            .ok_or(RundownError("invalid cache-aware rundown reference"))?;
        if !memory.allows(address, record.allocation.mapped, P::NONE) {
            return Err(RundownError(
                "cache-aware rundown backing is no longer mapped",
            ));
        }
        let live = pool.allocations.get(&address).ok_or(RundownError(
            "cache-aware rundown pool ownership is missing",
        ))?;
        if live.tag != record.allocation.tag
            || live.requested != record.allocation.requested
            || live.mapped != record.allocation.mapped
            || live.paged
            || live.executable
        {
            return Err(RundownError("cache-aware rundown pool ownership changed"));
        }
        if irql > 2 {
            return Err(RundownError("access above DISPATCH_LEVEL"));
        }
        let mut plan = self.plan(memory, pool);
        match operation {
            Operation::Acquire(count) => {
                if record.running_down {
                    return Ok(plan);
                }
                let maximum = if self.architecture == Architecture::X86 {
                    i32::MAX as u64
                } else {
                    i64::MAX as u64
                };
                let references = record
                    .references
                    .checked_add(u64::from(count))
                    .filter(|total| *total <= maximum)
                    .ok_or(RundownError("reference count overflow"))?;
                plan.state.records.get_mut(&address).unwrap().references = references;
                plan.result = 1;
            }
            Operation::Release(count) => {
                let references = record
                    .references
                    .checked_sub(u64::from(count))
                    .ok_or(RundownError("release exceeds acquired references"))?;
                plan.state.records.get_mut(&address).unwrap().references = references;
            }
            Operation::Wait | Operation::Free => {
                if irql > 1 {
                    return Err(RundownError("teardown above APC_LEVEL"));
                }
                let teardown = if matches!(operation, Operation::Wait) {
                    Teardown::Wait
                } else {
                    Teardown::Free
                };
                if teardown == Teardown::Wait {
                    plan.state.records.get_mut(&address).unwrap().running_down = true;
                }
                if record.references != 0 {
                    plan.blocked = Some(Blocked {
                        address,
                        operation: teardown,
                        references: record.references,
                    });
                    return Ok(plan);
                }
                if teardown == Teardown::Free {
                    pool.prepare_free(address, Some(record.allocation.tag), irql)
                        .map_err(|_| RundownError("rundown pool release failed validation"))?;
                    plan.memory
                        .unmap(address, record.allocation.mapped)
                        .map_err(|_| RundownError("rundown reservation release failed"))?;
                    plan.pool.commit_free(address);
                    plan.state.records.remove(&address);
                    plan.effect = Some(Effect::Unmap {
                        address,
                        size: record.allocation.mapped,
                    });
                }
            }
            Operation::Reinitialize | Operation::Completed => {
                return Err(RundownError(
                    "reinitialization/completed-state operations are not modeled",
                ));
            }
        }
        Ok(plan)
    }
    /// Generic pool release must not bypass the typed object's rundown lifecycle.
    pub fn require_pool_release(&self, base: u64, size: u64) -> Result<()> {
        let end = base
            .checked_add(size)
            .ok_or(RundownError("pool release range overflow"))?;
        if self.records.values().any(|record| {
            base < record.allocation.base + record.allocation.mapped && record.allocation.base < end
        }) {
            return Err(RundownError(
                "pool release would bypass a live cache-aware rundown object",
            ));
        }
        Ok(())
    }
    pub fn require_api_access(
        &mut self,
        address: u64,
        size: u64,
        access: &'static str,
    ) -> Result<()> {
        if size == 0 {
            return Ok(());
        }
        let end = address
            .checked_add(size)
            .ok_or(RundownError("API access range overflow"))?;
        if let Some(record) = self.records.values().find(|record| {
            address < record.allocation.base + record.allocation.mapped
                && record.allocation.base < end
        }) {
            if self.api_denials.len() < 64 {
                let base = record.allocation.base;
                let offset = if address < base {
                    format!("-0x{:x}", base - address)
                } else {
                    format!("0x{:x}", address - base)
                };
                self.api_denials.push(ApiDenial {
                    offset,
                    size,
                    access,
                });
            }
            return Err(RundownError(
                "unmodeled private EX_RUNDOWN_REF_CACHE_AWARE API access",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn allocated(architecture: Architecture) -> Plan {
        Rundowns::new(architecture)
            .allocate(
                &AddressSpace::new(architecture),
                &Pool::default(),
                AllocationRequest {
                    pool_type: 0x600,
                    tag: 1,
                    logical_cpus: 12,
                    irql: 0,
                },
            )
            .unwrap()
    }
    #[test]
    fn acquire_release_wait_rejects_future_acquire_and_free_releases_owned_mapping() {
        for architecture in [Architecture::X86, Architecture::X64] {
            let allocated = allocated(architecture);
            let address = allocated.result;
            assert_ne!(address, 0);
            assert_eq!(
                allocated.state.records[&address].allocation.requested,
                64 * 13
            );
            assert!(!allocated.memory.allows(address, 1, P::READ));
            assert!(!allocated.memory.allows(address, 1, P::EXECUTE));
            let acquired = allocated
                .state
                .operation(
                    &allocated.memory,
                    &allocated.pool,
                    address,
                    Operation::Acquire(3),
                    2,
                )
                .unwrap();
            assert_eq!(acquired.result, 1);
            assert_eq!(acquired.state.records[&address].references, 3);
            let released = acquired
                .state
                .operation(
                    &acquired.memory,
                    &acquired.pool,
                    address,
                    Operation::Release(3),
                    2,
                )
                .unwrap();
            let waited = released
                .state
                .operation(
                    &released.memory,
                    &released.pool,
                    address,
                    Operation::Wait,
                    1,
                )
                .unwrap();
            assert!(waited.state.records[&address].running_down);
            assert!(waited.blocked.is_none());
            assert_eq!(
                waited
                    .state
                    .operation(
                        &waited.memory,
                        &waited.pool,
                        address,
                        Operation::Acquire(1),
                        0
                    )
                    .unwrap()
                    .result,
                0
            );
            let freed = waited
                .state
                .operation(&waited.memory, &waited.pool, address, Operation::Free, 0)
                .unwrap();
            assert!(freed.state.records.is_empty());
            assert!(freed.pool.allocations.is_empty());
            assert!(!freed.memory.allows(address, 1, P::NONE));
            assert!(
                freed
                    .state
                    .operation(
                        &freed.memory,
                        &freed.pool,
                        address,
                        Operation::Acquire(1),
                        0
                    )
                    .is_err()
            );
        }
    }
    #[test]
    fn contended_wait_sets_running_down_without_fabricating_teardown_completion() {
        let allocated = allocated(Architecture::X64);
        let address = allocated.result;
        let acquired = allocated
            .state
            .operation(
                &allocated.memory,
                &allocated.pool,
                address,
                Operation::Acquire(3),
                0,
            )
            .unwrap();
        let wait = acquired
            .state
            .operation(
                &acquired.memory,
                &acquired.pool,
                address,
                Operation::Wait,
                0,
            )
            .unwrap();
        assert!(wait.state.records[&address].running_down);
        assert!(wait.effect.is_none());
        assert_eq!(wait.blocked.as_ref().unwrap().operation, Teardown::Wait);
        assert_eq!(wait.blocked.as_ref().unwrap().references, 3);
        assert_eq!(wait.pool.allocations.len(), 1);
        let free = acquired
            .state
            .operation(
                &acquired.memory,
                &acquired.pool,
                address,
                Operation::Free,
                0,
            )
            .unwrap();
        assert!(!free.state.records[&address].running_down);
        assert_eq!(free.blocked.unwrap().operation, Teardown::Free);
        // A future scheduler may release the real holders and retry the same
        // operation; the model itself has not scheduled or completed that work.
        let released = wait
            .state
            .operation(&wait.memory, &wait.pool, address, Operation::Release(3), 0)
            .unwrap();
        assert!(
            released
                .state
                .operation(
                    &released.memory,
                    &released.pool,
                    address,
                    Operation::Wait,
                    0
                )
                .unwrap()
                .blocked
                .is_none()
        );
    }
    #[test]
    fn overflow_underflow_zero_counts_and_reinitialization_are_explicit() {
        for architecture in [Architecture::X86, Architecture::X64] {
            let mut plan = allocated(architecture);
            let address = plan.result;
            assert_eq!(
                plan.state
                    .operation(&plan.memory, &plan.pool, address, Operation::Acquire(0), 0)
                    .unwrap()
                    .result,
                1
            );
            assert!(
                plan.state
                    .operation(&plan.memory, &plan.pool, address, Operation::Release(1), 0)
                    .is_err()
            );
            plan.state.records.get_mut(&address).unwrap().references =
                if architecture == Architecture::X86 {
                    i32::MAX as u64
                } else {
                    i64::MAX as u64
                };
            assert!(
                plan.state
                    .operation(&plan.memory, &plan.pool, address, Operation::Acquire(1), 0)
                    .is_err()
            );
            assert!(
                plan.state
                    .operation(
                        &plan.memory,
                        &plan.pool,
                        address,
                        Operation::Reinitialize,
                        0
                    )
                    .is_err()
            );
            assert!(
                plan.state
                    .operation(&plan.memory, &plan.pool, address, Operation::Completed, 0)
                    .is_err()
            );
        }
    }
    #[test]
    fn irql_pool_flags_topology_and_allocation_failures_preserve_state() {
        for architecture in [Architecture::X86, Architecture::X64] {
            let state = Rundowns::new(architecture);
            let memory = AddressSpace::new(architecture);
            let pool = Pool::default();
            for pool_type in [0, 1, 4, 5, 0x201, 0x800] {
                assert!(
                    state
                        .allocate(
                            &memory,
                            &pool,
                            AllocationRequest {
                                pool_type,
                                tag: 1,
                                logical_cpus: 1,
                                irql: 0
                            }
                        )
                        .is_err()
                );
            }
            for logical_cpus in [0, 65, u32::MAX] {
                assert!(
                    state
                        .allocate(
                            &memory,
                            &pool,
                            AllocationRequest {
                                pool_type: 0x600,
                                tag: 1,
                                logical_cpus,
                                irql: 0
                            }
                        )
                        .is_err()
                );
            }
            assert!(
                state
                    .allocate(
                        &memory,
                        &pool,
                        AllocationRequest {
                            pool_type: 0x600,
                            tag: 1,
                            logical_cpus: 1,
                            irql: 2
                        }
                    )
                    .is_err()
            );
            assert_eq!(
                state
                    .allocate(
                        &memory,
                        &pool,
                        AllocationRequest {
                            pool_type: 0x600,
                            tag: 0,
                            logical_cpus: 1,
                            irql: 0
                        }
                    )
                    .unwrap()
                    .result,
                if architecture == Architecture::X64 {
                    0xffffb00000000000
                } else {
                    0xe0000000
                }
            );
            let allocated = allocated(architecture);
            let address = allocated.result;
            assert!(
                allocated
                    .state
                    .operation(
                        &allocated.memory,
                        &allocated.pool,
                        address,
                        Operation::Acquire(1),
                        3
                    )
                    .is_err()
            );
            assert!(
                allocated
                    .state
                    .operation(
                        &allocated.memory,
                        &allocated.pool,
                        address,
                        Operation::Wait,
                        2
                    )
                    .is_err()
            );
            assert!(
                allocated
                    .state
                    .operation(
                        &allocated.memory,
                        &allocated.pool,
                        address,
                        Operation::Free,
                        2
                    )
                    .is_err()
            );
        }
    }
    #[test]
    fn opaque_access_generic_free_and_missing_backing_cannot_bypass_lifecycle() {
        let mut plan = allocated(Architecture::X64);
        let address = plan.result;
        assert!(plan.state.require_pool_release(address, 4096).is_err());
        assert!(plan.state.require_api_access(address, 8, "read").is_err());
        assert!(
            plan.state
                .require_api_access(address - 1, 2, "write")
                .is_err()
        );
        assert_eq!(plan.state.api_denials[1].offset, "-0x1");
        plan.state.require_api_access(address, 0, "read").unwrap();
        for _ in 0..100 {
            assert!(plan.state.require_api_access(address, 1, "read").is_err());
        }
        assert_eq!(plan.state.api_denials.len(), 64);
        assert!(
            plan.state
                .operation(
                    &plan.memory,
                    &Pool::default(),
                    address,
                    Operation::Acquire(1),
                    0
                )
                .is_err()
        );
        plan.memory.unmap(address, 4096).unwrap();
        assert!(
            plan.state
                .operation(&plan.memory, &plan.pool, address, Operation::Acquire(1), 0)
                .is_err()
        );
    }
}
