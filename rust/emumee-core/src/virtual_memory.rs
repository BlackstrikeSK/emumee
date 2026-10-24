//! Private guest reservations and page commitment. Never allocates host memory.
use crate::{
    memory::{AddressSpace, PAGE, Permissions},
    pe::Architecture,
};
use std::collections::BTreeMap;
use thiserror::Error;

pub const COMMIT: u32 = 0x1000;
pub const RESERVE: u32 = 0x2000;
pub const DECOMMIT: u32 = 0x4000;
pub const RELEASE: u32 = 0x8000;
const GRANULARITY: u64 = 65536;
const MAX_RESERVED: u64 = 128 * 1024 * 1024;
const MAX_ALLOCATIONS: usize = 4096;

#[derive(Debug, Error)]
#[error("Guest virtual memory: {reason} (Win32 {win32})")]
pub struct VmError {
    pub win32: u32,
    pub reason: &'static str,
}
fn error(win32: u32, reason: &'static str) -> VmError {
    VmError { win32, reason }
}
type Result<T> = std::result::Result<T, VmError>;

pub fn permissions(protection: u32) -> Result<Permissions> {
    Ok(match protection {
        1 => Permissions::NONE,
        2 => Permissions::READ,
        4 => Permissions::RW,
        0x10 => Permissions::EXECUTE,
        0x20 => Permissions::RX,
        0x40 => Permissions::ALL,
        _ => return Err(error(87, "unsupported private page protection")),
    })
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Allocation {
    size: u64,
    pages: Vec<Option<u32>>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VirtualMemory {
    architecture: Architecture,
    allocations: BTreeMap<u64, Allocation>,
    reserved: u64,
}
#[derive(Clone, Debug)]
pub enum Change {
    Map {
        base: u64,
        size: u64,
    },
    Protect {
        base: u64,
        size: u64,
        permissions: Permissions,
    },
    Zero {
        base: u64,
        size: u64,
    },
    Unmap {
        base: u64,
        size: u64,
    },
}
pub struct Plan {
    pub memory: AddressSpace,
    pub state: VirtualMemory,
    pub changes: Vec<Change>,
    pub result: u64,
    pub old_protection: Option<u32>,
}
fn rounded_end(address: u64, size: u64) -> Result<u64> {
    if size == 0 {
        return Err(error(87, "empty range"));
    }
    address
        .checked_add(size)
        .and_then(|n| n.checked_add(PAGE - 1))
        .map(|n| n & !(PAGE - 1))
        .ok_or_else(|| error(87, "range overflow"))
}
impl VirtualMemory {
    pub fn new(architecture: Architecture) -> Self {
        Self {
            architecture,
            allocations: BTreeMap::new(),
            reserved: 0,
        }
    }
    fn plan(&self, memory: &AddressSpace) -> Plan {
        Plan {
            memory: memory.clone(),
            state: self.clone(),
            changes: vec![],
            result: 0,
            old_protection: None,
        }
    }
    fn allocation(&self, address: u64, size: u64) -> Result<(u64, &Allocation)> {
        let end = address
            .checked_add(size)
            .ok_or_else(|| error(487, "range overflow"))?;
        self.allocations
            .range(..=address)
            .next_back()
            .filter(|(base, a)| end <= **base + a.size)
            .map(|(base, a)| (*base, a))
            .ok_or_else(|| error(487, "range is not in one private reservation"))
    }
    fn free_base(&self, memory: &AddressSpace, size: u64) -> Result<u64> {
        let mut base = 0x10000000u64;
        let limit = if self.architecture == Architecture::X86 {
            0x7fff0000
        } else {
            0x00007fff00000000
        };
        for region in memory.regions() {
            if region.base + region.size <= base {
                continue;
            }
            if base
                .checked_add(size)
                .is_some_and(|end| end <= region.base && end <= limit)
            {
                return Ok(base);
            }
            base = (region.base + region.size)
                .checked_add(GRANULARITY - 1)
                .map(|n| n & !(GRANULARITY - 1))
                .ok_or_else(|| error(8, "guest address space exhausted"))?;
        }
        if base.checked_add(size).is_some_and(|end| end <= limit) {
            Ok(base)
        } else {
            Err(error(8, "guest address space exhausted"))
        }
    }
    pub fn allocate(
        &self,
        memory: &AddressSpace,
        address: u64,
        size: u64,
        flags: u32,
        protection: u32,
    ) -> Result<Plan> {
        if ![COMMIT, RESERVE, COMMIT | RESERVE].contains(&flags) {
            return Err(error(87, "allocation flags are not modeled"));
        }
        let prot = permissions(protection)?;
        let reserve = flags & RESERVE != 0 || address == 0;
        let base = if reserve {
            address & !(GRANULARITY - 1)
        } else {
            address & !(PAGE - 1)
        };
        let extent = rounded_end(address, size)?
            .checked_sub(base)
            .ok_or_else(|| error(87, "range overflow"))?;
        if extent > MAX_RESERVED {
            return Err(error(8, "reservation exceeds guest memory bound"));
        }
        let mut plan = self.plan(memory);
        let result = if reserve {
            if self.allocations.len() >= MAX_ALLOCATIONS
                || self
                    .reserved
                    .checked_add(extent)
                    .is_none_or(|n| n > MAX_RESERVED)
            {
                return Err(error(8, "guest reservation limit"));
            }
            let base = if address == 0 {
                self.free_base(memory, extent)?
            } else {
                base
            };
            let limit = if self.architecture == Architecture::X86 {
                0x7fff0000
            } else {
                0x00007fff00000000
            };
            if base < GRANULARITY || base.checked_add(extent).is_none_or(|end| end > limit) {
                return Err(error(487, "outside guest application address range"));
            }
            plan.memory
                .map(
                    base,
                    extent,
                    Permissions::NONE,
                    Some(1024),
                    "private virtual allocation",
                )
                .map_err(|_| error(487, "reservation overlaps mapped memory"))?;
            plan.state.allocations.insert(
                base,
                Allocation {
                    size: extent,
                    pages: vec![None; (extent / PAGE) as usize],
                },
            );
            plan.state.reserved += extent;
            plan.changes.push(Change::Map { base, size: extent });
            base
        } else {
            self.allocation(base, extent)?;
            base
        };
        if flags & COMMIT != 0 {
            let (owner, _) = plan.state.allocation(result, extent)?;
            let a = plan.state.allocations.get_mut(&owner).unwrap();
            let first = ((result - owner) / PAGE) as usize;
            let last = first + (extent / PAGE) as usize;
            // Native Windows reference: recommit preserves bytes and reapplies
            // protection. Fresh/decommitted backing is already zeroed.
            a.pages[first..last].fill(Some(protection));
            plan.memory
                .protect(result, extent, prot)
                .map_err(|_| error(487, "commit metadata rejected"))?;
            plan.changes.push(Change::Protect {
                base: result,
                size: extent,
                permissions: prot,
            });
        }
        plan.result = result;
        Ok(plan)
    }
    pub fn protect(
        &self,
        memory: &AddressSpace,
        address: u64,
        size: u64,
        protection: u32,
    ) -> Result<Plan> {
        let prot = permissions(protection)?;
        let base = address & !(PAGE - 1);
        let extent = rounded_end(address, size)?
            .checked_sub(base)
            .ok_or_else(|| error(87, "range overflow"))?;
        let (owner, allocation) = self.allocation(base, extent)?;
        let first = ((base - owner) / PAGE) as usize;
        let last = first + (extent / PAGE) as usize;
        if allocation.pages[first..last].iter().any(Option::is_none) {
            return Err(error(487, "protection range contains uncommitted pages"));
        }
        let mut plan = self.plan(memory);
        plan.old_protection = allocation.pages[first];
        plan.state.allocations.get_mut(&owner).unwrap().pages[first..last].fill(Some(protection));
        plan.memory
            .protect(base, extent, prot)
            .map_err(|_| error(487, "protection metadata rejected"))?;
        plan.changes.push(Change::Protect {
            base,
            size: extent,
            permissions: prot,
        });
        plan.result = 1;
        Ok(plan)
    }
    pub fn free(&self, memory: &AddressSpace, address: u64, size: u64, flags: u32) -> Result<Plan> {
        let mut plan = self.plan(memory);
        if flags == RELEASE {
            if size != 0 {
                return Err(error(87, "release requires zero size"));
            }
            let a = self
                .allocations
                .get(&address)
                .ok_or_else(|| error(487, "release requires original allocation base"))?;
            plan.memory
                .unmap(address, a.size)
                .map_err(|_| error(487, "release metadata rejected"))?;
            plan.state.allocations.remove(&address);
            plan.state.reserved -= a.size;
            plan.changes.push(Change::Unmap {
                base: address,
                size: a.size,
            });
        } else if flags == DECOMMIT {
            let (base, extent) = if size == 0 {
                let a = self
                    .allocations
                    .get(&address)
                    .ok_or_else(|| error(487, "zero-sized decommit requires allocation base"))?;
                (address, a.size)
            } else {
                let base = address & !(PAGE - 1);
                (base, rounded_end(address, size)? - base)
            };
            let (owner, _) = self.allocation(base, extent)?;
            let a = plan.state.allocations.get_mut(&owner).unwrap();
            let first = ((base - owner) / PAGE) as usize;
            a.pages[first..first + (extent / PAGE) as usize].fill(None);
            plan.memory
                .protect(base, extent, Permissions::NONE)
                .map_err(|_| error(487, "decommit metadata rejected"))?;
            plan.changes.push(Change::Protect {
                base,
                size: extent,
                permissions: Permissions::NONE,
            });
            plan.changes.push(Change::Zero { base, size: extent });
        } else {
            return Err(error(87, "free flags are not modeled"));
        }
        plan.result = 1;
        Ok(plan)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn commitment_protection_and_release_preserve_allocation_boundaries() {
        let memory = AddressSpace::new(Architecture::X86);
        let vm = VirtualMemory::new(Architecture::X86);
        let reserve = vm
            .allocate(&memory, 0x10001234, 0x2000, RESERVE, 4)
            .unwrap();
        assert_eq!(reserve.result, 0x10000000);
        assert!(!reserve.memory.allows(reserve.result, 1, Permissions::READ));
        let commit = reserve
            .state
            .allocate(&reserve.memory, 0x10001fff, 2, COMMIT, 4)
            .unwrap();
        assert!(
            commit
                .memory
                .allows(0x10001000, 2 * PAGE, Permissions::WRITE)
        );
        assert!(!commit.memory.allows(0x10000000, 1, Permissions::READ));
        assert!(
            commit
                .state
                .protect(&commit.memory, 0x10000000, 2 * PAGE, 2)
                .is_err()
        );
        let readonly = commit
            .state
            .protect(&commit.memory, 0x10001fff, 2, 2)
            .unwrap();
        assert_eq!(readonly.old_protection, Some(4));
        assert!(!readonly.memory.allows(0x10001000, 1, Permissions::WRITE));
        let decommit = readonly
            .state
            .free(&readonly.memory, 0x10000000, 0, DECOMMIT)
            .unwrap();
        assert!(!decommit.memory.allows(0x10001000, 1, Permissions::READ));
        assert!(
            decommit
                .state
                .free(&decommit.memory, 0x10001000, 0, RELEASE)
                .is_err()
        );
        let release = decommit
            .state
            .free(&decommit.memory, 0x10000000, 0, RELEASE)
            .unwrap();
        assert_eq!(release.memory.regions().count(), 0);
    }
    #[test]
    fn failed_plans_never_mutate_live_state_and_recommit_reapplies_protection() {
        let memory = AddressSpace::new(Architecture::X64);
        let vm = VirtualMemory::new(Architecture::X64);
        let first = vm.allocate(&memory, 0, 8192, COMMIT | RESERVE, 4).unwrap();
        let readonly = first
            .state
            .protect(&first.memory, first.result, 1, 2)
            .unwrap();
        let again = readonly
            .state
            .allocate(&readonly.memory, first.result, 8192, COMMIT, 4)
            .unwrap();
        assert!(again.memory.allows(first.result, 8192, Permissions::WRITE));
        assert_eq!(again.changes.len(), 1);
        let before = again.state.clone();
        for (address, size, flags, prot) in [
            (first.result, 1, RESERVE, 4),
            (u64::MAX, 5, COMMIT, 4),
            (0, 0, RESERVE, 4),
            (0, 1, 0x80000, 4),
            (0, 1, RESERVE, 0x104),
        ] {
            assert!(
                again
                    .state
                    .allocate(&again.memory, address, size, flags, prot)
                    .is_err()
            );
            assert_eq!(again.state, before);
        }
    }
    #[test]
    fn allocations_skip_images_and_cannot_cross_reservations() {
        let mut memory = AddressSpace::new(Architecture::X86);
        memory
            .map(0x10000000, 65536, Permissions::RX, None, "image")
            .unwrap();
        let vm = VirtualMemory::new(Architecture::X86);
        let first = vm.allocate(&memory, 0, 65536, COMMIT, 4).unwrap();
        assert_eq!(first.result, 0x10010000);
        let second = first
            .state
            .allocate(&first.memory, 0, 65536, COMMIT, 4)
            .unwrap();
        assert_eq!(second.result, 0x10020000);
        assert!(
            second
                .state
                .protect(&second.memory, 0x1001ffff, 2, 2)
                .is_err()
        );
        assert!(
            second
                .state
                .free(&second.memory, first.result, 1, RELEASE)
                .is_err()
        );
        assert!(
            second
                .state
                .allocate(&second.memory, 0x80000000, 4096, RESERVE, 4)
                .is_err()
        );
    }
}
