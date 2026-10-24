//! Bounded synthetic guest heaps. One private reservation backs each live
//! block; no Windows heap headers, host allocations or host heap API is exposed.
use crate::{
    memory::{AddressSpace, Permissions},
    virtual_memory::{self as vm, Plan as VmPlan, VirtualMemory},
};
use serde::Serialize;
use std::collections::BTreeMap;
use thiserror::Error;
pub const PROCESS_HEAP: u64 = 0x5b000000;
const MAX_HEAPS: usize = 64;
const MAX_BLOCKS: usize = 4096;
const MAX_SIZE: u64 = 128 * 1024 * 1024;
#[derive(Debug, Error)]
pub enum HeapError {
    #[error("Guest heap profile unsupported: {0}")]
    Unsupported(&'static str),
    #[error("Guest heap ownership/backing violation: {0}")]
    Invalid(&'static str),
    #[error("Guest heap resource limit")]
    Limit,
}
type Result<T> = std::result::Result<T, HeapError>;
#[derive(Clone, Debug, Serialize)]
struct Heap {
    executable: bool,
}
#[derive(Clone, Debug, Serialize)]
struct Block {
    heap: u64,
    size: u64,
    capacity: u64,
}
#[derive(Clone, Debug, Serialize)]
pub struct Heaps {
    heaps: BTreeMap<u64, Heap>,
    blocks: BTreeMap<u64, Block>,
    next: u64,
}
impl Default for Heaps {
    fn default() -> Self {
        Self {
            heaps: BTreeMap::from([(PROCESS_HEAP, Heap { executable: false })]),
            blocks: BTreeMap::new(),
            next: PROCESS_HEAP + 8,
        }
    }
}
pub struct Plan {
    pub memory: VmPlan,
    pub state: Heaps,
    pub copy: Option<(u64, u64, u64)>,
    pub zero: Option<(u64, u64)>,
}
fn memory_error(error: vm::VmError) -> HeapError {
    if error.win32 == 8 {
        HeapError::Limit
    } else {
        HeapError::Invalid("private reservation no longer matches heap metadata")
    }
}
fn noop(memory: &AddressSpace, vm: &VirtualMemory, result: u64) -> VmPlan {
    VmPlan {
        memory: memory.clone(),
        state: vm.clone(),
        changes: Vec::new(),
        result,
        old_protection: None,
    }
}
impl Heaps {
    pub fn create(&mut self, flags: u32, initial: u64, maximum: u64) -> Result<u64> {
        if flags & !(1 | 0x40000) != 0 || initial != 0 || maximum != 0 {
            return Err(HeapError::Unsupported(
                "initial/fixed arenas, exception or other create flags",
            ));
        }
        if self.heaps.len() >= MAX_HEAPS {
            return Err(HeapError::Limit);
        }
        let handle = self.next;
        self.next += 8;
        self.heaps.insert(
            handle,
            Heap {
                executable: flags & 0x40000 != 0,
            },
        );
        Ok(handle)
    }
    fn heap(&self, handle: u64, flags: u32, allowed: u32) -> Result<&Heap> {
        if flags & !allowed != 0 {
            return Err(HeapError::Unsupported("heap call flags/exception dispatch"));
        }
        if handle == PROCESS_HEAP && flags & 1 != 0 {
            return Err(HeapError::Unsupported("unserialized process heap access"));
        }
        self.heaps
            .get(&handle)
            .ok_or(HeapError::Invalid("unknown heap handle"))
    }
    fn block(&self, heap: u64, address: u64) -> Result<&Block> {
        self.blocks
            .get(&address)
            .filter(|block| block.heap == heap)
            .ok_or(HeapError::Invalid("unknown, freed or wrong-heap pointer"))
    }
    pub fn owns_mapping(&self, address: u64) -> bool {
        self.blocks
            .range(..=address)
            .next_back()
            .is_some_and(|(base, block)| address < *base + block.capacity)
    }
    pub fn size(&self, heap: u64, flags: u32, address: u64) -> Result<u64> {
        self.heap(heap, flags, 1)?;
        Ok(self.block(heap, address)?.size)
    }
    pub fn allocate(
        &self,
        vm: &VirtualMemory,
        memory: &AddressSpace,
        heap: u64,
        flags: u32,
        size: u64,
    ) -> Result<Plan> {
        let metadata = self.heap(heap, flags, 1 | 8)?;
        if size > MAX_SIZE || self.blocks.len() >= MAX_BLOCKS {
            return Err(HeapError::Limit);
        }
        let plan = vm
            .allocate(
                memory,
                0,
                size.max(1),
                vm::RESERVE | vm::COMMIT,
                if metadata.executable { 0x40 } else { 4 },
            )
            .map_err(memory_error)?;
        let address = plan.result;
        let mut state = self.clone();
        state.blocks.insert(
            address,
            Block {
                heap,
                size,
                capacity: size.max(1).div_ceil(4096) * 4096,
            },
        );
        Ok(Plan {
            memory: plan,
            state,
            copy: None,
            zero: None,
        })
    }
    pub fn free(
        &self,
        vm: &VirtualMemory,
        memory: &AddressSpace,
        heap: u64,
        flags: u32,
        address: u64,
    ) -> Result<Plan> {
        self.heap(heap, flags, 1)?;
        if address == 0 {
            return Ok(Plan {
                memory: noop(memory, vm, 1),
                state: self.clone(),
                copy: None,
                zero: None,
            });
        }
        self.block(heap, address)?;
        let plan = vm
            .free(memory, address, 0, vm::RELEASE)
            .map_err(memory_error)?;
        let mut state = self.clone();
        state.blocks.remove(&address);
        Ok(Plan {
            memory: plan,
            state,
            copy: None,
            zero: None,
        })
    }
    pub fn reallocate(
        &self,
        vm: &VirtualMemory,
        memory: &AddressSpace,
        heap: u64,
        flags: u32,
        address: u64,
        size: u64,
    ) -> Result<Plan> {
        self.heap(heap, flags, 1 | 8 | 0x10)?;
        let old = self.block(heap, address)?;
        if size > MAX_SIZE {
            return Err(HeapError::Limit);
        }
        if size.max(1) <= old.capacity {
            let zero = if flags & 8 != 0 && size > old.size {
                let start = address + old.size;
                let length = size - old.size;
                if !memory.allows(start, length, Permissions::WRITE) {
                    return Err(HeapError::Invalid("zero extension is not writable"));
                }
                Some((start, length))
            } else {
                None
            };
            let mut state = self.clone();
            state.blocks.get_mut(&address).unwrap().size = size;
            return Ok(Plan {
                memory: noop(memory, vm, address),
                state,
                copy: None,
                zero,
            });
        }
        if flags & 0x10 != 0 {
            return Err(HeapError::Limit);
        }
        if old.size > 0 && !memory.allows(address, old.size.min(size), Permissions::READ) {
            return Err(HeapError::Invalid("reallocation source is not readable"));
        }
        let mut allocation = self.allocate(vm, memory, heap, flags & !0x10, size)?;
        let target = allocation.memory.result;
        let release = allocation
            .memory
            .state
            .free(&allocation.memory.memory, address, 0, vm::RELEASE)
            .map_err(memory_error)?;
        allocation.memory.changes.extend(release.changes);
        allocation.memory.state = release.state;
        allocation.memory.memory = release.memory;
        allocation.state.blocks.remove(&address);
        allocation.copy = Some((address, target, old.size.min(size)));
        Ok(allocation)
    }
    pub fn destroy(&self, vm: &VirtualMemory, memory: &AddressSpace, heap: u64) -> Result<Plan> {
        self.heap(heap, 0, 0)?;
        if heap == PROCESS_HEAP {
            return Err(HeapError::Unsupported("destroying the process heap"));
        }
        let mut plan = noop(memory, vm, 1);
        let mut state = self.clone();
        for (address, block) in &self.blocks {
            if block.heap == heap {
                let release = plan
                    .state
                    .free(&plan.memory, *address, 0, vm::RELEASE)
                    .map_err(memory_error)?;
                plan.changes.extend(release.changes);
                plan.state = release.state;
                plan.memory = release.memory;
                state.blocks.remove(address);
            }
        }
        state.heaps.remove(&heap);
        Ok(Plan {
            memory: plan,
            state,
            copy: None,
            zero: None,
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::Architecture;
    #[test]
    fn ownership_size_zero_blocks_and_destroy_are_transactional() {
        for arch in [Architecture::X86, Architecture::X64] {
            let memory = AddressSpace::new(arch);
            let vm = VirtualMemory::new(arch);
            let mut heaps = Heaps::default();
            let private = heaps.create(0, 0, 0).unwrap();
            let block = heaps.allocate(&vm, &memory, private, 8, 0).unwrap();
            assert_ne!(block.memory.result, 0);
            assert_eq!(
                block.state.size(private, 0, block.memory.result).unwrap(),
                0
            );
            assert!(
                block
                    .memory
                    .memory
                    .allows(block.memory.result, 1, Permissions::RW)
            );
            assert!(
                block
                    .state
                    .free(
                        &block.memory.state,
                        &block.memory.memory,
                        PROCESS_HEAP,
                        0,
                        block.memory.result
                    )
                    .is_err()
            );
            assert_eq!(heaps.blocks.len(), 0);
            let freed = block
                .state
                .destroy(&block.memory.state, &block.memory.memory, private)
                .unwrap();
            assert!(!freed.state.owns_mapping(block.memory.result));
            assert_eq!(freed.memory.memory.regions().count(), 0);
            assert!(
                freed
                    .state
                    .allocate(&freed.memory.state, &freed.memory.memory, private, 0, 1)
                    .is_err()
            );
        }
    }
    #[test]
    fn resize_plans_preserve_old_on_failure_and_separate_copy_from_zero_extension() {
        let memory = AddressSpace::new(Architecture::X64);
        let vm = VirtualMemory::new(Architecture::X64);
        let heaps = Heaps::default();
        let old = heaps.allocate(&vm, &memory, PROCESS_HEAP, 0, 17).unwrap();
        let address = old.memory.result;
        assert!(matches!(
            old.state.reallocate(
                &old.memory.state,
                &old.memory.memory,
                PROCESS_HEAP,
                0x10,
                address,
                8192
            ),
            Err(HeapError::Limit)
        ));
        assert_eq!(old.state.size(PROCESS_HEAP, 0, address).unwrap(), 17);
        let same = old
            .state
            .reallocate(
                &old.memory.state,
                &old.memory.memory,
                PROCESS_HEAP,
                8,
                address,
                32,
            )
            .unwrap();
        assert_eq!(same.memory.result, address);
        assert_eq!(same.zero, Some((address + 17, 15)));
        let moved = old
            .state
            .reallocate(
                &old.memory.state,
                &old.memory.memory,
                PROCESS_HEAP,
                8,
                address,
                8192,
            )
            .unwrap();
        assert_ne!(moved.memory.result, address);
        assert_eq!(moved.copy, Some((address, moved.memory.result, 17)));
        assert!(!moved.memory.memory.allows(address, 1, Permissions::READ));
    }
    #[test]
    fn executable_and_nx_heaps_have_distinct_guest_permissions() {
        let memory = AddressSpace::new(Architecture::X64);
        let vm = VirtualMemory::new(Architecture::X64);
        let mut heaps = Heaps::default();
        let exec = heaps.create(0x40000, 0, 0).unwrap();
        let code = heaps.allocate(&vm, &memory, exec, 0, 16).unwrap();
        assert!(
            code.memory
                .memory
                .allows(code.memory.result, 16, Permissions::ALL)
        );
        let data = heaps.allocate(&vm, &memory, PROCESS_HEAP, 0, 16).unwrap();
        assert!(
            !data
                .memory
                .memory
                .allows(data.memory.result, 1, Permissions::EXECUTE)
        );
        assert!(heaps.create(4, 0, 0).is_err());
    }
}
