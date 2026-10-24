//! Bounded guest kernel pool bookkeeping. Native mappings are applied by the
//! engine before a validated allocation/free is committed here.
use crate::{
    memory::{AddressSpace, Permissions as P},
    pe::Architecture,
};
use serde::Serialize;
use std::collections::BTreeMap;
use thiserror::Error;
const LIMIT: u64 = 128 * 1024 * 1024;
#[derive(Debug, Error)]
#[error("Guest kernel pool: {0}")]
pub struct PoolError(pub &'static str);
type Result<T> = std::result::Result<T, PoolError>;
#[derive(Clone, Debug, Serialize)]
pub struct Allocation {
    pub base: u64,
    pub requested: u64,
    pub mapped: u64,
    pub tag: u32,
    pub paged: bool,
    pub executable: bool,
    pub zero_initialized: bool,
}
impl Allocation {
    pub fn permissions(&self) -> P {
        if self.executable { P::ALL } else { P::RW }
    }
}
#[derive(Clone, Debug, Serialize, Default)]
pub struct Pool {
    pub allocations: BTreeMap<u64, Allocation>,
    pub mapped_bytes: u64,
    pub total_allocations: u64,
    pub total_frees: u64,
}
impl Pool {
    pub fn prepare(
        &self,
        memory: &AddressSpace,
        architecture: Architecture,
        flags: u64,
        size: u64,
        tag: u32,
        irql: u8,
    ) -> Result<Option<Allocation>> {
        // Optional flags can be ignored; unknown required behavior is explicit.
        if flags as u32 & !0x1c2 != 0 {
            return Err(PoolError("required pool flags are not modeled"));
        }
        let kind = flags & 0x1c0;
        // The Python driver pool accepts a zero tag, including the cache-aware
        // rundown allocation seen in the submitted driver.
        if ![0x40, 0x80, 0x100].contains(&kind) || size == 0 {
            return Ok(None);
        }
        let paged = kind == 0x100;
        if irql > 2 || (paged && irql > 1) {
            return Err(PoolError("pool type is not permitted at this IRQL"));
        }
        let Some(mapped) = size.checked_add(4095).map(|n| n & !4095) else {
            return Ok(None);
        };
        if mapped > LIMIT || self.mapped_bytes > LIMIT - mapped || self.allocations.len() >= 4096 {
            return Ok(None);
        }
        let mut base = if architecture == Architecture::X64 {
            0xffffb00000000000
        } else {
            0xe0000000
        };
        let end = base + 256 * 1024 * 1024;
        for region in memory.regions() {
            if region.base + region.size <= base {
                continue;
            }
            if region.base >= base + mapped {
                break;
            }
            base = (region.base + region.size + 4095) & !4095;
            if base > end || mapped > end - base {
                return Ok(None);
            }
        }
        if base > end || mapped > end - base {
            return Ok(None);
        }
        Ok(Some(Allocation {
            base,
            requested: size,
            mapped,
            tag,
            paged,
            executable: kind == 0x80 || (paged && architecture == Architecture::X86),
            zero_initialized: flags & 2 == 0,
        }))
    }
    pub fn commit_allocation(&mut self, allocation: Allocation) {
        self.mapped_bytes += allocation.mapped;
        self.total_allocations += 1;
        self.allocations.insert(allocation.base, allocation);
    }
    pub fn prepare_free(&self, address: u64, tag: Option<u32>, irql: u8) -> Result<&Allocation> {
        let allocation = self
            .allocations
            .get(&address)
            .ok_or(PoolError("free does not name a live pool allocation"))?;
        if tag.is_some_and(|tag| tag != allocation.tag) {
            return Err(PoolError("pool free tag mismatch"));
        }
        if irql > 2 || (allocation.paged && irql > 1) {
            return Err(PoolError("pool free is not permitted at this IRQL"));
        }
        Ok(allocation)
    }
    pub fn commit_free(&mut self, address: u64) {
        if let Some(allocation) = self.allocations.remove(&address) {
            self.mapped_bytes -= allocation.mapped;
            self.total_frees += 1;
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn allocation_reuse_bounds_flags_and_failed_frees_preserve_state() {
        for architecture in [Architecture::X86, Architecture::X64] {
            let mut memory = AddressSpace::new(architecture);
            let mut pool = Pool::default();
            let allocation = pool
                .prepare(&memory, architecture, 0x40, 17, 0x52555354, 0)
                .unwrap()
                .unwrap();
            assert_eq!(allocation.base % 4096, 0);
            assert_eq!(allocation.mapped, 4096);
            assert!(allocation.zero_initialized);
            assert!(!allocation.executable);
            memory
                .map(
                    allocation.base,
                    allocation.mapped,
                    allocation.permissions(),
                    None,
                    "kernel pool",
                )
                .unwrap();
            pool.commit_allocation(allocation.clone());
            let second = pool
                .prepare(&memory, architecture, 0x42, 4097, 7, 2)
                .unwrap()
                .unwrap();
            assert_eq!(second.base, allocation.base + 4096);
            assert!(!second.zero_initialized);
            assert_eq!(second.mapped, 8192);
            assert!(pool.prepare_free(allocation.base, Some(8), 0).is_err());
            assert!(pool.prepare_free(allocation.base + 1, None, 0).is_err());
            assert_eq!(pool.mapped_bytes, 4096);
            assert!(pool.prepare(&memory, architecture, 0x100, 8, 1, 2).is_err());
            assert!(
                pool.prepare(&memory, architecture, 0x140, 8, 1, 0)
                    .unwrap()
                    .is_none()
            );
            assert!(
                pool.prepare(&memory, architecture, 0x40, u64::MAX, 1, 0)
                    .unwrap()
                    .is_none()
            );
            assert!(
                pool.prepare(&memory, architecture, 0x40, LIMIT + 1, 1, 0)
                    .unwrap()
                    .is_none()
            );
            assert!(
                pool.prepare(&memory, architecture, 0x40, 1, 0, 0)
                    .unwrap()
                    .is_some()
            );
            assert!(pool.prepare(&memory, architecture, 0x41, 8, 1, 0).is_err());
            assert!(
                pool.prepare(&memory, architecture, 0x80_0000_0040, 8, 1, 0)
                    .unwrap()
                    .is_some()
            );
            pool.prepare_free(allocation.base, None, 0).unwrap();
            memory.unmap(allocation.base, allocation.mapped).unwrap();
            pool.commit_free(allocation.base);
            assert!(pool.prepare_free(allocation.base, None, 0).is_err());
            assert_eq!(
                pool.prepare(&memory, architecture, 0x80, 8, 1, 0)
                    .unwrap()
                    .unwrap()
                    .base,
                allocation.base
            );
        }
    }
}
