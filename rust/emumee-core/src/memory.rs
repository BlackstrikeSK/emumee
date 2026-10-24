//! Guest region permissions and ownership, separate from host process memory.
use crate::pe::Architecture;
use serde::Serialize;
use std::collections::BTreeMap;
use thiserror::Error;

pub const PAGE: u64 = 4096;
const MAX_REGIONS: usize = 100000;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct Permissions(pub u8);
impl Permissions {
    pub const NONE: Self = Self(0);
    pub const READ: Self = Self(1);
    pub const WRITE: Self = Self(2);
    pub const EXECUTE: Self = Self(4);
    pub const RW: Self = Self(3);
    pub const RX: Self = Self(5);
    pub const ALL: Self = Self(7);
    pub fn contains(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Region {
    pub base: u64,
    pub size: u64,
    pub permissions: Permissions,
    pub owner: Option<u64>,
    pub tag: String,
}
impl Region {
    fn end(&self) -> u64 {
        self.base + self.size
    }
}
#[derive(Debug, Error)]
#[error("Guest memory: {0}")]
pub struct MemoryError(pub &'static str);
type Result<T> = std::result::Result<T, MemoryError>;
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AddressSpace {
    architecture: Architecture,
    regions: BTreeMap<u64, Region>,
}
impl AddressSpace {
    pub fn new(architecture: Architecture) -> Self {
        Self {
            architecture,
            regions: BTreeMap::new(),
        }
    }
    fn end(&self, address: u64, size: u64) -> Result<u64> {
        if address == 0 || size == 0 {
            return Err(MemoryError("null or empty mapping"));
        }
        let end = address
            .checked_add(size)
            .ok_or(MemoryError("address overflow"))?;
        if self.architecture == Architecture::X86 && end > 1u64 << 32 {
            return Err(MemoryError("x86 range exceeds address space"));
        }
        Ok(end)
    }
    fn aligned(&self, address: u64, size: u64) -> Result<u64> {
        if address % PAGE != 0 || size % PAGE != 0 {
            return Err(MemoryError("range is not page aligned"));
        }
        self.end(address, size)
    }
    pub fn map(
        &mut self,
        base: u64,
        size: u64,
        permissions: Permissions,
        owner: Option<u64>,
        tag: &str,
    ) -> Result<()> {
        let end = self.aligned(base, size)?;
        if permissions.0 > 7 || tag.len() > 256 {
            return Err(MemoryError("invalid mapping metadata"));
        }
        if self.regions.len() >= MAX_REGIONS {
            return Err(MemoryError("region count exceeds bound"));
        }
        if self
            .regions
            .range(..end)
            .next_back()
            .is_some_and(|(_, region)| region.end() > base)
        {
            return Err(MemoryError("overlapping mapping"));
        }
        self.regions.insert(
            base,
            Region {
                base,
                size,
                permissions,
                owner,
                tag: tag.to_owned(),
            },
        );
        Ok(())
    }
    pub fn region(&self, address: u64) -> Option<&Region> {
        self.regions
            .range(..=address)
            .next_back()
            .map(|(_, region)| region)
            .filter(|region| address < region.end())
    }
    pub fn allows(&self, address: u64, size: u64, required: Permissions) -> bool {
        let Ok(end) = self.end(address, size) else {
            return false;
        };
        let mut cursor = address;
        while cursor < end {
            let Some(region) = self.region(cursor) else {
                return false;
            };
            if !region.permissions.contains(required) {
                return false;
            }
            cursor = region.end().min(end);
        }
        true
    }
    fn replace(&mut self, base: u64, size: u64, permissions: Option<Permissions>) -> Result<()> {
        let end = self.aligned(base, size)?;
        if !self.allows(base, size, Permissions::NONE) {
            return Err(MemoryError("range crosses unmapped memory"));
        }
        if permissions.is_some_and(|p| p.0 > 7) {
            return Err(MemoryError("invalid protection"));
        }
        let affected = self
            .regions
            .range(..end)
            .filter(|(_, r)| r.end() > base)
            .map(|(_, r)| r.clone())
            .collect::<Vec<_>>();
        let mut replacements = Vec::new();
        for region in &affected {
            if region.base < base {
                let mut left = region.clone();
                left.size = base - region.base;
                replacements.push(left);
            }
            if let Some(prot) = permissions {
                let mut middle = region.clone();
                middle.base = base.max(region.base);
                middle.size = end.min(region.end()) - middle.base;
                middle.permissions = prot;
                replacements.push(middle);
            }
            if region.end() > end {
                let mut right = region.clone();
                right.base = end;
                right.size = region.end() - end;
                replacements.push(right);
            }
        }
        if self.regions.len() - affected.len() + replacements.len() > MAX_REGIONS {
            return Err(MemoryError("protection split exceeds region bound"));
        }
        for region in affected {
            self.regions.remove(&region.base);
        }
        for region in replacements {
            self.regions.insert(region.base, region);
        }
        Ok(())
    }
    pub fn protect(&mut self, base: u64, size: u64, permissions: Permissions) -> Result<()> {
        self.replace(base, size, Some(permissions))
    }
    pub fn unmap(&mut self, base: u64, size: u64) -> Result<()> {
        self.replace(base, size, None)
    }
    pub fn regions(&self) -> impl Iterator<Item = &Region> {
        self.regions.values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn partial_protection_preserves_neighbors_and_allocation_identity() {
        let mut memory = AddressSpace::new(Architecture::X64);
        memory
            .map(0x10000, 3 * PAGE, Permissions::RW, Some(17), "pool")
            .unwrap();
        memory.protect(0x11000, PAGE, Permissions::READ).unwrap();
        assert!(memory.allows(0x10000, PAGE, Permissions::WRITE));
        assert!(!memory.allows(0x11000, 1, Permissions::WRITE));
        assert!(memory.allows(0x12000, PAGE, Permissions::WRITE));
        assert!(memory.regions().all(|region| region.owner == Some(17)));
        let before = memory.clone();
        assert!(memory.protect(0x13000, PAGE, Permissions::ALL).is_err());
        assert_eq!(memory, before);
    }
    #[test]
    fn gaps_and_cross_page_permissions_are_not_bypassed() {
        let mut memory = AddressSpace::new(Architecture::X64);
        memory
            .map(0x10000, 3 * PAGE, Permissions::READ, None, "image")
            .unwrap();
        assert!(memory.allows(0x10ff0, 32, Permissions::READ));
        memory.unmap(0x11000, PAGE).unwrap();
        assert!(!memory.allows(0x10ff0, 32, Permissions::READ));
        assert!(!memory.allows(0x10000, 1, Permissions::EXECUTE));
        assert!(
            memory
                .map(0x10000, PAGE, Permissions::ALL, None, "overlap")
                .is_err()
        );
    }
    #[test]
    fn architecture_limits_nulls_and_wrapping_ranges_are_rejected() {
        let mut memory = AddressSpace::new(Architecture::X86);
        memory
            .map(0xfffff000, PAGE, Permissions::RW, None, "top page")
            .unwrap();
        assert!(memory.allows(0xffffffff, 1, Permissions::READ));
        assert!(!memory.allows(0xffffffff, 2, Permissions::READ));
        assert!(
            memory
                .map(1u64 << 32, PAGE, Permissions::RW, None, "overflow")
                .is_err()
        );
        assert!(
            AddressSpace::new(Architecture::X64)
                .map(u64::MAX - 4095, PAGE, Permissions::READ, None, "wrap")
                .is_err()
        );
        assert!(!memory.allows(0, 1, Permissions::READ));
    }
}
