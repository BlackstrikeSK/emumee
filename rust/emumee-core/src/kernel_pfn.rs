use crate::kernel_paging::{Authority, FrameKind};
use thiserror::Error;

pub const BASE: u64 = 0xffff_de00_0000_0000;
pub const LENGTH: u64 = 16 * 1024 * 1024;
pub const STRIDE: u64 = 48;
pub const FIELD_OFFSET: u64 = 8;
pub const TAG: &str = "owned PFN backlink metadata";

#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("Owned PFN metadata: {0}")]
pub struct PfnError(pub &'static str);

pub fn intersects(address: u64, size: u64) -> bool {
    size != 0
        && u128::from(address) < u128::from(BASE) + u128::from(LENGTH)
        && u128::from(address) + u128::from(size) > u128::from(BASE)
}

pub fn field_address(pfn: u64) -> Result<u64, PfnError> {
    let offset = pfn
        .checked_mul(STRIDE)
        .and_then(|offset| offset.checked_add(FIELD_OFFSET))
        .ok_or(PfnError("field offset overflow"))?;
    if offset.checked_add(8).is_none_or(|end| end > LENGTH) {
        return Err(PfnError("field lies outside reserved metadata span"));
    }
    BASE.checked_add(offset)
        .ok_or(PfnError("field address overflow"))
}

pub fn table_backlink(authority: &Authority, pfn: u64) -> Result<u64, PfnError> {
    field_address(pfn)?;
    let (depth, prefix) = match authority.frame_kind(pfn) {
        Some(FrameKind::Table { depth, prefix }) if (1..=3).contains(&depth) => (depth, prefix),
        _ => {
            return Err(PfnError(
                "root, data, unknown or retired frame is unsupported",
            ));
        }
    };
    let self_index = authority.self_index();
    if self_index > 511
        || prefix >= (1u64 << (9 * depth))
        || prefix >> (9 * (depth - 1)) == u64::from(self_index)
    {
        return Err(PfnError("unsupported table geometry"));
    }
    let mut children = authority
        .tables()
        .filter(|table| table.depth == depth && table.prefix == prefix);
    if children.next().is_none_or(|table| table.pfn != pfn) || children.next().is_some() {
        return Err(PfnError("table identity disagrees with live inventory"));
    }
    let parent_depth = depth - 1;
    let parent_prefix = prefix >> 9;
    let mut parents = authority
        .tables()
        .filter(|table| table.depth == parent_depth && table.prefix == parent_prefix);
    let parent = parents
        .next()
        .ok_or(PfnError("ordinary parent is missing"))?;
    if parents.next().is_some()
        || authority.frame_kind(parent.pfn)
            != Some(FrameKind::Table {
                depth: parent_depth,
                prefix: parent_prefix,
            })
        || (parent_depth == 0 && parent.pfn != authority.root_pfn())
    {
        return Err(PfnError("ordinary parent identity is inconsistent"));
    }
    let mut indices = [self_index; 4];
    for level in 0..parent_depth {
        indices[usize::from(4 - parent_depth + level)] =
            ((parent_prefix >> (9 * (parent_depth - level - 1))) & 511) as u16;
    }
    let page = (u64::from(indices[0]) << 39)
        | (u64::from(indices[1]) << 30)
        | (u64::from(indices[2]) << 21)
        | (u64::from(indices[3]) << 12);
    let page = ((page << 16) as i64 >> 16) as u64;
    page.checked_add(8 * (prefix & 511))
        .ok_or(PfnError("parent entry address overflow"))
}

pub fn read(authority: &Authority, address: u64, size: u64) -> Result<Vec<u8>, PfnError> {
    if !(1..=8).contains(&size) {
        return Err(PfnError("read must contain one through eight bytes"));
    }
    let end = address
        .checked_add(size)
        .ok_or(PfnError("read range overflow"))?;
    let offset = address
        .checked_sub(BASE)
        .filter(|offset| *offset < LENGTH)
        .ok_or(PfnError("read lies outside reserved metadata span"))?;
    if end > BASE + LENGTH {
        return Err(PfnError("read crosses reserved metadata span"));
    }
    let pfn = offset / STRIDE;
    let field = field_address(pfn)?;
    let start = address
        .checked_sub(field)
        .filter(|start| *start < 8 && *start + size <= 8)
        .ok_or(PfnError("read is not wholly inside one supported field"))?;
    let bytes = table_backlink(authority, pfn)?.to_le_bytes();
    Ok(bytes[start as usize..(start + size) as usize].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        memory::{AddressSpace, PAGE, Permissions},
        pe::Architecture,
    };

    fn canonical_page(indices: [u16; 4]) -> u64 {
        let low = (u64::from(indices[0]) << 39)
            | (u64::from(indices[1]) << 30)
            | (u64::from(indices[2]) << 21)
            | (u64::from(indices[3]) << 12);
        ((low << 16) as i64 >> 16) as u64
    }

    fn mapped_memory(address: u64) -> AddressSpace {
        let mut memory = AddressSpace::new(Architecture::X64);
        memory
            .map(address, PAGE, Permissions::READ, Some(4), "PFN test data")
            .unwrap();
        memory
    }

    #[test]
    fn backlinks_match_parent_words_at_all_depths_and_prefix_extremes() {
        for first in [0, 255, 256, 511] {
            for second in [0, 255, 256, 511] {
                for third in [0, 255, 256, 511] {
                    let memory = mapped_memory(canonical_page([first, second, third, 1]));
                    let mut authority = Authority::new(&memory).unwrap();
                    let tables: Vec<_> = authority.tables().cloned().collect();
                    for table in tables.iter().filter(|table| table.depth != 0) {
                        let backlink = table_backlink(&authority, table.pfn).unwrap();
                        let parent = tables
                            .iter()
                            .find(|parent| {
                                parent.depth + 1 == table.depth
                                    && parent.prefix == table.prefix >> 9
                            })
                            .unwrap();
                        let entry_offset = 8 * (table.prefix & 511);
                        assert_eq!(backlink & (PAGE - 1), entry_offset);
                        assert!(backlink >= 0xffff_8000_0000_0000);
                        assert_eq!(
                            authority.translate(&memory, backlink).unwrap(),
                            Some(parent.pfn * PAGE + entry_offset)
                        );
                        let bytes = authority.table_bytes(&memory, parent.pfn).unwrap();
                        let offset = entry_offset as usize;
                        let word =
                            u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
                        assert_ne!(word & 1, 0);
                        assert_eq!(word & 0x80, 0);
                        assert_eq!((word & 0x000f_ffff_ffff_f000) / PAGE, table.pfn);
                        assert_eq!(
                            read(&authority, field_address(table.pfn).unwrap(), 8).unwrap(),
                            backlink.to_le_bytes()
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn root_data_unknown_and_retired_identities_are_refused() {
        let address = 0x4000;
        let mut memory = mapped_memory(address);
        let mut authority = Authority::new(&memory).unwrap();
        let data = authority.translate(&memory, address).unwrap().unwrap() / PAGE;
        let tables: Vec<_> = authority.tables().cloned().collect();
        for pfn in [authority.root_pfn(), data, 0, 256 + 262144] {
            assert!(table_backlink(&authority, pfn).is_err());
            assert!(read(&authority, field_address(pfn).unwrap(), 8).is_err());
        }
        memory.unmap(address, PAGE).unwrap();
        authority.sync(&memory).unwrap();
        for table in tables.iter().filter(|table| table.depth != 0) {
            assert_eq!(authority.frame_kind(table.pfn), None);
            assert!(table_backlink(&authority, table.pfn).is_err());
            assert!(read(&authority, field_address(table.pfn).unwrap(), 1).is_err());
        }
        memory
            .map(address, PAGE, Permissions::READ, Some(4), "replacement")
            .unwrap();
        authority.sync(&memory).unwrap();
        for old in tables.iter().filter(|table| table.depth != 0) {
            let replacement = authority
                .tables()
                .find(|table| table.depth == old.depth && table.prefix == old.prefix)
                .unwrap();
            assert_ne!(replacement.pfn, old.pfn);
            assert!(table_backlink(&authority, old.pfn).is_err());
            assert!(table_backlink(&authority, replacement.pfn).is_ok());
        }
    }

    #[test]
    fn reads_admit_only_contained_live_field_subranges() {
        let memory = mapped_memory(0x4000);
        let authority = Authority::new(&memory).unwrap();
        let table = authority.tables().find(|table| table.depth == 3).unwrap();
        let field = field_address(table.pfn).unwrap();
        let bytes = table_backlink(&authority, table.pfn).unwrap().to_le_bytes();
        for offset in 0..8u64 {
            for size in 1..=8 - offset {
                assert_eq!(
                    read(&authority, field + offset, size).unwrap(),
                    bytes[offset as usize..(offset + size) as usize]
                );
            }
            assert!(read(&authority, field + offset, 9 - offset).is_err());
        }
        for (address, size) in [
            (field, 0),
            (field, 9),
            (field, STRIDE),
            (field - 1, 1),
            (field - 1, 2),
            (field + 8, 1),
            (field + STRIDE - FIELD_OFFSET - 1, 2),
            (BASE - 1, 2),
            (BASE + LENGTH - 1, 2),
            (BASE + LENGTH, 1),
            (u64::MAX, 1),
            (u64::MAX - 3, 8),
            (0, u64::MAX),
        ] {
            assert!(read(&authority, address, size).is_err());
        }
    }

    #[test]
    fn intersection_uses_nonwrapping_intervals_and_exclusive_endpoints() {
        for (address, size, expected) in [
            (BASE, 0, false),
            (BASE, 1, true),
            (BASE - 1, 1, false),
            (BASE - 1, 2, true),
            (BASE + LENGTH - 1, 1, true),
            (BASE + LENGTH, 1, false),
            (BASE + LENGTH, u64::MAX, false),
            (BASE, u64::MAX, true),
            (0, u64::MAX, true),
            (u64::MAX, 1, false),
        ] {
            assert_eq!(intersects(address, size), expected);
        }
    }

    #[test]
    fn fixed_reservation_covers_lifetime_identity_bound_without_exposing_filler() {
        let maximum_owned_pfn = 256 + 262144 - 1;
        assert!(field_address(maximum_owned_pfn).unwrap() + 8 <= BASE + LENGTH);
        let last_fitting_pfn = (LENGTH - FIELD_OFFSET - 8) / STRIDE;
        assert!(field_address(last_fitting_pfn).is_ok());
        assert!(field_address(last_fitting_pfn + 1).is_err());
        assert!(field_address(u64::MAX).is_err());
        assert!(field_address(u64::MAX / STRIDE + 1).is_err());
        let mut memory = AddressSpace::new(Architecture::X64);
        memory
            .map(BASE, LENGTH, Permissions::READ, Some(4), TAG)
            .unwrap();
        let mut authority = Authority::new(&memory).unwrap();
        let inventory: Vec<_> = authority.tables().cloned().collect();
        for table in inventory.iter().filter(|table| table.depth != 0) {
            assert!(read(&authority, field_address(table.pfn).unwrap(), 8).is_ok());
        }
        let data = authority.translate(&memory, BASE).unwrap().unwrap() / PAGE;
        assert!(read(&authority, field_address(data).unwrap(), 8).is_err());
        assert!(read(&authority, field_address(last_fitting_pfn).unwrap(), 8).is_err());
        assert!(read(&authority, BASE, 8).is_err());
        assert_eq!(inventory, authority.tables().cloned().collect::<Vec<_>>());
        authority.sync(&memory).unwrap();
        assert_eq!(inventory, authority.tables().cloned().collect::<Vec<_>>());
    }
}
