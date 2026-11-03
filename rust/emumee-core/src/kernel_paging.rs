//! Owned synthetic physical identities and sparse four-level page-table bytes.
//!
//! No host RAM or host CR3 is consulted. The self-reference slot belongs to the
//! declared pinned guest profile. This module does not publish native mappings;
//! adapters must audit backing, apply effects, and commit plans transactionally.
use crate::{
    memory::{AddressSpace, PAGE, Permissions},
    pe::Architecture,
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

pub const SELF_INDEX: u16 = 493;
pub const VIEW_TAG: &str = "owned paging structural table";
const FIRST_PFN: u64 = 256;
const MAX_FRAMES: usize = 262144;
const MAX_TABLES: usize = 4096;
const PRESENT: u64 = 1;
const ORDINARY: u64 = 0x63;

#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("Owned paging: {0}")]
pub struct PagingError(pub &'static str);
type Result<T> = std::result::Result<T, PagingError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum FrameKind {
    Table { depth: u8, prefix: u64 },
    Data { source: u64, mapping_id: u64 },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Lease {
    pub pfn: u64,
    pub mapping_id: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Alias {
    pub source: u64,
    pub pages: u64,
    pub source_mapping_ids: Vec<u64>,
    pub target_mapping_ids: Vec<u64>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Transport {
    pub target: u64,
    pub backend_mapping_id: u64,
    pub target_mapping_id: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Table {
    pub pfn: u64,
    pub depth: u8,
    pub prefix: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct View {
    pub pfn: u64,
    pub mapping_id: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Authority {
    root_pfn: u64,
    self_index: u16,
    next_pfn: u64,
    frames: BTreeMap<u64, FrameKind>,
    retired: BTreeSet<u64>,
    tables: BTreeMap<u64, Table>,
    data: BTreeMap<u64, Lease>,
    aliases: BTreeMap<u64, Alias>,
    /// Explicit backend-only noncanonical transport aliases, not PTE leaves.
    transports: BTreeMap<u64, Transport>,
    /// Guest virtual addresses occupied by guarded structural table views.
    views: BTreeMap<u64, View>,
    epoch: Option<u64>,
}

fn canonical(address: u64) -> bool {
    address <= 0x7fff_ffff_ffff || address >= 0xffff_8000_0000_0000
}
fn key(depth: u8, prefix: u64) -> u64 {
    (u64::from(depth) << 56) | prefix
}
fn slot(va: u64, depth: u8) -> u16 {
    ((va >> (39 - depth * 9)) & 511) as u16
}
fn prefix(va: u64, depth: u8) -> u64 {
    (va >> (48 - depth * 9)) & ((1u64 << (depth * 9)) - 1)
}
fn canonical_page(indices: [u16; 4]) -> u64 {
    let low = (u64::from(indices[0]) << 39)
        | (u64::from(indices[1]) << 30)
        | (u64::from(indices[2]) << 21)
        | (u64::from(indices[3]) << 12);
    ((low << 16) as i64 >> 16) as u64
}
fn overlaps(a: u64, size: u64, b: u64, length: u64) -> bool {
    a as u128 + size as u128 > b as u128 && b as u128 + length as u128 > a as u128
}
fn page_mapping(memory: &AddressSpace, page: u64) -> Result<u64> {
    if page % PAGE != 0 || !memory.allows(page, PAGE, Permissions::NONE) {
        return Err(PagingError("page lacks complete logical backing"));
    }
    let id = memory
        .region(page)
        .ok_or(PagingError("missing page"))?
        .mapping_id();
    if memory
        .region(page + PAGE - 1)
        .is_none_or(|r| r.mapping_id() != id)
    {
        return Err(PagingError("page crosses mapping identities"));
    }
    Ok(id)
}

impl Authority {
    pub fn new(memory: &AddressSpace) -> Result<Self> {
        if memory.architecture() != Architecture::X64 {
            return Err(PagingError("four-level profile requires x64"));
        }
        let mut state = Self {
            root_pfn: FIRST_PFN,
            self_index: SELF_INDEX,
            next_pfn: FIRST_PFN,
            frames: BTreeMap::new(),
            retired: BTreeSet::new(),
            tables: BTreeMap::new(),
            data: BTreeMap::new(),
            aliases: BTreeMap::new(),
            transports: BTreeMap::new(),
            views: BTreeMap::new(),
            epoch: None,
        };
        let root = state.allocate(FrameKind::Table {
            depth: 0,
            prefix: 0,
        })?;
        assert_eq!(root, state.root_pfn);
        state.tables.insert(
            key(0, 0),
            Table {
                pfn: root,
                depth: 0,
                prefix: 0,
            },
        );
        state.sync(memory)?;
        Ok(state)
    }
    pub fn cr3(&self) -> u64 {
        self.root_pfn * PAGE
    }
    pub fn root_pfn(&self) -> u64 {
        self.root_pfn
    }
    pub fn self_index(&self) -> u16 {
        self.self_index
    }
    pub fn data_frames(&self) -> usize {
        self.data.len()
    }
    pub fn frame_kind(&self, pfn: u64) -> Option<FrameKind> {
        self.frames
            .get(&pfn)
            .copied()
            .filter(|_| !self.retired.contains(&pfn))
    }
    pub fn tables(&self) -> impl Iterator<Item = &Table> {
        self.tables.values()
    }
    pub fn views(&self) -> impl Iterator<Item = (&u64, &View)> {
        self.views.iter()
    }
    fn allocate(&mut self, kind: FrameKind) -> Result<u64> {
        if self.frames.len() >= MAX_FRAMES || self.next_pfn >= (1u64 << 40) {
            return Err(PagingError("physical identity capacity exhausted"));
        }
        let frame = self.next_pfn;
        self.next_pfn += 1;
        self.frames.insert(frame, kind);
        Ok(frame)
    }
    fn retire(&mut self, pfn: u64) {
        self.retired.insert(pfn);
    }
    fn excluded(&self, page: u64) -> bool {
        self.views.contains_key(&page) || self.transports.contains_key(&page)
    }
    /// Complete noncanonical exceptions must be explicitly declared as transport
    /// aliases before admitting their memory inventory. They never become PTEs.
    pub fn register_transport(
        &mut self,
        memory: &AddressSpace,
        backend: u64,
        target: u64,
    ) -> Result<()> {
        if canonical(backend)
            || !canonical(target)
            || backend % PAGE != 0
            || target % PAGE != 0
            || crate::kernel_physical::paging_alias(backend) != target
        {
            return Err(PagingError("invalid backend alias geometry"));
        }
        let backend_id = page_mapping(memory, backend)?;
        let target_id = page_mapping(memory, target)?;
        if self.transports.contains_key(&backend) {
            return Err(PagingError("duplicate backend alias"));
        }
        self.transports.insert(
            backend,
            Transport {
                target,
                backend_mapping_id: backend_id,
                target_mapping_id: target_id,
            },
        );
        self.epoch = None;
        Ok(())
    }
    pub fn register_alias(
        &mut self,
        memory: &AddressSpace,
        target: u64,
        source: u64,
        pages: u64,
    ) -> Result<()> {
        if pages == 0
            || pages > 32768
            || target % PAGE != 0
            || source % PAGE != 0
            || !canonical(target)
            || !canonical(source)
        {
            return Err(PagingError("invalid shared alias geometry"));
        }
        let size = pages
            .checked_mul(PAGE)
            .ok_or(PagingError("alias overflow"))?;
        target
            .checked_add(size)
            .ok_or(PagingError("alias target overflow"))?;
        source
            .checked_add(size)
            .ok_or(PagingError("alias source overflow"))?;
        if overlaps(target, size, source, size)
            || self.aliases.iter().any(|(at, a)| {
                overlaps(target, size, *at, a.pages * PAGE)
                    || overlaps(source, size, *at, a.pages * PAGE)
                    || overlaps(target, size, a.source, a.pages * PAGE)
            })
        {
            return Err(PagingError("alias cycles/overlap are unsupported"));
        }
        let mut source_ids = Vec::new();
        let mut target_ids = Vec::new();
        for i in 0..pages {
            source_ids.push(page_mapping(memory, source + i * PAGE)?);
            target_ids.push(page_mapping(memory, target + i * PAGE)?);
        }
        self.sync(memory)?;
        // Register before a separate target physical identity is exposed.
        if (0..pages).any(|i| self.data.contains_key(&(target + i * PAGE))) {
            return Err(PagingError("alias target already has a physical identity"));
        }
        self.aliases.insert(
            target,
            Alias {
                source,
                pages,
                source_mapping_ids: source_ids,
                target_mapping_ids: target_ids,
            },
        );
        self.epoch = None;
        Ok(())
    }
    pub fn remove_alias(&mut self, target: u64) -> Result<()> {
        self.aliases
            .remove(&target)
            .ok_or(PagingError("unknown shared alias"))?;
        self.epoch = None;
        Ok(())
    }
    fn source_page(&self, memory: &AddressSpace, page: u64) -> Result<u64> {
        for (target, alias) in &self.aliases {
            if page >= *target && (page - *target) / PAGE < alias.pages {
                let index = ((page - *target) / PAGE) as usize;
                let source = alias.source + index as u64 * PAGE;
                if page_mapping(memory, page)? != alias.target_mapping_ids[index]
                    || page_mapping(memory, source)? != alias.source_mapping_ids[index]
                {
                    return Err(PagingError("shared alias backing lifetime diverged"));
                }
                return Ok(source);
            }
        }
        Ok(page)
    }
    fn mapped_pages(&self, memory: &AddressSpace) -> Result<Vec<(u64, u64)>> {
        let mut spans = Vec::new();
        for r in memory.regions() {
            let end = r.base + r.size;
            if !canonical(r.base) || !canonical(end - 1) {
                // Only exact separately registered single-page exceptions.
                if r.size == PAGE {
                    if let Some(t) = self.transports.get(&r.base) {
                        if page_mapping(memory, r.base)? != t.backend_mapping_id
                            || page_mapping(memory, t.target)? != t.target_mapping_id
                        {
                            return Err(PagingError("backend transport lifetime diverged"));
                        }
                        continue;
                    }
                }
                return Err(PagingError("unqualified noncanonical native mapping"));
            }
            if slot(r.base, 0) == self.self_index || slot(end - 1, 0) == self.self_index {
                if r.size == PAGE
                    && self
                        .views
                        .get(&r.base)
                        .is_some_and(|v| v.mapping_id == r.mapping_id())
                    && r.permissions == Permissions::READ
                    && r.owner == Some(4)
                    && r.tag == VIEW_TAG
                {
                    continue;
                }
                return Err(PagingError(
                    "ordinary mapping overlaps reserved self-reference view",
                ));
            }
            // A span cannot silently cross the canonical hole or reserved slot.
            if (r.base <= 0x7fff_ffff_ffff && end > 0xffff_8000_0000_0000)
                || (slot(r.base, 0) < self.self_index && slot(end - 1, 0) > self.self_index)
            {
                return Err(PagingError("mapping crosses reserved paging geometry"));
            }
            if r.permissions == Permissions::NONE {
                continue;
            }
            if !r.permissions.contains(Permissions::READ) {
                return Err(PagingError(
                    "permissions lack an ordinary x64 readable-leaf representation",
                ));
            }
            spans.push((r.base, end));
        }
        Ok(spans)
    }
    pub fn sync(&mut self, memory: &AddressSpace) -> Result<()> {
        if self.epoch == Some(memory.epoch()) {
            return Ok(());
        }
        for (backend, t) in &self.transports {
            if page_mapping(memory, *backend).ok() != Some(t.backend_mapping_id)
                || page_mapping(memory, t.target).ok() != Some(t.target_mapping_id)
            {
                return Err(PagingError("backend transport lifetime diverged"));
            }
        }
        for (target, a) in &self.aliases {
            for i in 0..a.pages {
                if page_mapping(memory, *target + i * PAGE).ok()
                    != Some(a.target_mapping_ids[i as usize])
                    || page_mapping(memory, a.source + i * PAGE).ok()
                        != Some(a.source_mapping_ids[i as usize])
                {
                    return Err(PagingError("shared alias backing lifetime diverged"));
                }
            }
        }
        let spans = self.mapped_pages(memory)?;
        let mut needed = BTreeSet::from([key(0, 0)]);
        for (base, end) in spans {
            for depth in 1..=3 {
                let shift = 48 - depth * 9;
                let size = 1u64 << shift;
                let mut page = base & !(size - 1);
                loop {
                    needed.insert(key(depth, prefix(page, depth)));
                    if needed.len() > MAX_TABLES {
                        return Err(PagingError("sparse page-table capacity exhausted"));
                    }
                    let Some(next) = page.checked_add(size) else {
                        break;
                    };
                    if next >= end {
                        break;
                    }
                    page = next;
                }
            }
        }
        // Complete preflight precedes frame retirement/allocation.
        let missing = needed
            .iter()
            .filter(|k| !self.tables.contains_key(k))
            .count();
        if self.frames.len() + missing > MAX_FRAMES {
            return Err(PagingError("physical identity capacity exhausted"));
        }
        let removed: Vec<_> = self
            .tables
            .keys()
            .copied()
            .filter(|k| !needed.contains(k))
            .collect();
        for k in removed {
            let t = self.tables.remove(&k).unwrap();
            self.retire(t.pfn);
        }
        for k in needed {
            if !self.tables.contains_key(&k) {
                let depth = (k >> 56) as u8;
                let p = k & 0x00ff_ffff_ffff_ffff;
                let pfn = self.allocate(FrameKind::Table { depth, prefix: p })?;
                self.tables.insert(
                    k,
                    Table {
                        pfn,
                        depth,
                        prefix: p,
                    },
                );
            }
        }
        let stale: Vec<_> = self
            .data
            .iter()
            .filter_map(|(page, lease)| {
                (page_mapping(memory, *page).ok() != Some(lease.mapping_id)).then_some(*page)
            })
            .collect();
        for page in stale {
            let lease = self.data.remove(&page).unwrap();
            self.retire(lease.pfn);
        }
        self.epoch = Some(memory.epoch());
        Ok(())
    }
    pub fn data_frame(&mut self, memory: &AddressSpace, address: u64) -> Result<u64> {
        self.sync(memory)?;
        let page = address & !(PAGE - 1);
        if !canonical(page) || slot(page, 0) == self.self_index || self.excluded(page) {
            return Err(PagingError("not an ordinary architectural data mapping"));
        }
        if memory
            .region(page)
            .is_none_or(|r| !r.permissions.contains(Permissions::READ))
        {
            return Err(PagingError(
                "data mapping is not accessible through an ordinary readable leaf",
            ));
        }
        let page = self.source_page(memory, page)?;
        let id = page_mapping(memory, page)?;
        if let Some(lease) = self.data.get(&page) {
            return Ok(lease.pfn);
        }
        let pfn = self.allocate(FrameKind::Data {
            source: page,
            mapping_id: id,
        })?;
        self.data.insert(
            page,
            Lease {
                pfn,
                mapping_id: id,
            },
        );
        Ok(pfn)
    }
    fn virtual_key(&self, indices: &[u16]) -> Option<u64> {
        let mut depth = 0u8;
        let mut p = 0;
        for index in indices {
            if depth == 0 && *index == self.self_index {
                continue;
            }
            depth += 1;
            if depth > 3 {
                return None;
            }
            p = (p << 9) | u64::from(*index);
            if !self.tables.contains_key(&key(depth, p)) {
                return None;
            }
        }
        Some(key(depth, p))
    }
    pub fn translate(&mut self, memory: &AddressSpace, address: u64) -> Result<Option<u64>> {
        self.sync(memory)?;
        let address = crate::kernel_physical::paging_alias(address);
        let indices = [
            slot(address, 0),
            slot(address, 1),
            slot(address, 2),
            slot(address, 3),
        ];
        if indices[0] == self.self_index {
            let Some(k) = self.virtual_key(&indices) else {
                return Ok(None);
            };
            return Ok(Some(self.tables[&k].pfn * PAGE + (address & (PAGE - 1))));
        }
        if memory
            .region(address)
            .is_none_or(|r| r.permissions == Permissions::NONE)
        {
            return Ok(None);
        }
        Ok(Some(
            self.data_frame(memory, address)? * PAGE + (address & (PAGE - 1)),
        ))
    }
    pub fn walk(
        &mut self,
        memory: &AddressSpace,
        address: u64,
    ) -> Result<crate::kernel_physical::owned::Walk> {
        self.sync(memory)?;
        let mut entries = [None; 4];
        let mut frame = self.root_pfn;
        for (depth, entry) in entries.iter_mut().enumerate() {
            let bytes = self.table_bytes(memory, frame)?;
            let offset = usize::from(slot(address, depth as u8)) * 8;
            let word = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
            *entry = Some(word);
            if word & PRESENT == 0 {
                break;
            }
            frame = (word & 0x000f_ffff_ffff_f000) / PAGE;
        }
        Ok(crate::kernel_physical::owned::Walk {
            virtual_address: address,
            entries,
        })
    }
    pub fn table_bytes(&mut self, memory: &AddressSpace, pfn: u64) -> Result<Vec<u8>> {
        self.sync(memory)?;
        let (depth, p) = match self.frame_kind(pfn) {
            Some(FrameKind::Table { depth, prefix }) => (depth, prefix),
            _ => return Err(PagingError("unknown/retired table frame")),
        };
        let mut bytes = vec![0; PAGE as usize];
        for i in 0..512u16 {
            let value = if depth == 0 && i == self.self_index {
                self.cr3() | ORDINARY
            } else if depth < 3 {
                let child = (p << 9) | u64::from(i);
                self.tables
                    .get(&key(depth + 1, child))
                    .map(|t| {
                        (t.pfn * PAGE)
                            | ORDINARY
                            | if (child >> ((depth) * 9)) < 256 { 4 } else { 0 }
                    })
                    .unwrap_or(0)
            } else {
                let idx = [
                    ((p >> 18) & 511) as u16,
                    ((p >> 9) & 511) as u16,
                    (p & 511) as u16,
                    i,
                ];
                let address = canonical_page(idx);
                if let Some(region) = memory
                    .region(address)
                    .filter(|r| r.permissions != Permissions::NONE)
                {
                    let flags = PRESENT
                        | 0x60
                        | if region.permissions.contains(Permissions::WRITE) {
                            2
                        } else {
                            0
                        }
                        | if idx[0] < 256 { 4 } else { 0 }
                        | if region.permissions.contains(Permissions::EXECUTE) {
                            0
                        } else {
                            1u64 << 63
                        };
                    (self.data_frame(memory, address)? * PAGE) | flags
                } else {
                    0
                }
            };
            bytes[i as usize * 8..i as usize * 8 + 8].copy_from_slice(&value.to_le_bytes());
        }
        Ok(bytes)
    }
    /// Register a native read-only VTLB alias only after proving its table target;
    /// it is a structural transport mapping and must never become a data leaf.
    pub fn register_view(&mut self, memory: &AddressSpace, address: u64, pfn: u64) -> Result<()> {
        if !canonical(address) || address % PAGE != 0 || self.views.contains_key(&address) {
            return Err(PagingError("invalid/duplicate structural view"));
        }
        let r = memory
            .region(address)
            .ok_or(PagingError("structural view metadata missing"))?;
        if r.base != address
            || r.size != PAGE
            || r.permissions != Permissions::READ
            || r.owner != Some(4)
            || r.tag != VIEW_TAG
        {
            return Err(PagingError("structural view backing declaration differs"));
        }
        let mut next = self.clone();
        next.views.insert(
            address,
            View {
                pfn,
                mapping_id: r.mapping_id(),
            },
        );
        next.epoch = None;
        if next.translate(memory, address)? != Some(pfn * PAGE)
            || !matches!(next.frame_kind(pfn), Some(FrameKind::Table { .. }))
        {
            return Err(PagingError("structural view has wrong physical target"));
        }
        *self = next;
        Ok(())
    }
    pub fn remove_view(&mut self, address: u64) -> Result<()> {
        self.views
            .remove(&address)
            .ok_or(PagingError("unknown structural view"))?;
        self.epoch = None;
        Ok(())
    }
    pub fn refresh_view(&mut self, memory: &AddressSpace, address: u64, pfn: u64) -> Result<()> {
        if !self.views.contains_key(&address) {
            return Err(PagingError("unknown structural view"));
        }
        if self.translate(memory, address)? != Some(pfn * PAGE)
            || !matches!(self.frame_kind(pfn), Some(FrameKind::Table { .. }))
        {
            return Err(PagingError("structural view has wrong physical target"));
        }
        self.views.get_mut(&address).unwrap().pfn = pfn;
        Ok(())
    }
    pub fn require_write(&self, address: u64, size: u64) -> Result<()> {
        if size != 0
            && self
                .views
                .keys()
                .any(|page| overlaps(address, size, *page, PAGE))
        {
            return Err(PagingError("write to owned page-table view"));
        }
        Ok(())
    }
    pub fn require_mapping_change(&self, address: u64, size: u64) -> Result<()> {
        if size != 0
            && self
                .views
                .keys()
                .any(|page| overlaps(address, size, *page, PAGE))
        {
            return Err(PagingError("mapping change overlaps owned page-table view"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
