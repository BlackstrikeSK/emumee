//! Bounded nonpaged MDL metadata and synthetic guest page identities.
//!
//! Plans have no native side effects. The engine must apply validated writes,
//! allocate/free the descriptor in its kernel pool, and implement `MapAlias`
//! with genuinely shared, owned backing before committing the returned state.
//! Copying bytes into a second mapping does not satisfy this contract. Native
//! CPU permissions and API writes must both enforce read-only/NX aliases.
//! Probe/lock, unlock, kernel mappings and IRP/quota allocation are unsupported.
use crate::{
    memory::{AddressSpace, PAGE, Permissions},
    pe::Architecture,
    pool::Pool,
};
use serde::Serialize;
use std::collections::BTreeMap;
use thiserror::Error;

const MAX_DESCRIPTORS: usize = 4096;
const MAX_ALIASES: usize = 4096;
const MAX_FRAMES: usize = 32768;
const GRANULARITY: u64 = 65536;
const SOURCE_IS_NONPAGED_POOL: u16 = 4;

#[derive(Debug, Error)]
#[error("Guest MDL: {0}")]
pub struct MdlError(pub &'static str);
type Result<T> = std::result::Result<T, MdlError>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Layout {
    architecture: Architecture,
    buffer: u64,
    length: u32,
    pages: u32,
    size: u16,
}
impl Layout {
    pub fn buffer(&self) -> u64 {
        self.buffer
    }
    pub fn length(&self) -> u32 {
        self.length
    }
    pub fn pages(&self) -> u32 {
        self.pages
    }
    pub fn size(&self) -> u16 {
        self.size
    }
    pub fn start(&self) -> u64 {
        self.buffer & !(PAGE - 1)
    }
    pub fn byte_offset(&self) -> u32 {
        (self.buffer & (PAGE - 1)) as u32
    }
    pub fn header_size(&self) -> usize {
        if self.architecture == Architecture::X64 {
            48
        } else {
            28
        }
    }
    fn start_offset(&self) -> usize {
        if self.architecture == Architecture::X64 {
            32
        } else {
            16
        }
    }
    fn mapped_offset(&self) -> usize {
        if self.architecture == Architecture::X64 {
            24
        } else {
            12
        }
    }
    pub fn initial_bytes(&self) -> Vec<u8> {
        let width = self.architecture.width();
        let start = self.start_offset();
        let mut bytes = vec![0; self.size as usize];
        bytes[width..width + 2].copy_from_slice(&self.size.to_le_bytes());
        put_pointer(&mut bytes, start, self.start(), width);
        bytes[start + width..start + width + 4].copy_from_slice(&self.length.to_le_bytes());
        bytes[start + width + 4..start + width + 8]
            .copy_from_slice(&self.byte_offset().to_le_bytes());
        bytes
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Descriptor {
    pub layout: Layout,
    pub built: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Alias {
    pub base: u64,
    pub source_base: u64,
    pub size: u64,
    pub returned: u64,
    pub mdl: u64,
    pub owner: u64,
    pub readonly: bool,
}
impl Alias {
    pub fn permissions(&self) -> Permissions {
        if self.readonly {
            Permissions::READ
        } else {
            Permissions::RW
        }
    }
}

#[derive(Clone, Debug)]
pub struct GuestWrite {
    pub address: u64,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
pub enum Effect {
    None,
    MapAlias(Alias),
    UnmapAlias(Alias),
    FreeDescriptor { pointer: u64, size: u16 },
}

/// Commit `state` and `memory` only after every write/native effect succeeds.
#[derive(Clone, Debug)]
pub struct Plan {
    pub state: Mdls,
    pub memory: AddressSpace,
    pub writes: Vec<GuestWrite>,
    pub effect: Effect,
    pub result: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct MapRequest {
    pub pointer: u64,
    pub mode: u64,
    pub cache: u64,
    pub requested_address: u64,
    pub bugcheck_on_failure: u64,
    pub priority: u64,
    pub process: u64,
    pub irql: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Mdls {
    architecture: Architecture,
    descriptors: BTreeMap<u64, Descriptor>,
    frames: BTreeMap<u64, u64>,
    aliases: BTreeMap<u64, Alias>,
    next_alias: u64,
}

fn put_pointer(bytes: &mut [u8], offset: usize, value: u64, width: usize) {
    bytes[offset..offset + width].copy_from_slice(&value.to_le_bytes()[..width]);
}
fn get_pointer(bytes: &[u8], offset: usize, width: usize) -> u64 {
    let mut value = [0; 8];
    value[..width].copy_from_slice(&bytes[offset..offset + width]);
    u64::from_le_bytes(value)
}
fn range_end(address: u64, size: u64) -> Result<u64> {
    address.checked_add(size).ok_or(MdlError("range overflow"))
}
fn require(memory: &AddressSpace, address: u64, size: u64, permissions: Permissions) -> Result<()> {
    if !memory.allows(address, size, permissions) {
        return Err(MdlError("range is unmapped or lacks required permissions"));
    }
    Ok(())
}

impl Mdls {
    pub fn new(architecture: Architecture) -> Self {
        Self {
            architecture,
            descriptors: BTreeMap::new(),
            frames: BTreeMap::new(),
            aliases: BTreeMap::new(),
            next_alias: 0x40000000,
        }
    }
    pub fn descriptor_count(&self) -> usize {
        self.descriptors.len()
    }
    pub fn frame_count(&self) -> usize {
        self.frames.len()
    }
    pub fn alias_count(&self) -> usize {
        self.aliases.len()
    }
    pub fn descriptors(&self) -> &BTreeMap<u64, Descriptor> {
        &self.descriptors
    }
    pub fn aliases(&self) -> &BTreeMap<u64, Alias> {
        &self.aliases
    }

    /// `length` has the ULONG ABI width; BOOLEAN quota uses only its low byte.
    /// SecondaryBuffer is inert when IRP is null, matching the supported scope.
    pub fn allocation_layout(
        &self,
        address: u64,
        length: u64,
        quota: u64,
        irp: u64,
    ) -> Result<Option<Layout>> {
        if irp != 0 || quota as u8 != 0 {
            return Err(MdlError("IRP-linked/quota allocation is not modeled"));
        }
        let length = length as u32;
        let limit = 1u128 << (self.architecture.width() * 8);
        if length == 0 || address as u128 + length as u128 > limit {
            return Ok(None);
        }
        let pages = ((address & (PAGE - 1)) + u64::from(length)).div_ceil(PAGE);
        let header = if self.architecture == Architecture::X64 {
            48
        } else {
            28
        };
        let size = header + pages * self.architecture.width() as u64;
        if size > i16::MAX as u64 || self.descriptors.len() >= MAX_DESCRIPTORS {
            return Err(MdlError("descriptor exceeds the modeled size/count limit"));
        }
        Ok(Some(Layout {
            architecture: self.architecture,
            buffer: address,
            length,
            pages: pages as u32,
            size: size as u16,
        }))
    }

    fn plan(&self, memory: &AddressSpace) -> Plan {
        Plan {
            state: self.clone(),
            memory: memory.clone(),
            writes: vec![],
            effect: Effect::None,
            result: 0,
        }
    }
    fn descriptor<'a>(&'a self, memory: &AddressSpace, pointer: u64) -> Result<&'a Descriptor> {
        let descriptor = self
            .descriptors
            .get(&pointer)
            .ok_or(MdlError("unsupported or freed descriptor"))?;
        require(
            memory,
            pointer,
            u64::from(descriptor.layout.size),
            Permissions::READ,
        )?;
        Ok(descriptor)
    }
    /// The caller first allocates an owned NX kernel-pool descriptor of `size()`.
    /// A pool allocation failure returns null without calling this method.
    pub fn prepare_allocate(
        &self,
        memory: &AddressSpace,
        pointer: u64,
        layout: Layout,
    ) -> Result<Plan> {
        if layout.architecture != self.architecture || self.descriptors.len() >= MAX_DESCRIPTORS {
            return Err(MdlError("descriptor architecture/count mismatch"));
        }
        require(memory, pointer, u64::from(layout.size), Permissions::RW)?;
        let end = range_end(pointer, u64::from(layout.size))?;
        if self
            .descriptors
            .iter()
            .any(|(start, item)| pointer < *start + u64::from(item.layout.size) && *start < end)
        {
            return Err(MdlError(
                "descriptor storage overlaps an existing descriptor",
            ));
        }
        let mut plan = self.plan(memory);
        plan.writes.push(GuestWrite {
            address: pointer,
            bytes: layout.initial_bytes(),
        });
        plan.state.descriptors.insert(
            pointer,
            Descriptor {
                layout,
                built: false,
            },
        );
        plan.result = pointer;
        Ok(plan)
    }

    fn frame(&mut self, address: u64) -> Result<u64> {
        let page = address & !(PAGE - 1);
        let source = self
            .aliases
            .values()
            .find_map(|alias| {
                (page >= alias.base && page - alias.base < alias.size)
                    .then(|| alias.source_base + (page - alias.base))
            })
            .unwrap_or(page);
        if let Some(frame) = self.frames.get(&source) {
            return Ok(*frame);
        }
        if self.frames.len() >= MAX_FRAMES {
            return Err(MdlError("guest physical page identity limit exceeded"));
        }
        let frame = 256 + self.frames.len() as u64;
        self.frames.insert(source, frame);
        Ok(frame)
    }

    pub fn prepare_build(
        &self,
        memory: &AddressSpace,
        pointer: u64,
        current: &[u8],
    ) -> Result<Plan> {
        let descriptor = self.descriptor(memory, pointer)?;
        let layout = &descriptor.layout;
        require(
            memory,
            layout.buffer,
            u64::from(layout.length),
            Permissions::READ,
        )?;
        require(memory, pointer, u64::from(layout.size), Permissions::WRITE)?;
        if current.len() != layout.size as usize {
            return Err(MdlError("descriptor byte length mismatch"));
        }
        let width = self.architecture.width();
        let start = layout.start_offset();
        if u16::from_le_bytes(current[width..width + 2].try_into().unwrap()) != layout.size
            || get_pointer(current, start, width) != layout.start()
            || u32::from_le_bytes(
                current[start + width..start + width + 4]
                    .try_into()
                    .unwrap(),
            ) != layout.length
            || u32::from_le_bytes(
                current[start + width + 4..start + width + 8]
                    .try_into()
                    .unwrap(),
            ) != layout.byte_offset()
        {
            return Err(MdlError("modified descriptor geometry is not modeled"));
        }
        let mut plan = self.plan(memory);
        let mut bytes = current.to_vec();
        let flags = u16::from_le_bytes(bytes[width + 2..width + 4].try_into().unwrap());
        bytes[width + 2..width + 4]
            .copy_from_slice(&(flags | SOURCE_IS_NONPAGED_POOL).to_le_bytes());
        put_pointer(&mut bytes, layout.mapped_offset(), layout.buffer, width);
        for index in 0..layout.pages {
            let frame = plan.state.frame(layout.start() + u64::from(index) * PAGE)?;
            put_pointer(
                &mut bytes,
                layout.header_size() + index as usize * width,
                frame,
                width,
            );
        }
        plan.state.descriptors.get_mut(&pointer).unwrap().built = true;
        plan.writes.push(GuestWrite {
            address: pointer,
            bytes,
        });
        Ok(plan)
    }

    pub fn prepare_free(&self, memory: &AddressSpace, pointer: u64) -> Result<Plan> {
        let descriptor = self.descriptor(memory, pointer)?;
        if self.aliases.values().any(|alias| alias.mdl == pointer) {
            return Err(MdlError("freeing an MDL with active mappings"));
        }
        let mut plan = self.plan(memory);
        plan.effect = Effect::FreeDescriptor {
            pointer,
            size: descriptor.layout.size,
        };
        plan.state.descriptors.remove(&pointer);
        Ok(plan)
    }

    /// Returns the full PHYSICAL_ADDRESS. The x86 adapter splits it into EDX:EAX.
    pub fn prepare_physical_address(&self, memory: &AddressSpace, address: u64) -> Result<Plan> {
        require(memory, address, 1, Permissions::READ)?;
        let mut plan = self.plan(memory);
        plan.result = plan.state.frame(address)? * PAGE + (address & (PAGE - 1));
        Ok(plan)
    }

    fn alias_base(&self, memory: &AddressSpace, size: u64) -> Result<(u64, u64)> {
        let limit = if self.architecture == Architecture::X86 {
            0x7fff0000
        } else {
            0x00007fff00000000
        };
        let mut base = self.next_alias;
        for region in memory.regions() {
            let end = range_end(base, size)?;
            if region.base >= end {
                break;
            }
            let region_end = range_end(region.base, region.size)?;
            if region_end > base {
                base = region_end
                    .checked_add(GRANULARITY - 1)
                    .map(|value| value & !(GRANULARITY - 1))
                    .ok_or(MdlError("alias address space exhausted"))?;
            }
        }
        let end = range_end(base, size)?;
        let next = end
            .checked_add(GRANULARITY - 1)
            .map(|value| value & !(GRANULARITY - 1))
            .ok_or(MdlError("alias address space exhausted"))?;
        if end > limit || next > limit {
            return Err(MdlError("alias address space exhausted"));
        }
        Ok((base, next))
    }

    pub fn prepare_map(
        &self,
        memory: &AddressSpace,
        pool: &Pool,
        request: MapRequest,
    ) -> Result<Plan> {
        let descriptor = self.descriptor(memory, request.pointer)?;
        if !descriptor.built {
            return Err(MdlError("pages have not been built/locked"));
        }
        if request.mode as u8 != 1
            || request.cache as u32 != 1
            || request.requested_address != 0
            || request.bugcheck_on_failure as u8 != 0
        {
            return Err(MdlError(
                "only automatically placed cached user mappings are modeled",
            ));
        }
        if request.irql > 1 {
            return Err(MdlError("user mapping above APC_LEVEL"));
        }
        let priority = request.priority as u32;
        if priority & !0xc0000030 != 0 || priority & 0x30 == 0x30 {
            return Err(MdlError("unsupported mapping priority"));
        }
        if self.aliases.len() >= MAX_ALIASES {
            return Err(MdlError("mapping limit exceeded"));
        }
        let layout = &descriptor.layout;
        let end = range_end(layout.buffer, u64::from(layout.length))?;
        let active_nx_pool = pool.allocations.values().any(|allocation| {
            !allocation.paged
                && !allocation.executable
                && allocation.base <= layout.buffer
                && allocation
                    .base
                    .checked_add(allocation.requested)
                    .is_some_and(|stop| end <= stop)
        });
        if !active_nx_pool {
            return Err(MdlError(
                "aliases require an active modeled NX nonpaged pool allocation",
            ));
        }
        let source_base = layout.start();
        let size = u64::from(layout.pages) * PAGE;
        require(memory, source_base, size, Permissions::RW)?;
        for page in (source_base..range_end(source_base, size)?).step_by(PAGE as usize) {
            if memory
                .region(page)
                .is_none_or(|region| region.permissions != Permissions::RW)
            {
                return Err(MdlError("source pages must be readable/writable and NX"));
            }
        }
        let (base, next) = self.alias_base(memory, size)?;
        let alias = Alias {
            base,
            source_base,
            size,
            returned: base + u64::from(layout.byte_offset()),
            mdl: request.pointer,
            owner: request.process,
            readonly: priority & 0x80000000 != 0,
        };
        let mut plan = self.plan(memory);
        plan.memory
            .map(
                base,
                size,
                alias.permissions(),
                Some(alias.owner),
                "kernel MDL user alias",
            )
            .map_err(|_| MdlError("alias metadata mapping failed"))?;
        plan.state.next_alias = next;
        plan.state.aliases.insert(alias.returned, alias.clone());
        plan.result = alias.returned;
        plan.effect = Effect::MapAlias(alias);
        Ok(plan)
    }

    pub fn prepare_unmap(
        &self,
        memory: &AddressSpace,
        address: u64,
        pointer: u64,
        process: u64,
        irql: u8,
    ) -> Result<Plan> {
        self.descriptor(memory, pointer)?;
        let alias = self
            .aliases
            .get(&address)
            .filter(|alias| alias.mdl == pointer)
            .ok_or(MdlError("invalid mapping address or descriptor"))?;
        if alias.owner != process || irql > 1 {
            return Err(MdlError(
                "unmap requires original process at APC_LEVEL or below",
            ));
        }
        let mut plan = self.plan(memory);
        plan.memory
            .unmap(alias.base, alias.size)
            .map_err(|_| MdlError("alias metadata unmap failed"))?;
        plan.state.aliases.remove(&address);
        plan.effect = Effect::UnmapAlias(alias.clone());
        Ok(plan)
    }

    /// Invoke for every modeled API write, including writes that bypass CPU page checks.
    pub fn require_api_write(&self, address: u64, size: u64) -> Result<()> {
        if size == 0 {
            return Ok(());
        }
        let end = range_end(address, size)?;
        if self
            .aliases
            .values()
            .any(|alias| alias.readonly && address < alias.base + alias.size && alias.base < end)
        {
            return Err(MdlError("kernel API write to a read-only MDL alias"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool::Allocation;

    fn fixture(architecture: Architecture) -> (Mdls, AddressSpace, Pool, u64, u64) {
        let source = if architecture == Architecture::X64 {
            0xffffb00000000000
        } else {
            0xe0000000
        };
        let pointer = source + 0x8000;
        let mut memory = AddressSpace::new(architecture);
        memory
            .map(source, 0x4000, Permissions::RW, None, "NX pool")
            .unwrap();
        memory
            .map(pointer, PAGE, Permissions::RW, None, "MDL pool")
            .unwrap();
        let mut pool = Pool::default();
        pool.commit_allocation(Allocation {
            base: source,
            requested: 0x4000,
            mapped: 0x4000,
            tag: 1,
            paged: false,
            executable: false,
            zero_initialized: true,
        });
        (Mdls::new(architecture), memory, pool, pointer, source)
    }
    fn built(architecture: Architecture) -> (Mdls, AddressSpace, Pool, u64, u64) {
        let (state, memory, pool, pointer, source) = fixture(architecture);
        let layout = state
            .allocation_layout(source + 0x123, 0x2000, 0, 0)
            .unwrap()
            .unwrap();
        let initial = layout.initial_bytes();
        let plan = state.prepare_allocate(&memory, pointer, layout).unwrap();
        let plan = plan
            .state
            .prepare_build(&memory, pointer, &initial)
            .unwrap();
        (plan.state, memory, pool, pointer, source)
    }
    fn request(pointer: u64) -> MapRequest {
        MapRequest {
            pointer,
            mode: 1,
            cache: 1,
            requested_address: 0,
            bugcheck_on_failure: 0,
            priority: 0,
            process: 7,
            irql: 0,
        }
    }

    #[test]
    fn layouts_match_both_guest_abis_and_preserve_unaligned_geometry() {
        for architecture in [Architecture::X86, Architecture::X64] {
            let (state, memory, _, pointer, source) = fixture(architecture);
            let width = architecture.width();
            let layout = state
                .allocation_layout(source + 0x123, 0x2000, 0, 0)
                .unwrap()
                .unwrap();
            assert_eq!(layout.pages(), 3);
            assert_eq!(layout.size() as usize, layout.header_size() + 3 * width);
            let initial = layout.initial_bytes();
            let allocated = state
                .prepare_allocate(&memory, pointer, layout.clone())
                .unwrap();
            assert_eq!(state.descriptor_count(), 0);
            assert_eq!(allocated.writes[0].bytes, initial);
            let built = allocated
                .state
                .prepare_build(&memory, pointer, &initial)
                .unwrap();
            let bytes = &built.writes[0].bytes;
            assert_eq!(
                get_pointer(bytes, layout.mapped_offset(), width),
                source + 0x123
            );
            assert_eq!(get_pointer(bytes, layout.start_offset(), width), source);
            assert_eq!(
                u16::from_le_bytes(bytes[width + 2..width + 4].try_into().unwrap()),
                4
            );
            for index in 0..3 {
                assert_eq!(
                    get_pointer(bytes, layout.header_size() + index * width, width),
                    256 + index as u64
                );
            }
            assert_eq!(built.state.frame_count(), 3);
            let physical = built
                .state
                .prepare_physical_address(&memory, source + 0x123)
                .unwrap();
            assert_eq!(physical.result, 256 * PAGE + 0x123);
            let freed = built.state.prepare_free(&memory, pointer).unwrap();
            assert_eq!(freed.state.descriptor_count(), 0);
            assert!(freed.memory.allows(source, 0x4000, Permissions::RW));
            assert!(
                matches!(freed.effect, Effect::FreeDescriptor { pointer: p, .. } if p == pointer)
            );
            assert!(freed.state.prepare_free(&memory, pointer).is_err());
        }
    }

    #[test]
    fn malformed_geometry_permissions_and_failed_operations_preserve_state() {
        for architecture in [Architecture::X86, Architecture::X64] {
            let (state, mut memory, _, pointer, source) = fixture(architecture);
            let layout = state
                .allocation_layout(source + 0x123, 0x2000, 0, 0)
                .unwrap()
                .unwrap();
            let initial = layout.initial_bytes();
            let allocated = state
                .prepare_allocate(&memory, pointer, layout.clone())
                .unwrap()
                .state;
            for offset in [
                architecture.width(),
                layout.start_offset(),
                layout.start_offset() + architecture.width(),
                layout.start_offset() + architecture.width() + 4,
            ] {
                let mut bytes = initial.clone();
                bytes[offset] ^= 1;
                assert!(allocated.prepare_build(&memory, pointer, &bytes).is_err());
            }
            assert!(
                allocated
                    .prepare_build(&memory, pointer, &initial[..initial.len() - 1])
                    .is_err()
            );
            assert!(
                allocated
                    .prepare_allocate(&memory, pointer, layout)
                    .is_err()
            );
            assert!(!allocated.descriptors()[&pointer].built);
            assert_eq!(allocated.frame_count(), 0);
            memory.protect(pointer, PAGE, Permissions::READ).unwrap();
            assert!(allocated.prepare_build(&memory, pointer, &initial).is_err());
            memory.protect(pointer, PAGE, Permissions::RW).unwrap();
            memory.unmap(source + PAGE, PAGE).unwrap();
            assert!(allocated.prepare_build(&memory, pointer, &initial).is_err());
        }
    }

    #[test]
    fn allocation_abi_widths_limits_and_unsupported_linkage_are_explicit() {
        for architecture in [Architecture::X86, Architecture::X64] {
            let state = Mdls::new(architecture);
            assert!(state.allocation_layout(0x1000, 0, 0, 0).unwrap().is_none());
            assert_eq!(
                state
                    .allocation_layout(0x1000, (1u64 << 32) + 1, 0, 0)
                    .unwrap()
                    .unwrap()
                    .length(),
                1
            );
            let oversized = state.allocation_layout(0x1000, u32::MAX as u64, 0, 0);
            if architecture == Architecture::X86 {
                assert!(oversized.unwrap().is_none());
            } else {
                assert!(oversized.is_err());
            }
            assert!(state.allocation_layout(0x1000, 1, 1, 0).is_err());
            assert!(state.allocation_layout(0x1000, 1, 0, 1).is_err());
            assert!(
                state
                    .allocation_layout(0x1000, 1, 0x100, 0)
                    .unwrap()
                    .is_some()
            );
        }
        let x86 = Mdls::new(Architecture::X86);
        assert!(
            x86.allocation_layout(1u64 << 32, 1, 0, 0)
                .unwrap()
                .is_none()
        );
        assert!(
            x86.allocation_layout(u32::MAX as u64, 2, 0, 0)
                .unwrap()
                .is_none()
        );
        assert!(
            Mdls::new(Architecture::X64)
                .allocation_layout(u64::MAX, 2, 0, 0)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn aliases_keep_physical_identity_permissions_owner_and_lifetime() {
        for architecture in [Architecture::X86, Architecture::X64] {
            let (state, memory, pool, pointer, source) = built(architecture);
            let mut arguments = request(pointer);
            arguments.priority = 0xc0000010;
            let mapped = state.prepare_map(&memory, &pool, arguments).unwrap();
            let address = mapped.result;
            let alias = mapped.state.aliases()[&address].clone();
            assert_eq!(address & 4095, 0x123);
            assert_eq!(alias.source_base, source);
            assert_eq!(alias.size, 3 * PAGE);
            assert!(matches!(mapped.effect, Effect::MapAlias(_)));
            assert!(mapped.memory.allows(address, 0x2000, Permissions::READ));
            assert!(!mapped.memory.allows(address, 1, Permissions::WRITE));
            assert!(!mapped.memory.allows(address, 1, Permissions::EXECUTE));
            assert!(mapped.state.require_api_write(address, 4).is_err());
            assert!(mapped.state.require_api_write(alias.base - 1, 2).is_err());
            mapped.state.require_api_write(address, 0).unwrap();
            mapped
                .state
                .require_api_write(alias.base + alias.size, 1)
                .unwrap();
            assert!(mapped.state.require_api_write(u64::MAX, 2).is_err());
            let physical = mapped
                .state
                .prepare_physical_address(&mapped.memory, address)
                .unwrap();
            assert_eq!(physical.result, 256 * PAGE + 0x123);
            assert_eq!(physical.state.frame_count(), 3);
            assert!(mapped.state.prepare_free(&mapped.memory, pointer).is_err());
            assert!(
                mapped
                    .state
                    .prepare_unmap(&mapped.memory, address, pointer, 8, 0)
                    .is_err()
            );
            assert!(
                mapped
                    .state
                    .prepare_unmap(&mapped.memory, address, pointer, 7, 2)
                    .is_err()
            );
            assert!(
                mapped
                    .state
                    .prepare_unmap(&mapped.memory, address + 1, pointer, 7, 0)
                    .is_err()
            );
            let unmapped = mapped
                .state
                .prepare_unmap(&mapped.memory, address, pointer, 7, 1)
                .unwrap();
            assert!(!unmapped.memory.allows(address, 1, Permissions::READ));
            assert!(unmapped.memory.allows(source, 0x4000, Permissions::RW));
            assert_eq!(unmapped.state.alias_count(), 0);
            assert!(
                unmapped
                    .state
                    .prepare_free(&unmapped.memory, pointer)
                    .is_ok()
            );
        }
    }

    #[test]
    fn map_requires_built_active_nx_nonpaged_pool_and_supported_options() {
        for architecture in [Architecture::X86, Architecture::X64] {
            let (state, mut memory, mut pool, pointer, source) = built(architecture);
            for field in 0..8 {
                let mut arguments = request(pointer);
                match field {
                    0 => arguments.cache = 0,
                    1 => arguments.requested_address = 0x60000000,
                    2 => arguments.bugcheck_on_failure = 1,
                    3 => arguments.irql = 2,
                    4 => arguments.priority = 0x30,
                    5 => arguments.priority = 1,
                    6 => arguments.pointer += 1,
                    _ => arguments.mode = 0,
                }
                assert!(state.prepare_map(&memory, &pool, arguments).is_err());
            }
            let mut not_built = state.clone();
            not_built.descriptors.get_mut(&pointer).unwrap().built = false;
            assert!(
                not_built
                    .prepare_map(&memory, &pool, request(pointer))
                    .is_err()
            );
            for (paged, executable) in [(true, false), (false, true)] {
                let allocation = pool.allocations.get_mut(&source).unwrap();
                allocation.paged = paged;
                allocation.executable = executable;
                assert!(state.prepare_map(&memory, &pool, request(pointer)).is_err());
            }
            let allocation = pool.allocations.get_mut(&source).unwrap();
            allocation.paged = false;
            allocation.executable = false;
            memory
                .protect(source + PAGE, PAGE, Permissions::ALL)
                .unwrap();
            assert!(state.prepare_map(&memory, &pool, request(pointer)).is_err());
            memory
                .protect(source + PAGE, PAGE, Permissions::RW)
                .unwrap();
            pool.allocations.clear();
            assert!(state.prepare_map(&memory, &pool, request(pointer)).is_err());
            assert_eq!(state.alias_count(), 0);
        }
    }

    #[test]
    fn multiple_aliases_share_frames_skip_conflicts_and_unmap_independently() {
        let (state, mut memory, pool, pointer, source) = built(Architecture::X64);
        memory
            .map(0x40000000, GRANULARITY, Permissions::READ, None, "occupied")
            .unwrap();
        let first = state.prepare_map(&memory, &pool, request(pointer)).unwrap();
        assert_eq!(first.result, 0x40010123);
        assert!(first.memory.allows(first.result, 1, Permissions::RW));
        assert!(!first.memory.allows(first.result, 1, Permissions::EXECUTE));
        let second = first
            .state
            .prepare_map(&first.memory, &pool, request(pointer))
            .unwrap();
        assert_eq!(second.result, 0x40020123);
        let physical = second
            .state
            .prepare_physical_address(&second.memory, second.result + PAGE)
            .unwrap();
        assert_eq!(physical.result, 257 * PAGE + 0x123);
        let unmap = second
            .state
            .prepare_unmap(&second.memory, first.result, pointer, 7, 0)
            .unwrap();
        assert!(unmap.memory.allows(second.result, 1, Permissions::RW));
        assert!(unmap.memory.allows(source, 0x4000, Permissions::RW));
        assert_eq!(unmap.state.alias_count(), 1);
    }

    #[test]
    fn frame_and_alias_capacity_failures_do_not_change_live_state() {
        let (mut state, memory, pool, pointer, source) = built(Architecture::X86);
        state.frames = (0..MAX_FRAMES as u64)
            .map(|index| (0x100000 + index * PAGE, 256 + index))
            .collect();
        assert!(state.prepare_physical_address(&memory, source).is_err());
        assert_eq!(state.frame_count(), MAX_FRAMES);
        let alias = Alias {
            base: 0x50000000,
            source_base: source,
            size: PAGE,
            returned: 0x50000000,
            mdl: pointer,
            owner: 7,
            readonly: false,
        };
        state.aliases = (0..MAX_ALIASES as u64)
            .map(|index| (index, alias.clone()))
            .collect();
        assert!(state.prepare_map(&memory, &pool, request(pointer)).is_err());
        state.aliases.clear();
        state.next_alias = 0x7fff0000;
        assert!(state.prepare_map(&memory, &pool, request(pointer)).is_err());
        assert_eq!(state.alias_count(), 0);
    }

    #[test]
    fn repeated_build_keeps_flags_page_identity_and_descriptor_limit() {
        let (state, memory, _, pointer, _) = built(Architecture::X64);
        let descriptor = state.descriptors()[&pointer].clone();
        let mut bytes = descriptor.layout.initial_bytes();
        bytes[10..12].copy_from_slice(&0x200u16.to_le_bytes());
        let rebuilt = state.prepare_build(&memory, pointer, &bytes).unwrap();
        assert_eq!(rebuilt.state.frame_count(), 3);
        assert_eq!(
            u16::from_le_bytes(rebuilt.writes[0].bytes[10..12].try_into().unwrap()),
            0x204
        );
        let mut full = state;
        full.descriptors = (0..MAX_DESCRIPTORS as u64)
            .map(|index| (index, descriptor.clone()))
            .collect();
        assert!(full.allocation_layout(0x1000, 1, 0, 0).is_err());
        assert!(
            full.prepare_allocate(&memory, pointer, descriptor.layout)
                .is_err()
        );
        assert_eq!(full.descriptor_count(), MAX_DESCRIPTORS);
    }
}
