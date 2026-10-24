//! Engine adapter for bounded nonpaged MDLs and genuinely coherent user aliases.
//!
//! Integration contract (parent-owned shared files):
//! * `pub(crate) mod mdl`, `Model::Mdl(mdl::Call)`, ntoskrnl definition dispatch
//!   through `definition`, and `call(engine, call, args)` in API dispatch.
//! * `ApiState.mdls: mdl::State`, initialized with `State::new(architecture)`.
//! * Every `cpu::write` invokes `require_api_write` before writing nonempty data.
//! * Pool free calls `require_pool_release` before unmapping, then
//!   `release_pool_backing` only after successful native unmap.
//! * Stop-time capture calls `capture` before taking ArtifactCatalog. Serialize
//!   `report` as kernel_mdls; it reports synthetic PFNs, never physical RAM.
//! * The supported current process is the initial system-process identity4.
//!   Future attach/process adapters must update `State.process` coherently.
//!
//! The backend owns every host buffer. Guest pointer integers are used only as
//! Unicorn guest addresses; they are never converted into host pointers.
use super::*;
use anyhow::{Context, anyhow};
use emumee_core::mdl::{Alias, Effect, MapRequest, Mdls, Plan};
use std::{cell::UnsafeCell, ffi::c_void};

const PAGE: u64 = 4096;
const MAX_BACKING_PAGES: usize = 32768;
const CAPTURE_READ_LIMIT: u64 = 32 * 1024 * 1024;
const TAG: u32 = u32::from_le_bytes(*b"MdlN");

#[derive(Clone, Copy)]
pub(super) enum Call {
    Allocate,
    Build,
    Free,
    Physical,
    Map,
    Unmap,
}
/// Exact modeled routine names; provider publication must use these delegates.
pub(super) const ROUTINES: &[&str] = &[
    "IoAllocateMdl",
    "IoFreeMdl",
    "MmBuildMdlForNonPagedPool",
    "MmGetPhysicalAddress",
    "MmMapLockedPagesSpecifyCache",
    "MmUnmapLockedPages",
];
pub(super) fn definition(name: &str) -> Option<(Call, usize, T)> {
    Some(match name {
        "IoAllocateMdl" => (Call::Allocate, 5, T::Pointer),
        "IoFreeMdl" => (Call::Free, 1, T::Void),
        "MmBuildMdlForNonPagedPool" => (Call::Build, 1, T::Void),
        "MmGetPhysicalAddress" => (Call::Physical, 1, T::U64),
        "MmMapLockedPagesSpecifyCache" => (Call::Map, 6, T::Pointer),
        "MmUnmapLockedPages" => (Call::Unmap, 2, T::Void),
        _ => return None,
    })
}

#[repr(C, align(4096))]
struct OwnedPage {
    bytes: UnsafeCell<[u8; 4096]>,
}
impl OwnedPage {
    fn new(bytes: [u8; 4096]) -> Self {
        Self {
            bytes: UnsafeCell::new(bytes),
        }
    }
    fn pointer(&self) -> *mut c_void {
        self.bytes.get().cast()
    }
}

pub(crate) struct State {
    pub model: Mdls,
    /// Opaque guest identity, not a host process identifier or handle.
    pub process: u64,
    backing: BTreeMap<u64, Box<OwnedPage>>,
    poisoned: bool,
    capture_read_bytes: u64,
    capture_skipped_ranges: u64,
}
impl State {
    pub fn new(architecture: Architecture) -> Self {
        Self {
            model: Mdls::new(architecture),
            process: 4,
            backing: BTreeMap::new(),
            poisoned: false,
            capture_read_bytes: 0,
            capture_skipped_ranges: 0,
        }
    }
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub model: Mdls,
    pub owned_backing_pages: usize,
    pub current_process_identity: u64,
    pub native_effect_failure: bool,
    pub capture_read_bytes: u64,
    pub capture_skipped_ranges: u64,
    pub scope: &'static str,
}
pub(crate) fn report(engine: &Unicorn<Trace>) -> Report {
    let state = &engine.get_data().apis.mdls;
    Report {
        model: state.model.clone(),
        owned_backing_pages: state.backing.len(),
        current_process_identity: state.process,
        native_effect_failure: state.poisoned,
        capture_read_bytes: state.capture_read_bytes,
        capture_skipped_ranges: state.capture_skipped_ranges,
        scope: "Nonpaged MDL metadata, synthetic guest PFNs and coherent NX current-process user aliases of active modeled NX pool buffers. Probe/lock, unlock, kernel mappings, IRP linkage and quota remain unsupported.",
    }
}

fn ready(engine: &Unicorn<Trace>) -> Result<()> {
    ensure!(
        engine.get_data().apis.kernel_mode,
        "MDLs require a driver target"
    );
    ensure!(
        !engine.get_data().apis.mdls.poisoned,
        "MDL native effect failed; execution cannot resume safely"
    );
    Ok(())
}
fn invalidate(engine: &mut Unicorn<Trace>, address: u64, size: u64) -> Result<()> {
    let end = address.checked_add(size).context("MDL range overflow")?;
    engine
        .get_data_mut()
        .cpu
        .cache
        .invalidate(address, size as usize);
    uc(engine.ctl_remove_cache(address, end))
}
fn native_failure<T>(engine: &mut Unicorn<Trace>, error: anyhow::Error) -> Result<T> {
    // The normal API fault path stops guest execution. Keep *all* owned pages
    // alive, including partially converted source pages and uncertain aliases.
    engine.get_data_mut().apis.mdls.poisoned = true;
    Err(error.context("MDL native effect failed; execution stopped, backing retained"))
}

/// Called by the central model-write primitive, including writes bypassing CPU protection.
pub(crate) fn require_api_write(engine: &Unicorn<Trace>, address: u64, size: u64) -> Result<()> {
    engine
        .get_data()
        .apis
        .mdls
        .model
        .require_api_write(address, size)?;
    Ok(())
}

fn overlaps(a: u64, a_size: u64, b: u64, b_size: u64) -> Result<bool> {
    let a_end = a
        .checked_add(a_size)
        .context("MDL release range overflow")?;
    let b_end = b.checked_add(b_size).context("MDL owned range overflow")?;
    Ok(a < b_end && b < a_end)
}
fn require_release(
    engine: &Unicorn<Trace>,
    base: u64,
    size: u64,
    freeing_mdl: Option<u64>,
) -> Result<()> {
    ensure!(
        !engine.get_data().apis.mdls.poisoned,
        "Cannot release MDL backing after a native effect failure"
    );
    let model = &engine.get_data().apis.mdls.model;
    for (pointer, descriptor) in model.descriptors() {
        ensure!(
            Some(*pointer) == freeing_mdl
                || !overlaps(base, size, *pointer, u64::from(descriptor.layout.size()))?,
            "Kernel pool free would bypass a live MDL descriptor; use IoFreeMdl"
        );
    }
    for alias in model.aliases().values() {
        ensure!(
            !overlaps(base, size, alias.source_base, alias.size)?,
            "Kernel pool free has active MDL aliases"
        );
    }
    Ok(())
}
/// Pool-free preflight. Do not unmap or drop backing unless this succeeds.
pub(crate) fn require_pool_release(engine: &Unicorn<Trace>, base: u64, size: u64) -> Result<()> {
    require_release(engine, base, size, None)
}
/// Only after validated successful pool native unmap. No live alias may remain.
pub(crate) fn release_pool_backing(
    engine: &mut Unicorn<Trace>,
    base: u64,
    size: u64,
) -> Result<()> {
    ensure!(
        !engine.get_data().apis.mdls.poisoned,
        "Cannot drop MDL backing after a native effect failure"
    );
    let end = base
        .checked_add(size)
        .context("MDL backing release overflow")?;
    // Recheck aliases, but not descriptor bookkeeping: IoFreeMdl legitimately
    // removes the descriptor metadata in the same successful transaction.
    for alias in engine.get_data().apis.mdls.model.aliases().values() {
        ensure!(
            !overlaps(base, size, alias.source_base, alias.size)?,
            "Cannot drop backing with live MDL aliases"
        );
    }
    engine
        .get_data_mut()
        .apis
        .mdls
        .backing
        .retain(|page, _| *page < base || *page >= end);
    Ok(())
}

fn convert_source(engine: &mut Unicorn<Trace>, source: u64) -> Result<()> {
    if engine.get_data().apis.mdls.backing.contains_key(&source) {
        return Ok(());
    }
    super::reference_mapping::require_api_access(engine, source, PAGE, P::WRITE)?;
    ensure!(
        engine.get_data().apis.mdls.backing.len() < MAX_BACKING_PAGES,
        "Owned MDL backing page limit exceeded"
    );
    let mut original = [0u8; 4096];
    uc(engine.mem_read(source, &mut original))?;
    let backing = Box::new(OwnedPage::new(original));
    let pointer = backing.pointer();
    // Retain before the first destructive native operation; any error path
    // leaves the allocation live until uc_close has stopped all native access.
    engine
        .get_data_mut()
        .apis
        .mdls
        .backing
        .insert(source, backing);
    invalidate(engine, source, PAGE)?;
    uc(engine.mem_unmap(source, PAGE))?;
    // SAFETY: pointer comes exclusively from the owned aligned PAGE-byte box
    // retained in ApiState.mdls. Its address never changes. Native guest stores
    // use UnsafeCell; Rust does not form references to the shared byte storage.
    // Unicorn access is single-threaded, and this API hook pauses guest execution.
    // The pinned UnicornInner::drop calls uc_close before dropping Trace/State.
    if let Err(error) =
        unsafe { engine.mem_map_ptr(source, PAGE, Prot::READ | Prot::WRITE, pointer) }
    {
        // Best effort restores the original ordinary guest page. Regardless of
        // rollback outcome, the caller marks a fatal error and retains backing.
        let restored = engine
            .mem_map(source, PAGE, Prot::READ | Prot::WRITE)
            .and_then(|()| engine.mem_write(source, &original));
        return Err(anyhow!(
            "Source remap failed: {error:?}; original-page rollback: {restored:?}"
        ));
    }
    Ok(())
}

fn map_alias(engine: &mut Unicorn<Trace>, alias: &Alias) -> Result<()> {
    for offset in (0..alias.size).step_by(PAGE as usize) {
        convert_source(engine, alias.source_base + offset)?;
    }
    let protection = if alias.readonly {
        Prot::READ
    } else {
        Prot::READ | Prot::WRITE
    };
    let mut mapped = 0u64;
    for offset in (0..alias.size).step_by(PAGE as usize) {
        let pointer = engine.get_data().apis.mdls.backing[&(alias.source_base + offset)].pointer();
        // SAFETY: the same retained aligned UnsafeCell page owns both native
        // source and alias mappings. Every map is exactly PAGE bytes and NX.
        let result = unsafe { engine.mem_map_ptr(alias.base + offset, PAGE, protection, pointer) };
        if let Err(error) = result {
            let rollback = if mapped == 0 {
                Ok(())
            } else {
                engine.mem_unmap(alias.base, mapped)
            };
            return Err(anyhow!(
                "User alias map failed: {error:?}; partial-alias rollback: {rollback:?}"
            ));
        }
        mapped += PAGE;
    }
    invalidate(engine, alias.base, alias.size)
}

fn apply(engine: &mut Unicorn<Trace>, mut plan: Plan) -> Result<u64> {
    // All pure-state validation has completed. Native errors are fatal; neither
    // an alias result nor new descriptor state is published after partial work.
    if let Effect::MapAlias(alias) = &plan.effect {
        super::kernel_spin::require_alias(engine, alias.source_base, alias.size)?;
        crate::threads::timers::require_alias(engine, alias.source_base, alias.size)?;
    }
    let effects = (|| -> Result<()> {
        match &plan.effect {
            Effect::None => {}
            Effect::MapAlias(alias) => map_alias(engine, alias)?,
            Effect::UnmapAlias(alias) => {
                invalidate(engine, alias.base, alias.size)?;
                uc(engine.mem_unmap(alias.base, alias.size))?;
                // Source pages and their boxes remain live for later aliases.
            }
            Effect::FreeDescriptor { pointer, size } => {
                let irql = engine.get_data().apis.kernel.save().0;
                let allocation = engine
                    .get_data()
                    .apis
                    .pool
                    .prepare_free(*pointer, Some(TAG), irql)?
                    .clone();
                ensure!(
                    allocation.requested >= u64::from(*size),
                    "MDL descriptor pool size mismatch"
                );
                crate::threads::timers::require_pool_release(
                    engine,
                    allocation.base,
                    allocation.mapped,
                )?;
                super::kernel_spin::require_pool_release(
                    engine,
                    allocation.base,
                    allocation.mapped,
                )?;
                require_release(engine, allocation.base, allocation.mapped, Some(*pointer))?;
                plan.memory.unmap(allocation.base, allocation.mapped)?;
                invalidate(engine, allocation.base, allocation.mapped)?;
                uc(engine.mem_unmap(allocation.base, allocation.mapped))?;
                release_pool_backing(engine, allocation.base, allocation.mapped)?;
                engine.get_data_mut().apis.pool.commit_free(allocation.base);
                crate::threads::timers::retired_pool(engine, allocation.base, allocation.mapped)?;
                super::kernel_spin::retired_pool(engine, allocation.base, allocation.mapped)?;
            }
        }
        for write in &plan.writes {
            crate::cpu::write(engine, write.address, &write.bytes)?;
        }
        Ok(())
    })();
    if let Err(error) = effects {
        return native_failure(engine, error);
    }
    let state = &mut engine.get_data_mut().apis;
    state.mdls.model = plan.state;
    state.memory = plan.memory;
    Ok(plan.result)
}

fn allocate(engine: &mut Unicorn<Trace>, args: &[u64]) -> Result<u64> {
    super::kernel_spin::require_alias(engine, args[0], args[1])?;
    crate::threads::timers::require_alias(engine, args[0], args[1])?;
    let state = &engine.get_data().apis;
    let Some(layout) = state
        .mdls
        .model
        .allocation_layout(args[0], args[1], args[3], args[4])?
    else {
        return Ok(0);
    };
    // args[2] SecondaryBuffer has no effect in the supported null-IRP case.
    let irql = state.kernel.save().0;
    let Some(allocation) = state.pool.prepare(
        &state.memory,
        engine.get_data().architecture,
        0x40,
        u64::from(layout.size()),
        TAG,
        irql,
    )?
    else {
        return Ok(0);
    };
    let mut memory = state.memory.clone();
    memory.map(
        allocation.base,
        allocation.mapped,
        P::RW,
        None,
        "kernel MDL descriptor pool",
    )?;
    let plan = state
        .mdls
        .model
        .prepare_allocate(&memory, allocation.base, layout)?;
    let mut created = false;
    let effect = (|| -> Result<()> {
        uc(engine.mem_map(allocation.base, allocation.mapped, Prot::READ | Prot::WRITE))?;
        created = true;
        for write in &plan.writes {
            crate::cpu::write(engine, write.address, &write.bytes)?;
        }
        Ok(())
    })();
    if let Err(error) = effect {
        // No model metadata/pool ownership has been committed. Unmap only our
        // fresh allocation; never a guest-supplied or pre-existing host address.
        if created {
            let _ = engine.mem_unmap(allocation.base, allocation.mapped);
        }
        return native_failure(engine, error);
    }
    let result = allocation.base;
    let state = &mut engine.get_data_mut().apis;
    state.mdls.model = plan.state;
    state.memory = plan.memory;
    state.pool.commit_allocation(allocation);
    Ok(result)
}

pub(super) fn call(engine: &mut Unicorn<Trace>, call: Call, args: &[u64]) -> Result<u64> {
    ready(engine)?;
    let expected = match call {
        Call::Allocate => 5,
        Call::Map => 6,
        Call::Unmap => 2,
        _ => 1,
    };
    ensure!(args.len() == expected, "MDL argument count mismatch");
    if matches!(call, Call::Allocate) {
        return allocate(engine, args);
    }
    let state = &engine.get_data().apis;
    let plan = match call {
        Call::Build => {
            let size = state
                .mdls
                .model
                .descriptors()
                .get(&args[0])
                .context("Unsupported or freed MDL descriptor")?
                .layout
                .size();
            let bytes = read(engine, args[0], u64::from(size))?;
            state
                .mdls
                .model
                .prepare_build(&state.memory, args[0], &bytes)?
        }
        Call::Free => state.mdls.model.prepare_free(&state.memory, args[0])?,
        Call::Physical => state
            .mdls
            .model
            .prepare_physical_address(&state.memory, args[0])?,
        Call::Map => state.mdls.model.prepare_map(
            &state.memory,
            &state.pool,
            MapRequest {
                pointer: args[0],
                mode: args[1],
                cache: args[2],
                requested_address: args[3],
                bugcheck_on_failure: args[4],
                priority: args[5],
                process: state.mdls.process,
                irql: state.kernel.save().0,
            },
        )?,
        Call::Unmap => state.mdls.model.prepare_unmap(
            &state.memory,
            args[0],
            args[1],
            state.mdls.process,
            state.kernel.save().0,
        )?,
        Call::Allocate => unreachable!(),
    };
    apply(engine, plan)
}

/// Bounded stop-time evidence only. These remain typed memory snapshots.
pub(crate) fn capture(engine: &mut Unicorn<Trace>) {
    let descriptors = engine
        .get_data()
        .apis
        .mdls
        .model
        .descriptors()
        .iter()
        .map(|(pointer, descriptor)| (*pointer, descriptor.layout.clone()))
        .collect::<Vec<_>>();
    let mut seen = std::collections::BTreeSet::new();
    for (pointer, layout) in descriptors {
        for (address, size, source) in [
            (pointer, u64::from(layout.size()), "kernel_mdl_descriptor"),
            (
                layout.buffer(),
                u64::from(layout.length()),
                "kernel_mdl_buffer",
            ),
        ] {
            if !seen.insert((address, size)) {
                continue;
            }
            let allowed = engine
                .get_data()
                .apis
                .mdls
                .capture_read_bytes
                .checked_add(size)
                .is_some_and(|total| total <= CAPTURE_READ_LIMIT)
                && engine.get_data().apis.memory.allows(address, size, P::READ);
            if !allowed {
                crate::capture::aux_skipped(engine, size);
                engine.get_data_mut().apis.mdls.capture_skipped_ranges += 1;
                continue;
            }
            if !crate::capture::reserve_read(engine, size) {
                engine.get_data_mut().apis.mdls.capture_skipped_ranges += 1;
                continue;
            }
            match engine.mem_read_as_vec(address, size as usize) {
                Ok(bytes) => {
                    let state = &mut engine.get_data_mut().apis;
                    state.mdls.capture_read_bytes += size;
                    crate::capture::memory_record(
                        engine,
                        bytes,
                        source,
                        &format!("memory:{source}:0x{address:x}"),
                    );
                }
                Err(_) => {
                    crate::capture::aux_skipped(engine, size);
                    engine.get_data_mut().apis.mdls.capture_skipped_ranges += 1;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use emumee_core::pool::Allocation;
    fn engine(architecture: Architecture) -> crate::NativeEngine {
        let mut engine = crate::new_engine(architecture).unwrap();
        engine.get_data_mut().apis.kernel_mode = true;
        engine
    }
    fn source(engine: &mut Unicorn<Trace>) -> Allocation {
        let architecture = engine.get_data().architecture;
        let state = &engine.get_data().apis;
        let allocation = state
            .pool
            .prepare(&state.memory, architecture, 0x40, 0x4000, 1, 0)
            .unwrap()
            .unwrap();
        engine
            .mem_map(allocation.base, allocation.mapped, Prot::READ | Prot::WRITE)
            .unwrap();
        engine
            .get_data_mut()
            .apis
            .memory
            .map(
                allocation.base,
                allocation.mapped,
                P::RW,
                None,
                "test NX pool",
            )
            .unwrap();
        engine
            .get_data_mut()
            .apis
            .pool
            .commit_allocation(allocation.clone());
        allocation
    }
    #[test]
    fn backing_alignment_and_native_read_write_alias_coherence_both_abis() {
        let backing = Box::new(OwnedPage::new([0; 4096]));
        assert_eq!(backing.pointer() as usize % 4096, 0);
        for architecture in [Architecture::X86, Architecture::X64] {
            let mut engine = engine(architecture);
            let allocation = source(&mut engine);
            let buffer = allocation.base + 0x123;
            engine.mem_write(buffer, b"EMU!").unwrap();
            let pointer = call(&mut engine, Call::Allocate, &[buffer, 0x2000, 0, 0, 0]).unwrap();
            call(&mut engine, Call::Build, &[pointer]).unwrap();
            let alias = call(&mut engine, Call::Map, &[pointer, 1, 1, 0, 0, 0]).unwrap();
            assert_eq!(engine.mem_read_as_vec(alias, 4).unwrap(), b"EMU!");
            engine.mem_write(alias, b"CPU!").unwrap();
            assert_eq!(engine.mem_read_as_vec(buffer, 4).unwrap(), b"CPU!");
            crate::cpu::write(&mut engine, buffer, b"API!").unwrap();
            assert_eq!(engine.mem_read_as_vec(alias, 4).unwrap(), b"API!");
            let source_pfn = call(&mut engine, Call::Physical, &[buffer]).unwrap();
            assert_eq!(
                source_pfn,
                call(&mut engine, Call::Physical, &[alias]).unwrap()
            );
            assert!(require_pool_release(&engine, allocation.base, allocation.mapped).is_err());
            assert!(call(&mut engine, Call::Free, &[pointer]).is_err());
            call(&mut engine, Call::Unmap, &[alias, pointer]).unwrap();
            assert!(engine.mem_read_as_vec(alias, 1).is_err());
            call(&mut engine, Call::Free, &[pointer]).unwrap();
            assert!(engine.mem_read_as_vec(pointer, 1).is_err());
            require_pool_release(&engine, allocation.base, allocation.mapped).unwrap();
            engine
                .mem_unmap(allocation.base, allocation.mapped)
                .unwrap();
            release_pool_backing(&mut engine, allocation.base, allocation.mapped).unwrap();
            assert!(engine.get_data().apis.mdls.backing.is_empty());
        }
    }
    #[test]
    fn readonly_alias_write_guard_owner_and_nx_native_permissions() {
        for architecture in [Architecture::X86, Architecture::X64] {
            let mut engine = engine(architecture);
            let allocation = source(&mut engine);
            let pointer =
                call(&mut engine, Call::Allocate, &[allocation.base, 16, 0, 0, 0]).unwrap();
            call(&mut engine, Call::Build, &[pointer]).unwrap();
            let alias = call(&mut engine, Call::Map, &[pointer, 1, 1, 0, 0, 0x80000000]).unwrap();
            assert!(require_api_write(&engine, alias, 4).is_err());
            require_api_write(&engine, alias, 0).unwrap();
            let regions = engine.mem_regions().unwrap();
            let region = regions
                .iter()
                .find(|region| region.begin <= alias && alias <= region.end)
                .unwrap();
            assert_eq!(region.perms, Prot::READ.0 as u32);
            assert!(require_pool_release(&engine, pointer, PAGE).is_err());
            engine.get_data_mut().apis.mdls.process = 8;
            assert!(call(&mut engine, Call::Unmap, &[alias, pointer]).is_err());
            engine.get_data_mut().apis.mdls.process = 4;
            call(&mut engine, Call::Unmap, &[alias, pointer]).unwrap();
            call(&mut engine, Call::Free, &[pointer]).unwrap();
        }
    }

    #[test]
    fn partial_native_alias_failure_rolls_back_owned_alias_pages_and_keeps_backing() {
        let mut engine = engine(Architecture::X64);
        let allocation = source(&mut engine);
        let buffer = allocation.base + 0x123;
        engine.mem_write(buffer, b"SAFE").unwrap();
        let pointer = call(&mut engine, Call::Allocate, &[buffer, 0x2000, 0, 0, 0]).unwrap();
        call(&mut engine, Call::Build, &[pointer]).unwrap();
        // Deliberately create a native/model disagreement on the second alias
        // page. It must remain untouched; only our successful first page rolls back.
        engine
            .mem_map(0x40001000, PAGE, Prot::READ | Prot::WRITE)
            .unwrap();
        engine.mem_write(0x40001000, b"KEEP").unwrap();
        assert!(call(&mut engine, Call::Map, &[pointer, 1, 1, 0, 0, 0]).is_err());
        assert!(engine.mem_read_as_vec(0x40000000, 1).is_err());
        assert_eq!(engine.mem_read_as_vec(0x40001000, 4).unwrap(), b"KEEP");
        assert_eq!(engine.mem_read_as_vec(buffer, 4).unwrap(), b"SAFE");
        assert_eq!(engine.get_data().apis.mdls.model.alias_count(), 0);
        assert_eq!(engine.get_data().apis.mdls.backing.len(), 3);
        assert!(engine.get_data().apis.mdls.poisoned);
        assert!(call(&mut engine, Call::Physical, &[buffer]).is_err());
        assert!(require_pool_release(&engine, allocation.base, allocation.mapped).is_err());
    }
}
