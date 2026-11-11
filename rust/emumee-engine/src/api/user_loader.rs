use super::*;
use anyhow::Context;
use emumee_core::{modules::ModuleId, persona::Encoding, virtual_memory as vm};

const LDR_SIZE: u64 = 8 * 1024 * 1024;
const ROWS: u64 = 0x1000;
const STRINGS: u64 = 0x50000;
const SLOTS: usize = 1024;
const TLS_LIMIT: u64 = 64 * 1024 * 1024;

#[derive(Clone, Debug, Serialize)]
pub struct Entry {
    pub module: ModuleId,
    pub address: u64,
    pub base: u64,
    pub name: String,
    pub path: String,
    pub references: u32,
    pub initialized: bool,
}
#[derive(Clone, Debug, Serialize)]
pub struct ThreadStorage {
    pub teb: u64,
    pub vector: u64,
    pub blocks: BTreeMap<usize, u64>,
}
struct Slot {
    module: ModuleId,
    template: Vec<u8>,
    size: u64,
    alignment: u64,
}
#[derive(Default)]
pub(crate) struct State {
    ldr: u64,
    previous_bytes: usize,
    pub(crate) entries: Vec<Entry>,
    slots: Vec<Option<Slot>>,
    pub(crate) threads: BTreeMap<u64, ThreadStorage>,
    ranges: BTreeMap<u64, u64>,
    tls_bytes: u64,
    publications: u64,
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub ldr: u64,
    pub entries: Vec<Entry>,
    pub threads: BTreeMap<u64, ThreadStorage>,
    pub slot_modules: Vec<Option<ModuleId>>,
    pub tls_bytes: u64,
    pub publications: u64,
}
pub(crate) fn report(engine: &Unicorn<Trace>) -> Option<Report> {
    let state = &engine.get_data().apis.user_loader;
    (state.ldr != 0).then(|| Report {
        ldr: state.ldr,
        entries: state.entries.clone(),
        threads: state.threads.clone(),
        slot_modules: state
            .slots
            .iter()
            .map(|slot| slot.as_ref().map(|slot| slot.module))
            .collect(),
        tls_bytes: state.tls_bytes,
        publications: state.publications,
    })
}
pub(crate) fn require_change(engine: &Unicorn<Trace>, address: u64, size: u64) -> Result<()> {
    let end = address
        .checked_add(size.max(1))
        .context("Owned loader range overflow")?;
    ensure!(
        !engine
            .get_data()
            .apis
            .user_loader
            .ranges
            .iter()
            .any(|(base, size)| address < base + size && *base < end),
        "Mapping change overlaps owned user loader/TLS storage"
    );
    Ok(())
}
pub(crate) fn allocate(engine: &mut Unicorn<Trace>, size: u64) -> Result<u64> {
    let state = &engine.get_data().apis;
    let plan =
        state
            .allocations
            .allocate(&state.memory, 0, size.max(1), vm::RESERVE | vm::COMMIT, 4)?;
    let address = allocation::apply(engine, plan)?;
    engine
        .get_data_mut()
        .apis
        .user_loader
        .ranges
        .insert(address, size.max(1).div_ceil(4096) * 4096);
    Ok(address)
}
pub(crate) fn release(engine: &mut Unicorn<Trace>, address: u64) -> Result<()> {
    let state = &engine.get_data().apis;
    let plan = state
        .allocations
        .free(&state.memory, address, 0, vm::RELEASE)?;
    allocation::apply(engine, plan)?;
    engine
        .get_data_mut()
        .apis
        .user_loader
        .ranges
        .remove(&address);
    Ok(())
}
fn pointer(engine: &mut Unicorn<Trace>, address: u64, value: u64) -> Result<()> {
    let width = engine.get_data().architecture.width();
    crate::cpu::write(engine, address, &value.to_le_bytes()[..width])
}
fn preflight_allocations(
    engine: &Unicorn<Trace>,
    memory: &AddressSpace,
    sizes: &[u64],
) -> Result<()> {
    let mut memory = memory.clone();
    let mut allocations = engine.get_data().apis.allocations.clone();
    for size in sizes {
        let plan = allocations.allocate(&memory, 0, (*size).max(1), vm::RESERVE | vm::COMMIT, 4)?;
        memory = plan.memory;
        allocations = plan.state;
    }
    Ok(())
}
fn preflight_tls(
    engine: &Unicorn<Trace>,
    memory: &AddressSpace,
    sizes: &[u64],
    extra: &[u64],
) -> Result<()> {
    let cost = sizes
        .iter()
        .try_fold(0u64, |total, size| {
            total.checked_add(size.div_ceil(4096) * 4096)
        })
        .context("Static TLS reservation overflow")?;
    ensure!(
        engine
            .get_data()
            .apis
            .user_loader
            .tls_bytes
            .checked_add(cost)
            .is_some_and(|total| total <= TLS_LIMIT),
        "Aggregate static TLS quota exceeded"
    );
    let mut all = extra.to_vec();
    all.extend(sizes);
    preflight_allocations(engine, memory, &all)
}
pub(crate) fn preflight_thread(engine: &Unicorn<Trace>, stack_size: u64) -> Result<()> {
    let mut sizes = vec![(SLOTS * engine.get_data().architecture.width()) as u64];
    sizes.extend(
        engine
            .get_data()
            .apis
            .user_loader
            .slots
            .iter()
            .flatten()
            .map(|slot| slot.size + slot.alignment),
    );
    preflight_tls(
        engine,
        &engine.get_data().apis.memory,
        &sizes,
        &[stack_size, 8192],
    )
}
pub(crate) fn preflight_storage(
    engine: &Unicorn<Trace>,
    memory: &AddressSpace,
    storage: &[emumee_core::pe::TlsStorage],
) -> Result<()> {
    if storage.is_empty() {
        return Ok(());
    }
    ensure!(
        engine.get_data().apis.user_loader.slots.len() + storage.len() <= SLOTS,
        "Static TLS index generation quota exceeded"
    );
    let mut sizes = Vec::new();
    for plan in storage {
        let size =
            (plan.initialized_bytes as u64 + plan.zero_fill as u64).max(1) + plan.alignment as u64;
        sizes.extend(std::iter::repeat_n(
            size,
            engine.get_data().apis.user_loader.threads.len(),
        ));
    }
    preflight_tls(engine, memory, &sizes, &[])
}
pub(crate) fn attach_thread(engine: &mut Unicorn<Trace>, thread: u64, teb: u64) -> Result<()> {
    ensure!(
        !engine
            .get_data()
            .apis
            .user_loader
            .threads
            .contains_key(&thread),
        "TLS thread identity already exists"
    );
    let width = engine.get_data().architecture.width();
    let cost = SLOTS as u64 * width as u64
        + engine
            .get_data()
            .apis
            .user_loader
            .slots
            .iter()
            .flatten()
            .map(|slot| (slot.size + slot.alignment).div_ceil(4096) * 4096)
            .sum::<u64>();
    ensure!(
        engine.get_data().apis.user_loader.tls_bytes + cost <= TLS_LIMIT,
        "Aggregate static TLS quota exceeded"
    );
    let vector = allocate(engine, (SLOTS * width) as u64)?;
    engine.get_data_mut().apis.user_loader.threads.insert(
        thread,
        ThreadStorage {
            teb,
            vector,
            blocks: BTreeMap::new(),
        },
    );
    pointer(engine, teb + if width == 8 { 0x58 } else { 0x2c }, vector)?;
    engine.get_data_mut().apis.user_loader.tls_bytes += (SLOTS * width) as u64;
    for index in 0..engine.get_data().apis.user_loader.slots.len() {
        if engine.get_data().apis.user_loader.slots[index].is_some() {
            install_block(engine, thread, index)?;
        }
    }
    Ok(())
}
fn install_block(engine: &mut Unicorn<Trace>, thread: u64, index: usize) -> Result<()> {
    let slot = engine.get_data().apis.user_loader.slots[index]
        .as_ref()
        .unwrap();
    let (size, alignment, template) = (slot.size, slot.alignment, slot.template.clone());
    let cost = (size + alignment).div_ceil(4096) * 4096;
    ensure!(
        engine.get_data().apis.user_loader.tls_bytes + cost <= TLS_LIMIT,
        "Aggregate static TLS quota exceeded"
    );
    let backing = allocate(engine, size + alignment)?;
    let block = (backing + alignment - 1) & !(alignment - 1);
    crate::cpu::write(engine, block, &template)?;
    let vector = engine.get_data().apis.user_loader.threads[&thread].vector;
    pointer(
        engine,
        vector + index as u64 * engine.get_data().architecture.width() as u64,
        block,
    )?;
    let state = &mut engine.get_data_mut().apis.user_loader;
    state
        .threads
        .get_mut(&thread)
        .unwrap()
        .blocks
        .insert(index, backing);
    state.tls_bytes += cost;
    Ok(())
}
pub(crate) fn detach_thread(engine: &mut Unicorn<Trace>, thread: u64) -> Result<()> {
    let storage = engine
        .get_data()
        .apis
        .user_loader
        .threads
        .get(&thread)
        .context("TLS thread is absent")?
        .clone();
    let mut cost = SLOTS as u64 * engine.get_data().architecture.width() as u64;
    for (index, block) in &storage.blocks {
        if let Some(slot) = &engine.get_data().apis.user_loader.slots[*index] {
            cost += (slot.size + slot.alignment).div_ceil(4096) * 4096;
        }
        release(engine, *block)?;
    }
    release(engine, storage.vector)?;
    engine
        .get_data_mut()
        .apis
        .user_loader
        .threads
        .remove(&thread);
    engine.get_data_mut().apis.user_loader.tls_bytes -= cost;
    Ok(())
}
fn reconcile_tls(engine: &mut Unicorn<Trace>) -> Result<()> {
    let retired = engine
        .get_data()
        .apis
        .user_loader
        .slots
        .iter()
        .enumerate()
        .filter_map(|(index, slot)| {
            slot.as_ref()
                .filter(|slot| {
                    engine
                        .get_data()
                        .apis
                        .modules
                        .by_identity(slot.module)
                        .is_none()
                })
                .map(|_| index)
        })
        .collect::<Vec<_>>();
    for index in retired {
        let threads = engine
            .get_data()
            .apis
            .user_loader
            .threads
            .keys()
            .copied()
            .collect::<Vec<_>>();
        let slot = engine.get_data().apis.user_loader.slots[index]
            .as_ref()
            .unwrap();
        let cost = (slot.size + slot.alignment).div_ceil(4096) * 4096;
        for thread in threads {
            let storage = &engine.get_data().apis.user_loader.threads[&thread];
            let (vector, backing) = (storage.vector, storage.blocks.get(&index).copied());
            pointer(
                engine,
                vector + index as u64 * engine.get_data().architecture.width() as u64,
                0,
            )?;
            if let Some(backing) = backing {
                release(engine, backing)?;
                let state = &mut engine.get_data_mut().apis.user_loader;
                state
                    .threads
                    .get_mut(&thread)
                    .unwrap()
                    .blocks
                    .remove(&index);
                state.tls_bytes -= cost;
            }
        }
        engine.get_data_mut().apis.user_loader.slots[index] = None;
    }
    let modules = engine
        .get_data()
        .apis
        .modules
        .modules()
        .filter_map(|module| {
            module
                .initializer_tls()
                .and_then(|tls| tls.storage.as_ref())
                .map(|storage| (module.identity(), module.base, storage.clone()))
        })
        .collect::<Vec<_>>();
    let new_storage = modules
        .iter()
        .filter(|(module, _, _)| {
            !engine
                .get_data()
                .apis
                .user_loader
                .slots
                .iter()
                .flatten()
                .any(|slot| slot.module == *module)
        })
        .map(|(_, _, storage)| storage.clone())
        .collect::<Vec<_>>();
    preflight_storage(engine, &engine.get_data().apis.memory, &new_storage)?;
    for (module, base, storage) in modules {
        if engine
            .get_data()
            .apis
            .user_loader
            .slots
            .iter()
            .flatten()
            .any(|slot| slot.module == module)
        {
            continue;
        }
        let index = engine.get_data().apis.user_loader.slots.len();
        ensure!(index < SLOTS, "Static TLS index generation quota exceeded");
        require(engine, base + storage.index_rva as u64, 4, P::WRITE)?;
        let template = if let Some(rva) = storage
            .template_rva
            .filter(|_| storage.initialized_bytes != 0)
        {
            read(engine, base + rva as u64, storage.initialized_bytes as u64)?
        } else {
            vec![]
        };
        let size = (storage.initialized_bytes as u64 + storage.zero_fill as u64).max(1);
        let alignment = storage.alignment as u64;
        let threads = engine
            .get_data()
            .apis
            .user_loader
            .threads
            .keys()
            .copied()
            .collect::<Vec<_>>();
        ensure!(
            engine.get_data().apis.user_loader.tls_bytes
                + (size + alignment).div_ceil(4096) * 4096 * threads.len() as u64
                <= TLS_LIMIT,
            "Aggregate static TLS quota exceeded"
        );
        engine
            .get_data_mut()
            .apis
            .user_loader
            .slots
            .push(Some(Slot {
                module,
                template,
                size,
                alignment,
            }));
        crate::cpu::write(
            engine,
            base + storage.index_rva as u64,
            &(index as u32).to_le_bytes(),
        )?;
        for thread in threads {
            install_block(engine, thread, index)?;
        }
    }
    Ok(())
}
fn integer(bytes: &mut [u8], offset: usize, value: u64, width: usize) {
    bytes[offset..offset + width].copy_from_slice(&value.to_le_bytes()[..width]);
}
fn descriptor(
    bytes: &mut Vec<u8>,
    offset: usize,
    text: &str,
    base: u64,
    width: usize,
) -> Result<()> {
    let encoded = Encoding::Utf16.encode(text, true);
    ensure!(
        encoded.len() <= 65536 && bytes.len() + encoded.len() <= LDR_SIZE as usize,
        "Guest loader strings exceed owned quota"
    );
    integer(bytes, offset, (encoded.len() - 2) as u64, 2);
    integer(bytes, offset + 2, encoded.len().min(65534) as u64, 2);
    let address = base + bytes.len() as u64;
    integer(
        bytes,
        offset + if width == 8 { 8 } else { 4 },
        address,
        width,
    );
    bytes.extend(encoded);
    Ok(())
}
pub(crate) fn sync(engine: &mut Unicorn<Trace>) -> Result<()> {
    let Some(bootstrap) = super::user_bootstrap::report(engine) else {
        return Ok(());
    };
    if engine.get_data().apis.user_loader.ldr == 0 {
        let ldr = allocate(engine, LDR_SIZE)?;
        engine.get_data_mut().apis.user_loader.ldr = ldr;
        pointer(
            engine,
            bootstrap.peb
                + if engine.get_data().architecture.width() == 8 {
                    0x18
                } else {
                    0xc
                },
            ldr,
        )?;
        attach_thread(engine, 1, bootstrap.teb)?;
    }
    reconcile_tls(engine)?;
    let state = &engine.get_data().apis;
    let base = state.user_loader.ldr;
    let width = engine.get_data().architecture.width();
    let primary = state.modules.primary().map(|module| module.identity());
    let modules = state
        .modules
        .user_loader_order()
        .into_iter()
        .cloned()
        .collect::<Vec<_>>();
    let mut bytes = vec![0; STRINGS as usize];
    integer(&mut bytes, 0, if width == 8 { 0x58 } else { 0x30 }, 4);
    bytes[4] = 1;
    let mut entries = vec![];
    for module in &modules {
        let id = module.identity();
        let row = ROWS + id.0 * 0x100;
        ensure!(
            row + 0x100 <= STRINGS,
            "Guest loader identity generation quota exceeded"
        );
        let path = module.provenance().map_or_else(
            || module.name.clone(),
            |provenance| provenance.guest_path.clone(),
        );
        let initialized = module
            .lifecycle()
            .is_some_and(|life| life.phase == emumee_core::modules::ImagePhase::Ready)
            || module
                .dynamic_image()
                .is_some_and(|image| image.phase == emumee_core::modules::DynamicPhase::Ready)
            || module
                .provenance()
                .is_some_and(|p| p.origin == emumee_core::modules::ModuleOrigin::SyntheticProvider);
        let entry = Entry {
            module: id,
            address: base + row,
            base: module.base,
            name: module.name.clone(),
            path: path.clone(),
            references: module.api_references(),
            initialized,
        };
        let row = row as usize;
        integer(&mut bytes, row + 6 * width, module.base, width);
        integer(
            &mut bytes,
            row + 7 * width,
            if module.entry_rva() == 0 {
                0
            } else {
                module.base + module.entry_rva() as u64
            },
            width,
        );
        integer(&mut bytes, row + 8 * width, module.size, 4);
        descriptor(
            &mut bytes,
            row + if width == 8 { 0x48 } else { 0x24 },
            &path,
            base,
            width,
        )?;
        descriptor(
            &mut bytes,
            row + if width == 8 { 0x58 } else { 0x2c },
            path.rsplit('\\').next().unwrap_or(&module.name),
            base,
            width,
        )?;
        integer(
            &mut bytes,
            row + if width == 8 { 0x68 } else { 0x34 },
            if initialized { 0x80004 } else { 0x1004 },
            4,
        );
        integer(
            &mut bytes,
            row + if width == 8 { 0x6c } else { 0x38 },
            if module.lifecycle().is_some()
                || module.provenance().is_some_and(|p| {
                    p.origin == emumee_core::modules::ModuleOrigin::SyntheticProvider
                })
            {
                65535
            } else {
                module.api_references().min(65535) as u64
            },
            2,
        );
        let index = state
            .user_loader
            .slots
            .iter()
            .position(|slot| slot.as_ref().is_some_and(|slot| slot.module == id));
        integer(
            &mut bytes,
            row + if width == 8 { 0x6e } else { 0x3a },
            index.unwrap_or(0) as u64,
            2,
        );
        entries.push(entry);
    }
    for list in 0..3 {
        let head = if width == 8 { 0x10 } else { 0xc } + list * 2 * width;
        let mut order = entries
            .iter()
            .filter(|entry| {
                list != 2
                    || Some(entry.module) != primary
                    || state.modules.primary().is_some_and(|module| {
                        module
                            .lifecycle()
                            .is_some_and(|life| life.kind == emumee_core::pe::Kind::Dll)
                    })
            })
            .collect::<Vec<_>>();
        if list == 2 {
            order.sort_by_key(|entry| {
                state
                    .modules
                    .initialization_order()
                    .iter()
                    .position(|id| *id == entry.module)
                    .unwrap_or(usize::MAX)
            });
        }
        let links = std::iter::once(base + head as u64)
            .chain(
                order
                    .iter()
                    .map(|entry| entry.address + (list * 2 * width) as u64),
            )
            .collect::<Vec<_>>();
        for (index, address) in links.iter().enumerate() {
            let offset = (*address - base) as usize;
            integer(&mut bytes, offset, links[(index + 1) % links.len()], width);
            integer(
                &mut bytes,
                offset + width,
                links[(index + links.len() - 1) % links.len()],
                width,
            );
        }
    }
    let old = state.user_loader.previous_bytes;
    let mut previous = vec![0; bytes.len()];
    uc(engine.mem_read(base, &mut previous))?;
    if previous != bytes {
        if old > bytes.len() {
            crate::cpu::write(
                engine,
                base + bytes.len() as u64,
                &vec![0; old - bytes.len()],
            )?;
        }
        crate::cpu::write(engine, base, &bytes)?;
        engine.get_data_mut().apis.user_loader.publications += 1;
    }
    let state = &mut engine.get_data_mut().apis.user_loader;
    state.previous_bytes = bytes.len();
    state.entries = entries;
    Ok(())
}
