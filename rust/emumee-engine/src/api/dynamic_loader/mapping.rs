//! Candidate preparation is pure. Known-success native map/unmap owns publication.
use super::*;
use emumee_core::{
    memory::AddressSpace,
    modules::{DynamicDescriptor, ModuleCatalog, ModuleOrigin, Resolution},
    pe::Kind,
};
pub(super) enum LoadError {
    Refused(u32),
    Fatal(anyhow::Error),
}
impl From<anyhow::Error> for LoadError {
    fn from(e: anyhow::Error) -> Self {
        Self::Fatal(e)
    }
}
impl From<emumee_core::memory::MemoryError> for LoadError {
    fn from(e: emumee_core::memory::MemoryError) -> Self {
        Self::Fatal(e.into())
    }
}
pub(super) enum Loaded {
    Retained(u64),
    New(ModuleId, u64),
}
fn unsupported(message: &str) -> LoadError {
    LoadError::Fatal(anyhow::anyhow!(
        "Dynamic DLL profile unsupported: {message}"
    ))
}
fn file_error(error: emumee_core::filesystem::FileError) -> LoadError {
    if error.win32 == 50 {
        unsupported(error.reason)
    } else {
        LoadError::Refused(if error.win32 == 3 || error.win32 == 2 {
            126
        } else {
            error.win32
        })
    }
}
fn basename(name: &str) -> std::result::Result<String, LoadError> {
    let name = name.rsplit(['\\', '/']).next().unwrap_or_default();
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    {
        return Err(unsupported(
            "DLL basename is outside the finite catalog namespace",
        ));
    }
    let mut name = name.to_ascii_lowercase();
    if !name.contains('.') {
        name.push_str(".dll");
    }
    Ok(name)
}
fn path_shaped(name: &str) -> bool {
    name.bytes().any(|b| b"\\/:".contains(&b))
}
fn normalized_request(name: &str) -> String {
    let leaf = name.rsplit(['\\', '/']).next().unwrap_or_default();
    if !leaf.contains('.') {
        format!("{name}.dll")
    } else {
        name.into()
    }
}
/// GetModuleHandle identity lookup is non-owning and also works during startup.
pub(super) fn lookup(engine: &Unicorn<Trace>, name: &str) -> Result<Option<ModuleId>> {
    let name = normalized_request(name);
    if !path_shaped(&name) {
        return Ok(engine
            .get_data()
            .apis
            .modules
            .module(&name)?
            .map(|m| m.identity()));
    }
    let path = engine.get_data().apis.files.path(&name)?;
    let leaf = name.rsplit(['\\', '/']).next().unwrap_or_default();
    if engine
        .get_data()
        .apis
        .modules
        .module(leaf)?
        .is_some_and(|m| m.provenance().is_none())
    {
        bail!(
            "Loaded module path identity is unavailable; refusing to invent full-path absence: {leaf}"
        );
    }
    for module in engine.get_data().apis.modules.modules() {
        if let Some(provenance) = module.provenance() {
            if engine.get_data().apis.files.path(&provenance.guest_path)? == path {
                return Ok(Some(module.identity()));
            }
        }
    }
    Ok(None)
}
fn placement(engine: &Unicorn<Trace>, preferred: u64, size: u64) -> Result<u64> {
    let environment = emumee_core::kernel_environment::Environment::new(
        engine.get_data().architecture,
        &engine.get_data().cpu.profile,
        engine.get_data().machine.windows_build(),
        engine.get_data().cpu.processor,
    )?;
    let last = environment.highest_user_address;
    let fits = |base: u64| -> bool {
        base >= 0x10000
            && base % 0x10000 == 0
            && base
                .checked_add(size)
                .is_some_and(|end| end > base && end - 1 <= last)
            && !engine
                .get_data()
                .apis
                .memory
                .regions()
                .any(|r| base < r.base + r.size && r.base < base + size)
    };
    if fits(preferred) {
        return Ok(preferred);
    }
    let mut base = 0x10000u64;
    for region in engine.get_data().apis.memory.regions() {
        if region.base >= base && region.base - base >= size && fits(base) {
            return Ok(base);
        }
        if region.base + region.size > base {
            base = region
                .base
                .checked_add(region.size)
                .and_then(|n| n.checked_add(0xffff))
                .context("DLL placement overflow")?
                & !0xffff;
        }
        if base > last {
            break;
        }
    }
    ensure!(fits(base), "No bounded user address range for DLL");
    Ok(base)
}
fn routine_binding(binding: &Binding) -> bool {
    !matches!(
        binding.model,
        Model::Unsupported
            | Model::Environment(kernel_environment::Call::Data(_))
            | Model::Objects(kernel_objects::Call::Data(_))
    )
}
fn installed_gate(engine: &Unicorn<Trace>, address: u64) -> bool {
    let state = &engine.get_data().apis;
    address >= state.base
        && address < state.end
        && (address - state.base) % 16 == 0
        && state
            .bindings
            .get(((address - state.base) / 16) as usize)
            .is_some_and(|b| routine_binding(b))
}
fn modeled_external(engine: &Unicorn<Trace>, module: &str, symbol: &ImportName) -> Result<u64> {
    let name = match symbol {
        ImportName::Name(name) => name.clone(),
        ImportName::Ordinal { ordinal } => format!("#{ordinal}"),
    };
    let expected = super::super::definition(engine.get_data().architecture, module, &name);
    ensure!(
        routine_binding(&expected),
        "Dynamic DLL import has no modeled finite external binding: {}",
        expected.name
    );
    let state = &engine.get_data().apis;
    let index = state
        .bindings
        .iter()
        .position(|b| b.name == expected.name && routine_binding(b))
        .context("Dynamic DLL import requires an API gate not installed in the actual process")?;
    let address = state.base + index as u64 * 16;
    ensure!(
        installed_gate(engine, address),
        "Dynamic external gate is not published"
    );
    Ok(address)
}
fn actual_edges(
    engine: &Unicorn<Trace>,
    catalog: &ModuleCatalog,
    owner: ModuleId,
    chain: &[String],
    edges: &mut Vec<(ModuleId, ModuleId)>,
) -> Result<()> {
    let mut previous = owner;
    for step in chain {
        let module = step
            .split_once('!')
            .context("Invalid actual forwarder chain")?
            .0;
        let m = catalog
            .module(module)?
            .context("Actual followed module vanished")?;
        if m.provenance()
            .is_some_and(|p| p.origin == ModuleOrigin::SyntheticProvider)
            || engine
                .get_data()
                .apis
                .providers
                .iter()
                .any(|p| p.module == m.name && p.base == m.base)
        {
            continue;
        }
        if previous == m.identity() {
            continue;
        }
        ensure!(
            engine
                .get_data()
                .apis
                .modules
                .loader_image_ready(m.identity()),
            "Dynamic DLL import targets an image that has not actually initialized"
        );
        if previous != m.identity() && !edges.contains(&(previous, m.identity())) {
            edges.push((previous, m.identity()));
        }
        previous = m.identity();
    }
    Ok(())
}
fn bindings(
    engine: &Unicorn<Trace>,
    catalog: &ModuleCatalog,
    pe: &PeImage,
    owner: ModuleId,
    image: &mut [u8],
) -> Result<Vec<(ModuleId, ModuleId)>> {
    let width = pe.sample.architecture.width();
    let mut edges = Vec::new();
    for import in &pe.imports {
        let address = match catalog.resolve(&import.module, &import.name)? {
            Resolution::Found { address, chain } => {
                actual_edges(engine, catalog, owner, &chain, &mut edges)?;
                // Metadata-only classified CODE remains NONE, even if catalogued.
                // Guest data exports can be readable; an actual gate must be modeled.
                ensure!(
                    installed_gate(engine, address)
                        || engine.get_data().apis.memory.allows(address, 1, P::READ),
                    "Dynamic DLL import resolves to protected/unmodeled metadata: {}!{:?}",
                    import.module,
                    import.name
                );
                if address >= engine.get_data().apis.base && address < engine.get_data().apis.end {
                    ensure!(
                        installed_gate(engine, address),
                        "Dynamic import enters an unsupported API gate"
                    );
                }
                address
            }
            Resolution::MissingModule { .. } => {
                modeled_external(engine, &import.module, &import.name)?
            }
            Resolution::MissingExport { module, .. } => {
                bail!("Dynamic DLL import missing from actual loaded {module}")
            }
        };
        let at = import.iat_rva as usize;
        let target = image
            .get_mut(
                at..at
                    .checked_add(width)
                    .context("Dynamic IAT offset overflow")?,
            )
            .context("Dynamic IAT exceeds materialized image")?;
        ensure!(
            width == 8 || address <= u32::MAX as u64,
            "Dynamic x86 import pointer exceeds ABI width"
        );
        target.copy_from_slice(&address.to_le_bytes()[..width]);
    }
    Ok(edges)
}
type ProtectionPlan = Vec<(u64, u64, P)>;

fn protection_plan(
    memory: &AddressSpace,
    pe: &PeImage,
    base: u64,
) -> Result<(AddressSpace, ProtectionPlan)> {
    let mut memory = memory.clone();
    let mut plan = vec![
        (base, pe.image_size as u64, P::NONE),
        (base, (pe.headers_size as u64 + 4095) & !4095, P::READ),
    ];
    for section in &pe.sections {
        let size = (section.virtual_size.max(section.raw_size) as u64 + 4095) & !4095;
        if size == 0 {
            continue;
        }
        let p = P((if section.characteristics & 0x40000000 != 0 {
            1
        } else {
            0
        }) | (if section.characteristics & 0x80000000 != 0 {
            2
        } else {
            0
        }) | (if section.characteristics & 0x20000000 != 0 {
            4
        } else {
            0
        }));
        plan.push((base + section.rva as u64, size, p));
    }
    for (base, size, p) in &plan {
        memory.protect(*base, *size, *p)?;
    }
    Ok((memory, plan))
}
struct Prepared {
    pe: PeImage,
    image: Vec<u8>,
    catalog: ModuleCatalog,
    mapped: AddressSpace,
    protected: AddressSpace,
    plan: ProtectionPlan,
    id: ModuleId,
}
fn prepare_new(
    engine: &Unicorn<Trace>,
    path: &str,
    name: &str,
    bytes: &[u8],
) -> std::result::Result<Prepared, LoadError> {
    if bytes.len() > 32 * 1024 * 1024 {
        return Err(LoadError::Refused(8));
    }
    let mut pe = PeImage::parse(bytes, name).map_err(|_| LoadError::Refused(193))?;
    if pe.sample.architecture != engine.get_data().architecture
        || pe.sample.kind != Kind::Dll
        || pe.sample.managed
    {
        return Err(LoadError::Refused(193));
    }
    if pe.image_size as u64 > emumee_core::modules::MAX_DYNAMIC_IMAGE {
        return Err(LoadError::Refused(8));
    }
    let tls = pe
        .tls_callbacks_only(bytes)
        .map_err(|e| unsupported(&format!("{e}")))?;
    let base = placement(engine, pe.image_base, pe.image_size as u64)?;
    let mut image = pe
        .materialize(bytes, base)
        .map_err(|_| LoadError::Refused(193))?;
    // accepted_headers/preferred-base/hash remain original and immutable.
    pe.image_base = base;
    let mut catalog = engine.get_data().apis.modules.clone();
    catalog
        .add_with_path(name, base, &pe, path, ModuleOrigin::GuestFile)
        .map_err(|e| unsupported(&format!("{e}")))?;
    let id = catalog.module(name).unwrap().unwrap().identity();
    let edges = bindings(engine, &catalog, &pe, id, &mut image)?;
    let dependencies = edges
        .iter()
        .filter_map(|(from, to)| (*from == id).then_some(*to))
        .collect();
    // Commit existing-owner forwarder edges on the candidate before publishing
    // its operation; actual installed IAT bytes are the only source of edges.
    for (from, to) in edges.iter().copied().filter(|(from, _)| *from != id) {
        catalog
            .acquire_late_dependencies(from, &[to], OWNER, engine.get_data().instructions)
            .map_err(|e| unsupported(&format!("{e}")))?;
    }
    catalog
        .publish_dynamic_image(
            id,
            DynamicDescriptor {
                owner: OWNER,
                accepted_sha256: pe.sample.sha256.clone(),
                raw_bytes: bytes.len() as u64,
                tls,
                dependencies,
            },
            engine.get_data().instructions,
        )
        .map_err(|e| unsupported(&format!("{e}")))?;
    let mut mapped = engine.get_data().apis.memory.clone();
    mapped.map(
        base,
        pe.image_size as u64,
        P::NONE,
        Some(OWNER),
        "guest dynamic DLL",
    )?;
    let (protected, plan) = protection_plan(&mapped, &pe, base)?;
    Ok(Prepared {
        pe,
        image,
        catalog,
        mapped,
        protected,
        plan,
        id,
    })
}
pub(super) fn load(
    engine: &mut Unicorn<Trace>,
    requested: &str,
) -> std::result::Result<Loaded, LoadError> {
    let request = normalized_request(requested);
    if let Some(id) = lookup(engine, &request)? {
        let count = engine.get_data().instructions;
        return engine
            .get_data_mut()
            .apis
            .modules
            .retain_dynamic_reference(id, OWNER, count)
            .map(Loaded::Retained)
            .map_err(|e| {
                if e.win32 == 50 {
                    unsupported(e.reason)
                } else {
                    LoadError::Refused(e.win32)
                }
            });
    }
    let name = basename(&request)?;
    let snapshot = engine
        .get_data()
        .apis
        .files
        .loader_file_snapshot(&request)
        .map_err(file_error)?
        .ok_or(LoadError::Refused(126))?;
    if snapshot.configured_backing {
        return Err(unsupported(
            "configured-backing DLL execution has no authorized ordinary guest copy",
        ));
    }
    if engine
        .get_data()
        .apis
        .modules
        .module(&name)
        .map_err(|e| unsupported(&format!("{e}")))?
        .is_some()
    {
        return Err(unsupported("another path already owns this DLL basename"));
    }
    let Prepared {
        pe,
        image,
        catalog,
        mapped,
        protected,
        plan,
        id,
    } = prepare_new(engine, &snapshot.path, &name, &snapshot.bytes)?;
    let base = pe.image_base;
    if let Err(error) =
        uc(engine.mem_map(base, pe.image_size as u64, Prot::ALL)).with_context(|| {
            format!(
                "Dynamic DLL native map {name} at {base:#x}+{:#x}",
                pe.image_size
            )
        })
    {
        native_failure(engine, "map", &error);
        return Err(LoadError::Fatal(error));
    }
    // Known-success native mapping is now real, even if later publication fails.
    engine.get_data_mut().apis.modules = catalog;
    engine.get_data_mut().apis.memory = mapped;
    let publish = (|| -> Result<()> {
        crate::capture::materialized(engine, base, &image);
        crate::indicators::materialized(engine, base, &image);
        crate::cpu::write(engine, base, &image)?;
        for (address, size, p) in &plan {
            uc(engine.mem_protect(
                *address,
                *size,
                (if p.contains(P::READ) {
                    Prot::READ
                } else {
                    Prot::NONE
                }) | (if p.contains(P::WRITE) {
                    Prot::WRITE
                } else {
                    Prot::NONE
                }) | (if p.contains(P::EXECUTE) {
                    Prot::EXEC
                } else {
                    Prot::NONE
                }),
            ))?;
        }
        for (address, size, p) in &plan {
            if p.contains(P::WRITE) && p.contains(P::EXECUTE) {
                crate::cpu::watch(engine, *address, *size)?;
            }
        }
        Ok(())
    })();
    if let Err(error) = publish {
        native_failure(engine, "image/protection publication", &error);
        return Err(LoadError::Fatal(error));
    }
    engine.get_data_mut().apis.memory = protected;
    let count = engine.get_data().instructions;
    engine
        .get_data_mut()
        .apis
        .modules
        .dynamic_mapped(id, count)
        .map_err(|e| LoadError::Fatal(e.into()))?;
    Ok(Loaded::New(id, base))
}
pub(super) fn publish_handle(
    engine: &mut Unicorn<Trace>,
    output: Option<u64>,
    base: u64,
) -> Result<()> {
    if let Some(output) = output {
        let width = engine.get_data().architecture.width();
        require(engine, output, width as u64, P::WRITE)?;
        if let Err(error) = crate::cpu::write(engine, output, &base.to_le_bytes()[..width]) {
            native_failure(
                engine,
                "NT result publication after actual reference acquisition",
                &error,
            );
            return Err(error);
        }
    }
    Ok(())
}
/// Real GetProcAddress forwarders extend ownership only for followed guest edges.
pub(crate) fn retain_followed_edges(
    engine: &mut Unicorn<Trace>,
    module: &str,
    chain: &[String],
) -> Result<()> {
    if engine.get_data().apis.kernel_mode {
        return Ok(());
    }
    let catalog = &engine.get_data().apis.modules;
    // Export-only isolated catalog probes predate process lifecycle authority.
    // No dynamic image can be retired in this state, so there is no new pin to acquire.
    if catalog.dynamic_state().owner.is_none()
        && !catalog.modules().any(|m| m.dynamic_image().is_some())
    {
        return Ok(());
    }
    let owner = catalog
        .module(module)?
        .context("GetProcAddress owner vanished")?
        .identity();
    let mut edges = Vec::new();
    actual_edges(engine, catalog, owner, chain, &mut edges)?;
    edges.retain(|(from, to)| {
        !catalog
            .by_identity(*from)
            .unwrap()
            .loader_dependencies()
            .any(|id| id == *to)
    });
    if edges.is_empty() {
        return Ok(());
    }
    ensure!(
        !engine.get_data().loader_active && engine.get_data().dynamic_loader.pending.is_none(),
        "New GetProcAddress ownership during a loader callback is not modeled"
    );
    let mut candidate = catalog.clone();
    candidate.establish_user_loader(OWNER)?;
    for (from, to) in edges {
        candidate.acquire_late_dependencies(from, &[to], OWNER, engine.get_data().instructions)?;
    }
    engine.get_data_mut().apis.modules = candidate;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn missing_loaded_path_provenance_is_not_absence_and_typed_data_is_not_a_gate() {
        for architecture in [Architecture::X86, Architecture::X64] {
            let mut engine = crate::new_engine(architecture).unwrap();
            let before = engine.get_data().apis.memory.clone();
            let (_, modules) = emumee_core::fixtures::native_loader_probe(
                architecture,
                emumee_core::fixtures::LoaderFixture::Basic,
            );
            let pe = PeImage::parse(&modules[0].1, "guest.dll").unwrap();
            engine
                .get_data_mut()
                .apis
                .modules
                .add("guest.dll", pe.image_base, &pe)
                .unwrap();
            assert!(lookup(&engine, "guest").unwrap().is_some());
            assert!(
                lookup(&engine, r"C:\Windows\guest.dll")
                    .unwrap_err()
                    .to_string()
                    .contains("path identity is unavailable")
            );
            assert!(
                lookup(&engine, r"C:\workspace\absent.dll")
                    .unwrap()
                    .is_none()
            );
            assert_eq!(engine.get_data().apis.modules.dynamic_state().owner, None);
            assert_eq!(engine.get_data().apis.memory, before);
            let routine = super::super::super::definition(
                architecture,
                "kernel32.dll",
                "GetCurrentProcessId",
            );
            assert!(routine_binding(&routine));
            let data =
                super::super::super::definition(architecture, "ntoskrnl.exe", "KeNumberProcessors");
            assert!(!routine_binding(&data));
            assert!(!routine_binding(&super::super::super::definition(
                architecture,
                "cng.sys",
                "NoInventedRoutine"
            )));
        }
    }
}
