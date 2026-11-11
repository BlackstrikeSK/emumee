use super::*;

struct Failure(u32, String);
fn bad(code: u32, error: impl std::fmt::Display) -> Failure {
    Failure(code, error.to_string())
}
type Checked<T> = std::result::Result<T, Failure>;
struct Image {
    pe: PeImage,
    bytes: Vec<u8>,
    materialized: Vec<u8>,
    protection: ProtectionPlan,
    id: ModuleId,
}
struct Plan {
    root: ModuleId,
    base: u64,
    images: Vec<Image>,
    catalog: ModuleCatalog,
    memory: AddressSpace,
    order: Vec<ModuleId>,
}
fn prepare(
    engine: &mut Unicorn<Trace>,
    requested: &str,
    horizon: &ExecutionHorizon,
) -> Checked<Plan> {
    modeled_external(engine, "kernel32", &ImportName::Name("LoadLibraryW".into()))
        .map_err(|error| bad(50, error))?;
    let mut catalog = engine.get_data().apis.modules.clone();
    let mut memory = engine.get_data().apis.memory.clone();
    let mut images: Vec<Image> = vec![];
    let mut pending = vec![normalized_request(requested)];
    let mut root = None;
    loop {
        for name in std::mem::take(&mut pending) {
            if horizon.expired(engine.get_data().instructions) {
                return Err(bad(0, "shared loader horizon exhausted"));
            }
            if images.len() >= emumee_core::modules::MAX_DYNAMIC_LIVE {
                return Err(bad(8, "dynamic DLL graph count quota exceeded"));
            }
            let snapshot = engine
                .get_data()
                .apis
                .files
                .loader_file_snapshot(&name)
                .map_err(|error| bad(error.win32, error))?
                .ok_or_else(|| bad(126, format!("guest DLL dependency absent: {name}")))?;
            if snapshot.configured_backing {
                return Err(bad(
                    50,
                    "DLL source has no authorized ordinary guest byte snapshot",
                ));
            }
            let name = basename(&snapshot.path).map_err(|error| match error {
                LoadError::Refused(code) => bad(code, "invalid DLL basename"),
                LoadError::Fatal(error) => bad(87, error),
                LoadError::Horizon => bad(0, "shared horizon exhausted"),
            })?;
            if catalog
                .module(&name)
                .map_err(|error| bad(87, error))?
                .is_some()
            {
                continue;
            }
            if snapshot.bytes.is_empty()
                || snapshot.bytes.len() > 32 * 1024 * 1024
                || images.iter().map(|image| image.bytes.len()).sum::<usize>()
                    + snapshot.bytes.len()
                    > 64 * 1024 * 1024
            {
                return Err(bad(8, "dynamic DLL raw byte quota exceeded"));
            }
            let mut pe = PeImage::parse(&snapshot.bytes, &name).map_err(|error| bad(193, error))?;
            if pe.sample.architecture != engine.get_data().architecture
                || pe.sample.kind != Kind::Dll
                || pe.sample.managed
            {
                return Err(bad(
                    193,
                    "DLL dependency architecture or native image kind differs",
                ));
            }
            if pe.image_size as u64
                + images
                    .iter()
                    .map(|image| image.pe.image_size as u64)
                    .sum::<u64>()
                + engine
                    .get_data()
                    .apis
                    .modules
                    .modules()
                    .filter(|module| module.dynamic_image().is_some())
                    .map(|module| module.size)
                    .sum::<u64>()
                > emumee_core::modules::MAX_DYNAMIC_IMAGE
            {
                return Err(bad(8, "aggregate dynamic image staging quota exceeded"));
            }
            let base = placement_in(engine, &memory, pe.image_base, pe.image_size as u64)
                .map_err(|error| bad(8, error))?;
            let materialized = pe
                .materialize(&snapshot.bytes, base)
                .map_err(|error| bad(193, error))?;
            pe.image_base = base;
            catalog
                .add_with_path(&name, base, &pe, &snapshot.path, ModuleOrigin::GuestFile)
                .map_err(|error| bad(50, error))?;
            let id = catalog.module(&name).unwrap().unwrap().identity();
            root.get_or_insert(id);
            memory
                .map(
                    base,
                    pe.image_size as u64,
                    P::NONE,
                    Some(OWNER),
                    "guest dynamic DLL graph",
                )
                .map_err(|error| bad(8, error))?;
            let (protected, protection) =
                protection_plan(&memory, &pe, base).map_err(|error| bad(193, error))?;
            memory = protected;
            let tls = pe
                .tls_with_storage(&snapshot.bytes)
                .map_err(|error| bad(193, error))?;
            if let Some(storage) = &tls.storage {
                if !memory.allows(base + storage.index_rva as u64, 4, P::WRITE)
                    || storage.template_rva.is_some_and(|rva| {
                        storage.initialized_bytes != 0
                            && !memory.allows(
                                base + rva as u64,
                                storage.initialized_bytes as u64,
                                P::READ,
                            )
                    })
                {
                    return Err(bad(
                        193,
                        "TLS index/template guest page permissions are invalid",
                    ));
                }
            }
            images.push(Image {
                pe,
                bytes: snapshot.bytes,
                materialized,
                protection,
                id,
            });
        }
        for image in &images {
            for import in &image.pe.imports {
                match catalog
                    .resolve(&import.module, &import.name)
                    .map_err(|error| bad(50, error))?
                {
                    Resolution::MissingModule { module, symbol, .. } => {
                        let name = match &symbol {
                            ImportName::Name(name) => name.clone(),
                            ImportName::Ordinal { ordinal } => format!("#{ordinal}"),
                        };
                        if routine_binding(&super::super::super::definition(
                            engine.get_data().architecture,
                            &module,
                            &name,
                        )) {
                            modeled_external(engine, &module, &symbol)
                                .map_err(|error| bad(50, error))?;
                        } else if !pending.contains(&module) {
                            pending.push(module);
                        }
                    }
                    Resolution::MissingExport { module, symbol } => {
                        return Err(bad(
                            127,
                            format!("unresolved DLL export {module}!{symbol:?}"),
                        ));
                    }
                    Resolution::Found { .. } => {}
                }
            }
        }
        if pending.is_empty() {
            break;
        }
    }
    let ids = images.iter().map(|image| image.id).collect::<Vec<_>>();
    let mut edges = vec![];
    let mut descriptors = vec![];
    for image in &mut images {
        edges.extend(
            bindings(
                engine,
                &catalog,
                &memory,
                &image.pe,
                image.id,
                &mut image.materialized,
                &ids,
            )
            .map_err(|error| bad(50, error))?,
        );
        descriptors.push((
            image.id,
            DynamicDescriptor {
                owner: OWNER,
                accepted_sha256: image.pe.sample.sha256.clone(),
                raw_bytes: image.bytes.len() as u64,
                tls: image
                    .pe
                    .tls_with_storage(&image.bytes)
                    .map_err(|error| bad(193, error))?,
                dependencies: vec![],
            },
        ));
    }
    let root = root.ok_or_else(|| bad(126, "dynamic DLL root is absent"))?;
    let storage = descriptors
        .iter()
        .filter_map(|(_, descriptor)| descriptor.tls.storage.clone())
        .collect::<Vec<_>>();
    super::super::super::user_loader::preflight_storage(engine, &memory, &storage)
        .map_err(|error| bad(8, error))?;
    let base = catalog.by_identity(root).unwrap().base;
    let order = catalog
        .publish_dynamic_graph(root, &descriptors, &edges, engine.get_data().instructions)
        .map_err(|error| bad(error.win32, error))?;
    Ok(Plan {
        root,
        base,
        images,
        catalog,
        memory,
        order,
    })
}
fn refuse(engine: &mut Unicorn<Trace>, requested: &str, failure: Failure) -> LoadError {
    if failure.0 == 0 {
        return LoadError::Horizon;
    }
    let instruction = engine.get_data().instructions;
    let state = &mut engine.get_data_mut().dynamic_loader;
    if state.refusals.len() < 128 {
        state.refusals.push(super::super::Refusal {
            requested: requested.chars().take(512).collect(),
            win32: failure.0,
            reason: failure.1.chars().take(1024).collect(),
            instruction,
        });
    }
    LoadError::Refused(failure.0)
}
pub(super) fn load(
    engine: &mut Unicorn<Trace>,
    requested: &str,
    horizon: &ExecutionHorizon,
) -> std::result::Result<Loaded, LoadError> {
    if let Some(id) = lookup(engine, requested)? {
        let count = engine.get_data().instructions;
        return engine
            .get_data_mut()
            .apis
            .modules
            .retain_dynamic_reference(id, OWNER, count)
            .map(Loaded::Retained)
            .map_err(|error| refuse(engine, requested, bad(error.win32, error)));
    }
    let plan = prepare(engine, requested, horizon)
        .map_err(|failure| refuse(engine, requested, failure))?;
    let mut mapped = vec![];
    let result = (|| -> std::result::Result<(), LoadError> {
        for image in &plan.images {
            if horizon.expired(engine.get_data().instructions) {
                return Err(LoadError::Horizon);
            }
            uc(engine.mem_map(image.pe.image_base, image.pe.image_size as u64, Prot::ALL))?;
            mapped.push((image.pe.image_base, image.pe.image_size as u64));
            crate::cpu::write(engine, image.pe.image_base, &image.materialized)?;
            for (base, size, permissions) in &image.protection {
                let mut native = Prot::NONE;
                if permissions.contains(P::READ) {
                    native |= Prot::READ;
                }
                if permissions.contains(P::WRITE) {
                    native |= Prot::WRITE;
                }
                if permissions.contains(P::EXECUTE) {
                    native |= Prot::EXEC;
                }
                uc(engine.mem_protect(*base, *size, native))?;
                if permissions.contains(P::WRITE) && permissions.contains(P::EXECUTE) {
                    crate::cpu::watch(engine, *base, *size)?;
                }
            }
        }
        if horizon.expired(engine.get_data().instructions) {
            return Err(LoadError::Horizon);
        }
        Ok(())
    })();
    if let Err(error) = result {
        for (base, size) in mapped.into_iter().rev() {
            if let Err(rollback) = uc(engine.mem_unmap(base, size)) {
                native_failure(engine, "DLL graph native rollback", &rollback);
                return Err(LoadError::Fatal(rollback));
            }
            engine
                .get_data_mut()
                .cpu
                .cache
                .invalidate(base, size as usize);
            if let Err(rollback) = uc(engine.ctl_remove_cache(base, base + size)) {
                native_failure(engine, "DLL graph cache rollback", &rollback);
                return Err(LoadError::Fatal(rollback));
            }
        }
        if let LoadError::Fatal(error) = &error {
            native_failure(engine, "DLL graph map/protection publication", error);
        }
        return Err(error);
    }
    engine.get_data_mut().apis.modules = plan.catalog;
    engine.get_data_mut().apis.memory = plan.memory;
    for image in &plan.images {
        crate::capture::materialized(engine, image.pe.image_base, &image.materialized);
        crate::indicators::materialized(engine, image.pe.image_base, &image.materialized);
    }
    Ok(Loaded::New(plan.root, plan.base, plan.order))
}
