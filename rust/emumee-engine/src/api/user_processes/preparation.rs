use super::*;
use anyhow::anyhow;
use emumee_core::{
    modules::{ModuleOrigin, StaticStartup},
    persona::{Persona, ProcessConfig},
};

pub(super) struct Startup {
    pub loader: Option<StaticStartup>,
    pub image: PeImage,
}
struct Companion {
    name: String,
    path: String,
    image: PeImage,
    bytes: Vec<u8>,
}
fn map_image(engine: &mut Unicorn<Trace>, image: &PeImage, bytes: &[u8], base: u64) -> Result<()> {
    let mut prospective = engine.get_data().apis.memory.clone();
    prospective.map(
        base,
        image.image_size as u64,
        P::NONE,
        None,
        "child image admission",
    )?;
    crate::map_image(engine, image, bytes, base)
}
fn executable(
    engine: &Unicorn<Trace>,
    name: &str,
) -> Result<Option<emumee_core::filesystem::LoaderFileSnapshot>> {
    let mut names = vec![name.to_owned()];
    if !name.rsplit('\\').next().unwrap_or(name).contains('.') {
        names.push(format!("{name}.exe"));
    }
    let config = engine.get_data().apis.persona.model.config();
    let directories = if name.contains('\\') || name.contains(':') {
        vec![String::new()]
    } else {
        vec![
            String::new(),
            config.system_directory.clone(),
            config.windows_directory.clone(),
        ]
    };
    for directory in directories {
        for name in &names {
            let path = if directory.is_empty() {
                name.clone()
            } else {
                format!("{directory}\\{name}")
            };
            if let Some(snapshot) = engine.get_data().apis.files.loader_file_snapshot(&path)? {
                return Ok(Some(snapshot));
            }
        }
    }
    Ok(None)
}
fn security(engine: &Unicorn<Trace>, address: u64) -> Result<u32> {
    if address == 0 {
        return Ok(0);
    }
    let width = engine.get_data().architecture.width();
    let size = if width == 8 { 24 } else { 12 };
    let bytes = read(engine, address, size)?;
    ensure!(
        u32::from_le_bytes(bytes[..4].try_into().unwrap()) as u64 == size,
        "Invalid process security-attributes size"
    );
    let pointer = if width == 8 {
        &bytes[8..16]
    } else {
        &bytes[4..8]
    };
    ensure!(
        pointer.iter().all(|byte| *byte == 0),
        "Guest process security descriptors are unsupported"
    );
    Ok(u32::from(
        bytes[2 * width..2 * width + 4]
            .iter()
            .any(|byte| *byte != 0),
    ))
}
fn companions(engine: &Unicorn<Trace>, root: &PeImage, path: &str) -> Result<Vec<Companion>> {
    let inventory: serde_json::Value =
        serde_json::from_str(include_str!("../../../../api-parity/legacy-inventory.json"))?;
    let mut known = inventory["entries"]
        .as_array()
        .context("Provider inventory absent")?
        .iter()
        .filter_map(|entry| {
            entry["module"]
                .as_str()
                .map(|module| format!("{module}.dll"))
        })
        .collect::<std::collections::BTreeSet<_>>();
    known.extend([
        "kernelbase.dll".into(),
        path.rsplit('\\')
            .next()
            .unwrap_or(path)
            .to_ascii_lowercase(),
    ]);
    let directory = path.rsplit_once('\\').context("Child directory absent")?.0;
    let mut pending = root
        .imports
        .iter()
        .map(|import| import.module.to_ascii_lowercase())
        .collect::<Vec<_>>();
    let mut images = vec![];
    let mut total = 0usize;
    while let Some(name) = pending.pop() {
        if name.starts_with("api-ms-win-") {
            continue;
        }
        if !known.insert(name.clone()) {
            continue;
        }
        ensure!(images.len() < 16, "Child DLL graph exceeds companion bound");
        ensure!(
            !name.contains(['\\', '/', ':']),
            "Child import has a path-shaped DLL name"
        );
        let candidate = format!("{directory}\\{name}");
        let snapshot = engine
            .get_data()
            .apis
            .files
            .loader_file_snapshot(&candidate)?
            .or(engine.get_data().apis.files.loader_file_snapshot(&format!(
                "{}\\{name}",
                engine
                    .get_data()
                    .apis
                    .persona
                    .model
                    .config()
                    .system_directory
            ))?)
            .context("Child static DLL dependency absent from guest VFS")?;
        ensure!(
            !snapshot.configured_backing
                || engine
                    .get_data()
                    .machine
                    .submitted_image(&snapshot.path, &snapshot.bytes),
            "Child DLL dependency has no ordinary guest byte authority"
        );
        total = total
            .checked_add(snapshot.bytes.len())
            .context("Child DLL raw-byte admission overflow")?;
        ensure!(
            total <= emumee_core::user_input::MAX_STAGED_TOTAL as usize,
            "Child DLL graph raw-byte bound exceeded"
        );
        let image = PeImage::parse(&snapshot.bytes, &name)?;
        ensure!(
            image.sample.architecture == root.sample.architecture
                && image.sample.kind == emumee_core::pe::Kind::Dll
                && !image.sample.managed,
            "Child dependency is not a same-architecture native DLL"
        );
        pending.extend(
            image
                .imports
                .iter()
                .map(|import| import.module.to_ascii_lowercase()),
        );
        images.push(Companion {
            name,
            path: snapshot.path,
            image,
            bytes: snapshot.bytes,
        });
    }
    Ok(images)
}
fn initialize(
    engine: &mut Unicorn<Trace>,
    bytes: &[u8],
    path: &str,
    suspended: bool,
) -> Result<()> {
    let name = path
        .rsplit('\\')
        .next()
        .context("Child image name missing")?;
    let image = PeImage::parse(bytes, name)?;
    ensure!(
        image.sample.architecture == engine.get_data().architecture
            && !image.sample.managed
            && image.sample.kind == emumee_core::pe::Kind::Exe,
        "Child image requires a same-architecture unmanaged EXE"
    );
    allowance(engine)?;
    engine
        .get_data_mut()
        .apis
        .target(image.sample.architecture, false)?;
    crt_startup::initialize(engine)?;
    kernel_objects::initialize(engine)?;
    engine.get_data_mut().apis.modules.add_with_path(
        name,
        image.image_base,
        &image,
        path,
        ModuleOrigin::SubmittedUser,
    )?;
    engine.get_data_mut().apis.modules.set_primary(name)?;
    map_image(engine, &image, bytes, image.image_base)?;
    let mut companions = companions(engine, &image, path)?;
    for Companion {
        name,
        path,
        image,
        bytes,
    } in &mut companions
    {
        let base = dynamic_loader::place_image(engine, image.image_base, image.image_size as u64)?;
        engine.get_data_mut().apis.modules.add_with_path(
            name,
            base,
            image,
            path,
            ModuleOrigin::SubmittedUser,
        )?;
        map_image(engine, image, bytes, base)?;
        image.image_base = base;
    }
    bind(engine, &image)?;
    for Companion { image, .. } in &companions {
        bind(engine, image)?;
    }
    user_providers::initialize(engine)?;
    initialize_metadata_providers(engine, &image)?;
    bind(engine, &image)?;
    for Companion { image, .. } in &companions {
        initialize_metadata_providers(engine, image)?;
        bind(engine, image)?;
        crate::protect_image(engine, image)?;
    }
    crate::protect_image(engine, &image)?;
    for (base, size, native, model, label) in [
        (
            crate::STACK,
            crate::STACK_SIZE,
            Prot::READ | Prot::WRITE,
            P::RW,
            "child root stack",
        ),
        (
            crate::RETURN,
            4096,
            Prot::READ | Prot::EXEC,
            P::RX,
            "child return markers",
        ),
        (
            crate::OBJECTS,
            4096,
            Prot::READ | Prot::WRITE,
            P::RW,
            "child bootstrap objects",
        ),
    ] {
        engine
            .get_data_mut()
            .apis
            .memory
            .map(base, size, model, None, label)?;
        uc(engine.mem_map(base, size, native))?;
    }
    engine.get_data_mut().return_marker = crate::RETURN;
    user_bootstrap::initialize(engine, image.image_base, crate::STACK, crate::STACK_SIZE)?;
    crate::time::initialize(engine)?;
    let sp = crate::STACK + crate::STACK_SIZE
        - if image.sample.architecture == Architecture::X64 {
            0x108
        } else {
            0x10c
        };
    let width = image.sample.architecture.width();
    crate::cpu::write(engine, sp, &crate::RETURN.to_le_bytes()[..width])?;
    uc(engine.reg_write(
        if width == 8 {
            RegisterX86::RSP
        } else {
            RegisterX86::ESP
        },
        sp,
    ))?;
    uc(engine.reg_write(
        crate::threads::pc_register(image.sample.architecture),
        image.image_base + image.entry_rva as u64,
    ))?;
    user_threads::set_primary_suspended(engine, suspended)?;
    let (companion_bytes, parsed): (Vec<_>, Vec<_>) = companions
        .into_iter()
        .map(|companion| ((companion.name, companion.bytes), companion.image))
        .unzip();
    let loader = native_loader::prepare(engine, &image, bytes, &companion_bytes, &parsed)?;
    engine.get_data_mut().process.startup = Some(Startup { loader, image });
    Ok(())
}
pub(super) fn create(engine: &mut Unicorn<Trace>, args: &[u64], wide: bool) -> Result<u64> {
    let width = engine.get_data().architecture.width();
    if require(engine, args[9], (2 * width + 8) as u64, P::WRITE).is_err() {
        return Ok(failure(engine, 998));
    }
    if args[6] != 0 || args[5] & !0x08000014 != 0 {
        return Ok(failure(engine, 50));
    }
    let process_flags = match security(engine, args[2]) {
        Ok(flags) => flags,
        Err(_) => return Ok(failure(engine, 87)),
    };
    let thread_flags = match security(engine, args[3]) {
        Ok(flags) => flags,
        Err(_) => return Ok(failure(engine, 87)),
    };
    if engine.get_data().processes.records.len() > MAX_CHILDREN
        || !handles::admits(&engine.get_data().processes, 2)
    {
        return Ok(failure(engine, 8));
    }
    let command = if args[1] == 0 {
        String::new()
    } else {
        files::path(engine, args[1], wide)?
    };
    let application = if args[0] != 0 {
        files::path(engine, args[0], wide)?
    } else if let Some(quoted) = command.strip_prefix('"') {
        quoted.split('"').next().unwrap_or("").to_owned()
    } else {
        command.split_whitespace().next().unwrap_or("").to_owned()
    };
    if application.is_empty() {
        return Ok(failure(engine, 87));
    }
    let snapshot = match executable(engine, &application) {
        Ok(Some(snapshot)) => snapshot,
        Ok(None) => return Ok(failure(engine, 2)),
        Err(_) => return Ok(failure(engine, 3)),
    };
    if snapshot.configured_backing
        && !engine
            .get_data()
            .machine
            .submitted_image(&snapshot.path, &snapshot.bytes)
    {
        return Ok(failure(engine, 50));
    }
    let (path, bytes) = (snapshot.path, snapshot.bytes);
    let image = match PeImage::parse(&bytes, &application) {
        Ok(image) => image,
        Err(_) => return Ok(failure(engine, 193)),
    };
    if image.sample.architecture != engine.get_data().architecture
        || image.sample.managed
        || image.sample.kind != emumee_core::pe::Kind::Exe
    {
        return Ok(failure(engine, 50));
    }
    let parent = pid(engine);
    let inherited_handles = if args[4] != 0 {
        engine
            .get_data()
            .processes
            .handles
            .iter()
            .filter(|((owner, _), handle)| *owner == parent && handle.flags & 1 != 0)
            .map(|((_, value), handle)| (*value, *handle))
            .chain(
                user_threads::inheritable_handles(engine.get_data())
                    .into_iter()
                    .map(|handle| {
                        (
                            handle.handle,
                            Handle {
                                target: Target::Thread(parent, handle.thread),
                                access: handle.access,
                                flags: handle.flags,
                            },
                        )
                    }),
            )
            .collect::<Vec<_>>()
    } else {
        vec![]
    };
    if engine.get_data().processes.handles.len() + inherited_handles.len() + 2 > 4096 {
        return Ok(failure(engine, 8));
    }
    let child = engine
        .get_data()
        .processes
        .records
        .keys()
        .next_back()
        .copied()
        .unwrap_or(ROOT)
        + 1;
    let mut model = Persona::new(engine.get_data().apis.persona.model.config().clone())?;
    let directory = if args[7] != 0 {
        Some(files::path(engine, args[7], wide)?)
    } else {
        None
    };
    let inherited = engine
        .get_data()
        .apis
        .persona
        .model
        .environment(ROOT)?
        .entries()
        .iter()
        .map(|(name, value)| (name.clone(), Some(value.clone())))
        .collect();
    model.add_process(
        ROOT,
        ProcessConfig {
            image_path: path.clone(),
            arguments: vec![],
            force_quotes: vec![],
            command_line: (!command.is_empty()).then_some(command),
            current_directory: directory,
            environment_overrides: inherited,
        },
    )?;
    let apis = ApiState::seeded(
        engine.get_data().architecture,
        model,
        {
            let mut registry = engine.get_data().apis.registry.clone();
            registry.cleanup_process(ROOT);
            registry
        },
        engine.get_data().apis.files.snapshot_without_handles(),
    );
    let mut trace = Trace::new(engine.get_data().architecture);
    trace.apis = apis;
    trace.machine = engine.get_data().machine.clone();
    trace.cpu = crate::cpu::CpuState::configured(engine.get_data().cpu.profile.clone());
    user_threads::inherit_alias_namespace(engine.get_data(), &mut trace);
    trace.continuation_depth = 1;
    trace.process.id = child;
    let cpu = uc(engine.context_init())?;
    let parent_snapshot = exchange(
        engine,
        Snapshot {
            trace: Box::new(trace),
            cpu,
            pages: vec![],
        },
    )?;
    engine
        .get_data_mut()
        .processes
        .parked
        .insert(parent, parent_snapshot);
    let initialized = initialize(engine, &bytes, &path, args[5] & 4 != 0);
    let peb = user_bootstrap::report(engine).map_or(0, |report| report.peb);
    let restored = switch(engine, parent);
    restored?;
    if let Err(error) = initialized {
        engine.get_data_mut().processes.parked.remove(&child);
        allowance(engine)?;
        let admission = error
            .chain()
            .any(|cause| cause.is::<emumee_core::memory::MemoryError>());
        return Ok(failure(engine, if admission { 8 } else { 193 }));
    }
    engine.get_data_mut().processes.records.insert(
        child,
        ProcessReport {
            id: child,
            parent,
            image: path,
            exit_code: None,
            failure: None,
            failure_kind: None,
            peb,
            backing_released: false,
        },
    );
    let process = handles::insert(
        engine,
        parent,
        Target::Process(child),
        PROCESS_ALL,
        process_flags,
    )
    .map_err(|error| anyhow!("Child process handle admission {error}"))?;
    let thread = handles::insert(
        engine,
        parent,
        Target::Thread(child, 1),
        THREAD_ALL,
        thread_flags,
    )
    .map_err(|error| anyhow!("Child thread handle admission {error}"))?;
    for (handle, entry) in inherited_handles {
        engine
            .get_data_mut()
            .processes
            .handles
            .insert((child, handle), entry);
    }
    let mut output = Vec::with_capacity(2 * width + 8);
    output.extend_from_slice(&process.to_le_bytes()[..width]);
    output.extend_from_slice(&thread.to_le_bytes()[..width]);
    output.extend_from_slice(&(child as u32).to_le_bytes());
    output.extend_from_slice(&(tid(child, 1) as u32).to_le_bytes());
    crate::cpu::write(engine, args[9], &output)?;
    engine.get_data_mut().apis.last_error = 0;
    Ok(1)
}
