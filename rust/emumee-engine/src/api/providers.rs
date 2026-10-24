//! Initial explicit synthetic provider profile. Unknown synthetic exports stop
//! rather than reporting them absent on a real Windows installation.
use super::*;
use emumee_core::modules::Resolution;

#[derive(Clone, Debug, Serialize)]
pub struct ProviderEvidence {
    pub module: String,
    pub base: u64,
    pub exports: usize,
    pub image_size: u32,
    pub reference_catalog: Option<emumee_core::provider::CatalogMetadata>,
    pub metadata_only: Option<emumee_core::provider::MetadataEvidence>,
    pub scope: &'static str,
}
pub(super) struct CatalogStorage {
    base: u64,
    first: u32,
    symbols: Vec<emumee_core::provider::ProtectedSymbol>,
}
#[derive(Clone, Debug, Serialize)]
pub struct ProviderDenial {
    pub name: String,
    pub kind: &'static str,
    pub access: &'static str,
    pub address: u64,
    pub size: usize,
    pub offset: u64,
}
pub(super) fn describe(
    engine: &Unicorn<Trace>,
    address: u64,
    size: usize,
    access: &'static str,
) -> Option<ProviderDenial> {
    if let Some(row) = provider_metadata::describe(engine, address, size, access) {
        return Some(row);
    }
    let catalog = engine.get_data().apis.protected_catalog.as_ref()?;
    if size == 0 {
        return None;
    }
    let first = catalog.base + catalog.first as u64;
    let end = first + catalog.symbols.len() as u64 * 4096;
    if address >= end || address.saturating_add(size as u64) <= first {
        return None;
    }
    let index = ((address.max(first) - first) / 4096) as usize;
    let symbol = catalog.symbols.get(index)?;
    Some(ProviderDenial {
        name: symbol.name.clone(),
        kind: symbol.kind,
        access,
        address,
        size,
        offset: address.saturating_sub(catalog.base + symbol.rva as u64),
    })
}
pub(super) fn record_access(
    engine: &mut Unicorn<Trace>,
    address: u64,
    size: usize,
    access: &'static str,
) {
    if let Some(denial) = describe(engine, address, size, access) {
        let state = &mut engine.get_data_mut().apis;
        if state.provider_denials.len() < 64 {
            state.provider_denials.push(denial);
        } else {
            state.provider_denials_omitted += 1;
        }
    }
}

const KERNEL: &[&str] = &[
    "ExSystemTimeToLocalTime",
    "RtlTimeToTimeFields",
    "RtlInitUnicodeString",
    "RtlDuplicateUnicodeString",
    "RtlFreeUnicodeString",
    "wcslen",
    "strchr",
    "swprintf_s",
    "_vsnwprintf",
    "ZwOpenKey",
    "ZwQueryValueKey",
    "ExAllocatePool2",
    "ExAllocatePoolWithTag",
    "ExAllocatePool",
    "ExFreePool",
    "ExFreePoolWithTag",
    "MmGetSystemRoutineAddress",
    "IoGetCurrentProcess",
    "PsGetCurrentProcess",
    "PsGetCurrentProcessId",
    "PsGetCurrentThreadId",
    "KeGetCurrentThread",
    "PsGetCurrentThread",
    "ObReferenceObjectByPointer",
    "ObReferenceObjectByHandle",
    "ObfReferenceObject",
    "ObReferenceObject",
    "ObfDereferenceObject",
    "ObDereferenceObject",
    "KeGetCurrentIrql",
    "KeQueryActiveProcessorCountEx",
    "KeGetCurrentProcessorNumber",
    "KeGetCurrentProcessorNumberEx",
    "KeQueryPerformanceCounter",
    "KeQuerySystemTime",
    "KeQuerySystemTimePrecise",
    "KeQueryInterruptTime",
    "KeInitializeEvent",
    "KeSetEvent",
    "KeResetEvent",
    "KeClearEvent",
    "KeWaitForSingleObject",
    "KeWaitForMultipleObjects",
    "KeIpiGenericCall",
    "KeDelayExecutionThread",
    "KeInitializeGuardedMutex",
    "KeAcquireGuardedMutex",
    "KeReleaseGuardedMutex",
    "KeEnterCriticalRegion",
    "KeLeaveCriticalRegion",
    "KeRaiseIrql",
    "KeLowerIrql",
    "PsCreateSystemThread",
    "KeSetActualBasePriorityThread",
    "PsTerminateSystemThread",
    "ZwClose",
    "NtClose",
    "DbgPrompt",
    "KdChangeOption",
    "RtlMoveMemory",
    "RtlCopyMemory",
    "RtlZeroMemory",
    "RtlFillMemory",
    "RtlCompareMemory",
    "strcmp",
    "strlen",
    "DbgPrintEx",
];
const WIN32: &[&str] = &[
    "GetModuleHandleA",
    "GetModuleHandleW",
    "GetProcAddress",
    "GetCurrentProcessId",
    "GetLastError",
    "SetLastError",
    "Sleep",
    "GetTickCount",
    "GetTickCount64",
    "QueryPerformanceCounter",
    "QueryPerformanceFrequency",
    "GetSystemTimeAsFileTime",
    "GetSystemTimePreciseAsFileTime",
    "VirtualAlloc",
    "VirtualProtect",
    "VirtualFree",
    "CreateFileA",
    "CreateFileW",
    "ReadFile",
    "WriteFile",
    "SetFilePointer",
    "GetFileSizeEx",
    "CloseHandle",
    "LoadLibraryA",
    "LoadLibraryW",
    "LoadLibraryExA",
    "LoadLibraryExW",
    "FreeLibrary",
];
const NTDLL: &[&str] = &[
    "LdrLoadDll",
    "LdrUnloadDll",
    "RtlMoveMemory",
    "RtlCopyMemory",
    "RtlZeroMemory",
    "RtlFillMemory",
    "RtlCompareMemory",
    "strcmp",
    "strlen",
];

fn gate(engine: &mut Unicorn<Trace>, module: &str, name: &str) -> Result<u64> {
    let binding = definition(engine.get_data().architecture, module, name);
    ensure!(
        !matches!(binding.model, Model::Unsupported),
        "Provider export has no API model: {module}!{name}"
    );
    ensure!(
        !matches!(
            binding.model,
            Model::Environment(kernel_environment::Call::Data(_))
                | Model::Objects(kernel_objects::Call::Data(_))
        ),
        "Typed provider data cannot use a routine gate"
    );
    if let Some(index) = engine
        .get_data()
        .apis
        .bindings
        .iter()
        .position(|old| old.name == binding.name)
    {
        return Ok(engine.get_data().apis.base + index as u64 * 16);
    }
    let state = &engine.get_data().apis;
    ensure!(
        state.end > state.base && state.bindings.len() < 4096,
        "Provider API gate bound exceeded"
    );
    let address = state.base + state.bindings.len() as u64 * 16;
    let stub = super::return_stub(engine.get_data().architecture, &binding)?;
    crate::cpu::write(engine, address, &stub)?;
    engine.get_data_mut().apis.bindings.push(Arc::new(binding));
    Ok(address)
}

pub(super) fn initialize(engine: &mut Unicorn<Trace>) -> Result<()> {
    initialize_with_reference(engine, None).map(|_| ())
}
pub(super) fn initialize_with_reference(
    engine: &mut Unicorn<Trace>,
    reference: Option<&reference_mapping::IntegratedPrepared>,
) -> Result<Option<reference_mapping::MappingReceipt>> {
    let mut reference_receipt = None;
    if reference.is_none()
        && !engine.get_data().apis.bindings.iter().any(|b| {
            matches!(
                b.model,
                Model::SystemRoutine
                    | Model::DynamicLoader(_)
                    | Model::KernelModules(_)
                    | Model::ModuleHandleA
                    | Model::ModuleHandleW
                    | Model::Procedure
                    | Model::Environment(kernel_environment::Call::Data(_))
                    | Model::Objects(kernel_objects::Call::Data(_))
            )
        })
    {
        return Ok(None);
    }
    let architecture = engine.get_data().architecture;
    let kernel = engine.get_data().apis.kernel_mode;
    if reference.is_some() {
        ensure!(
            kernel && architecture == Architecture::X64,
            "Reference provider requires x64 kernel mode"
        );
        let base = engine.get_data().apis.base;
        if engine.get_data().apis.end == base {
            uc(engine.mem_map(base, 65536, Prot::READ | Prot::EXEC))?;
            engine.get_data_mut().apis.memory.map(
                base,
                65536,
                P::RX,
                None,
                "generated Windows API stubs",
            )?;
            engine.get_data_mut().apis.end = base + 65536;
        }
        // The only displaced legacy provider is HAL. Check its new native and
        // catalog slot before committing the enlarged ntoskrnl image.
        let hal = reference_mapping::REFERENCE_HAL_BASE;
        ensure!(
            engine.get_data().apis.modules.module("hal.dll")?.is_none(),
            "Reference HAL name conflicts with an existing guest module"
        );
        let mut planned_memory = engine.get_data().apis.memory.clone();
        planned_memory.map(hal, 0x6000, P::READ, None, "reference HAL slot preflight")?;
        ensure!(
            uc(engine.mem_regions())?
                .iter()
                .all(|r| hal > r.end || hal + 0x6000 <= r.begin)
                && engine
                    .get_data()
                    .apis
                    .modules
                    .modules()
                    .all(|m| hal >= m.base + m.size || hal + 0x6000 <= m.base),
            "Reference HAL slot conflicts with existing guest mapping"
        );
    }
    let profiles: &[(&str, &[&str])] = if kernel {
        &[
            ("ntoskrnl.exe", KERNEL),
            ("hal.dll", &["KeQueryPerformanceCounter"]),
        ]
    } else {
        &[
            ("kernel32.dll", WIN32),
            ("kernelbase.dll", WIN32),
            ("ntdll.dll", NTDLL),
            ("msvcrt.dll", &["strcmp", "strlen"]),
        ]
    };
    let first = match (architecture, kernel) {
        (Architecture::X64, true) => 0xfffff80000400000,
        (Architecture::X86, true) => 0x80400000,
        _ => 0x74000000,
    };
    for (index, (module, names)) in profiles.iter().enumerate() {
        ensure!(
            engine.get_data().apis.modules.module(module)?.is_none(),
            "Synthetic provider conflicts with a guest module"
        );
        let mut selected = names.to_vec();
        if architecture == Architecture::X64 && matches!(*module, "ntoskrnl.exe" | "ntdll.dll") {
            selected.push("__C_specific_handler");
            selected.push("DbgBreakPoint");
        }
        if kernel && *module == "ntoskrnl.exe" {
            // Publishing only the central table strands valid delegated import
            // bindings on catalog NONE pages when all imports are rebound.
            // The authoritative modeled lists are finite and module-specific;
            // gate() still rejects unsupported/data bindings, preserving every
            // unimplemented catalog symbol and all separate HAL/CNG semantics.
            for name in mdl::ROUTINES
                .iter()
                .chain(rundown::ROUTINES)
                .chain(callbacks::ROUTINES)
                .chain(kernel_sync::ROUTINES)
                .chain(kernel_spin::routines(architecture))
                .chain(crate::threads::timers::ROUTINES)
                .chain(kernel_modules::ROUTINES)
                .chain(kernel_files::ROUTINES)
            {
                if !selected.contains(name) {
                    selected.push(*name);
                }
            }
        }
        if *module == "kernel32.dll" {
            selected.extend([
                "RtlMoveMemory",
                "RtlCopyMemory",
                "RtlZeroMemory",
                "RtlFillMemory",
            ]);
        }
        let mut exports = Vec::with_capacity(selected.len());
        for name in &selected {
            exports.push((*name, gate(engine, module, name)?));
        }
        let base = if reference.is_some() && *module == "hal.dll" {
            reference_mapping::REFERENCE_HAL_BASE
        } else {
            first + index as u64 * if kernel { 0x1000000 } else { 0x100000 }
        };
        let data = if kernel && *module == "ntoskrnl.exe" {
            let mut data = kernel_environment::data_exports(engine)?;
            data.extend(kernel_objects::data_exports(engine)?);
            data
        } else {
            Vec::new()
        };
        let mut pending_lock = None;
        let mut redirected = None;
        let (bytes, reference_catalog) =
            if kernel && architecture == Architecture::X64 && *module == "ntoskrnl.exe" {
                let mut image = emumee_core::provider::catalog_image_with_data(
                    architecture,
                    base,
                    &exports,
                    &data,
                )?;
                let mut lock_rva = emumee_core::provider::append_kernel_lock_storage(&mut image)?;
                if let Some(reference) = reference {
                    let integrated = emumee_core::provider::integrate_reference_with_header(
                        image,
                        base,
                        &reference.view,
                        &reference.code_exports,
                        Some(&reference.header_identity),
                    )?;
                    image = integrated.image;
                    lock_rva = integrated.lock_rva;
                    redirected = Some(integrated.redirected_exports);
                }
                pending_lock = Some((
                    lock_rva,
                    CatalogStorage {
                        base,
                        first: image.metadata.protected_rva,
                        symbols: image.symbols,
                    },
                ));
                (image.bytes, Some(image.metadata))
            } else {
                (
                    emumee_core::provider::image_with_data(
                        architecture,
                        base,
                        module,
                        &exports,
                        &data,
                    )?,
                    None,
                )
            };
        let pe = PeImage::parse(&bytes, module)?;
        let integrated = *module == "ntoskrnl.exe" && reference.is_some();
        if integrated {
            reference_receipt = Some(reference_mapping::map_integrated_provider(
                engine,
                &pe,
                &bytes,
                reference.unwrap(),
                redirected.unwrap(),
            )?);
        } else {
            crate::map_image(engine, &pe, &bytes, base)?;
            crate::protect_image(engine, &pe)?;
        }
        if let Some((lock_rva, storage)) = pending_lock {
            engine.get_data_mut().kernel_lock_storage = Some(base + u64::from(lock_rva));
            engine.get_data_mut().apis.protected_catalog = Some(storage);
        }
        let path = match *module {
            "ntoskrnl.exe" => r"C:\Windows\system32\ntoskrnl.exe",
            "hal.dll" => r"C:\Windows\system32\hal.dll",
            _ => "",
        };
        if integrated {
            // Transactional reference mapping already published its checked catalog.
        } else if path.is_empty() {
            engine.get_data_mut().apis.modules.add(module, base, &pe)?;
        } else {
            engine.get_data_mut().apis.modules.add_with_path(
                module,
                base,
                &pe,
                path,
                emumee_core::modules::ModuleOrigin::SyntheticProvider,
            )?;
        }
        if kernel && *module == "ntoskrnl.exe" {
            kernel_environment::record_globals(engine)?;
            kernel_objects::record_exports(engine)?;
        }
        engine.get_data_mut().apis.providers.push(ProviderEvidence {module:(*module).into(),base,exports:pe.exports.len(),image_size:pe.image_size,reference_catalog,metadata_only:None,scope:if integrated { "Synthetic provider with authenticated same-base READ/NX reference inspection sections; modeled routines retain generated stubs, configured public data retain original RVAs and unmodeled private data remain inaccessible. Reference code cannot execute." } else { "Synthetic guest PE; modeled routines execute through guest stubs. Explicit configured public kernel globals use READ/NX data. The x64 queued-spin-lock backing is a separate ntoskrnl RW/NX section. Classified unimplemented kernel code/data use no-access pages. Other provider profiles remain partial. No Windows binary bytes or private data values." }});
    }
    Ok(reference_receipt)
}

fn ansi(engine: &Unicorn<Trace>, address: u64) -> Result<String> {
    let length = string_length(engine, address, 129)?;
    let bytes = read(engine, address, length)?;
    ensure!(
        bytes.is_ascii(),
        "Dynamic loader name is not ASCII in the current profile"
    );
    Ok(String::from_utf8(bytes)?)
}
fn unicode_string(engine: &Unicorn<Trace>, address: u64) -> Result<String> {
    let width = engine.get_data().architecture.width();
    let header = read(engine, address, if width == 8 { 16 } else { 8 })?;
    let length = u16::from_le_bytes(header[..2].try_into().unwrap()) as usize;
    let maximum = u16::from_le_bytes(header[2..4].try_into().unwrap()) as usize;
    ensure!(
        length <= 256 && length <= maximum && length % 2 == 0,
        "Invalid bounded UNICODE_STRING length"
    );
    let mut pointer = [0u8; 8];
    pointer[..width].copy_from_slice(&header[width..width * 2]);
    let bytes = read(engine, u64::from_le_bytes(pointer), length as u64)?;
    let units = bytes
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect::<Vec<_>>();
    Ok(String::from_utf16(&units)?)
}
fn resolve(engine: &Unicorn<Trace>, module: &str, symbol: &ImportName) -> Result<Option<u64>> {
    match engine.get_data().apis.modules.resolve(module, symbol)? {
        Resolution::Found { address, .. } => Ok(Some(address)),
        _ => {
            ensure!(
                !engine
                    .get_data()
                    .apis
                    .providers
                    .iter()
                    .any(|p| p.module == module),
                "Unmodeled synthetic provider export: {module}!{symbol:?}; Windows export availability is not established"
            );
            Ok(None)
        }
    }
}
pub(super) fn call(engine: &mut Unicorn<Trace>, model: Model, args: &[u64]) -> Result<u64> {
    match model {
        Model::SystemRoutine => {
            ensure!(
                engine.get_data().apis.kernel_mode,
                "MmGetSystemRoutineAddress requires a kernel target"
            );
            ensure!(
                engine.get_data().apis.kernel.save().0 == 0,
                "MmGetSystemRoutineAddress requires PASSIVE_LEVEL"
            );
            let name = ImportName::Name(unicode_string(engine, args[0])?);
            for module in ["ntoskrnl.exe", "hal.dll"] {
                if let Resolution::Found { address, .. } =
                    engine.get_data().apis.modules.resolve(module, &name)?
                {
                    return Ok(address);
                }
            }
            bail!(
                "Unmodeled synthetic provider export: {name:?}; Windows export availability is not established"
            )
        }
        Model::ModuleHandleA | Model::ModuleHandleW => {
            let name = if args[0] == 0 {
                return engine
                    .get_data()
                    .apis
                    .modules
                    .primary()
                    .map(|module| module.base)
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "GetModuleHandle(NULL) has no actual primary module identity"
                        )
                    });
            } else {
                files::path(engine, args[0], matches!(model, Model::ModuleHandleW))?
            };
            if let Some(base) = dynamic_loader::module_handle(engine, &name)? {
                Ok(base)
            } else {
                engine.get_data_mut().apis.last_error = 126;
                Ok(0)
            }
        }
        Model::Procedure => {
            let module = engine
                .get_data()
                .apis
                .modules
                .modules()
                .find(|m| m.base == args[0])
                .map(|m| m.name.clone());
            let Some(module) = module else {
                engine.get_data_mut().apis.last_error = 126;
                return Ok(0);
            };
            let symbol = if args[1] <= 0xffff {
                ImportName::Ordinal {
                    ordinal: args[1] as u16,
                }
            } else {
                ImportName::Name(ansi(engine, args[1])?)
            };
            if let Some(address) = resolve(engine, &module, &symbol)? {
                if let Resolution::Found { chain, .. } =
                    engine.get_data().apis.modules.resolve(&module, &symbol)?
                {
                    dynamic_loader::retain_followed_edges(engine, &module, &chain)?;
                }
                Ok(address)
            } else {
                engine.get_data_mut().apis.last_error = 127;
                Ok(0)
            }
        }
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn complete_guest_export_tables_support_names_ordinals_missing_symbols_and_forwarders() {
        for architecture in [Architecture::X86, Architecture::X64] {
            let mut engine = crate::new_engine(architecture).unwrap();
            let (root, companions) = emumee_core::fixtures::linked_probe(
                architecture,
                emumee_core::fixtures::LinkedFixture::Forwarded,
            );
            let pe = PeImage::parse(&root, "root.exe").unwrap();
            crate::map_image(&mut engine, &pe, &root, pe.image_base).unwrap();
            crate::protect_image(&mut engine, &pe).unwrap();
            for (name, bytes) in &companions {
                let pe = PeImage::parse(bytes, name).unwrap();
                engine
                    .get_data_mut()
                    .apis
                    .modules
                    .add(name, pe.image_base, &pe)
                    .unwrap();
                crate::map_image(&mut engine, &pe, bytes, pe.image_base).unwrap();
                crate::protect_image(&mut engine, &pe).unwrap();
            }
            let string = pe.image_base + 0x2c00;
            let first = engine
                .get_data()
                .apis
                .modules
                .module("GUEST.DLL")
                .unwrap()
                .unwrap()
                .base;
            let target = engine
                .get_data()
                .apis
                .modules
                .module("other.dll")
                .unwrap()
                .unwrap()
                .base
                + 0x1000;
            crate::cpu::write(&mut engine, string, b"Alpha\0").unwrap();
            assert_eq!(
                call(&mut engine, Model::Procedure, &[first, string]).unwrap(),
                target
            );
            assert_eq!(
                call(&mut engine, Model::Procedure, &[first, 1]).unwrap(),
                target
            );
            crate::cpu::write(&mut engine, string, b"alpha\0").unwrap();
            assert_eq!(
                call(&mut engine, Model::Procedure, &[first, string]).unwrap(),
                0
            );
            assert_eq!(engine.get_data().apis.last_error, 127);
            assert_eq!(call(&mut engine, Model::Procedure, &[first, 2]).unwrap(), 0);
            assert_eq!(
                call(&mut engine, Model::Procedure, &[first + 1, 1]).unwrap(),
                0
            );
            assert_eq!(engine.get_data().apis.last_error, 126);
        }
    }
}

#[cfg(test)]
mod delegated_routines_tests {
    use super::*;
    #[test]
    fn explicit_delegated_routines_have_exact_supported_kernel_bindings_only() {
        for architecture in [Architecture::X86, Architecture::X64] {
            for name in mdl::ROUTINES
                .iter()
                .chain(rundown::ROUTINES)
                .chain(callbacks::ROUTINES)
            {
                let binding = definition(architecture, "ntoskrnl.exe", name);
                assert!(!matches!(binding.model, Model::Unsupported));
                assert!(binding.count > 0);
                assert!(matches!(
                    definition(architecture, "cng.sys", name).model,
                    Model::Unsupported
                ));
                assert!(matches!(
                    definition(architecture, "hal.dll", name).model,
                    Model::Unsupported
                ));
            }
            let insert = definition(architecture, "ntoskrnl.exe", "KeInsertQueueDpc");
            assert!(matches!(insert.model, Model::DpcQueue(true)));
            assert_eq!(insert.count, 3);
            let remove = definition(architecture, "ntoskrnl.exe", "KeRemoveQueueDpc");
            assert!(matches!(remove.model, Model::DpcQueue(false)));
            assert_eq!(remove.count, 1);
        }
    }
}
