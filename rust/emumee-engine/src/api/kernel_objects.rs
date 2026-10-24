//! System/Driver ownership and opaque type identities; no foreign handle table.
use super::*;
use emumee_core::{
    kernel_layout::KernelLayout,
    kernel_objects::{Kind, Objects, Operation},
    provider::DataExport,
};
use std::cell::RefCell;
#[derive(Clone, Copy)]
pub(super) enum Call {
    CurrentProcess,
    CurrentPid,
    CurrentThread,
    CurrentTid,
    ByPointer,
    Reference,
    ByHandle,
    Data(Option<Kind>),
}
pub(super) fn definition(name: &str) -> Option<(Call, usize, C, T)> {
    if name == "PsInitialSystemProcess" {
        return Some((Call::Data(None), 0, C::Stdcall, T::Pointer));
    }
    if let Some(kind) = Kind::from_export(name) {
        return Some((Call::Data(Some(kind)), 0, C::Stdcall, T::Pointer));
    }
    Some(match name {
        "IoGetCurrentProcess" | "PsGetCurrentProcess" => {
            (Call::CurrentProcess, 0, C::Stdcall, T::Pointer)
        }
        "PsGetCurrentProcessId" => (Call::CurrentPid, 0, C::Stdcall, T::Pointer),
        "PsGetCurrentThreadId" => (Call::CurrentTid, 0, C::Stdcall, T::Pointer),
        "KeGetCurrentThread" | "PsGetCurrentThread" => {
            (Call::CurrentThread, 0, C::Stdcall, T::Pointer)
        }
        "ObReferenceObjectByPointer" => (Call::ByPointer, 4, C::Stdcall, T::U32),
        "ObfReferenceObject" | "ObReferenceObject" => (Call::Reference, 1, C::Fastcall, T::Void),
        "ObReferenceObjectByHandle" => (Call::ByHandle, 6, C::Stdcall, T::U32),
        _ => return None,
    })
}
#[derive(Default)]
pub(crate) struct State {
    pub(super) model: Option<Objects>,
    storage: Vec<Storage>,
    denials: RefCell<Vec<Denial>>,
    omitted: std::cell::Cell<u64>,
    native_failure: bool,
}
#[derive(Clone, Debug, Serialize)]
pub struct Storage {
    pub name: &'static str,
    pub address: u64,
    pub value: u64,
    pub width: usize,
    pub permissions: &'static str,
}
#[derive(Clone, Debug, Serialize)]
pub struct Denial {
    pub address: u64,
    pub size: u64,
    pub access: &'static str,
    pub identity: u64,
    pub kind: &'static str,
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub system_process: Option<u64>,
    pub system_pid: u32,
    pub driver_object: Option<u64>,
    pub driver_object_initialized: bool,
    pub types: Vec<emumee_core::kernel_objects::TypeIdentity>,
    pub objects: Vec<emumee_core::kernel_objects::Object>,
    pub storage: Vec<Storage>,
    pub events: Vec<emumee_core::kernel_objects::Event>,
    pub events_omitted: u64,
    pub api_denials: Vec<Denial>,
    pub denials_omitted: u64,
    pub native_effect_failure: bool,
    pub scope: &'static str,
}
pub(crate) fn report(engine: &Unicorn<Trace>) -> Report {
    let state = &engine.get_data().apis.objects;
    let model = state.model.as_ref();
    let expected_size = if engine.get_data().architecture == Architecture::X64 {
        0x150u16
    } else {
        0xa8
    };
    let driver_object_initialized = model
        .and_then(|owned| read(engine, owned.driver_object, 4).ok())
        .is_some_and(|bytes| {
            bytes[..2] == 4u16.to_le_bytes() && bytes[2..4] == expected_size.to_le_bytes()
        });
    Report {
        system_process: model.map(|m| m.system_process),
        system_pid: 4,
        driver_object: model.map(|m| m.driver_object),
        driver_object_initialized,
        types: model.map(|m| m.types.clone()).unwrap_or_default(),
        objects: model
            .map(|m| m.records.values().cloned().collect())
            .unwrap_or_default(),
        storage: state.storage.clone(),
        events: model.map(|m| m.events.clone()).unwrap_or_default(),
        events_omitted: model.map_or(0, |m| m.omitted),
        api_denials: state.denials.borrow().clone(),
        denials_omitted: state.omitted.get(),
        native_effect_failure: state.native_failure,
        scope: "Owned System PID4 opaque identity and actual DriverEntry DRIVER_OBJECT; permanent lifetime references separate from transient API references. Type identity pages are NONE; pointer exports READ/NX. No EPROCESS/OBJECT_TYPE internals, KTHREAD process fields, process attach, UserMode ACL checks, namespace, foreign process/file handles or teardown synthesis. Scheduler thread handle references delegate to the actual thread execution map.",
    }
}
fn model<'engine>(engine: &'engine Unicorn<'_, Trace>) -> Result<&'engine Objects> {
    ensure!(
        engine.get_data().apis.kernel_mode,
        "Kernel object API requires a driver target"
    );
    ensure!(
        !engine.get_data().apis.objects.native_failure,
        "Kernel object native initialization/effect failed"
    );
    engine
        .get_data()
        .apis
        .objects
        .model
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Owned kernel object identities have not been initialized"))
}
pub(crate) fn initialize(engine: &mut Unicorn<Trace>) -> Result<()> {
    if !engine.get_data().apis.kernel_mode {
        return Ok(());
    }
    ensure!(
        engine.get_data().apis.objects.model.is_none()
            && !engine.get_data().apis.objects.native_failure,
        "Kernel object identities already initialized or failed"
    );
    let architecture = engine.get_data().architecture;
    let layout = KernelLayout::for_architecture(architecture);
    let owned = Objects::new(
        architecture,
        layout.driver_object + 0x3000,
        layout.driver_object,
        layout.driver_object + 0x10000,
    )?;
    let pages: Vec<_> = std::iter::once(owned.system_process)
        .chain(owned.types.iter().map(|entry| entry.identity))
        .collect();
    for address in &pages {
        ensure!(
            engine.get_data().apis.memory.region(*address).is_none(),
            "Owned kernel identity reservation collides with mapped guest memory"
        );
    }
    // Any partial native failure is terminal. Retain failed state and never
    // retry, remove evidence or continue with only part of the identity catalog.
    engine.get_data_mut().apis.objects.native_failure = true;
    for address in pages {
        uc(engine.mem_map(address, 4096, Prot::NONE))?;
        engine.get_data_mut().apis.memory.map(
            address,
            4096,
            P::NONE,
            Some(4),
            "owned opaque kernel object/type identity",
        )?;
    }
    engine.get_data_mut().apis.objects.model = Some(owned);
    engine.get_data_mut().apis.objects.native_failure = false;
    Ok(())
}
fn opaque_overlap(
    engine: &Unicorn<Trace>,
    address: u64,
    size: u64,
) -> Result<Option<(u64, &'static str)>> {
    if size == 0 {
        return Ok(None);
    }
    let end = address
        .checked_add(size)
        .ok_or_else(|| anyhow::anyhow!("Kernel identity access range overflow"))?;
    let Some(model) = engine.get_data().apis.objects.model.as_ref() else {
        return Ok(None);
    };
    for (identity, kind) in std::iter::once((model.system_process, "EPROCESS")).chain(
        model
            .types
            .iter()
            .map(|item| (item.identity, "OBJECT_TYPE")),
    ) {
        if address < identity + 4096 && identity < end {
            return Ok(Some((identity, kind)));
        }
    }
    Ok(None)
}
pub(crate) fn record_private_access(
    engine: &Unicorn<Trace>,
    address: u64,
    size: u64,
    access: &'static str,
) {
    if let Ok(Some((identity, kind))) = opaque_overlap(engine, address, size) {
        let state = &engine.get_data().apis.objects;
        let mut denials = state.denials.borrow_mut();
        if denials.len() < 64 {
            denials.push(Denial {
                address,
                size,
                access,
                identity,
                kind,
            });
        } else {
            state.omitted.set(state.omitted.get().saturating_add(1));
        }
    }
}
pub(crate) fn require_api_access(
    engine: &Unicorn<Trace>,
    address: u64,
    size: u64,
    permissions: P,
) -> Result<()> {
    if permissions == P::NONE || size == 0 {
        return Ok(());
    }
    if let Some((_, kind)) = opaque_overlap(engine, address, size)? {
        let access = if permissions.contains(P::WRITE) {
            "write"
        } else if permissions.contains(P::EXECUTE) {
            "execute"
        } else {
            "read"
        };
        record_private_access(engine, address, size, access);
        bail!("Unmodeled private kernel {kind} identity cannot be accessed through an API");
    }
    if permissions.contains(P::WRITE) || permissions.contains(P::EXECUTE) {
        let end = address
            .checked_add(size)
            .ok_or_else(|| anyhow::anyhow!("Kernel export access range overflow"))?;
        for storage in &engine.get_data().apis.objects.storage {
            let page = storage.address & !4095;
            ensure!(
                address >= page + 4096 || end <= page,
                "Kernel object pointer export page is READ/NX"
            );
        }
    }
    Ok(())
}
pub(crate) fn data_exports(engine: &Unicorn<Trace>) -> Result<Vec<DataExport>> {
    let model = model(engine)?;
    let width = engine.get_data().architecture.width();
    let mut data = vec![DataExport {
        name: "PsInitialSystemProcess",
        bytes: model.system_process.to_le_bytes()[..width].to_vec(),
        alignment: width,
    }];
    data.extend(model.types.iter().map(|item| DataExport {
        name: item.kind.export(),
        bytes: item.identity.to_le_bytes()[..width].to_vec(),
        alignment: width,
    }));
    Ok(data)
}
pub(crate) fn record_exports(engine: &mut Unicorn<Trace>) -> Result<()> {
    use emumee_core::modules::Resolution;
    let data = data_exports(engine)?;
    let mut storage = Vec::new();
    for item in data {
        let Resolution::Found { address, .. } = engine
            .get_data()
            .apis
            .modules
            .resolve("ntoskrnl.exe", &ImportName::Name(item.name.into()))?
        else {
            bail!("Owned object pointer export was not published");
        };
        require(engine, address, item.bytes.len() as u64, P::READ)?;
        ensure!(
            !engine
                .get_data()
                .apis
                .memory
                .allows(address, item.bytes.len() as u64, P::WRITE)
                && !engine.get_data().apis.memory.allows(
                    address,
                    item.bytes.len() as u64,
                    P::EXECUTE
                ),
            "Owned object pointer exports require READ/NX storage"
        );
        ensure!(
            read(engine, address, item.bytes.len() as u64)? == item.bytes,
            "Owned object pointer export value mismatch"
        );
        let mut value = [0; 8];
        value[..item.bytes.len()].copy_from_slice(&item.bytes);
        storage.push(Storage {
            name: item.name,
            address,
            value: u64::from_le_bytes(value),
            width: item.bytes.len(),
            permissions: "r--",
        });
    }
    engine.get_data_mut().apis.objects.storage = storage;
    Ok(())
}
fn validate_driver_entry_identity(engine: &Unicorn<Trace>, address: u64) -> Result<()> {
    let owned = model(engine)?;
    if address == owned.driver_object {
        let bytes = read(engine, address, 4)?;
        let size = if engine.get_data().architecture == Architecture::X64 {
            0x150u16
        } else {
            0xa8
        };
        ensure!(
            bytes[..2] == 4u16.to_le_bytes() && bytes[2..4] == size.to_le_bytes(),
            "Driver object identity requires the actual initialized DriverEntry reservation"
        );
    }
    Ok(())
}
pub(crate) fn dereference(engine: &mut Unicorn<Trace>, address: u64) -> Result<bool> {
    if super::kernel_thread_objects::owns(engine, address) {
        super::kernel_thread_objects::dereference(engine, address)?;
        return Ok(true);
    }
    if !engine
        .get_data()
        .apis
        .objects
        .model
        .as_ref()
        .is_some_and(|model| model.records.contains_key(&address))
    {
        return Ok(false);
    }
    validate_driver_entry_identity(engine, address)?;
    let irql = engine.get_data().apis.kernel.save().0;
    let plan = model(engine)?.plan(irql, address, Operation::Dereference)?;
    engine.get_data_mut().apis.objects.model = Some(plan.state);
    Ok(true)
}
pub(super) fn call(engine: &mut Unicorn<Trace>, call: Call, args: &[u64]) -> Result<u64> {
    model(engine)?;
    let count = match call {
        Call::ByPointer => 4,
        Call::Reference => 1,
        Call::ByHandle => 6,
        _ => 0,
    };
    ensure!(
        args.len() == count,
        "Kernel object API argument count mismatch"
    );
    match call {
        Call::CurrentProcess => {
            let model = model(engine)?;
            model.object(model.system_process)?;
            Ok(model.system_process)
        }
        Call::CurrentPid => {
            let model = model(engine)?;
            model.object(model.system_process)?;
            Ok(4)
        }
        Call::ByHandle => super::kernel_thread_objects::by_handle(engine, args),
        Call::CurrentThread => super::kernel_thread_objects::current_thread(engine),
        Call::CurrentTid => super::kernel_thread_objects::current_tid(engine),
        Call::Data(kind) => {
            bail!(
                "Kernel object pointer export {} was called as a routine instead of bound as data",
                kind.map(Kind::export).unwrap_or("PsInitialSystemProcess")
            )
        }
        Call::Reference | Call::ByPointer => {
            validate_driver_entry_identity(engine, args[0])?;
            let irql = engine.get_data().apis.kernel.save().0;
            let operation = if matches!(call, Call::ByPointer) {
                Operation::ByPointer {
                    object_type: args[2],
                    mode: args[3],
                }
            } else {
                Operation::Reference
            };
            let plan = model(engine)?.plan(irql, args[0], operation)?;
            let result = plan.result;
            engine.get_data_mut().apis.objects.model = Some(plan.state);
            Ok(result)
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn owned_none_process_and_types_refuse_api_reads_and_native_bridge_writes() {
        for architecture in [Architecture::X86, Architecture::X64] {
            let mut engine = crate::new_engine(architecture).unwrap();
            engine
                .get_data_mut()
                .apis
                .target(architecture, true)
                .unwrap();
            initialize(&mut engine).unwrap();
            let address = model(&engine).unwrap().system_process;
            assert_eq!(
                call(&mut engine, Call::CurrentProcess, &[]).unwrap(),
                address
            );
            assert_eq!(call(&mut engine, Call::CurrentPid, &[]).unwrap(), 4);
            assert!(require_api_access(&engine, address, 1, P::READ).is_err());
            assert!(crate::cpu::write(&mut engine, address, b"FAKE").is_err());
            uc(engine.mem_map(0x9000, 4096, Prot::READ | Prot::WRITE)).unwrap();
            engine
                .get_data_mut()
                .apis
                .memory
                .map(0x9000, 4096, P::RW, None, "object-test-output")
                .unwrap();
            crate::cpu::write(&mut engine, 0x9000, &[0xcc; 8]).unwrap();
            assert!(call(&mut engine, Call::ByHandle, &[1, 0, 0, 0, 0x9000, 0]).is_err());
            assert_eq!(engine.mem_read_as_vec(0x9000, 8).unwrap(), [0xcc; 8]);
            assert_eq!(data_exports(&engine).unwrap().len(), 13);
            call(&mut engine, Call::Reference, &[address]).unwrap();
            assert!(dereference(&mut engine, address).unwrap());
            assert!(dereference(&mut engine, address).is_err());
            assert_eq!(
                model(&engine).unwrap().records[&address].permanent_references,
                1
            );
        }
    }
    #[test]
    fn identities_do_not_overlap_boot_reservations_or_claim_initialized_driver_bytes() {
        for architecture in [Architecture::X86, Architecture::X64] {
            let mut engine = crate::new_engine(architecture).unwrap();
            engine
                .get_data_mut()
                .apis
                .target(architecture, true)
                .unwrap();
            initialize(&mut engine).unwrap();
            let driver = model(&engine).unwrap().driver_object;
            assert_eq!(
                driver,
                KernelLayout::for_architecture(architecture).driver_object
            );
            assert!(call(&mut engine, Call::Reference, &[driver]).is_err());
            assert!(initialize(&mut engine).is_err());
            assert_eq!(report(&engine).objects.len(), 2);
        }
    }
}
