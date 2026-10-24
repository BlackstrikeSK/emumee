//! Kernel module queries over actual catalog/provenance, never host inventory.
use super::*;
use emumee_core::kernel_modules::{self as inventory, ModuleRow};
#[derive(Clone, Copy)]
pub(super) enum Call {
    Query,
    Pc,
}
pub(super) const ROUTINES: &[&str] = &[
    "ZwQuerySystemInformation",
    "NtQuerySystemInformation",
    "RtlPcToFileHeader",
];
pub(super) fn definition(name: &str) -> Option<(Call, usize, T)> {
    Some(match name {
        "ZwQuerySystemInformation" | "NtQuerySystemInformation" => (Call::Query, 4, T::U32),
        "RtlPcToFileHeader" => (Call::Pc, 2, T::Pointer),
        _ => return None,
    })
}
#[derive(Default)]
pub(crate) struct State {
    events: Vec<Event>,
    omitted: u64,
    last_inventory: Vec<ModuleRow>,
    native_effect_failure: bool,
}
#[derive(Clone, Debug, Serialize)]
pub struct Event {
    pub operation: &'static str,
    pub class: Option<u32>,
    pub capacity: u32,
    pub required: u32,
    pub copied: u32,
    pub status: u32,
    pub pc: Option<u64>,
    pub found_base: Option<u64>,
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub events: Vec<Event>,
    pub events_omitted: u64,
    pub last_inventory: Vec<ModuleRow>,
    pub native_effect_failure: bool,
    pub scope: &'static str,
}
pub(crate) fn report(engine: &Unicorn<Trace>) -> Report {
    let s = &engine.get_data().apis.kernel_modules;
    Report {
        events: s.events.clone(),
        events_omitted: s.omitted,
        last_inventory: s.last_inventory.clone(),
        native_effect_failure: s.native_effect_failure,
        scope: "Actual mapped ModuleCatalog with explicit owned/configured/synthetic guest paths and immutable accepted headers; native classes11/77 and half-open PC lookup only. Query events distinguish copied buffers from length retries; returned metadata is not proof of guest consumption, module resolution, actual Windows binaries or trust. No host enumeration, debugger/CI/time/process classes or general loader-list ABI.",
    }
}
fn overlap(a: u64, n: u64, b: u64, m: u64) -> bool {
    n != 0 && m != 0 && a < b.saturating_add(m) && b < a.saturating_add(n)
}
fn record(engine: &mut Unicorn<Trace>, event: Event) {
    let s = &mut engine.get_data_mut().apis.kernel_modules;
    if s.events.len() < 128 {
        s.events.push(event);
    } else {
        s.omitted = s.omitted.saturating_add(1);
    }
}
fn writable(engine: &Unicorn<Trace>, address: u64, size: u64) -> Result<()> {
    require(engine, address, size, P::WRITE)?;
    super::mdl::require_api_write(engine, address, size)
}
fn publish(engine: &mut Unicorn<Trace>, writes: &[(u64, &[u8])]) -> Result<()> {
    for (index, (address, bytes)) in writes.iter().enumerate() {
        writable(engine, *address, bytes.len() as u64)?;
        for (previous, data) in &writes[..index] {
            ensure!(
                !overlap(*address, bytes.len() as u64, *previous, data.len() as u64),
                "Module query outputs overlap; profile unsupported"
            );
        }
    }
    for (address, bytes) in writes {
        if let Err(error) = crate::cpu::write(engine, *address, bytes) {
            engine
                .get_data_mut()
                .apis
                .kernel_modules
                .native_effect_failure = true;
            return Err(error);
        }
    }
    Ok(())
}
pub(super) fn call(engine: &mut Unicorn<Trace>, call: Call, args: &[u64]) -> Result<u64> {
    ensure!(
        !engine.get_data().apis.kernel_modules.native_effect_failure,
        "Kernel module query native effect failed; execution cannot resume"
    );
    let irql = super::kernel_sync::observe_irql(engine)?;
    ensure!(
        irql == 0,
        "Kernel module inventory/lookup requires supported PASSIVE_LEVEL profile"
    );
    if matches!(call, Call::Pc) {
        let width = engine.get_data().architecture.width();
        writable(engine, args[1], width as u64)?;
        let base = engine
            .get_data()
            .apis
            .modules
            .containing(args[0])
            .map_or(0, |module| module.base);
        let bytes = base.to_le_bytes();
        publish(engine, &[(args[1], &bytes[..width])])?;
        record(
            engine,
            Event {
                operation: "pc_to_file_header",
                class: None,
                capacity: width as u32,
                required: width as u32,
                copied: width as u32,
                status: 0,
                pc: Some(args[0]),
                found_base: Some(base),
            },
        );
        return Ok(base);
    }
    let class = args[0] as u32;
    let capacity = args[2] as u32;
    let planned = inventory::module_buffer(
        engine.get_data().architecture,
        &engine.get_data().apis.modules,
        class,
    )?;
    let required = u32::try_from(planned.bytes.len())
        .map_err(|_| anyhow::anyhow!("Module inventory output exceeds ULONG"))?;
    if args[3] != 0 {
        writable(engine, args[3], 4)?;
    }
    let success = capacity >= required;
    if success {
        writable(engine, args[1], required.into())?;
        ensure!(
            args[3] == 0 || !overlap(args[1], required.into(), args[3], 4),
            "Module query outputs overlap; profile unsupported"
        );
    }
    let length = required.to_le_bytes();
    let mut writes: Vec<(u64, &[u8])> = Vec::with_capacity(2);
    if success {
        writes.push((args[1], &planned.bytes));
    }
    if args[3] != 0 {
        writes.push((args[3], &length));
    }
    publish(engine, &writes)?;
    let status = if success { 0 } else { 0xc0000004 };
    engine.get_data_mut().apis.kernel_modules.last_inventory = planned.rows;
    record(
        engine,
        Event {
            operation: "system_information",
            class: Some(class),
            capacity,
            required,
            copied: if success { required } else { 0 },
            status,
            pc: None,
            found_base: None,
        },
    );
    Ok(status.into())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn module_query_bindings_are_kernel_only_native_abi_and_other_classes_have_no_success_handler()
    {
        for arch in [Architecture::X86, Architecture::X64] {
            for name in ROUTINES {
                let b = super::super::definition(arch, "ntoskrnl.exe", name);
                assert!(matches!(b.model, Model::KernelModules(_)));
                assert_eq!(b.convention, C::Stdcall);
                for module in ["ntdll.dll", "kernel32.dll", "hal.dll"] {
                    assert!(matches!(
                        super::super::definition(arch, module, name).model,
                        Model::Unsupported
                    ));
                }
            }
        }
    }
    #[test]
    fn protected_outputs_preflight_together_and_unexpected_partial_native_failure_is_terminal() {
        for overlap_case in [false, true] {
            let mut engine = crate::new_engine(Architecture::X64).unwrap();
            engine
                .get_data_mut()
                .apis
                .memory
                .map(0x10000, 4096, P::RW, None, "owned query output")
                .unwrap();
            uc(engine.mem_map(0x10000, 4096, Prot::READ | Prot::WRITE)).unwrap();
            uc(engine.mem_write(0x10000, &[0x77; 16])).unwrap();
            let first = [1; 8];
            let second = [2; 4];
            let address = if overlap_case { 0x10004 } else { 0x11000 };
            assert!(publish(&mut engine, &[(0x10000, &first), (address, &second)]).is_err());
            assert_eq!(uc(engine.mem_read_as_vec(0x10000, 16)).unwrap(), [0x77; 16]);
            assert!(!report(&engine).native_effect_failure);
        }
        let mut engine = crate::new_engine(Architecture::X64).unwrap();
        for address in [0x10000, 0x20000] {
            engine
                .get_data_mut()
                .apis
                .memory
                .map(address, 4096, P::RW, None, "owned native-failure fault")
                .unwrap();
        }
        uc(engine.mem_map(0x10000, 4096, Prot::READ | Prot::WRITE)).unwrap();
        assert!(publish(&mut engine, &[(0x10000, &[1; 8]), (0x20000, &[2; 4])]).is_err());
        assert_eq!(uc(engine.mem_read_as_vec(0x10000, 8)).unwrap(), [1; 8]);
        assert!(report(&engine).native_effect_failure);
        let error = call(&mut engine, Call::Query, &[11, 0, 0, 0])
            .unwrap_err()
            .to_string();
        assert!(error.contains("execution cannot resume"));
        assert!(report(&engine).events.is_empty());
    }
}
