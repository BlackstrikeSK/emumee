//! Configured processor identity and explicit READ/NX public kernel globals.
use super::*;
use emumee_core::{
    kernel_environment::{Environment, Global},
    provider::DataExport,
};

#[derive(Clone, Copy)]
pub(super) enum Call {
    ActiveCount,
    Current,
    CurrentEx,
    ChangeOption,
    Data(Global),
}
pub(super) fn definition(name: &str) -> Option<(Call, usize, C, T)> {
    if let Some(global) = Global::from_name(name) {
        return Some((Call::Data(global), 0, C::Stdcall, T::Pointer));
    }
    Some(match name {
        "KeQueryActiveProcessorCountEx" => (Call::ActiveCount, 1, C::Stdcall, T::U32),
        "KeGetCurrentProcessorNumber" => (Call::Current, 0, C::Stdcall, T::U32),
        "KeGetCurrentProcessorNumberEx" => (Call::CurrentEx, 1, C::Stdcall, T::U32),
        "KdChangeOption" => (Call::ChangeOption, 6, C::Stdcall, T::U32),
        _ => return None,
    })
}
#[derive(Default)]
pub(crate) struct State {
    identity: Option<Environment>,
    globals: Vec<GlobalEvidence>,
    queries: u64,
    processor_number_writes: u64,
}
#[derive(Clone, Debug, Serialize)]
pub struct GlobalEvidence {
    pub name: &'static str,
    pub address: u64,
    pub width: usize,
    pub value: u64,
    pub permissions: &'static str,
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub identity: Option<Environment>,
    pub globals: Vec<GlobalEvidence>,
    pub queries: u64,
    pub processor_number_writes: u64,
    pub scope: &'static str,
}
fn configured(engine: &Unicorn<Trace>) -> Result<Environment> {
    // The actual execution domain selects the configured logical processor;
    // ordinary threads run on CPU0 and guest IPI members use their owned CPU.
    Ok(Environment::new(
        engine.get_data().architecture,
        &engine.get_data().cpu.profile,
        engine.get_data().machine.windows_build(),
        engine.get_data().cpu.processor,
    )?
    .with_boot_debug(engine.get_data().machine.boot_debug()))
}
fn remember(engine: &mut Unicorn<Trace>, model: &Environment) -> Result<()> {
    if let Some(old) = &engine.get_data().apis.environment.identity {
        ensure!(
            old.logical_processors == model.logical_processors
                && old.windows_build == model.windows_build
                && old.highest_user_address == model.highest_user_address
                && old.user_probe_address == model.user_probe_address
                && old.debugger_enabled == model.debugger_enabled
                && old.debugger_present == model.debugger_present,
            "Configured kernel identity changed after publication"
        );
    }
    engine.get_data_mut().apis.environment.identity = Some(model.clone());
    Ok(())
}
pub(crate) fn report(engine: &Unicorn<Trace>) -> Report {
    let state = &engine.get_data().apis.environment;
    Report {
        identity: state.identity.as_ref().map(|identity| {
            let mut current = identity.clone();
            current.current_processor = engine.get_data().cpu.processor;
            current
        }),
        globals: state.globals.clone(),
        queries: state.queries,
        processor_number_writes: state.processor_number_writes,
        scope: "Configured CpuProfile, selected logical CPU, Windows build and boot_config.debug. Five public kernel globals have typed READ/NX storage. Debugging enablement is separate from debugger presence: no attached transport is synthesized. KdChangeOption implements the no-debug-controls early return only; enabled-debugger option mutation and enable/disable/refresh APIs remain unsupported. No host topology or private global synthesis. Bounded IPI execution is reported separately.",
    }
}
/// The low-level native write bridge bypasses Unicorn page protections. Guard
/// the whole published READ/NX data page there as well as at API preflight.
pub(crate) fn require_api_access(
    engine: &Unicorn<Trace>,
    address: u64,
    size: u64,
    permissions: P,
) -> Result<()> {
    if size == 0 || (!permissions.contains(P::WRITE) && !permissions.contains(P::EXECUTE)) {
        return Ok(());
    }
    let end = address
        .checked_add(size)
        .ok_or_else(|| anyhow::anyhow!("Kernel data access range overflow"))?;
    for global in &engine.get_data().apis.environment.globals {
        let page = global.address & !4095;
        ensure!(
            address >= page + 4096 || end <= page,
            "Modeled kernel global READ/NX page cannot be written or executed through an API"
        );
    }
    Ok(())
}
pub(super) fn data_exports(engine: &mut Unicorn<Trace>) -> Result<Vec<DataExport>> {
    let model = configured(engine)?;
    remember(engine, &model)?;
    Ok(Global::ALL
        .into_iter()
        .map(|global| DataExport {
            name: global.name(),
            bytes: model.global_bytes(global),
            alignment: if matches!(
                global,
                Global::NumberProcessors | Global::DebuggerEnabled | Global::DebuggerNotPresent
            ) {
                1
            } else {
                engine.get_data().architecture.width()
            },
        })
        .collect())
}
/// Called only after the owned ntoskrnl provider is mapped and protected, before
/// imports are rebound. Records actual EAT addresses, never API gate addresses.
pub(super) fn record_globals(engine: &mut Unicorn<Trace>) -> Result<()> {
    use emumee_core::modules::Resolution;
    let model = configured(engine)?;
    remember(engine, &model)?;
    let mut evidence = Vec::new();
    for global in Global::ALL {
        let Resolution::Found { address, .. } = engine
            .get_data()
            .apis
            .modules
            .resolve("ntoskrnl.exe", &ImportName::Name(global.name().into()))?
        else {
            bail!("Modeled kernel data export was not published");
        };
        let bytes = model.global_bytes(global);
        require(engine, address, bytes.len() as u64, P::READ)?;
        ensure!(
            !engine
                .get_data()
                .apis
                .memory
                .allows(address, bytes.len() as u64, P::WRITE)
                && !engine
                    .get_data()
                    .apis
                    .memory
                    .allows(address, bytes.len() as u64, P::EXECUTE),
            "Modeled kernel data must be READ/NX"
        );
        ensure!(
            read(engine, address, bytes.len() as u64)? == bytes,
            "Modeled kernel global bytes differ from configured identity"
        );
        let mut value = [0u8; 8];
        value[..bytes.len()].copy_from_slice(&bytes);
        evidence.push(GlobalEvidence {
            name: global.name(),
            address,
            width: bytes.len(),
            value: u64::from_le_bytes(value),
            permissions: "r--",
        });
    }
    engine.get_data_mut().apis.environment.globals = evidence;
    Ok(())
}
pub(super) fn call(engine: &mut Unicorn<Trace>, call: Call, args: &[u64]) -> Result<u64> {
    ensure!(
        engine.get_data().apis.kernel_mode,
        "Kernel environment API requires a native driver target"
    );
    let expected = match call {
        Call::ActiveCount | Call::CurrentEx => 1,
        Call::ChangeOption => 6,
        _ => 0,
    };
    ensure!(
        args.len() == expected,
        "Kernel environment API argument count mismatch"
    );
    if let Call::Data(global) = call {
        bail!(
            "Kernel global {} was called as a routine instead of bound as data",
            global.name()
        );
    }
    let model = configured(engine)?;
    remember(engine, &model)?;
    engine.get_data_mut().apis.environment.queries += 1;
    Ok(match call {
        Call::ChangeOption => {
            // WDK contract and pinned kernel RVA4ba810: KdPitchDebugger
            // rejects a no-debug-controls boot before any buffer access.
            ensure!(
                !model.debugger_enabled,
                "KdChangeOption enabled-debugger option mutation is not yet modeled"
            );
            0xc0000354 // STATUS_DEBUGGER_INACTIVE, never STATUS_SUCCESS.
        }
        Call::ActiveCount => model.active_processor_count_ex(args[0]) as u64,
        Call::Current => model.current_processor_number() as u64,
        Call::CurrentEx => {
            if args[0] != 0 {
                // Validate every byte before the only write, including across
                // region boundaries. Unicorn mem_write itself bypasses RO.
                require(engine, args[0], 4, P::WRITE)?;
                crate::cpu::write(engine, args[0], &model.processor_number())?;
                engine
                    .get_data_mut()
                    .apis
                    .environment
                    .processor_number_writes += 1;
            }
            model.current_processor as u64
        }
        Call::Data(_) => unreachable!(),
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    fn engine(architecture: Architecture) -> crate::NativeEngine {
        let mut engine = crate::new_engine(architecture).unwrap();
        engine
            .get_data_mut()
            .apis
            .target(architecture, true)
            .unwrap();
        engine.get_data_mut().cpu.profile.cores = 3;
        engine.get_data_mut().cpu.profile.threads_per_core = 2;
        uc(engine.mem_map(0x9000, 4096, Prot::READ | Prot::WRITE)).unwrap();
        engine
            .get_data_mut()
            .apis
            .memory
            .map(0x9000, 4096, P::RW, None, "environment-test")
            .unwrap();
        engine
    }
    #[test]
    fn configured_queries_write_full_optional_processor_number_and_validate_argument_count() {
        for architecture in [Architecture::X86, Architecture::X64] {
            let mut engine = engine(architecture);
            assert_eq!(call(&mut engine, Call::ActiveCount, &[0]).unwrap(), 6);
            assert_eq!(
                call(&mut engine, Call::ActiveCount, &[u64::MAX]).unwrap(),
                6
            );
            assert_eq!(call(&mut engine, Call::ActiveCount, &[1]).unwrap(), 0);
            assert_eq!(call(&mut engine, Call::CurrentEx, &[0]).unwrap(), 0);
            crate::cpu::write(&mut engine, 0x9100, &[0xcc; 8]).unwrap();
            assert_eq!(call(&mut engine, Call::CurrentEx, &[0x9101]).unwrap(), 0);
            assert_eq!(
                engine.mem_read_as_vec(0x9100, 8).unwrap(),
                [0xcc, 0, 0, 0, 0, 0xcc, 0xcc, 0xcc]
            );
            assert!(call(&mut engine, Call::CurrentEx, &[]).is_err());
            assert!(call(&mut engine, Call::Current, &[1]).is_err());
            assert!(call(&mut engine, Call::Data(Global::HighestUserAddress), &[]).is_err());
        }
    }
    #[test]
    fn bad_cross_boundary_readonly_and_overflow_outputs_preserve_all_bytes() {
        for architecture in [Architecture::X86, Architecture::X64] {
            let mut engine = engine(architecture);
            crate::cpu::write(&mut engine, 0x9ffc, &[0xcc; 4]).unwrap();
            for address in [0x9ffe, 0xdeadbeef, u64::MAX - 1] {
                assert!(call(&mut engine, Call::CurrentEx, &[address]).is_err());
                assert_eq!(engine.mem_read_as_vec(0x9ffc, 4).unwrap(), [0xcc; 4]);
            }
            uc(engine.mem_protect(0x9000, 4096, Prot::READ)).unwrap();
            engine
                .get_data_mut()
                .apis
                .memory
                .protect(0x9000, 4096, P::READ)
                .unwrap();
            assert!(call(&mut engine, Call::CurrentEx, &[0x9ffc]).is_err());
            assert_eq!(engine.mem_read_as_vec(0x9ffc, 4).unwrap(), [0xcc; 4]);
            assert_eq!(report(&engine).processor_number_writes, 0);
            engine
                .get_data_mut()
                .apis
                .environment
                .globals
                .push(GlobalEvidence {
                    name: "KeNumberProcessors",
                    address: 0x9000,
                    width: 1,
                    value: 6,
                    permissions: "r--",
                });
            // Protection covers padding in the READ/NX page too. The direct
            // host-side bridge must never bypass this published ownership.
            assert!(crate::cpu::write(&mut engine, 0x9ffc, b"FAIL").is_err());
            assert!(require_api_access(&engine, 0x9001, 1, P::WRITE).is_err());
            assert!(require_api_access(&engine, 0x9001, 1, P::EXECUTE).is_err());
            assert!(require_api_access(&engine, 0x9001, 1, P::READ).is_ok());
            assert_eq!(engine.mem_read_as_vec(0x9ffc, 4).unwrap(), [0xcc; 4]);
        }
    }
}
