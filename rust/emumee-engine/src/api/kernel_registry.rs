//! Read-only native key APIs over the installed sole Registry authority.
use super::*;
use emumee_core::registry::{self, NativeError, NativeHandleClass, NativeOpen, NativeQuery};
use sha2::{Digest, Sha256};
const OWNER: u64 = 4;
const MISMATCH: u32 = 0xc0000024;
#[derive(Clone, Copy)]
pub(super) enum Call {
    Open,
    Query,
}
pub(super) fn definition(name: &str) -> Option<(Call, usize)> {
    Some(match name {
        "ZwOpenKey" => (Call::Open, 3),
        "ZwQueryValueKey" => (Call::Query, 6),
        _ => return None,
    })
}
#[derive(Default)]
pub(crate) struct State {
    native_effect_failure: bool,
    events: Vec<Event>,
    omitted: u64,
}
#[derive(Clone, Debug, Serialize)]
pub struct Event {
    pub operation: &'static str,
    pub handle: u64,
    pub status: u32,
    pub name_preview: String,
    pub name_units: usize,
    pub name_utf8_sha256: String,
    pub information_class: Option<u32>,
    pub capacity: Option<u32>,
    pub required: Option<u32>,
    pub copied: usize,
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub handles: registry::NativeHandleReport,
    pub events: Vec<Event>,
    pub events_omitted: u64,
    pub native_effect_failure: bool,
    pub scope: &'static str,
}
pub(crate) fn report(engine: &Unicorn<Trace>) -> Report {
    let state = &engine.get_data().apis.kernel_registry;
    Report {
        handles: engine.get_data().apis.registry.native_handle_report(),
        events: state.events.clone(),
        events_omitted: state.omitted,
        native_effect_failure: state.native_effect_failure,
        scope: "ZwOpenKey/ZwQueryValueKey classes1/2 and shared typed ZwClose only, actual installed Registry. System4/PASSIVE/kernel-only finite handles; native Machine/User roots. No HKCU/SID guessing, ACLs/transactions, Create/Set, valid unported query classes, private CM objects or kernel-file close fabrication.",
    }
}
fn record(engine: &mut Unicorn<Trace>, event: Event) {
    let state = &mut engine.get_data_mut().apis.kernel_registry;
    if state.events.len() < 128 {
        state.events.push(event);
    } else {
        state.omitted = state.omitted.saturating_add(1);
    }
}
fn event(operation: &'static str, handle: u64, status: u32, name: &str) -> Event {
    Event {
        operation,
        handle,
        status,
        name_preview: name.chars().take(128).collect(),
        name_units: name.encode_utf16().count(),
        name_utf8_sha256: format!("{:x}", Sha256::digest(name.as_bytes())),
        information_class: None,
        capacity: None,
        required: None,
        copied: 0,
    }
}
fn ready(engine: &mut Unicorn<Trace>) -> Result<()> {
    ensure!(
        engine.get_data().apis.kernel_mode,
        "Native registry/handle API requires a driver target"
    );
    ensure!(
        super::kernel_sync::observe_irql(engine)? == 0,
        "Native registry/handle API requires PASSIVE_LEVEL"
    );
    ensure!(
        !engine.get_data().apis.kernel_registry.native_effect_failure,
        "Native registry effect failed; execution cannot resume"
    );
    Ok(())
}
fn failure(error: NativeError) -> Result<u32> {
    if let Some(status) = error.status {
        Ok(status)
    } else {
        bail!("Native registry profile unsupported: {}", error.reason)
    }
}
fn pointer(bytes: &[u8], offset: usize, width: usize) -> u64 {
    let mut value = [0; 8];
    value[..width].copy_from_slice(&bytes[offset..offset + width]);
    u64::from_le_bytes(value)
}
fn counted(engine: &Unicorn<Trace>, address: u64, empty: bool) -> Result<String> {
    ensure!(
        address != 0,
        "Native registry counted name descriptor is required"
    );
    let width = engine.get_data().architecture.width();
    let header = read(engine, address, if width == 8 { 16 } else { 8 })?;
    let length = u16::from_le_bytes(header[..2].try_into().unwrap()) as usize;
    let maximum = u16::from_le_bytes(header[2..4].try_into().unwrap()) as usize;
    ensure!(
        length % 2 == 0 && length <= maximum,
        "Native registry UNICODE_STRING length/maximum profile"
    );
    ensure!(
        empty || length != 0,
        "Empty native registry object name is not modeled"
    );
    let address = pointer(&header, if width == 8 { 8 } else { 4 }, width);
    let bytes = if length == 0 {
        Vec::new()
    } else {
        read(engine, address, length as u64)?
    };
    let name = registry::decode_name(&bytes, true)?;
    ensure!(
        !name.contains('\0'),
        "Embedded-NUL native registry name is not modeled"
    );
    Ok(name)
}
fn known_wrong_type(engine: &Unicorn<Trace>, handle: u64) -> Result<Option<u32>> {
    let arch = engine.get_data().architecture;
    if engine
        .get_data()
        .apis
        .registry
        .native_handle_class(arch, OWNER, handle)
        != NativeHandleClass::Foreign
    {
        return Ok(None);
    }
    Ok(
        match crate::threads::lookup_reference_handle(engine, handle)? {
            crate::threads::HandleLookup::Thread(_) => Some(MISMATCH),
            crate::threads::HandleLookup::Invalid => Some(registry::STATUS_INVALID_HANDLE),
            crate::threads::HandleLookup::Foreign => {
                use emumee_core::filesystem::NativeFileClass as F;
                match engine
                    .get_data()
                    .apis
                    .files
                    .native_file_class(arch, OWNER, handle)
                {
                    F::Live(_) => Some(MISMATCH),
                    F::Invalid => Some(registry::STATUS_INVALID_HANDLE),
                    F::UserLive => bail!(
                        "Ordinary user-file handle is outside native registry/kernel-file profile"
                    ),
                    F::Foreign => None,
                }
            }
        },
    )
}
fn outputs(engine: &mut Unicorn<Trace>, writes: &[(u64, Vec<u8>)]) -> Result<()> {
    for (index, (address, bytes)) in writes.iter().enumerate() {
        if bytes.is_empty() {
            continue;
        }
        require(engine, *address, bytes.len() as u64, P::WRITE)?;
        let end = address
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| anyhow::anyhow!("Native registry output range overflow"))?;
        for (other, data) in &writes[..index] {
            if data.is_empty() {
                continue;
            }
            let other_end = other
                .checked_add(data.len() as u64)
                .ok_or_else(|| anyhow::anyhow!("Native registry output range overflow"))?;
            ensure!(
                *address >= other_end || *other >= end,
                "Overlapping native registry outputs are not modeled"
            );
        }
    }
    for (address, bytes) in writes {
        if bytes.is_empty() {
            continue;
        }
        if let Err(error) = crate::cpu::write(engine, *address, bytes) {
            engine
                .get_data_mut()
                .apis
                .kernel_registry
                .native_effect_failure = true;
            return Err(error);
        }
    }
    Ok(())
}
fn open(engine: &mut Unicorn<Trace>, args: &[u64]) -> Result<u64> {
    let width = engine.get_data().architecture.width();
    let size = if width == 8 { 48 } else { 24 };
    let bytes = read(engine, args[2], size)?;
    if u32::from_le_bytes(bytes[..4].try_into().unwrap()) != size as u32 {
        return Ok(0xc000000d);
    }
    let (root, name, flags, security, qos) = if width == 8 {
        (8, 16, 24, 32, 40)
    } else {
        (4, 8, 12, 16, 20)
    };
    let flags = u32::from_le_bytes(bytes[flags..flags + 4].try_into().unwrap());
    ensure!(
        flags & !0x240 == 0
            && pointer(&bytes, security, width) == 0
            && pointer(&bytes, qos, width) == 0,
        "Native registry object attributes/security profile unsupported"
    );
    let name = counted(engine, pointer(&bytes, name, width), false)?;
    let root = pointer(&bytes, root, width);
    if root != 0 {
        if let Some(status) = known_wrong_type(engine, root)? {
            record(engine, event("open", root, status, &name));
            return Ok(status as u64);
        }
    }
    let plan = engine
        .get_data()
        .apis
        .registry
        .plan_native_open(NativeOpen {
            architecture: engine.get_data().architecture,
            owner: OWNER,
            root,
            name: &name,
            access: args[1] as u32,
        });
    let plan = match plan {
        Ok(plan) => plan,
        Err(error) => {
            let status = failure(error)?;
            record(engine, event("open", 0, status, &name));
            return Ok(status as u64);
        }
    };
    let handle = plan.handle();
    ensure!(
        !engine.get_data().apis.files.owns_handle(handle)
            && !matches!(
                crate::threads::lookup_reference_handle(engine, handle)?,
                crate::threads::HandleLookup::Thread(_)
            ),
        "Native registry candidate handle collides with an existing typed owner"
    );
    outputs(engine, &[(args[0], handle.to_le_bytes()[..width].to_vec())])?;
    if let Err(error) = engine.get_data_mut().apis.registry.commit_native_open(plan) {
        engine
            .get_data_mut()
            .apis
            .kernel_registry
            .native_effect_failure = true;
        bail!("Native registry open commit failed after output: {error}");
    }
    record(engine, event("open", handle, 0, &name));
    Ok(0)
}
fn query(engine: &mut Unicorn<Trace>, args: &[u64]) -> Result<u64> {
    let name = counted(engine, args[1], true)?;
    if let Some(status) = known_wrong_type(engine, args[0])? {
        record(engine, event("query", args[0], status, &name));
        return Ok(status as u64);
    }
    let plan = engine.get_data().apis.registry.native_query(NativeQuery {
        architecture: engine.get_data().architecture,
        owner: OWNER,
        handle: args[0],
        name: &name,
        class: args[2] as u32,
        capacity: args[4] as u32,
    });
    let plan = match plan {
        Ok(plan) => plan,
        Err(error) => {
            let status = failure(error)?;
            record(engine, event("query", args[0], status, &name));
            return Ok(status as u64);
        }
    };
    let mut row = event("query", args[0], plan.status, &name);
    row.information_class = Some(args[2] as u32);
    row.capacity = Some(args[4] as u32);
    row.required = Some(plan.required);
    row.copied = plan.bytes.len();
    outputs(
        engine,
        &[
            (args[3], plan.bytes),
            (args[5], plan.required.to_le_bytes().to_vec()),
        ],
    )?;
    record(engine, row);
    Ok(plan.status as u64)
}
pub(super) fn call(engine: &mut Unicorn<Trace>, call: Call, args: &[u64]) -> Result<u64> {
    ready(engine)?;
    ensure!(
        args.len()
            == match call {
                Call::Open => 3,
                Call::Query => 6,
            },
        "Native registry argument count mismatch"
    );
    match call {
        Call::Open => open(engine, args),
        Call::Query => query(engine, args),
    }
}
/// Generic close over actual typed Registry and Thread authorities. A future
/// kernel-file lane must add its real owner/domain, never a generic success.
pub(crate) fn close(engine: &mut Unicorn<Trace>, handle: u64) -> Result<u64> {
    ready(engine)?;
    super::kernel_files::ensure_healthy(engine)?;
    let arch = engine.get_data().architecture;
    let status = match engine
        .get_data()
        .apis
        .registry
        .native_handle_class(arch, OWNER, handle)
    {
        NativeHandleClass::KernelLive => match engine
            .get_data_mut()
            .apis
            .registry
            .native_close(arch, OWNER, handle)
        {
            Ok(()) => 0,
            Err(error) => failure(error)?,
        },
        NativeHandleClass::Invalid => registry::STATUS_INVALID_HANDLE,
        NativeHandleClass::UserLive => {
            bail!("User registry handles are outside kernel close profile")
        }
        NativeHandleClass::Foreign => {
            match crate::threads::lookup_reference_handle(engine, handle)? {
                crate::threads::HandleLookup::Thread(_) => {
                    return crate::threads::close(engine, handle);
                }
                crate::threads::HandleLookup::Invalid => registry::STATUS_INVALID_HANDLE,
                crate::threads::HandleLookup::Foreign => {
                    if let Some(status) = super::kernel_files::close_if_owned(engine, handle)? {
                        return Ok(status);
                    }
                    registry::STATUS_INVALID_HANDLE
                }
            }
        }
    };
    record(engine, event("close", handle, status, ""));
    Ok(status as u64)
}

/// Closed generated fixture entry, never an arbitrary external image runner.
pub(crate) fn fixture(
    architecture: Architecture,
    kind: emumee_core::fixtures::NativeRegistryFixture,
    budget: u64,
) -> Result<crate::Execution> {
    let validated = emumee_core::fullpersona::decode(
        &emumee_core::fixtures::native_registry_document(),
        &emumee_core::fullpersona::ResolveContext::default(),
    )?;
    let prepared = crate::configured::Prepared::new(
        validated,
        crate::configured::Request {
            architecture,
            kernel: true,
            initial_processor: 0,
            process: None,
            budget,
            timeout_us: 30_000_000,
        },
    )?;
    crate::run_generated_with_fixture_configuration(
        &emumee_core::fixtures::native_registry_probe(architecture, kind),
        &[],
        budget,
        30_000_000,
        crate::GeneratedConfiguration {
            configured: Some(prepared),
            ..Default::default()
        },
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    fn memory(engine: &mut Unicorn<Trace>, native: bool) {
        engine.get_data_mut().apis.kernel_mode = true;
        crate::kernel_cpu::initialize(engine).unwrap();
        engine
            .get_data_mut()
            .apis
            .memory
            .map(0x10000, 4096, P::RW, None, "native registry test")
            .unwrap();
        if native {
            engine
                .mem_map(0x10000, 4096, Prot::READ | Prot::WRITE)
                .unwrap();
        }
    }
    #[test]
    fn output_plan_preflights_every_range_and_overlap_before_any_write() {
        for writes in [
            vec![(0x10000, vec![1; 8]), (0x11000, vec![2; 4])],
            vec![(0x10000, vec![1; 8]), (0x10004, vec![2; 4])],
        ] {
            let mut engine = crate::new_engine(Architecture::X64).unwrap();
            memory(&mut engine, true);
            engine.mem_write(0x10000, &[0x77; 16]).unwrap();
            assert!(outputs(&mut engine, &writes).is_err());
            assert_eq!(engine.mem_read_as_vec(0x10000, 16).unwrap(), [0x77; 16]);
            assert_eq!(report(&engine).handles.lifetime_issues, 0);
            assert!(!report(&engine).native_effect_failure);
        }
    }
    #[test]
    fn native_output_effect_failure_is_sticky_and_never_allows_resume() {
        let mut engine = crate::new_engine(Architecture::X64).unwrap();
        memory(&mut engine, false);
        assert!(outputs(&mut engine, &[(0x10000, vec![1; 8])]).is_err());
        assert!(report(&engine).native_effect_failure);
        assert!(
            ready(&mut engine)
                .unwrap_err()
                .to_string()
                .contains("cannot resume")
        );
        assert_eq!(report(&engine).handles.lifetime_issues, 0);
    }
    #[test]
    fn counted_names_use_exact_length_without_terminator_and_reject_malformed_units() {
        for arch in [Architecture::X86, Architecture::X64] {
            let mut engine = crate::new_engine(arch).unwrap();
            memory(&mut engine, true);
            let mut descriptor = vec![0; 16];
            descriptor[..2].copy_from_slice(&2u16.to_le_bytes());
            descriptor[2..4].copy_from_slice(&4u16.to_le_bytes());
            let width = arch.width();
            let offset = if width == 8 { 8 } else { 4 };
            descriptor[offset..offset + width].copy_from_slice(&0x10100u64.to_le_bytes()[..width]);
            engine.mem_write(0x10000, &descriptor).unwrap();
            engine.mem_write(0x10100, &[b'G', 0, b'X', 0]).unwrap();
            assert_eq!(counted(&engine, 0x10000, false).unwrap(), "G");
            engine.mem_write(0x10100, &[0, 0xd8]).unwrap();
            assert!(counted(&engine, 0x10000, false).is_err());
            engine.mem_write(0x10000, &1u16.to_le_bytes()).unwrap();
            assert!(counted(&engine, 0x10000, false).is_err());
        }
    }
    #[test]
    fn initialized_actual_processor_irql_is_required_before_any_registry_effect() {
        for arch in [Architecture::X86, Architecture::X64] {
            let mut engine = crate::new_engine(arch).unwrap();
            engine.get_data_mut().apis.kernel_mode = true;
            assert!(
                ready(&mut engine)
                    .unwrap_err()
                    .to_string()
                    .contains("not initialized")
            );
            crate::kernel_cpu::initialize(&mut engine).unwrap();
            ready(&mut engine).unwrap();
            if arch == Architecture::X64 {
                engine.reg_write(RegisterX86::CR8, 2).unwrap();
            } else {
                let pcr = crate::kernel_cpu::current_pcr(&engine).unwrap();
                engine.mem_write(pcr + 0x24, &[2]).unwrap();
            }
            assert_eq!(engine.get_data().apis.kernel.save().0, 0);
            assert!(
                ready(&mut engine)
                    .unwrap_err()
                    .to_string()
                    .contains("PASSIVE_LEVEL")
            );
            assert_eq!(engine.get_data().apis.kernel.save().0, 2);
            let state = report(&engine);
            assert_eq!(state.handles.lifetime_issues, 0);
            assert_eq!(state.handles.live, 0);
            assert!(state.events.is_empty());
        }
    }
}
