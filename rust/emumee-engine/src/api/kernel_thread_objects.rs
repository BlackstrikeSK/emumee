//! Actual scheduler thread identities and references. Only the documented
//! Type/Size/Signal bytes and explicitly profiled fields are readable; mirrors
//! are bounded privileged effects. Other private bytes remain inaccessible.
use super::*;
use emumee_core::{
    kernel_objects::{Kind, Objects, Operation},
    kernel_thread_objects::{Effect, Lifetimes, Plan, PrivateAccess},
};
use std::cell::{Cell, RefCell};
mod fields;
pub(crate) use fields::sync_critical;
#[derive(Default)]
pub(crate) struct State {
    model: RefCell<Option<Lifetimes>>,
    denials: RefCell<Vec<PrivateAccess>>,
    omitted: Cell<u64>,
    read_checks: Cell<u64>,
    read_guard_installed: bool,
    native_failure: bool,
    last_effect: Option<NativeEffect>,
    critical_mirrors: BTreeMap<u64, fields::CriticalMirror>,
}
#[derive(Clone, Debug, Serialize)]
pub struct NativeEffect {
    pub object: u64,
    pub operation: &'static str,
}
#[derive(Clone, Debug, Serialize)]
pub struct HandleEvidence {
    pub handle: u64,
    pub slot: u64,
    pub object: u64,
    pub owner: u64,
    pub granted_access: u32,
    pub kernel_only: bool,
}
#[derive(Debug, Serialize)]
pub struct Report {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_process_field: Option<emumee_core::kernel_thread_objects::SystemProcessField>,
    pub stack_fields: Vec<emumee_core::kernel_thread_objects::StackFields>,
    pub thread_fields: Vec<fields::FieldEvidence>,
    pub quiescent_parked_fields: Vec<emumee_core::kernel_thread_objects::ParkedPairFields>,
    pub threads: Vec<emumee_core::kernel_thread_objects::Lifetime>,
    pub handles: Vec<HandleEvidence>,
    pub private_accesses: Vec<PrivateAccess>,
    pub accesses_omitted: u64,
    pub read_guard_checks: u64,
    pub read_guard_installed: bool,
    pub native_effect_failure: bool,
    pub last_native_effect: Option<NativeEffect>,
    pub scope: &'static str,
}
pub(crate) fn report(engine: &Unicorn<Trace>) -> Report {
    let state = &engine.get_data().apis.thread_objects;
    Report {
        thread_fields: fields::report(engine),
        quiescent_parked_fields: fields::parked_report(engine),
        stack_fields: state
            .model
            .borrow()
            .as_ref()
            .map(|model| {
                engine
                    .get_data()
                    .apis
                    .objects
                    .model
                    .as_ref()
                    .map(|objects| {
                        model
                            .entries
                            .keys()
                            .filter_map(|address| {
                                model.stack_fields(objects, *address).ok().flatten()
                            })
                            .collect()
                    })
                    .unwrap_or_default()
            })
            .unwrap_or_default(),
        system_process_field: state
            .model
            .borrow()
            .as_ref()
            .and_then(|m| m.system_process_field()),
        threads: state
            .model
            .borrow()
            .as_ref()
            .map(|m| m.entries.values().cloned().collect())
            .unwrap_or_default(),
        handles: crate::threads::thread_handle_evidence(engine),
        private_accesses: state.denials.borrow().clone(),
        accesses_omitted: state.omitted.get(),
        read_guard_checks: state.read_checks.get(),
        read_guard_installed: state.read_guard_installed,
        native_effect_failure: state.native_failure,
        last_native_effect: state.last_effect.clone(),
        scope: "Actual scheduler thread slots/handles, System owner4, execution/handle/API lifetime anchors and persistent termination signals. Initial caller remains borrowed across DriverEntry return. Eight Type/Size/Signal bytes readable; configured x64 build26200 exposes ApcState.Process at0xb8 for every modeled thread and StackLimit/StackBase at0x30/0x38 for owned ordinary thread stacks. Pinned fields also expose KernelMode byte0x232, owned CLIENT_ID at0x508 and a read-only KernelApcDisable SHORT at0x1e4 synchronized with authoritative critical-region depth. No CombinedApcDisable DWORD, SpecialApcDisable, native inline counter mutation or APC delivery. Parked IPI callback stacks do not imply ordinary thread stack fields. Unknown private bytes, writes, crossing reads and retired bodies stop. No EPROCESS body, process attach or foreign process ownership is synthesized. KernelMode handle desired access follows legacy trusted-kernel behavior; UserMode/foreign process/file/security profiles remain unsupported.",
    }
}
pub(crate) fn read_guard_installed(engine: &Unicorn<Trace>) -> bool {
    engine.get_data().apis.thread_objects.read_guard_installed
}
pub(crate) fn completion_error(engine: &Unicorn<Trace>) -> Option<String> {
    engine
        .get_data()
        .apis
        .thread_objects
        .native_failure
        .then(|| "Kernel thread identity native effect failed; execution cannot resume".into())
}
fn objects<'engine>(engine: &'engine Unicorn<'_, Trace>) -> Result<&'engine Objects> {
    ensure!(
        engine.get_data().apis.kernel_mode,
        "Kernel thread objects require a driver target"
    );
    ensure!(
        !engine.get_data().apis.thread_objects.native_failure,
        "Kernel thread identity native effect failed"
    );
    engine
        .get_data()
        .apis
        .objects
        .model
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Owned kernel object model not initialized"))
}
fn note(engine: &Unicorn<Trace>, denial: PrivateAccess) {
    let state = &engine.get_data().apis.thread_objects;
    let mut rows = state.denials.borrow_mut();
    if rows.len() < 64 {
        rows.push(denial);
    } else {
        state.omitted.set(state.omitted.get().saturating_add(1));
    }
}
fn denial(
    engine: &Unicorn<Trace>,
    address: u64,
    size: u64,
    access: &'static str,
) -> Result<Option<PrivateAccess>> {
    let state = engine.get_data().apis.thread_objects.model.borrow();
    match state.as_ref() {
        Some(model) => {
            let denied = model.private_access(address, size, access)?;
            if denied.is_none()
                && access == "read"
                && let Some(field) = model.parked_pair_for_read(address, size)
            {
                ensure!(
                    uc(engine.mem_read_as_vec(field.thread + u64::from(field.offset), 8))?
                        == field.bytes(),
                    "Quiescent parked field mirror diverged; refusing repair"
                );
            }
            Ok(denied)
        }
        None => Ok(None),
    }
}
pub(crate) fn record_private_access(
    engine: &Unicorn<Trace>,
    address: u64,
    size: u64,
    access: &'static str,
) {
    if let Ok(Some(denied)) = denial(engine, address, size, access) {
        note(engine, denied);
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
    let access = if permissions.contains(P::WRITE) {
        "write"
    } else if permissions.contains(P::EXECUTE) {
        "execute"
    } else {
        "read"
    };
    if let Some(denied) = denial(engine, address, size, access)? {
        note(engine, denied);
        bail!("Unmodeled private or released kernel thread body access");
    }
    Ok(())
}
fn install_read_guard(engine: &mut Unicorn<Trace>) -> Result<()> {
    if engine.get_data().apis.thread_objects.read_guard_installed {
        return Ok(());
    }
    uc(engine.add_mem_hook(
        unicorn_engine::unicorn_const::HookType::MEM_READ,
        1,
        0,
        |engine, _, address, size, _| {
            // The model/telemetry borrows end before writing a fault or stopping
            // Unicorn. Normal reads perform no allocation and one ordered lookup.
            let checks = &engine.get_data().apis.thread_objects.read_checks;
            checks.set(checks.get().saturating_add(1));
            // Reuse this all-native read hook for bounded, diagnostic-only
            // observations of separately backed initial context pages.
            crate::kernel_context_reads::observe(engine, address, size);
            let denied = denial(engine, address, size as u64, "read");
            match denied {
                Ok(None) => {}
                Ok(Some(row)) => {
                    note(engine, row);
                    engine.get_data_mut().apis.fault.get_or_insert_with(|| {
                        "Unmodeled private or released kernel thread body read".into()
                    });
                    let _ = engine.emu_stop();
                }
                Err(error) => {
                    engine.get_data_mut().apis.fault.get_or_insert_with(|| {
                        format!("Kernel thread read validation failed: {error}")
                    });
                    let _ = engine.emu_stop();
                }
            }
            true
        },
    ))?;
    engine
        .get_data_mut()
        .apis
        .thread_objects
        .read_guard_installed = true;
    Ok(())
}
/// No caller can supply arbitrary bytes or a tail address to this mirror. All
/// writes derive from a validated core effect, are exactly8 bytes, and target
/// the same owned page; execution is NX throughout. No general guard bypass.
fn mirror_header(
    engine: &mut Unicorn<Trace>,
    plan: &Plan,
    address: u64,
    signaled: bool,
) -> Result<()> {
    let life = plan
        .lifetimes
        .entries
        .get(&address)
        .ok_or_else(|| anyhow::anyhow!("Thread mirror has no planned identity"))?;
    ensure!(
        life.address == address
            && plan
                .objects
                .records
                .get(&address)
                .is_some_and(|r| r.kind == Kind::Thread),
        "Thread mirror does not target owned thread identity"
    );
    ensure!(
        engine.get_data().apis.memory.allows(address, 4096, P::NONE),
        "Thread mirror target is not mapped guest backing"
    );
    super::reference_mapping::require_api_access(engine, address, 8, P::WRITE)?;
    let mut header = [0u8; 8];
    header[0] = 6;
    header[2] = if engine.get_data().architecture == Architecture::X64 {
        6
    } else {
        4
    };
    header[4..8].copy_from_slice(&u32::from(signaled).to_le_bytes());
    uc(engine.mem_write(address, &header))?;
    Ok(())
}
fn apply(engine: &mut Unicorn<Trace>, plan: Plan) -> Result<()> {
    if !plan.effects.is_empty() {
        engine.get_data_mut().apis.thread_objects.native_failure = true;
    }
    for effect in &plan.effects {
        let (address, operation) = match effect {
            Effect::Initialize { address } => (*address, "initialize_header"),
            Effect::Signal { address } => (*address, "signal_header"),
            Effect::Retire { address } => (*address, "retire_page"),
        };
        engine.get_data_mut().apis.thread_objects.last_effect = Some(NativeEffect {
            object: address,
            operation,
        });
        match *effect {
            Effect::Initialize { address } => {
                mirror_header(engine, &plan, address, false)?;
                if let Some(field) = plan.lifetimes.system_process_field() {
                    ensure!(
                        field.process == plan.objects.system_process,
                        "Thread System process projection diverged from owned Process"
                    );
                    let at = address + u64::from(field.offset);
                    super::reference_mapping::require_api_access(engine, at, 8, P::WRITE)?;
                    uc(engine.mem_write(at, &field.process.to_le_bytes()))?;
                }
                if let Some(field) = plan.lifetimes.stack_fields(&plan.objects, address)? {
                    ensure!(
                        engine.get_data().apis.memory.allows(
                            field.limit,
                            field.base - field.limit,
                            P::RW
                        ),
                        "Thread stack fields lack owned readable/writable stack backing"
                    );
                    let at = address + u64::from(field.limit_offset);
                    super::reference_mapping::require_api_access(engine, at, 16, P::WRITE)?;
                    let mut bytes = [0; 16];
                    bytes[..8].copy_from_slice(&field.limit.to_le_bytes());
                    bytes[8..].copy_from_slice(&field.base.to_le_bytes());
                    uc(engine.mem_write(at, &bytes))?;
                }
                fields::initialize(engine, &plan, address)?;
                super::kernel_pushlocks::initialize_thread(
                    engine,
                    &plan.lifetimes.entries[&address],
                )?;
                uc(engine.mem_protect(address, 4096, Prot::READ))?;
                engine
                    .get_data_mut()
                    .apis
                    .memory
                    .protect(address, 4096, P::READ)?;
            }
            Effect::Signal { address } => {
                super::kernel_pushlocks::finish_thread(engine, &plan.lifetimes.entries[&address])?;
                mirror_header(engine, &plan, address, true)?;
            }
            Effect::Retire { address } => {
                super::kernel_pushlocks::finish_thread(engine, &plan.lifetimes.entries[&address])?;
                uc(engine.mem_protect(address, 4096, Prot::NONE))?;
                engine
                    .get_data_mut()
                    .apis
                    .memory
                    .protect(address, 4096, P::NONE)?;
            }
        }
    }
    engine.get_data_mut().apis.objects.model = Some(plan.objects);
    *engine.get_data().apis.thread_objects.model.borrow_mut() = Some(plan.lifetimes);
    engine.get_data_mut().apis.thread_objects.native_failure = false;
    Ok(())
}
pub(crate) fn initialize_root(engine: &mut Unicorn<Trace>) -> Result<()> {
    ensure!(
        engine
            .get_data()
            .apis
            .thread_objects
            .model
            .borrow()
            .is_none(),
        "Initial System caller identity already initialized"
    );
    let mut plan = Lifetimes::initialize(engine.get_data().architecture, objects(engine)?)?;
    if engine.get_data().architecture == Architecture::X64
        && engine.get_data().machine.windows_build() == 26200
    {
        plan.lifetimes
            .configure_system_process_26200(&plan.objects)?;
    }
    if engine.get_data().quiescent_parked_requested {
        plan.lifetimes
            .configure_quiescent_parked_26200(&plan.objects)?;
    }
    // Install before any published body may be used by the guest. Native hook
    // installation failure is fatal, even when no page has yet changed.
    engine.get_data_mut().apis.thread_objects.native_failure = true;
    install_read_guard(engine)?;
    apply(engine, plan)
}
pub(crate) fn created(
    engine: &mut Unicorn<Trace>,
    slot: u64,
    actual_open_handles: u32,
) -> Result<()> {
    let address =
        emumee_core::kernel_layout::KernelLayout::for_architecture(engine.get_data().architecture)
            .thread_object(slot)
            .ok_or_else(|| anyhow::anyhow!("Kernel thread slot exceeds layout"))?;
    let plan = {
        let lives = engine.get_data().apis.thread_objects.model.borrow();
        lives
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Initial caller identity missing"))?
            .create(objects(engine)?, slot, address, actual_open_handles)?
    };
    apply(engine, plan)
}
pub(crate) fn closed(
    engine: &mut Unicorn<Trace>,
    slot: u64,
    actual_open_handles_before: u32,
) -> Result<()> {
    let plan = {
        let lives = engine.get_data().apis.thread_objects.model.borrow();
        lives
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Thread identity model missing"))?
            .close(objects(engine)?, slot, actual_open_handles_before)?
    };
    apply(engine, plan)
}
pub(crate) fn exited(
    engine: &mut Unicorn<Trace>,
    slot: u64,
    actual_open_handles: u32,
) -> Result<()> {
    let plan = {
        let lives = engine.get_data().apis.thread_objects.model.borrow();
        lives
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Thread identity model missing"))?
            .exit(objects(engine)?, slot, actual_open_handles)?
    };
    apply(engine, plan)
}
pub(crate) fn owns(engine: &Unicorn<Trace>, address: u64) -> bool {
    engine
        .get_data()
        .apis
        .thread_objects
        .model
        .borrow()
        .as_ref()
        .is_some_and(|model| model.entries.contains_key(&address))
}
pub(crate) fn dereference(engine: &mut Unicorn<Trace>, address: u64) -> Result<()> {
    let updated = objects(engine)?.plan(
        engine.get_data().apis.kernel.save().0,
        address,
        Operation::Dereference,
    )?;
    let plan = {
        let lives = engine.get_data().apis.thread_objects.model.borrow();
        lives
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Thread identity model missing"))?
            .after_api_reference(&updated.state, address)?
    };
    apply(engine, plan)
}
#[derive(Clone, Copy)]
pub(crate) struct WaitTarget {
    pub slot: u64,
    pub address: u64,
    pub terminated: bool,
}
pub(crate) fn wait_target(engine: &Unicorn<Trace>, address: u64) -> Result<Option<WaitTarget>> {
    let target = {
        let lives = engine.get_data().apis.thread_objects.model.borrow();
        let Some(lives) = lives.as_ref() else {
            return Ok(None);
        };
        if !lives.entries.contains_key(&address) {
            return Ok(None);
        }
        let target = lives.wait_target(objects(engine)?, address)?;
        WaitTarget {
            slot: target.slot,
            address,
            terminated: target.terminated,
        }
    };
    let expected = {
        let lives = engine.get_data().apis.thread_objects.model.borrow();
        lives.as_ref().unwrap().header(address)?
    };
    ensure!(
        read(engine, address, 8)? == expected,
        "Thread public dispatcher header diverges from scheduler lifetime"
    );
    Ok(Some(target))
}
pub(crate) fn current_thread(engine: &Unicorn<Trace>) -> Result<u64> {
    let address = crate::threads::thread_address(engine);
    let record = objects(engine)?.object(address)?;
    ensure!(
        record.kind == Kind::Thread,
        "Current thread pointer is not an owned scheduler identity"
    );
    Ok(address)
}
pub(crate) fn ordinary_stack_fields(
    engine: &Unicorn<Trace>,
    address: u64,
) -> Result<Option<emumee_core::kernel_thread_objects::StackFields>> {
    let lives = engine.get_data().apis.thread_objects.model.borrow();
    Ok(lives
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Thread stack lifetime model missing"))?
        .stack_fields(objects(engine)?, address)?)
}
fn guest_id(engine: &Unicorn<Trace>, address: u64) -> Result<u64> {
    let lives = engine.get_data().apis.thread_objects.model.borrow();
    Ok(lives
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Thread ID lifetime model missing"))?
        .guest_id(objects(engine)?, address)?)
}
pub(crate) fn current_tid(engine: &mut Unicorn<Trace>) -> Result<u64> {
    super::kernel_sync::observe_irql(engine)?;
    guest_id(engine, current_thread(engine)?)
}
pub(crate) fn guest_id_for_slot(engine: &Unicorn<Trace>, slot: u64) -> Result<u64> {
    let address =
        emumee_core::kernel_layout::KernelLayout::for_architecture(engine.get_data().architecture)
            .thread_object(slot)
            .ok_or_else(|| anyhow::anyhow!("Thread ID slot outside owned layout"))?;
    guest_id(engine, address)
}
pub(crate) fn by_handle(engine: &mut Unicorn<Trace>, args: &[u64]) -> Result<u64> {
    ensure!(
        args.len() == 6,
        "Thread reference-by-handle argument count mismatch"
    );
    ensure!(
        engine.get_data().apis.kernel.save().0 == 0,
        "ObReferenceObjectByHandle requires PASSIVE_LEVEL"
    );
    let handle = match crate::threads::lookup_reference_handle(engine, args[0])? {
        crate::threads::HandleLookup::Invalid => return Ok(0xc0000008),
        crate::threads::HandleLookup::Foreign => {
            bail!("Foreign process/file kernel handle reference profile is not modeled")
        }
        crate::threads::HandleLookup::Thread(handle) => handle,
    };
    ensure!(
        handle.owner == 4 && handle.kernel_only,
        "Thread handle has unsupported owner/access profile"
    );
    let owned = objects(engine)?;
    let record = owned.object(handle.object)?;
    ensure!(
        record.kind == Kind::Thread,
        "Scheduler handle object is not a live owned thread"
    );
    if args[2] != 0 && args[2] != owned.identity(Kind::Thread) {
        return Ok(0xc0000024);
    }
    ensure!(
        args[3] as u8 == 0,
        "UserMode thread handle security/access validation is not modeled"
    );
    ensure!(
        args[5] == 0,
        "Object handle-information output is not modeled"
    );
    // Legacy KernelMode behavior intentionally does not enforce DesiredAccess;
    // actual granted mask is retained in the sole authoritative handle map.
    let _configured_granted_access = handle.granted_access;
    let width = engine.get_data().architecture.width();
    require(engine, args[4], width as u64, P::WRITE)?;
    let event_count = objects(engine)?.events.len();
    let plan = objects(engine)?.plan(
        0,
        handle.object,
        Operation::ByPointer {
            object_type: args[2],
            mode: 0,
        },
    )?;
    // Full output preflight precedes the only write; ref commits only after a
    // successful native write. A partial write is fatal and cannot be resumed.
    engine.get_data_mut().apis.thread_objects.native_failure = true;
    engine.get_data_mut().apis.thread_objects.last_effect = Some(NativeEffect {
        object: handle.object,
        operation: "reference_by_handle_output",
    });
    crate::cpu::write(engine, args[4], &handle.object.to_le_bytes()[..width])?;
    let mut state = plan.state;
    // Preserve operation identity in the existing bounded reference journal.
    if state.events.len() > event_count {
        if let Some(event) = state.events.last_mut() {
            event.operation = "reference_by_handle";
        }
    }
    engine.get_data_mut().apis.objects.model = Some(state);
    engine.get_data_mut().apis.thread_objects.native_failure = false;
    Ok(0)
}

pub(crate) fn validate_owned_thread(engine: &Unicorn<Trace>, address: u64) -> Result<()> {
    ensure!(
        objects(engine)?.object(address)?.kind == Kind::Thread,
        "Processor current object is not a live owned Thread"
    );
    Ok(())
}
pub(crate) fn register_parked_processor(engine: &mut Unicorn<Trace>, processor: u32) -> Result<()> {
    let address = emumee_core::ipi::processor_layout(engine.get_data().architecture, processor)
        .and_then(|layout| layout.parked_thread)
        .ok_or_else(|| anyhow::anyhow!("Parked processor identity missing"))?;
    validate_quiescent(engine, address)?;
    let plan = {
        let lives = engine.get_data().apis.thread_objects.model.borrow();
        lives
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Initial caller identity missing"))?
            .register_parked_processor(objects(engine)?, processor)?
    };
    apply(engine, plan)?;
    validate_quiescent(engine, address)
}

pub(crate) fn validate_quiescent(engine: &Unicorn<Trace>, address: u64) -> Result<()> {
    let model = engine.get_data().apis.thread_objects.model.borrow();
    let Some(model) = model.as_ref() else {
        return Ok(());
    };
    if !model.entries.contains_key(&address) {
        return Ok(());
    }
    if let Some(field) = model.parked_pair_fields(objects(engine)?, address)? {
        ensure!(
            uc(engine.mem_read_as_vec(address + u64::from(field.offset), 8))? == field.bytes(),
            "Quiescent parked field mirror diverged; refusing repair"
        );
    }
    Ok(())
}

pub(crate) fn require_quiescent_callback_api(engine: &Unicorn<Trace>) -> Result<()> {
    if !engine.get_data().quiescent_parked_requested {
        return Ok(());
    }
    let Some(thread) = crate::ipi::current_thread(engine) else {
        return Ok(());
    };
    let model = engine.get_data().apis.thread_objects.model.borrow();
    let model = model
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Quiescent IPI identity missing"))?;
    let life = model
        .entries
        .get(&thread)
        .ok_or_else(|| anyhow::anyhow!("Quiescent IPI identity foreign"))?;
    ensure!(
        !matches!(
            life.role,
            emumee_core::kernel_thread_objects::Ownership::ParkedProcessor { .. }
        ),
        "Quiescent parked profile refuses remote IPI callback API effects"
    );
    Ok(())
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
        crate::api::kernel_objects::initialize(&mut engine).unwrap();
        let layout = emumee_core::kernel_layout::KernelLayout::for_architecture(architecture);
        uc(engine.mem_map(layout.driver_object, 3 * 4096, Prot::READ | Prot::WRITE)).unwrap();
        engine
            .get_data_mut()
            .apis
            .memory
            .map(
                layout.driver_object,
                3 * 4096,
                P::RW,
                Some(4),
                "owned initial boot reservations",
            )
            .unwrap();
        initialize_root(&mut engine).unwrap();
        crate::kernel_cpu::initialize(&mut engine).unwrap();
        // The before-page16-byte test explicitly enables the guest's declared
        // SSE support; no unsupported instruction or host CPU source is used.
        let cr4 = uc(engine.reg_read(RegisterX86::CR4)).unwrap();
        uc(engine.reg_write(RegisterX86::CR4, cr4 | 0x600)).unwrap();
        uc(engine.mem_map(0x100000, 8192, Prot::ALL)).unwrap();
        engine
            .get_data_mut()
            .apis
            .memory
            .map(
                0x100000,
                8192,
                P::ALL,
                None,
                "owned read-guard code and marker",
            )
            .unwrap();
        engine
    }
    fn probe(engine: &mut Unicorn<Trace>, address: u64, vector16: bool) -> Vec<u8> {
        let architecture = engine.get_data().architecture;
        let wide = architecture == Architecture::X64;
        let mut code = Vec::new();
        if wide {
            code.push(0x48);
        }
        code.push(0xb8);
        if wide {
            code.extend(address.to_le_bytes());
        } else {
            code.extend((address as u32).to_le_bytes());
        }
        if vector16 {
            code.extend([0xf3, 0x0f, 0x6f, 0]);
        } else if wide {
            code.extend([0x48, 0x8b, 0]);
        } else {
            code.extend([0xdd, 0]);
        }
        code.push(0xb8);
        code.extend(*b"DONE");
        code.push(0xa3);
        if wide {
            code.extend(0x101000u64.to_le_bytes());
        } else {
            code.extend(0x101000u32.to_le_bytes());
        }
        crate::cpu::write(engine, 0x100000, &code).unwrap();
        crate::cpu::write(engine, 0x101000, b"COLD").unwrap();
        code
    }
    fn parked_engine(enabled: bool) -> (crate::NativeEngine, u64) {
        let mut engine = engine(Architecture::X64);
        let address = emumee_core::ipi::processor_layout(Architecture::X64, 3)
            .unwrap()
            .parked_thread
            .unwrap();
        if enabled {
            let mut model = engine
                .get_data()
                .apis
                .thread_objects
                .model
                .borrow()
                .as_ref()
                .unwrap()
                .clone();
            if model
                .thread_fields(objects(&engine).unwrap(), current_thread(&engine).unwrap())
                .unwrap()
                .is_none()
            {
                model
                    .configure_system_process_26200(objects(&engine).unwrap())
                    .unwrap();
            }
            model
                .configure_quiescent_parked_26200(objects(&engine).unwrap())
                .unwrap();
            *engine.get_data().apis.thread_objects.model.borrow_mut() = Some(model);
            engine.get_data_mut().quiescent_parked_requested = true;
        }
        uc(engine.mem_map(address, 4096, Prot::READ | Prot::WRITE)).unwrap();
        engine
            .get_data_mut()
            .apis
            .memory
            .map(address, 4096, P::RW, Some(4), "owned test parked page")
            .unwrap();
        register_parked_processor(&mut engine, 3).unwrap();
        (engine, address)
    }
    #[test]
    fn quiescent_native_pair_is_opt_in_and_preserves_the_legacy_refusal() {
        for enabled in [false, true] {
            let (mut engine, address) = parked_engine(enabled);
            assert_eq!(engine.mem_read_as_vec(address + 0x5d8, 8).unwrap(), [0; 8]);
            let code = probe(&mut engine, address + 0x5d8, false);
            let _ = engine.emu_start(0x100000, 0x100000 + code.len() as u64, 0, 20);
            assert_eq!(
                engine.mem_read_as_vec(0x101000, 4).unwrap(),
                if enabled { b"DONE" } else { b"COLD" }
            );
            let evidence = report(&engine);
            assert_eq!(evidence.quiescent_parked_fields.len(), usize::from(enabled));
            if enabled {
                assert!(
                    evidence.quiescent_parked_fields[0]
                        .provenance
                        .contains("not captured memory")
                );
                assert!(evidence.private_accesses.is_empty());
                register_parked_processor(&mut engine, 3).unwrap();
            } else {
                assert_eq!(evidence.private_accesses.len(), 1);
            }
        }
    }
    #[test]
    fn quiescent_native_pair_keeps_adjacent_bytes_and_api_writes_private() {
        for offset in [0x5d7, 0x5d9, 0x5e0] {
            let (mut engine, address) = parked_engine(true);
            let code = probe(&mut engine, address + offset, false);
            let _ = engine.emu_start(0x100000, 0x100000 + code.len() as u64, 0, 20);
            assert_eq!(engine.mem_read_as_vec(0x101000, 4).unwrap(), b"COLD");
            assert!(!report(&engine).private_accesses.is_empty());
            assert!(require_api_access(&engine, address + 0x5d8, 8, P::WRITE).is_err());
            assert!(require_api_access(&engine, address + 0x5d8, 8, P::EXECUTE).is_err());
            assert!(crate::cpu::write(&mut engine, address + 0x5d8, &[1; 8]).is_err());
            assert_eq!(engine.mem_read_as_vec(address + 0x5d8, 8).unwrap(), [0; 8]);
        }
    }
    #[test]
    fn quiescent_native_pair_divergence_refuses_reuse_and_read_without_repair() {
        let (mut engine, address) = parked_engine(true);
        uc(engine.mem_write(address + 0x5d8, &[0x31; 8])).unwrap();
        assert!(
            register_parked_processor(&mut engine, 3)
                .unwrap_err()
                .to_string()
                .contains("refusing repair")
        );
        let code = probe(&mut engine, address + 0x5d8, false);
        let _ = engine.emu_start(0x100000, 0x100000 + code.len() as u64, 0, 20);
        assert_eq!(engine.mem_read_as_vec(0x101000, 4).unwrap(), b"COLD");
        assert!(
            engine
                .get_data()
                .apis
                .fault
                .as_deref()
                .unwrap()
                .contains("mirror diverged")
        );
        assert_eq!(
            engine.mem_read_as_vec(address + 0x5d8, 8).unwrap(),
            [0x31; 8]
        );
    }
    #[test]
    fn quiescent_remote_ipi_api_policy_refuses_before_model_effects() {
        let (mut engine, _) = parked_engine(true);
        let caller = current_thread(&engine).unwrap();
        let model = engine
            .get_data()
            .ipi
            .model
            .begin(0x100000, 0, 4, 0, caller, 0)
            .unwrap();
        engine.get_data_mut().ipi.model = model.clone().dispatch(0, 0).unwrap();
        assert!(require_quiescent_callback_api(&engine).is_ok());
        let mut remote = model;
        for processor in 0..3 {
            remote = remote
                .dispatch(processor, u64::from(processor))
                .unwrap()
                .return_member(processor, u64::from(processor) + 1, 0, remote.level())
                .unwrap();
        }
        engine.get_data_mut().ipi.model = remote.dispatch(3, 3).unwrap();
        assert!(
            require_quiescent_callback_api(&engine)
                .unwrap_err()
                .to_string()
                .contains("callback API effects")
        );
    }
    #[test]
    fn native_interval_reads_stop_before_any_successor_and_public_header_remains_readable() {
        for architecture in [Architecture::X86, Architecture::X64] {
            for (offset, vector16, denied) in
                [(0i64, false, false), (4, false, true), (-4, true, true)]
            {
                let mut engine = engine(architecture);
                let body = emumee_core::kernel_layout::KernelLayout::for_architecture(architecture)
                    .root_thread;
                let address = body.checked_add_signed(offset).unwrap();
                let code = probe(&mut engine, address, vector16);
                let _ = engine.emu_start(0x100000, 0x100000 + code.len() as u64, 0, 20);
                let marker = engine.mem_read_as_vec(0x101000, 4).unwrap();
                if denied {
                    assert_eq!(
                        marker, b"COLD",
                        "{architecture:?} offset{offset}: successor executed"
                    );
                    assert!(
                        engine
                            .get_data()
                            .apis
                            .fault
                            .as_deref()
                            .is_some_and(|error| error
                                .contains("private or released kernel thread body read"))
                    );
                    assert!(!report(&engine).private_accesses.is_empty());
                } else {
                    assert_eq!(marker, b"DONE");
                    assert_eq!(engine.get_data().apis.fault, None);
                }
                assert!(report(&engine).read_guard_checks > 0);
            }
        }
    }
    #[test]
    fn api_guard_checks_crossing_intervals_and_never_permits_header_writes() {
        for architecture in [Architecture::X86, Architecture::X64] {
            let mut engine = engine(architecture);
            let body = emumee_core::kernel_layout::KernelLayout::for_architecture(architecture)
                .root_thread;
            let before = engine.mem_read_as_vec(body, 8).unwrap();
            assert!(require_api_access(&engine, body, 8, P::READ).is_ok());
            assert!(require_api_access(&engine, body + 4, 8, P::READ).is_err());
            assert!(require_api_access(&engine, body - 4, 16, P::READ).is_err());
            assert!(crate::cpu::write(&mut engine, body, b"FAIL").is_err());
            assert_eq!(engine.mem_read_as_vec(body, 8).unwrap(), before);
            assert_eq!(current_thread(&engine).unwrap(), body);
        }
    }
    #[test]
    fn critical_mirror_rejects_native_divergence_instead_of_repairing_it() {
        let mut engine = engine(Architecture::X64);
        let address = emumee_core::kernel_layout::KernelLayout::for_architecture(Architecture::X64)
            .root_thread;
        if report(&engine).thread_fields.is_empty() {
            let mut lives = engine
                .get_data()
                .apis
                .thread_objects
                .model
                .borrow()
                .as_ref()
                .unwrap()
                .clone();
            lives
                .configure_system_process_26200(objects(&engine).unwrap())
                .unwrap();
            let plan = Plan {
                lifetimes: lives,
                objects: objects(&engine).unwrap().clone(),
                effects: Vec::new(),
            };
            fields::initialize(&mut engine, &plan, address).unwrap();
            *engine.get_data().apis.thread_objects.model.borrow_mut() = Some(plan.lifetimes);
        }
        engine.get_data_mut().apis.kernel.restore((0, 2));
        sync_critical(&mut engine, address).unwrap();
        assert_eq!(
            engine.mem_read_as_vec(address + 0x1e4, 2).unwrap(),
            0xfffeu16.to_le_bytes()
        );
        assert!(crate::cpu::write(&mut engine, address + 0x1e4, &[0, 0]).is_err());
        uc(engine.mem_write(address + 0x1e4, &[0x34, 0x12])).unwrap(); // Deliberate host-side corruption.
        let error = sync_critical(&mut engine, address).unwrap_err();
        assert!(error.to_string().contains("refusing repair"));
        assert_eq!(
            engine.mem_read_as_vec(address + 0x1e4, 2).unwrap(),
            [0x34, 0x12]
        );
        assert!(completion_error(&engine).is_some());
        assert_eq!(report(&engine).thread_fields[0].critical_depth, 2);
    }
}
