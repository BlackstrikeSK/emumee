//! Checked guest adapters for bug-check reason records and named callbacks.
//!
//! Fresh modeled kernels own the closed Callback directory and its finite
//! name/type registry. Other directories and general object-manager namespace
//! or security resolution remain outside this adapter.
//! No callback is ever executed by this adapter; active notifications stop.
use super::*;
use anyhow::Context;
use emumee_core::kernel_callbacks::{
    self as model, BugCheckPlan, BugCheckRequest, BugChecks, CreateRequest, NamedCallbacks,
    NamedPlan,
};
use std::cell::RefCell;

const PAGE: u64 = 4096;
#[derive(Clone, Copy)]
pub(super) enum Call {
    BugRegister,
    BugDeregister,
    Create,
    Register,
    Unregister,
    Notify,
}
/// Exact modeled routine names; provider publication must use these delegates.
pub(super) const ROUTINES: &[&str] = &[
    "KeRegisterBugCheckReasonCallback",
    "KeDeregisterBugCheckReasonCallback",
    "ExCreateCallback",
    "ExRegisterCallback",
    "ExUnregisterCallback",
    "ExNotifyCallback",
];
pub(super) fn definition(name: &str) -> Option<(Call, usize, T)> {
    Some(match name {
        "KeRegisterBugCheckReasonCallback" => (Call::BugRegister, 4, T::U32),
        "KeDeregisterBugCheckReasonCallback" => (Call::BugDeregister, 1, T::U32),
        "ExCreateCallback" => (Call::Create, 4, T::U32),
        "ExRegisterCallback" => (Call::Register, 3, T::Pointer),
        "ExUnregisterCallback" => (Call::Unregister, 1, T::Void),
        "ExNotifyCallback" => (Call::Notify, 3, T::Void),
        _ => return None,
    })
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
enum NamespaceAuthority {
    Unavailable,
    OwnedGeneratedFixtureDirectory,
    OwnedFreshKernelDirectory,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum DirectoryType {
    CallbackObject,
    Other(emumee_core::kernel_objects::Kind),
}
#[derive(Clone, Debug, Serialize)]
pub struct DirectoryEntry {
    pub name: String,
    pub object_type: DirectoryType,
}
#[derive(Clone, Debug, Serialize)]
pub struct CreateObservation {
    pub arguments: [u64; 4],
    pub name: Option<String>,
    pub name_truncated: bool,
    pub resolution: &'static str,
    pub result: Option<u32>,
    pub object: Option<u64>,
    pub error: Option<String>,
}
pub(crate) struct State {
    bugchecks: BugChecks,
    named: RefCell<NamedCallbacks>,
    namespace: NamespaceAuthority,
    directory: BTreeMap<String, DirectoryType>,
    suppress_default_namespace: bool,
    create_observations: Vec<CreateObservation>,
    create_observations_omitted: u64,
    head_initialized: bool,
    native_effect_failure: bool,
    lifecycle_errors: Vec<&'static str>,
    blocked_notifications: Vec<BlockedNotification>,
}
impl State {
    pub fn new(architecture: Architecture) -> Self {
        let head = if architecture == Architecture::X64 {
            0xffffc10000000000
        } else {
            0xc1000000
        };
        Self {
            bugchecks: BugChecks::new(architecture, head),
            named: RefCell::new(NamedCallbacks::new(architecture)),
            namespace: NamespaceAuthority::Unavailable,
            directory: BTreeMap::new(),
            suppress_default_namespace: false,
            create_observations: Vec::new(),
            create_observations_omitted: 0,
            head_initialized: false,
            native_effect_failure: false,
            lifecycle_errors: vec![],
            blocked_notifications: vec![],
        }
    }
    pub fn configure_owned_fixture_namespace(&mut self) -> Result<()> {
        self.configure_namespace(NamespaceAuthority::OwnedGeneratedFixtureDirectory)
    }
    fn configure_namespace(&mut self, authority: NamespaceAuthority) -> Result<()> {
        let named = self.named.borrow();
        ensure!(
            named.objects.is_empty() && named.registrations.is_empty() && named.pending.is_empty(),
            "Callback namespace authority cannot change after objects exist"
        );
        self.namespace = authority;
        self.directory = model::SYSTEM_NAMES
            .into_iter()
            .map(|name| (name.to_owned(), DirectoryType::CallbackObject))
            .collect();
        Ok(())
    }
    pub fn configure_owned_kernel_namespace(&mut self) -> Result<()> {
        if self.namespace == NamespaceAuthority::Unavailable && !self.suppress_default_namespace {
            self.configure_namespace(NamespaceAuthority::OwnedFreshKernelDirectory)?;
        }
        Ok(())
    }
    pub fn configure_unavailable_fixture_namespace(&mut self) -> Result<()> {
        ensure!(
            self.named.borrow().objects.is_empty() && self.directory.is_empty(),
            "Unavailable fixture namespace must be selected before objects exist"
        );
        self.suppress_default_namespace = true;
        self.namespace = NamespaceAuthority::Unavailable;
        Ok(())
    }
}
fn directory_leaf(name: &str) -> bool {
    name.get(..10)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(r"\Callback\"))
        && !name[10..].is_empty()
        && !name[10..].contains(['\\', '\0'])
}
fn insert_directory_entry(
    directory: &mut BTreeMap<String, DirectoryType>,
    name: &str,
    kind: DirectoryType,
) -> Result<()> {
    ensure!(
        directory_leaf(name) && name.encode_utf16().count() <= 16383,
        "Only bounded absolute Callback-directory leaf names are owned"
    );
    if let Some(old) = directory.get(name) {
        ensure!(
            *old == kind,
            "Owned callback namespace entry has a different type"
        );
    } else {
        ensure!(
            directory.len() < 259,
            "Owned callback directory entry limit exceeded"
        );
        directory.insert(name.to_owned(), kind);
    }
    Ok(())
}
#[derive(Clone, Debug, Serialize)]
pub struct BlockedNotification {
    pub object: u64,
    pub arguments: [u64; 2],
    pub registered: usize,
    pub dispatched: usize,
}
#[derive(Debug, Serialize)]
pub struct ObjectReport {
    pub address: u64,
    pub name: String,
    pub allow_multiple: bool,
    pub permanent: bool,
    pub system: bool,
    pub references: u64,
    pub live: bool,
    pub permissions: &'static str,
}
#[derive(Debug, Serialize)]
pub struct NamedReport {
    pub objects: Vec<ObjectReport>,
    pub registrations: Vec<model::Registration>,
    pub events: Vec<model::Event>,
    pub omitted_events: u64,
    pub api_denials: Vec<model::ApiDenial>,
    pub callbacks_executed: u64,
    pub pending_invocations: usize,
    pub create_requests: Vec<CreateObservation>,
    pub create_requests_omitted: u64,
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub bugcheck: BugChecks,
    pub named: NamedReport,
    namespace_authority: NamespaceAuthority,
    pub directory: Option<&'static str>,
    /// Bounded type catalog/reservations, including retired names; not a live
    /// object listing. Named object live/references fields own lifetime truth.
    pub directory_entries: Vec<DirectoryEntry>,
    pub owned_list_head_initialized: bool,
    pub native_effect_failure: bool,
    pub lifecycle_errors: Vec<&'static str>,
    pub blocked_notifications: Vec<BlockedNotification>,
    pub scope: &'static str,
}
pub(crate) fn report(engine: &Unicorn<Trace>) -> Report {
    let state = &engine.get_data().apis.callbacks;
    let named = state.named.borrow();
    Report {
        bugcheck: state.bugchecks.clone(),
        named: NamedReport {
            objects: named
                .objects
                .values()
                .map(|object| ObjectReport {
                    address: object.address,
                    name: object.name.clone(),
                    allow_multiple: object.allow_multiple,
                    permanent: object.permanent,
                    system: object.system,
                    references: object.references(),
                    live: object.live(),
                    permissions: "---",
                })
                .collect(),
            registrations: named.registrations.values().cloned().collect(),
            events: named.events.clone(),
            omitted_events: named.omitted_events,
            api_denials: named.api_denials.clone(),
            callbacks_executed: named.callbacks_executed,
            pending_invocations: named.pending.len(),
            create_requests: state.create_observations.clone(),
            create_requests_omitted: state.create_observations_omitted,
        },
        namespace_authority: state.namespace,
        directory: (state.namespace != NamespaceAuthority::Unavailable).then_some(r"\Callback"),
        directory_entries: state
            .directory
            .iter()
            .map(|(name, kind)| DirectoryEntry {
                name: name.clone(),
                object_type: *kind,
            })
            .collect(),
        owned_list_head_initialized: state.head_initialized,
        native_effect_failure: state.native_effect_failure,
        lifecycle_errors: state.lifecycle_errors.clone(),
        blocked_notifications: state.blocked_notifications.clone(),
        scope: "Bug-check reason bookkeeping and named callbacks in the guest's explicitly owned closed Callback directory. The finite directory_entries type catalog includes predefined reservations and retired names; named.objects live/references fields alone describe object lifetime. Only callback-object insertions are supported. No host namespace is consulted. Callback objects and registrations remain opaque; active notification dispatch, other object-manager directories/security and unrelated callback families remain unsupported.",
    }
}
pub(crate) fn completion_error(engine: &Unicorn<Trace>) -> Option<String> {
    let state = &engine.get_data().apis.callbacks;
    if state.native_effect_failure {
        return Some("Callback native effect failed".to_owned());
    }
    if let Some(error) = state.lifecycle_errors.first() {
        return Some((*error).to_owned());
    }
    if !state.named.borrow().pending.is_empty() {
        return Some(
            "Pending kernel callbacks require actual guest callback scheduling".to_owned(),
        );
    }
    None
}
fn ready(engine: &Unicorn<Trace>) -> Result<()> {
    ensure!(
        engine.get_data().apis.kernel_mode,
        "Kernel callbacks require a driver target"
    );
    ensure!(
        !engine.get_data().apis.callbacks.native_effect_failure,
        "Callback native effect failed; execution cannot resume"
    );
    Ok(())
}
fn failure<T>(engine: &mut Unicorn<Trace>, error: anyhow::Error) -> Result<T> {
    engine.get_data_mut().apis.callbacks.native_effect_failure = true;
    Err(error.context("Callback native effect failed; execution stopped"))
}
/// The short RefCell borrow permits the existing immutable guest-read validators
/// to record denial telemetry. Never retain it across a native write or callback.
fn require_access_kind(
    engine: &Unicorn<Trace>,
    address: u64,
    size: u64,
    access: &'static str,
) -> Result<()> {
    engine
        .get_data()
        .apis
        .callbacks
        .named
        .borrow_mut()
        .require_api_access(address, size, access)?;
    Ok(())
}
pub(crate) fn require_api_access(
    engine: &Unicorn<Trace>,
    address: u64,
    size: u64,
    permissions: P,
) -> Result<()> {
    if permissions == P::NONE {
        return Ok(());
    }
    let access = if permissions.contains(P::WRITE) {
        if permissions.contains(P::READ) {
            "read/write"
        } else {
            "write"
        }
    } else if permissions.contains(P::EXECUTE) {
        "execute"
    } else {
        "read"
    };
    require_access_kind(engine, address, size, access)
}
/// Parent calls this alongside catalog telemetry for native READ/WRITE/FETCH_PROT.
pub(crate) fn record_private_access(
    engine: &Unicorn<Trace>,
    address: u64,
    size: u64,
    access: &'static str,
) {
    let _ = require_access_kind(engine, address, size, access);
}
fn pointer(bytes: &[u8], offset: usize, width: usize) -> u64 {
    let mut raw = [0; 8];
    raw[..width].copy_from_slice(&bytes[offset..offset + width]);
    u64::from_le_bytes(raw)
}
fn initialize_head(engine: &mut Unicorn<Trace>) -> Result<()> {
    if engine.get_data().apis.callbacks.head_initialized {
        return Ok(());
    }
    let head = engine.get_data().apis.callbacks.bugchecks.head;
    let width = engine.get_data().architecture.width();
    let mut memory = engine.get_data().apis.memory.clone();
    memory
        .map(
            head,
            PAGE,
            P::RW,
            None,
            "owned bug-check callback list head",
        )
        .context("Defined bug-check list-head address is occupied")?;
    let mut links = vec![0; width * 2];
    links[..width].copy_from_slice(&head.to_le_bytes()[..width]);
    links[width..].copy_from_slice(&head.to_le_bytes()[..width]);
    let mut created = false;
    let effect = (|| -> Result<()> {
        uc(engine.mem_map(head, PAGE, Prot::READ | Prot::WRITE))?;
        created = true;
        crate::cpu::write(engine, head, &links)?;
        Ok(())
    })();
    if let Err(error) = effect {
        if created {
            let _ = engine.mem_unmap(head, PAGE);
        }
        return failure(engine, error);
    }
    engine.get_data_mut().apis.memory = memory;
    engine.get_data_mut().apis.callbacks.head_initialized = true;
    Ok(())
}
fn apply_bugcheck(engine: &mut Unicorn<Trace>, plan: BugCheckPlan) -> Result<u64> {
    for write in &plan.writes {
        if let Err(error) = crate::cpu::write(engine, write.address, &write.bytes) {
            return failure(engine, error);
        }
    }
    let state = &mut engine.get_data_mut().apis.callbacks;
    state.bugchecks = plan.state;
    if let Some(error) = plan.lifecycle_error {
        if state.lifecycle_errors.len() < 256 {
            state.lifecycle_errors.push(error);
        }
    }
    Ok(plan.result)
}
fn register_bugcheck(engine: &mut Unicorn<Trace>, args: &[u64]) -> Result<u64> {
    initialize_head(engine)?;
    let size = engine.get_data().apis.callbacks.bugchecks.record_size();
    // Legacy validates readable/writable record storage before BOOLEAN rejection.
    require_api_access(engine, args[0], size as u64, P::WRITE)?;
    require(engine, args[0], size as u64, P::RW)?;
    let record = read(engine, args[0], size as u64)?;
    let state = &engine.get_data().apis;
    let bugchecks = &state.callbacks.bugchecks;
    let needs_component = !bugchecks.registered.iter().any(|row| row.record == args[0])
        && record[bugchecks.state_offset()] == 0
        && (2..8).contains(&(args[2] as u32))
        && state.memory.allows(args[1], 1, P::EXECUTE);
    let mut component = Vec::new();
    if needs_component {
        for offset in 0..256 {
            let address = args[3]
                .checked_add(offset)
                .context("Bug-check component address overflow")?;
            let value = read(engine, address, 1)?[0];
            component.push(value);
            if value == 0 {
                break;
            }
        }
    }
    let state = &engine.get_data().apis;
    let plan = state.callbacks.bugchecks.register(
        &state.memory,
        BugCheckRequest {
            record: args[0],
            record_bytes: &record,
            routine: args[1],
            reason: args[2],
            component: args[3],
            component_bytes: &component,
        },
    )?;
    apply_bugcheck(engine, plan)
}
fn apply_named(engine: &mut Unicorn<Trace>, plan: NamedPlan) -> Result<u64> {
    let mut created = Vec::new();
    let effect = (|| -> Result<()> {
        for base in &plan.opaque_mappings {
            uc(engine.mem_map(*base, PAGE, Prot::NONE))?;
            created.push(*base);
        }
        for write in &plan.writes {
            crate::cpu::write(engine, write.address, &write.bytes)?;
        }
        Ok(())
    })();
    if let Err(error) = effect {
        for base in created.into_iter().rev() {
            let _ = engine.mem_unmap(base, PAGE);
        }
        return failure(engine, error);
    }
    ensure!(
        plan.invocations.is_empty(),
        "Actual guest callback scheduling is required before publishing notification success"
    );
    // No RefCell borrow survives a native operation above.
    *engine.get_data().apis.callbacks.named.borrow_mut() = plan.state;
    engine.get_data_mut().apis.memory = plan.memory;
    Ok(plan.result)
}
fn create_named(engine: &mut Unicorn<Trace>, args: &[u64]) -> Result<u64> {
    let mut observation = CreateObservation {
        arguments: [args[0], args[1], args[2], args[3]],
        name: None,
        name_truncated: false,
        resolution: "not_resolved",
        result: None,
        object: None,
        error: None,
    };
    if engine.get_data().apis.callbacks.namespace == NamespaceAuthority::Unavailable {
        observation.resolution = "unavailable";
    }
    let result = create_named_impl(engine, args, &mut observation);
    match &result {
        Ok(status) => observation.result = Some(*status as u32),
        Err(error) => observation.error = Some(format!("{error:#}").chars().take(512).collect()),
    }
    let state = &mut engine.get_data_mut().apis.callbacks;
    if state.create_observations.len() < 128 {
        state.create_observations.push(observation);
    } else {
        state.create_observations_omitted = state.create_observations_omitted.saturating_add(1);
    }
    result
}
fn create_named_impl(
    engine: &mut Unicorn<Trace>,
    args: &[u64],
    observation: &mut CreateObservation,
) -> Result<u64> {
    ensure!(
        engine.get_data().apis.callbacks.namespace != NamespaceAuthority::Unavailable,
        "Callback directory ownership/type resolution is unavailable for this target"
    );
    ensure!(
        engine.get_data().apis.kernel.save().0 <= 1,
        "Named callback operation above its supported IRQL"
    );
    let width = engine.get_data().architecture.width();
    require_api_access(engine, args[0], width as u64, P::WRITE)?;
    require(engine, args[0], width as u64, P::WRITE)?;
    let size = if width == 8 { 48 } else { 24 };
    let attributes = read(engine, args[1], size)?;
    let (root, name, flags, security, qos) = if width == 8 {
        (8, 16, 24, 32, 40)
    } else {
        (4, 8, 12, 16, 20)
    };
    let attributes_valid = u32::from_le_bytes(attributes[..4].try_into().unwrap()) == size as u32
        && pointer(&attributes, root, width) == 0
        && pointer(&attributes, security, width) == 0
        && pointer(&attributes, qos, width) == 0
        && u32::from_le_bytes(attributes[flags..flags + 4].try_into().unwrap())
            & !(0x10 | 0x40 | 0x80 | 0x200)
            == 0;
    let unicode_address = pointer(&attributes, name, width);
    let mut unicode = None;
    let mut text = None;
    // Preserve validation order: a bad OA/UNICODE length must not dereference a
    // later invalid guest pointer merely to return its documented status.
    if attributes_valid && unicode_address != 0 {
        let bytes = read(engine, unicode_address, if width == 8 { 16 } else { 8 })?;
        let length = u16::from_le_bytes(bytes[..2].try_into().unwrap());
        let maximum = u16::from_le_bytes(bytes[2..4].try_into().unwrap());
        if length != 0 && length % 2 == 0 && length <= maximum && length <= 32766 {
            let buffer = pointer(&bytes, if width == 8 { 8 } else { 4 }, width);
            text = Some(read(engine, buffer, u64::from(length))?);
        }
        unicode = Some(bytes);
    }
    let decoded_name = text.as_deref().and_then(|raw| {
        let units = raw
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>();
        String::from_utf16(&units).ok()
    });
    let flags = u32::from_le_bytes(attributes[flags..flags + 4].try_into().unwrap());
    let mut directory = engine.get_data().apis.callbacks.directory.clone();
    let foreign_type_collision = if let Some(name) = &decoded_name {
        observation.name_truncated = name.chars().count() > 256;
        observation.name = Some(name.chars().take(256).collect());
        if directory_leaf(name) {
            let entry = directory.iter().find(|(existing, _)| {
                model::callback_name_equal(existing, name, flags & 0x40 != 0)
            });
            match entry.map(|(_, kind)| *kind) {
                Some(DirectoryType::CallbackObject) => {
                    observation.resolution = "owned_callback_type";
                    false
                }
                Some(DirectoryType::Other(_)) => {
                    observation.resolution = "owned_foreign_type";
                    true
                }
                None => {
                    observation.resolution = "owned_directory_absent";
                    false
                }
            }
        } else {
            observation.resolution = "outside_owned_directory";
            false
        }
    } else {
        false
    };
    let plan = {
        let state = &engine.get_data().apis;
        let named = state.callbacks.named.borrow();
        // The closed directory registry supplies actual modeled type
        // provenance. No host or unowned namespace absence is inferred.
        named.create(
            &state.memory,
            CreateRequest {
                output: args[0],
                attributes_address: args[1],
                attributes: &attributes,
                unicode_string: unicode.as_deref(),
                name: text.as_deref(),
                create: args[2],
                allow_multiple: args[3],
                irql: state.kernel.save().0,
                foreign_type_collision,
            },
        )?
    };
    let mut published_object = None;
    if plan.result == 0 {
        let output = plan
            .writes
            .iter()
            .find(|write| write.address == args[0])
            .context("Successful callback creation has no output plan")?;
        let address = pointer(&output.bytes, 0, width);
        let object = plan
            .state
            .objects
            .get(&address)
            .context("Successful callback creation has no typed object")?;
        insert_directory_entry(&mut directory, &object.name, DirectoryType::CallbackObject)?;
        published_object = Some(address);
    }
    let result = apply_named(engine, plan)?;
    engine.get_data_mut().apis.callbacks.directory = directory;
    observation.object = published_object;
    Ok(result)
}
/// Returns false for an address outside this callback subsystem so the parent
/// object-manager dispatcher can continue its typed object lookup.
pub(crate) fn dereference(engine: &mut Unicorn<Trace>, address: u64) -> Result<bool> {
    if !engine
        .get_data()
        .apis
        .callbacks
        .named
        .borrow()
        .objects
        .contains_key(&address)
    {
        return Ok(false);
    }
    ready(engine)?;
    let plan = {
        let state = &engine.get_data().apis;
        state
            .callbacks
            .named
            .borrow()
            .dereference(&state.memory, address)?
    };
    apply_named(engine, plan)?;
    Ok(true)
}
pub(super) fn call(engine: &mut Unicorn<Trace>, call: Call, args: &[u64]) -> Result<u64> {
    ready(engine)?;
    let count = match call {
        Call::BugRegister | Call::Create => 4,
        Call::Register | Call::Notify => 3,
        _ => 1,
    };
    ensure!(args.len() == count, "Callback argument count mismatch");
    match call {
        Call::BugRegister => return register_bugcheck(engine, args),
        Call::BugDeregister => {
            initialize_head(engine)?;
            let state = &engine.get_data().apis;
            let plan = state
                .callbacks
                .bugchecks
                .deregister(&state.memory, args[0])?;
            return apply_bugcheck(engine, plan);
        }
        Call::Create => {
            crate::kernel_stack_writes::freeze_before_callback(engine);
            return create_named(engine, args);
        }
        _ => {}
    }
    let plan = {
        let state = &engine.get_data().apis;
        let named = state.callbacks.named.borrow();
        let irql = state.kernel.save().0;
        match call {
            Call::Register => named.register(&state.memory, args[0], args[1], args[2], irql)?,
            Call::Unregister => named.unregister(&state.memory, args[0], irql)?,
            Call::Notify => named.notify(&state.memory, args[0], [args[1], args[2]], irql)?,
            _ => unreachable!(),
        }
    };
    if !plan.invocations.is_empty() {
        // Preserve the baseline notify attempt without publishing dispatch
        // references/pending invocations for routines that never started.
        let count = plan.invocations.len();
        {
            let mut named = engine.get_data().apis.callbacks.named.borrow_mut();
            named.events = plan.state.events;
            named.omitted_events = plan.state.omitted_events;
        }
        let state = &mut engine.get_data_mut().apis.callbacks;
        if state.blocked_notifications.len() < 256 {
            state.blocked_notifications.push(BlockedNotification {
                object: args[0],
                arguments: [args[1], args[2]],
                registered: count,
                dispatched: 0,
            });
        }
        bail!(
            "ExNotifyCallback dispatch of registered guest routines is not modeled; actual guest callback scheduling is required"
        );
    }
    apply_named(engine, plan)
}
/// Captures only readable guest bug-check records, never opaque callback bodies.
pub(crate) fn capture(engine: &mut Unicorn<Trace>) {
    let (records, size) = {
        let state = &engine.get_data().apis.callbacks;
        (
            state
                .bugchecks
                .registered
                .iter()
                .map(|row| row.record)
                .collect::<Vec<_>>(),
            state.bugchecks.record_size(),
        )
    };
    for address in records {
        if engine.get_data().capture.is_some()
            && !engine.get_data().apis.memory.allows(
                address,
                size as u64,
                emumee_core::memory::Permissions::READ,
            )
        {
            crate::capture::aux_skipped(engine, size as u64);
            continue;
        }
        if !crate::capture::reserve_read(engine, size as u64) {
            continue;
        }
        if let Ok(bytes) = engine.mem_read_as_vec(address, size) {
            crate::capture::memory_record(
                engine,
                bytes,
                "kernel_bugcheck_record",
                &format!("memory:kernel_bugcheck_record:0x{address:x}"),
            );
        } else {
            crate::capture::aux_skipped(engine, size as u64);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn engine(architecture: Architecture) -> crate::NativeEngine {
        let mut engine = crate::new_engine(architecture).unwrap();
        engine.get_data_mut().apis.kernel_mode = true;
        engine
            .mem_map(0x1000, 0x5000, Prot::READ | Prot::WRITE)
            .unwrap();
        engine
            .get_data_mut()
            .apis
            .memory
            .map(0x1000, 0x5000, P::RW, None, "callback fixture data")
            .unwrap();
        engine
            .mem_map(0x8000, PAGE, Prot::READ | Prot::EXEC)
            .unwrap();
        engine
            .get_data_mut()
            .apis
            .memory
            .map(0x8000, PAGE, P::RX, None, "callback fixture code")
            .unwrap();
        engine.mem_write(0x8000, &[0x0f, 0x0b]).unwrap(); // Any invented execution would fault.
        engine
    }
    fn write_create(engine: &mut Unicorn<Trace>, name: &str, flags: u32) {
        let width = engine.get_data().architecture.width();
        let mut attributes = vec![0; if width == 8 { 48 } else { 24 }];
        let size = attributes.len() as u32;
        attributes[..4].copy_from_slice(&size.to_le_bytes());
        let name_offset = if width == 8 { 16 } else { 8 };
        attributes[name_offset..name_offset + width]
            .copy_from_slice(&0x2200u64.to_le_bytes()[..width]);
        let offset = if width == 8 { 24 } else { 12 };
        attributes[offset..offset + 4].copy_from_slice(&flags.to_le_bytes());
        let bytes = name
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        let mut unicode = vec![0; if width == 8 { 16 } else { 8 }];
        unicode[..2].copy_from_slice(&(bytes.len() as u16).to_le_bytes());
        unicode[2..4].copy_from_slice(&(bytes.len() as u16 + 2).to_le_bytes());
        let offset = if width == 8 { 8 } else { 4 };
        unicode[offset..offset + width].copy_from_slice(&0x2300u64.to_le_bytes()[..width]);
        engine.mem_write(0x2100, &attributes).unwrap();
        engine.mem_write(0x2200, &unicode).unwrap();
        engine.mem_write(0x2300, &bytes).unwrap();
    }
    #[test]
    fn bugcheck_registration_writes_real_guest_record_and_never_dispatches() {
        for architecture in [Architecture::X86, Architecture::X64] {
            let mut engine = engine(architecture);
            engine.mem_write(0x3000, b"EMU\0").unwrap();
            assert_eq!(
                call(&mut engine, Call::BugRegister, &[0x2000, 0x8000, 2, 0x3000]).unwrap(),
                1
            );
            let state = report(&engine);
            assert_eq!(state.bugcheck.callbacks_executed, 0);
            assert_eq!(state.bugcheck.registered.len(), 1);
            let width = architecture.width();
            let bytes = engine
                .mem_read_as_vec(0x2000, if width == 8 { 48 } else { 28 })
                .unwrap();
            assert_eq!(pointer(&bytes, width * 2, width), 0x8000);
            assert_eq!(bytes[width * 5 + 4], 1);
            assert_eq!(
                call(&mut engine, Call::BugRegister, &[0x2000, 0x8000, 2, 0]).unwrap(),
                0
            );
            assert_eq!(
                call(&mut engine, Call::BugDeregister, &[0x2000]).unwrap(),
                1
            );
            assert_eq!(
                call(&mut engine, Call::BugDeregister, &[0x2000]).unwrap(),
                0
            );
            assert_eq!(
                engine
                    .mem_read_as_vec(0x2000 + (width * 5 + 4) as u64, 1)
                    .unwrap(),
                [0]
            );
        }
    }
    #[test]
    fn unknown_namespace_stops_but_owned_fixture_objects_are_private_and_referenced() {
        for architecture in [Architecture::X86, Architecture::X64] {
            let mut engine = engine(architecture);
            write_create(&mut engine, r"\Callback\Fixture", 0x40);
            assert!(call(&mut engine, Call::Create, &[0x2000, 0x2100, 1, 0]).is_err());
            engine
                .get_data_mut()
                .apis
                .callbacks
                .configure_owned_fixture_namespace()
                .unwrap();
            assert_eq!(
                call(&mut engine, Call::Create, &[0x2000, 0x2100, 1, 0]).unwrap(),
                0
            );
            let width = architecture.width();
            let object = pointer(&engine.mem_read_as_vec(0x2000, width).unwrap(), 0, width);
            let regions = engine.mem_regions().unwrap();
            assert_eq!(
                regions
                    .iter()
                    .find(|region| region.begin == object)
                    .unwrap()
                    .perms,
                Prot::NONE.0 as u32
            );
            assert!(require_api_access(&engine, object, 1, P::READ).is_err());
            let token = call(&mut engine, Call::Register, &[object, 0x8000, 0x1234]).unwrap();
            assert_ne!(token, 0);
            assert!(dereference(&mut engine, object).unwrap());
            assert_eq!(report(&engine).named.objects[0].references, 1);
            call(&mut engine, Call::Unregister, &[token]).unwrap();
            let report = report(&engine);
            assert_eq!(report.named.objects[0].references, 0);
            assert!(!report.named.objects[0].live);
            assert_eq!(report.named.callbacks_executed, 0);
            assert_eq!(report.named.api_denials.len(), 1);
        }
    }
    #[test]
    fn active_notify_stops_without_pending_or_completed_guest_execution() {
        let mut engine = engine(Architecture::X64);
        engine
            .get_data_mut()
            .apis
            .callbacks
            .configure_owned_fixture_namespace()
            .unwrap();
        write_create(&mut engine, r"\Callback\Fixture", 0x40);
        call(&mut engine, Call::Create, &[0x2000, 0x2100, 1, 1]).unwrap();
        let object = pointer(&engine.mem_read_as_vec(0x2000, 8).unwrap(), 0, 8);
        call(&mut engine, Call::Notify, &[object, 1, 2]).unwrap();
        let token = call(&mut engine, Call::Register, &[object, 0x8000, 0x1234]).unwrap();
        assert!(call(&mut engine, Call::Notify, &[object, 0x1111, 0x2222]).is_err());
        let result = report(&engine);
        assert_eq!(result.named.callbacks_executed, 0);
        assert_eq!(result.named.pending_invocations, 0);
        assert_eq!(result.named.objects[0].references, 2);
        assert_eq!(result.blocked_notifications[0].dispatched, 0);
        assert_eq!(result.blocked_notifications[0].registered, 1);
        assert_eq!(engine.mem_read_as_vec(0x8000, 2).unwrap(), [0x0f, 0x0b]);
        call(&mut engine, Call::Unregister, &[token]).unwrap();
    }
    #[test]
    fn fresh_callback_directory_resolves_types_and_keeps_failures_without_outputs() {
        for architecture in [Architecture::X86, Architecture::X64] {
            let mut engine = engine(architecture);
            engine
                .get_data_mut()
                .apis
                .callbacks
                .configure_owned_kernel_namespace()
                .unwrap();
            let state = &mut engine.get_data_mut().apis.callbacks;
            insert_directory_entry(
                &mut state.directory,
                r"\Callback\Foreign",
                DirectoryType::Other(emumee_core::kernel_objects::Kind::Event),
            )
            .unwrap();
            write_create(&mut engine, r"\callback\foreign", 0x40);
            engine.mem_write(0x2000, &[0x5a; 8]).unwrap();
            assert_eq!(
                call(&mut engine, Call::Create, &[0x2000, 0x2100, 1, 0]).unwrap(),
                u64::from(model::STATUS_OBJECT_TYPE_MISMATCH)
            );
            assert_eq!(engine.mem_read_as_vec(0x2000, 8).unwrap(), [0x5a; 8]);
            let result = report(&engine);
            assert_eq!(
                result.namespace_authority,
                NamespaceAuthority::OwnedFreshKernelDirectory
            );
            assert!(result.named.objects.is_empty());
            assert_eq!(
                result.named.create_requests[0].resolution,
                "owned_foreign_type"
            );
            assert_eq!(result.named.create_requests[0].object, None);
            write_create(&mut engine, r"\Other\Unowned", 0x40);
            assert!(call(&mut engine, Call::Create, &[0x2000, 0x2100, 1, 0]).is_err());
            let result = report(&engine);
            assert!(result.named.objects.is_empty());
            assert_eq!(result.directory_entries.len(), 4);
            assert_eq!(
                result.named.create_requests[1].resolution,
                "outside_owned_directory"
            );
            assert!(result.named.create_requests[1].error.is_some());
        }
    }
    #[test]
    fn callback_explicit_unavailable_fixture_stays_unavailable_at_kernel_initialization() {
        let mut engine = engine(Architecture::X64);
        engine
            .get_data_mut()
            .apis
            .callbacks
            .configure_unavailable_fixture_namespace()
            .unwrap();
        engine
            .get_data_mut()
            .apis
            .target(Architecture::X64, true)
            .unwrap();
        write_create(&mut engine, r"\Callback\Fixture", 0x40);
        assert!(call(&mut engine, Call::Create, &[0x2000, 0x2100, 1, 0]).is_err());
        let result = report(&engine);
        assert_eq!(result.namespace_authority, NamespaceAuthority::Unavailable);
        assert!(result.directory_entries.is_empty());
        assert_eq!(result.named.create_requests[0].resolution, "unavailable");
    }
}
