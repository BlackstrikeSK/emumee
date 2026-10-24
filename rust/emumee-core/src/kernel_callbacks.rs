//! Guest bug-check reason records and named executive callback objects.
//!
//! Registering a callback never executes it. Named notifications with active
//! registrations return explicit invocation plans; only the engine scheduler
//! may complete them after actual guest execution and a validated guest return.
//! Crash dispatch, process/thread/image/object/registry callback families are
//! unsupported. No system event, bug check or callback return is synthesized.
use crate::{
    memory::{AddressSpace, Permissions as P},
    pe::Architecture,
};
use serde::Serialize;
use std::collections::BTreeMap;
use thiserror::Error;
use unicode_casefold::UnicodeCaseFold;

const LIMIT: usize = 256;
const PAGE: u64 = 4096;
pub const STATUS_INVALID_PARAMETER: u32 = 0xc000000d;
pub const STATUS_UNSUCCESSFUL: u32 = 0xc0000001;
pub const STATUS_OBJECT_NAME_INVALID: u32 = 0xc0000033;
pub const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xc0000034;
pub const STATUS_OBJECT_TYPE_MISMATCH: u32 = 0xc0000024;
pub const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xc000009a;
pub const SYSTEM_NAMES: [&str; 3] = [
    r"\Callback\SetSystemTime",
    r"\Callback\PowerState",
    r"\Callback\ProcessorAdd",
];
/// Shared object-name comparison for the closed modeled Callback directory.
pub fn callback_name_equal(left: &str, right: &str, insensitive: bool) -> bool {
    if insensitive {
        left.case_fold().eq(right.case_fold())
    } else {
        left == right
    }
}

#[derive(Debug, Error)]
#[error("Guest kernel callback: {0}")]
pub struct CallbackError(pub &'static str);
type Result<T> = std::result::Result<T, CallbackError>;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum CallbackKind {
    BugCheckReason,
    NamedExecutive,
    Process,
    Thread,
    Image,
    Object,
    Registry,
}
pub fn require_supported_kind(kind: CallbackKind) -> Result<()> {
    // Family registration support does not imply callback dispatch support.
    if !matches!(
        kind,
        CallbackKind::BugCheckReason | CallbackKind::NamedExecutive
    ) {
        return Err(CallbackError("this callback family is not modeled"));
    }
    Ok(())
}
#[derive(Clone, Debug)]
pub struct Write {
    pub address: u64,
    pub bytes: Vec<u8>,
}
fn require(memory: &AddressSpace, address: u64, size: u64, permission: P) -> Result<()> {
    if !memory.allows(address, size, permission) {
        return Err(CallbackError("guest range lacks required permissions"));
    }
    Ok(())
}
fn put_pointer(bytes: &mut [u8], offset: usize, value: u64, width: usize) {
    bytes[offset..offset + width].copy_from_slice(&value.to_le_bytes()[..width]);
}
fn pointer(bytes: &[u8], offset: usize, width: usize) -> u64 {
    let mut value = [0; 8];
    value[..width].copy_from_slice(&bytes[offset..offset + width]);
    u64::from_le_bytes(value)
}
fn irql(current: u8, maximum: u8) -> Result<()> {
    if current > maximum {
        return Err(CallbackError(
            "named callback operation above its supported IRQL",
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize)]
pub struct BugCheckRecord {
    pub record: u64,
    pub routine: u64,
    pub reason: u32,
    pub component: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct BugChecks {
    architecture: Architecture,
    pub head: u64,
    pub registered: Vec<BugCheckRecord>,
    pub callbacks_executed: u64,
}
pub struct BugCheckPlan {
    pub state: BugChecks,
    pub writes: Vec<Write>,
    pub result: u64,
    pub lifecycle_error: Option<&'static str>,
}
pub struct BugCheckRequest<'a> {
    pub record: u64,
    pub record_bytes: &'a [u8],
    pub routine: u64,
    pub reason: u64,
    pub component: u64,
    /// Bounded bytes through the first NUL (at most256), read by the adapter.
    pub component_bytes: &'a [u8],
}
impl BugChecks {
    pub fn new(architecture: Architecture, head: u64) -> Self {
        Self {
            architecture,
            head,
            registered: vec![],
            callbacks_executed: 0,
        }
    }
    pub fn record_size(&self) -> usize {
        if self.architecture == Architecture::X64 {
            48
        } else {
            28
        }
    }
    pub fn state_offset(&self) -> usize {
        self.architecture.width() * 5 + 4
    }
    fn plan(&self) -> BugCheckPlan {
        BugCheckPlan {
            state: self.clone(),
            writes: vec![],
            result: 0,
            lifecycle_error: None,
        }
    }
    fn links(&self, memory: &AddressSpace) -> Result<Vec<Write>> {
        let width = self.architecture.width();
        let nodes = std::iter::once(self.head)
            .chain(self.registered.iter().map(|r| r.record))
            .collect::<Vec<_>>();
        for address in &nodes {
            require(memory, *address, (width * 2) as u64, P::WRITE)?;
        }
        Ok(nodes
            .iter()
            .enumerate()
            .map(|(index, address)| {
                let mut bytes = vec![0; width * 2];
                put_pointer(&mut bytes, 0, nodes[(index + 1) % nodes.len()], width);
                put_pointer(
                    &mut bytes,
                    width,
                    nodes[(index + nodes.len() - 1) % nodes.len()],
                    width,
                );
                Write {
                    address: *address,
                    bytes,
                }
            })
            .collect())
    }
    pub fn register(
        &self,
        memory: &AddressSpace,
        request: BugCheckRequest<'_>,
    ) -> Result<BugCheckPlan> {
        let size = self.record_size();
        let width = self.architecture.width();
        require(memory, request.record, size as u64, P::RW)?;
        if request.record_bytes.len() != size {
            return Err(CallbackError("bug-check record byte length mismatch"));
        }
        let mut plan = self.plan();
        if self.registered.iter().any(|r| r.record == request.record)
            || request.record_bytes[self.state_offset()] != 0
        {
            return Ok(plan);
        }
        let record_end = request
            .record
            .checked_add(size as u64)
            .ok_or(CallbackError("bug-check record range overflow"))?;
        let head_end = self
            .head
            .checked_add((width * 2) as u64)
            .ok_or(CallbackError("bug-check list head overflow"))?;
        if request.record < head_end && self.head < record_end
            || self
                .registered
                .iter()
                .any(|row| request.record < row.record + size as u64 && row.record < record_end)
        {
            return Err(CallbackError(
                "overlapping bug-check records/list storage is not modeled",
            ));
        }
        let reason = request.reason as u32;
        if !(2..8).contains(&reason) || !memory.allows(request.routine, 1, P::EXECUTE) {
            return Ok(plan);
        }
        let Some(end) = request
            .component_bytes
            .iter()
            .take(256)
            .position(|byte| *byte == 0)
        else {
            if request.component_bytes.len() != 256 {
                return Err(CallbackError(
                    "incomplete bounded bug-check component snapshot",
                ));
            }
            require(memory, request.component, 256, P::READ)?;
            plan.lifecycle_error = Some("bug-check component exceeds the modeled255-byte limit");
            return Ok(plan);
        };
        require(memory, request.component, (end + 1) as u64, P::READ)?;
        if self.registered.len() >= LIMIT {
            plan.lifecycle_error = Some("bug-check callback registration limit exceeded");
            return Ok(plan);
        }
        let label = request.component_bytes[..end]
            .iter()
            .map(|byte| {
                if byte.is_ascii() {
                    char::from(*byte)
                } else {
                    '\u{fffd}'
                }
            })
            .collect();
        let mut bytes = request.record_bytes.to_vec();
        put_pointer(&mut bytes, width * 2, request.routine, width);
        put_pointer(&mut bytes, width * 3, request.component, width);
        bytes[width * 5..width * 5 + 4].copy_from_slice(&reason.to_le_bytes());
        bytes[self.state_offset()] = 1;
        plan.state.registered.push(BugCheckRecord {
            record: request.record,
            routine: request.routine,
            reason,
            component: label,
        });
        // Validate every link before exposing any record writes to the engine.
        let links = plan.state.links(memory)?;
        plan.writes.push(Write {
            address: request.record,
            bytes,
        });
        plan.writes.extend(links);
        plan.result = 1;
        Ok(plan)
    }
    pub fn deregister(&self, memory: &AddressSpace, record: u64) -> Result<BugCheckPlan> {
        require(memory, record, self.record_size() as u64, P::READ)?;
        let mut plan = self.plan();
        let Some(index) = self.registered.iter().position(|r| r.record == record) else {
            return Ok(plan);
        };
        require(memory, record, self.record_size() as u64, P::WRITE)?;
        plan.state.registered.remove(index);
        let links = plan.state.links(memory)?;
        plan.writes.push(Write {
            address: record + self.state_offset() as u64,
            bytes: vec![0],
        });
        plan.writes.extend(links);
        plan.result = 1;
        Ok(plan)
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Object {
    pub address: u64,
    pub name: String,
    pub allow_multiple: bool,
    pub permanent: bool,
    pub system: bool,
    caller_references: u32,
    registration_references: u32,
    dispatch_references: u32,
}
impl Object {
    pub fn references(&self) -> u64 {
        u64::from(self.caller_references)
            + u64::from(self.registration_references)
            + u64::from(self.dispatch_references)
            + u64::from(self.permanent)
    }
    pub fn live(&self) -> bool {
        self.references() != 0
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct Registration {
    pub token: u64,
    pub object: u64,
    pub routine: u64,
    pub context: u64,
    pub active: bool,
}
#[derive(Clone, Debug, Serialize)]
pub struct Invocation {
    pub id: u64,
    pub kind: CallbackKind,
    pub object: u64,
    pub registration: u64,
    pub routine: u64,
    pub arguments: [u64; 3],
    pub irql: u8,
}
#[derive(Clone, Debug, Serialize)]
pub struct Event {
    pub operation: &'static str,
    pub object: u64,
    pub token: Option<u64>,
    pub references_after: u64,
    pub registered: usize,
    pub dispatched: usize,
}
#[derive(Clone, Debug, Serialize)]
pub struct ApiDenial {
    pub kind: &'static str,
    pub offset: String,
    pub size: u64,
    pub access: &'static str,
}
#[derive(Clone, Debug, Serialize)]
pub struct NamedCallbacks {
    architecture: Architecture,
    pub objects: BTreeMap<u64, Object>,
    pub registrations: BTreeMap<u64, Registration>,
    pub pending: BTreeMap<u64, Invocation>,
    pub events: Vec<Event>,
    pub omitted_events: u64,
    pub api_denials: Vec<ApiDenial>,
    pub callbacks_executed: u64,
    next_address: u64,
    next_invocation: u64,
}
pub struct NamedPlan {
    pub state: NamedCallbacks,
    pub memory: AddressSpace,
    pub writes: Vec<Write>,
    /// Opaque PAGE-sized NONE mappings; parent must map these natively before commit.
    pub opaque_mappings: Vec<u64>,
    pub result: u64,
    /// Nonempty means the enclosing ExNotifyCallback has NOT completed yet.
    pub invocations: Vec<Invocation>,
}
pub struct CreateRequest<'a> {
    pub output: u64,
    pub attributes_address: u64,
    pub attributes: &'a [u8],
    pub unicode_string: Option<&'a [u8]>,
    pub name: Option<&'a [u8]>,
    pub create: u64,
    pub allow_multiple: u64,
    pub irql: u8,
    /// Object-manager adapter checks noncallback objects using the same lookup rule.
    pub foreign_type_collision: bool,
}
impl NamedCallbacks {
    pub fn new(architecture: Architecture) -> Self {
        Self {
            architecture,
            objects: BTreeMap::new(),
            registrations: BTreeMap::new(),
            pending: BTreeMap::new(),
            events: vec![],
            omitted_events: 0,
            api_denials: vec![],
            callbacks_executed: 0,
            next_address: if architecture == Architecture::X64 {
                0xffffc00000000000
            } else {
                0xc0000000
            },
            next_invocation: 1,
        }
    }
    fn plan(&self, memory: &AddressSpace) -> NamedPlan {
        NamedPlan {
            state: self.clone(),
            memory: memory.clone(),
            writes: vec![],
            opaque_mappings: vec![],
            result: 0,
            invocations: vec![],
        }
    }
    fn object(&self, address: u64) -> Result<&Object> {
        self.objects
            .get(&address)
            .filter(|object| object.live())
            .ok_or(CallbackError("requires a live CALLBACK_OBJECT"))
    }
    fn event(
        &mut self,
        operation: &'static str,
        object: u64,
        token: Option<u64>,
        registered: usize,
        dispatched: usize,
    ) {
        if self.events.len() >= LIMIT {
            self.omitted_events += 1;
            return;
        }
        let references_after = self.objects[&object].references();
        self.events.push(Event {
            operation,
            object,
            token,
            references_after,
            registered,
            dispatched,
        });
    }
    fn identity(&mut self, memory: &mut AddressSpace, tag: &str) -> Result<u64> {
        let mut base = self.next_address;
        for region in memory.regions() {
            let end = base
                .checked_add(PAGE)
                .ok_or(CallbackError("opaque callback address overflow"))?;
            if region.base >= end {
                break;
            }
            let stop = region
                .base
                .checked_add(region.size)
                .ok_or(CallbackError("opaque callback region overflow"))?;
            if stop > base {
                base = stop;
            }
        }
        let end = base
            .checked_add(PAGE)
            .ok_or(CallbackError("opaque callback address overflow"))?;
        if self.architecture == Architecture::X86 && end > 1u64 << 32 {
            return Err(CallbackError("opaque callback address space exhausted"));
        }
        memory
            .map(base, PAGE, P::NONE, None, tag)
            .map_err(|_| CallbackError("opaque callback map failed"))?;
        self.next_address = end;
        Ok(base)
    }
    pub fn create(&self, memory: &AddressSpace, request: CreateRequest<'_>) -> Result<NamedPlan> {
        irql(request.irql, 1)?;
        let width = self.architecture.width();
        let size = if width == 8 { 48 } else { 24 };
        require(memory, request.output, width as u64, P::WRITE)?;
        require(memory, request.attributes_address, size as u64, P::READ)?;
        if request.attributes.len() != size {
            return Err(CallbackError("OBJECT_ATTRIBUTES byte length mismatch"));
        }
        let mut plan = self.plan(memory);
        if u32::from_le_bytes(request.attributes[..4].try_into().unwrap()) != size as u32 {
            plan.result = STATUS_INVALID_PARAMETER.into();
            return Ok(plan);
        }
        let (root, name_offset, flags_offset, security, qos) = if width == 8 {
            (8, 16, 24, 32, 40)
        } else {
            (4, 8, 12, 16, 20)
        };
        if pointer(request.attributes, root, width) != 0
            || pointer(request.attributes, security, width) != 0
            || pointer(request.attributes, qos, width) != 0
        {
            return Err(CallbackError(
                "callback root handles and security descriptors are not modeled",
            ));
        }
        let flags = u32::from_le_bytes(
            request.attributes[flags_offset..flags_offset + 4]
                .try_into()
                .unwrap(),
        );
        if flags & !(0x10 | 0x40 | 0x80 | 0x200) != 0 {
            return Err(CallbackError("unsupported callback object attributes"));
        }
        let unicode_address = pointer(request.attributes, name_offset, width);
        if unicode_address == 0 {
            plan.result = STATUS_UNSUCCESSFUL.into();
            return Ok(plan);
        }
        let us_size = if width == 8 { 16 } else { 8 };
        require(memory, unicode_address, us_size as u64, P::READ)?;
        let unicode = request
            .unicode_string
            .filter(|bytes| bytes.len() == us_size)
            .ok_or(CallbackError("UNICODE_STRING byte length mismatch"))?;
        let length = u16::from_le_bytes(unicode[..2].try_into().unwrap()) as usize;
        let maximum = u16::from_le_bytes(unicode[2..4].try_into().unwrap()) as usize;
        if length % 2 != 0 || length > maximum || length > 32766 {
            plan.result = STATUS_INVALID_PARAMETER.into();
            return Ok(plan);
        }
        if length == 0 {
            plan.result = STATUS_UNSUCCESSFUL.into();
            return Ok(plan);
        }
        let name_address = pointer(unicode, if width == 8 { 8 } else { 4 }, width);
        require(memory, name_address, length as u64, P::READ)?;
        let raw = request
            .name
            .filter(|bytes| bytes.len() == length)
            .ok_or(CallbackError("callback name byte length mismatch"))?;
        let units = raw
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes(pair.try_into().unwrap()))
            .collect::<Vec<_>>();
        let Ok(name) = String::from_utf16(&units) else {
            plan.result = STATUS_OBJECT_NAME_INVALID.into();
            return Ok(plan);
        };
        if name.contains('\0') || !name.starts_with('\\') || name.ends_with('\\') {
            plan.result = STATUS_OBJECT_NAME_INVALID.into();
            return Ok(plan);
        }
        let Some(prefix) = name.get(..10) else {
            return Err(CallbackError(
                "only absolute Callback-directory names are modeled",
            ));
        };
        if prefix.case_fold().collect::<String>() != "\\callback\\" || name[10..].contains('\\') {
            return Err(CallbackError(
                "only absolute Callback-directory names are modeled",
            ));
        }
        if request.foreign_type_collision {
            plan.result = STATUS_OBJECT_TYPE_MISMATCH.into();
            return Ok(plan);
        }
        let equal = |other: &str| callback_name_equal(other, &name, flags & 0x40 != 0);
        let existing = self
            .objects
            .values()
            .find(|object| object.live() && equal(&object.name))
            .map(|object| object.address);
        let system_name = SYSTEM_NAMES.into_iter().find(|system| equal(system));
        let address = if let Some(address) = existing {
            let object = plan.state.objects.get_mut(&address).unwrap();
            object.caller_references = object
                .caller_references
                .checked_add(1)
                .ok_or(CallbackError("callback reference count overflow"))?;
            address
        } else {
            if system_name.is_none() && request.create as u8 == 0 {
                plan.result = STATUS_OBJECT_NAME_NOT_FOUND.into();
                return Ok(plan);
            }
            if self.objects.len() >= LIMIT {
                plan.result = STATUS_INSUFFICIENT_RESOURCES.into();
                return Ok(plan);
            }
            let address = plan
                .state
                .identity(&mut plan.memory, "private CALLBACK_OBJECT")?;
            plan.opaque_mappings.push(address);
            let system = system_name.is_some();
            plan.state.objects.insert(
                address,
                Object {
                    address,
                    name: system_name.map_or(name, str::to_owned),
                    allow_multiple: system || request.allow_multiple as u8 != 0,
                    permanent: system || flags & 0x10 != 0,
                    system,
                    caller_references: 1,
                    registration_references: 0,
                    dispatch_references: 0,
                },
            );
            address
        };
        plan.writes.push(Write {
            address: request.output,
            bytes: address.to_le_bytes()[..width].to_vec(),
        });
        plan.state.event(
            if existing.is_some() || system_name.is_some() {
                "open"
            } else {
                "create"
            },
            address,
            None,
            0,
            0,
        );
        Ok(plan)
    }
    pub fn register(
        &self,
        memory: &AddressSpace,
        address: u64,
        routine: u64,
        context: u64,
        current_irql: u8,
    ) -> Result<NamedPlan> {
        irql(current_irql, 1)?;
        let object = self.object(address)?;
        let mut plan = self.plan(memory);
        if !object.allow_multiple
            && self
                .registrations
                .values()
                .any(|r| r.active && r.object == address)
        {
            return Ok(plan);
        }
        if !memory.allows(routine, 1, P::EXECUTE) || self.registrations.len() >= LIMIT {
            return Ok(plan);
        }
        let context = if self.architecture == Architecture::X86 {
            context as u32 as u64
        } else {
            context
        };
        let token = plan
            .state
            .identity(&mut plan.memory, "private CALLBACK_REGISTRATION")?;
        plan.opaque_mappings.push(token);
        plan.state.registrations.insert(
            token,
            Registration {
                token,
                object: address,
                routine,
                context,
                active: true,
            },
        );
        plan.state
            .objects
            .get_mut(&address)
            .unwrap()
            .registration_references += 1;
        plan.state.event("register", address, Some(token), 0, 0);
        plan.result = token;
        Ok(plan)
    }
    pub fn unregister(
        &self,
        memory: &AddressSpace,
        token: u64,
        current_irql: u8,
    ) -> Result<NamedPlan> {
        irql(current_irql, 1)?;
        let row = self
            .registrations
            .get(&token)
            .filter(|row| row.active)
            .ok_or(CallbackError("invalid or inactive callback registration"))?;
        if self
            .pending
            .values()
            .any(|invocation| invocation.registration == token)
        {
            return Err(CallbackError(
                "unregister waiting for an active callback requires scheduling",
            ));
        }
        let mut plan = self.plan(memory);
        plan.state.registrations.get_mut(&token).unwrap().active = false;
        plan.state
            .objects
            .get_mut(&row.object)
            .unwrap()
            .registration_references -= 1;
        plan.state
            .event("unregister", row.object, Some(token), 0, 0);
        Ok(plan)
    }
    pub fn dereference(&self, memory: &AddressSpace, address: u64) -> Result<NamedPlan> {
        self.object(address)?;
        let mut plan = self.plan(memory);
        let object = plan.state.objects.get_mut(&address).unwrap();
        object.caller_references = object
            .caller_references
            .checked_sub(1)
            .ok_or(CallbackError(
                "caller cannot consume callback internal references",
            ))?;
        Ok(plan)
    }
    pub fn notify(
        &self,
        memory: &AddressSpace,
        address: u64,
        arguments: [u64; 2],
        current_irql: u8,
    ) -> Result<NamedPlan> {
        irql(current_irql, 2)?;
        let arguments = if self.architecture == Architecture::X86 {
            arguments.map(|value| value as u32 as u64)
        } else {
            arguments
        };
        let object = self.object(address)?;
        if object.system {
            return Err(CallbackError(
                "drivers must not notify system-defined callback objects",
            ));
        }
        if !self.pending.is_empty() {
            return Err(CallbackError(
                "nested/in-flight callback notifications require scheduling",
            ));
        }
        let active = self
            .registrations
            .values()
            .filter(|row| row.active && row.object == address)
            .cloned()
            .collect::<Vec<_>>();
        let mut plan = self.plan(memory);
        plan.state.event("notify", address, None, active.len(), 0);
        for row in active {
            // Revalidate the actual guest entry address immediately before a
            // dispatch plan; module unload/protection changes cannot become success.
            require(memory, row.routine, 1, P::EXECUTE)?;
            let id = plan.state.next_invocation;
            plan.state.next_invocation = id
                .checked_add(1)
                .ok_or(CallbackError("callback invocation counter overflow"))?;
            let invocation = Invocation {
                id,
                kind: CallbackKind::NamedExecutive,
                object: address,
                registration: row.token,
                routine: row.routine,
                arguments: [row.context, arguments[0], arguments[1]],
                irql: current_irql,
            };
            plan.state.pending.insert(id, invocation.clone());
            plan.invocations.push(invocation);
            plan.state
                .objects
                .get_mut(&address)
                .unwrap()
                .dispatch_references += 1;
        }
        Ok(plan)
    }
    /// Engine-only completion contract: call after an actual guest return to the
    /// scheduler's validated continuation, never merely after planning/registering.
    pub fn complete_invocation(&self, memory: &AddressSpace, id: u64) -> Result<NamedPlan> {
        let invocation = self
            .pending
            .get(&id)
            .ok_or(CallbackError("unknown or completed callback invocation"))?;
        let mut plan = self.plan(memory);
        plan.state.pending.remove(&id);
        plan.state
            .objects
            .get_mut(&invocation.object)
            .unwrap()
            .dispatch_references -= 1;
        plan.state.callbacks_executed = plan
            .state
            .callbacks_executed
            .checked_add(1)
            .ok_or(CallbackError("callback completion count overflow"))?;
        plan.state.event(
            "guest_return",
            invocation.object,
            Some(invocation.registration),
            0,
            1,
        );
        Ok(plan)
    }
    /// Fault/timeout/budget abort releases only the dispatch reference and never
    /// claims callback completion or a successful ExNotifyCallback return.
    pub fn abort_invocation(&self, memory: &AddressSpace, id: u64) -> Result<NamedPlan> {
        let invocation = self
            .pending
            .get(&id)
            .ok_or(CallbackError("unknown or completed callback invocation"))?;
        let mut plan = self.plan(memory);
        plan.state.pending.remove(&id);
        plan.state
            .objects
            .get_mut(&invocation.object)
            .unwrap()
            .dispatch_references -= 1;
        plan.state.event(
            "guest_abort",
            invocation.object,
            Some(invocation.registration),
            0,
            0,
        );
        Ok(plan)
    }
    pub fn require_api_access(
        &mut self,
        address: u64,
        size: u64,
        access: &'static str,
    ) -> Result<()> {
        if size == 0 {
            return Ok(());
        }
        let end = address
            .checked_add(size)
            .ok_or(CallbackError("callback API range overflow"))?;
        let private = self
            .objects
            .keys()
            .map(|base| (*base, "CALLBACK_OBJECT"))
            .chain(
                self.registrations
                    .keys()
                    .map(|base| (*base, "CALLBACK_REGISTRATION")),
            )
            .find(|(base, _)| address < *base + PAGE && *base < end);
        if let Some((base, kind)) = private {
            if self.api_denials.len() < 64 {
                let offset = if address < base {
                    format!("-0x{:x}", base - address)
                } else {
                    format!("0x{:x}", address - base)
                };
                self.api_denials.push(ApiDenial {
                    kind,
                    offset,
                    size,
                    access,
                });
            }
            return Err(CallbackError(
                "unmodeled private callback object/registration API access",
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn memory(architecture: Architecture) -> AddressSpace {
        let mut memory = AddressSpace::new(architecture);
        memory
            .map(0x1000, 0x5000, P::RW, None, "fixture data")
            .unwrap();
        memory
            .map(0x8000, PAGE, P::RX, None, "guest callback code")
            .unwrap();
        memory
    }
    fn input(architecture: Architecture, name: &str, flags: u32) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let width = architecture.width();
        let mut attributes = vec![0; if width == 8 { 48 } else { 24 }];
        let size = attributes.len() as u32;
        attributes[..4].copy_from_slice(&size.to_le_bytes());
        put_pointer(
            &mut attributes,
            if width == 8 { 16 } else { 8 },
            0x2200,
            width,
        );
        let flag_offset = if width == 8 { 24 } else { 12 };
        attributes[flag_offset..flag_offset + 4].copy_from_slice(&flags.to_le_bytes());
        let bytes = name
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        let mut unicode = vec![0; if width == 8 { 16 } else { 8 }];
        unicode[..2].copy_from_slice(&(bytes.len() as u16).to_le_bytes());
        unicode[2..4].copy_from_slice(&(bytes.len() as u16 + 2).to_le_bytes());
        put_pointer(&mut unicode, if width == 8 { 8 } else { 4 }, 0x2300, width);
        (attributes, unicode, bytes)
    }
    fn create(
        state: &NamedCallbacks,
        memory: &AddressSpace,
        name: &str,
        make: bool,
        multiple: bool,
        flags: u32,
    ) -> NamedPlan {
        let (attributes, unicode, bytes) = input(state.architecture, name, flags);
        state
            .create(
                memory,
                CreateRequest {
                    output: 0x2000,
                    attributes_address: 0x2100,
                    attributes: &attributes,
                    unicode_string: Some(&unicode),
                    name: Some(&bytes),
                    create: u64::from(make),
                    allow_multiple: u64::from(multiple),
                    irql: 0,
                    foreign_type_collision: false,
                },
            )
            .unwrap()
    }
    fn address(plan: &NamedPlan) -> u64 {
        pointer(&plan.writes[0].bytes, 0, plan.state.architecture.width())
    }

    #[test]
    fn bugcheck_boolean_record_layout_registration_and_deregistration_both_abis() {
        for architecture in [Architecture::X86, Architecture::X64] {
            let memory = memory(architecture);
            let initial = BugChecks::new(architecture, 0x5000);
            let bytes = vec![0; initial.record_size()];
            let request = || BugCheckRequest {
                record: 0x2000,
                record_bytes: &bytes,
                routine: 0x8000,
                reason: 2,
                component: 0x3000,
                component_bytes: b"EMU\0",
            };
            let plan = initial.register(&memory, request()).unwrap();
            assert_eq!(initial.registered.len(), 0);
            assert_eq!(plan.result, 1);
            assert_eq!(plan.state.callbacks_executed, 0);
            let width = architecture.width();
            let blob = &plan.writes[0].bytes;
            assert_eq!(pointer(blob, width * 2, width), 0x8000);
            assert_eq!(pointer(blob, width * 3, width), 0x3000);
            assert_eq!(&blob[width * 5..width * 5 + 4], &2u32.to_le_bytes());
            assert_eq!(blob[initial.state_offset()], 1);
            assert_eq!(plan.state.register(&memory, request()).unwrap().result, 0);
            let deregistered = plan.state.deregister(&memory, 0x2000).unwrap();
            assert_eq!(deregistered.result, 1);
            assert!(deregistered.state.registered.is_empty());
            assert_eq!(
                deregistered.writes[0].address,
                0x2000 + initial.state_offset() as u64
            );
            assert_eq!(deregistered.writes[0].bytes, [0]);
            assert_eq!(
                deregistered
                    .state
                    .deregister(&memory, 0x2000)
                    .unwrap()
                    .result,
                0
            );
        }
    }
    #[test]
    fn bugcheck_list_relinks_without_running_callbacks_or_freeing_record_storage() {
        for architecture in [Architecture::X86, Architecture::X64] {
            let memory = memory(architecture);
            let state = BugChecks::new(architecture, 0x5000);
            let bytes = vec![0; state.record_size()];
            let first = state
                .register(
                    &memory,
                    BugCheckRequest {
                        record: 0x2000,
                        record_bytes: &bytes,
                        routine: 0x8000,
                        reason: 2,
                        component: 0x3000,
                        component_bytes: b"ONE\0",
                    },
                )
                .unwrap();
            let second = first
                .state
                .register(
                    &memory,
                    BugCheckRequest {
                        record: 0x2040,
                        record_bytes: &bytes,
                        routine: 0x8001,
                        reason: 7,
                        component: 0x3000,
                        component_bytes: b"TWO\0",
                    },
                )
                .unwrap();
            let removed = second.state.deregister(&memory, 0x2000).unwrap();
            assert_eq!(removed.state.registered.len(), 1);
            assert_eq!(removed.state.registered[0].record, 0x2040);
            let link = removed
                .writes
                .iter()
                .find(|write| write.address == 0x2040)
                .unwrap();
            assert_eq!(pointer(&link.bytes, 0, architecture.width()), 0x5000);
            assert_eq!(
                pointer(&link.bytes, architecture.width(), architecture.width()),
                0x5000
            );
            assert!(memory.allows(0x2000, state.record_size() as u64, P::RW));
            assert_eq!(removed.state.callbacks_executed, 0);
        }
    }
    #[test]
    fn bugcheck_invalid_reason_routine_record_storage_and_component_limit() {
        let mut memory = memory(Architecture::X64);
        let state = BugChecks::new(Architecture::X64, 0x5000);
        let bytes = vec![0; state.record_size()];
        for reason in [0, 1, 8, u32::MAX as u64] {
            let plan = state
                .register(
                    &memory,
                    BugCheckRequest {
                        record: 0x2000,
                        record_bytes: &bytes,
                        routine: 0x8000,
                        reason,
                        component: 0x3000,
                        component_bytes: b"EMU\0",
                    },
                )
                .unwrap();
            assert_eq!(plan.result, 0);
            assert!(plan.writes.is_empty());
        }
        let denied = state
            .register(
                &memory,
                BugCheckRequest {
                    record: 0x2000,
                    record_bytes: &bytes,
                    routine: 0x3000,
                    reason: 2,
                    component: 0x3000,
                    component_bytes: b"EMU\0",
                },
            )
            .unwrap();
        assert_eq!(denied.result, 0);
        let limit = state
            .register(
                &memory,
                BugCheckRequest {
                    record: 0x2000,
                    record_bytes: &bytes,
                    routine: 0x8000,
                    reason: 2,
                    component: 0x3000,
                    component_bytes: &[b'A'; 256],
                },
            )
            .unwrap();
        assert_eq!(limit.result, 0);
        assert!(limit.lifecycle_error.is_some());
        assert!(limit.state.registered.is_empty());
        memory.protect(0x2000, PAGE, P::READ).unwrap();
        assert!(
            state
                .register(
                    &memory,
                    BugCheckRequest {
                        record: 0x2000,
                        record_bytes: &bytes,
                        routine: 0x8000,
                        reason: 2,
                        component: 0x3000,
                        component_bytes: b"EMU\0"
                    }
                )
                .is_err()
        );
    }
    #[test]
    fn named_create_open_unicode_case_and_system_namespace_lifetimes() {
        for architecture in [Architecture::X86, Architecture::X64] {
            let memory = memory(architecture);
            let state = NamedCallbacks::new(architecture);
            let created = create(&state, &memory, r"\Callback\Straße", true, false, 0x40);
            let object = address(&created);
            assert_eq!(created.result, 0);
            assert!(
                object
                    >= if architecture == Architecture::X64 {
                        0xffff000000000000
                    } else {
                        0x80000000
                    }
            );
            assert!(!created.memory.allows(object, 1, P::READ));
            assert!(!created.memory.allows(object, 1, P::WRITE));
            assert!(!created.memory.allows(object, 1, P::EXECUTE));
            let opened = create(
                &created.state,
                &created.memory,
                r"\CALLBACK\STRASSE",
                false,
                true,
                0x40,
            );
            assert_eq!(address(&opened), object);
            assert_eq!(opened.state.objects[&object].references(), 2);
            let missing = create(
                &created.state,
                &created.memory,
                r"\Callback\STRASSE",
                false,
                true,
                0,
            );
            assert_eq!(missing.result, u64::from(STATUS_OBJECT_NAME_NOT_FOUND));
            assert!(missing.writes.is_empty());
            for name in SYSTEM_NAMES {
                let system = create(&state, &memory, name, false, false, 0x40);
                let address = address(&system);
                let object = &system.state.objects[&address];
                assert!(object.system && object.permanent && object.allow_multiple);
                assert_eq!(object.references(), 2);
                assert!(
                    system
                        .state
                        .notify(&system.memory, address, [1, 2], 0)
                        .is_err()
                );
            }
        }
    }
    #[test]
    fn named_object_references_delete_temporary_names_but_keep_permanent_names() {
        for architecture in [Architecture::X86, Architecture::X64] {
            let memory = memory(architecture);
            let state = NamedCallbacks::new(architecture);
            let created = create(&state, &memory, r"\Callback\Temporary", true, false, 0x40);
            let object = address(&created);
            let dead = created.state.dereference(&created.memory, object).unwrap();
            assert!(!dead.state.objects[&object].live());
            assert_eq!(
                create(
                    &dead.state,
                    &dead.memory,
                    r"\Callback\Temporary",
                    false,
                    false,
                    0x40
                )
                .result,
                u64::from(STATUS_OBJECT_NAME_NOT_FOUND)
            );
            let fresh = create(
                &dead.state,
                &dead.memory,
                r"\Callback\Temporary",
                true,
                false,
                0x40,
            );
            assert_ne!(address(&fresh), object);
            let permanent = create(&state, &memory, r"\Callback\Permanent", true, false, 0x50);
            let address = address(&permanent);
            let retained = permanent
                .state
                .dereference(&permanent.memory, address)
                .unwrap();
            assert_eq!(retained.state.objects[&address].references(), 1);
            assert!(
                retained
                    .state
                    .dereference(&retained.memory, address)
                    .is_err()
            );
            let reopened = create(
                &retained.state,
                &retained.memory,
                r"\Callback\Permanent",
                false,
                false,
                0x40,
            );
            assert_eq!(
                address,
                pointer(&reopened.writes[0].bytes, 0, architecture.width())
            );
            assert_eq!(reopened.state.objects[&address].references(), 2);
        }
    }
    #[test]
    fn registration_multiple_rules_hold_object_references_and_stale_tokens_remain_private() {
        for architecture in [Architecture::X86, Architecture::X64] {
            let created = create(
                &NamedCallbacks::new(architecture),
                &memory(architecture),
                r"\Callback\Single",
                true,
                false,
                0x40,
            );
            let object = address(&created);
            let registered = created
                .state
                .register(&created.memory, object, 0x8000, 0x1234, 0)
                .unwrap();
            let token = registered.result;
            assert_ne!(token, 0);
            assert_eq!(registered.state.objects[&object].references(), 2);
            assert_eq!(registered.state.callbacks_executed, 0);
            assert!(registered.state.pending.is_empty());
            assert_eq!(
                registered
                    .state
                    .register(&registered.memory, object, 0x8000, 0, 0)
                    .unwrap()
                    .result,
                0
            );
            let caller_released = registered
                .state
                .dereference(&registered.memory, object)
                .unwrap();
            assert_eq!(caller_released.state.objects[&object].references(), 1);
            let mut unregistered = caller_released
                .state
                .unregister(&caller_released.memory, token, 0)
                .unwrap();
            assert_eq!(unregistered.state.objects[&object].references(), 0);
            assert!(
                unregistered
                    .state
                    .unregister(&unregistered.memory, token, 0)
                    .is_err()
            );
            assert!(
                unregistered
                    .state
                    .require_api_access(token, 1, "read")
                    .is_err()
            );
            assert_eq!(
                unregistered.state.api_denials[0].kind,
                "CALLBACK_REGISTRATION"
            );
            assert!(!unregistered.memory.allows(token, 1, P::READ));
            let created = create(
                &NamedCallbacks::new(architecture),
                &memory(architecture),
                r"\Callback\Multiple",
                true,
                true,
                0x40,
            );
            let object = address(&created);
            let first = created
                .state
                .register(&created.memory, object, 0x8000, 0, 0)
                .unwrap();
            let second = first
                .state
                .register(&first.memory, object, 0x8001, 0, 0)
                .unwrap();
            assert_ne!(first.result, second.result);
            assert_eq!(second.state.objects[&object].references(), 3);
        }
    }
    #[test]
    fn actual_invocation_plan_completion_abort_and_pending_unregister_contract() {
        for architecture in [Architecture::X86, Architecture::X64] {
            let created = create(
                &NamedCallbacks::new(architecture),
                &memory(architecture),
                r"\Callback\Dispatch",
                true,
                true,
                0x40,
            );
            let object = address(&created);
            let first = created
                .state
                .register(&created.memory, object, 0x8000, 0x1234, 0)
                .unwrap();
            let second = first
                .state
                .register(&first.memory, object, 0x8001, 0x5678, 0)
                .unwrap();
            let plan = second
                .state
                .notify(&second.memory, object, [0x1111, 0x2222], 2)
                .unwrap();
            assert_eq!(plan.invocations.len(), 2);
            assert_eq!(plan.state.callbacks_executed, 0);
            assert_eq!(plan.state.objects[&object].references(), 5);
            assert_eq!(plan.invocations[0].routine, 0x8000);
            assert_eq!(plan.invocations[0].arguments, [0x1234, 0x1111, 0x2222]);
            assert_eq!(plan.invocations[0].irql, 2);
            assert!(
                plan.state
                    .unregister(&plan.memory, first.result, 0)
                    .is_err()
            );
            assert!(plan.state.notify(&plan.memory, object, [0, 0], 0).is_err());
            let first_id = plan.invocations[0].id;
            let second_id = plan.invocations[1].id;
            let completed = plan
                .state
                .complete_invocation(&plan.memory, first_id)
                .unwrap();
            assert_eq!(completed.state.callbacks_executed, 1);
            assert!(
                completed
                    .state
                    .complete_invocation(&completed.memory, first_id)
                    .is_err()
            );
            let aborted = completed
                .state
                .abort_invocation(&completed.memory, second_id)
                .unwrap();
            assert_eq!(aborted.state.callbacks_executed, 1);
            assert!(aborted.state.pending.is_empty());
            assert_eq!(aborted.state.objects[&object].references(), 3);
            assert_eq!(
                aborted.state.events.last().unwrap().operation,
                "guest_abort"
            );
        }
    }
    #[test]
    fn invalid_structures_names_security_irql_and_foreign_types_do_not_write_success() {
        for architecture in [Architecture::X86, Architecture::X64] {
            let memory = memory(architecture);
            let state = NamedCallbacks::new(architecture);
            let (attributes, unicode, bytes) = input(architecture, r"\Callback\Valid", 0x40);
            for mode in 0..10 {
                let mut a = attributes.clone();
                let mut u = unicode.clone();
                let mut name = bytes.clone();
                let mut current_irql = 0;
                let mut collision = false;
                match mode {
                    0 => a[..4].copy_from_slice(&4u32.to_le_bytes()),
                    1 => u[..2].copy_from_slice(&3u16.to_le_bytes()),
                    2 => u[2..4].copy_from_slice(&2u16.to_le_bytes()),
                    3 => put_pointer(
                        &mut a,
                        if architecture == Architecture::X64 {
                            16
                        } else {
                            8
                        },
                        0,
                        architecture.width(),
                    ),
                    4 => name[..2].copy_from_slice(&0xd800u16.to_le_bytes()),
                    5 => name[..2].fill(0),
                    6 => put_pointer(
                        &mut a,
                        if architecture == Architecture::X64 {
                            8
                        } else {
                            4
                        },
                        1,
                        architecture.width(),
                    ),
                    7 => put_pointer(
                        &mut a,
                        if architecture == Architecture::X64 {
                            32
                        } else {
                            16
                        },
                        1,
                        architecture.width(),
                    ),
                    8 => current_irql = 2,
                    _ => collision = true,
                }
                let result = state.create(
                    &memory,
                    CreateRequest {
                        output: 0x2000,
                        attributes_address: 0x2100,
                        attributes: &a,
                        unicode_string: Some(&u),
                        name: Some(&name),
                        create: 1,
                        allow_multiple: 0,
                        irql: current_irql,
                        foreign_type_collision: collision,
                    },
                );
                if (6..9).contains(&mode) {
                    assert!(result.is_err());
                } else {
                    let rejected = result.unwrap();
                    assert_ne!(rejected.result, 0);
                    assert!(rejected.writes.is_empty());
                    assert!(rejected.state.objects.is_empty());
                }
            }
        }
    }
    #[test]
    fn named_irql_executable_revalidation_private_api_denials_and_empty_notify() {
        let architecture = Architecture::X64;
        let created = create(
            &NamedCallbacks::new(architecture),
            &memory(architecture),
            r"\Callback\Fixture",
            true,
            false,
            0x40,
        );
        let object = address(&created);
        assert!(
            created
                .state
                .register(&created.memory, object, 0x8000, 0, 2)
                .is_err()
        );
        assert_eq!(
            created
                .state
                .register(&created.memory, object, 0x2000, 0, 0)
                .unwrap()
                .result,
            0
        );
        assert!(
            created
                .state
                .notify(&created.memory, object, [0, 0], 3)
                .is_err()
        );
        let empty = created
            .state
            .notify(&created.memory, object, [0, 0], 2)
            .unwrap();
        assert!(empty.invocations.is_empty());
        assert_eq!(empty.state.callbacks_executed, 0);
        assert_eq!(empty.state.events.last().unwrap().registered, 0);
        let registered = created
            .state
            .register(&created.memory, object, 0x8000, 0, 0)
            .unwrap();
        assert!(
            registered
                .state
                .unregister(&registered.memory, registered.result, 2)
                .is_err()
        );
        let mut no_code = registered.memory.clone();
        no_code.protect(0x8000, PAGE, P::READ).unwrap();
        assert!(
            registered
                .state
                .notify(&no_code, object, [0, 0], 0)
                .is_err()
        );
        let mut state = registered.state;
        assert!(state.require_api_access(object - 1, 2, "write").is_err());
        assert_eq!(state.api_denials[0].offset, "-0x1");
        state.require_api_access(object, 0, "read").unwrap();
        assert!(state.require_api_access(u64::MAX, 2, "read").is_err());
        for _ in 0..100 {
            assert!(state.require_api_access(object, 1, "read").is_err());
        }
        assert_eq!(state.api_denials.len(), 64);
    }
    #[test]
    fn bounded_objects_tokens_events_and_unimplemented_callback_families() {
        for kind in [
            CallbackKind::Process,
            CallbackKind::Thread,
            CallbackKind::Image,
            CallbackKind::Object,
            CallbackKind::Registry,
        ] {
            assert!(require_supported_kind(kind).is_err());
        }
        require_supported_kind(CallbackKind::BugCheckReason).unwrap();
        require_supported_kind(CallbackKind::NamedExecutive).unwrap();
        let mut created = create(
            &NamedCallbacks::new(Architecture::X64),
            &memory(Architecture::X64),
            r"\Callback\Fixture",
            true,
            true,
            0x40,
        );
        let object = address(&created);
        let template = created.state.objects[&object].clone();
        let registered = created
            .state
            .register(&created.memory, object, 0x8000, 0, 0)
            .unwrap();
        let mut token_limit = registered.state;
        let registration = token_limit.registrations[&registered.result].clone();
        token_limit.registrations = (0..LIMIT as u64)
            .map(|token| {
                (
                    token,
                    Registration {
                        token,
                        ..registration.clone()
                    },
                )
            })
            .collect();
        let rejected = token_limit
            .register(&registered.memory, object, 0x8000, 0, 0)
            .unwrap();
        assert_eq!(rejected.result, 0);
        assert!(rejected.opaque_mappings.is_empty());
        for _ in 0..300 {
            created
                .state
                .event("test bounded event", object, None, 0, 0);
        }
        assert_eq!(created.state.events.len(), LIMIT);
        assert_eq!(created.state.omitted_events, 45);
        created.state.objects = (0..LIMIT as u64)
            .map(|index| {
                (
                    index,
                    Object {
                        address: index,
                        ..template.clone()
                    },
                )
            })
            .collect();
        let full = create(
            &created.state,
            &created.memory,
            r"\Callback\Another",
            true,
            false,
            0x40,
        );
        assert_eq!(full.result, u64::from(STATUS_INSUFFICIENT_RESOURCES));
        assert!(full.writes.is_empty());
    }
}
