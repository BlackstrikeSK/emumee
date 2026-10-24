//! Sole ModuleCatalog dynamic-image ownership; never executes a guest callback.
use super::*;
use crate::pe::{Kind, TlsCallbackPlan};
pub const MAX_DYNAMIC_LIVE: usize = 32;
pub const MAX_DYNAMIC_RAW: u64 = 64 * 1024 * 1024;
pub const MAX_DYNAMIC_IMAGE: u64 = 128 * 1024 * 1024;
pub const MAX_DYNAMIC_GENERATIONS: usize = 256;
const MAX_DYNAMIC_EVENTS: usize = 1024;
const MAX_DYNAMIC_ROUTINES: usize = 4096;
#[derive(Debug, Error)]
#[error("Guest dynamic loader: {reason} (Win32 {win32})")]
pub struct DynamicError {
    pub win32: u32,
    pub reason: &'static str,
}
type DynamicResult<T> = std::result::Result<T, DynamicError>;
fn fail(win32: u32, reason: &'static str) -> DynamicError {
    DynamicError { win32, reason }
}
impl From<ModuleError> for DynamicError {
    fn from(e: ModuleError) -> Self {
        fail(50, e.0)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DynamicPhase {
    Publishing,
    Mapped,
    Initializing,
    Ready,
    AttachRefused,
    Detaching,
    Interrupted,
}
#[derive(Clone, Debug, Serialize)]
pub struct DynamicImage {
    pub owner: u64,
    pub raw_bytes: u64,
    pub tls: TlsCallbackPlan,
    pub dependencies: Vec<ModuleId>,
    pub phase: DynamicPhase,
    pub attach_returns: usize,
    pub detach_returns: usize,
    pub attach_failed: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DynamicOperationKind {
    Load,
    Release,
    FailedLoad,
}
#[derive(Clone, Debug, Serialize)]
pub struct PendingDynamicRoutine {
    pub invocation: LoaderInvocation,
    pub started_instructions: u64,
}
#[derive(Clone, Debug, Serialize)]
pub struct DynamicOperation {
    pub id: u64,
    pub kind: DynamicOperationKind,
    pub root: ModuleId,
    pub modules: Vec<ModuleId>,
    pub cursor: usize,
    pub interrupted: bool,
    pub returning: bool,
    pub active_routine: Option<PendingDynamicRoutine>,
}
#[derive(Clone, Debug, Serialize)]
pub struct DynamicEvent {
    pub operation: Option<u64>,
    pub kind: &'static str,
    pub module: ModuleId,
    pub api_references: u32,
    pub instruction: u64,
    pub dependencies: Vec<ModuleId>,
}
#[derive(Clone, Debug, Serialize)]
pub struct DynamicRoutineEvent {
    pub operation: u64,
    pub invocation: LoaderInvocation,
    pub started_instructions: u64,
    pub stopped_instructions: Option<u64>,
    pub returned_value: Option<u64>,
    pub failure: Option<String>,
}
#[derive(Clone, Debug, Serialize)]
pub struct DynamicRetiredImage {
    pub id: ModuleId,
    pub name: String,
    pub base: u64,
    pub size: u64,
    pub load_order: u16,
    pub provenance: Option<ModuleProvenance>,
    pub image: DynamicImage,
    pub released_dependencies: Vec<ModuleId>,
}
#[derive(Clone, Debug, Serialize)]
pub struct DynamicState {
    pub owner: Option<u64>,
    pub active: Option<DynamicOperation>,
    next_operation: u64,
    pub events: Vec<DynamicEvent>,
    pub events_omitted: u64,
    pub routines: Vec<DynamicRoutineEvent>,
    pub routines_omitted: u64,
    pub retired: Vec<DynamicRetiredImage>,
}
impl Default for DynamicState {
    fn default() -> Self {
        Self {
            owner: None,
            active: None,
            next_operation: 1,
            events: Vec::new(),
            events_omitted: 0,
            routines: Vec::new(),
            routines_omitted: 0,
            retired: Vec::new(),
        }
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct ModuleReferences {
    pub id: ModuleId,
    pub api_references: u32,
    pub incoming_owners: Vec<ModuleId>,
    pub process_anchor: bool,
    pub pending_anchor: bool,
}
#[derive(Clone, Debug)]
pub struct DynamicDescriptor {
    pub owner: u64,
    pub accepted_sha256: String,
    pub raw_bytes: u64,
    pub tls: TlsCallbackPlan,
    pub dependencies: Vec<ModuleId>,
}
impl LoadedModule {
    pub fn dynamic_image(&self) -> Option<&DynamicImage> {
        self.dynamic.as_ref()
    }
    pub fn initializer_tls(&self) -> Option<&TlsCallbackPlan> {
        self.lifecycle
            .as_ref()
            .map(|l| &l.tls)
            .or_else(|| self.dynamic.as_ref().map(|l| &l.tls))
    }
    pub fn api_references(&self) -> u32 {
        self.api_references
    }
    pub fn loader_dependencies(&self) -> impl Iterator<Item = ModuleId> + '_ {
        self.lifecycle
            .iter()
            .flat_map(|l| l.dependencies.iter())
            .chain(self.dynamic.iter().flat_map(|l| l.dependencies.iter()))
            .chain(self.late_dependencies.iter())
            .copied()
    }
}
impl ModuleCatalog {
    pub fn dynamic_state(&self) -> &DynamicState {
        &self.dynamic_state
    }
    pub fn establish_user_loader(&mut self, owner: u64) -> DynamicResult<()> {
        if owner == 0
            || self.primary().is_none_or(|m| {
                m.image_kind == Kind::Driver
                    || m.provenance
                        .as_ref()
                        .is_none_or(|p| p.origin == ModuleOrigin::SyntheticProvider)
            })
            || self.dynamic_state.owner.is_some_and(|old| old != owner)
        {
            return Err(fail(
                50,
                "dynamic loader has no actual single user-process authority",
            ));
        }
        self.dynamic_state.owner = Some(owner);
        Ok(())
    }
    fn owner(&self, owner: u64) -> DynamicResult<()> {
        if self.dynamic_state.owner != Some(owner) {
            Err(fail(
                6,
                "DLL owner differs from the current modeled user process",
            ))
        } else {
            Ok(())
        }
    }
    fn available_operation(&self) -> DynamicResult<()> {
        if self.dynamic_state.active.is_some() {
            Err(fail(50, "nested or unfinished dynamic loader operation"))
        } else {
            Ok(())
        }
    }
    fn by_id_mut(&mut self, id: ModuleId) -> DynamicResult<&mut LoadedModule> {
        self.modules
            .values_mut()
            .find(|m| m.id == id)
            .ok_or_else(|| fail(6, "DLL identity is no longer mapped"))
    }
    pub fn loader_image_ready(&self, id: ModuleId) -> bool {
        self.by_identity(id).is_some_and(|m| self.resident(m))
    }
    fn resident(&self, m: &LoadedModule) -> bool {
        (self.primary == Some(m.id) && m.image_kind == Kind::Exe)
            || m.lifecycle
                .as_ref()
                .is_some_and(|l| l.phase == ImagePhase::Ready)
            || m.dynamic.as_ref().is_some_and(|l| {
                l.phase == DynamicPhase::Ready && Some(l.owner) == self.dynamic_state.owner
            })
    }
    pub fn references(&self, id: ModuleId) -> DynamicResult<ModuleReferences> {
        let m = self
            .by_identity(id)
            .ok_or_else(|| fail(6, "DLL identity is absent"))?;
        Ok(ModuleReferences {
            id,
            api_references: m.api_references,
            incoming_owners: self
                .modules
                .values()
                .filter(|owner| {
                    owner.id != id && owner.loader_dependencies().any(|target| target == id)
                })
                .map(|owner| owner.id)
                .collect(),
            process_anchor: self.primary == Some(id)
                || m.lifecycle.as_ref().is_some_and(|l| l.static_anchor),
            pending_anchor: m
                .dynamic
                .as_ref()
                .is_some_and(|l| l.phase != DynamicPhase::Ready),
        })
    }
    fn event(&mut self, kind: &'static str, id: ModuleId, instruction: u64) {
        let api_references = self.by_identity(id).map_or(0, |m| m.api_references);
        let dependencies = self
            .by_identity(id)
            .map_or_else(Vec::new, |m| m.loader_dependencies().collect());
        let operation = self.dynamic_state.active.as_ref().map(|op| op.id);
        if self.dynamic_state.events.len() < MAX_DYNAMIC_EVENTS {
            self.dynamic_state.events.push(DynamicEvent {
                operation,
                kind,
                module: id,
                api_references,
                instruction,
                dependencies,
            });
        } else {
            self.dynamic_state.events_omitted += 1;
        }
    }
    pub fn retain_dynamic_reference(
        &mut self,
        id: ModuleId,
        owner: u64,
        instruction: u64,
    ) -> DynamicResult<u64> {
        self.owner(owner)?;
        self.available_operation()?;
        let m = self
            .by_identity(id)
            .ok_or_else(|| fail(6, "DLL handle is absent"))?;
        if m.image_kind != Kind::Dll || !self.resident(m) {
            return Err(fail(
                50,
                "only an actually ready guest DLL can acquire a reference",
            ));
        }
        let refs = m
            .api_references
            .checked_add(1)
            .ok_or_else(|| fail(8, "DLL API reference count exhausted"))?;
        let base = m.base;
        self.by_id_mut(id)?.api_references = refs;
        self.event("api_reference_acquired", id, instruction);
        Ok(base)
    }
    fn check_dependencies(&self, owner: ModuleId, dependencies: &[ModuleId]) -> DynamicResult<()> {
        let mut unique = BTreeSet::new();
        for target in dependencies {
            let m = self
                .by_identity(*target)
                .ok_or_else(|| fail(126, "DLL dependency is no longer mapped"))?;
            if *target == owner || !unique.insert(*target) || !self.resident(m) {
                return Err(fail(
                    50,
                    "DLL dependency must be a distinct actually ready guest image",
                ));
            }
            let mut pending = vec![*target];
            let mut visited = BTreeSet::new();
            while let Some(next) = pending.pop() {
                if next == owner {
                    return Err(fail(50, "DLL reference-induced dependency cycle"));
                }
                if visited.insert(next) {
                    if visited.len() > 256 {
                        return Err(fail(50, "DLL dependency graph bound"));
                    }
                    if let Some(m) = self.by_identity(next) {
                        pending.extend(m.loader_dependencies());
                    }
                }
            }
        }
        Ok(())
    }
    /// Only actual installed IAT/followed-forwarder evidence may call this method.
    pub fn acquire_late_dependencies(
        &mut self,
        owner: ModuleId,
        targets: &[ModuleId],
        current_owner: u64,
        instruction: u64,
    ) -> DynamicResult<()> {
        self.owner(current_owner)?;
        self.available_operation()?;
        let m = self
            .by_identity(owner)
            .ok_or_else(|| fail(6, "forwarding DLL owner is absent"))?;
        if !self.resident(m) {
            return Err(fail(
                50,
                "forwarding owner is not an actually resident guest image",
            ));
        }
        let missing = targets
            .iter()
            .copied()
            .filter(|target| !m.loader_dependencies().any(|old| old == *target))
            .collect::<Vec<_>>();
        self.check_dependencies(owner, &missing)?;
        self.by_id_mut(owner)?.late_dependencies.extend(missing);
        self.event(
            "followed_forwarder_dependencies_acquired",
            owner,
            instruction,
        );
        Ok(())
    }
    fn start_operation(
        &mut self,
        kind: DynamicOperationKind,
        root: ModuleId,
        modules: Vec<ModuleId>,
    ) -> DynamicResult<u64> {
        self.available_operation()?;
        let id = self.dynamic_state.next_operation;
        let next = id
            .checked_add(1)
            .ok_or_else(|| fail(8, "dynamic operation identity exhausted"))?;
        self.dynamic_state.next_operation = next;
        self.dynamic_state.active = Some(DynamicOperation {
            id,
            kind,
            root,
            modules,
            cursor: 0,
            interrupted: false,
            returning: false,
            active_routine: None,
        });
        Ok(id)
    }
    /// Prepare on a clone before native mapping; publish only after known map success.
    pub fn publish_dynamic_image(
        &mut self,
        id: ModuleId,
        descriptor: DynamicDescriptor,
        instruction: u64,
    ) -> DynamicResult<u64> {
        self.owner(descriptor.owner)?;
        self.available_operation()?;
        let m = self
            .by_identity(id)
            .ok_or_else(|| fail(6, "new DLL catalog identity is absent"))?;
        let live = self
            .modules
            .values()
            .filter_map(|m| m.dynamic.as_ref())
            .collect::<Vec<_>>();
        if live.len() >= MAX_DYNAMIC_LIVE
            || live.len() + self.dynamic_state.retired.len() >= MAX_DYNAMIC_GENERATIONS
            || descriptor.raw_bytes == 0
            || descriptor.raw_bytes > 32 * 1024 * 1024
            || live
                .iter()
                .map(|l| l.raw_bytes)
                .sum::<u64>()
                .checked_add(descriptor.raw_bytes)
                .is_none_or(|n| n > MAX_DYNAMIC_RAW)
            || m.size > MAX_DYNAMIC_IMAGE
            || m.image_kind != Kind::Dll
            || m.lifecycle.is_some()
            || m.dynamic.is_some()
            || m.api_references != 0
            || self.primary == Some(id)
            || m.provenance.as_ref().is_none_or(|p| {
                p.accepted_image_sha256 != descriptor.accepted_sha256
                    || p.origin != ModuleOrigin::GuestFile
            })
        {
            return Err(fail(
                50,
                "new DLL descriptor/provenance/capacity is outside the bounded profile",
            ));
        }
        if descriptor.tls.architecture() != self.architecture
            || descriptor.tls.callback_rvas.len() > crate::pe::MAX_TLS_CALLBACKS
            || descriptor
                .tls
                .callback_rvas
                .iter()
                .any(|rva| *rva == 0 || *rva as u64 >= m.size)
            || descriptor
                .tls
                .mirror_checks(m.base)
                .map_err(|_| fail(193, "new DLL TLS pointer widths"))?
                .iter()
                .any(|c| c.rva as u64 + c.expected.len() as u64 > m.size)
        {
            return Err(fail(
                193,
                "new DLL TLS layout differs from actual image bounds",
            ));
        }
        self.check_dependencies(id, &descriptor.dependencies)?;
        // All fallible pure validation precedes publication.
        let operation = self.start_operation(DynamicOperationKind::Load, id, vec![id])?;
        self.by_id_mut(id)?.dynamic = Some(DynamicImage {
            owner: descriptor.owner,
            raw_bytes: descriptor.raw_bytes,
            tls: descriptor.tls,
            dependencies: descriptor.dependencies,
            phase: DynamicPhase::Publishing,
            attach_returns: 0,
            detach_returns: 0,
            attach_failed: false,
        });
        self.event("native_mapping_published", id, instruction);
        Ok(operation)
    }
    pub fn dynamic_mapped(&mut self, id: ModuleId, instruction: u64) -> DynamicResult<()> {
        self.expect_current(id, DynamicOperationKind::Load)?;
        let image = self
            .by_id_mut(id)?
            .dynamic
            .as_mut()
            .ok_or_else(|| fail(50, "new DLL dynamic state is absent"))?;
        if image.phase != DynamicPhase::Publishing {
            return Err(fail(50, "new DLL mapping publication order"));
        }
        image.phase = DynamicPhase::Mapped;
        self.event("mapped_bytes_and_protections_published", id, instruction);
        Ok(())
    }
    fn expect_current(&self, id: ModuleId, kind: DynamicOperationKind) -> DynamicResult<()> {
        let op = self
            .dynamic_state
            .active
            .as_ref()
            .ok_or_else(|| fail(50, "dynamic operation is absent"))?;
        if op.interrupted
            || op.returning
            || op.kind != kind
            || op.modules.get(op.cursor) != Some(&id)
        {
            return Err(fail(
                50,
                "dynamic module transition disagrees with actual pending operation",
            ));
        }
        Ok(())
    }
    pub fn dynamic_calls(
        &self,
        id: ModuleId,
        detach: bool,
    ) -> DynamicResult<Vec<LoaderInvocation>> {
        let m = self
            .by_identity(id)
            .ok_or_else(|| fail(6, "dynamic callback image is absent"))?;
        let image = m
            .dynamic
            .as_ref()
            .ok_or_else(|| fail(50, "module has no dynamic initialization authority"))?;
        let mut calls = Vec::new();
        for (i, rva) in image.tls.callback_rvas.iter().enumerate() {
            calls.push(LoaderInvocation {
                module: id,
                routine: if detach {
                    LoaderRoutine::TlsDetach
                } else {
                    LoaderRoutine::TlsAttach
                },
                callback_index: Some(i),
                address: m.base + *rva as u64,
                arguments: [m.base, u64::from(!detach), 0],
            });
        }
        if m.entry_rva != 0 {
            calls.push(LoaderInvocation {
                module: id,
                routine: if detach {
                    LoaderRoutine::DllDetach
                } else {
                    LoaderRoutine::DllAttach
                },
                callback_index: None,
                address: m.base + m.entry_rva as u64,
                arguments: [m.base, u64::from(!detach), 0],
            });
        }
        Ok(calls)
    }
    pub fn begin_dynamic_routine(
        &mut self,
        call: &LoaderInvocation,
        instruction: u64,
    ) -> DynamicResult<Option<usize>> {
        let op = self
            .dynamic_state
            .active
            .as_ref()
            .ok_or_else(|| fail(50, "dynamic routine has no active operation"))?;
        let detach = op.kind != DynamicOperationKind::Load;
        self.expect_current(call.module, op.kind)?;
        if op.active_routine.is_some() {
            return Err(fail(50, "previous dynamic initializer has not settled"));
        }
        let operation = op.id;
        let m = self
            .by_identity(call.module)
            .ok_or_else(|| fail(6, "dynamic routine module disappeared"))?;
        let image = m
            .dynamic
            .as_ref()
            .ok_or_else(|| fail(50, "dynamic routine state missing"))?;
        let index = if detach {
            image.detach_returns
        } else {
            image.attach_returns
        };
        let expected = self.dynamic_calls(call.module, detach)?;
        if detach
            && !matches!(
                image.phase,
                DynamicPhase::Detaching | DynamicPhase::AttachRefused
            )
            || !detach
                && !matches!(
                    image.phase,
                    DynamicPhase::Mapped | DynamicPhase::Initializing
                )
            || expected.get(index).is_none_or(|c| {
                c.address != call.address
                    || c.arguments != call.arguments
                    || c.routine != call.routine
                    || c.callback_index != call.callback_index
            })
            || self
                .dynamic_state
                .routines
                .last()
                .is_some_and(|e| e.stopped_instructions.is_none())
        {
            return Err(fail(
                50,
                "dynamic initializer call order differs from actual returns",
            ));
        }
        self.by_id_mut(call.module)?.dynamic.as_mut().unwrap().phase = if detach {
            DynamicPhase::Detaching
        } else {
            DynamicPhase::Initializing
        };
        self.dynamic_state.active.as_mut().unwrap().active_routine = Some(PendingDynamicRoutine {
            invocation: call.clone(),
            started_instructions: instruction,
        });
        if self.dynamic_state.routines.len() < MAX_DYNAMIC_ROUTINES {
            let index = self.dynamic_state.routines.len();
            self.dynamic_state.routines.push(DynamicRoutineEvent {
                operation,
                invocation: call.clone(),
                started_instructions: instruction,
                stopped_instructions: None,
                returned_value: None,
                failure: None,
            });
            Ok(Some(index))
        } else {
            self.dynamic_state.routines_omitted += 1;
            Ok(None)
        }
    }
    pub fn settle_dynamic_routine(
        &mut self,
        call: &LoaderInvocation,
        event: Option<usize>,
        instruction: u64,
        value: Option<u64>,
        failure: Option<String>,
    ) -> DynamicResult<()> {
        let kind = self
            .dynamic_state
            .active
            .as_ref()
            .ok_or_else(|| fail(50, "dynamic return has no operation"))?
            .kind;
        self.expect_current(call.module, kind)?;
        let pending = self
            .dynamic_state
            .active
            .as_ref()
            .unwrap()
            .active_routine
            .as_ref()
            .ok_or_else(|| fail(50, "dynamic return has no actual pending initializer"))?;
        if pending.invocation.module != call.module
            || pending.invocation.address != call.address
            || pending.invocation.arguments != call.arguments
            || pending.invocation.routine != call.routine
            || pending.invocation.callback_index != call.callback_index
            || instruction < pending.started_instructions
        {
            return Err(fail(
                50,
                "dynamic return differs from actual pending invocation",
            ));
        }
        if value.is_some() == failure.is_some() {
            return Err(fail(
                50,
                "dynamic return cannot also be an execution failure",
            ));
        }
        if let Some(index) = event {
            if index + 1 != self.dynamic_state.routines.len() {
                return Err(fail(50, "dynamic return observation is out of order"));
            }
            let event = &mut self.dynamic_state.routines[index];
            if event.stopped_instructions.is_some() || instruction < event.started_instructions {
                return Err(fail(50, "dynamic return count is inconsistent"));
            }
            event.stopped_instructions = Some(instruction);
            event.returned_value = value;
            event.failure = failure;
        }
        self.dynamic_state.active.as_mut().unwrap().active_routine = None;
        let image = self.by_id_mut(call.module)?.dynamic.as_mut().unwrap();
        if value.is_none() {
            image.phase = DynamicPhase::Interrupted;
            self.dynamic_state.active.as_mut().unwrap().interrupted = true;
        } else {
            if kind == DynamicOperationKind::Load {
                image.attach_returns += 1;
            } else {
                image.detach_returns += 1;
            }
            if call.routine == LoaderRoutine::DllAttach && value.is_some_and(|v| v as u32 == 0) {
                image.attach_failed = true;
                image.phase = DynamicPhase::AttachRefused;
            }
        }
        Ok(())
    }
    pub fn dynamic_ready(&mut self, id: ModuleId, instruction: u64) -> DynamicResult<u64> {
        self.expect_current(id, DynamicOperationKind::Load)?;
        let expected = self.dynamic_calls(id, false)?.len();
        let m = self.by_id_mut(id)?;
        let image = m.dynamic.as_mut().unwrap();
        if image.attach_failed
            || image.attach_returns != expected
            || !matches!(
                image.phase,
                DynamicPhase::Mapped | DynamicPhase::Initializing
            )
        {
            return Err(fail(
                50,
                "dynamic DLL cannot publish successful initialization",
            ));
        }
        image.phase = DynamicPhase::Ready;
        m.api_references = 1;
        let base = m.base;
        self.dynamic_state.active.as_mut().unwrap().returning = true;
        self.event("actual_initialized_reference_acquired", id, instruction);
        Ok(base)
    }
    fn eligible(&self, id: ModuleId) -> bool {
        let Some(m) = self.by_identity(id) else {
            return false;
        };
        let Ok(refs) = self.references(id) else {
            return false;
        };
        m.dynamic
            .as_ref()
            .is_some_and(|image| image.phase == DynamicPhase::Ready)
            && refs.api_references == 0
            && refs.incoming_owners.is_empty()
            && !refs.process_anchor
    }
    fn release_queue(&self, root: ModuleId) -> DynamicResult<Vec<ModuleId>> {
        fn collect(
            c: &mut ModuleCatalog,
            id: ModuleId,
            queue: &mut Vec<ModuleId>,
        ) -> DynamicResult<()> {
            if !c.eligible(id) {
                return Ok(());
            }
            if queue.len() >= MAX_DYNAMIC_LIVE {
                return Err(fail(50, "dynamic cascade count bound"));
            }
            let m = c.by_identity(id).unwrap();
            let name = m.name.clone();
            let dependencies = m.loader_dependencies().collect::<Vec<_>>();
            queue.push(id);
            c.modules.remove(&name);
            for target in dependencies.into_iter().rev() {
                collect(c, target, queue)?;
            }
            Ok(())
        }
        let mut candidate = self.clone();
        let mut queue = Vec::new();
        collect(&mut candidate, root, &mut queue)?;
        Ok(queue)
    }
    pub fn release_dynamic_reference(
        &mut self,
        id: ModuleId,
        owner: u64,
        instruction: u64,
    ) -> DynamicResult<bool> {
        self.owner(owner)?;
        self.available_operation()?;
        let m = self
            .by_identity(id)
            .ok_or_else(|| fail(6, "DLL handle is absent"))?;
        if m.image_kind != Kind::Dll || !self.resident(m) {
            return Err(fail(50, "release requires an actually ready guest DLL"));
        }
        if m.api_references == 0 {
            return Err(fail(
                if m.lifecycle.is_some() { 50 } else { 6 },
                "DLL has no acquired API reference; initial static-anchor release is outside this profile",
            ));
        }
        let mut candidate = self.clone();
        candidate.by_id_mut(id)?.api_references -= 1;
        let queue = candidate.release_queue(id)?;
        if !queue.is_empty() {
            candidate.start_operation(DynamicOperationKind::Release, id, queue)?;
            candidate.by_id_mut(id)?.dynamic.as_mut().unwrap().phase = DynamicPhase::Detaching;
        }
        candidate.event("api_reference_released", id, instruction);
        *self = candidate;
        Ok(self.dynamic_state.active.is_some())
    }
    pub fn fail_dynamic_attach(&mut self, id: ModuleId, instruction: u64) -> DynamicResult<()> {
        self.expect_current(id, DynamicOperationKind::Load)?;
        let m = self.by_identity(id).unwrap();
        let image = m.dynamic.as_ref().unwrap();
        if !image.attach_failed
            || image.phase != DynamicPhase::AttachRefused
            || m.api_references != 0
        {
            return Err(fail(
                50,
                "failed-load cleanup needs an actual DllMain FALSE",
            ));
        }
        let op = self.dynamic_state.active.as_mut().unwrap();
        op.kind = DynamicOperationKind::FailedLoad;
        op.modules = vec![id];
        op.cursor = 0;
        self.event("actual_attach_false_cleanup_started", id, instruction);
        Ok(())
    }
    /// Preflight on a clone, then commit only after native unmap known-success.
    pub fn retire_dynamic_image(&mut self, id: ModuleId, instruction: u64) -> DynamicResult<()> {
        let kind = self
            .dynamic_state
            .active
            .as_ref()
            .ok_or_else(|| fail(50, "dynamic retirement has no operation"))?
            .kind;
        if kind == DynamicOperationKind::Load {
            return Err(fail(50, "successful pending load cannot retire"));
        }
        self.expect_current(id, kind)?;
        let m = self
            .by_identity(id)
            .ok_or_else(|| fail(6, "dynamic retirement module missing"))?;
        let image = m.dynamic.as_ref().unwrap();
        let refs = self.references(id)?;
        if !matches!(
            image.phase,
            DynamicPhase::Detaching | DynamicPhase::AttachRefused
        ) || image.detach_returns != self.dynamic_calls(id, true)?.len()
            || refs.api_references != 0
            || !refs.incoming_owners.is_empty()
            || refs.process_anchor
        {
            return Err(fail(
                50,
                "dynamic retirement precedes real detach or remaining ownership",
            ));
        }
        let next = self
            .dynamic_state
            .active
            .as_ref()
            .unwrap()
            .modules
            .get(self.dynamic_state.active.as_ref().unwrap().cursor + 1)
            .copied();
        if let Some(next) = next {
            let target = self
                .by_identity(next)
                .ok_or_else(|| fail(50, "next dynamic retirement target disappeared"))?;
            let refs = self.references(next)?;
            if target
                .dynamic
                .as_ref()
                .is_none_or(|image| image.phase != DynamicPhase::Ready)
                || refs.api_references != 0
                || refs.process_anchor
                || refs.incoming_owners.iter().any(|owner| *owner != id)
            {
                return Err(fail(
                    50,
                    "actual released dependency refs disagree with preflight cascade",
                ));
            }
        }
        let name = m.name.clone();
        let released_dependencies = m.loader_dependencies().collect();
        let m = self.modules.remove(&name).unwrap();
        self.export_count -= m.exports.len();
        self.dynamic_state.retired.push(DynamicRetiredImage {
            id,
            name: m.name,
            base: m.base,
            size: m.size,
            load_order: m.load_order,
            provenance: m.provenance,
            image: m.dynamic.unwrap(),
            released_dependencies,
        });
        {
            let op = self.dynamic_state.active.as_mut().unwrap();
            op.cursor += 1;
            op.returning = next.is_none();
        }
        if let Some(next) = next {
            // Identity and state were checked before removing the actual owner.
            self.modules
                .values_mut()
                .find(|m| m.id == next)
                .unwrap()
                .dynamic
                .as_mut()
                .unwrap()
                .phase = DynamicPhase::Detaching;
        }
        self.event("actual_native_unmap_retired", id, instruction);
        Ok(())
    }
    pub fn finish_dynamic_operation(
        &mut self,
        operation: u64,
        instruction: u64,
    ) -> DynamicResult<()> {
        let op = self
            .dynamic_state
            .active
            .as_ref()
            .ok_or_else(|| fail(50, "dynamic completion has no active operation"))?;
        if op.id != operation || !op.returning || op.interrupted {
            return Err(fail(
                50,
                "dynamic API cannot complete an unfinished native operation",
            ));
        }
        let root = op.root;
        self.event("caller_api_result_published", root, instruction);
        self.dynamic_state.active = None;
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn root(arch: Architecture) -> ModuleCatalog {
        let (bytes, _) =
            crate::fixtures::native_loader_probe(arch, crate::fixtures::LoaderFixture::RootTls);
        let pe = PeImage::parse(&bytes, "root.exe").unwrap();
        let mut c = ModuleCatalog::new(arch);
        c.add_with_path(
            "root.exe",
            pe.image_base,
            &pe,
            r"C:\workspace\root.exe",
            ModuleOrigin::OwnedGenerated,
        )
        .unwrap();
        c.set_primary("root.exe").unwrap();
        c.establish_user_loader(1024).unwrap();
        c
    }
    fn image(
        c: &mut ModuleCatalog,
        name: &str,
        base: u64,
        deps: Vec<ModuleId>,
        tls: bool,
    ) -> (ModuleId, u64) {
        let (_, companions) = crate::fixtures::native_loader_probe(
            c.architecture,
            if tls {
                crate::fixtures::LoaderFixture::Tls
            } else {
                crate::fixtures::LoaderFixture::Basic
            },
        );
        let bytes = &companions[0].1;
        let pe = PeImage::parse(bytes, name).unwrap();
        c.add_with_path(
            name,
            base,
            &pe,
            &format!(r"C:\workspace\{name}"),
            ModuleOrigin::GuestFile,
        )
        .unwrap();
        let id = c.module(name).unwrap().unwrap().id;
        let op = c
            .publish_dynamic_image(
                id,
                DynamicDescriptor {
                    owner: 1024,
                    accepted_sha256: pe.sample.sha256.clone(),
                    raw_bytes: bytes.len() as u64,
                    tls: pe.tls_callbacks_only(bytes).unwrap(),
                    dependencies: deps,
                },
                0,
            )
            .unwrap();
        c.dynamic_mapped(id, 0).unwrap();
        (id, op)
    }
    fn returned(c: &mut ModuleCatalog, call: &LoaderInvocation, value: Option<u64>) {
        let event = c.begin_dynamic_routine(call, 0).unwrap();
        c.settle_dynamic_routine(
            call,
            event,
            1,
            value,
            value.is_none().then(|| "shared horizon".into()),
        )
        .unwrap();
    }
    fn attach(c: &mut ModuleCatalog, id: ModuleId, op: u64) {
        for call in c.dynamic_calls(id, false).unwrap() {
            returned(c, &call, Some(1));
        }
        c.dynamic_ready(id, 1).unwrap();
        c.finish_dynamic_operation(op, 1).unwrap();
    }
    fn detach_current(c: &mut ModuleCatalog) {
        let op = c.dynamic_state.active.as_ref().unwrap();
        let id = op.modules[op.cursor];
        for call in c.dynamic_calls(id, true).unwrap() {
            returned(c, &call, Some(0));
        }
        c.retire_dynamic_image(id, 2).unwrap();
    }
    #[test]
    fn retains_release_only_actual_api_refs_and_reload_has_a_new_identity() {
        for arch in [Architecture::X86, Architecture::X64] {
            let mut c = root(arch);
            let (id, op) = image(&mut c, "fresh.dll", 0x500000, Vec::new(), true);
            attach(&mut c, id, op);
            let count = c.dynamic_state.routines.len();
            assert_eq!(c.retain_dynamic_reference(id, 1024, 2).unwrap(), 0x500000);
            assert_eq!(c.references(id).unwrap().api_references, 2);
            assert_eq!(c.dynamic_state.routines.len(), count);
            assert!(!c.release_dynamic_reference(id, 1024, 2).unwrap());
            assert_eq!(c.references(id).unwrap().api_references, 1);
            assert!(c.release_dynamic_reference(id, 1024, 2).unwrap());
            let operation = c.dynamic_state.active.as_ref().unwrap().id;
            assert!(c.finish_dynamic_operation(operation, 2).is_err());
            detach_current(&mut c);
            c.finish_dynamic_operation(operation, 3).unwrap();
            assert!(c.by_identity(id).is_none());
            assert_eq!(c.dynamic_state.retired.len(), 1);
            let (fresh, op) = image(&mut c, "fresh.dll", 0x500000, Vec::new(), true);
            assert!(fresh > id);
            attach(&mut c, fresh, op);
            assert_eq!(c.references(fresh).unwrap().api_references, 1);
            assert!(c.references(id).is_err());
        }
    }
    #[test]
    fn actual_installed_edges_pin_a_target_until_the_owner_really_retires() {
        let mut c = root(Architecture::X64);
        let (b, op) = image(&mut c, "b.dll", 0x500000, Vec::new(), false);
        attach(&mut c, b, op);
        let (a, op) = image(&mut c, "a.dll", 0x600000, vec![b], false);
        attach(&mut c, a, op);
        assert!(!c.release_dynamic_reference(b, 1024, 2).unwrap());
        assert_eq!(c.references(b).unwrap().incoming_owners, [a]);
        assert_eq!(c.references(b).unwrap().api_references, 0);
        assert!(c.release_dynamic_reference(a, 1024, 2).unwrap());
        let op = c.dynamic_state.active.as_ref().unwrap().id;
        assert_eq!(c.dynamic_state.active.as_ref().unwrap().modules, [a, b]);
        assert!(c.retire_dynamic_image(b, 2).is_err());
        assert!(c.by_identity(a).is_some());
        assert!(c.by_identity(b).is_some());
        detach_current(&mut c);
        assert!(c.by_identity(a).is_none());
        assert_eq!(
            c.by_identity(b).unwrap().dynamic.as_ref().unwrap().phase,
            DynamicPhase::Detaching
        );
        detach_current(&mut c);
        c.finish_dynamic_operation(op, 3).unwrap();
        assert!(c.by_identity(b).is_none());
        assert_eq!(
            c.dynamic_state
                .retired
                .iter()
                .map(|m| m.id)
                .collect::<Vec<_>>(),
            [a, b]
        );
    }
    #[test]
    fn actual_false_has_real_cleanup_but_does_not_poison_static_failure_authority() {
        let mut c = root(Architecture::X64);
        let (id, op) = image(&mut c, "failed.dll", 0x500000, Vec::new(), true);
        let calls = c.dynamic_calls(id, false).unwrap();
        returned(&mut c, &calls[0], Some(1));
        returned(&mut c, &calls[1], Some(0));
        assert!(c.dynamic_ready(id, 2).is_err());
        assert!(c.failed_static_attach().is_none());
        assert_eq!(c.references(id).unwrap().api_references, 0);
        c.fail_dynamic_attach(id, 2).unwrap();
        assert!(c.retire_dynamic_image(id, 2).is_err());
        detach_current(&mut c);
        c.finish_dynamic_operation(op, 3).unwrap();
        assert!(c.by_identity(id).is_none());
        assert_eq!(c.dynamic_state.routines[1].returned_value, Some(0));
        assert_eq!(c.dynamic_state.routines[3].returned_value, Some(0));
        assert!(c.loader_events.is_empty());
    }
    #[test]
    fn interrupted_attach_never_grants_a_reference_return_or_fake_detach() {
        let mut c = root(Architecture::X86);
        let (id, op) = image(&mut c, "loop.dll", 0x500000, Vec::new(), true);
        let calls = c.dynamic_calls(id, false).unwrap();
        returned(&mut c, &calls[0], Some(1));
        let event = c.begin_dynamic_routine(&calls[1], 0).unwrap();
        assert!(c.begin_dynamic_routine(&calls[1], 0).is_err());
        c.settle_dynamic_routine(
            &calls[1],
            event,
            100,
            None,
            Some("instruction horizon".into()),
        )
        .unwrap();
        assert!(c.dynamic_ready(id, 100).is_err());
        assert!(c.fail_dynamic_attach(id, 100).is_err());
        assert!(c.retire_dynamic_image(id, 100).is_err());
        assert!(c.finish_dynamic_operation(op, 100).is_err());
        let refs = c.references(id).unwrap();
        assert_eq!(refs.api_references, 0);
        assert!(refs.pending_anchor);
        assert_eq!(c.dynamic_state.routines.len(), 2);
        assert_eq!(c.dynamic_state.routines[0].returned_value, Some(1));
        assert_eq!(c.dynamic_state.routines[1].returned_value, None);
    }
    #[test]
    fn late_followed_edges_are_real_pins_and_cycles_or_foreign_owners_are_atomic_refusals() {
        let mut c = root(Architecture::X64);
        let (b, op) = image(&mut c, "b.dll", 0x500000, Vec::new(), false);
        attach(&mut c, b, op);
        let (a, op) = image(&mut c, "a.dll", 0x600000, vec![b], false);
        attach(&mut c, a, op);
        assert!(c.acquire_late_dependencies(b, &[a], 1024, 2).is_err());
        assert!(c.references(a).unwrap().incoming_owners.is_empty());
        assert!(c.retain_dynamic_reference(a, 4096, 2).is_err());
        assert_eq!(c.references(a).unwrap().api_references, 1);
        let root = c.primary().unwrap().id;
        c.acquire_late_dependencies(root, &[a], 1024, 2).unwrap();
        assert_eq!(c.references(a).unwrap().incoming_owners, [root]);
        assert!(!c.release_dynamic_reference(a, 1024, 2).unwrap());
        assert!(!c.release_dynamic_reference(b, 1024, 2).unwrap());
        assert!(c.by_identity(a).is_some());
        assert!(c.by_identity(b).is_some());
        assert!(c.dynamic_state.retired.is_empty());
    }
    #[test]
    fn evidence_overflow_does_not_remove_the_pending_routine_lifetime_guard() {
        let mut c = root(Architecture::X64);
        let (id, _) = image(&mut c, "many.dll", 0x500000, Vec::new(), false);
        let call = c.dynamic_calls(id, false).unwrap().remove(0);
        c.dynamic_state.routines = vec![
            DynamicRoutineEvent {
                operation: 0,
                invocation: call.clone(),
                started_instructions: 0,
                stopped_instructions: Some(0),
                returned_value: Some(1),
                failure: None
            };
            MAX_DYNAMIC_ROUTINES
        ];
        let event = c.begin_dynamic_routine(&call, 0).unwrap();
        assert!(event.is_none());
        assert!(c.begin_dynamic_routine(&call, 0).is_err());
        assert!(
            c.settle_dynamic_routine(&call, event, 1, None, None)
                .is_err()
        );
        c.settle_dynamic_routine(&call, event, 1, Some(1), None)
            .unwrap();
        assert_eq!(c.dynamic_state.routines_omitted, 1);
        assert_eq!(
            c.by_identity(id)
                .unwrap()
                .dynamic
                .as_ref()
                .unwrap()
                .attach_returns,
            1
        );
    }
}
