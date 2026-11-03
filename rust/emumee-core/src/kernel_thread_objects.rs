//! Scheduler-owned thread lifetimes. No second handle table: adapters pass
//! counts observed from threads.rs's authoritative owned handle map.
use crate::{
    kernel_layout::KernelLayout,
    kernel_objects::{Kind, Objects},
    pe::Architecture,
};
use serde::Serialize;
use std::collections::BTreeMap;
use thiserror::Error;
mod borrowed;
mod fields;
mod quiescent;
pub use borrowed::Ownership;
pub use fields::{ThreadFields, kernel_apc_disable_word};
pub use quiescent::ParkedPairFields;
#[derive(Debug, Error)]
#[error("Kernel thread lifetime: {0}")]
pub struct ThreadObjectError(pub &'static str);
type Result<T> = std::result::Result<T, ThreadObjectError>;
#[derive(Clone, Debug, Serialize)]
pub struct Lifetime {
    pub slot: u64,
    pub guest_id: u64,
    pub address: u64,
    pub owner: u64,
    pub root_caller: bool,
    pub role: Ownership,
    pub executing: bool,
    pub open_handles: u32,
    pub terminated: bool,
    pub retired: bool,
}
#[derive(Clone, Debug, Serialize)]
pub struct Lifetimes {
    architecture: Architecture,
    #[serde(skip_serializing_if = "Option::is_none")]
    system_process: Option<SystemProcessField>,
    quiescent_parked_26200: bool,
    pub entries: BTreeMap<u64, Lifetime>,
}
/// The pinned x64 ApcState.Process projection. Other private bytes remain
/// unknown; this does not expose the Process object's private body.
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub struct SystemProcessField {
    pub offset: u16,
    pub process: u64,
}
/// Pinned KTHREAD stack bounds for actual scheduler-owned stacks. Parked IPI
/// identities have callback stacks, not an owned ordinary thread stack.
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub struct StackFields {
    pub thread: u64,
    pub limit_offset: u16,
    pub base_offset: u16,
    pub limit: u64,
    pub base: u64,
}
#[derive(Clone, Copy, Debug, Serialize)]
pub enum Effect {
    Initialize { address: u64 },
    Signal { address: u64 },
    Retire { address: u64 },
}
pub struct Plan {
    pub lifetimes: Lifetimes,
    pub objects: Objects,
    pub effects: Vec<Effect>,
}
#[derive(Clone, Debug, Serialize)]
pub struct PrivateAccess {
    pub address: u64,
    pub size: u64,
    pub object: u64,
    pub slot: u64,
    pub retired: bool,
    pub access: &'static str,
}
impl Lifetimes {
    pub fn initialize(architecture: Architecture, objects: &Objects) -> Result<Plan> {
        let address = KernelLayout::for_architecture(architecture).root_thread;
        let mut owned = objects.clone();
        owned
            .register_owned(address, Kind::Thread, 1)
            .map_err(|_| {
                ThreadObjectError("initial caller identity conflicts with owned kernel objects")
            })?;
        let state = Self {
            architecture,
            system_process: None,
            quiescent_parked_26200: false,
            entries: BTreeMap::from([(
                address,
                Lifetime {
                    slot: 1,
                    guest_id: 0x1004,
                    address,
                    owner: 4,
                    root_caller: true,
                    role: Ownership::InitialCaller,
                    executing: true,
                    open_handles: 0,
                    terminated: false,
                    retired: false,
                },
            )]),
        };
        Ok(Plan {
            lifetimes: state,
            objects: owned,
            effects: vec![Effect::Initialize { address }],
        })
    }
    pub fn slot(&self, slot: u64) -> Result<&Lifetime> {
        self.entries
            .values()
            .find(|entry| entry.slot == slot && slot != 0)
            .ok_or(ThreadObjectError("unknown scheduler thread identity"))
    }
    pub fn configure_system_process_26200(&mut self, objects: &Objects) -> Result<()> {
        if self.architecture != Architecture::X64
            || self.entries.len() != 1
            || self.system_process.is_some()
            || !self
                .entries
                .values()
                .all(|life| life.root_caller && life.owner == 4 && !life.retired)
        {
            return Err(ThreadObjectError(
                "System process field requires a fresh pinned x64 caller",
            ));
        }
        let process = objects
            .object(objects.system_process)
            .map_err(|_| ThreadObjectError("System process identity missing"))?;
        if process.kind != Kind::Process || process.permanent_references == 0 {
            return Err(ThreadObjectError(
                "System process field lacks a live permanent Process",
            ));
        }
        self.system_process = Some(SystemProcessField {
            offset: 0xb8,
            process: objects.system_process,
        });
        Ok(())
    }
    pub fn system_process_field(&self) -> Option<SystemProcessField> {
        self.system_process
    }
    fn projected_stack(&self, life: &Lifetime) -> Option<StackFields> {
        if self.system_process.is_none() || life.retired {
            return None;
        }
        let layout = KernelLayout::for_architecture(self.architecture);
        let (limit, size) = match life.role {
            Ownership::InitialCaller if life.slot == 1 && life.address == layout.root_thread => {
                (layout.entry_stack, crate::kernel_layout::ENTRY_STACK_SIZE)
            }
            Ownership::CreatedSystemThread
                if layout.thread_object(life.slot) == Some(life.address) =>
            {
                (
                    layout.thread_stack(life.slot)?,
                    crate::kernel_layout::THREAD_STACK_SIZE,
                )
            }
            _ => return None,
        };
        Some(StackFields {
            thread: life.address,
            limit_offset: 0x30,
            base_offset: 0x38,
            limit,
            base: limit.checked_add(size)?,
        })
    }
    pub fn stack_fields(&self, objects: &Objects, address: u64) -> Result<Option<StackFields>> {
        Ok(self.projected_stack(self.consistent(objects, address)?))
    }
    fn consistent(&self, objects: &Objects, address: u64) -> Result<&Lifetime> {
        let life = self
            .entries
            .get(&address)
            .ok_or(ThreadObjectError("foreign scheduler object identity"))?;
        let object = objects.records.get(&address).ok_or(ThreadObjectError(
            "thread object absent from owned reference model",
        ))?;
        let anchors = if life.role.borrowed() {
            1
        } else {
            u32::from(life.executing) + life.open_handles
        };
        let expected_id = match life.role {
            Ownership::InitialCaller if life.slot == 1 => 0x1004,
            Ownership::CreatedSystemThread if (2..=64).contains(&life.slot) => {
                0x1000 + life.slot * 4
            }
            Ownership::ParkedProcessor { processor }
                if life.slot == 0 && (1..64).contains(&processor) =>
            {
                0x2000 + u64::from(processor) * 4
            }
            _ => return Err(ThreadObjectError("thread guest ID ownership diverged")),
        };
        if life.owner != 4
            || life.guest_id != expected_id
            || object.kind != Kind::Thread
            || object.permanent_references != anchors
            || object.live == life.retired
            || life.retired && object.references() != 0
            || !life.retired && object.references() == 0
        {
            return Err(ThreadObjectError(
                "scheduler and object reference ownership diverged",
            ));
        }
        Ok(life)
    }
    /// Returns the ID published with this genuine object lifetime. This is not
    /// a scheduler slot or a host OS identity; retired identities are refused.
    pub fn guest_id(&self, objects: &Objects, address: u64) -> Result<u64> {
        let life = self.consistent(objects, address)?;
        if life.retired {
            return Err(ThreadObjectError("retired guest thread ID"));
        }
        Ok(life.guest_id)
    }
    pub fn create(
        &self,
        objects: &Objects,
        slot: u64,
        address: u64,
        observed_handles: u32,
    ) -> Result<Plan> {
        if !(2..=64).contains(&slot)
            || KernelLayout::for_architecture(self.architecture).thread_object(slot)
                != Some(address)
            || self.entries.contains_key(&address)
            || self.entries.values().any(|entry| entry.slot == slot)
            || observed_handles != 1
        {
            return Err(ThreadObjectError(
                "thread creation does not match actual scheduler/handle ownership",
            ));
        }
        let mut next = self.clone();
        let mut owned = objects.clone();
        owned
            .register_owned(address, Kind::Thread, 2)
            .map_err(|_| ThreadObjectError("thread creation object reservation conflict"))?;
        next.entries.insert(
            address,
            Lifetime {
                slot,
                guest_id: 0x1000 + slot * 4,
                address,
                owner: 4,
                root_caller: false,
                role: Ownership::CreatedSystemThread,
                executing: true,
                open_handles: 1,
                terminated: false,
                retired: false,
            },
        );
        Ok(Plan {
            lifetimes: next,
            objects: owned,
            effects: vec![Effect::Initialize { address }],
        })
    }
    fn finish(
        mut lifetimes: Self,
        mut objects: Objects,
        address: u64,
        mut effects: Vec<Effect>,
    ) -> Result<Plan> {
        let life = lifetimes.entries.get_mut(&address).unwrap();
        let object = objects.records.get_mut(&address).unwrap();
        if !life.role.borrowed() && object.references() == 0 {
            if life.executing || life.open_handles != 0 || !life.terminated {
                return Err(ThreadObjectError("cannot retire a running or owned thread"));
            }
            life.retired = true;
            object.live = false;
            effects.push(Effect::Retire { address });
        }
        lifetimes.consistent(&objects, address)?;
        Ok(Plan {
            lifetimes,
            objects,
            effects,
        })
    }
    pub fn close(
        &self,
        objects: &Objects,
        slot: u64,
        observed_handles_before: u32,
    ) -> Result<Plan> {
        let life = self.slot(slot)?;
        self.consistent(objects, life.address)?;
        if life.root_caller
            || life.retired
            || life.open_handles != observed_handles_before
            || observed_handles_before == 0
        {
            return Err(ThreadObjectError(
                "close does not match an actual owned scheduler handle",
            ));
        }
        let address = life.address;
        let mut next = self.clone();
        let mut owned = objects.clone();
        next.entries.get_mut(&address).unwrap().open_handles -= 1;
        owned
            .records
            .get_mut(&address)
            .unwrap()
            .permanent_references -= 1;
        Self::finish(next, owned, address, Vec::new())
    }
    pub fn exit(&self, objects: &Objects, slot: u64, observed_handles: u32) -> Result<Plan> {
        let life = self.slot(slot)?;
        self.consistent(objects, life.address)?;
        if life.root_caller {
            return Err(ThreadObjectError(
                "DriverEntry return does not terminate its borrowed System caller",
            ));
        }
        if life.retired
            || life.terminated
            || !life.executing
            || life.open_handles != observed_handles
        {
            return Err(ThreadObjectError(
                "thread exit does not match actual scheduler lifetime",
            ));
        }
        let address = life.address;
        let mut next = self.clone();
        let mut owned = objects.clone();
        let changed = next.entries.get_mut(&address).unwrap();
        changed.executing = false;
        changed.terminated = true;
        owned
            .records
            .get_mut(&address)
            .unwrap()
            .permanent_references -= 1;
        Self::finish(next, owned, address, vec![Effect::Signal { address }])
    }
    /// Existing Objects::plan already applies typed pointer/API reference
    /// changes; reconcile retirement after that transactional model step.
    pub fn after_api_reference(&self, objects: &Objects, address: u64) -> Result<Plan> {
        let life = self
            .entries
            .get(&address)
            .ok_or(ThreadObjectError("unknown thread API reference"))?;
        let object = objects
            .records
            .get(&address)
            .ok_or(ThreadObjectError("missing thread API object"))?;
        let anchors = if life.role.borrowed() {
            1
        } else {
            u32::from(life.executing) + life.open_handles
        };
        if object.kind != Kind::Thread || object.permanent_references != anchors || life.retired {
            return Err(ThreadObjectError(
                "thread API reference changed scheduler ownership",
            ));
        }
        Self::finish(self.clone(), objects.clone(), address, Vec::new())
    }
    pub fn wait_target(&self, objects: &Objects, address: u64) -> Result<&Lifetime> {
        let life = self.consistent(objects, address)?;
        if matches!(life.role, Ownership::ParkedProcessor { .. }) {
            return Err(ThreadObjectError(
                "parked processor Thread waits are outside the supported profile",
            ));
        }
        if life.retired {
            return Err(ThreadObjectError(
                "wait references a released thread object",
            ));
        }
        if life.root_caller {
            return Err(ThreadObjectError(
                "borrowed initial System caller termination is not modeled",
            ));
        }
        Ok(life)
    }
    pub fn header(&self, address: u64) -> Result<[u8; 8]> {
        let life = self
            .entries
            .get(&address)
            .filter(|entry| !entry.retired)
            .ok_or(ThreadObjectError("header of retired/unknown thread"))?;
        let mut header = [0u8; 8];
        header[0] = 6;
        header[2] = if self.architecture == Architecture::X64 {
            6
        } else {
            4
        };
        header[4..8].copy_from_slice(&u32::from(life.terminated).to_le_bytes());
        Ok(header)
    }
    /// Interval intersection, including reads beginning in header/previous
    /// mappings. Address ordering makes unrelated CPU reads a bounded lookup.
    pub fn private_access(
        &self,
        address: u64,
        size: u64,
        access: &'static str,
    ) -> Result<Option<PrivateAccess>> {
        if size == 0 {
            return Ok(None);
        }
        let end = address
            .checked_add(size)
            .ok_or(ThreadObjectError("thread access range overflow"))?;
        for (body, life) in self.entries.range(..end).rev() {
            if body + 4096 <= address {
                break;
            }
            if !life.retired
                && access == "read"
                && (self.system_process.is_some_and(|field| {
                    address >= body + u64::from(field.offset)
                        && end <= body + u64::from(field.offset) + 8
                }) || self.projected_stack(life).is_some_and(|field| {
                    address >= body + u64::from(field.limit_offset)
                        && end <= body + u64::from(field.base_offset) + 8
                }) || self.projected_parked_pair(life).is_some_and(|field| {
                    address >= field.thread + u64::from(field.offset)
                        && end <= field.thread + u64::from(field.offset) + 8
                }) || self.projected_fields(life).is_some_and(|field| {
                    field.intervals().into_iter().any(|(offset, bytes)| {
                        address >= body + u64::from(offset)
                            && end <= body + u64::from(offset) + u64::from(bytes)
                    })
                }))
            {
                continue;
            }
            let private = if life.retired || access != "read" {
                *body
            } else {
                body + 8
            };
            if private < end && address < body + 4096 {
                return Ok(Some(PrivateAccess {
                    address,
                    size,
                    object: *body,
                    slot: life.slot,
                    retired: life.retired,
                    access,
                }));
            }
        }
        Ok(None)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pinned_stack_bounds_follow_owned_stacks_and_lifetimes_without_opening_gaps() {
        let mut root = initial(Architecture::X64);
        let layout = KernelLayout::for_architecture(Architecture::X64);
        assert_eq!(
            root.lifetimes
                .stack_fields(&root.objects, layout.root_thread)
                .unwrap(),
            None
        );
        root.lifetimes
            .configure_system_process_26200(&root.objects)
            .unwrap();
        let child = root
            .lifetimes
            .create(&root.objects, 2, layout.thread_object(2).unwrap(), 1)
            .unwrap();
        let measured: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/native_capture_layout.json"
        ))
        .unwrap();
        assert_eq!(measured["thread_fields"]["stack_limit"], 0x30);
        assert_eq!(measured["thread_fields"]["stack_base"], 0x38);
        for (address, limit, size) in [
            (
                layout.root_thread,
                layout.entry_stack,
                crate::kernel_layout::ENTRY_STACK_SIZE,
            ),
            (
                layout.thread_object(2).unwrap(),
                layout.thread_stack(2).unwrap(),
                crate::kernel_layout::THREAD_STACK_SIZE,
            ),
        ] {
            let fields = child
                .lifetimes
                .stack_fields(&child.objects, address)
                .unwrap()
                .unwrap();
            assert_eq!((fields.limit, fields.base), (limit, limit + size));
            assert_eq!((fields.limit_offset, fields.base_offset), (0x30, 0x38));
            for (offset, bytes) in [(0x30, 16), (0x30, 8), (0x38, 8), (0x3f, 1), (0x34, 8)] {
                assert!(
                    child
                        .lifetimes
                        .private_access(address + offset, bytes, "read")
                        .unwrap()
                        .is_none()
                );
            }
            for (offset, bytes, access) in [
                (0x2f, 8, "read"),
                (0x38, 9, "read"),
                (8, 0x38, "read"),
                (0x30, 16, "write"),
                (0x38, 8, "execute"),
                (0x78, 4, "read"),
            ] {
                assert!(
                    child
                        .lifetimes
                        .private_access(address + offset, bytes, access)
                        .unwrap()
                        .is_some()
                );
            }
        }
        let parked = child
            .lifetimes
            .register_parked_processor(&child.objects, 1)
            .unwrap();
        let address = crate::ipi::processor_layout(Architecture::X64, 1)
            .unwrap()
            .parked_thread
            .unwrap();
        assert_eq!(
            parked
                .lifetimes
                .stack_fields(&parked.objects, address)
                .unwrap(),
            None
        );
        assert!(
            parked
                .lifetimes
                .private_access(address + 0x30, 16, "read")
                .unwrap()
                .is_some()
        );
        let closed = child.lifetimes.close(&child.objects, 2, 1).unwrap();
        let retired = closed.lifetimes.exit(&closed.objects, 2, 0).unwrap();
        let address = layout.thread_object(2).unwrap();
        assert_eq!(
            retired
                .lifetimes
                .stack_fields(&retired.objects, address)
                .unwrap(),
            None
        );
        assert!(
            retired
                .lifetimes
                .private_access(address + 0x30, 16, "read")
                .unwrap()
                .is_some()
        );
    }
    #[test]
    fn pinned_system_process_projection_is_lifetime_bound_and_preserves_private_gaps() {
        let mut root = initial(Architecture::X64);
        root.lifetimes
            .configure_system_process_26200(&root.objects)
            .unwrap();
        let field = root.lifetimes.system_process_field().unwrap();
        assert_eq!(
            field,
            SystemProcessField {
                offset: 0xb8,
                process: root.objects.system_process
            }
        );
        let body = KernelLayout::for_architecture(Architecture::X64).root_thread;
        for (offset, size) in [(0xb8, 8), (0xb8, 1), (0xbc, 4), (0xbf, 1)] {
            assert!(
                root.lifetimes
                    .private_access(body + offset, size, "read")
                    .unwrap()
                    .is_none()
            );
        }
        for (offset, size, access) in [
            (0xb7, 8, "read"),
            (0xb8, 9, "read"),
            (8, 0xb8, "read"),
            (0xb8, 8, "write"),
            (0xb8, 8, "execute"),
        ] {
            assert!(
                root.lifetimes
                    .private_access(body + offset, size, access)
                    .unwrap()
                    .is_some()
            );
        }
        let address = KernelLayout::for_architecture(Architecture::X64)
            .thread_object(2)
            .unwrap();
        let child = root.lifetimes.create(&root.objects, 2, address, 1).unwrap();
        assert_eq!(child.lifetimes.system_process_field(), Some(field));
        let closed = child.lifetimes.close(&child.objects, 2, 1).unwrap();
        let retired = closed.lifetimes.exit(&closed.objects, 2, 0).unwrap();
        assert!(
            retired
                .lifetimes
                .private_access(address + 0xb8, 8, "read")
                .unwrap()
                .is_some()
        );
    }
    #[test]
    fn system_process_projection_cannot_be_reconfigured_or_guessed_for_other_architectures() {
        let mut x86 = initial(Architecture::X86);
        assert!(
            x86.lifetimes
                .configure_system_process_26200(&x86.objects)
                .is_err()
        );
        let mut x64 = initial(Architecture::X64);
        let body = KernelLayout::for_architecture(Architecture::X64).root_thread;
        assert!(
            x64.lifetimes
                .private_access(body + 0xb8, 8, "read")
                .unwrap()
                .is_some()
        );
        x64.lifetimes
            .configure_system_process_26200(&x64.objects)
            .unwrap();
        assert!(
            x64.lifetimes
                .configure_system_process_26200(&x64.objects)
                .is_err()
        );
        let mut invalid = initial(Architecture::X64);
        let mut objects = invalid.objects.clone();
        objects
            .records
            .get_mut(&objects.system_process)
            .unwrap()
            .kind = Kind::Thread;
        assert!(
            invalid
                .lifetimes
                .configure_system_process_26200(&objects)
                .is_err()
        );
        assert!(invalid.lifetimes.system_process_field().is_none());
    }
    #[test]
    fn guest_ids_are_distinct_stable_lifetime_values_and_retired_ids_cannot_be_queried() {
        for arch in [Architecture::X86, Architecture::X64] {
            let mut plan = initial(arch);
            let layout = KernelLayout::for_architecture(arch);
            assert_eq!(
                plan.lifetimes
                    .guest_id(&plan.objects, layout.root_thread)
                    .unwrap(),
                0x1004
            );
            for slot in 2..=64 {
                plan = plan
                    .lifetimes
                    .create(&plan.objects, slot, layout.thread_object(slot).unwrap(), 1)
                    .unwrap();
            }
            for cpu in 1..(arch.width() as u32 * 8) {
                plan = plan
                    .lifetimes
                    .register_parked_processor(&plan.objects, cpu)
                    .unwrap();
            }
            let ids = plan
                .lifetimes
                .entries
                .values()
                .map(|l| l.guest_id)
                .collect::<std::collections::BTreeSet<_>>();
            assert_eq!(ids.len(), plan.lifetimes.entries.len());
            let address = layout.thread_object(2).unwrap();
            assert_eq!(
                plan.lifetimes.guest_id(&plan.objects, address).unwrap(),
                0x1008
            );
            plan = plan.lifetimes.close(&plan.objects, 2, 1).unwrap();
            assert_eq!(
                plan.lifetimes.guest_id(&plan.objects, address).unwrap(),
                0x1008
            );
            plan = plan.lifetimes.exit(&plan.objects, 2, 0).unwrap();
            assert!(plan.lifetimes.guest_id(&plan.objects, address).is_err());
            plan.lifetimes
                .entries
                .get_mut(&layout.root_thread)
                .unwrap()
                .guest_id = 0x1008;
            assert!(
                plan.lifetimes
                    .guest_id(&plan.objects, layout.root_thread)
                    .is_err()
            );
        }
    }
    fn initial(architecture: Architecture) -> Plan {
        let layout = KernelLayout::for_architecture(architecture);
        let objects = Objects::new(
            architecture,
            layout.driver_object + 0x3000,
            layout.driver_object,
            layout.driver_object + 0x10000,
        )
        .unwrap();
        Lifetimes::initialize(architecture, &objects).unwrap()
    }
    #[test]
    fn real_handle_execution_and_api_references_release_independent_anchors() {
        for architecture in [Architecture::X86, Architecture::X64] {
            let root = initial(architecture);
            let address = KernelLayout::for_architecture(architecture)
                .thread_object(2)
                .unwrap();
            let child = root.lifetimes.create(&root.objects, 2, address, 1).unwrap();
            let referenced = child
                .objects
                .plan(0, address, crate::kernel_objects::Operation::Reference)
                .unwrap();
            let closed = child.lifetimes.close(&referenced.state, 2, 1).unwrap();
            assert_eq!(closed.objects.records[&address].references(), 2);
            let exited = closed.lifetimes.exit(&closed.objects, 2, 0).unwrap();
            assert_eq!(exited.objects.records[&address].references(), 1);
            assert_eq!(
                exited.lifetimes.header(address).unwrap()[4..8],
                1u32.to_le_bytes()
            );
            let released = exited
                .objects
                .plan(0, address, crate::kernel_objects::Operation::Dereference)
                .unwrap();
            let retired = exited
                .lifetimes
                .after_api_reference(&released.state, address)
                .unwrap();
            assert!(!retired.objects.records[&address].live);
            assert!(matches!(
                retired.effects.last(),
                Some(Effect::Retire { .. })
            ));
            assert!(
                retired
                    .lifetimes
                    .wait_target(&retired.objects, address)
                    .is_err()
            );
            assert!(root.lifetimes.exit(&root.objects, 1, 0).is_err());
        }
    }
    #[test]
    fn close_after_exit_and_unreferenced_exit_retire_only_after_last_real_owner() {
        let root = initial(Architecture::X64);
        let address = KernelLayout::for_architecture(Architecture::X64)
            .thread_object(2)
            .unwrap();
        let child = root.lifetimes.create(&root.objects, 2, address, 1).unwrap();
        assert!(child.lifetimes.close(&child.objects, 2, 0).is_err());
        let exited = child.lifetimes.exit(&child.objects, 2, 1).unwrap();
        assert!(exited.objects.records[&address].live);
        let closed = exited.lifetimes.close(&exited.objects, 2, 1).unwrap();
        assert!(closed.lifetimes.entries[&address].retired);
        let closed = child.lifetimes.close(&child.objects, 2, 1).unwrap();
        assert!(closed.objects.records[&address].live);
        assert!(
            closed
                .lifetimes
                .exit(&closed.objects, 2, 0)
                .unwrap()
                .lifetimes
                .entries[&address]
                .retired
        );
    }
    #[test]
    fn interval_guards_cover_header_tail_and_previous_mapping_crossings() {
        for architecture in [Architecture::X86, Architecture::X64] {
            let root = initial(architecture);
            let body = KernelLayout::for_architecture(architecture).root_thread;
            assert!(
                root.lifetimes
                    .private_access(body, 8, "read")
                    .unwrap()
                    .is_none()
            );
            for (address, size) in [
                (body + 4, 8),
                (body + 7, 2),
                (body - 4, 16),
                (body + 8, 1),
                (body + 4095, 2),
            ] {
                assert!(
                    root.lifetimes
                        .private_access(address, size, "read")
                        .unwrap()
                        .is_some(),
                    "{address:x}+{size:x}"
                );
            }
            assert!(
                root.lifetimes
                    .private_access(body, 1, "write")
                    .unwrap()
                    .is_some()
            );
            assert!(
                root.lifetimes
                    .private_access(body, 1, "execute")
                    .unwrap()
                    .is_some()
            );
            assert!(
                root.lifetimes
                    .private_access(body - 4, 12, "read")
                    .unwrap()
                    .is_none()
            );
            assert!(
                root.lifetimes
                    .private_access(u64::MAX - 1, 4, "read")
                    .is_err()
            );
        }
    }
}
