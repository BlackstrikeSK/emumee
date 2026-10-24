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
pub use borrowed::Ownership;
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
    pub entries: BTreeMap<u64, Lifetime>,
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
        if life.guest_id != expected_id
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
