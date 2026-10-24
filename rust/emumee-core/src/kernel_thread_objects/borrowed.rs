//! Explicit permanently borrowed processor environments. These are not created
//! scheduler threads and never own a PsCreateSystemThread handle/execution anchor.
use super::*;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Ownership {
    InitialCaller,
    CreatedSystemThread,
    ParkedProcessor { processor: u32 },
}
impl Ownership {
    pub fn borrowed(self) -> bool {
        !matches!(self, Self::CreatedSystemThread)
    }
}
impl Lifetimes {
    pub fn register_parked_processor(&self, objects: &Objects, processor: u32) -> Result<Plan> {
        let address = crate::ipi::processor_layout(self.architecture, processor)
            .and_then(|layout| layout.parked_thread)
            .ok_or(ThreadObjectError(
                "parked processor requires distinct remote owned identity",
            ))?;
        if let Some(life) = self.entries.get(&address) {
            self.consistent(objects, address)?;
            if life.role != (Ownership::ParkedProcessor { processor })
                || life.root_caller
                || life.slot != 0
                || life.executing
                || life.terminated
                || life.retired
                || life.open_handles != 0
            {
                return Err(ThreadObjectError(
                    "parked processor ownership profile diverged",
                ));
            }
            return Ok(Plan {
                lifetimes: self.clone(),
                objects: objects.clone(),
                effects: Vec::new(),
            });
        }
        let mut next = self.clone();
        let mut owned = objects.clone();
        owned
            .register_owned(address, Kind::Thread, 1)
            .map_err(|_| {
                ThreadObjectError("parked processor identity conflicts with owned objects")
            })?;
        next.entries.insert(
            address,
            Lifetime {
                slot: 0,
                guest_id: 0x2000 + u64::from(processor) * 4,
                address,
                owner: 4,
                root_caller: false,
                executing: false,
                open_handles: 0,
                terminated: false,
                retired: false,
                role: Ownership::ParkedProcessor { processor },
            },
        );
        next.consistent(&owned, address)?;
        Ok(Plan {
            lifetimes: next,
            objects: owned,
            effects: vec![Effect::Initialize { address }],
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parked_cpu_identity_has_its_own_borrowed_anchor_and_cannot_fake_a_created_thread() {
        for architecture in [Architecture::X86, Architecture::X64] {
            let layout = KernelLayout::for_architecture(architecture);
            let objects = Objects::new(
                architecture,
                layout.driver_object + 0x3000,
                layout.driver_object,
                layout.driver_object + 0x10000,
            )
            .unwrap();
            let root = Lifetimes::initialize(architecture, &objects).unwrap();
            let parked = root
                .lifetimes
                .register_parked_processor(&root.objects, 1)
                .unwrap();
            let address = crate::ipi::processor_layout(architecture, 1)
                .unwrap()
                .parked_thread
                .unwrap();
            let life = &parked.lifetimes.entries[&address];
            assert_eq!(life.slot, 0);
            assert!(!life.root_caller && !life.executing && life.open_handles == 0);
            assert_eq!(life.role, Ownership::ParkedProcessor { processor: 1 });
            assert!(
                parked
                    .lifetimes
                    .wait_target(&parked.objects, address)
                    .is_err()
            );
            assert!(
                parked
                    .objects
                    .plan(0, address, crate::kernel_objects::Operation::Dereference)
                    .is_err()
            );
            let referenced = parked
                .objects
                .plan(0, address, crate::kernel_objects::Operation::Reference)
                .unwrap();
            let released = referenced
                .state
                .plan(0, address, crate::kernel_objects::Operation::Dereference)
                .unwrap();
            let after = parked
                .lifetimes
                .after_api_reference(&released.state, address)
                .unwrap();
            assert!(after.effects.is_empty());
            assert!(!after.lifetimes.entries[&address].retired);
            assert_eq!(after.objects.records[&address].permanent_references, 1);
            assert!(
                after
                    .lifetimes
                    .register_parked_processor(&after.objects, 1)
                    .unwrap()
                    .effects
                    .is_empty()
            );
            assert!(
                after
                    .lifetimes
                    .register_parked_processor(&after.objects, 0)
                    .is_err()
            );
        }
    }
}
