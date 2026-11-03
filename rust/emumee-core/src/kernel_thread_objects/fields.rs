//! Pinned, individually known fields; never a synthetic full ETHREAD image.
use super::*;

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub struct ThreadFields {
    pub thread: u64,
    pub previous_mode_offset: u16,
    pub previous_mode: u8,
    pub cid_offset: u16,
    pub process_id: u64,
    pub thread_id: u64,
    pub kernel_apc_disable_offset: u16,
}
impl ThreadFields {
    pub(super) fn intervals(self) -> [(u16, u16); 3] {
        [
            (self.previous_mode_offset, 1),
            (self.cid_offset, 16),
            (self.kernel_apc_disable_offset, 2),
        ]
    }
}
/// Raw SHORT representation of the owned critical-region nesting counter.
/// This does not model SpecialApcDisable, native inline updates or APC delivery.
pub fn kernel_apc_disable_word(critical_depth: u16) -> u16 {
    0u16.wrapping_sub(critical_depth)
}
impl Lifetimes {
    pub(super) fn projected_fields(&self, life: &Lifetime) -> Option<ThreadFields> {
        if self.system_process.is_none() || life.retired || life.owner != 4 {
            return None;
        }
        Some(ThreadFields {
            thread: life.address,
            previous_mode_offset: 0x232,
            previous_mode: 0, // All admitted owned contexts are KernelMode.
            cid_offset: 0x508,
            process_id: life.owner,
            thread_id: life.guest_id,
            kernel_apc_disable_offset: 0x1e4,
        })
    }
    pub fn thread_fields(&self, objects: &Objects, address: u64) -> Result<Option<ThreadFields>> {
        Ok(self.projected_fields(self.consistent(objects, address)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn raw_counter_has_exact_modular_encoding_for_every_owned_depth() {
        for depth in 0..=u16::MAX {
            let word = kernel_apc_disable_word(depth);
            assert_eq!(word.wrapping_add(depth), 0);
            assert_eq!(word != 0, depth != 0);
        }
    }
    #[test]
    fn pinned_identity_fields_follow_lifetimes_and_admit_only_exact_known_intervals() {
        let layout = KernelLayout::for_architecture(Architecture::X64);
        let objects = Objects::new(
            Architecture::X64,
            layout.driver_object + 0x3000,
            layout.driver_object,
            layout.driver_object + 0x10000,
        )
        .unwrap();
        let mut plan = Lifetimes::initialize(Architecture::X64, &objects).unwrap();
        let root = KernelLayout::for_architecture(Architecture::X64).root_thread;
        assert_eq!(
            plan.lifetimes.thread_fields(&plan.objects, root).unwrap(),
            None
        );
        plan.lifetimes
            .configure_system_process_26200(&plan.objects)
            .unwrap();
        let child = KernelLayout::for_architecture(Architecture::X64)
            .thread_object(2)
            .unwrap();
        let plan = plan.lifetimes.create(&plan.objects, 2, child, 1).unwrap();
        for (address, id) in [(root, 0x1004), (child, 0x1008)] {
            let fields = plan
                .lifetimes
                .thread_fields(&plan.objects, address)
                .unwrap()
                .unwrap();
            assert_eq!(
                (fields.process_id, fields.thread_id, fields.previous_mode),
                (4, id, 0)
            );
            for (offset, size) in [(0x232, 1), (0x508, 16), (0x510, 8), (0x517, 1), (0x1e4, 2)] {
                assert!(
                    plan.lifetimes
                        .private_access(address + offset, size, "read")
                        .unwrap()
                        .is_none()
                );
                assert!(
                    plan.lifetimes
                        .private_access(address + offset, size, "write")
                        .unwrap()
                        .is_some()
                );
                assert!(
                    plan.lifetimes
                        .private_access(address + offset, size, "execute")
                        .unwrap()
                        .is_some()
                );
            }
            for (offset, size) in [
                (0x231, 2),
                (0x232, 2),
                (0x507, 16),
                (0x510, 9),
                (0x1e4, 4),
                (0x1e3, 2),
                (0x1e6, 2),
            ] {
                assert!(
                    plan.lifetimes
                        .private_access(address + offset, size, "read")
                        .unwrap()
                        .is_some()
                );
            }
        }
        let mut corrupt = plan.lifetimes.clone();
        corrupt.entries.get_mut(&child).unwrap().owner = 5;
        assert!(corrupt.thread_fields(&plan.objects, child).is_err());
        let exited = plan.lifetimes.exit(&plan.objects, 2, 1).unwrap();
        assert!(
            exited
                .lifetimes
                .thread_fields(&exited.objects, child)
                .unwrap()
                .is_some()
        );
        let retired = exited.lifetimes.close(&exited.objects, 2, 1).unwrap();
        assert_eq!(
            retired
                .lifetimes
                .thread_fields(&retired.objects, child)
                .unwrap(),
            None
        );
        assert!(
            retired
                .lifetimes
                .private_access(child + 0x508, 16, "read")
                .unwrap()
                .is_some()
        );
        let parked = plan
            .lifetimes
            .register_parked_processor(&plan.objects, 1)
            .unwrap();
        let parked_address = crate::ipi::processor_layout(Architecture::X64, 1)
            .unwrap()
            .parked_thread
            .unwrap();
        let fields = parked
            .lifetimes
            .thread_fields(&parked.objects, parked_address)
            .unwrap()
            .unwrap();
        assert_eq!(fields.thread_id, 0x2004);
        assert_eq!(
            parked
                .lifetimes
                .stack_fields(&parked.objects, parked_address)
                .unwrap(),
            None
        );
    }
}
