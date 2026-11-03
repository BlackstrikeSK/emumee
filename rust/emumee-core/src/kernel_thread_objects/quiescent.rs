use super::*;

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub struct ParkedPairFields {
    pub thread: u64,
    pub offset: u16,
    pub exit_status: u32,
    pub cache_manager_count: u32,
    pub provenance: &'static str,
}
impl ParkedPairFields {
    pub fn bytes(self) -> [u8; 8] {
        let mut bytes = [0; 8];
        bytes[..4].copy_from_slice(&self.exit_status.to_le_bytes());
        bytes[4..].copy_from_slice(&self.cache_manager_count.to_le_bytes());
        bytes
    }
}
impl Lifetimes {
    pub fn configure_quiescent_parked_26200(&mut self, objects: &Objects) -> Result<()> {
        if self.architecture != Architecture::X64
            || self.system_process.is_none()
            || self.quiescent_parked_26200
            || self.entries.len() != 1
            || !self.entries.values().all(|life| {
                life.role == Ownership::InitialCaller
                    && life.root_caller
                    && life.executing
                    && !life.terminated
                    && !life.retired
            })
        {
            return Err(ThreadObjectError(
                "quiescent parked constructor requires a fresh pinned x64 System environment",
            ));
        }
        self.consistent(
            objects,
            KernelLayout::for_architecture(self.architecture).root_thread,
        )?;
        self.quiescent_parked_26200 = true;
        Ok(())
    }
    pub(super) fn projected_parked_pair(&self, life: &Lifetime) -> Option<ParkedPairFields> {
        let Ownership::ParkedProcessor { processor } = life.role else {
            return None;
        };
        if !self.quiescent_parked_26200
            || self.system_process.is_none()
            || self.architecture != Architecture::X64
            || life.owner != 4
            || life.slot != 0
            || life.guest_id != 0x2000 + u64::from(processor) * 4
            || life.root_caller
            || life.executing
            || life.terminated
            || life.retired
            || life.open_handles != 0
            || crate::ipi::processor_layout(self.architecture, processor)
                .and_then(|layout| layout.parked_thread)
                != Some(life.address)
        {
            return None;
        }
        Some(ParkedPairFields {
            thread: life.address,
            offset: 0x5d8,
            exit_status: 0,
            cache_manager_count: 0,
            provenance: "quiescent_allocated_system_26200_v1: modeled constructor birth; no prior cache/page-I/O/termination history; not captured memory",
        })
    }
    pub fn parked_pair_fields(
        &self,
        objects: &Objects,
        address: u64,
    ) -> Result<Option<ParkedPairFields>> {
        Ok(self.projected_parked_pair(self.consistent(objects, address)?))
    }
    pub fn parked_pair_for_read(&self, address: u64, size: u64) -> Option<ParkedPairFields> {
        if !self.quiescent_parked_26200 || size == 0 {
            return None;
        }
        let life = self.entries.get(&(address & !4095))?;
        let field = self.projected_parked_pair(life)?;
        let start = field.thread.checked_add(u64::from(field.offset))?;
        (address >= start && address.checked_add(size)? <= start + 8).then_some(field)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn root() -> Plan {
        let layout = KernelLayout::for_architecture(Architecture::X64);
        let objects = Objects::new(
            Architecture::X64,
            layout.driver_object + 0x3000,
            layout.driver_object,
            layout.driver_object + 0x10000,
        )
        .unwrap();
        let mut plan = Lifetimes::initialize(Architecture::X64, &objects).unwrap();
        plan.lifetimes
            .configure_system_process_26200(&plan.objects)
            .unwrap();
        plan
    }
    #[test]
    fn quiescent_pair_requires_explicit_fresh_birth_and_does_not_expose_other_roles() {
        let mut plan = root();
        let legacy = plan
            .lifetimes
            .register_parked_processor(&plan.objects, 3)
            .unwrap();
        let address = crate::ipi::processor_layout(Architecture::X64, 3)
            .unwrap()
            .parked_thread
            .unwrap();
        assert!(
            legacy
                .lifetimes
                .parked_pair_fields(&legacy.objects, address)
                .unwrap()
                .is_none()
        );
        let mut late = legacy.lifetimes;
        assert!(
            late.configure_quiescent_parked_26200(&legacy.objects)
                .is_err()
        );
        plan.lifetimes
            .configure_quiescent_parked_26200(&plan.objects)
            .unwrap();
        assert!(
            plan.lifetimes
                .configure_quiescent_parked_26200(&plan.objects)
                .is_err()
        );
        let root_address = KernelLayout::for_architecture(Architecture::X64).root_thread;
        assert!(
            plan.lifetimes
                .parked_pair_fields(&plan.objects, root_address)
                .unwrap()
                .is_none()
        );
        let child_address = KernelLayout::for_architecture(Architecture::X64)
            .thread_object(2)
            .unwrap();
        let child = plan
            .lifetimes
            .create(&plan.objects, 2, child_address, 1)
            .unwrap();
        assert!(
            child
                .lifetimes
                .parked_pair_fields(&child.objects, child_address)
                .unwrap()
                .is_none()
        );
    }
    #[test]
    fn quiescent_pair_admits_only_exact_live_read_intervals_and_refuses_corrupt_lifetimes() {
        let mut root = root();
        root.lifetimes
            .configure_quiescent_parked_26200(&root.objects)
            .unwrap();
        for processor in 1..64 {
            let plan = root
                .lifetimes
                .register_parked_processor(&root.objects, processor)
                .unwrap();
            let address = crate::ipi::processor_layout(Architecture::X64, processor)
                .unwrap()
                .parked_thread
                .unwrap();
            let field = plan
                .lifetimes
                .parked_pair_fields(&plan.objects, address)
                .unwrap()
                .unwrap();
            assert_eq!(field.bytes(), [0; 8]);
            for offset in 0..8 {
                for size in 1..=8 - offset {
                    let at = address + 0x5d8 + offset;
                    assert!(
                        plan.lifetimes
                            .private_access(at, size, "read")
                            .unwrap()
                            .is_none()
                    );
                    assert_eq!(plan.lifetimes.parked_pair_for_read(at, size), Some(field));
                    for access in ["write", "execute"] {
                        assert!(
                            plan.lifetimes
                                .private_access(at, size, access)
                                .unwrap()
                                .is_some()
                        );
                    }
                }
            }
            for (offset, size) in [(0x5d7, 2), (0x5d8, 9), (0x5df, 2), (0x5e0, 1)] {
                assert!(
                    plan.lifetimes
                        .private_access(address + offset, size, "read")
                        .unwrap()
                        .is_some()
                );
                assert!(
                    plan.lifetimes
                        .parked_pair_for_read(address + offset, size)
                        .is_none()
                );
            }
            for corrupt_field in 0..5 {
                let mut corrupt = plan.lifetimes.clone();
                let life = corrupt.entries.get_mut(&address).unwrap();
                match corrupt_field {
                    0 => life.executing = true,
                    1 => life.terminated = true,
                    2 => life.retired = true,
                    3 => life.open_handles = 1,
                    _ => life.address += 4096,
                }
                assert!(corrupt.parked_pair_for_read(address + 0x5d8, 8).is_none());
            }
        }
    }
}
