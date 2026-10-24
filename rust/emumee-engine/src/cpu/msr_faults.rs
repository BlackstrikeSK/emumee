//! No KVM paravirtual MSR device is implemented by this CPU backend.
//! Unknown-index zero is not an implemented hardware register.
use super::*;

pub(super) fn before(
    engine: &mut Unicorn<Trace>,
    pc: u64,
    size: u32,
    index: u32,
    write: bool,
) -> Result<bool> {
    if !(0x4b564d00..=0x4b564dff).contains(&index) {
        return Ok(false);
    }
    let signature =
        engine
            .get_data()
            .cpu
            .profile
            .leaf(0x40000000, 0, engine.get_data().cpu.processor);
    ensure!(
        signature[1..] != [0x4b4d564b, 0x564b4d56, 0x4d],
        "Advertised KVM paravirtual MSR backend is not implemented"
    );
    // Device policy, not a physical-host measurement: CPUID alone cannot
    // disprove a hidden hypervisor. Advertised KVM needs a real backend.
    crate::native_exceptions::queue_msr_gp(engine, pc, size, index, write)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use emumee_core::cpu::CpuidOverride;

    #[test]
    fn advertised_kvm_requires_an_implemented_device_and_other_indices_remain_separate() {
        let observations = (|| -> Result<(bool, String, bool)> {
            let mut engine = crate::new_engine(Architecture::X64)?;
            let outside = before(&mut engine, 0x1000, 2, 0xdeadbeef, false)?;
            engine
                .get_data_mut()
                .cpu
                .profile
                .cpuid_overrides
                .push(CpuidOverride {
                    function: 0x40000000,
                    subleaf: 0,
                    eax: 0x40000001,
                    ebx: 0x4b4d564b,
                    ecx: 0x564b4d56,
                    edx: 0x4d,
                });
            let error = before(&mut engine, 0x1000, 2, 0x4b564d00, false)
                .expect_err("An advertised device must not be silently replaced with a fault")
                .to_string();
            Ok((
                outside,
                error,
                crate::native_exceptions::report(&engine).is_none(),
            ))
        })()
        .unwrap();
        assert!(!observations.0);
        assert!(observations.1.contains("Advertised KVM"));
        assert!(observations.2);
    }
}
