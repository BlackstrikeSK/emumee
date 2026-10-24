//! Exact legacy scalar synchronization. No synthetic waiters or owner records.
use super::*;
use emumee_core::kernel_sync::{self as scalar_sync, Blocked, Operation as O};
#[derive(Clone, Copy)]
pub(super) enum Call {
    RundownInitialize,
    RundownAcquire,
    RundownRelease,
    RundownWait,
    PushInitialize,
    PushAcquire,
    PushRelease,
    Raise,
    Lower,
    AllApcsDisabled,
    ApcsDisabled,
    PreviousMode,
}
pub(super) const ROUTINES: &[&str] = &[
    "ExInitializeRundownProtection",
    "ExAcquireRundownProtection",
    "ExReleaseRundownProtection",
    "ExWaitForRundownProtectionRelease",
    "ExInitializePushLock",
    "ExAcquirePushLockExclusiveEx",
    "ExReleasePushLockExclusiveEx",
    "KfRaiseIrql",
    "KfLowerIrql",
    "KeAreAllApcsDisabled",
    "KeAreApcsDisabled",
    "ExGetPreviousMode",
];
#[derive(Clone, Debug, Serialize)]
pub struct Observation {
    pub operation: &'static str,
    pub address: u64,
    pub width: usize,
    pub before: u64,
    pub after: u64,
    pub wrote: bool,
    pub completed: bool,
}
pub(super) fn definition(module: &str, name: &str) -> Option<(Call, usize, C, T)> {
    if module != "ntoskrnl" {
        return None;
    }
    use Call::*;
    Some(match name {
        "ExInitializeRundownProtection" => (RundownInitialize, 1, C::Fastcall, T::Void),
        "ExAcquireRundownProtection" => (RundownAcquire, 1, C::Fastcall, T::U32),
        "ExReleaseRundownProtection" => (RundownRelease, 1, C::Fastcall, T::Void),
        "ExWaitForRundownProtectionRelease" => (RundownWait, 1, C::Fastcall, T::Void),
        "ExInitializePushLock" => (PushInitialize, 1, C::Stdcall, T::Void),
        "ExAcquirePushLockExclusiveEx" => (PushAcquire, 2, C::Fastcall, T::Void),
        "ExReleasePushLockExclusiveEx" => (PushRelease, 2, C::Fastcall, T::Void),
        "KfRaiseIrql" => (Raise, 1, C::Fastcall, T::U32),
        "KfLowerIrql" => (Lower, 1, C::Fastcall, T::Void),
        "KeAreAllApcsDisabled" => (AllApcsDisabled, 0, C::Stdcall, T::U32),
        "KeAreApcsDisabled" => (ApcsDisabled, 0, C::Stdcall, T::U32),
        "ExGetPreviousMode" => (PreviousMode, 0, C::Stdcall, T::U32),
        _ => return None,
    })
}
/// Refresh actual processor authority before an API can overwrite the mirror.
/// Active IPI entry validation remains earlier in the common dispatch path.
pub(crate) fn observe_irql(engine: &mut Unicorn<Trace>) -> Result<u8> {
    ensure!(
        engine.get_data().apis.kernel_mode,
        "Kernel synchronization requires a native driver target"
    );
    let pcr = crate::kernel_cpu::current_pcr(engine)?;
    ensure!(
        uc(engine.reg_read(RegisterX86::CS))? & 3 == 0,
        "Kernel synchronization requires actual CPL0"
    );
    let wide = engine.get_data().architecture == Architecture::X64;
    let irql = if wide {
        let value = uc(engine.reg_read(RegisterX86::CR8))?;
        ensure!(value <= 15, "Actual x64 IRQL exceeds architectural width");
        value as u8
    } else {
        read(engine, pcr + 0x24, 1)?[0]
    };
    ensure!(
        irql <= if wide { 15 } else { 31 },
        "Actual IRQL exceeds processor profile"
    );
    let critical = engine.get_data().apis.kernel.save().1;
    engine.get_data_mut().apis.kernel.restore((irql, critical));
    Ok(irql)
}
pub(super) fn call(engine: &mut Unicorn<Trace>, call: Call, args: &[u64]) -> Result<u64> {
    use Call::*;
    let irql = observe_irql(engine)?;
    let critical = engine.get_data().apis.kernel.save().1;
    match call {
        Raise => {
            let new = args[0] as u8;
            let maximum = if engine.get_data().architecture == Architecture::X64 {
                15
            } else {
                31
            };
            ensure!(new >= irql && new <= maximum, "Invalid IRQL raise");
            engine.get_data_mut().apis.kernel.restore((new, critical));
            crate::kernel_cpu::sync(engine, crate::threads::thread_address(engine))?;
            return Ok(irql.into());
        }
        Lower => {
            let new = args[0] as u8;
            super::kernel_spin::require_lower(engine, new)?;
            ensure!(new <= irql, "Invalid IRQL lower");
            engine.get_data_mut().apis.kernel.restore((new, critical));
            crate::kernel_cpu::sync(engine, crate::threads::thread_address(engine))?;
            return Ok(0);
        }
        AllApcsDisabled => {
            ensure!(irql <= 2, "APC query above DISPATCH_LEVEL");
            return Ok(u64::from(irql >= 1));
        }
        ApcsDisabled => {
            ensure!(irql <= 2, "APC query above DISPATCH_LEVEL");
            return Ok(u64::from(critical > 0 || irql >= 1));
        }
        PreviousMode => {
            ensure!(irql <= 2, "Previous-mode query above DISPATCH_LEVEL");
            return Ok(0); // Only actual initialized KernelMode driver callers exist.
        }
        _ => {}
    }
    let op = match call {
        RundownInitialize => O::RundownInitialize,
        RundownAcquire => O::RundownAcquire,
        RundownRelease => O::RundownRelease,
        RundownWait => O::RundownWait,
        PushInitialize => O::PushInitialize,
        PushAcquire => O::PushAcquire,
        PushRelease => O::PushRelease,
        _ => unreachable!(),
    };
    let limit = if matches!(call, PushInitialize) {
        if engine.get_data().architecture == Architecture::X64 {
            15
        } else {
            31
        }
    } else if matches!(call, RundownAcquire | RundownRelease | PushRelease) {
        2
    } else {
        1
    };
    ensure!(
        irql <= limit,
        "Synchronization operation above supported IRQL"
    );
    if matches!(call, PushAcquire | PushRelease) {
        ensure!(
            critical > 0 || irql >= 1,
            "Push-lock operation requires disabled normal kernel APCs"
        );
    }
    let width = engine.get_data().architecture.width();
    let address = args[0];
    ensure!(
        address % width as u64 == 0,
        "Synchronization word is not pointer aligned"
    );
    require(engine, address, width as u64, P::RW)?;
    let raw = read(engine, address, width as u64)?;
    let mut bytes = [0u8; 8];
    bytes[..width].copy_from_slice(&raw);
    let effect = scalar_sync::transition(
        engine.get_data().architecture,
        op,
        u64::from_le_bytes(bytes),
        args.get(1).copied().unwrap_or(0),
    )?;
    if let Some(value) = effect.write {
        crate::cpu::write(engine, address, &value.to_le_bytes()[..width])?;
    }
    let operation = match op {
        O::RundownInitialize => "rundown_initialize",
        O::RundownAcquire => "rundown_acquire",
        O::RundownRelease => "rundown_release",
        O::RundownWait => "rundown_wait",
        O::PushInitialize => "push_initialize",
        O::PushAcquire => "push_acquire",
        O::PushRelease => "push_release",
    };
    // Stop evidence only. Subsequent calls always reread the actual guest word.
    engine
        .get_data_mut()
        .apis
        .kernel
        .record_scalar(Observation {
            operation,
            address,
            width,
            before: u64::from_le_bytes(bytes),
            after: effect.write.unwrap_or(u64::from_le_bytes(bytes)),
            wrote: effect.write.is_some(),
            completed: effect.blocked.is_none(),
        });
    match effect.blocked {
        Some(Blocked::Rundown) => bail!("Blocked rundown wait requires kernel thread scheduling"),
        Some(Blocked::PushLock) => {
            bail!("Blocked push-lock acquisition requires kernel thread scheduling")
        }
        None => Ok(effect.result),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_wdk_and_legacy_calling_conventions_do_not_publish_unimplemented_families() {
        for architecture in [Architecture::X86, Architecture::X64] {
            for name in ROUTINES {
                let binding = super::super::definition(architecture, "ntoskrnl.exe", name);
                assert!(matches!(binding.model, Model::NormalSync(_)));
                let expected = if matches!(
                    *name,
                    "ExInitializePushLock"
                        | "KeAreAllApcsDisabled"
                        | "KeAreApcsDisabled"
                        | "ExGetPreviousMode"
                ) {
                    C::Stdcall
                } else {
                    C::Fastcall
                };
                assert_eq!(binding.convention, expected);
                for module in ["hal.dll", "cng.sys", "foreign.dll"] {
                    assert!(matches!(
                        super::super::definition(architecture, module, name).model,
                        Model::Unsupported
                    ));
                }
            }
            let lower = super::super::definition(architecture, "ntoskrnl.exe", "KeLowerIrql");
            assert_eq!(
                (lower.convention, lower.count, lower.returns),
                (C::Fastcall, 1, T::Void)
            );
            for name in [
                "ExAcquireRundownProtectionEx",
                "ExReInitializeRundownProtection",
                "ExRundownCompleted",
                "ExAcquirePushLockSharedEx",
                "ExTryAcquirePushLockExclusiveEx",
            ] {
                assert!(matches!(
                    super::super::definition(architecture, "ntoskrnl.exe", name).model,
                    Model::Unsupported
                ));
            }
        }
    }
}
