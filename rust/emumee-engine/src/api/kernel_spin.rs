//! Actual initialized spin words and ordinary-CPU exclusion. State is owned by
//! the existing KernelState, never an independent wait queue or host lock.
use super::*;
use anyhow::Context as _;
use emumee_core::kernel_spin::{Backing, Input, Operation, Owner};
use emumee_core::modules::ModuleOrigin;
use unicorn_engine::unicorn_const::HookType;
pub(super) fn routines(arch: Architecture) -> &'static [&'static str] {
    match arch {
        Architecture::X64 => &[
            "KeInitializeSpinLock",
            "KeAcquireSpinLockRaiseToDpc",
            "KeReleaseSpinLock",
        ],
        Architecture::X86 => &[
            "KeInitializeSpinLock",
            "KfAcquireSpinLock",
            "KfReleaseSpinLock",
        ],
    }
}
#[derive(Clone, Copy)]
pub(super) enum Call {
    Initialize,
    Acquire,
    Release,
}
pub(super) fn definition(arch: Architecture, name: &str) -> Option<(Call, usize, C, T)> {
    Some(match (arch, name) {
        (_, "KeInitializeSpinLock") => (Call::Initialize, 1, C::Stdcall, T::Void),
        (Architecture::X64, "KeAcquireSpinLockRaiseToDpc") => {
            (Call::Acquire, 1, C::Stdcall, T::U32)
        }
        (Architecture::X64, "KeReleaseSpinLock") => (Call::Release, 2, C::Stdcall, T::Void),
        (Architecture::X86, "KfAcquireSpinLock") => (Call::Acquire, 1, C::Fastcall, T::U32),
        (Architecture::X86, "KfReleaseSpinLock") => (Call::Release, 2, C::Fastcall, T::Void),
        _ => return None,
    })
}
fn owner(engine: &Unicorn<Trace>) -> Owner {
    Owner {
        processor: engine.get_data().cpu.processor,
        thread: crate::threads::thread_address(engine),
    }
}
fn intersects(a: u64, n: u64, b: u64, m: u64) -> bool {
    a.checked_add(n).is_none_or(|end| b < end) && b.checked_add(m).is_none_or(|end| a < end)
}
pub(crate) fn require_write(engine: &Unicorn<Trace>, address: u64, size: u64) -> Result<()> {
    if size == 0 {
        return Ok(());
    }
    let state = &engine.get_data().apis.kernel;
    if state.spin_native_write == Some((address, size)) {
        return Ok(());
    }
    ensure!(
        !state.spin.overlaps(address, size),
        "API mutation of an initialized spin word is unsupported"
    );
    Ok(())
}
pub(crate) fn require_mapping_change(
    engine: &Unicorn<Trace>,
    address: u64,
    size: u64,
) -> Result<()> {
    // VirtualFree RELEASE reports size0; still protect a registered word atbase.
    ensure!(
        !engine
            .get_data()
            .apis
            .kernel
            .spin
            .overlaps(address, size.max(1)),
        "Memory mapping change overlaps an initialized spin word"
    );
    Ok(())
}
pub(crate) fn require_alias(engine: &Unicorn<Trace>, address: u64, size: u64) -> Result<()> {
    ensure!(
        !engine.get_data().apis.kernel.spin.overlaps(address, size),
        "MDL alias/descriptor overlaps an initialized spin word"
    );
    Ok(())
}
pub(crate) fn require_pool_release(engine: &Unicorn<Trace>, base: u64, size: u64) -> Result<()> {
    engine
        .get_data()
        .apis
        .kernel
        .spin
        .require_release(base, size)?;
    Ok(())
}
pub(crate) fn retired_pool(engine: &mut Unicorn<Trace>, base: u64, size: u64) -> Result<()> {
    engine.get_data_mut().apis.kernel.spin.retire(base, size)?;
    Ok(())
}
pub(crate) fn require_no_held(engine: &Unicorn<Trace>) -> Result<()> {
    ensure!(
        engine.get_data().apis.kernel.spin.held().next().is_none(),
        "IPI entry while holding a spin lock is outside the supported owner profile"
    );
    Ok(())
}
pub(crate) fn require_lower(engine: &Unicorn<Trace>, new: u8) -> Result<()> {
    engine
        .get_data()
        .apis
        .kernel
        .spin
        .require_lower(owner(engine), new)?;
    Ok(())
}
pub(crate) fn require_exit(engine: &Unicorn<Trace>) -> Result<()> {
    engine
        .get_data()
        .apis
        .kernel
        .spin
        .require_exit(owner(engine))?;
    Ok(())
}
fn checked_current_owner(engine: &Unicorn<Trace>, actual: u8) -> Result<()> {
    let current = owner(engine);
    ensure!(
        engine
            .get_data()
            .apis
            .kernel
            .spin
            .held()
            .all(|r| r.held.unwrap().owner == current),
        "Spin owner diverges from current ordinary processor/thread context"
    );
    require_lower(engine, actual)
}
pub(crate) fn require_ready(engine: &mut Unicorn<Trace>) -> Result<()> {
    engine.get_data().apis.kernel.spin.ready()?;
    if engine.get_data().apis.kernel_mode {
        let actual = super::kernel_sync::observe_irql(engine)?;
        checked_current_owner(engine, actual)?;
    }
    Ok(())
}
pub(crate) fn quantum_eligible(engine: &mut Unicorn<Trace>) -> Result<bool> {
    engine.get_data().apis.kernel.spin.ready()?;
    let actual = super::kernel_sync::observe_irql(engine)?;
    checked_current_owner(engine, actual)?;
    Ok(actual < 2)
}
pub(crate) fn completion_error(engine: &Unicorn<Trace>) -> Option<String> {
    engine
        .get_data()
        .apis
        .kernel
        .spin
        .ready()
        .err()
        .map(|e| e.to_string())
}
fn backing(engine: &Unicorn<Trace>, address: u64, width: u64) -> Result<Backing> {
    ensure!(
        address != 0 && address % width == 0,
        "Kernel spin null or unaligned word"
    );
    super::require_without_spin_guard(engine, address, width, P::RW)?;
    let end = address
        .checked_add(width)
        .context("Spin word range overflow")?;
    let mdls = &engine.get_data().apis.mdls.model;
    ensure!(
        !mdls
            .aliases()
            .values()
            .any(|a| intersects(address, width, a.source_base, a.size)
                || intersects(address, width, a.base, a.size)),
        "Spin backing has an unsupported MDL alias"
    );
    ensure!(
        !mdls.descriptors().iter().any(|(pointer, d)| intersects(
            address,
            width,
            *pointer,
            d.layout.size().into()
        ) || intersects(
            address,
            width,
            d.layout.buffer(),
            d.layout.length().into()
        )),
        "Spin backing has an unsupported MDL descriptor"
    );
    if let Some(a) = engine
        .get_data()
        .apis
        .pool
        .allocations
        .values()
        .find(|a| address >= a.base && end <= a.base + a.requested)
    {
        ensure!(!a.paged, "Spin backing cannot be paged Pool");
        return Ok(Backing::NonpagedPool {
            base: a.base,
            requested: a.requested,
            mapped: a.mapped,
        });
    }
    if let Some(module) = engine.get_data().apis.modules.containing(address) {
        ensure!(
            end <= module.base + module.size
                && !engine
                    .get_data()
                    .apis
                    .memory
                    .allows(address, width, P::EXECUTE),
            "Spin image backing must be writable resident data"
        );
        ensure!(
            module.provenance().is_some_and(|p| matches!(
                p.origin,
                ModuleOrigin::OwnedGenerated
                    | ModuleOrigin::ConfiguredGuest
                    | ModuleOrigin::SubmittedDriver
            )),
            "Spin image backing lacks actual guest-image provenance"
        );
        return Ok(Backing::Image {
            base: module.base,
            size: module.size,
        });
    }
    bail!("Spin backing is outside initialized guest-image/nonpaged-Pool profile")
}
fn install_guard(engine: &mut Unicorn<Trace>) -> Result<()> {
    if engine.get_data().apis.kernel.spin_guard_installed {
        return Ok(());
    }
    uc(engine.add_mem_hook(HookType::MEM_WRITE,1,0,|engine,_,address,size,_|{
        if require_write(engine,address,size as u64).is_err(){
            // Unicorn may already have committed a guest instruction's write;
            // retain truthful uncertain effects and categorically stop/resume.
            engine.get_data_mut().apis.kernel.spin.native_effect_failure=true;
            let denials=engine.get_data().apis.kernel.spin_guest_denials.saturating_add(1);
            engine.get_data_mut().apis.kernel.spin_guest_denials=denials;
            engine.get_data_mut().apis.fault=Some("Direct guest mutation of an initialized spin word is unsupported; native effects uncertain".into());
            let _=engine.emu_stop();
        }
        true
    }))?;
    engine.get_data_mut().apis.kernel.spin_guard_installed = true;
    Ok(())
}
pub(super) fn call(engine: &mut Unicorn<Trace>, call: Call, args: &[u64]) -> Result<u64> {
    ensure!(
        args.len() == if matches!(call, Call::Release) { 2 } else { 1 },
        "Spin argument count mismatch"
    );
    require_ready(engine)?;
    let irql = super::kernel_sync::observe_irql(engine)?;
    let arch = engine.get_data().architecture;
    let width = arch.width();
    let backing = backing(engine, args[0], width as u64)?;
    let bytes = read(engine, args[0], width as u64)?;
    let mut word = [0; 8];
    word[..width].copy_from_slice(&bytes);
    let operation = match call {
        Call::Initialize => Operation::Initialize,
        Call::Acquire => Operation::Acquire,
        Call::Release => Operation::Release {
            new_irql: args[1] as u8,
        },
    };
    let plan = engine.get_data().apis.kernel.spin.plan(
        operation,
        Input {
            architecture: arch,
            address: args[0],
            word: u64::from_le_bytes(word),
            backing,
            owner: owner(engine),
            irql,
        },
    )?;
    let result = plan.result;
    let critical = engine.get_data().apis.kernel.save().1;
    engine
        .get_data_mut()
        .apis
        .kernel
        .spin
        .begin(plan.attempt.clone());
    install_guard(engine)?;
    engine.get_data_mut().apis.kernel.spin_native_write = Some((args[0], width as u64));
    let write = crate::cpu::write(engine, args[0], &plan.attempt.after.to_le_bytes()[..width]);
    engine.get_data_mut().apis.kernel.spin_native_write = None;
    write?;
    engine
        .get_data_mut()
        .apis
        .kernel
        .restore((plan.attempt.new_irql, critical));
    crate::kernel_cpu::sync(engine, crate::threads::thread_address(engine))?;
    engine.get_data_mut().apis.kernel.spin.complete(plan);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn engine(arch: Architecture) -> crate::NativeEngine {
        let mut e = crate::new_engine(arch).unwrap();
        e.get_data_mut().apis.target(arch, true).unwrap();
        crate::kernel_cpu::initialize(&mut e).unwrap();
        e.get_data_mut()
            .apis
            .memory
            .map(0x10000, 0x4000, P::RW, Some(4), "spin native source image")
            .unwrap();
        e.mem_map(0x10000, 0x4000, Prot::READ | Prot::WRITE)
            .unwrap();
        let pe = emumee_core::pe::PeImage::parse(
            &emumee_core::fixtures::counted_driver(arch, 1),
            "spin-test.sys",
        )
        .unwrap();
        e.get_data_mut()
            .apis
            .modules
            .add_with_path(
                "spin-test.sys",
                0x10000,
                &pe,
                r"C:\fixtures\spin-test.sys",
                ModuleOrigin::OwnedGenerated,
            )
            .unwrap();
        e.get_data_mut().apis.last_error = 0x12345678;
        e
    }
    fn word(e: &Unicorn<Trace>, address: u64) -> u64 {
        let mut b = [0; 8];
        let width = e.get_data().architecture.width();
        b[..width].copy_from_slice(&e.mem_read_as_vec(address, width).unwrap());
        u64::from_le_bytes(b)
    }
    #[test]
    fn native_exact_names_have_real_architecture_specific_conventions_and_no_guessed_aliases() {
        for arch in [Architecture::X86, Architecture::X64] {
            let init = super::super::definition(arch, "ntoskrnl.exe", "KeInitializeSpinLock");
            assert!(matches!(init.model, Model::Spin(_)));
            assert_eq!(
                (init.count, init.convention, init.returns),
                (1, C::Stdcall, T::Void)
            );
            let names = if arch == Architecture::X64 {
                ["KeAcquireSpinLockRaiseToDpc", "KeReleaseSpinLock"]
            } else {
                ["KfAcquireSpinLock", "KfReleaseSpinLock"]
            };
            for (index, name) in names.into_iter().enumerate() {
                let b = super::super::definition(arch, "ntoskrnl.exe", name);
                assert!(matches!(b.model, Model::Spin(_)));
                assert_eq!(
                    (b.count, b.convention, b.returns),
                    (
                        index + 1,
                        if arch == Architecture::X64 {
                            C::Stdcall
                        } else {
                            C::Fastcall
                        },
                        if index == 0 { T::U32 } else { T::Void }
                    )
                );
                assert!(!matches!(
                    super::super::definition(arch, "hal.dll", name).model,
                    Model::Spin(_)
                ));
            }
            for name in if arch == Architecture::X64 {
                ["KfAcquireSpinLock", "KfReleaseSpinLock"]
            } else {
                ["KeAcquireSpinLockRaiseToDpc", "KeReleaseSpinLock"]
            } {
                assert!(!matches!(
                    super::super::definition(arch, "ntoskrnl.exe", name).model,
                    Model::Spin(_)
                ));
            }
        }
    }
    #[test]
    fn actual_word_cr8_pcr_nested_saved_irql_and_critical_depth_are_preserved() {
        for arch in [Architecture::X86, Architecture::X64] {
            let mut e = engine(arch);
            e.get_data_mut().apis.kernel.restore((1, 7));
            let thread = crate::threads::thread_address(&e);
            crate::kernel_cpu::sync(&mut e, thread).unwrap();
            for address in [0x12000, 0x12010] {
                call(&mut e, Call::Initialize, &[address]).unwrap();
                assert_eq!(word(&e, address), 0);
            }
            assert_eq!(call(&mut e, Call::Acquire, &[0x12000]).unwrap(), 1);
            assert_eq!(call(&mut e, Call::Acquire, &[0x12010]).unwrap(), 2);
            assert_eq!(word(&e, 0x12000), 1);
            assert_eq!(e.get_data().apis.kernel.save(), (2, 7));
            assert!(call(&mut e, Call::Release, &[0x12000, 1]).is_err());
            call(&mut e, Call::Release, &[0x12010, 2]).unwrap();
            call(&mut e, Call::Release, &[0x12000, 1]).unwrap();
            assert_eq!(e.get_data().apis.kernel.save(), (1, 7));
            assert_eq!(word(&e, 0x12000), 0);
            assert_eq!(super::super::kernel_sync::observe_irql(&mut e).unwrap(), 1);
            assert_eq!(e.get_data().apis.last_error, 0x12345678);
        }
    }
    #[test]
    fn divergent_words_wrong_irql_direct_write_and_protection_are_explicit_preflight_failures() {
        for arch in [Architecture::X86, Architecture::X64] {
            let mut e = engine(arch);
            call(&mut e, Call::Initialize, &[0x12000]).unwrap();
            e.mem_write(0x12000, &1u64.to_le_bytes()[..arch.width()])
                .unwrap();
            assert!(
                call(&mut e, Call::Acquire, &[0x12000])
                    .unwrap_err()
                    .to_string()
                    .contains("divergent or busy")
            );
            e.mem_write(0x12000, &0u64.to_le_bytes()[..arch.width()])
                .unwrap();
            call(&mut e, Call::Acquire, &[0x12000]).unwrap();
            assert!(require_write(&e, 0x12000, 1).is_err());
            assert!(require_mapping_change(&e, 0x12000, 0).is_err());
            assert!(require_lower(&e, 0).is_err());
            assert!(require_exit(&e).is_err());
            assert!(require_no_held(&e).is_err());
            assert!(!e.get_data().apis.kernel.spin.native_effect_failure);
            assert_eq!(word(&e, 0x12000), 1);
        }
    }
    #[test]
    fn genuine_nonpaged_pool_free_guard_retirement_and_reused_backing_never_alias_old_ownership() {
        for arch in [Architecture::X86, Architecture::X64] {
            let mut e = engine(arch);
            let address = pool::call(
                &mut e,
                Model::PoolTagged,
                &[0, 16, u32::from_le_bytes(*b"Spin").into()],
            )
            .unwrap();
            call(&mut e, Call::Initialize, &[address]).unwrap();
            call(&mut e, Call::Acquire, &[address]).unwrap();
            assert!(pool::call(&mut e, Model::PoolFree, &[address]).is_err());
            call(&mut e, Call::Release, &[address, 0]).unwrap();
            pool::call(&mut e, Model::PoolFree, &[address]).unwrap();
            assert!(e.get_data().apis.kernel.spin.records().all(|r| !r.live));
            let reused = pool::call(
                &mut e,
                Model::PoolTagged,
                &[0, 16, u32::from_le_bytes(*b"Spin").into()],
            )
            .unwrap();
            assert_eq!(reused, address);
            assert!(call(&mut e, Call::Acquire, &[reused]).is_err());
            call(&mut e, Call::Initialize, &[reused]).unwrap();
            call(&mut e, Call::Acquire, &[reused]).unwrap();
            call(&mut e, Call::Release, &[reused, 0]).unwrap();
        }
    }
    #[test]
    fn paged_arbitrary_alias_and_readonly_backing_do_not_become_locks() {
        for arch in [Architecture::X86, Architecture::X64] {
            let mut e = engine(arch);
            let paged = pool::call(
                &mut e,
                Model::PoolTagged,
                &[1, 16, u32::from_le_bytes(*b"Spin").into()],
            )
            .unwrap();
            assert!(
                call(&mut e, Call::Initialize, &[paged])
                    .unwrap_err()
                    .to_string()
                    .contains("paged Pool")
            );
            for address in [0, 0x12001, 0x13ffc] {
                assert!(call(&mut e, Call::Initialize, &[address]).is_err());
            }
            e.get_data_mut()
                .apis
                .memory
                .protect(0x12000, 4096, P::READ)
                .unwrap();
            e.mem_protect(0x12000, 4096, Prot::READ).unwrap();
            assert!(call(&mut e, Call::Initialize, &[0x12000]).is_err());
            assert_eq!(e.get_data().apis.kernel.spin.initializations, 0);
        }
    }
    #[test]
    fn actual_existing_mdl_alias_and_future_descriptor_creation_cannot_bypass_spin_words() {
        for arch in [Architecture::X86, Architecture::X64] {
            let mut e = engine(arch);
            let address = pool::call(
                &mut e,
                Model::PoolTagged,
                &[512, 16, u32::from_le_bytes(*b"Spin").into()],
            )
            .unwrap();
            let descriptor =
                mdl::call(&mut e, mdl::Call::Allocate, &[address, 16, 0, 0, 0]).unwrap();
            mdl::call(&mut e, mdl::Call::Build, &[descriptor]).unwrap();
            mdl::call(&mut e, mdl::Call::Map, &[descriptor, 1, 1, 0, 0, 0]).unwrap();
            assert!(
                call(&mut e, Call::Initialize, &[address])
                    .unwrap_err()
                    .to_string()
                    .contains("unsupported MDL alias")
            );
            let other = pool::call(
                &mut e,
                Model::PoolTagged,
                &[512, 16, u32::from_le_bytes(*b"Spin").into()],
            )
            .unwrap();
            call(&mut e, Call::Initialize, &[other]).unwrap();
            assert!(
                mdl::call(&mut e, mdl::Call::Allocate, &[other, 16, 0, 0, 0])
                    .unwrap_err()
                    .to_string()
                    .contains("initialized spin word")
            );
        }
    }
    #[test]
    fn failed_native_irql_publication_is_sticky_with_honest_written_word_and_pending_owner() {
        let mut e = engine(Architecture::X64);
        call(&mut e, Call::Initialize, &[0x12000]).unwrap();
        let pcr = crate::kernel_cpu::current_pcr(&e).unwrap();
        e.mem_unmap(pcr, 4096).unwrap();
        assert!(call(&mut e, Call::Acquire, &[0x12000]).is_err());
        assert_eq!(word(&e, 0x12000), 1);
        assert!(e.get_data().apis.kernel.spin.native_effect_failure);
        assert!(
            !e.get_data()
                .apis
                .kernel
                .spin
                .last_attempt
                .as_ref()
                .unwrap()
                .completed
        );
        assert_eq!(e.get_data().apis.kernel.spin.held().count(), 0);
        assert!(require_ready(&mut e).is_err());
    }
}
