//! Legacy-layout timer bodies backed by the sole Scheduler. Actual queued DPC
//! invocation is separately attested by the same native outer execution loop.
use super::*;
use emumee_core::{
    modules::ModuleOrigin,
    scheduler::{Dpc, TimerBacking},
};
use unicorn_engine::unicorn_const::HookType;
#[derive(Clone, Copy)]
pub(crate) enum Call {
    Initialize,
    InitializeEx,
    InitializeDpc,
    Set,
    SetEx,
    Cancel,
}
pub(crate) const ROUTINES: &[&str] = &[
    "KeInitializeTimer",
    "KeInitializeTimerEx",
    "KeInitializeDpc",
    "KeSetTimer",
    "KeSetTimerEx",
    "KeCancelTimer",
];
pub(crate) fn definition(
    arch: Architecture,
    name: &str,
) -> Option<(Call, usize, emumee_core::abi::ReturnType)> {
    use emumee_core::abi::ReturnType as T;
    Some(match name {
        "KeInitializeTimer" => (Call::Initialize, 1, T::Void),
        "KeInitializeTimerEx" => (Call::InitializeEx, 2, T::Void),
        "KeInitializeDpc" => (Call::InitializeDpc, 3, T::Void),
        "KeSetTimer" => (
            Call::Set,
            if arch == Architecture::X86 { 4 } else { 3 },
            T::U32,
        ),
        "KeSetTimerEx" => (
            Call::SetEx,
            if arch == Architecture::X86 { 5 } else { 4 },
            T::U32,
        ),
        "KeCancelTimer" => (Call::Cancel, 1, T::U32),
        _ => return None,
    })
}
fn overlap(a: u64, n: u64, b: u64, m: u64) -> bool {
    a.checked_add(n).is_none_or(|e| b < e) && b.checked_add(m).is_none_or(|e| a < e)
}
pub(crate) fn require_ready(engine: &Unicorn<Trace>) -> Result<()> {
    if let Some(t) = &engine.get_data().threads {
        ensure!(
            !t.timer_effect_failed,
            "Timer native effect failed; execution cannot resume"
        );
        if let Some(stop) = &t.timer_stop {
            bail!("{stop}");
        }
    }
    Ok(())
}
pub(crate) fn require_write(engine: &Unicorn<Trace>, address: u64, size: u64) -> Result<()> {
    if size == 0 {
        return Ok(());
    }
    if let Some(t) = &engine.get_data().threads {
        ensure!(
            !t.model.timer_metadata_overlap(address, size),
            "API mutation of initialized timer/DPC metadata is unsupported"
        );
    }
    Ok(())
}
pub(crate) fn require_mapping_change(
    engine: &Unicorn<Trace>,
    address: u64,
    size: u64,
) -> Result<()> {
    dpc::require_mapping_change(engine, address, size)?;
    if let Some(t) = &engine.get_data().threads {
        ensure!(
            !t.model.timer_metadata_overlap(address, size.max(1)),
            "Memory mapping change overlaps initialized timer/DPC metadata"
        );
    }
    Ok(())
}
pub(crate) fn require_alias(engine: &Unicorn<Trace>, address: u64, size: u64) -> Result<()> {
    dpc::require_alias(engine, address, size)?;
    if let Some(t) = &engine.get_data().threads {
        ensure!(
            !t.model.timer_metadata_overlap(address, size),
            "MDL alias/descriptor overlaps initialized timer/DPC metadata"
        );
    }
    Ok(())
}
pub(crate) fn require_pool_release(engine: &Unicorn<Trace>, address: u64, size: u64) -> Result<()> {
    require_ready(engine)?;
    if let Some(t) = &engine.get_data().threads {
        t.model.require_timer_release(address, size)?;
    }
    Ok(())
}
pub(crate) fn retired_pool(engine: &mut Unicorn<Trace>, address: u64, size: u64) -> Result<()> {
    if let Some(t) = &mut engine.get_data_mut().threads {
        t.model.retire_timer_backing(address, size)?;
    }
    Ok(())
}
fn backing(engine: &Unicorn<Trace>, address: u64, size: u64) -> Result<TimerBacking> {
    let width = engine.get_data().architecture.width() as u64;
    ensure!(
        address != 0 && address % width == 0,
        "Timer/DPC null or unaligned metadata"
    );
    crate::api::require_without_timer_guard(engine, address, size, P::RW)?;
    let end = address
        .checked_add(size)
        .context("Timer/DPC range overflow")?;
    let mdl = &engine.get_data().apis.mdls.model;
    ensure!(
        !mdl.aliases()
            .values()
            .any(|a| overlap(address, size, a.base, a.size)
                || overlap(address, size, a.source_base, a.size))
            && !mdl.descriptors().iter().any(|(p, d)| overlap(
                address,
                size,
                *p,
                d.layout.size().into()
            ) || overlap(
                address,
                size,
                d.layout.buffer(),
                d.layout.length().into()
            )),
        "Timer/DPC backing has unsupported MDL alias/descriptor"
    );
    if let Some(a) = engine
        .get_data()
        .apis
        .pool
        .allocations
        .values()
        .find(|a| address >= a.base && end <= a.base + a.requested)
    {
        ensure!(!a.paged, "Timer/DPC backing cannot be paged Pool");
        return Ok(TimerBacking::NonpagedPool {
            base: a.base,
            requested: a.requested,
            mapped: a.mapped,
        });
    }
    if let Some(m) = engine.get_data().apis.modules.containing(address) {
        ensure!(
            end <= m.base + m.size
                && !engine
                    .get_data()
                    .apis
                    .memory
                    .allows(address, size, P::EXECUTE)
                && m.provenance().is_some_and(|p| matches!(
                    p.origin,
                    ModuleOrigin::OwnedGenerated
                        | ModuleOrigin::ConfiguredGuest
                        | ModuleOrigin::SubmittedDriver
                )),
            "Timer/DPC image backing requires resident writable guest data"
        );
        return Ok(TimerBacking::Image {
            base: m.base,
            size: m.size,
        });
    }
    bail!("Timer/DPC backing outside guest-image/nonpaged-Pool profile")
}
fn bodies(model: &Scheduler) -> Vec<(u64, TimerBacking, Vec<u8>)> {
    model
        .timers()
        .map(|t| (t.address, t.backing, t.bytes()))
        .chain(model.dpcs().map(|d| (d.address, d.backing, d.bytes())))
        .collect()
}
pub(super) fn validate_model(engine: &Unicorn<Trace>, model: &Scheduler) -> Result<()> {
    if model.timers().next().is_none() && model.dpcs().next().is_none() {
        return Ok(());
    }
    // Timer expiration may satisfy mixed waits and consume an Event, so attest
    // the existing event mirror before planning any cross-object acquisition.
    for (address, manual, signaled) in model.event_states() {
        let size = if engine.get_data().architecture == Architecture::X64 {
            24
        } else {
            16
        };
        crate::api::require_without_timer_guard(engine, address, size, P::RW)?;
        let bytes = uc(engine.mem_read_as_vec(address, size as usize))?;
        ensure!(
            bytes[0] == u8::from(!manual)
                && bytes[2] == (size / 4) as u8
                && u32::from_le_bytes(bytes[4..8].try_into().unwrap()) == u32::from(signaled),
            "Guest event state diverges from timer wait scheduler"
        );
    }
    for (address, origin, bytes) in bodies(model) {
        ensure!(
            backing(engine, address, bytes.len() as u64)? == origin,
            "Timer/DPC backing authority diverged"
        );
        ensure!(
            uc(engine.mem_read_as_vec(address, bytes.len()))? == bytes,
            "Guest timer/DPC metadata diverges from scheduler"
        );
    }
    Ok(())
}
pub(super) fn validate_all(engine: &Unicorn<Trace>) -> Result<()> {
    require_ready(engine)?;
    if let Some(t) = &engine.get_data().threads {
        validate_model(engine, &t.model)?;
    }
    Ok(())
}
/// Preflight every output before the first native effect. Candidate state is
/// published only after successful mirrors; failure retains old model+flag.
pub(super) fn publish(
    engine: &mut Unicorn<Trace>,
    threads: &mut ThreadExecution,
    candidate: Scheduler,
) -> Result<()> {
    let old = bodies(&threads.model);
    let next = bodies(&candidate);
    let mut writes = Vec::new();
    for (address, origin, bytes) in next {
        ensure!(
            backing(engine, address, bytes.len() as u64)? == origin,
            "Timer/DPC candidate backing authority diverged"
        );
        if !old.iter().any(|(a, _, b)| *a == address && *b == bytes) {
            writes.push((address, bytes));
        }
    }
    for (address, _, signal) in candidate.event_states() {
        if threads.model.event_state(address)?.1 != signal {
            crate::api::require_without_timer_guard(engine, address + 4, 4, P::WRITE)?;
            writes.push((address + 4, u32::from(signal).to_le_bytes().to_vec()));
        }
    }
    if !writes.is_empty() {
        threads.timer_effect_failed = true;
        install_guards(engine, threads)?;
        for (address, bytes) in writes {
            cpu::write(engine, address, &bytes)?;
        }
        threads.timer_effect_failed = false;
    }
    threads.model = candidate;
    Ok(())
}
pub(super) fn with_threads<T>(
    engine: &mut Unicorn<Trace>,
    operation: impl FnOnce(&mut Unicorn<Trace>, &mut ThreadExecution) -> Result<T>,
) -> Result<T> {
    let mut t = engine
        .get_data_mut()
        .threads
        .take()
        .context("Timer lacks scheduler authority")?;
    let result = operation(engine, &mut t);
    engine.get_data_mut().threads = Some(t);
    result
}
pub(super) fn advance_model(
    engine: &mut Unicorn<Trace>,
    threads: &mut ThreadExecution,
    now: u64,
) -> Result<()> {
    if threads.model.timers().next().is_none() && threads.model.dpcs().next().is_none() {
        threads.model.advance_to(now)?;
        return Ok(());
    }
    validate_model(engine, &threads.model)?;
    let mut candidate = threads.model.clone();
    candidate.advance_to(now)?;
    publish(engine, threads, candidate)
}
pub(super) fn mirror_model(
    engine: &mut Unicorn<Trace>,
    threads: &mut ThreadExecution,
) -> Result<()> {
    // Scheduler wait consumption may have changed only SignalState already.
    let next = bodies(&threads.model);
    for (address, origin, bytes) in &next {
        ensure!(
            backing(engine, *address, bytes.len() as u64)? == *origin,
            "Timer/DPC mirror backing authority diverged"
        );
    }
    if !next.is_empty() {
        threads.timer_effect_failed = true;
        for (address, _, bytes) in next {
            cpu::write(engine, address, &bytes)?;
        }
        threads.timer_effect_failed = false;
    }
    Ok(())
}
pub(super) fn mirror_all(engine: &mut Unicorn<Trace>) -> Result<()> {
    if engine.get_data().threads.is_some() {
        with_threads(engine, mirror_model)?;
    }
    Ok(())
}
pub(crate) fn refresh(engine: &mut Unicorn<Trace>) -> Result<()> {
    require_ready(engine)?;
    if engine
        .get_data()
        .threads
        .as_ref()
        .is_none_or(|t| t.model.timers().next().is_none())
    {
        return Ok(());
    }
    crate::api::kernel_spin::require_ready(engine)?;
    engine.get_data_mut().clock.flush_cycles()?;
    let now = engine.get_data().clock.qpc();
    with_threads(engine, |engine, t| advance_model(engine, t, now))?;
    Ok(())
}
fn install_guards(engine: &mut Unicorn<Trace>, threads: &mut ThreadExecution) -> Result<()> {
    if threads.timer_guards_installed {
        return Ok(());
    }
    uc(engine.add_mem_hook(HookType::MEM_WRITE,1,0,|engine,_,address,size,_|{
        if require_write(engine,address,size as u64).is_err(){let message="Direct guest mutation of initialized timer/DPC metadata; native effects uncertain".to_owned();if let Some(t)=&mut engine.get_data_mut().threads{t.timer_effect_failed=true;t.timer_guest_denials=t.timer_guest_denials.saturating_add(1);t.timer_stop=Some(message.clone());}engine.get_data_mut().apis.fault=Some(message);let _=engine.emu_stop();}true
    }))?;
    uc(
        engine.add_mem_hook(HookType::MEM_READ, 1, 0, |engine, _, address, size, _| {
            let interested = engine
                .get_data()
                .threads
                .as_ref()
                .is_some_and(|t| t.model.timer_read_overlap(address, size as u64));
            if interested && let Err(error) = refresh(engine) {
                let message = format!("{error:#}");
                if let Some(t) = &mut engine.get_data_mut().threads {
                    t.timer_stop = Some(message.clone());
                }
                engine.get_data_mut().apis.fault = Some(message);
                let _ = engine.emu_stop();
            }
            true
        }),
    )?;
    threads.timer_guards_installed = true;
    Ok(())
}
fn prepare(engine: &mut Unicorn<Trace>, observe: bool) -> Result<()> {
    crate::api::kernel_spin::require_ready(engine)?;
    require_ready(engine)?;
    ensure!(
        engine.get_data().apis.kernel_mode && engine.get_data().apis.kernel.save().0 <= 2,
        "Timer API requires initialized kernel context at or below DISPATCH_LEVEL"
    );
    if observe {
        engine.get_data_mut().clock.observe()?;
    } else {
        engine.get_data_mut().clock.flush_cycles()?;
    }
    if engine.get_data().threads.is_none() {
        engine.get_data_mut().threads = Some(ThreadExecution::new(
            engine.get_data().instructions,
            engine.get_data().architecture,
        )?);
    }
    validate_all(engine)?;
    let now = engine.get_data().clock.qpc();
    with_threads(engine, |e, t| advance_model(e, t, now))?;
    Ok(())
}
pub(crate) fn call(engine: &mut Unicorn<Trace>, call: Call, args: &[u64]) -> Result<u64> {
    let arch = engine.get_data().architecture;
    let wide = arch == Architecture::X64;
    let expected = match call {
        Call::Initialize | Call::Cancel => 1,
        Call::InitializeEx => 2,
        Call::InitializeDpc => 3,
        Call::Set => {
            if wide {
                3
            } else {
                4
            }
        }
        Call::SetEx => {
            if wide {
                4
            } else {
                5
            }
        }
    };
    ensure!(args.len() == expected, "Timer API argument count mismatch");
    // Invalid incoming arguments must not expire/rearm another live timer.
    // Only after this preflight do valid timer operations observe guest time.
    match call {
        Call::Initialize | Call::InitializeEx => {
            if matches!(call, Call::InitializeEx) {
                ensure!(args[1] as u32 <= 1, "Invalid kernel timer type");
            }
            let origin = backing(engine, args[0], if wide { 64 } else { 40 })?;
            if let Some(t) = &engine.get_data().threads {
                let mut candidate = t.model.clone();
                let kind = if matches!(call, Call::InitializeEx) {
                    args[1] as u32
                } else {
                    0
                };
                candidate.initialize_timer(args[0], arch, origin, kind == 0)?;
            }
        }
        Call::InitializeDpc => {
            let origin = backing(engine, args[0], if wide { 64 } else { 32 })?;
            if let Some(t) = &engine.get_data().threads {
                let mut candidate = t.model.clone();
                candidate.initialize_dpc(Dpc {
                    address: args[0],
                    architecture: arch,
                    backing: origin,
                    routine: args[1],
                    context: args[2],
                    phase: emumee_core::scheduler::DpcPhase::Idle,
                })?;
            }
            ensure!(
                engine.get_data().apis.memory.allows(args[1], 1, P::EXECUTE)
                    && engine
                        .get_data()
                        .apis
                        .modules
                        .containing(args[1])
                        .and_then(|m| m.provenance())
                        .is_some_and(|p| matches!(
                            p.origin,
                            ModuleOrigin::OwnedGenerated
                                | ModuleOrigin::ConfiguredGuest
                                | ModuleOrigin::SubmittedDriver
                        )),
                "Kernel DPC routine requires actual executable guest image provenance"
            );
        }
        Call::Set | Call::SetEx | Call::Cancel => {
            let model = &engine
                .get_data()
                .threads
                .as_ref()
                .context("unsupported or uninitialized timer")?
                .model;
            model.timer(args[0])?;
            if !matches!(call, Call::Cancel) {
                let at = if wide { 2 } else { 3 };
                let extended = matches!(call, Call::SetEx);
                if extended {
                    ensure!(args[at] as u32 as i32 >= 0, "negative timer period");
                }
                let dpc = args[at + usize::from(extended)];
                if dpc != 0 {
                    model.dpc(dpc)?;
                }
            }
        }
    }
    prepare(
        engine,
        matches!(call, Call::Set | Call::SetEx | Call::Cancel),
    )?;
    if matches!(call, Call::InitializeDpc) {
        dpc::prepare_environment(engine)?;
    }
    let address = args[0];
    let mut candidate = engine.get_data().threads.as_ref().unwrap().model.clone();
    let result = match call {
        Call::Initialize | Call::InitializeEx => {
            let kind = if matches!(call, Call::InitializeEx) {
                args[1] as u32
            } else {
                0
            };
            ensure!(kind <= 1, "Invalid kernel timer type");
            let origin = backing(engine, address, if wide { 64 } else { 40 })?;
            candidate.initialize_timer(address, arch, origin, kind == 0)?;
            0
        }
        Call::InitializeDpc => {
            let origin = backing(engine, address, if wide { 64 } else { 32 })?;
            let routine = args[1];
            ensure!(
                engine.get_data().apis.memory.allows(routine, 1, P::EXECUTE)
                    && engine
                        .get_data()
                        .apis
                        .modules
                        .containing(routine)
                        .and_then(|m| m.provenance())
                        .is_some_and(|p| matches!(
                            p.origin,
                            ModuleOrigin::OwnedGenerated
                                | ModuleOrigin::ConfiguredGuest
                                | ModuleOrigin::SubmittedDriver
                        )),
                "Kernel DPC routine requires actual executable guest image provenance"
            );
            candidate.initialize_dpc(Dpc {
                address,
                architecture: arch,
                backing: origin,
                routine,
                context: args[2],
                phase: emumee_core::scheduler::DpcPhase::Idle,
            })?;
            0
        }
        Call::Cancel => u64::from(candidate.cancel_timer(address)?),
        Call::Set | Call::SetEx => {
            let extended = matches!(call, Call::SetEx);
            let bits = if wide {
                args[1]
            } else {
                args[1] as u32 as u64 | ((args[2] as u32 as u64) << 32)
            };
            let due = bits as i64;
            let at = if wide { 2 } else { 3 };
            let period = if extended { args[at] as u32 as i32 } else { 0 };
            let dpc = args[at + usize::from(extended)];
            let delta = if due < 0 {
                due.unsigned_abs()
            } else {
                (due as u64).saturating_sub(engine.get_data().clock.utc_filetime)
            };
            let horizon = engine
                .get_data()
                .clock
                .qpc()
                .checked_add(delta)
                .context("Timer deadline exceeds guest clock range")?;
            let mut clock = engine.get_data().clock.clone();
            clock.advance_100ns(delta)?;
            let previous = candidate.set_timer(address, horizon, due >= 0, period, dpc)?;
            // Immediate expiration publishes genuine queued work; the native outer
            // loop separately attests callback execution and actual return.
            u64::from(previous)
        }
    };
    with_threads(engine, |e, t| publish(e, t, candidate))?;
    refresh(engine)?;
    Ok(result)
}
pub(crate) fn wait_one(engine: &mut Unicorn<Trace>, args: &[u64]) -> Result<Option<u64>> {
    if engine
        .get_data()
        .threads
        .as_ref()
        .is_none_or(|t| t.model.timer(args[0]).is_err())
    {
        return Ok(None);
    }
    ensure!(
        args[1] == 0 && args[2] as u8 == 0 && args[3] as u8 == 0,
        "Only non-alertable Executive/KernelMode timer waits are modeled"
    );
    // Use the very same multiple-wait continuation and timeout parser with a
    // one-element guest-independent target list, not a fake event or host wait.
    waits::wait_timer(engine, args[0], args[4]).map(Some)
}
pub(crate) fn settle(engine: &mut Unicorn<Trace>, completed: bool) -> Option<String> {
    if completed && let Err(error) = refresh(engine) {
        return Some(format!("{error:#}"));
    }
    if completed {
        completion_error(engine)
    } else {
        require_ready(engine).err().map(|e| format!("{e:#}"))
    }
}
fn completion_error(engine: &Unicorn<Trace>) -> Option<String> {
    let t = engine.get_data().threads.as_ref()?;
    if let Err(error) = require_ready(engine) {
        return Some(format!("{error:#}"));
    }
    if t.model.queued_dpcs().next().is_some() || t.model.active_dpc().is_some() {
        return Some(
            "Unfinished actual DPC work at completion; root observation retained separately".into(),
        );
    }
    t.model.pending_timer_dpc().map(|timer|format!("Inserted timer DPC requires callback scheduling before completion (timer0x{:x},due{},dpc0x{:x}); root return retained separately",timer.address,timer.due,timer.dpc))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn engine(arch: Architecture) -> crate::NativeEngine {
        let mut e = crate::new_engine(arch).unwrap();
        e.get_data_mut().apis.target(arch, true).unwrap();
        crate::kernel_cpu::initialize(&mut e).unwrap();
        let marker = e.get_data().return_marker;
        e.get_data_mut()
            .apis
            .memory
            .map(marker, 4096, P::RX, None, "source owned DPC return page")
            .unwrap();
        e.mem_map(marker, 4096, Prot::READ | Prot::EXEC).unwrap();
        e.get_data_mut()
            .apis
            .memory
            .map(
                0x10000,
                0x4000,
                P::RW,
                Some(4),
                "generated timer test image",
            )
            .unwrap();
        e.mem_map(0x10000, 0x4000, Prot::READ | Prot::WRITE)
            .unwrap();
        let pe = emumee_core::pe::PeImage::parse(
            &emumee_core::fixtures::counted_driver(arch, 1),
            "timer-test.sys",
        )
        .unwrap();
        e.get_data_mut()
            .apis
            .modules
            .add_with_path(
                "timer-test.sys",
                0x10000,
                &pe,
                r"C:\fixtures\timer-test.sys",
                ModuleOrigin::OwnedGenerated,
            )
            .unwrap();
        e.mem_write(0x10000, &[0xc3]).unwrap();
        // Existing generated-image provenance plus actual executable code bytes.
        e.get_data_mut()
            .apis
            .memory
            .protect(0x10000, 4096, P::RX)
            .unwrap();
        e.mem_protect(0x10000, 4096, Prot::READ | Prot::EXEC)
            .unwrap();
        e.get_data_mut().apis.last_error = 0x12345678;
        e
    }
    fn set(
        e: &mut Unicorn<Trace>,
        address: u64,
        due: i64,
        period: Option<i32>,
        dpc: u64,
    ) -> Result<u64> {
        let mut args = vec![address, due as u64];
        if e.get_data().architecture == Architecture::X86 {
            args[1] = due as u32 as u64;
            args.push((due as u64 >> 32) as u32 as u64);
        }
        if let Some(period) = period {
            args.push(period as u32 as u64);
        }
        args.push(dpc);
        call(
            e,
            if period.is_some() {
                Call::SetEx
            } else {
                Call::Set
            },
            &args,
        )
    }
    fn signal(e: &Unicorn<Trace>, address: u64) -> u32 {
        u32::from_le_bytes(
            e.mem_read_as_vec(address + 4, 4)
                .unwrap()
                .try_into()
                .unwrap(),
        )
    }
    #[test]
    fn both_architectures_publish_real_legacy_header_expiration_replacement_and_cancel() {
        for arch in [Architecture::X86, Architecture::X64] {
            let mut e = engine(arch);
            call(&mut e, Call::Initialize, &[0x12000]).unwrap();
            assert_eq!(
                e.mem_read_as_vec(0x12000, 4).unwrap(),
                [8, 0, if arch == Architecture::X64 { 16 } else { 10 }, 0]
            );
            assert_eq!(set(&mut e, 0x12000, -10_000, None, 0).unwrap(), 0);
            assert_eq!(set(&mut e, 0x12000, -20_000, None, 0).unwrap(), 1);
            e.get_data_mut().clock.advance_100ns(30_000).unwrap();
            refresh(&mut e).unwrap();
            assert_eq!(signal(&e, 0x12000), 1);
            assert_eq!(call(&mut e, Call::Cancel, &[0x12000]).unwrap(), 0);
            assert_eq!(e.get_data().apis.last_error, 0x12345678);
            assert!(!e.get_data().threads.as_ref().unwrap().timer_effect_failed);
        }
    }
    #[test]
    fn negative_period_and_unknown_dpc_do_not_publish_or_observe_other_timers() {
        for arch in [Architecture::X86, Architecture::X64] {
            let mut e = engine(arch);
            call(&mut e, Call::Initialize, &[0x12000]).unwrap();
            set(&mut e, 0x12000, -100_000, None, 0).unwrap();
            let before = e.get_data().clock.qpc();
            let bytes = e
                .mem_read_as_vec(0x12000, if arch == Architecture::X64 { 64 } else { 40 })
                .unwrap();
            assert!(set(&mut e, 0x12000, -10_000, Some(-1), 0).is_err());
            assert!(set(&mut e, 0x12000, -10_000, None, 0x12100).is_err());
            assert_eq!(e.get_data().clock.qpc(), before);
            assert_eq!(e.mem_read_as_vec(0x12000, bytes.len()).unwrap(), bytes);
        }
    }
    #[test]
    fn genuine_dpc_metadata_fullwidth_queues_actual_expiration_and_cancel_before_due() {
        for arch in [Architecture::X86, Architecture::X64] {
            let mut e = engine(arch);
            call(&mut e, Call::InitializeDpc, &[0x12100, 0x10000, 0x12345678]).unwrap();
            call(&mut e, Call::Initialize, &[0x12000]).unwrap();
            set(&mut e, 0x12000, -100_000, None, 0x12100).unwrap();
            assert!(
                completion_error(&e)
                    .unwrap()
                    .contains("requires callback scheduling")
            );
            assert_eq!(call(&mut e, Call::Cancel, &[0x12000]).unwrap(), 1);
            assert_eq!(completion_error(&e), None);
            assert_eq!(set(&mut e, 0x12000, 0, None, 0x12100).unwrap(), 0);
            let t = e.get_data().threads.as_ref().unwrap();
            assert!(!t.model.timer(0x12000).unwrap().inserted);
            assert!(t.model.timer(0x12000).unwrap().signaled);
            assert_eq!(t.model.queued_dpcs().collect::<Vec<_>>(), [0x12100]);
            assert_eq!(t.model.dpc_counters().started, 0);
            assert_eq!(signal(&e, 0x12000), 1);
            assert!(!t.timer_effect_failed);
        }
    }
    #[test]
    fn initialized_pool_lifetime_held_refusal_cancel_free_and_fresh_reinitialize_use_real_pool() {
        for arch in [Architecture::X86, Architecture::X64] {
            let mut e = engine(arch);
            let address = crate::api::timer_test_pool(&mut e, Some(512), 0).unwrap();
            call(&mut e, Call::Initialize, &[address]).unwrap();
            set(&mut e, address, -1_000_000, None, 0).unwrap();
            assert!(require_pool_release(&e, address, 4096).is_err());
            call(&mut e, Call::Cancel, &[address]).unwrap();
            crate::api::timer_test_pool(&mut e, None, address).unwrap();
            assert!(
                e.get_data()
                    .threads
                    .as_ref()
                    .unwrap()
                    .model
                    .timers()
                    .next()
                    .is_none()
            );
            let reused = crate::api::timer_test_pool(&mut e, Some(512), 0).unwrap();
            assert_eq!(address, reused);
            assert!(set(&mut e, reused, -1, None, 0).is_err());
            call(&mut e, Call::Initialize, &[reused]).unwrap();
        }
    }
    #[test]
    fn all_owner_guards_preflight_unaligned_paged_alias_and_direct_mutation() {
        for arch in [Architecture::X86, Architecture::X64] {
            let mut e = engine(arch);
            assert!(call(&mut e, Call::Initialize, &[0]).is_err());
            assert!(call(&mut e, Call::Initialize, &[0x12001]).is_err());
            call(&mut e, Call::Initialize, &[0x12000]).unwrap();
            assert!(require_write(&e, 0x12004, 4).is_err());
            assert!(require_alias(&e, 0x12000, 64).is_err());
            assert!(require_mapping_change(&e, 0x12000, 0).is_err());
            let paged = crate::api::timer_test_pool(&mut e, Some(1), 0).unwrap();
            assert!(
                call(&mut e, Call::Initialize, &[paged])
                    .unwrap_err()
                    .to_string()
                    .contains("paged Pool")
            );
            assert!(call(&mut e, Call::InitializeDpc, &[0x12100, 0x12000, 0]).is_err());
        }
    }
    #[test]
    fn failed_real_native_write_is_sticky_without_publishing_candidate_or_fake_body() {
        let mut e = engine(Architecture::X64);
        e.get_data_mut().threads = Some(ThreadExecution::new(0, Architecture::X64).unwrap());
        let mut candidate = e.get_data().threads.as_ref().unwrap().model.clone();
        candidate
            .initialize_timer(
                0x12000,
                Architecture::X64,
                backing(&e, 0x12000, 64).unwrap(),
                true,
            )
            .unwrap();
        e.mem_unmap(0x12000, 4096).unwrap();
        assert!(with_threads(&mut e, |e, t| publish(e, t, candidate)).is_err());
        let t = e.get_data().threads.as_ref().unwrap();
        assert!(t.timer_effect_failed);
        assert!(t.model.timers().next().is_none());
        assert!(require_ready(&e).is_err());
    }
}
