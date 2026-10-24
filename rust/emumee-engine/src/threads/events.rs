//! Initial non-alertable kernel event waits, using actual CPU continuations.
use super::*;
pub(super) fn prepare(engine: &mut Unicorn<Trace>) -> Result<()> {
    ensure!(
        engine.get_data().apis.kernel_mode,
        "Kernel events require a native driver target"
    );
    ensure!(
        engine.get_data().apis.kernel.save().0 <= 2,
        "Event operation above DISPATCH_LEVEL"
    );
    engine.get_data_mut().clock.flush_cycles()?;
    if engine.get_data().threads.is_none() {
        engine.get_data_mut().threads = Some(ThreadExecution::new(
            engine.get_data().instructions,
            engine.get_data().architecture,
        )?);
    }
    validate_all(engine)?;
    timers::validate_all(engine)?;
    timers::refresh(engine)?;
    let now = engine.get_data().clock.qpc();
    engine
        .get_data_mut()
        .threads
        .as_mut()
        .unwrap()
        .model
        .advance_to(now)?;
    mirror_all(engine)?;
    Ok(())
}
fn layout(engine: &Unicorn<Trace>, address: u64) -> Result<usize> {
    let size = if engine.get_data().architecture == Architecture::X64 {
        24
    } else {
        16
    };
    range(engine, address, size, P::RW)?;
    Ok(size as usize)
}
pub(super) fn check(engine: &Unicorn<Trace>, address: u64) -> Result<()> {
    let size = layout(engine, address)?;
    let data = uc(engine.mem_read_as_vec(address, size))?;
    let (manual, signaled) = engine
        .get_data()
        .threads
        .as_ref()
        .unwrap()
        .model
        .event_state(address)?;
    ensure!(
        data[0] == u8::from(!manual)
            && data[2] == (size / 4) as u8
            && u32::from_le_bytes(data[4..8].try_into().unwrap()) == u32::from(signaled),
        "Guest event state diverges from scheduler"
    );
    Ok(())
}
pub(crate) fn initialize_event(engine: &mut Unicorn<Trace>, args: &[u64]) -> Result<u64> {
    let address = args[0];
    let size = layout(engine, address)?;
    ensure!(args[1] <= 1 && args[2] <= 1, "Invalid event type/state");
    prepare(engine)?;
    engine
        .get_data_mut()
        .threads
        .as_mut()
        .unwrap()
        .model
        .initialize_event(address, args[1] == 0, args[2] != 0)?;
    let mut header = [0u8; 24];
    header[0] = args[1] as u8;
    header[2] = (size / 4) as u8;
    header[4..8].copy_from_slice(&(args[2] as u32).to_le_bytes());
    let width = engine.get_data().architecture.width();
    for offset in [8, 8 + width] {
        header[offset..offset + width].copy_from_slice(&(address + 8).to_le_bytes()[..width]);
    }
    cpu::write(engine, address, &header[..size])?;
    Ok(0)
}
pub(crate) fn set_event(engine: &mut Unicorn<Trace>, args: &[u64]) -> Result<u64> {
    ensure!(
        args[1] == 0 && args[2] == 0,
        "Event priority boost/Wait=TRUE continuation is not modeled"
    );
    prepare(engine)?;
    check(engine, args[0])?;
    let previous = engine
        .get_data_mut()
        .threads
        .as_mut()
        .unwrap()
        .model
        .set_event(args[0])?;
    mirror_all(engine)?;
    Ok(u64::from(previous))
}
pub(crate) fn reset_event(engine: &mut Unicorn<Trace>, address: u64) -> Result<u64> {
    prepare(engine)?;
    check(engine, address)?;
    let previous = engine
        .get_data_mut()
        .threads
        .as_mut()
        .unwrap()
        .model
        .reset_event(address)?;
    mirror_all(engine)?;
    Ok(u64::from(previous))
}
pub(crate) fn wait_event(engine: &mut Unicorn<Trace>, args: &[u64]) -> Result<u64> {
    if let Some(value) = timers::wait_one(engine, args)? {
        return Ok(value);
    }
    if let Some(value) = super::object_references::wait_thread(engine, args)? {
        return Ok(value);
    }
    ensure!(
        args[1] == 0 && args[2] == 0 && args[3] == 0,
        "Only non-alertable Executive/KernelMode event waits are modeled"
    );
    prepare(engine)?;
    check(engine, args[0])?;
    validate_all(engine)?;
    let now = engine.get_data().clock.qpc();
    let mut poll = false;
    let deadline = if args[4] == 0 {
        None
    } else {
        range(engine, args[4], 8, P::READ)?;
        let value = i64::from_le_bytes(uc(engine.mem_read_as_vec(args[4], 8))?.try_into().unwrap());
        poll = value == 0;
        let interval = if value < 0 {
            value.unsigned_abs()
        } else {
            (value as u64).saturating_sub(engine.get_data().clock.utc_filetime)
        };
        Some(
            now.checked_add(interval)
                .context("Event timeout exceeds guest clock range")?,
        )
    };
    let irql = engine.get_data().apis.kernel.save().0;
    ensure!(irql <= 1 || poll, "Nonzero event wait above APC_LEVEL");
    let pc = uc(engine.pc_read())?;
    let event = engine.get_data().apis.next_event_index();
    let threads = engine.get_data_mut().threads.as_mut().unwrap();
    let result = match threads
        .model
        .wait(&[Object::Event(args[0])], false, deadline, irql)?
    {
        WaitOutcome::Immediate(emumee_core::scheduler::WaitResult::Satisfied(0)) => 0,
        WaitOutcome::Immediate(emumee_core::scheduler::WaitResult::Timeout) => 0x102,
        WaitOutcome::Blocked => {
            let thread = threads.current_slot;
            threads.waiting.insert(
                thread,
                WaitContinuation {
                    address: args[0],
                    pc,
                    old_irql: irql,
                    event,
                    event_object: true,
                    thread_object: false,
                },
            );
            threads.waits += 1;
            engine.get_data_mut().thread_action = Some(Action::Wait { thread });
            0
        }
        _ => bail!("Invalid single-event wait result"),
    };
    mirror_all(engine)?;
    Ok(result)
}

pub(super) fn validate_all(engine: &Unicorn<Trace>) -> Result<()> {
    if let Some(threads) = engine.get_data().threads.as_ref() {
        for (address, _, _) in threads.model.event_states() {
            check(engine, address)?;
        }
    }
    Ok(())
}
pub(super) fn mirror_model(
    engine: &mut Unicorn<Trace>,
    threads: &mut ThreadExecution,
) -> Result<()> {
    threads.wait_effect_failed = true;
    for (address, _, signaled) in threads.model.event_states() {
        // Full preflight was required before mutation; recheck output span before
        // each bounded mirror so a failure is explicit and cannot resume guest.
        range(engine, address + 4, 4, P::WRITE)?;
        cpu::write(engine, address + 4, &u32::from(signaled).to_le_bytes())?;
    }
    timers::mirror_model(engine, threads)?;
    threads.wait_effect_failed = false;
    Ok(())
}
pub(super) fn mirror_all(engine: &mut Unicorn<Trace>) -> Result<()> {
    let states = engine
        .get_data()
        .threads
        .as_ref()
        .map(|threads| threads.model.event_states().collect::<Vec<_>>())
        .unwrap_or_default();
    if let Some(threads) = engine.get_data_mut().threads.as_mut() {
        threads.wait_effect_failed = true;
    }
    for (address, _, signaled) in states {
        range(engine, address + 4, 4, P::WRITE)?;
        cpu::write(engine, address + 4, &u32::from(signaled).to_le_bytes())?;
    }
    timers::mirror_all(engine)?;
    if let Some(threads) = engine.get_data_mut().threads.as_mut() {
        threads.wait_effect_failed = false;
    }
    Ok(())
}
