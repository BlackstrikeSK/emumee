//! Non-alertable delay and multiple-object waits on the actual scheduler.
//! Continuations contain guest addresses only; no host waits or synthetic events.
use super::*;
use emumee_core::scheduler::WaitResult;
use std::collections::BTreeSet;
#[derive(Clone)]
pub(super) enum Kind {
    Multiple {
        objects: Vec<(u64, Object)>,
        all: bool,
    },
    Delay {
        deadline: u64,
    },
}
pub(super) struct Continuation {
    pc: u64,
    observation: Option<usize>,
    kind: Kind,
}
fn deadline(engine: &Unicorn<Trace>, pointer: u64, optional: bool) -> Result<(Option<u64>, bool)> {
    if optional && pointer == 0 {
        return Ok((None, false));
    }
    range(engine, pointer, 8, P::READ)?;
    let value = i64::from_le_bytes(uc(engine.mem_read_as_vec(pointer, 8))?.try_into().unwrap());
    let now = engine.get_data().clock.qpc();
    let delta = if value < 0 {
        value.unsigned_abs()
    } else {
        (value as u64).saturating_sub(engine.get_data().clock.utc_filetime)
    };
    let end = now
        .checked_add(delta)
        .context("Kernel wait deadline exceeds guest clock range")?;
    // Validate the same clock arithmetic needed to reach the deadline before
    // changing scheduler/object state. No host sleeping or partial fake wake.
    let mut clock = engine.get_data().clock.clone();
    clock.advance_100ns(delta)?;
    Ok((Some(end), value == 0))
}
fn observation(engine: &Unicorn<Trace>) -> Option<usize> {
    engine.get_data().apis.next_event_index()
}
fn block(engine: &mut Unicorn<Trace>, kind: Kind) -> Result<()> {
    let pc = uc(engine.pc_read())?;
    let observation = observation(engine);
    let threads = engine
        .get_data_mut()
        .threads
        .as_mut()
        .context("Wait continuation lacks scheduler")?;
    let thread = threads.current_slot;
    ensure!(
        !threads.extended_waiting.contains_key(&thread),
        "Duplicate saved kernel wait continuation"
    );
    threads.extended_waiting.insert(
        thread,
        Continuation {
            pc,
            observation,
            kind,
        },
    );
    threads.waits += 1;
    engine.get_data_mut().thread_action = Some(Action::Wait { thread });
    Ok(())
}
pub(crate) fn delay(engine: &mut Unicorn<Trace>, args: &[u64]) -> Result<u64> {
    ensure!(args.len() == 3, "Kernel delay argument count mismatch");
    ensure!(
        args[0] as u8 == 0 && args[1] as u8 == 0,
        "Alertable/UserMode kernel delay is not modeled"
    );
    ensure!(
        engine.get_data().apis.kernel.save().0 <= 1,
        "Kernel delay above APC_LEVEL"
    );
    events::prepare(engine)?;
    let (end, _) = deadline(engine, args[2], false)?;
    let end = end.unwrap();
    let irql = engine.get_data().apis.kernel.save().0;
    let result = engine
        .get_data_mut()
        .threads
        .as_mut()
        .unwrap()
        .model
        .delay_until(end, irql)?;
    match result {
        WaitOutcome::Immediate(WaitResult::Timeout) => Ok(0),
        WaitOutcome::Blocked => {
            block(engine, Kind::Delay { deadline: end })?;
            Ok(0)
        }
        _ => bail!("Kernel delay received a fabricated object satisfaction"),
    }
}
fn targets(engine: &Unicorn<Trace>, addresses: &[u64]) -> Result<Vec<(u64, Object)>> {
    addresses
        .iter()
        .map(|address| {
            let object = if engine
                .get_data()
                .threads
                .as_ref()
                .unwrap()
                .model
                .timer(*address)
                .is_ok()
            {
                Object::Timer(*address)
            } else if let Some(target) =
                crate::api::kernel_thread_objects::wait_target(engine, *address)?
            {
                Object::Thread(target.slot)
            } else {
                events::check(engine, *address)?;
                Object::Event(*address)
            };
            Ok((*address, object))
        })
        .collect()
}
pub(super) fn wait_timer(engine: &mut Unicorn<Trace>, address: u64, timeout: u64) -> Result<u64> {
    events::prepare(engine)?;
    timers::validate_all(engine)?;
    let (end, _) = deadline(engine, timeout, true)?;
    let irql = engine.get_data().apis.kernel.save().0;
    let result = engine.get_data_mut().threads.as_mut().unwrap().model.wait(
        &[Object::Timer(address)],
        false,
        end,
        irql,
    )?;
    events::mirror_all(engine)?;
    match result {
        WaitOutcome::Immediate(WaitResult::Satisfied(0)) => Ok(0),
        WaitOutcome::Immediate(WaitResult::Timeout) => Ok(0x102),
        WaitOutcome::Blocked => {
            block(
                engine,
                Kind::Multiple {
                    objects: vec![(address, Object::Timer(address))],
                    all: false,
                },
            )?;
            Ok(0)
        }
        _ => bail!("Invalid single timer wait result"),
    }
}
pub(crate) fn wait_many(engine: &mut Unicorn<Trace>, args: &[u64]) -> Result<u64> {
    ensure!(
        args.len() == 8,
        "Multiple kernel wait argument count mismatch"
    );
    let count = args[0] as u32 as u64;
    let wait_type = args[2] as u32;
    ensure!(
        (1..=64).contains(&count) && wait_type <= 1,
        "Invalid multiple kernel wait count/type"
    );
    ensure!(
        args[4] as u8 == 0 && args[5] as u8 == 0,
        "Alertable/UserMode multiple kernel wait is not modeled"
    );
    ensure!(
        engine.get_data().apis.kernel.save().0 <= 2,
        "Multiple kernel wait above DISPATCH_LEVEL"
    );
    let width = engine.get_data().architecture.width();
    range(engine, args[1], count * width as u64, P::READ)?;
    ensure!(
        count <= 3 || args[7] != 0,
        "Large kernel wait requires caller wait-block storage"
    );
    if args[7] != 0 {
        let size = if width == 8 { 48 } else { 24 };
        range(engine, args[7], count * size, P::WRITE)?;
    }
    let raw = uc(engine.mem_read_as_vec(args[1], count as usize * width))?;
    let addresses = raw
        .chunks_exact(width)
        .map(|bytes| {
            let mut value = [0u8; 8];
            value[..width].copy_from_slice(bytes);
            u64::from_le_bytes(value)
        })
        .collect::<Vec<_>>();
    ensure!(
        addresses.iter().copied().collect::<BTreeSet<_>>().len() == count as usize,
        "Duplicate dispatcher objects in multiple kernel wait"
    );
    events::prepare(engine)?;
    let objects = targets(engine, &addresses)?;
    let (end, _poll) = deadline(engine, args[6], true)?;
    let irql = engine.get_data().apis.kernel.save().0;
    let all = wait_type == 0;
    let native = objects
        .iter()
        .map(|(_, object)| *object)
        .collect::<Vec<_>>();
    let result = engine
        .get_data_mut()
        .threads
        .as_mut()
        .unwrap()
        .model
        .wait(&native, all, end, irql)?;
    events::mirror_all(engine)?;
    match result {
        WaitOutcome::Immediate(WaitResult::Satisfied(index)) => Ok(index as u64),
        WaitOutcome::Immediate(WaitResult::Timeout) => Ok(0x102),
        WaitOutcome::Blocked => {
            block(engine, Kind::Multiple { objects, all })?;
            Ok(0)
        }
    }
}
/// Called before native/scheduler changes; initialized event bodies and known
/// thread identities must still agree with the actual state, including wait-all.
pub(super) fn validate_all(engine: &Unicorn<Trace>) -> Result<()> {
    events::validate_all(engine)?;
    timers::validate_all(engine)?;
    if let Some(threads) = engine.get_data().threads.as_ref() {
        for continuation in threads.extended_waiting.values() {
            if let Kind::Multiple { objects, .. } = &continuation.kind {
                for (address, object) in objects {
                    if let Object::Thread(slot) = object {
                        let target =
                            crate::api::kernel_thread_objects::wait_target(engine, *address)?
                                .context("Pending multiple wait lost its owned thread")?;
                        ensure!(
                            target.slot == *slot,
                            "Pending multiple wait changed thread identity"
                        );
                    }
                }
            }
        }
    }
    Ok(())
}
pub(super) fn resume(engine: &mut Unicorn<Trace>, pc: u64) -> Result<bool> {
    let Some(threads) = engine.get_data().threads.as_ref() else {
        return Ok(false);
    };
    let current = threads.current_slot;
    let Some(continuation) = threads.extended_waiting.get(&current) else {
        return Ok(false);
    };
    if continuation.pc != pc {
        return Ok(false);
    };
    validate_all(engine)?;
    let threads = engine.get_data().threads.as_ref().unwrap();
    let continuation = threads.extended_waiting.get(&current).unwrap();
    let result = threads
        .model
        .thread(current)
        .and_then(|thread| thread.wait_result.as_ref())
        .context("Kernel wait resumed without a scheduler result")?;
    let (value, effect) = match (&continuation.kind, result) {
        (Kind::Delay { deadline }, WaitResult::Timeout) => {
            ensure!(
                engine.get_data().clock.qpc() >= *deadline,
                "Kernel delay resumed before its real deadline"
            );
            (0, "delay_elapsed")
        }
        (Kind::Multiple { objects, all }, WaitResult::Satisfied(index)) => {
            ensure!(
                *index < objects.len() && (!*all || *index == 0),
                "Multiple wait result index disagrees with object array"
            );
            (*index as u64, "multiple_wait_satisfied")
        }
        (Kind::Multiple { .. }, WaitResult::Timeout) => (0x102, "wait_timeout"),
        _ => bail!("Kernel wait continuation has an invalid scheduler result"),
    };
    let threads = engine.get_data_mut().threads.as_mut().unwrap();
    let continuation = threads.extended_waiting.remove(&current).unwrap();
    threads.resumed += 1;
    if let Some(index) = continuation.observation {
        let event = &mut engine.get_data_mut().apis.events[index];
        event.pending = false;
        event.result = Some(value);
        event.effect = Some(effect);
    }
    uc(engine.reg_write(
        if engine.get_data().architecture == Architecture::X64 {
            RegisterX86::RAX
        } else {
            RegisterX86::EAX
        },
        value,
    ))?;
    Ok(true)
}
