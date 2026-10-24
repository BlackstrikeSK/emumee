//! Glue to the actual ThreadExecution handle map and scheduler continuations.
use super::*;
#[derive(Clone, Copy, Debug, Serialize)]
pub(crate) struct HandleRecord {
    pub id: u64,
    pub granted_access: u32,
    pub owner: u64,
    pub kernel_only: bool,
}
#[derive(Clone, Copy)]
pub(crate) struct HandleInfo {
    pub object: u64,
    pub granted_access: u32,
    pub owner: u64,
    pub kernel_only: bool,
}
pub(crate) enum HandleLookup {
    Thread(HandleInfo),
    Invalid,
    Foreign,
}
pub(crate) fn thread_handle_evidence(
    engine: &Unicorn<Trace>,
) -> Vec<crate::api::kernel_thread_objects::HandleEvidence> {
    engine
        .get_data()
        .threads
        .as_ref()
        .map(|threads| {
            threads
                .handles
                .iter()
                .map(
                    |(handle, entry)| crate::api::kernel_thread_objects::HandleEvidence {
                        handle: *handle,
                        slot: entry.id,
                        object: address_for(engine.get_data().architecture, entry.id),
                        owner: entry.owner,
                        granted_access: entry.granted_access,
                        kernel_only: entry.kernel_only,
                    },
                )
                .collect()
        })
        .unwrap_or_default()
}
pub(crate) fn lookup_reference_handle(
    engine: &Unicorn<Trace>,
    handle: u64,
) -> Result<HandleLookup> {
    if let Some(threads) = engine.get_data().threads.as_ref() {
        if let Some(entry) = threads.handles.get(&handle) {
            ensure!(
                threads.model.thread(entry.id).is_some(),
                "Thread handle has no actual scheduler context"
            );
            return Ok(HandleLookup::Thread(HandleInfo {
                object: address_for(engine.get_data().architecture, entry.id),
                granted_access: entry.granted_access,
                owner: entry.owner,
                kernel_only: entry.kernel_only,
            }));
        }
        if threads.closed_handles.contains(&handle) {
            return Ok(HandleLookup::Invalid);
        }
    }
    let first =
        emumee_core::kernel_layout::native_thread_handle_first(engine.get_data().architecture);
    // This explicitly owned synthetic thread-handle reservation is finite.
    // Unrecognized process/file namespaces are not reported absent globally.
    if handle == 0
        || handle >= first + 8
            && handle <= first + emumee_core::kernel_layout::NATIVE_THREAD_LIMIT * 4
            && handle % 4 == 0
    {
        Ok(HandleLookup::Invalid)
    } else {
        Ok(HandleLookup::Foreign)
    }
}
pub(crate) fn close_reference_handle(engine: &mut Unicorn<Trace>, handle: u64) -> Result<u64> {
    ensure!(
        engine.get_data().apis.kernel_mode,
        "Kernel handles require a native driver target"
    );
    ensure!(
        engine.get_data().apis.kernel.save().0 == 0,
        "Kernel handle close requires PASSIVE_LEVEL"
    );
    let Some(entry) = engine
        .get_data()
        .threads
        .as_ref()
        .and_then(|threads| threads.handles.get(&handle))
        .copied()
    else {
        return Ok(0xc0000008);
    };
    ensure!(
        entry.owner == 4 && entry.kernel_only,
        "Kernel handle close has unsupported owner/access profile"
    );
    let observed = engine
        .get_data()
        .threads
        .as_ref()
        .unwrap()
        .handles
        .values()
        .filter(|candidate| candidate.id == entry.id)
        .count() as u32;
    crate::api::kernel_thread_objects::closed(engine, entry.id, observed)?;
    let threads = engine.get_data_mut().threads.as_mut().unwrap();
    ensure!(
        threads.handles.remove(&handle).is_some(),
        "Actual kernel handle disappeared during close"
    );
    threads.closed_handles.insert(handle);
    Ok(0)
}
pub(crate) fn validate_thread_wait_resume(engine: &Unicorn<Trace>, pc: u64) -> Result<()> {
    let address = engine
        .get_data()
        .threads
        .as_ref()
        .and_then(|threads| threads.waiting.get(&threads.current_slot))
        .filter(|wait| wait.pc == pc && wait.thread_object)
        .map(|wait| wait.address);
    if let Some(address) = address {
        ensure!(
            crate::api::kernel_thread_objects::wait_target(engine, address)?.is_some(),
            "Resumed thread wait no longer has a live owned object"
        );
    }
    Ok(())
}
pub(crate) fn wait_thread(engine: &mut Unicorn<Trace>, args: &[u64]) -> Result<Option<u64>> {
    ensure!(args.len() == 5, "Thread wait argument count mismatch");
    let Some(target) = crate::api::kernel_thread_objects::wait_target(engine, args[0])? else {
        return Ok(None);
    };
    ensure!(
        args[1] == 0 && args[2] == 0 && args[3] == 0,
        "Only non-alertable Executive/KernelMode thread waits are modeled"
    );
    ensure!(
        engine.get_data().apis.kernel.save().0 <= 2,
        "Thread wait above DISPATCH_LEVEL"
    );
    super::events::validate_all(engine)?;
    engine.get_data_mut().clock.flush_cycles()?;
    let now = engine.get_data().clock.qpc();
    let mut poll = false;
    let deadline = if args[4] == 0 {
        None
    } else {
        range(engine, args[4], 8, P::READ)?;
        crate::api::kernel_thread_objects::require_api_access(engine, args[4], 8, P::READ)?;
        let value = i64::from_le_bytes(uc(engine.mem_read_as_vec(args[4], 8))?.try_into().unwrap());
        poll = value == 0;
        let interval = if value < 0 {
            value.unsigned_abs()
        } else {
            (value as u64).saturating_sub(engine.get_data().clock.utc_filetime)
        };
        Some(
            now.checked_add(interval)
                .context("Thread wait deadline exceeds guest clock range")?,
        )
    };
    let irql = engine.get_data().apis.kernel.save().0;
    ensure!(irql <= 1 || poll, "Nonzero thread wait above APC_LEVEL");
    let pc = uc(engine.pc_read())?;
    let event = engine.get_data().apis.next_event_index();
    let threads = engine
        .get_data_mut()
        .threads
        .as_mut()
        .context("Thread object lacks actual scheduler")?;
    ensure!(
        threads.model.thread(target.slot).is_some(),
        "Thread wait target has no scheduler context"
    );
    threads.model.advance_to(now)?;
    let value = match threads
        .model
        .wait(&[Object::Thread(target.slot)], false, deadline, irql)?
    {
        WaitOutcome::Immediate(emumee_core::scheduler::WaitResult::Satisfied(0)) => {
            ensure!(
                target.terminated,
                "Scheduler fabricated thread termination signal"
            );
            0
        }
        WaitOutcome::Immediate(emumee_core::scheduler::WaitResult::Timeout) => 0x102,
        WaitOutcome::Blocked => {
            let thread = threads.current_slot;
            threads.waiting.insert(
                thread,
                WaitContinuation {
                    address: target.address,
                    pc,
                    old_irql: irql,
                    event,
                    event_object: false,
                    thread_object: true,
                },
            );
            threads.waits += 1;
            engine.get_data_mut().thread_action = Some(Action::Wait { thread });
            0
        }
        _ => bail!("Invalid single-thread wait result"),
    };
    super::events::mirror_all(engine)?;
    Ok(Some(value))
}
