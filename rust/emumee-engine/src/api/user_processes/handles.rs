use super::*;

fn maximum(engine: &Unicorn<Trace>) -> u64 {
    if engine.get_data().architecture == Architecture::X64 {
        u64::MAX
    } else {
        u32::MAX as u64
    }
}
pub(super) fn trace<'borrow>(
    engine: &'borrow Unicorn<'_, Trace>,
    id: u64,
) -> Option<&'borrow Trace> {
    if id == pid(engine) {
        Some(engine.get_data())
    } else {
        engine
            .get_data()
            .processes
            .parked
            .get(&id)
            .map(|snapshot| snapshot.trace.as_ref())
    }
}
pub(super) fn process(
    engine: &Unicorn<Trace>,
    handle: u64,
    access: u32,
) -> std::result::Result<u64, u32> {
    if handle == maximum(engine) {
        return Ok(pid(engine));
    }
    let entry = engine
        .get_data()
        .processes
        .handles
        .get(&(pid(engine), handle))
        .ok_or(6u32)?;
    let Target::Process(id) = entry.target else {
        return Err(6);
    };
    if access & !entry.access != 0 {
        return Err(5);
    }
    if access & 0x3a != 0
        && engine
            .get_data()
            .processes
            .records
            .get(&id)
            .is_some_and(|record| record.exit_code.is_some())
    {
        return Err(5);
    }
    Ok(id)
}
pub(super) fn target(
    engine: &Unicorn<Trace>,
    handle: u64,
    access: u32,
) -> std::result::Result<Target, u32> {
    if handle == maximum(engine) {
        return Ok(Target::Process(pid(engine)));
    }
    if handle == maximum(engine) - 1 {
        return Ok(Target::Thread(
            pid(engine),
            user_threads::current_id(engine),
        ));
    }
    if let Some(entry) = engine
        .get_data()
        .processes
        .handles
        .get(&(pid(engine), handle))
    {
        if access & !entry.access != 0 {
            return Err(5);
        }
        return Ok(entry.target);
    }
    let (id, rights, _) = user_threads::process_handle(engine.get_data(), handle).ok_or(6u32)?;
    if access & !rights != 0 {
        return Err(5);
    }
    Ok(Target::Thread(pid(engine), id))
}
pub(super) fn admits(state: &State, count: usize) -> bool {
    state
        .handles
        .len()
        .checked_add(count)
        .is_some_and(|n| n <= 4096)
        && u64::try_from(count)
            .ok()
            .and_then(|n| n.checked_mul(4))
            .and_then(|bytes| state.next_handle.max(0x25000000).checked_add(bytes))
            .is_some_and(|end| end <= 0x26000000)
}
pub(super) fn insert(
    engine: &mut Unicorn<Trace>,
    owner: u64,
    target: Target,
    access: u32,
    flags: u32,
) -> std::result::Result<u64, u32> {
    let state = &mut engine.get_data_mut().processes;
    if !admits(state, 1) {
        return Err(8);
    }
    let handle = state.next_handle.max(0x25000000);
    state.next_handle = handle.checked_add(4).ok_or(8u32)?;
    state.handles.insert(
        (owner, handle),
        Handle {
            target,
            access,
            flags,
        },
    );
    Ok(handle)
}
pub(super) fn close(engine: &mut Unicorn<Trace>, handle: u64) -> Option<u64> {
    let key = (pid(engine), handle);
    let entry = engine.get_data().processes.handles.get(&key)?;
    if entry.flags & 2 != 0 {
        return Some(failure(engine, 5));
    }
    engine.get_data_mut().processes.handles.remove(&key);
    Some(1)
}
pub(super) fn external(engine: &Unicorn<Trace>) -> BTreeMap<u64, bool> {
    engine
        .get_data()
        .processes
        .handles
        .iter()
        .filter_map(|((owner, handle), entry)| {
            if *owner != pid(engine) || entry.access & SYNCHRONIZE == 0 {
                return None;
            }
            let ready = match entry.target {
                Target::Process(id) => engine
                    .get_data()
                    .processes
                    .records
                    .get(&id)?
                    .exit_code
                    .is_some(),
                Target::Thread(id, thread) => {
                    engine
                        .get_data()
                        .processes
                        .records
                        .get(&id)?
                        .exit_code
                        .is_some()
                        || trace(engine, id)
                            .and_then(|trace| user_threads::process_thread(trace, thread))
                            .is_some_and(|thread| thread.exit_code.is_some())
                }
            };
            Some((*handle, ready))
        })
        .collect()
}
pub(super) fn wait_access(
    engine: &Unicorn<Trace>,
    handles: &[u64],
) -> std::result::Result<(), u32> {
    let mut seen = std::collections::BTreeSet::new();
    for handle in handles {
        if let Some(entry) = engine
            .get_data()
            .processes
            .handles
            .get(&(pid(engine), *handle))
        {
            if entry.access & SYNCHRONIZE == 0 {
                return Err(5);
            }
            if !seen.insert(entry.target) {
                return Err(87);
            }
        } else if let Some((id, _, _)) = user_threads::process_handle(engine.get_data(), *handle) {
            if !seen.insert(Target::Thread(pid(engine), id)) {
                return Err(87);
            }
        }
    }
    Ok(())
}
fn query_access(engine: &Unicorn<Trace>, handle: u64) -> std::result::Result<u64, u32> {
    process(engine, handle, 0x1000).or_else(|_| process(engine, handle, 0x400))
}
fn local(engine: &mut Unicorn<Trace>, name: &str, args: &[u64]) -> Result<u64> {
    let (call, _, _) =
        user_threads::definition("kernel32", name).context("Local thread API absent")?;
    user_threads::invoke(engine, call, args)
}
pub(super) fn invoke(engine: &mut Unicorn<Trace>, call: Call, args: &[u64]) -> Result<Option<u64>> {
    let owner = pid(engine);
    let result = match call {
        Call::Pid => owner,
        Call::ThreadId => tid(owner, user_threads::current_id(engine)),
        Call::Open => {
            let id = args[2] as u32 as u64;
            if args[0] as u32 & !PROCESS_ALL != 0 {
                failure(engine, 5)
            } else if id != owner && !engine.get_data().processes.records.contains_key(&id) {
                failure(engine, 87)
            } else {
                match insert(
                    engine,
                    owner,
                    Target::Process(id),
                    args[0] as u32,
                    u32::from(args[1] != 0),
                ) {
                    Ok(handle) => handle,
                    Err(error) => failure(engine, error),
                }
            }
        }
        Call::Id | Call::Debugger | Call::ExitCode => {
            let id = match query_access(engine, args[0]) {
                Ok(id) => id,
                Err(error) => return Ok(Some(failure(engine, error))),
            };
            if matches!(call, Call::Id) {
                id
            } else {
                if require(engine, args[1], 4, P::WRITE).is_err() {
                    return Ok(Some(failure(engine, 998)));
                }
                let code = if matches!(call, Call::Debugger) {
                    0
                } else {
                    engine
                        .get_data()
                        .processes
                        .records
                        .get(&id)
                        .and_then(|record| record.exit_code)
                        .unwrap_or(259)
                };
                crate::cpu::write(engine, args[1], &code.to_le_bytes())?;
                1
            }
        }
        Call::ThreadProcessId | Call::QueryThreadId => {
            match target(engine, args[0], 0x40).or_else(|_| target(engine, args[0], 0x800)) {
                Ok(Target::Thread(id, thread)) => {
                    if matches!(call, Call::QueryThreadId) {
                        tid(id, thread)
                    } else {
                        id
                    }
                }
                Ok(_) => failure(engine, 6),
                Err(error) => failure(engine, error),
            }
        }
        Call::Thread(call) => {
            let index = if matches!(call, user_threads::Call::Apc) {
                1
            } else {
                0
            };
            if !engine
                .get_data()
                .processes
                .handles
                .contains_key(&(owner, args[index]))
            {
                return Ok(Some(user_threads::invoke(engine, call, args)?));
            }
            return Ok(None);
        }
        Call::OpenThread => {
            let wanted = args[2] as u32 as u64;
            if wanted < 0x10000 {
                return Ok(Some(local(engine, "OpenThread", args)?));
            }
            let id = ROOT + wanted / 0x10000;
            let thread = wanted % 0x10000;
            if args[0] as u32 & !THREAD_ALL != 0 {
                failure(engine, 5)
            } else if trace(engine, id)
                .and_then(|trace| user_threads::process_thread(trace, thread))
                .is_none()
            {
                failure(engine, 87)
            } else {
                match insert(
                    engine,
                    owner,
                    Target::Thread(id, thread),
                    args[0] as u32,
                    u32::from(args[1] != 0),
                ) {
                    Ok(handle) => handle,
                    Err(error) => failure(engine, error),
                }
            }
        }
        Call::Flags(set) => {
            let key = (owner, args[0]);
            if !engine.get_data().processes.handles.contains_key(&key) {
                return Ok(Some(local(
                    engine,
                    if set {
                        "SetHandleInformation"
                    } else {
                        "GetHandleInformation"
                    },
                    args,
                )?));
            }
            if set {
                if args[1] & !3 != 0 || args[2] & !3 != 0 {
                    failure(engine, 87)
                } else {
                    let entry = engine
                        .get_data_mut()
                        .processes
                        .handles
                        .get_mut(&key)
                        .unwrap();
                    entry.flags =
                        (entry.flags & !(args[1] as u32)) | (args[2] as u32 & args[1] as u32);
                    1
                }
            } else {
                if require(engine, args[1], 4, P::WRITE).is_err() {
                    return Ok(Some(failure(engine, 998)));
                }
                let flags = engine.get_data().processes.handles[&key].flags;
                crate::cpu::write(engine, args[1], &flags.to_le_bytes())?;
                1
            }
        }
        Call::Duplicate => {
            if args[6] & !3 != 0 {
                return Ok(Some(failure(engine, 87)));
            }
            let source_owner = match process(engine, args[0], 0x40) {
                Ok(id) => id,
                Err(error) => return Ok(Some(failure(engine, error))),
            };
            let destination = match process(engine, args[2], 0x40) {
                Ok(id) => id,
                Err(error) => return Ok(Some(failure(engine, error))),
            };
            let world_handle = engine
                .get_data()
                .processes
                .handles
                .get(&(source_owner, args[1]))
                .copied();
            if world_handle.is_none()
                && args[1] != maximum(engine)
                && source_owner == owner
                && destination == owner
            {
                return Ok(Some(local(engine, "DuplicateHandle", args)?));
            }
            if require(
                engine,
                args[3],
                engine.get_data().architecture.width() as u64,
                P::WRITE,
            )
            .is_err()
            {
                return Ok(Some(failure(engine, 998)));
            }
            let entry = if args[1] == maximum(engine) {
                Handle {
                    target: Target::Process(source_owner),
                    access: PROCESS_ALL,
                    flags: 0,
                }
            } else if args[1] == maximum(engine) - 1 && source_owner == owner {
                Handle {
                    target: Target::Thread(owner, user_threads::current_id(engine)),
                    access: THREAD_ALL,
                    flags: 0,
                }
            } else {
                match world_handle.or_else(|| {
                    trace(engine, source_owner)
                        .and_then(|trace| user_threads::process_handle(trace, args[1]))
                        .map(|(thread, access, flags)| Handle {
                            target: Target::Thread(source_owner, thread),
                            access,
                            flags,
                        })
                }) {
                    Some(entry) => entry,
                    None => return Ok(Some(failure(engine, 6))),
                }
            };
            let access = if args[6] & 2 != 0 {
                entry.access
            } else {
                args[4] as u32
            };
            if access & !entry.access != 0 || args[6] & 1 != 0 && entry.flags & 2 != 0 {
                return Ok(Some(failure(engine, 5)));
            }
            let handle = match insert(
                engine,
                destination,
                entry.target,
                access,
                u32::from(args[5] != 0),
            ) {
                Ok(handle) => handle,
                Err(error) => return Ok(Some(failure(engine, error))),
            };
            let width = engine.get_data().architecture.width();
            crate::cpu::write(engine, args[3], &handle.to_le_bytes()[..width])?;
            if args[6] & 1 != 0 && args[1] < maximum(engine) - 1 {
                if world_handle.is_some() {
                    engine
                        .get_data_mut()
                        .processes
                        .handles
                        .remove(&(source_owner, args[1]));
                } else if source_owner == owner {
                    user_threads::close_process_handle(engine.get_data_mut(), args[1]).map_err(
                        |error| anyhow::anyhow!("Validated source handle close failed: {error}"),
                    )?;
                } else {
                    let source = engine
                        .get_data_mut()
                        .processes
                        .parked
                        .get_mut(&source_owner)
                        .context("Duplicate source process disappeared")?;
                    user_threads::close_process_handle(&mut source.trace, args[1]).map_err(
                        |error| anyhow::anyhow!("Validated foreign handle close failed: {error}"),
                    )?;
                }
            }
            1
        }
        _ => return Ok(None),
    };
    Ok(Some(result))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn m4_child_creation_refuses_two_handle_exhaustion_before_publishing_state() {
        for architecture in [Architecture::X86, Architecture::X64] {
            let mut engine = crate::new_engine(architecture).unwrap();
            engine
                .get_data_mut()
                .apis
                .memory
                .map(0x10000, 4096, P::RW, None, "process output")
                .unwrap();
            engine
                .mem_map(0x10000, 4096, Prot::READ | Prot::WRITE)
                .unwrap();
            engine.mem_write(0x10000, &[0xa5; 24]).unwrap();
            let mut args = [0; 10];
            args[9] = 0x10000;
            for next in [0x25fffffc, 0x26000000, u64::MAX] {
                engine.get_data_mut().processes.next_handle = next;
                assert_eq!(preparation::create(&mut engine, &args, false).unwrap(), 0);
                assert_eq!(engine.get_data().apis.last_error, 8);
                let state = &engine.get_data().processes;
                assert_eq!(state.next_handle, next);
                assert!(
                    state.records.is_empty() && state.parked.is_empty() && state.handles.is_empty()
                );
                assert_eq!(engine.mem_read_as_vec(0x10000, 24).unwrap(), [0xa5; 24]);
            }
            engine.get_data_mut().processes.next_handle = 0x25fffff8;
            assert!(admits(&engine.get_data().processes, 2));
        }
    }
    #[test]
    fn m4_process_handle_exhaustion_preserves_namespace_and_existing_authority() {
        for architecture in [Architecture::X86, Architecture::X64] {
            let mut engine = crate::new_engine(architecture).unwrap();
            engine.get_data_mut().processes.next_handle = 0x25fffffc;
            assert_eq!(
                insert(&mut engine, ROOT, Target::Process(ROOT), PROCESS_ALL, 1),
                Ok(0x25fffffc)
            );
            assert_eq!(
                insert(&mut engine, ROOT, Target::Process(ROOT), PROCESS_ALL, 1),
                Err(8)
            );
            assert_eq!(process(&engine, 0x25fffffc, 0x40), Ok(ROOT));
            assert_eq!(engine.get_data().processes.handles.len(), 1);
            engine.get_data_mut().processes.next_handle = u64::MAX;
            assert_eq!(
                insert(&mut engine, ROOT, Target::Process(ROOT), PROCESS_ALL, 1),
                Err(8)
            );
            assert_eq!(engine.get_data().processes.handles.len(), 1);
        }
    }
}
