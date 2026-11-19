//! Process-owned thread handles. Handles carry authority; records carry lifetime.
use super::*;
pub(super) const ALL: u32 = 0x1fffff;
#[derive(Clone, Copy)]
pub(super) struct Handle {
    pub canonical: u64,
    pub access: u32,
    pub flags: u32,
}
#[derive(Clone, Copy)]
pub(in crate::api) enum Call {
    Open,
    Duplicate,
    GetFlags,
    SetFlags,
    Context(bool),
}
pub(super) fn definition(name: &str) -> Option<(Call, usize, T)> {
    Some(match name {
        "OpenThread" => (Call::Open, 3, T::Pointer),
        "DuplicateHandle" => (Call::Duplicate, 7, T::U32),
        "GetHandleInformation" => (Call::GetFlags, 2, T::U32),
        "SetHandleInformation" => (Call::SetFlags, 3, T::U32),
        "GetThreadContext" => (Call::Context(false), 2, T::U32),
        "SetThreadContext" => (Call::Context(true), 2, T::U32),
        _ => return None,
    })
}
pub(super) fn resolve(
    engine: &Unicorn<Trace>,
    handle: u64,
    access: u32,
) -> std::result::Result<u64, u32> {
    let pseudo = if engine.get_data().architecture == Architecture::X64 {
        u64::MAX - 1
    } else {
        u32::MAX as u64 - 1
    };
    if handle == pseudo {
        return engine
            .get_data()
            .user_threads
            .by_id(current_id(engine))
            .map(|t| t.handle)
            .ok_or(6);
    }
    let h = engine
        .get_data()
        .user_threads
        .handles
        .get(&handle)
        .ok_or(6u32)?;
    if h.access & access != access {
        return Err(5);
    }
    Ok(h.canonical)
}
fn insert(engine: &mut Unicorn<Trace>, h: Handle) -> std::result::Result<u64, u32> {
    let state = &mut engine.get_data_mut().user_threads;
    if state.handles.len() >= 4096 {
        return Err(8);
    }
    let handle = state.next_handle.max(0x6d000000);
    if handle >= 0x6e000000 {
        return Err(8);
    }
    state.next_handle = handle + 4;
    state.handles.insert(handle, h);
    Ok(handle)
}
pub(super) fn invoke(engine: &mut Unicorn<Trace>, call: Call, args: &[u64]) -> Result<u64> {
    let result = match call {
        Call::Open => {
            if args[0] as u32 & !ALL != 0 {
                Err(5)
            } else if let Some(canonical) = engine
                .get_data()
                .user_threads
                .by_id(args[2] as u32 as u64)
                .map(|t| t.handle)
            {
                insert(
                    engine,
                    Handle {
                        canonical,
                        access: args[0] as u32,
                        flags: u32::from(args[1] != 0),
                    },
                )
            } else {
                Err(87)
            }
        }
        Call::Duplicate => {
            if args[6] & !3 != 0 {
                Err(87)
            } else if !user_runtime::process_access(engine, args[0], 0x40)
                || !user_runtime::process_access(engine, args[2], 0x40)
            {
                Err(5)
            } else if require(
                engine,
                args[3],
                engine.get_data().architecture.width() as u64,
                P::WRITE,
            )
            .is_err()
            {
                Err(998)
            } else {
                let source = engine
                    .get_data()
                    .user_threads
                    .handles
                    .get(&args[1])
                    .copied()
                    .or_else(|| {
                        let pseudo = if engine.get_data().architecture == Architecture::X64 {
                            u64::MAX - 1
                        } else {
                            u32::MAX as u64 - 1
                        };
                        (args[1] == pseudo)
                            .then(|| {
                                engine
                                    .get_data()
                                    .user_threads
                                    .by_id(current_id(engine))
                                    .map(|t| Handle {
                                        canonical: t.handle,
                                        access: ALL,
                                        flags: 0,
                                    })
                            })
                            .flatten()
                    });
                let sync = engine.get_data().apis.user_sync.owns(args[1]);
                let outcome = if sync {
                    if args[6] & 1 != 0
                        && engine
                            .get_data()
                            .apis
                            .user_sync
                            .flags(args[1])
                            .is_ok_and(|f| f & 2 != 0)
                    {
                        Err(5)
                    } else {
                        engine.get_data_mut().apis.user_sync.duplicate_access(
                            args[1],
                            (args[6] & 2 == 0).then_some(args[4] as u32),
                            args[5] != 0,
                        )
                    }
                } else if let Some(source) = source {
                    let access = if args[6] & 2 != 0 {
                        source.access
                    } else {
                        args[4] as u32
                    };
                    if access & !source.access != 0 || (args[6] & 1 != 0 && source.flags & 2 != 0) {
                        Err(5)
                    } else {
                        insert(
                            engine,
                            Handle {
                                canonical: source.canonical,
                                access,
                                flags: u32::from(args[5] != 0),
                            },
                        )
                    }
                } else {
                    Err(6)
                };
                // DUPLICATE_CLOSE_SOURCE closes even when duplication fails.
                if args[6] & 1 != 0 {
                    if sync {
                        let _ = engine.get_data_mut().apis.user_sync.close_checked(args[1]);
                    } else {
                        close(engine, args[1]);
                    }
                }
                match outcome {
                    Ok(h) => {
                        crate::cpu::write(
                            engine,
                            args[3],
                            &h.to_le_bytes()[..engine.get_data().architecture.width()],
                        )?;
                        Ok(1)
                    }
                    Err(e) => Err(e),
                }
            }
        }
        Call::GetFlags => {
            let flags = engine
                .get_data()
                .user_threads
                .handles
                .get(&args[0])
                .map(|h| h.flags)
                .map(Ok)
                .unwrap_or_else(|| engine.get_data().apis.user_sync.flags(args[0]));
            match flags {
                Err(error) => Err(error),
                Ok(_) if require(engine, args[1], 4, P::WRITE).is_err() => Err(998),
                Ok(flags) => {
                    crate::cpu::write(engine, args[1], &flags.to_le_bytes())?;
                    Ok(1)
                }
            }
        }
        Call::SetFlags => {
            if args[1] & !3 != 0 || args[2] & !3 != 0 {
                Err(87)
            } else if let Some(h) = engine.get_data_mut().user_threads.handles.get_mut(&args[0]) {
                h.flags = (h.flags & !(args[1] as u32)) | (args[2] as u32 & args[1] as u32);
                Ok(1)
            } else {
                engine
                    .get_data_mut()
                    .apis
                    .user_sync
                    .set_flags(args[0], args[1] as u32, args[2] as u32)
                    .map(|_| 1)
            }
        }
        Call::Context(set) => return scheduling::queue_context(engine, args, set),
    };
    Ok(match result {
        Ok(value) => value,
        Err(error) => failure(engine, error, 0),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn m4_thread_alias_exhaustion_does_not_enter_dispatcher_namespace() {
        for architecture in [Architecture::X86, Architecture::X64] {
            let mut engine = crate::new_engine(architecture).unwrap();
            engine.get_data_mut().user_threads.next_handle = 0x6dfffffc;
            let metadata = Handle {
                canonical: ROOT_HANDLE,
                access: ALL,
                flags: 0,
            };
            assert_eq!(insert(&mut engine, metadata), Ok(0x6dfffffc));
            assert_eq!(insert(&mut engine, metadata), Err(8));
            assert_eq!(engine.get_data().user_threads.handles.len(), 1);
            engine.get_data_mut().user_threads.next_handle = u64::MAX;
            assert_eq!(insert(&mut engine, metadata), Err(8));
            assert_eq!(engine.get_data().user_threads.handles.len(), 1);
        }
    }
}
