//! Win32 dispatcher APIs over guest-owned objects and virtual time.
use super::*;
use emumee_core::user_sync::Object;

#[derive(Clone, Copy)]
pub(super) enum Call {
    Create(u8, bool),
    Open(u8, bool),
    Event(bool),
    MutexRelease,
    SemaphoreRelease,
    Wait(bool, bool),
    Sleep(bool),
}
pub(super) fn definition(module: &str, name: &str) -> Option<(Call, usize, T)> {
    if !matches!(module, "kernel32" | "kernelbase") && !module.starts_with("api-ms-win-core-synch-")
    {
        return None;
    }
    Some(match name {
        "CreateEventA" | "CreateEventW" => (Call::Create(0, name.ends_with('W')), 4, T::Pointer),
        "CreateMutexA" | "CreateMutexW" => (Call::Create(1, name.ends_with('W')), 3, T::Pointer),
        "CreateSemaphoreA" | "CreateSemaphoreW" => {
            (Call::Create(2, name.ends_with('W')), 4, T::Pointer)
        }
        "OpenEventA" | "OpenEventW" => (Call::Open(0, name.ends_with('W')), 3, T::Pointer),
        "OpenMutexA" | "OpenMutexW" => (Call::Open(1, name.ends_with('W')), 3, T::Pointer),
        "OpenSemaphoreA" | "OpenSemaphoreW" => (Call::Open(2, name.ends_with('W')), 3, T::Pointer),
        "SetEvent" => (Call::Event(true), 1, T::U32),
        "ResetEvent" => (Call::Event(false), 1, T::U32),
        "ReleaseMutex" => (Call::MutexRelease, 1, T::U32),
        "ReleaseSemaphore" => (Call::SemaphoreRelease, 3, T::U32),
        "WaitForSingleObject" => (Call::Wait(false, false), 2, T::U32),
        "WaitForSingleObjectEx" => (Call::Wait(false, true), 3, T::U32),
        "WaitForMultipleObjects" => (Call::Wait(true, false), 4, T::U32),
        "WaitForMultipleObjectsEx" => (Call::Wait(true, true), 5, T::U32),
        "Sleep" => (Call::Sleep(false), 1, T::U32),
        "SleepEx" => (Call::Sleep(true), 2, T::U32),
        _ => return None,
    })
}
fn fail(engine: &mut Unicorn<Trace>, error: u32, value: u64) -> u64 {
    engine.get_data_mut().apis.last_error = error;
    value
}
fn object(kind: u8) -> Object {
    match kind {
        0 => Object::Event {
            manual: false,
            signaled: false,
        },
        1 => Object::Mutex {
            owner: None,
            recursion: 0,
            abandoned: false,
        },
        _ => Object::Semaphore {
            count: 0,
            maximum: 1,
        },
    }
}
pub(super) fn security_attributes(
    engine: &Unicorn<Trace>,
    address: u64,
) -> std::result::Result<bool, u32> {
    if address == 0 {
        return Ok(false);
    }
    let size = if engine.get_data().architecture == Architecture::X64 {
        24
    } else {
        12
    };
    let bytes = read(engine, address, size).map_err(|_| 998u32)?;
    if u32::from_le_bytes(bytes[..4].try_into().unwrap()) != size as u32 {
        return Err(87);
    }
    let at = if size == 24 { 16 } else { 8 };
    Ok(u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()) != 0)
}
pub(super) fn invoke(engine: &mut Unicorn<Trace>, call: Call, args: &[u64]) -> Result<u64> {
    let thread = user_threads::current_id(engine);
    match call {
        Call::Create(kind, wide) => {
            let inherit = match security_attributes(engine, args[0]) {
                Ok(v) => v,
                Err(e) => return Ok(fail(engine, e, 0)),
            };
            let name_at = args[if kind == 1 { 2 } else { 3 }];
            let name = if name_at == 0 {
                None
            } else {
                Some(files::path(engine, name_at, wide)?)
            };
            let value = match kind {
                0 => Object::Event {
                    manual: args[1] != 0,
                    signaled: args[2] != 0,
                },
                1 => Object::Mutex {
                    owner: (args[1] != 0).then_some(thread),
                    recursion: u32::from(args[1] != 0),
                    abandoned: false,
                },
                _ => {
                    if args[2] as u32 == 0
                        || args[2] as u32 > i32::MAX as u32
                        || args[1] as u32 > args[2] as u32
                    {
                        return Ok(fail(engine, 87, 0));
                    }
                    Object::Semaphore {
                        count: args[1] as u32,
                        maximum: args[2] as u32,
                    }
                }
            };
            Ok(
                match engine.get_data_mut().apis.user_sync.create(value, name) {
                    Ok((handle, exists)) => {
                        engine
                            .get_data_mut()
                            .apis
                            .user_sync
                            .set_flags(handle, 1, u32::from(inherit))
                            .map_err(|e| {
                                anyhow::anyhow!("New synchronization handle flags: {e}")
                            })?;
                        engine.get_data_mut().apis.last_error = if exists { 183 } else { 0 };
                        handle
                    }
                    Err(error) => fail(engine, error, 0),
                },
            )
        }
        Call::Open(kind, wide) => {
            let name = files::path(engine, args[2], wide)?;
            Ok(
                match engine
                    .get_data_mut()
                    .apis
                    .user_sync
                    .open(&name, &object(kind))
                {
                    Ok(handle) => {
                        if let Err(e) = engine
                            .get_data_mut()
                            .apis
                            .user_sync
                            .restrict(handle, args[0] as u32)
                        {
                            engine.get_data_mut().apis.user_sync.close(handle);
                            return Ok(fail(engine, e, 0));
                        }
                        engine
                            .get_data_mut()
                            .apis
                            .user_sync
                            .set_flags(handle, 1, u32::from(args[1] != 0))
                            .map_err(|e| {
                                anyhow::anyhow!("Opened synchronization handle flags: {e}")
                            })?;
                        handle
                    }
                    Err(error) => fail(engine, error, 0),
                },
            )
        }
        Call::Event(set) => Ok(
            match engine.get_data_mut().apis.user_sync.event(args[0], set) {
                Ok(()) => 1,
                Err(error) => fail(engine, error, 0),
            },
        ),
        Call::MutexRelease => Ok(
            match engine
                .get_data_mut()
                .apis
                .user_sync
                .release_mutex(args[0], thread)
            {
                Ok(()) => 1,
                Err(error) => fail(engine, error, 0),
            },
        ),
        Call::SemaphoreRelease => {
            if args[2] != 0 && require(engine, args[2], 4, P::WRITE).is_err() {
                return Ok(fail(engine, 998, 0));
            }
            match engine
                .get_data_mut()
                .apis
                .user_sync
                .release_semaphore(args[0], args[1] as u32)
            {
                Ok(previous) => {
                    if args[2] != 0 {
                        crate::cpu::write(engine, args[2], &previous.to_le_bytes())?;
                    }
                    Ok(1)
                }
                Err(error) => Ok(fail(engine, error, 0)),
            }
        }
        Call::Wait(many, extended) => {
            let alertable = extended && args[if many { 4 } else { 2 }] != 0;
            let (handles, all, timeout, argc) = if many {
                let count = args[0] as u32 as usize;
                if count == 0 || count > emumee_core::user_sync::MAX_WAIT {
                    return Ok(fail(engine, 87, u32::MAX as u64));
                }
                let width = engine.get_data().architecture.width();
                let bytes = match read(engine, args[1], (count * width) as u64) {
                    Ok(bytes) => bytes,
                    Err(_) => return Ok(fail(engine, 998, u32::MAX as u64)),
                };
                let handles = bytes
                    .chunks_exact(width)
                    .map(|b| {
                        let mut value = [0; 8];
                        value[..width].copy_from_slice(b);
                        u64::from_le_bytes(value)
                    })
                    .collect::<Vec<_>>();
                (
                    handles,
                    args[2] != 0,
                    args[3] as u32,
                    if extended { 5 } else { 4 },
                )
            } else {
                (
                    vec![args[0]],
                    false,
                    args[1] as u32,
                    if extended { 3 } else { 2 },
                )
            };
            if let Err(error) = user_threads::wait_access(engine, &handles) {
                return Ok(fail(engine, error, u32::MAX as u64));
            }
            let external = user_threads::scheduling::external(engine);
            match engine
                .get_data_mut()
                .apis
                .user_sync
                .wait(&handles, all, thread, &external)
            {
                Err(error) => Ok(fail(engine, error, u32::MAX as u64)),
                Ok(Some(value)) => Ok(value as u64),
                Ok(None) if timeout == 0 => Ok(0x102),
                Ok(None) => user_threads::scheduling::alertable_wait(
                    engine,
                    user_threads::Wait::Objects { handles, all },
                    timeout,
                    argc,
                    alertable,
                ),
            }
        }
        Call::Sleep(extended) => {
            let alertable = extended && args[1] != 0;
            if engine.get_data().apis.user_bootstrap.is_none() {
                engine
                    .get_data_mut()
                    .clock
                    .advance_milliseconds(args[0] as u32)?;
                return Ok(0);
            }
            user_threads::scheduling::alertable_wait(
                engine,
                user_threads::Wait::Sleep,
                args[0] as u32,
                if extended { 2 } else { 1 },
                alertable,
            )
        }
    }
}
