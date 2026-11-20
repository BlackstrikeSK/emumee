use super::*;

pub(super) fn local_fallback(engine: &mut Unicorn<Trace>, call: Call, args: &[u64]) -> Result<u64> {
    // NtUnmapViewOfSection against the calling process itself unmaps one of its
    // own images, the self-replacement path. It returns an NTSTATUS directly.
    if let Call::UnmapSection = call {
        return unmap_current_section(engine, args[1]);
    }
    let call = match call {
        Call::Memory(write) => user_runtime::Call::ProcessMemory(write),
        Call::Virtual(operation @ 0..=2) => user_runtime::Call::VirtualEx(operation),
        Call::Terminate => user_runtime::Call::Terminate,
        _ => return Ok(failure(engine, 50)),
    };
    user_runtime::invoke(engine, args, call)
}
/// NtUnmapViewOfSection semantics against whichever address space is current:
/// remove the image mapped exactly at `base`, running no detach and respecting
/// no lifecycle phase, as the native call does. Returns an NTSTATUS. The caller
/// has already entered the target process's space when the handle is remote.
fn unmap_current_section(engine: &mut Unicorn<Trace>, base: u64) -> Result<u64> {
    const STATUS_SUCCESS: u64 = 0;
    const STATUS_NOT_MAPPED_VIEW: u64 = 0xc000_0019;
    // The address must be an image's own base. An interior address, a private
    // VirtualAlloc reservation or free memory is not a mapped section.
    if !engine
        .get_data()
        .apis
        .modules
        .modules()
        .any(|module| module.base == base)
    {
        return Ok(STATUS_NOT_MAPPED_VIEW);
    }
    let mut catalog = engine.get_data().apis.modules.clone();
    let size = match catalog.unmap_section(base) {
        Ok(size) => size,
        Err(_) => return Ok(STATUS_NOT_MAPPED_VIEW),
    };
    let mut memory = engine.get_data().apis.memory.clone();
    memory
        .unmap(base, size)
        .context("NtUnmapViewOfSection model unmap")?;
    uc(engine.mem_unmap(base, size))
        .with_context(|| format!("NtUnmapViewOfSection native unmap at {base:#x}+{size:#x}"))?;
    engine.get_data_mut().apis.modules = catalog;
    engine.get_data_mut().apis.memory = memory;
    engine.get_data_mut().cpu.cache.invalidate(base, size as usize);
    uc(engine.ctl_remove_cache(base, base + size))?;
    super::record_forced_unmap(engine, base, size);
    // Refresh the PEB loader list; the primary image may now be gone, which is
    // exactly the state a replacement loader expects to rebuild.
    super::user_loader::sync(engine)?;
    Ok(STATUS_SUCCESS)
}
/// NtUnmapViewOfSection against another process: enter its space, unmap, return.
fn section(engine: &mut Unicorn<Trace>, args: &[u64]) -> Result<u64> {
    const STATUS_INVALID_HANDLE: u64 = 0xc000_0008;
    const STATUS_PROCESS_IS_TERMINATING: u64 = 0xc000_010a;
    // Resolve with no access demand first: the access-gated resolution refuses
    // an exited target, which would otherwise hide the terminating answer
    // behind an invalid-handle one.
    let id = match handles::process(engine, args[0], 0) {
        Ok(id) => id,
        Err(_) => return Ok(STATUS_INVALID_HANDLE),
    };
    if engine
        .get_data()
        .processes
        .records
        .get(&id)
        .is_some_and(|record| record.exit_code.is_some())
    {
        return Ok(STATUS_PROCESS_IS_TERMINATING);
    }
    // PROCESS_VM_OPERATION is the access NtUnmapViewOfSection requires.
    if handles::process(engine, args[0], 8).is_err() {
        return Ok(STATUS_INVALID_HANDLE);
    }
    let caller = pid(engine);
    switch(engine, id)?;
    let result = unmap_current_section(engine, args[1]);
    switch(engine, caller)?;
    result
}
fn put_count(engine: &mut Unicorn<Trace>, pointer: u64, count: u64) -> Result<()> {
    if pointer != 0 {
        let width = engine.get_data().architecture.width();
        crate::cpu::write(engine, pointer, &count.to_le_bytes()[..width])?;
    }
    Ok(())
}
fn memory(engine: &mut Unicorn<Trace>, args: &[u64], write: bool) -> Result<u64> {
    let id = match handles::process(engine, args[0], if write { 0x28 } else { 0x10 }) {
        Ok(id) => id,
        Err(error) => return Ok(failure(engine, error)),
    };
    let size = args[3];
    let width = engine.get_data().architecture.width();
    if size > MAX_TRANSFER {
        return Ok(failure(engine, 87));
    }
    if args[4] != 0 && require(engine, args[4], width as u64, P::WRITE).is_err() {
        return Ok(failure(engine, 998));
    }
    if size != 0
        && require(
            engine,
            args[2],
            size,
            if write { P::READ } else { P::WRITE },
        )
        .is_err()
    {
        put_count(engine, args[4], 0)?;
        return Ok(failure(engine, 299));
    }
    let caller = pid(engine);
    let source = if write && size != 0 {
        read(engine, args[2], size)?
    } else {
        vec![]
    };
    switch(engine, id)?;
    let operation = (|| -> Result<Vec<u8>> {
        if size == 0 {
            return Ok(vec![]);
        }
        require(
            engine,
            args[1],
            size,
            if write { P::WRITE } else { P::READ },
        )?;
        if write {
            crate::cpu::write(engine, args[1], &source)?;
            Ok(vec![])
        } else {
            read(engine, args[1], size)
        }
    })();
    switch(engine, caller)?;
    let bytes = match operation {
        Ok(bytes) => bytes,
        Err(_) => {
            put_count(engine, args[4], 0)?;
            return Ok(failure(engine, 299));
        }
    };
    if !write && size != 0 {
        crate::cpu::write(engine, args[2], &bytes)?;
    }
    put_count(engine, args[4], size)?;
    Ok(1)
}
fn virtual_memory(engine: &mut Unicorn<Trace>, args: &[u64], operation: u8) -> Result<u64> {
    let id = match handles::process(engine, args[0], if operation == 3 { 0x400 } else { 8 }) {
        Ok(id) => id,
        Err(error) => return Ok(failure(engine, error)),
    };
    if engine
        .get_data()
        .processes
        .records
        .get(&id)
        .is_some_and(|record| record.exit_code.is_some())
    {
        return Ok(failure(engine, 487));
    }
    let width = engine.get_data().architecture.width();
    let output_size = if operation == 3 {
        if width == 8 { 48 } else { 28 }
    } else {
        4
    };
    if operation >= 2
        && (operation == 3 && args[3] < output_size
            || require(
                engine,
                args[if operation == 3 { 2 } else { 4 }],
                output_size,
                P::WRITE,
            )
            .is_err())
    {
        return Ok(failure(engine, 998));
    }
    let caller = pid(engine);
    switch(engine, id)?;
    let mut output = vec![];
    let result = (|| -> Result<u64> {
        Ok(match operation {
            0 => allocation::allocate(engine, &args[1..])?,
            1 => allocation::free(engine, &args[1..])?,
            2 => {
                let temporary = allocation::allocate(engine, &[0, 4096, 0x3000, 4])?;
                ensure!(temporary != 0, "Remote protection scratch admission failed");
                let result = allocation::protect(engine, &[args[1], args[2], args[3], temporary]);
                if result.as_ref().is_ok_and(|value| *value != 0) {
                    output = read(engine, temporary, 4)?;
                }
                let error = engine.get_data().apis.last_error;
                allocation::free(engine, &[temporary, 0, 0x8000])?;
                engine.get_data_mut().apis.last_error = error;
                result?
            }
            _ => {
                let region = engine
                    .get_data()
                    .apis
                    .memory
                    .region(args[1])
                    .context("Remote query address unmapped")?;
                output = vec![0; output_size as usize];
                let protection: u32 = match region.permissions.0 {
                    0 => 1,
                    1 => 2,
                    3 => 4,
                    4 => 0x10,
                    5 => 0x20,
                    7 => 0x40,
                    _ => 1,
                };
                for (at, value, length) in [
                    (0, region.base, width),
                    (width, region.base, width),
                    (2 * width, protection as u64, 4),
                    (if width == 8 { 24 } else { 12 }, region.size, width),
                    (if width == 8 { 32 } else { 16 }, 0x1000, 4),
                    (if width == 8 { 36 } else { 20 }, protection as u64, 4),
                    (if width == 8 { 40 } else { 24 }, 0x20000, 4),
                ] {
                    output[at..at + length].copy_from_slice(&value.to_le_bytes()[..length]);
                }
                output_size
            }
        })
    })();
    let error = engine.get_data().apis.last_error;
    switch(engine, caller)?;
    engine.get_data_mut().apis.last_error = error;
    let value = match result {
        Ok(value) => value,
        Err(_) => return Ok(failure(engine, 487)),
    };
    if value != 0 && !output.is_empty() {
        crate::cpu::write(engine, args[if operation == 3 { 2 } else { 4 }], &output)?;
    }
    Ok(value)
}
fn thread(engine: &mut Unicorn<Trace>, args: &[u64], call: user_threads::Call) -> Result<u64> {
    let index = if matches!(call, user_threads::Call::Apc) {
        1
    } else {
        0
    };
    let access = match call {
        user_threads::Call::Authority(user_threads::authority::Call::Context(set)) => {
            if set {
                0x10
            } else {
                8
            }
        }
        user_threads::Call::Suspend | user_threads::Call::Resume => 2,
        user_threads::Call::Terminate => 1,
        user_threads::Call::Apc => 0x10,
        user_threads::Call::ExitCode => 0x40,
        _ => 0,
    };
    let resolved = handles::target(engine, args[index], access).or_else(|error| {
        if matches!(call, user_threads::Call::ExitCode) {
            handles::target(engine, args[index], 0x800)
        } else {
            Err(error)
        }
    });
    let (id, thread) = match resolved {
        Ok(Target::Thread(id, thread)) => (id, thread),
        Ok(_) => return Ok(failure(engine, 6)),
        Err(error) => {
            failure(engine, error);
            return Ok(
                if matches!(
                    call,
                    user_threads::Call::Suspend | user_threads::Call::Resume
                ) {
                    u32::MAX as u64
                } else {
                    0
                },
            );
        }
    };
    if matches!(call, user_threads::Call::ExitCode) {
        if require(engine, args[1], 4, P::WRITE).is_err() {
            return Ok(failure(engine, 998));
        }
        let code = engine
            .get_data()
            .processes
            .records
            .get(&id)
            .and_then(|record| record.exit_code)
            .or_else(|| {
                handles::trace(engine, id)
                    .and_then(|trace| user_threads::process_thread(trace, thread))
                    .and_then(|thread| thread.exit_code)
            })
            .unwrap_or(259);
        crate::cpu::write(engine, args[1], &code.to_le_bytes())?;
        return Ok(1);
    }
    if engine
        .get_data()
        .processes
        .records
        .get(&id)
        .is_some_and(|record| record.exit_code.is_some())
    {
        return Ok(failure(engine, 5));
    }
    let caller = pid(engine);
    let context =
        if let user_threads::Call::Authority(user_threads::authority::Call::Context(set)) = call {
            let size = if engine.get_data().architecture == Architecture::X64 {
                1232
            } else {
                716
            };
            if require(engine, args[1], size, if set { P::READ } else { P::RW }).is_err() {
                return Ok(failure(engine, 998));
            }
            Some((set, read(engine, args[1], size)?))
        } else {
            None
        };
    switch(engine, id)?;
    let mut output = vec![];
    let result = match call {
        user_threads::Call::Authority(user_threads::authority::Call::Context(_)) => {
            let (set, bytes) = context.as_ref().unwrap();
            let temporary = allocation::allocate(engine, &[0, 4096, 0x3000, 4])?;
            if temporary == 0 {
                Ok(0)
            } else {
                crate::cpu::write(engine, temporary, bytes)?;
                let result = user_threads::remote_context(engine, thread, temporary, *set);
                if !*set && result.as_ref().is_ok_and(|result| *result != 0) {
                    output = read(engine, temporary, bytes.len() as u64)?;
                }
                allocation::free(engine, &[temporary, 0, 0x8000])?;
                result
            }
        }
        user_threads::Call::Suspend => user_threads::remote_suspend(engine, thread, true),
        user_threads::Call::Resume => user_threads::remote_suspend(engine, thread, false),
        user_threads::Call::Terminate => {
            user_threads::remote_terminate(engine, thread, args[1] as u32)
        }
        user_threads::Call::Apc => {
            if require(engine, args[0], 1, P::EXECUTE).is_err() {
                Ok(failure(engine, 998))
            } else {
                Ok(u64::from(user_threads::scheduling::queue_apc(
                    engine, thread, args[0], args[2],
                )))
            }
        }
        _ => Ok(failure(engine, 50)),
    };
    let error = engine.get_data().apis.last_error;
    switch(engine, caller)?;
    engine.get_data_mut().apis.last_error = error;
    if !output.is_empty() {
        crate::cpu::write(engine, args[1], &output)?;
    }
    result
}
pub(super) fn dispatch(
    engine: &mut Unicorn<Trace>,
    call: Call,
    args: &[u64],
    horizon: &ExecutionHorizon,
) -> Result<u64> {
    match call {
        Call::Create(wide) => preparation::create(engine, args, wide),
        Call::CreateInternal(wide) => {
            if args[0] != 0 || args[11] != 0 {
                return Ok(failure(engine, 50));
            }
            preparation::create(engine, &args[1..11], wide)
        }
        Call::WinExec => {
            let scratch = allocation::allocate(engine, &[0, 4096, 0x3000, 4])?;
            if scratch == 0 {
                return Ok(8);
            }
            let result = preparation::create(
                engine,
                &[0, args[0], 0, 0, 0, 0, 0, 0, scratch + 0x100, scratch],
                false,
            );
            let error = engine.get_data().apis.last_error;
            if result.as_ref().is_ok_and(|result| *result != 0) {
                let width = engine.get_data().architecture.width();
                let handles = read(engine, scratch, (width * 2) as u64)?;
                for raw in handles.chunks_exact(width) {
                    let mut value = [0; 8];
                    value[..width].copy_from_slice(raw);
                    handles::close(engine, u64::from_le_bytes(value));
                }
            }
            allocation::free(engine, &[scratch, 0, 0x8000])?;
            engine.get_data_mut().apis.last_error = error;
            Ok(if result? != 0 {
                33
            } else if error == 193 {
                11
            } else if error == 50 {
                1
            } else {
                u64::from(error.min(31))
            })
        }
        Call::NtQuery => {
            let id = match handles::process(engine, args[0], 0x400) {
                Ok(id) => id,
                Err(_) => return Ok(0xc0000008),
            };
            let width = engine.get_data().architecture.width();
            let size = match args[1] {
                0 => width * 6,
                7 | 26 => width,
                _ => return Ok(0xc0000003),
            };
            if args[4] != 0 && require(engine, args[4], 4, P::WRITE).is_err() {
                return Ok(0xc0000005);
            }
            if args[3] < size as u64 {
                return Ok(0xc0000004);
            }
            if require(engine, args[2], size as u64, P::WRITE).is_err() {
                return Ok(0xc0000005);
            }
            let peb = engine
                .get_data()
                .processes
                .records
                .get(&id)
                .map(|record| record.peb)
                .or_else(|| user_bootstrap::report(engine).map(|report| report.peb))
                .context("Process basic information lacks PEB")?;
            let mut bytes = vec![0; size];
            if args[1] == 0 {
                let code = engine
                    .get_data()
                    .processes
                    .records
                    .get(&id)
                    .and_then(|record| record.exit_code)
                    .unwrap_or(259);
                let parent = engine
                    .get_data()
                    .processes
                    .records
                    .get(&id)
                    .map_or(0, |record| record.parent);
                for (index, value) in [u64::from(code), peb, 1, 8, id, parent]
                    .into_iter()
                    .enumerate()
                {
                    bytes[index * width..(index + 1) * width]
                        .copy_from_slice(&value.to_le_bytes()[..width]);
                }
            } else if args[1] == 26 && width == 4 {
                bytes.copy_from_slice(&(peb as u32).to_le_bytes());
            }
            crate::cpu::write(engine, args[2], &bytes)?;
            if args[4] != 0 {
                crate::cpu::write(engine, args[4], &(size as u32).to_le_bytes())?;
            }
            Ok(0)
        }
        Call::Memory(write) => memory(engine, args, write),
        Call::UnmapSection => section(engine, args),
        Call::Virtual(operation) => virtual_memory(engine, args, operation),
        Call::Thread(call) => thread(engine, args, call),
        Call::Terminate => {
            let id = match handles::process(engine, args[0], 1) {
                Ok(id) => id,
                Err(error) => return Ok(failure(engine, error)),
            };
            if engine
                .get_data()
                .processes
                .records
                .get(&id)
                .is_some_and(|record| record.exit_code.is_some())
            {
                return Ok(1);
            }
            let caller = pid(engine);
            switch(engine, id)?;
            user_lifecycle::request_exit(engine, args[1] as u32, true)?;
            if caller != id {
                finish(engine, empty_outcome(), horizon)?;
                switch(engine, caller)?;
            }
            Ok(1)
        }
        Call::RemoteThread => {
            let id = match handles::process(engine, args[0], 0x43a) {
                Ok(id) => id,
                Err(error) => return Ok(failure(engine, error)),
            };
            if args[6] != 0 && require(engine, args[6], 4, P::WRITE).is_err() {
                return Ok(failure(engine, 998));
            }
            if args[1] != 0 || args[5] & !4 != 0 {
                return Ok(failure(engine, 87));
            }
            let caller = pid(engine);
            switch(engine, id)?;
            let created = user_threads::remote_create(engine, args[2], args[3], args[4], args[5]);
            let error = engine.get_data().apis.last_error;
            switch(engine, caller)?;
            engine.get_data_mut().apis.last_error = error;
            let local = created?;
            if local == 0 {
                return Ok(0);
            }
            let handle =
                match handles::insert(engine, caller, Target::Thread(id, local), THREAD_ALL, 0) {
                    Ok(handle) => handle,
                    Err(error) => return Ok(failure(engine, error)),
                };
            if args[6] != 0 {
                crate::cpu::write(engine, args[6], &(tid(id, local) as u32).to_le_bytes())?;
            }
            Ok(handle)
        }
        _ => Ok(failure(engine, 50)),
    }
}
