//! Bounded guest-owned legacy CRT standard streams. This adapter does not bind
//! GetStdHandle/WriteFile: f001..3 are guest console metadata, never host handles.
use super::*;
use anyhow::Context;
use emumee_core::{
    crt_stdio::{BackingKind, CONSOLE_HANDLES, Request, Stdio, Stream, stream_mode},
    virtual_memory as vm,
};
const OWNER: u64 = 1024;
#[derive(Clone, Copy)]
pub(super) enum Call {
    LegacyIob,
    UcrtIob,
    Fileno,
    Write,
    SetMode,
    Flush,
    Isatty,
    OsHandle,
    Errno,
    Open(bool),
    Close,
    Read,
    Seek,
    Tell,
    PutChar,
    Puts,
    Unsupported(&'static str),
}
pub(crate) struct State {
    pub model: Stdio,
}
impl State {
    pub(crate) fn fixture(architecture: Architecture) -> Self {
        let mut model = Stdio::new(architecture);
        model
            .add_process(OWNER, CONSOLE_HANDLES)
            .expect("generated guest console metadata");
        Self { model }
    }
}
pub(super) fn definition(module: &str, name: &str) -> Option<(Call, usize, T)> {
    let msvcrt = module == "msvcrt";
    let ucrt = module == "ucrtbase";
    let private = module == "api-ms-win-crt-private-l1-1-0";
    let stdio = module == "api-ms-win-crt-stdio-l1-1-0";
    let runtime = module == "api-ms-win-crt-runtime-l1-1-0";
    Some(match name {
        "__iob_func" if msvcrt => (Call::LegacyIob, 0, T::Pointer),
        "__acrt_iob_func" if msvcrt || ucrt || stdio => (Call::UcrtIob, 1, T::Pointer),
        "_o___acrt_iob_func" if private => (Call::UcrtIob, 1, T::Pointer),
        "_fileno" if msvcrt || ucrt || stdio => (Call::Fileno, 1, T::U32),
        "_o__fileno" if private => (Call::Fileno, 1, T::U32),
        "_write" if msvcrt || ucrt || stdio => (Call::Write, 3, T::U32),
        "_o__write" if private => (Call::Write, 3, T::U32),
        "_setmode" if msvcrt || ucrt || stdio => (Call::SetMode, 2, T::U32),
        "_o__setmode" if private => (Call::SetMode, 2, T::U32),
        "fflush" if msvcrt || ucrt || stdio => (Call::Flush, 1, T::U32),
        "_o_fflush" if private => (Call::Flush, 1, T::U32),
        "_isatty" if msvcrt || ucrt || stdio => (Call::Isatty, 1, T::U32),
        "_get_osfhandle" if msvcrt || ucrt || stdio => (Call::OsHandle, 1, T::Pointer),
        "_o__get_osfhandle" if private => (Call::OsHandle, 1, T::Pointer),
        "_errno" if msvcrt || ucrt || runtime => (Call::Errno, 0, T::Pointer),
        "fopen" if msvcrt || ucrt || stdio => (Call::Open(false), 2, T::Pointer),
        "_wfopen" if msvcrt || ucrt || stdio => (Call::Open(true), 2, T::Pointer),
        "fclose" if msvcrt || ucrt || stdio => (Call::Close, 1, T::U32),
        "fread" if msvcrt || ucrt || stdio => (Call::Read, 4, T::Pointer),
        "fseek" if msvcrt || ucrt || stdio => (Call::Seek, 3, T::U32),
        "ftell" if msvcrt || ucrt || stdio => (Call::Tell, 1, T::U32),
        "fputc" | "putc" if msvcrt || ucrt || stdio => (Call::PutChar, 2, T::U32),
        "puts" if msvcrt || ucrt || stdio => (Call::Puts, 1, T::U32),
        "_o__errno" if private => (Call::Errno, 0, T::Pointer),
        "printf" | "fprintf" | "wprintf" | "fwprintf" | "_vsnwprintf" | "swprintf_s"
        | "_snwprintf_s"
            if msvcrt || ucrt || stdio =>
        {
            (
                Call::Unsupported("CRT formatted output requires a real guest format model"),
                match name {
                    "printf" | "wprintf" => 1,
                    "fprintf" | "fwprintf" => 2,
                    "swprintf_s" => 3,
                    _ => 4,
                },
                T::U32,
            )
        }
        "__stdio_common_vfprintf" | "__stdio_common_vswprintf" if ucrt || stdio => (
            Call::Unsupported("CRT formatted output requires a real guest format model"),
            if name == "__stdio_common_vfprintf" {
                5
            } else {
                6
            },
            T::U32,
        ),
        "_o___stdio_common_vfprintf" | "_o___stdio_common_vswprintf" if private => (
            Call::Unsupported("CRT formatted output requires a real guest format model"),
            if name == "_o___stdio_common_vfprintf" {
                5
            } else {
                6
            },
            T::U32,
        ),
        _ => return None,
    })
}
/// Call before nonzero-address recommit, release/decommit or protection changes.
/// Ordinary guest RW access to FILE/errno remains allowed; only mapping ownership
/// changes are stopped. Process cleanup must unmap pages using trusted VM plans.
pub(crate) fn require_allocation_change(
    engine: &Unicorn<Trace>,
    address: u64,
    size: u64,
) -> Result<()> {
    ensure!(
        !engine
            .get_data()
            .apis
            .crt_stdio
            .model
            .owned_overlap(OWNER, address, size)?,
        "Guest allocation change overlaps CRT-owned FILE/errno storage"
    );
    Ok(())
}
fn backing(engine: &mut Unicorn<Trace>, kind: BackingKind) -> Result<u64> {
    match engine
        .get_data()
        .apis
        .crt_stdio
        .model
        .backing(OWNER, kind)?
    {
        Request::Existing(address) => {
            ensure!(
                engine.get_data().apis.memory.allows(address, 4096, P::RW),
                "CRT-owned guest backing lost readable/writable mapping"
            );
            Ok(address)
        }
        Request::Allocate { image, size } => {
            let state = &engine.get_data().apis;
            let plan = state
                .allocations
                .allocate(&state.memory, 0, size, vm::RESERVE | vm::COMMIT, 4)
                .map_err(|error| anyhow::anyhow!("CRT owned allocation failed: {error}"))?;
            let address = allocation::apply(engine, plan)?;
            ensure!(
                engine.get_data().apis.memory.allows(address, size, P::RW),
                "CRT guest allocation lacks RW mapping"
            );
            crate::cpu::write(engine, address, &image)?;
            engine
                .get_data_mut()
                .apis
                .crt_stdio
                .model
                .register_backing(OWNER, kind, address, size)?;
            Ok(address)
        }
    }
}
pub(super) fn invoke(engine: &mut Unicorn<Trace>, args: &[u64], call: Call) -> Result<u64> {
    Ok(match call {
        Call::LegacyIob => backing(engine, BackingKind::LegacyIob)?,
        Call::UcrtIob => {
            ensure!(
                args[0] <= 2,
                "CRT stdio profile unsupported: nonstandard UCRT FILE index"
            );
            backing(engine, BackingKind::UcrtIob)? + args[0] * 0x80
        }
        Call::Errno => {
            let thread = crate::threads::current_id(engine);
            backing(engine, BackingKind::Errno(thread))?
        }
        Call::Fileno => engine
            .get_data()
            .apis
            .crt_stdio
            .model
            .fileno(OWNER, args[0])? as u32 as u64,
        Call::Flush => engine
            .get_data()
            .apis
            .crt_stdio
            .model
            .fflush(OWNER, args[0])? as u32 as u64,
        Call::Isatty => engine
            .get_data()
            .apis
            .crt_stdio
            .model
            .isatty(OWNER, args[0] as u32 as i32) as u64,
        Call::OsHandle => engine
            .get_data()
            .apis
            .crt_stdio
            .model
            .os_handle(OWNER, args[0] as u32 as i32)?,
        Call::SetMode => engine.get_data_mut().apis.crt_stdio.model.setmode(
            OWNER,
            args[0] as u32 as i32,
            args[1] as u32,
        )? as u64,
        Call::Write => {
            let descriptor = args[0] as u32 as i32;
            let count = args[2] as u32 as usize;
            engine
                .get_data()
                .apis
                .crt_stdio
                .model
                .validate_write(OWNER, descriptor, count)?;
            let bytes = if count == 0 {
                Vec::new()
            } else {
                ensure!(
                    args[1] != 0
                        && engine
                            .get_data()
                            .apis
                            .memory
                            .allows(args[1], count as u64, P::READ),
                    "CRT stdio write buffer is not readable guest memory"
                );
                read(engine, args[1], count as u64)?
            };
            engine
                .get_data_mut()
                .apis
                .crt_stdio
                .model
                .write(OWNER, descriptor, &bytes)? as u64
        }
        Call::Unsupported(reason) => bail!("{reason}"),
        // fopen resolves the guest path through the virtual file system and
        // binds one page-owned FILE to the handle it returns.
        Call::Open(wide) => {
            if args[0] == 0 || args[1] == 0 {
                return Ok(0);
            }
            let path = super::files::path(engine, args[0], wide)?;
            let mode = {
                let raw = super::files::path(engine, args[1], wide)?;
                stream_mode(&raw)?
            };
            let (number, descriptor) = engine
                .get_data_mut()
                .apis
                .crt_stdio
                .model
                .next_stream(OWNER)?;
            let opened = engine.get_data_mut().apis.files.open(
                &path,
                mode.access,
                3,
                mode.disposition,
                OWNER,
            );
            let (handle, last) = match opened {
                Ok(value) => value,
                Err(error) => {
                    engine.get_data_mut().apis.last_error = error.win32;
                    return Ok(0);
                }
            };
            engine.get_data_mut().apis.last_error = last;
            if mode.append {
                engine
                    .get_data_mut()
                    .apis
                    .files
                    .seek(handle, OWNER, 0, 2)?;
            }
            let address = backing(engine, BackingKind::Stream(number))?;
            let image = engine
                .get_data()
                .apis
                .crt_stdio
                .model
                .stream_image(descriptor, mode);
            crate::cpu::write(engine, address, &image)?;
            engine
                .get_data_mut()
                .apis
                .crt_stdio
                .model
                .register_stream(Stream {
                    owner: OWNER,
                    number,
                    address,
                    handle,
                    descriptor,
                    readable: mode.readable,
                    writable: mode.writable,
                })?;
            address
        }
        Call::Close => {
            if args[0] == 0 {
                return Ok(u64::from(u32::MAX));
            }
            let record = engine
                .get_data_mut()
                .apis
                .crt_stdio
                .model
                .retire_stream(OWNER, args[0])?;
            engine
                .get_data_mut()
                .apis
                .files
                .close(record.handle, OWNER)?;
            // The FILE page stays mapped: retiring guest memory here would
            // invalidate a pointer the guest may still hold.
            0
        }
        Call::Read => {
            let record = stream(engine, args[3])?;
            ensure!(record.readable, "CRT stream was not opened for reading");
            let Some(total) = args[1].checked_mul(args[2]) else {
                return Ok(0);
            };
            if total == 0 || args[0] == 0 {
                return Ok(0);
            }
            ensure!(
                total <= emumee_core::crt_stdio::MAX_RAW as u64,
                "CRT stream read exceeds the modeled transfer bound"
            );
            require(engine, args[0], total, P::WRITE)?;
            let bytes = engine.get_data_mut().apis.files.read(
                record.handle,
                OWNER,
                total as usize,
            )?;
            if !bytes.is_empty() {
                crate::cpu::write(engine, args[0], &bytes)?;
            }
            // fread reports whole items, as the C contract requires.
            bytes.len() as u64 / args[1]
        }
        Call::Seek => {
            let record = stream(engine, args[0])?;
            ensure!(args[2] <= 2, "CRT stream seek origin is not modeled");
            let offset = args[1] as u32 as i32 as i64;
            match engine
                .get_data_mut()
                .apis
                .files
                .seek(record.handle, OWNER, offset, args[2] as u32)
            {
                Ok(_) => 0,
                Err(_) => u64::from(u32::MAX),
            }
        }
        Call::Tell => {
            let record = stream(engine, args[0])?;
            match engine
                .get_data_mut()
                .apis
                .files
                .seek(record.handle, OWNER, 0, 1)
            {
                Ok(position) => position,
                Err(_) => u64::from(u32::MAX),
            }
        }
        // fputc writes one byte, unlike the frozen reference which only echoed
        // the character back without producing output.
        Call::PutChar => {
            let byte = args[0] as u8;
            if let Ok(descriptor) = engine
                .get_data()
                .apis
                .crt_stdio
                .model
                .fileno(OWNER, args[1])
                && (1..=2).contains(&descriptor)
            {
                engine
                    .get_data_mut()
                    .apis
                    .crt_stdio
                    .model
                    .write(OWNER, descriptor, &[byte])?;
                return Ok(u64::from(byte));
            }
            let record = stream(engine, args[1])?;
            ensure!(record.writable, "CRT stream was not opened for writing");
            engine
                .get_data_mut()
                .apis
                .files
                .write(record.handle, OWNER, &[byte])?;
            u64::from(byte)
        }
        Call::Puts => {
            ensure!(args[0] != 0, "CRT puts string pointer is null");
            let mut text = Vec::new();
            for index in 0..emumee_core::crt_stdio::MAX_WRITE as u64 {
                let byte = read(engine, args[0] + index, 1)?[0];
                if byte == 0 {
                    break;
                }
                text.push(byte);
            }
            ensure!(
                text.len() < emumee_core::crt_stdio::MAX_WRITE,
                "CRT puts string exceeds the modeled output bound"
            );
            text.push(b'\n');
            let written = engine
                .get_data_mut()
                .apis
                .crt_stdio
                .model
                .write(OWNER, 1, &text)?;
            // puts returns a nonnegative value on success.
            u64::from(written != 0)
        }
    })
}
/// The opened stream a guest FILE pointer names, or an explicit stop.
fn stream(engine: &Unicorn<Trace>, address: u64) -> Result<Stream> {
    engine
        .get_data()
        .apis
        .crt_stdio
        .model
        .opened(OWNER, address)
        .context("CRT stream pointer is not an opened guest FILE")
}
