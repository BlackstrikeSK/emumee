//! Bounded guest-owned legacy CRT standard streams. This adapter does not bind
//! GetStdHandle/WriteFile: f001..3 are guest console metadata, never host handles.
use super::*;
use emumee_core::{
    crt_stdio::{BackingKind, CONSOLE_HANDLES, Request, Stdio},
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
    })
}
