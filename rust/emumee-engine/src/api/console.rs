//! Guest console bridge. Ordinary guest files keep the existing VFS route.
use super::*;
use emumee_core::{
    console::{self as model, AliasOptions, Console, ConsoleError, Kind, WritePlan, WriteSource},
    crt_stdio::ConsoleWrite,
};
const OWNER: u64 = 1024;
#[derive(Clone, Copy)]
pub(super) enum Call {
    GetStd,
    SetStd,
    Write(bool),
    FileType,
    GetMode,
    SetMode,
    CodePage,
    Screen,
    FileCreate(bool),
    FileTransfer(bool),
    FileClose,
    Allocate,
    Window,
    Title { wide: bool, set: bool },
    CtrlHandler,
    HistoryInfo,
}
pub(crate) struct State {
    pub model: Console,
    /// Title the guest itself set. No title is published until then: this
    /// profile has no window manager to supply a launcher's caption.
    title: Option<String>,
    /// Recorded Ctrl handlers. No console control event is ever delivered in
    /// this profile, so a recorded handler is never dispatched.
    ctrl_handlers: Vec<(u64, bool)>,
}
impl State {
    pub(crate) fn fixture() -> Self {
        let mut model = Console::new(437).expect("generated CP437 guest profile");
        model.add_process(OWNER).expect("generated console owner");
        Self {
            model,
            title: None,
            ctrl_handlers: Vec::new(),
        }
    }
}
pub(super) fn definition(module: &str, name: &str) -> Option<(Call, usize, T)> {
    let kernel = matches!(module, "kernel32" | "kernelbase");
    let console = kernel
        || matches!(
            module,
            "api-ms-win-core-console-l1-1-0" | "api-ms-win-core-console-l2-1-0"
        );
    let process = kernel
        || matches!(
            module,
            "api-ms-win-core-processenvironment-l1-1-0"
                | "api-ms-win-core-processenvironment-l1-2-0"
        );
    let file = matches!(
        module,
        "api-ms-win-core-file-l1-1-0" | "api-ms-win-core-file-l1-2-0"
    );
    Some(match name {
        "GetStdHandle" if process => (Call::GetStd, 1, T::Pointer),
        "SetStdHandle" if process => (Call::SetStd, 2, T::U32),
        "WriteConsoleA" if console => (Call::Write(false), 5, T::U32),
        "WriteConsoleW" if console => (Call::Write(true), 5, T::U32),
        "GetFileType" if kernel || file => (Call::FileType, 1, T::U32),
        "GetConsoleMode" if console => (Call::GetMode, 2, T::U32),
        "SetConsoleMode" if console => (Call::SetMode, 2, T::U32),
        "GetConsoleCP" | "GetConsoleOutputCP" if console => (Call::CodePage, 0, T::U32),
        "GetConsoleScreenBufferInfo" if console => (Call::Screen, 2, T::U32),
        "AllocConsole" if console => (Call::Allocate, 0, T::U32),
        "GetConsoleWindow" if console => (Call::Window, 0, T::Pointer),
        "GetConsoleTitleA" | "GetConsoleTitleW" if console => (
            Call::Title {
                wide: name.ends_with('W'),
                set: false,
            },
            2,
            T::U32,
        ),
        "SetConsoleTitleA" | "SetConsoleTitleW" if console => (
            Call::Title {
                wide: name.ends_with('W'),
                set: true,
            },
            1,
            T::U32,
        ),
        "SetConsoleCtrlHandler" if console => (Call::CtrlHandler, 2, T::U32),
        "SetConsoleHistoryInfo" if console => (Call::HistoryInfo, 1, T::U32),
        "CreateFileA" if file => (Call::FileCreate(false), 7, T::Pointer),
        "CreateFileW" if file => (Call::FileCreate(true), 7, T::Pointer),
        "WriteFile" if file => (Call::FileTransfer(true), 5, T::U32),
        "ReadFile" if file => (Call::FileTransfer(false), 5, T::U32),
        "CloseHandle" if file => (Call::FileClose, 1, T::U32),
        _ => return None,
    })
}
fn standard(engine: &Unicorn<Trace>) -> Result<[u64; 3]> {
    Ok(engine
        .get_data()
        .apis
        .crt_stdio
        .model
        .standard_handles(OWNER)?)
}
fn selector(value: u64) -> Option<usize> {
    match value as u32 {
        0xfffffff6 => Some(0),
        0xfffffff5 => Some(1),
        0xfffffff4 => Some(2),
        _ => None,
    }
}
fn invalid(engine: &Unicorn<Trace>) -> u64 {
    if engine.get_data().architecture == Architecture::X86 {
        u32::MAX as u64
    } else {
        u64::MAX
    }
}
fn fail(engine: &mut Unicorn<Trace>, error: ConsoleError, value: u64) -> Result<u64> {
    ensure!(error.win32 != 50, "{error}");
    engine.get_data_mut().apis.last_error = error.win32;
    Ok(value)
}
fn ordinary(engine: &mut Unicorn<Trace>, code: u32) -> Result<u64> {
    engine.get_data_mut().apis.last_error = code;
    Ok(0)
}
fn writable(engine: &Unicorn<Trace>, address: u64, size: u64) -> bool {
    address != 0
        && engine
            .get_data()
            .apis
            .memory
            .allows(address, size, P::WRITE)
}
fn commit(engine: &mut Unicorn<Trace>, plan: WritePlan) -> Result<u64> {
    let count = plan.units;
    engine
        .get_data_mut()
        .apis
        .crt_stdio
        .model
        .append_console(ConsoleWrite {
            owner: OWNER,
            descriptor: plan.descriptor,
            data: &plan.bytes,
            text: &plan.text,
            encoding: plan.encoding,
            mode: plan.mode,
            kind: plan.kind,
        })?;
    engine.get_data_mut().apis.last_error = 0;
    Ok(count as u64)
}
pub(super) fn create(engine: &mut Unicorn<Trace>, args: &[u64], name: &str) -> Result<Option<u64>> {
    if !name.eq_ignore_ascii_case("conin$") && !name.eq_ignore_ascii_case("conout$") {
        return Ok(None);
    }
    let options = AliasOptions {
        access: args[1] as u32,
        share: args[2] as u32,
        security: args[3],
        disposition: args[4] as u32,
        flags: args[5] as u32,
        template: args[6],
    };
    let result = engine
        .get_data_mut()
        .apis
        .console
        .model
        .open(OWNER, name, options);
    Ok(Some(match result {
        Ok(handle) => {
            engine.get_data_mut().apis.last_error = 0;
            handle
        }
        Err(error) => {
            let value = invalid(engine);
            fail(engine, error, value)?
        }
    }))
}
pub(super) fn close(engine: &mut Unicorn<Trace>, handle: u64) -> Result<Option<u64>> {
    ensure!(
        !emumee_core::crt_stdio::CONSOLE_HANDLES.contains(&handle),
        "Closing default console handles requires object lifetime integration; close owned aliases instead"
    );
    if !model::reserved_alias(handle) {
        return Ok(None);
    }
    let result = engine
        .get_data_mut()
        .apis
        .console
        .model
        .close(OWNER, handle);
    Ok(Some(match result {
        Ok(()) => {
            engine.get_data_mut().apis.last_error = 0;
            1
        }
        Err(error) => fail(engine, error, 0)?,
    }))
}
/// Some(...) consumes only the reserved console namespace. None means the
/// existing VFS transfer owns this handle. A retired/foreign alias never falls
/// through and cannot become an unrelated file or a fabricated stdin EOF.
pub(super) fn transfer(
    engine: &mut Unicorn<Trace>,
    args: &[u64],
    write: bool,
) -> Result<Option<u64>> {
    if !engine.get_data().apis.console.model.claimed(args[0]) {
        return Ok(None);
    }
    ensure!(args[4] == 0, "Console overlapped I/O is not modeled");
    if args[3] == 0 {
        return ordinary(engine, 87).map(Some);
    }
    if !writable(engine, args[3], 4) {
        return ordinary(engine, 998).map(Some);
    }
    let std = standard(engine)?;
    let kind = engine
        .get_data()
        .apis
        .console
        .model
        .kind(OWNER, args[0], std);
    if !write {
        if matches!(kind, Ok(Some(Kind::Input))) {
            bail!("Guest console stdin input is not modeled");
        }
        crate::cpu::write(engine, args[3], &0u32.to_le_bytes())?;
        return ordinary(engine, 6).map(Some);
    }
    let count = args[2] as u32 as u64;
    if count != 0 {
        let end = args[1]
            .checked_add(count)
            .ok_or_else(|| anyhow::anyhow!("Console write buffer overflow"))?;
        let count_end = args[3]
            .checked_add(4)
            .ok_or_else(|| anyhow::anyhow!("Console count pointer overflow"))?;
        ensure!(
            args[1] >= count_end || args[3] >= end,
            "Overlapping console write/count storage is not modeled"
        );
    }
    // Synchronous WriteFile initializes the caller's count before ordinary
    // validation failures. Unsupported overlapped/aliasing profiles stop above.
    crate::cpu::write(engine, args[3], &0u32.to_le_bytes())?;
    if let Err(error) = kind {
        return fail(engine, error, 0).map(Some);
    }
    if count > model::MAX_FILE_WRITE as u64 {
        return ordinary(engine, 8).map(Some);
    }
    if count != 0
        && (args[1] == 0
            || !engine
                .get_data()
                .apis
                .memory
                .allows(args[1], count, P::READ))
    {
        return ordinary(engine, 998).map(Some);
    }
    let bytes = if count == 0 {
        Vec::new()
    } else {
        read(engine, args[1], count)?
    };
    let plan =
        engine
            .get_data()
            .apis
            .console
            .model
            .write(OWNER, args[0], std, bytes, WriteSource::File);
    match plan {
        Ok(plan) => {
            let written = plan.units;
            commit(engine, plan)?;
            crate::cpu::write(engine, args[3], &written.to_le_bytes())?;
            Ok(Some(1))
        }
        Err(error) => fail(engine, error, 0).map(Some),
    }
}
fn write_console(engine: &mut Unicorn<Trace>, args: &[u64], wide: bool) -> Result<u64> {
    let std = standard(engine)?;
    if let Err(error) = engine
        .get_data()
        .apis
        .console
        .model
        .stream(OWNER, args[0], std)
    {
        return fail(engine, error, 0);
    }
    let count = args[2] as u32 as u64;
    if args[4] != 0 || (count != 0 && args[1] == 0) {
        return ordinary(engine, 87);
    }
    let bytes = count * if wide { 2 } else { 1 };
    if bytes > model::MAX_CONSOLE_WRITE as u64 {
        return ordinary(engine, 8);
    }
    if bytes != 0
        && !engine
            .get_data()
            .apis
            .memory
            .allows(args[1], bytes, P::READ)
    {
        return ordinary(engine, 998);
    }
    if args[3] != 0 && !writable(engine, args[3], 4) {
        return ordinary(engine, 998);
    }
    let payload = if bytes == 0 {
        Vec::new()
    } else {
        read(engine, args[1], bytes)?
    };
    let plan = engine.get_data().apis.console.model.write(
        OWNER,
        args[0],
        std,
        payload,
        if wide {
            WriteSource::Wide
        } else {
            WriteSource::Ansi
        },
    );
    match plan {
        Ok(plan) => {
            // Core validation and all guest ranges precede any visible output.
            if args[3] != 0 {
                crate::cpu::write(engine, args[3], &(count as u32).to_le_bytes())?;
            }
            commit(engine, plan)?;
            Ok(1)
        }
        Err(error) => fail(engine, error, 0),
    }
}
pub(super) fn invoke(engine: &mut Unicorn<Trace>, args: &[u64], call: Call) -> Result<u64> {
    match call {
        Call::GetStd => {
            let Some(index) = selector(args[0]) else {
                let value = invalid(engine);
                engine.get_data_mut().apis.last_error = 87;
                return Ok(value);
            };
            Ok(standard(engine)?[index])
        }
        Call::SetStd => {
            let Some(index) = selector(args[0]) else {
                return ordinary(engine, 87);
            };
            engine
                .get_data_mut()
                .apis
                .crt_stdio
                .model
                .set_standard_handle(OWNER, index, args[1])?;
            Ok(1)
        }
        Call::Write(wide) => write_console(engine, args, wide),
        Call::CodePage => Ok(engine.get_data().apis.console.model.code_page() as u64),
        Call::FileType => {
            match engine
                .get_data()
                .apis
                .console
                .model
                .kind(OWNER, args[0], standard(engine)?)
            {
                Ok(Some(_)) => Ok(2),
                Err(error) => fail(engine, error, 0),
                Ok(None) => match engine.get_data().apis.files.size(args[0], OWNER) {
                    Ok(_) => Ok(1),
                    Err(error) => {
                        engine.get_data_mut().apis.last_error = error.win32;
                        Ok(0)
                    }
                },
            }
        }
        Call::GetMode => {
            let result =
                engine
                    .get_data()
                    .apis
                    .console
                    .model
                    .mode(OWNER, args[0], standard(engine)?);
            match result {
                Ok(mode) => {
                    if !writable(engine, args[1], 4) {
                        return ordinary(engine, 998);
                    }
                    crate::cpu::write(engine, args[1], &mode.to_le_bytes())?;
                    engine.get_data_mut().apis.last_error = 0;
                    Ok(1)
                }
                Err(error) => fail(engine, error, 0),
            }
        }
        Call::SetMode => {
            let std = standard(engine)?;
            let result = engine.get_data_mut().apis.console.model.set_mode(
                OWNER,
                args[0],
                std,
                args[1] as u32,
            );
            match result {
                Ok(()) => {
                    engine.get_data_mut().apis.last_error = 0;
                    Ok(1)
                }
                Err(error) => fail(engine, error, 0),
            }
        }
        Call::Screen => {
            let result =
                engine
                    .get_data()
                    .apis
                    .console
                    .model
                    .screen(OWNER, args[0], standard(engine)?);
            match result {
                Ok(bytes) => {
                    if !writable(engine, args[1], bytes.len() as u64) {
                        return ordinary(engine, 87);
                    }
                    crate::cpu::write(engine, args[1], &bytes)?;
                    engine.get_data_mut().apis.last_error = 0;
                    Ok(1)
                }
                Err(error) => fail(engine, error, 0),
            }
        }
        Call::FileCreate(wide) => files::create(engine, args, wide),
        Call::FileTransfer(write) => files::transfer(engine, args, write),
        Call::FileClose => files::close(engine, args),
        // A console is already attached to the modeled process, and Windows
        // refuses a second one.
        Call::Allocate => ordinary(engine, 5),
        // There is no window manager, so the console has no window handle. This
        // is the same answer Windows gives a process whose console has no
        // associated window.
        Call::Window => Ok(0),
        Call::Title { wide, set } => {
            if set {
                let text = text_input(engine, args[0], wide)?;
                engine.get_data_mut().apis.console.title = Some(text);
                engine.get_data_mut().apis.last_error = 0;
                Ok(1)
            } else {
                let title = engine
                    .get_data()
                    .apis
                    .console
                    .title
                    .clone()
                    .unwrap_or_default();
                // The capacity is a DWORD, so only its low half is the
                // caller's own value.
                let capacity = u64::from(args[1] as u32);
                if args[0] == 0 || capacity == 0 {
                    return ordinary(engine, 87);
                }
                // Windows truncates rather than failing, and reports the
                // character count it actually copied.
                let width = if wide { 2usize } else { 1 };
                let mut units: Vec<char> = title.chars().collect();
                units.truncate((capacity - 1) as usize);
                let text: String = units.into_iter().collect();
                let encoding = if wide {
                    emumee_core::persona::Encoding::Utf16
                } else {
                    emumee_core::persona::Encoding::Cp1252
                };
                let bytes = encoding.encode(&text, true);
                if !writable(engine, args[0], bytes.len() as u64) {
                    return ordinary(engine, 998);
                }
                crate::cpu::write(engine, args[0], &bytes)?;
                engine.get_data_mut().apis.last_error = 0;
                Ok(((bytes.len() / width) - 1) as u64)
            }
        }
        Call::CtrlHandler => {
            // A null routine with add set asks for Ctrl+C to be ignored; both
            // forms are recorded and neither is ever dispatched, because no
            // console control event exists in this profile.
            // Add is a BOOL, a DWORD; the upper half of its stack slot is
            // not the caller's value.
            let add = args[1] as u32 != 0;
            let handlers = &mut engine.get_data_mut().apis.console.ctrl_handlers;
            if add {
                if handlers.len() >= 32 {
                    return ordinary(engine, 8);
                }
                handlers.push((args[0], true));
            } else if let Some(index) = handlers
                .iter()
                .rposition(|(routine, _)| *routine == args[0])
            {
                handlers.remove(index);
            } else {
                return ordinary(engine, 87);
            }
            engine.get_data_mut().apis.last_error = 0;
            Ok(1)
        }
        Call::HistoryInfo => {
            // CONSOLE_HISTORY_INFO is four DWORDs. The modeled console keeps no
            // command history, so the settings are validated and then have
            // nothing to change.
            if !engine
                .get_data()
                .apis
                .memory
                .allows(args[0], 16, P::READ)
            {
                return ordinary(engine, 998);
            }
            let size = u32::from_le_bytes(read(engine, args[0], 4)?.try_into().unwrap());
            if size != 16 {
                return ordinary(engine, 87);
            }
            engine.get_data_mut().apis.last_error = 0;
            Ok(1)
        }
    }
}
/// Read a NUL-terminated guest string for the console title.
fn text_input(engine: &Unicorn<Trace>, address: u64, wide: bool) -> Result<String> {
    ensure!(address != 0, "Null console title pointer");
    let width = if wide { 2u64 } else { 1 };
    let mut units = Vec::new();
    for index in 0..1024u64 {
        let at = address
            .checked_add(index * width)
            .ok_or_else(|| anyhow::anyhow!("Console title pointer overflow"))?;
        let unit = if wide {
            u16::from_le_bytes(read(engine, at, 2)?.try_into().unwrap())
        } else {
            u16::from(byte(engine, at)?)
        };
        if unit == 0 {
            return if wide {
                String::from_utf16(&units)
                    .map_err(|_| anyhow::anyhow!("Invalid UTF-16 console title"))
            } else {
                emumee_core::persona::Encoding::Cp1252
                    .decode(&units.into_iter().map(|u| u as u8).collect::<Vec<_>>())
                    .map_err(Into::into)
            };
        }
        units.push(unit);
    }
    bail!("Console title exceeds the modeled 1024 character bound")
}
