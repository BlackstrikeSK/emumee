//! Metadata/path/enumeration APIs over the actual in-memory guest VFS catalog.
use super::*;
use emumee_core::{
    filesystem::{FileError, PathPlan, Searches},
    persona::Encoding,
};
const OWNER: u64 = 1024;
#[derive(Clone, Copy)]
pub(super) enum Call {
    Create(bool),
    Remove(bool),
    Attributes(bool),
    SetAttributes(bool),
    AttributesEx(bool),
    First(bool),
    Next(bool),
    Close,
    FullPath(bool),
    LongPath(bool),
    ShortPath(bool),
    FirstEx(bool),
    TempFileName(bool),
    BinaryType(bool),
    SetCurrent(bool),
}
#[derive(Default)]
pub(crate) struct State {
    pub searches: Searches,
}
pub(super) fn definition(module: &str, name: &str) -> Option<(Call, usize, T)> {
    let kernel = matches!(module, "kernel32" | "kernelbase");
    let file = kernel
        || matches!(
            module,
            "api-ms-win-core-file-l1-1-0"
                | "api-ms-win-core-file-l1-2-0"
                | "api-ms-win-core-file-l2-1-0"
        );
    let process = kernel
        || matches!(
            module,
            "api-ms-win-core-processenvironment-l1-1-0"
                | "api-ms-win-core-processenvironment-l1-2-0"
        );
    let wide = name.ends_with('W');
    Some(match name {
        "CreateDirectoryA" | "CreateDirectoryW" if file => (Call::Create(wide), 2, T::U32),
        "RemoveDirectoryA" | "RemoveDirectoryW" if file => (Call::Remove(wide), 1, T::U32),
        "GetFileAttributesA" | "GetFileAttributesW" if file => (Call::Attributes(wide), 1, T::U32),
        "SetFileAttributesA" | "SetFileAttributesW" if file => {
            (Call::SetAttributes(wide), 2, T::U32)
        }
        "GetFileAttributesExA" | "GetFileAttributesExW" if file => {
            (Call::AttributesEx(wide), 3, T::U32)
        }
        "FindFirstFileA" | "FindFirstFileW" if file => (Call::First(wide), 2, T::Pointer),
        "FindNextFileA" | "FindNextFileW" if file => (Call::Next(wide), 2, T::U32),
        "FindClose" if file => (Call::Close, 1, T::U32),
        "GetFullPathNameA" | "GetFullPathNameW" if file => (Call::FullPath(wide), 4, T::U32),
        "GetLongPathNameA" | "GetLongPathNameW" if file => (Call::LongPath(wide), 3, T::U32),
        // The modeled volume generates no 8.3 aliases, exactly like a Windows
        // volume with short-name creation disabled, so the short path is the
        // long path.
        "GetShortPathNameA" | "GetShortPathNameW" if file => (Call::ShortPath(wide), 3, T::U32),
        // Only the generic spelling is declared; its structure and search
        // arguments decide nothing this profile does not already model.
        "FindFirstFileEx" if file => (Call::FirstEx(false), 6, T::Pointer),
        "GetTempFileNameA" | "GetTempFileNameW" if file => {
            (Call::TempFileName(wide), 4, T::U32)
        }
        "GetBinaryType" if kernel => (Call::BinaryType(false), 2, T::U32),
        "SetCurrentDirectoryA" | "SetCurrentDirectoryW" if process || file => {
            (Call::SetCurrent(wide), 1, T::U32)
        }
        _ => return None,
    })
}
/// The COFF machine of a guest PE image, read from its own headers.
fn pe_machine(bytes: &[u8]) -> Option<u16> {
    if bytes.len() < 0x40 || bytes[..2] != *b"MZ" {
        return None;
    }
    let offset = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
    let header = offset.checked_add(6)?;
    if header > bytes.len() || bytes[offset..offset + 4] != *b"PE\0\0" {
        return None;
    }
    Some(u16::from_le_bytes(
        bytes[offset + 4..offset + 6].try_into().unwrap(),
    ))
}
fn failure(engine: &mut Unicorn<Trace>, error: FileError, value: u64) -> Result<u64> {
    ensure!(error.win32 != 50, "{error}");
    engine.get_data_mut().apis.last_error = error.win32;
    Ok(value)
}
fn bad(engine: &mut Unicorn<Trace>, code: u32, value: u64) -> Result<u64> {
    engine.get_data_mut().apis.last_error = code;
    Ok(value)
}
fn invalid(engine: &Unicorn<Trace>) -> u64 {
    if engine.get_data().architecture == Architecture::X86 {
        u32::MAX as u64
    } else {
        u64::MAX
    }
}
pub(super) fn name(engine: &Unicorn<Trace>, address: u64, wide: bool) -> Result<String> {
    if address == 0 {
        return Err(FileError {
            win32: 87,
            reason: "null guest path",
        }
        .into());
    }
    let width = if wide { 2 } else { 1 };
    let mut bytes = Vec::new();
    for index in 0..32768u64 {
        let at = address.checked_add(index * width).ok_or(FileError {
            win32: 998,
            reason: "guest path pointer overflow",
        })?;
        if !engine.get_data().apis.memory.allows(at, width, P::READ) {
            return Err(FileError {
                win32: 998,
                reason: "unreadable guest path",
            }
            .into());
        }
        let unit = read(engine, at, width)?;
        if unit.iter().all(|u| *u == 0) {
            if bytes.is_empty() {
                return Err(FileError {
                    win32: 87,
                    reason: "empty guest path",
                }
                .into());
            }
            let encoding = if wide {
                Encoding::Utf16
            } else {
                Encoding::Cp1252
            };
            return encoding.decode(&bytes).map_err(|_| {
                FileError {
                    win32: 50,
                    reason: "malformed guest path encoding",
                }
                .into()
            });
        }
        bytes.extend(unit);
    }
    Err(FileError {
        win32: 87,
        reason: "unterminated or excessive guest path",
    }
    .into())
}
fn writable(engine: &Unicorn<Trace>, address: u64, size: u64) -> bool {
    address != 0
        && engine
            .get_data()
            .apis
            .memory
            .allows(address, size, P::WRITE)
}
fn names_failure(engine: &mut Unicorn<Trace>, error: anyhow::Error, value: u64) -> Result<u64> {
    if let Some(error) = error.downcast_ref::<FileError>() {
        ensure!(error.win32 != 50, "{error}");
        engine.get_data_mut().apis.last_error = error.win32;
        Ok(value)
    } else {
        Err(error)
    }
}
fn path_output(
    engine: &mut Unicorn<Trace>,
    plan: PathPlan,
    output: u64,
    file_part: u64,
) -> Result<u64> {
    let Some(bytes) = plan.bytes else {
        return Ok(plan.result as u64);
    };
    let width = engine.get_data().architecture.width() as u64;
    if !writable(engine, output, bytes.len() as u64)
        || (file_part != 0 && !writable(engine, file_part, width))
    {
        return bad(engine, 87, 0);
    }
    let pointer = if let Some(offset) = plan.file_part_offset {
        output
            .checked_add(offset)
            .ok_or_else(|| anyhow::anyhow!("Guest file-part output pointer overflow"))?
    } else {
        0
    };
    if file_part != 0 {
        let end = output
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| anyhow::anyhow!("Guest path output range overflow"))?;
        let part_end = file_part
            .checked_add(width)
            .ok_or_else(|| anyhow::anyhow!("Guest file-part range overflow"))?;
        ensure!(
            file_part >= end || part_end <= output,
            "Overlapping path and file-part output storage is not modeled"
        );
        ensure!(
            width == 8 || pointer <= u32::MAX as u64,
            "Guest file-part output exceeds x86 width"
        );
    }
    crate::cpu::write(engine, output, &bytes)?;
    if file_part != 0 {
        let bytes = if width == 8 {
            pointer.to_le_bytes().to_vec()
        } else {
            (pointer as u32).to_le_bytes().to_vec()
        };
        crate::cpu::write(engine, file_part, &bytes)?;
    }
    engine.get_data_mut().apis.last_error = 0;
    Ok(plan.result as u64)
}
pub(super) fn invoke(engine: &mut Unicorn<Trace>, args: &[u64], call: Call) -> Result<u64> {
    if let Call::Close = call {
        return match engine
            .get_data_mut()
            .apis
            .file_metadata
            .searches
            .close(OWNER, args[0])
        {
            Ok(()) => Ok(1),
            Err(error) => failure(engine, error, 0),
        };
    }
    if let Call::Next(wide) = call {
        let entry = match engine
            .get_data()
            .apis
            .file_metadata
            .searches
            .peek_next(OWNER, args[0])
        {
            Ok(entry) => entry,
            Err(error) => return failure(engine, error, 0),
        };
        let image = match entry.find_data(wide) {
            Ok(image) => image,
            Err(error) => return failure(engine, error, 0),
        };
        if !writable(engine, args[1], image.len() as u64) {
            return bad(engine, 998, 0);
        }
        crate::cpu::write(engine, args[1], &image)?;
        engine
            .get_data_mut()
            .apis
            .file_metadata
            .searches
            .advance(OWNER, args[0])?;
        return Ok(1);
    }
    let wide = match call {
        Call::Create(w)
        | Call::Remove(w)
        | Call::Attributes(w)
        | Call::SetAttributes(w)
        | Call::AttributesEx(w)
        | Call::First(w)
        | Call::FirstEx(w)
        | Call::FullPath(w)
        | Call::LongPath(w)
        | Call::ShortPath(w)
        | Call::TempFileName(w)
        | Call::BinaryType(w)
        | Call::SetCurrent(w) => w,
        _ => unreachable!(),
    };
    let fail_value = match call {
        Call::Attributes(_) => u32::MAX as u64,
        Call::First(_) | Call::FirstEx(_) => invalid(engine),
        _ => 0,
    };
    let path = match name(engine, args[0], wide) {
        Ok(path) => path,
        Err(error) => return names_failure(engine, error, fail_value),
    };
    match call {
        Call::Create(_) => {
            ensure!(
                args[1] == 0,
                "Directory security attributes are not modeled"
            );
            match engine.get_data_mut().apis.files.create_directory(&path) {
                Ok(()) => {
                    engine.get_data_mut().apis.last_error = 0;
                    Ok(1)
                }
                Err(error) => failure(engine, error, 0),
            }
        }
        Call::Remove(_) => match engine.get_data_mut().apis.files.remove_directory(&path) {
            Ok(()) => {
                engine.get_data_mut().apis.last_error = 0;
                Ok(1)
            }
            Err(error) => failure(engine, error, 0),
        },
        Call::Attributes(_) => match engine.get_data().apis.files.metadata(&path) {
            Ok(meta) => {
                engine.get_data_mut().apis.last_error = 0;
                Ok(meta.attributes as u64)
            }
            Err(error) => failure(engine, error, fail_value),
        },
        Call::SetAttributes(_) => match engine
            .get_data_mut()
            .apis
            .files
            .set_attributes(&path, args[1] as u32)
        {
            Ok(()) => {
                engine.get_data_mut().apis.last_error = 0;
                Ok(1)
            }
            Err(error) => failure(engine, error, 0),
        },
        Call::AttributesEx(_) => {
            if args[1] as u32 != 0 {
                return bad(engine, 87, 0);
            }
            let metadata = match engine.get_data().apis.files.metadata(&path) {
                Ok(meta) => meta,
                Err(error) => return failure(engine, error, 0),
            };
            let image = metadata.image();
            if !writable(engine, args[2], image.len() as u64) {
                return bad(engine, 998, 0);
            }
            crate::cpu::write(engine, args[2], &image)?;
            engine.get_data_mut().apis.last_error = 0;
            Ok(1)
        }
        Call::TempFileName(_) => {
            // The directory must already exist as a directory; this call never
            // creates one, and a file of that name is not one.
            if !matches!(engine.get_data().apis.files.is_directory(&path), Ok(true)) {
                return bad(engine, 3, 0);
            }
            let prefix: String = if args[1] == 0 {
                String::new()
            } else {
                match name(engine, args[1], wide) {
                    // Only the first three characters are used, as documented.
                    Ok(text) => text.chars().take(3).collect(),
                    Err(error) => return names_failure(engine, error, 0),
                }
            };
            let compose = |unique: u32| format!("{path}\\{prefix}{unique:04x}.tmp");
            // A zero request asks this call to pick a free name and create the
            // file; a supplied number is used as given and creates nothing.
            let (unique, create) = if args[2] as u32 == 0 {
                let mut chosen = None;
                for candidate in 1..=0xffffu32 {
                    if matches!(
                        engine.get_data().apis.files.exists(&compose(candidate)),
                        Ok(false)
                    ) {
                        chosen = Some(candidate);
                        break;
                    }
                }
                match chosen {
                    Some(candidate) => (candidate, true),
                    None => return bad(engine, 80, 0),
                }
            } else {
                (args[2] as u32 & 0xffff, false)
            };
            let chosen = compose(unique);
            let encoding = if wide {
                Encoding::Utf16
            } else {
                Encoding::Cp1252
            };
            let bytes = encoding.encode(&chosen, true);
            if !writable(engine, args[3], bytes.len() as u64) {
                return bad(engine, 998, 0);
            }
            if create {
                // CREATE_NEW with write access, immediately closed, leaves the
                // empty file the documented contract promises.
                let handle = match engine
                    .get_data_mut()
                    .apis
                    .files
                    .open(&chosen, 0x40000000, 0, 1, OWNER)
                {
                    Ok((handle, _)) => handle,
                    Err(error) => return failure(engine, error, 0),
                };
                if let Err(error) = engine.get_data_mut().apis.files.close(handle, OWNER) {
                    return failure(engine, error, 0);
                }
            }
            crate::cpu::write(engine, args[3], &bytes)?;
            engine.get_data_mut().apis.last_error = 0;
            Ok(unique.into())
        }
        Call::BinaryType(_) => {
            if !writable(engine, args[1], 4) {
                return bad(engine, 998, 0);
            }
            let contents = match engine.get_data().apis.files.contents(&path) {
                Ok(Some(bytes)) => bytes.to_vec(),
                Ok(None) => return bad(engine, 2, 0),
                Err(error) => return failure(engine, error, 0),
            };
            // Classify from the guest file's own headers; no host image is
            // consulted and no execution happens here.
            let machine = pe_machine(&contents);
            let kind = match machine {
                Some(0x14c) => 0u32,
                Some(0x8664) => 6,
                // ERROR_BAD_EXE_FORMAT covers both a non-PE file and a machine
                // this profile does not classify.
                _ => return bad(engine, 193, 0),
            };
            crate::cpu::write(engine, args[1], &kind.to_le_bytes())?;
            engine.get_data_mut().apis.last_error = 0;
            Ok(1)
        }
        Call::ShortPath(_) => {
            match engine
                .get_data()
                .apis
                .files
                .long_path(&path, wide, args[2] as u32)
            {
                Ok(plan) => path_output(engine, plan, args[1], 0),
                Err(error) => failure(engine, error, 0),
            }
        }
        Call::First(wide) | Call::FirstEx(wide) => {
            // The extended spelling takes its output buffer after the
            // information level, so the structure address differs.
            let output = if let Call::FirstEx(_) = call {
                // FindExInfoStandard/FindExInfoBasic over a name match, with no
                // filter and no additional flags, is the whole modeled profile.
                // The information level, the search operation and the
                // additional flags are DWORDs; only the filter is a pointer.
                ensure!(
                    matches!(args[1] as u32, 0 | 1)
                        && args[3] as u32 == 0
                        && args[4] == 0
                        && args[5] as u32 == 0,
                    "FindFirstFileEx information level, search operation, filter or flags are not modeled"
                );
                args[2]
            } else {
                args[1]
            };
            let entries = match engine.get_data().apis.files.enumerate(&path) {
                Ok(entries) => entries,
                Err(error) => return failure(engine, error, fail_value),
            };
            let plan = match engine
                .get_data()
                .apis
                .file_metadata
                .searches
                .plan_first(OWNER, &path, entries)
            {
                Ok(plan) => plan,
                Err(error) => return failure(engine, error, fail_value),
            };
            let image = match plan.entry().find_data(wide) {
                Ok(image) => image,
                Err(error) => return failure(engine, error, fail_value),
            };
            if !writable(engine, output, image.len() as u64) {
                return bad(engine, 998, fail_value);
            }
            crate::cpu::write(engine, output, &image)?;
            engine
                .get_data_mut()
                .apis
                .file_metadata
                .searches
                .commit_first(plan)
                .map_err(Into::into)
        }
        Call::FullPath(_) => {
            match engine
                .get_data()
                .apis
                .files
                .full_path(&path, wide, args[1] as u32)
            {
                Ok(plan) => path_output(engine, plan, args[2], args[3]),
                Err(error) => failure(engine, error, 0),
            }
        }
        Call::LongPath(_) => {
            match engine
                .get_data()
                .apis
                .files
                .long_path(&path, wide, args[2] as u32)
            {
                Ok(plan) => path_output(engine, plan, args[1], 0),
                Err(error) => failure(engine, error, 0),
            }
        }
        Call::SetCurrent(_) => {
            let plan = match engine.get_data().apis.files.directory_plan(&path) {
                Ok(plan) => plan,
                Err(error) => return failure(engine, error, 0),
            };
            let mut persona = engine.get_data().apis.persona.model.clone();
            persona.commit_directory(OWNER, plan.display())?;
            // VFS commit revalidates before mutation. Once it succeeds, publish
            // prevalidated persona with no fallible or guest-visible step left.
            if let Err(error) = engine.get_data_mut().apis.files.commit_directory(plan) {
                return failure(engine, error, 0);
            }
            engine.get_data_mut().apis.persona.model = persona;
            super::user_bootstrap::refresh_process(engine)?;
            engine.get_data_mut().apis.last_error = 0;
            Ok(1)
        }
        Call::Next(_) | Call::Close => unreachable!(),
    }
}
