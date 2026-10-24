//! Guest-only bounded legacy-profile file namespace mutation.
use super::*;
use emumee_core::filesystem::FileError;
const OWNER: u64 = 1024;
#[derive(Clone, Copy)]
pub(super) enum Call {
    Delete(bool),
    Copy(bool),
    Move(bool, bool),
    RenameHandle,
}
pub(super) fn definition(module: &str, name: &str) -> Option<(Call, usize, T)> {
    if !matches!(
        module,
        "kernel32"
            | "kernelbase"
            | "api-ms-win-core-file-l1-1-0"
            | "api-ms-win-core-file-l1-2-0"
            | "api-ms-win-core-file-l2-1-0"
    ) {
        return None;
    }
    let wide = name.ends_with('W');
    Some(match name {
        "DeleteFileA" | "DeleteFileW" => (Call::Delete(wide), 1, T::U32),
        "CopyFileA" | "CopyFileW" => (Call::Copy(wide), 3, T::U32),
        "MoveFileA" | "MoveFileW" => (Call::Move(wide, false), 2, T::U32),
        "MoveFileExA" | "MoveFileExW" => (Call::Move(wide, true), 3, T::U32),
        "SetFileInformationByHandle" => (Call::RenameHandle, 4, T::U32),
        _ => return None,
    })
}
fn failure(engine: &mut Unicorn<Trace>, error: anyhow::Error) -> Result<u64> {
    if let Some(error) = error.downcast_ref::<FileError>() {
        ensure!(error.win32 != 50, "{error}");
        engine.get_data_mut().apis.last_error = error.win32;
        Ok(0)
    } else {
        Err(error)
    }
}
fn bad(code: u32, reason: &'static str) -> anyhow::Error {
    FileError {
        win32: code,
        reason,
    }
    .into()
}
fn capture(engine: &mut Unicorn<Trace>, path: &str, bytes: Vec<u8>, source: &str) {
    engine.get_data_mut().apis.captures.add(
        bytes,
        emumee_core::artifacts::ArtifactKind::GuestFile,
        source,
        path,
    );
}
fn snapshot(engine: &Unicorn<Trace>, name: &str) -> Result<(String, Vec<u8>)> {
    let fs = &engine.get_data().apis.files;
    let path = fs.path(name)?;
    let bytes = fs.contents(name)?.unwrap_or_default().to_vec();
    Ok((path, bytes))
}
fn renamed(
    engine: &mut Unicorn<Trace>,
    old: &str,
    new: &str,
    flags: u32,
    handle: Option<u64>,
) -> Result<u64> {
    let (source, bytes) = snapshot(engine, old)?;
    let (destination, replaced) = snapshot(engine, new)?;
    let fs = &mut engine.get_data_mut().apis.files;
    if let Some(handle) = handle {
        fs.rename_file_handle(handle, OWNER, new, flags & 1 != 0)?;
    } else {
        fs.move_file(old, new, flags)?;
    }
    if source != destination {
        capture(engine, &destination, replaced, "virtual_file_move_replaced");
    }
    capture(engine, &destination, bytes, "virtual_file_move");
    engine.get_data_mut().apis.last_error = 0;
    Ok(1)
}
fn rename_handle(engine: &mut Unicorn<Trace>, args: &[u64]) -> Result<u64> {
    ensure!(
        args[1] as u32 == 3,
        "SetFileInformationByHandle classes outside FileRenameInfo are not modeled"
    );
    let width = engine.get_data().architecture.width();
    let offset = if width == 8 { 20usize } else { 12 };
    let size = args[3] as u32 as usize;
    if size < offset {
        return Err(bad(24, "short FILE_RENAME_INFO"));
    }
    ensure!(
        size <= offset + 65534,
        "Oversized FILE_RENAME_INFO is not modeled"
    );
    let address = args[2];
    if address == 0 {
        return Err(bad(87, "null FILE_RENAME_INFO"));
    }
    if !engine
        .get_data()
        .apis
        .memory
        .allows(address, offset as u64, P::READ)
    {
        return Err(bad(998, "unreadable FILE_RENAME_INFO header"));
    }
    let raw = read(engine, address, offset as u64)?;
    let root_offset = if width == 8 { 8 } else { 4 };
    let root = raw[root_offset..root_offset + width]
        .iter()
        .any(|b| *b != 0);
    ensure!(
        !root,
        "FILE_RENAME_INFO RootDirectory handles are not modeled"
    );
    ensure!(
        raw[0] <= 1,
        "FILE_RENAME_INFO flags outside ReplaceIfExists are not modeled"
    );
    let length = u32::from_le_bytes(raw[offset - 4..offset].try_into().unwrap()) as usize;
    if length == 0 || length & 1 != 0 {
        return Err(bad(87, "invalid FILE_RENAME_INFO name length"));
    }
    if length > 65534 || length > size - offset {
        return Err(bad(24, "FILE_RENAME_INFO name exceeds supplied buffer"));
    }
    let at = address
        .checked_add(offset as u64)
        .ok_or_else(|| bad(998, "FILE_RENAME_INFO pointer overflow"))?;
    if !engine
        .get_data()
        .apis
        .memory
        .allows(at, length as u64, P::READ)
    {
        return Err(bad(998, "unreadable FILE_RENAME_INFO name"));
    }
    let name = read(engine, at, length as u64)?;
    let units: Vec<_> = name
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect();
    let new = String::from_utf16(&units).map_err(|_| bad(87, "invalid FILE_RENAME_INFO UTF-16"))?;
    if new.is_empty() || new.contains('\0') {
        return Err(bad(87, "invalid FILE_RENAME_INFO name"));
    }
    ensure!(
        !new.starts_with(':'),
        "FILE_RENAME_INFO alternate streams are not modeled"
    );
    let source = engine.get_data().apis.files.handle_path(args[0], OWNER)?;
    renamed(engine, &source, &new, u32::from(raw[0] != 0), Some(args[0]))
}
pub(super) fn invoke(engine: &mut Unicorn<Trace>, args: &[u64], call: Call) -> Result<u64> {
    let result = (|| -> Result<u64> {
        let (wide, index) = match call {
            Call::Delete(w) | Call::Copy(w) | Call::Move(w, _) => (w, Some(0)),
            Call::RenameHandle => (false, None),
        };
        let Some(index) = index else {
            return rename_handle(engine, args);
        };
        let old = filesystem_metadata::name(engine, args[index], wide)?;
        match call {
            Call::Delete(_) => {
                let (path, bytes) = snapshot(engine, &old)?;
                engine.get_data_mut().apis.files.delete_file(&old)?;
                capture(engine, &path, bytes, "virtual_file_delete");
                engine.get_data_mut().apis.last_error = 0;
                Ok(1)
            }
            Call::Copy(_) => {
                let new = filesystem_metadata::name(engine, args[1], wide)?;
                engine
                    .get_data_mut()
                    .apis
                    .files
                    .copy_file(&old, &new, args[2] as u32 != 0)?;
                let (path, bytes) = snapshot(engine, &new)?;
                capture(engine, &path, bytes, "virtual_file_copy");
                engine.get_data_mut().apis.last_error = 0;
                Ok(1)
            }
            Call::Move(_, extended) => {
                let new = filesystem_metadata::name(engine, args[1], wide)?;
                renamed(
                    engine,
                    &old,
                    &new,
                    if extended { args[2] as u32 } else { 0 },
                    None,
                )
            }
            Call::RenameHandle => unreachable!(),
        }
    })();
    match result {
        Ok(value) => Ok(value),
        Err(error) => failure(engine, error),
    }
}
