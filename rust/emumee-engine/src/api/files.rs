//! Synchronous guest-only file APIs. No std::fs or native file calls are used.
use super::*;
use anyhow::Context;
use emumee_core::filesystem::FileError;
const OWNER: u64 = 1024;
fn fail(engine: &mut Unicorn<Trace>, error: FileError, failure: u64) -> Result<u64> {
    ensure!(error.win32 != 50, "{}", error);
    engine.get_data_mut().apis.last_error = error.win32;
    Ok(failure)
}
fn valid_output(engine: &mut Unicorn<Trace>, address: u64, length: u64) -> bool {
    if length == 0
        || engine
            .get_data()
            .apis
            .memory
            .allows(address, length, P::WRITE)
    {
        true
    } else {
        engine.get_data_mut().apis.last_error = 998;
        false
    }
}
pub(super) fn path(engine: &Unicorn<Trace>, address: u64, wide: bool) -> Result<String> {
    let mut units = Vec::new();
    for index in 0..32768u64 {
        let at = address
            .checked_add(index * if wide { 2 } else { 1 })
            .context("Guest path pointer overflow")?;
        let unit = if wide {
            let raw = read(engine, at, 2)?;
            u16::from_le_bytes(raw.try_into().unwrap())
        } else {
            byte(engine, at)? as u16
        };
        if unit == 0 {
            return if wide {
                String::from_utf16(&units).map_err(|_| anyhow::anyhow!("Invalid UTF-16 guest path"))
            } else {
                emumee_core::persona::Encoding::Cp1252
                    .decode(&units.into_iter().map(|u| u as u8).collect::<Vec<_>>())
                    .map_err(Into::into)
            };
        }
        units.push(unit);
    }
    bail!("Guest path exceeds 32768 characters")
}
pub(super) fn create(engine: &mut Unicorn<Trace>, args: &[u64], wide: bool) -> Result<u64> {
    let name = path(engine, args[0], wide)?;
    if let Some(value) = console::create(engine, args, &name)? {
        return Ok(value);
    }
    ensure!(
        args[3] == 0 && args[6] == 0,
        "CreateFile security/template parameters are not modeled"
    );
    ensure!(
        [0, 0x80].contains(&(args[5] as u32)),
        "CreateFile flags/attributes 0x{:x} are not modeled",
        args[5]
    );
    let result = engine.get_data_mut().apis.files.open(
        &name,
        args[1] as u32,
        args[2] as u32,
        args[4] as u32,
        OWNER,
    );
    let failure = if engine.get_data().architecture == Architecture::X86 {
        u32::MAX as u64
    } else {
        u64::MAX
    };
    match result {
        Ok((handle, last)) => {
            engine.get_data_mut().apis.last_error = last;
            Ok(handle)
        }
        Err(error) => fail(engine, error, failure),
    }
}
pub(super) fn transfer(engine: &mut Unicorn<Trace>, args: &[u64], write: bool) -> Result<u64> {
    if let Some(value) = console::transfer(engine, args, write)? {
        return Ok(value);
    }
    ensure!(
        args[4] == 0,
        "Overlapped file I/O requires the pending I/O model"
    );
    let count = args[2] as u32 as u64;
    ensure!(
        count <= MAX_TRANSFER,
        "File I/O exceeds 16MiB transfer bound"
    );
    if !valid_output(engine, args[3], 4) {
        return Ok(0);
    }
    if write {
        let data = read(engine, args[1], count)?;
        match engine
            .get_data_mut()
            .apis
            .files
            .write(args[0], OWNER, &data)
        {
            Ok(written) => {
                crate::cpu::write(engine, args[3], &(written as u32).to_le_bytes())?;
                Ok(1)
            }
            Err(error) => fail(engine, error, 0),
        }
    } else {
        if !valid_output(engine, args[1], count) {
            return Ok(0);
        }
        match engine
            .get_data_mut()
            .apis
            .files
            .read(args[0], OWNER, count as usize)
        {
            Ok(data) => {
                if !data.is_empty() {
                    crate::cpu::write(engine, args[1], &data)?;
                }
                crate::cpu::write(engine, args[3], &(data.len() as u32).to_le_bytes())?;
                Ok(1)
            }
            Err(error) => fail(engine, error, 0),
        }
    }
}
pub(super) fn seek(engine: &mut Unicorn<Trace>, args: &[u64]) -> Result<u64> {
    let offset = if args[2] == 0 {
        args[1] as u32 as i32 as i64
    } else {
        if !valid_output(engine, args[2], 4) {
            return Ok(u32::MAX as u64);
        }
        let high = u32::from_le_bytes(read(engine, args[2], 4)?.try_into().unwrap());
        ((high as u64) << 32 | args[1] as u32 as u64) as i64
    };
    match engine
        .get_data_mut()
        .apis
        .files
        .seek(args[0], OWNER, offset, args[3] as u32)
    {
        Ok(position) => {
            if args[2] != 0 {
                crate::cpu::write(engine, args[2], &((position >> 32) as u32).to_le_bytes())?;
            }
            engine.get_data_mut().apis.last_error = 0;
            Ok(position as u32 as u64)
        }
        Err(error) => fail(engine, error, u32::MAX as u64),
    }
}
pub(super) fn size(engine: &mut Unicorn<Trace>, args: &[u64]) -> Result<u64> {
    if !valid_output(engine, args[1], 8) {
        return Ok(0);
    }
    match engine.get_data().apis.files.size(args[0], OWNER) {
        Ok(size) => {
            crate::cpu::write(engine, args[1], &size.to_le_bytes())?;
            Ok(1)
        }
        Err(error) => fail(engine, error, 0),
    }
}
pub(super) fn close(engine: &mut Unicorn<Trace>, args: &[u64]) -> Result<u64> {
    if let Some(value) = console::close(engine, args[0])? {
        return Ok(value);
    }
    match engine.get_data_mut().apis.files.close(args[0], OWNER) {
        Ok(()) => Ok(1),
        Err(error) => fail(engine, error, 0),
    }
}
