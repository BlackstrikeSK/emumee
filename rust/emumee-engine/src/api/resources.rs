//! PE resource-directory model: `FindResource*`, `LoadResource`,
//! `LockResource`, `SizeofResource`, `FreeResource` and `LoadStringW`.
//!
//! Every lookup walks the three-level resource tree of a mapped image directly
//! out of guest memory, so it reflects the bytes the sample actually loaded
//! (including any it rewrote). No host resource loader is consulted and no
//! resource storage is invented: a module with no resource directory, or a type
//! / name / language that is not present, fails with the Windows error the
//! guest would see.
use super::*;

#[derive(Clone, Copy)]
pub(super) enum Call {
    /// `FindResourceA`/`FindResourceW`: `wide` picks the string width.
    Find { wide: bool },
    /// `FindResourceExA`/`FindResourceExW`: type/name are swapped and a
    /// language argument follows.
    FindEx { wide: bool },
    Load,
    Lock,
    Sizeof,
    Free,
    /// `LoadStringW` out of a string-table bundle.
    LoadString,
}

// Windows resource errors.
const ERROR_RESOURCE_DATA_NOT_FOUND: u32 = 1812;
const ERROR_RESOURCE_TYPE_NOT_FOUND: u32 = 1813;
const ERROR_RESOURCE_NAME_NOT_FOUND: u32 = 1814;
const ERROR_RESOURCE_LANG_NOT_FOUND: u32 = 1815;
const ERROR_INVALID_PARAMETER: u32 = 87;

const RT_STRING: u32 = 6;

pub(super) fn definition(module: &str, name: &str) -> Option<(Call, usize, T)> {
    let call = match (module, name) {
        ("kernel32" | "kernelbase", "FindResourceA") => (Call::Find { wide: false }, 3, T::Pointer),
        ("kernel32" | "kernelbase", "FindResourceW") => (Call::Find { wide: true }, 3, T::Pointer),
        ("kernel32" | "kernelbase", "FindResourceExA") => {
            (Call::FindEx { wide: false }, 4, T::Pointer)
        }
        ("kernel32" | "kernelbase", "FindResourceExW") => (Call::FindEx { wide: true }, 4, T::Pointer),
        ("kernel32" | "kernelbase", "LoadResource") => (Call::Load, 2, T::Pointer),
        ("kernel32" | "kernelbase", "LockResource") => (Call::Lock, 1, T::Pointer),
        ("kernel32" | "kernelbase", "SizeofResource") => (Call::Sizeof, 2, T::U32),
        ("kernel32" | "kernelbase", "FreeResource") => (Call::Free, 1, T::U32),
        (
            "kernel32" | "kernelbase" | "user32" | "api-ms-win-core-libraryloader-l1-2-0",
            "LoadStringW",
        ) => (Call::LoadString, 4, T::U32),
        _ => return None,
    };
    Some(call)
}

/// Either an integer `MAKEINTRESOURCE` id or a string type/name selector.
enum Selector {
    Id(u32),
    Name(String),
}

impl Selector {
    fn read(engine: &Unicorn<Trace>, value: u64, wide: bool) -> Result<Self> {
        // MAKEINTRESOURCE packs an id in the low word with the rest zero.
        if value <= 0xffff {
            Ok(Selector::Id(value as u32))
        } else {
            Ok(Selector::Name(files::path(engine, value, wide)?.to_ascii_uppercase()))
        }
    }
}

fn read_u16(engine: &Unicorn<Trace>, address: u64) -> Result<u16> {
    let bytes = read(engine, address, 2)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(engine: &Unicorn<Trace>, address: u64) -> Result<u32> {
    let bytes = read(engine, address, 4)?;
    Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
}

/// Resolve `HMODULE` to a mapped base: null means the primary image, otherwise
/// the argument is the base a loader handed back.
fn module_base(engine: &Unicorn<Trace>, handle: u64) -> Result<u64> {
    if handle == 0 {
        engine
            .get_data()
            .apis
            .modules
            .primary()
            .map(|module| module.base)
            .ok_or_else(|| anyhow::anyhow!("Resource lookup has no primary module identity"))
    } else {
        Ok(handle)
    }
}

/// The resource directory's RVA and size from a mapped image's data directory,
/// read out of guest memory so a self-modified header is honored. `None` when
/// the image carries no resource directory.
fn resource_directory(engine: &Unicorn<Trace>, base: u64) -> Result<Option<(u32, u32)>> {
    let lfanew = read_u32(engine, base + 0x3c)?;
    let pe = base + lfanew as u64;
    ensure!(read(engine, pe, 4)? == *b"PE\0\0", "Module header is not a PE image");
    let optional = pe + 24;
    let magic = read_u16(engine, optional)?;
    let dd_offset: u64 = match magic {
        0x10b => 96,
        0x20b => 112,
        _ => bail!("Unsupported optional-header magic {magic:#x}"),
    };
    let count = read_u32(engine, optional + dd_offset - 4)?;
    if count <= 2 {
        return Ok(None);
    }
    let entry = optional + dd_offset + 2 * 8;
    let rva = read_u32(engine, entry)?;
    let size = read_u32(engine, entry + 4)?;
    Ok((rva != 0).then_some((rva, size)))
}

/// Match one `Selector` against a resource directory level and return the
/// child offset (relative to the resource base) the matching entry points at,
/// plus whether that child is a subdirectory (high bit of `OffsetToData`).
fn find_entry(
    engine: &Unicorn<Trace>,
    resource_base: u64,
    dir_offset: u32,
    selector: &Selector,
) -> Result<Option<(u32, bool)>> {
    let dir = resource_base + dir_offset as u64;
    let named = read_u16(engine, dir + 12)? as u64;
    let ids = read_u16(engine, dir + 14)? as u64;
    ensure!(named + ids <= 8192, "Resource directory entry count is implausible");
    for index in 0..(named + ids) {
        let entry = dir + 16 + index * 8;
        let name = read_u32(engine, entry)?;
        let offset = read_u32(engine, entry + 4)?;
        let is_named = name & 0x8000_0000 != 0;
        let matches = match selector {
            Selector::Id(id) => !is_named && name == *id,
            Selector::Name(text) => {
                is_named && {
                    let at = resource_base + (name & 0x7fff_ffff) as u64;
                    let length = read_u16(engine, at)? as u64;
                    ensure!(length <= 4096, "Resource name string is implausibly long");
                    let raw = read(engine, at + 2, length * 2)?;
                    let units: Vec<u16> = raw
                        .chunks_exact(2)
                        .map(|b| u16::from_le_bytes([b[0], b[1]]))
                        .collect();
                    String::from_utf16(&units)
                        .map(|value| value.to_ascii_uppercase() == *text)
                        .unwrap_or(false)
                }
            }
        };
        if matches {
            return Ok(Some((offset & 0x7fff_ffff, offset & 0x8000_0000 != 0)));
        }
    }
    Ok(None)
}

/// Pick a language leaf. `FindResourceEx` asks for an exact language and falls
/// back to the first entry (the neutral/default resource) when it is absent, as
/// the loader does; `FindResource` always takes the first entry.
fn language_leaf(
    engine: &Unicorn<Trace>,
    resource_base: u64,
    dir_offset: u32,
    language: Option<u32>,
) -> Result<Option<u32>> {
    let dir = resource_base + dir_offset as u64;
    let named = read_u16(engine, dir + 12)? as u64;
    let ids = read_u16(engine, dir + 14)? as u64;
    let total = named + ids;
    if total == 0 {
        return Ok(None);
    }
    if let Some(language) = language {
        if let Some((offset, _)) =
            find_entry(engine, resource_base, dir_offset, &Selector::Id(language))?
        {
            return Ok(Some(offset));
        }
    }
    // First entry: lowest id after named entries, i.e. the default resource.
    let entry = dir + 16;
    Ok(Some(read_u32(engine, entry + 4)? & 0x7fff_ffff))
}

/// Walk type -> name -> language to the data-entry offset for a resource.
fn locate(
    engine: &Unicorn<Trace>,
    base: u64,
    resource: (u32, u32),
    kind: &Selector,
    name: &Selector,
    language: Option<u32>,
) -> std::result::Result<u64, u32> {
    let resource_base = base + resource.0 as u64;
    let step = |level: u32, selector: &Selector, miss: u32| -> std::result::Result<u32, u32> {
        match find_entry(engine, resource_base, level, selector) {
            Ok(Some((offset, true))) => Ok(offset),
            Ok(Some((_, false))) => Err(miss),
            Ok(None) => Err(miss),
            Err(_) => Err(miss),
        }
    };
    let type_dir = step(0, kind, ERROR_RESOURCE_TYPE_NOT_FOUND)?;
    let name_dir = step(type_dir, name, ERROR_RESOURCE_NAME_NOT_FOUND)?;
    match language_leaf(engine, resource_base, name_dir, language) {
        Ok(Some(data_offset)) => Ok(resource_base + data_offset as u64),
        _ => Err(ERROR_RESOURCE_LANG_NOT_FOUND),
    }
}

fn fail(engine: &mut Unicorn<Trace>, code: u32) -> Result<u64> {
    engine.get_data_mut().apis.last_error = code;
    Ok(0)
}

pub(super) fn invoke(engine: &mut Unicorn<Trace>, args: &[u64], call: Call) -> Result<u64> {
    match call {
        Call::Find { wide } | Call::FindEx { wide } => {
            let ex = matches!(call, Call::FindEx { .. });
            // FindResource(hModule, lpName, lpType); the Ex form swaps the two
            // selectors and adds a language word.
            let (name_arg, type_arg, language) = if ex {
                (args[2], args[1], Some(args[3] as u16 as u32))
            } else {
                (args[1], args[2], None)
            };
            let base = module_base(engine, args[0])?;
            let Some(resource) = resource_directory(engine, base)? else {
                return fail(engine, ERROR_RESOURCE_TYPE_NOT_FOUND);
            };
            let kind = Selector::read(engine, type_arg, wide)?;
            let name = Selector::read(engine, name_arg, wide)?;
            match locate(engine, base, resource, &kind, &name, language) {
                Ok(entry) => Ok(entry),
                Err(code) => fail(engine, code),
            }
        }
        Call::Load => {
            // LoadResource(hModule, hResInfo): the HRSRC addresses the data
            // entry; the HGLOBAL is the resource's mapped first byte.
            let base = module_base(engine, args[0])?;
            if args[1] == 0 {
                return fail(engine, ERROR_INVALID_PARAMETER);
            }
            let offset = read_u32(engine, args[1])?;
            Ok(base + offset as u64)
        }
        // LockResource is identity on a mapped image: the HGLOBAL already is the
        // first byte. A null handle stays null.
        Call::Lock => Ok(args[0]),
        Call::Sizeof => {
            if args[1] == 0 {
                return fail(engine, ERROR_RESOURCE_DATA_NOT_FOUND);
            }
            Ok(read_u32(engine, args[1] + 4)? as u64)
        }
        // FreeResource is a documented no-op on mapped images and returns FALSE.
        Call::Free => Ok(0),
        Call::LoadString => load_string(engine, args),
    }
}

/// `LoadStringW(hInstance, uID, lpBuffer, cchBufferMax)` out of the RT_STRING
/// bundle that holds string `uID`.
fn load_string(engine: &mut Unicorn<Trace>, args: &[u64]) -> Result<u64> {
    let base = module_base(engine, args[0])?;
    let id = args[1] as u32;
    let buffer = args[2];
    let capacity = args[3] as u32;
    let Some(resource) = resource_directory(engine, base)? else {
        return fail(engine, ERROR_RESOURCE_NAME_NOT_FOUND);
    };
    // A string table stores 16 strings per bundle; the bundle id is 1-based.
    let bundle = (id >> 4) + 1;
    let within = (id & 0xf) as usize;
    let data_entry = match locate(
        engine,
        base,
        resource,
        &Selector::Id(RT_STRING),
        &Selector::Id(bundle),
        None,
    ) {
        Ok(entry) => entry,
        Err(code) => return fail(engine, code),
    };
    let rva = read_u32(engine, data_entry)?;
    let size = read_u32(engine, data_entry + 4)?;
    let mut cursor = base + rva as u64;
    let end = cursor + size as u64;
    let mut units: Vec<u16> = Vec::new();
    for index in 0..16 {
        ensure!(cursor + 2 <= end, "String-table bundle is truncated");
        let length = read_u16(engine, cursor)? as u64;
        cursor += 2;
        ensure!(cursor + length * 2 <= end, "String-table entry overruns its bundle");
        if index == within {
            let raw = read(engine, cursor, length * 2)?;
            units = raw
                .chunks_exact(2)
                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                .collect();
            break;
        }
        cursor += length * 2;
    }
    if capacity == 0 {
        // A zero capacity asks for a read-only pointer to the resource string.
        let pointer = cursor;
        let width = if engine.get_data().architecture == Architecture::X64 {
            8
        } else {
            4
        };
        let bytes = &pointer.to_le_bytes()[..width];
        require(engine, buffer, width as u64, P::WRITE)?;
        crate::cpu::write(engine, buffer, bytes)?;
        return Ok(units.len() as u64);
    }
    let copied = units.len().min(capacity as usize - 1);
    let mut out: Vec<u8> = units[..copied].iter().flat_map(|u| u.to_le_bytes()).collect();
    out.extend([0, 0]);
    require(engine, buffer, out.len() as u64, P::WRITE)?;
    crate::cpu::write(engine, buffer, &out)?;
    Ok(copied as u64)
}
