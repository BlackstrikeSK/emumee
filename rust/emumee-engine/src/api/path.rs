//! `shlwapi` path-string helpers. Every function operates on guest buffers only,
//! as fixed-width code units, so pointer returns land exactly inside the caller
//! buffer and in-place edits write back the modified string. No host path API
//! and no filesystem are touched; these are pure string transforms.
use super::*;

const LIMIT: u64 = 32768;
const SEP: u16 = b'\\' as u16;
const SLASH: u16 = b'/' as u16;
const DOT: u16 = b'.' as u16;
const COLON: u16 = b':' as u16;

#[derive(Clone, Copy)]
pub(super) enum Call {
    AddBackslash,
    Append,
    Canonicalize,
    FindExtension,
    FindFileName,
    IsRelative,
    RemoveExtension,
    RemoveFileSpec,
    RenameExtension,
    StripPath,
}

pub(super) fn definition(module: &str, name: &str) -> Option<(Call, usize, T, bool)> {
    if module != "shlwapi" {
        return None;
    }
    let wide = name.ends_with('W');
    // `PathCanonicalize` with no width tail is the narrow export.
    let (call, count, returns) = match name {
        "PathAddBackslashA" | "PathAddBackslashW" => (Call::AddBackslash, 1, T::Pointer),
        "PathAppendA" | "PathAppendW" => (Call::Append, 2, T::U32),
        "PathCanonicalize" | "PathCanonicalizeA" | "PathCanonicalizeW" => {
            (Call::Canonicalize, 2, T::U32)
        }
        "PathFindExtensionA" | "PathFindExtensionW" => (Call::FindExtension, 1, T::Pointer),
        "PathFindFileNameA" | "PathFindFileNameW" => (Call::FindFileName, 1, T::Pointer),
        "PathIsRelativeA" | "PathIsRelativeW" => (Call::IsRelative, 1, T::U32),
        "PathRemoveExtensionA" | "PathRemoveExtensionW" => (Call::RemoveExtension, 1, T::U32),
        "PathRemoveFileSpecA" | "PathRemoveFileSpecW" => (Call::RemoveFileSpec, 1, T::U32),
        "PathRenameExtensionA" | "PathRenameExtensionW" => (Call::RenameExtension, 2, T::U32),
        "PathStripPathA" | "PathStripPathW" => (Call::StripPath, 1, T::U32),
        _ => return None,
    };
    Some((call, count, returns, wide))
}

fn width(wide: bool) -> u64 {
    if wide {
        2
    } else {
        1
    }
}

/// Read a null-terminated string as fixed-width code units.
fn read_units(engine: &Unicorn<Trace>, address: u64, wide: bool) -> Result<Vec<u16>> {
    let mut units = Vec::new();
    for index in 0..LIMIT {
        let at = address
            .checked_add(index * width(wide))
            .ok_or_else(|| anyhow::anyhow!("Path pointer overflow"))?;
        let unit = if wide {
            let raw = read(engine, at, 2)?;
            u16::from_le_bytes([raw[0], raw[1]])
        } else {
            byte(engine, at)? as u16
        };
        if unit == 0 {
            return Ok(units);
        }
        units.push(unit);
    }
    bail!("Path exceeds its modeled length bound")
}

/// Write units back as a null-terminated string of the same width.
fn write_units(engine: &mut Unicorn<Trace>, address: u64, units: &[u16], wide: bool) -> Result<()> {
    let mut bytes = Vec::with_capacity((units.len() + 1) * width(wide) as usize);
    for &unit in units {
        if wide {
            bytes.extend(unit.to_le_bytes());
        } else {
            bytes.push(unit as u8);
        }
    }
    bytes.extend(std::iter::repeat_n(0u8, width(wide) as usize));
    require(engine, address, bytes.len() as u64, P::WRITE)?;
    crate::cpu::write(engine, address, &bytes)
}

fn is_sep(unit: u16) -> bool {
    unit == SEP || unit == SLASH
}

/// Index just past the last separator, i.e. the start of the file name.
fn file_name_start(units: &[u16]) -> usize {
    units
        .iter()
        .rposition(|&u| is_sep(u) || u == COLON)
        .map(|index| index + 1)
        .unwrap_or(0)
}

/// Index of the extension dot in the last component, or the length if none.
fn extension_index(units: &[u16]) -> usize {
    let start = file_name_start(units);
    units[start..]
        .iter()
        .rposition(|&u| u == DOT)
        .map(|index| start + index)
        .unwrap_or(units.len())
}

pub(super) fn invoke(engine: &mut Unicorn<Trace>, args: &[u64], call: Call, wide: bool) -> Result<u64> {
    let w = width(wide);
    match call {
        Call::AddBackslash => {
            let mut units = read_units(engine, args[0], wide)?;
            if units.last() != Some(&SEP) {
                units.push(SEP);
                write_units(engine, args[0], &units, wide)?;
            }
            // Pointer to the terminating null.
            Ok(args[0] + units.len() as u64 * w)
        }
        Call::Append => {
            let mut path = read_units(engine, args[0], wide)?;
            let more = if args[1] != 0 {
                read_units(engine, args[1], wide)?
            } else {
                Vec::new()
            };
            while path.last() == Some(&SEP) || path.last() == Some(&SLASH) {
                path.pop();
            }
            let more: Vec<u16> = more.into_iter().skip_while(|&u| is_sep(u)).collect();
            if !more.is_empty() {
                if !path.is_empty() {
                    path.push(SEP);
                }
                path.extend(more);
            }
            write_units(engine, args[0], &path, wide)?;
            Ok(1)
        }
        Call::Canonicalize => {
            let src = read_units(engine, args[1], wide)?;
            let canonical = canonicalize(&src);
            write_units(engine, args[0], &canonical, wide)?;
            Ok(1)
        }
        Call::FindExtension => Ok(args[0] + extension_index(&read_units(engine, args[0], wide)?) as u64 * w),
        Call::FindFileName => {
            let units = read_units(engine, args[0], wide)?;
            Ok(args[0] + file_name_start(&units) as u64 * w)
        }
        Call::IsRelative => {
            let units = read_units(engine, args[0], wide)?;
            let relative = match units.as_slice() {
                [] => true,
                [first, ..] if is_sep(*first) => false,
                [_, second, ..] if *second == COLON => false,
                _ => true,
            };
            Ok(relative as u64)
        }
        Call::RemoveExtension => {
            let mut units = read_units(engine, args[0], wide)?;
            units.truncate(extension_index(&units));
            write_units(engine, args[0], &units, wide)?;
            Ok(0)
        }
        Call::RemoveFileSpec => {
            let units = read_units(engine, args[0], wide)?;
            let cut = match units.iter().rposition(|&u| is_sep(u)) {
                Some(index) if index > 0 && units[index - 1] == COLON => index + 1, // keep root slash
                Some(index) => index,
                None => 0,
            };
            let changed = cut != units.len();
            write_units(engine, args[0], &units[..cut], wide)?;
            Ok(changed as u64)
        }
        Call::RenameExtension => {
            let mut units = read_units(engine, args[0], wide)?;
            let ext = read_units(engine, args[1], wide)?;
            units.truncate(extension_index(&units));
            units.extend(ext);
            write_units(engine, args[0], &units, wide)?;
            Ok(1)
        }
        Call::StripPath => {
            let units = read_units(engine, args[0], wide)?;
            let name = units[file_name_start(&units)..].to_vec();
            write_units(engine, args[0], &name, wide)?;
            Ok(0)
        }
    }
}

/// Resolve `.` and `..` components, preserving a leading `X:` drive and a
/// leading separator.
fn canonicalize(src: &[u16]) -> Vec<u16> {
    // Separate an optional drive prefix ("X:") from the rest.
    let (prefix, rest) = if src.len() >= 2 && src[1] == COLON {
        (src[..2].to_vec(), &src[2..])
    } else {
        (Vec::new(), src)
    };
    let rooted = rest.first().is_some_and(|&u| is_sep(u));
    let mut stack: Vec<Vec<u16>> = Vec::new();
    for component in rest.split(|&u| is_sep(u)).filter(|c| !c.is_empty()) {
        if component == [DOT] {
            continue;
        }
        if component == [DOT, DOT] {
            stack.pop();
            continue;
        }
        stack.push(component.to_vec());
    }
    let mut out = prefix;
    if rooted {
        out.push(SEP);
    }
    for (index, component) in stack.iter().enumerate() {
        if index > 0 {
            out.push(SEP);
        }
        out.extend_from_slice(component);
    }
    out
}
