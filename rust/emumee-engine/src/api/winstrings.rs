//! Bounded Windows text APIs over guest bytes and fixed code-page tables.
use super::*;
use emumee_core::{codepage::CodePage, persona::Encoding};
#[cfg(test)]
#[path = "winstrings_tests.rs"]
mod tests;
const LIMIT: usize = 32767;
#[derive(Clone, Copy)]
pub(super) enum Call {
    Length(bool),
    Compare(bool),
    Find,
    Upper,
    Lower,
    Trim,
    Oem,
    Unicode,
    Convert(bool),
    Ansi,
    OemPage,
    ValidPage,
    CpInfo,
    Dbcs,
    CharOem,
    Presence,
}
pub(super) fn definition(module: &str, name: &str) -> Option<(Call, usize, T, C)> {
    let kernel = matches!(module, "kernel32" | "kernelbase");
    let strings = kernel || module.starts_with("api-ms-win-core-string-");
    let locale = kernel || module.starts_with("api-ms-win-core-localization-");
    let crt = matches!(
        module,
        "msvcrt" | "ucrtbase" | "api-ms-win-crt-private-l1-1-0" | "api-ms-win-crt-string-l1-1-0"
    );
    let mut convention = C::Stdcall;
    let (call, count, returns) = match name {
        "lstrlenA" | "lstrlenW" if kernel => (Call::Length(name.ends_with('W')), 1, T::U32),
        "CompareStringA" | "CompareStringW" if strings => {
            (Call::Compare(name.ends_with('W')), 6, T::U32)
        }
        "FindStringOrdinal" if kernel || module == "api-ms-win-core-libraryloader-l1-2-0" => {
            (Call::Find, 6, T::U32)
        }
        "CharUpperW" if strings || module == "user32" => (Call::Upper, 1, T::Pointer),
        "_wcslwr" if crt => {
            convention = C::Cdecl;
            (Call::Lower, 1, T::Pointer)
        }
        "StrTrimW" if module == "shlwapi" => (Call::Trim, 2, T::U32),
        "RtlOemToUnicodeN" if module == "ntdll" => (Call::Oem, 5, T::U32),
        "RtlIsTextUnicode" if module == "ntdll" => (Call::Unicode, 3, T::U32),
        "WideCharToMultiByte" if strings => (Call::Convert(true), 8, T::U32),
        "MultiByteToWideChar" if strings => (Call::Convert(false), 6, T::U32),
        "GetACP" if locale => (Call::Ansi, 0, T::U32),
        "GetOEMCP" if locale => (Call::OemPage, 0, T::U32),
        "IsValidCodePage" if locale => (Call::ValidPage, 1, T::U32),
        "GetCPInfo" if locale => (Call::CpInfo, 2, T::U32),
        "IsDBCSLeadByte" if locale => (Call::Dbcs, 1, T::U32),
        "CharToOemA"
            if matches!(
                module,
                "user32" | "ext-ms-win-ntuser-chartranslation-l1-1-0"
            ) =>
        {
            (Call::CharOem, 2, T::U32)
        }
        "ApiSetQueryApiSetPresence" if module == "api-ms-win-core-apiquery-l1-1-0" => {
            (Call::Presence, 2, T::U32)
        }
        _ => return None,
    };
    Some((call, count, returns, convention))
}
fn fail(engine: &mut Unicorn<Trace>, error: u32) -> u64 {
    engine.get_data_mut().apis.last_error = error;
    0
}
fn accessible(engine: &Unicorn<Trace>, at: u64, len: usize, permission: P) -> bool {
    at != 0
        && engine
            .get_data()
            .apis
            .memory
            .allows(at, len as u64, permission)
}
fn put(engine: &mut Unicorn<Trace>, at: u64, bytes: &[u8]) -> Result<()> {
    require(engine, at, bytes.len() as u64, P::WRITE)?;
    crate::cpu::write(engine, at, bytes)
}
fn raw(engine: &Unicorn<Trace>, at: u64, count: i32, wide: bool) -> Option<Vec<u8>> {
    if at == 0 || count < -1 || count > LIMIT as i32 {
        return None;
    }
    let width = if wide { 2 } else { 1 };
    if count >= 0 {
        return read(engine, at, count as u64 * width).ok();
    }
    let mut bytes = vec![];
    for i in 0..=LIMIT {
        let p = at.checked_add(i as u64 * width)?;
        let b = read(engine, p, width).ok()?;
        if b.iter().all(|v| *v == 0) {
            return Some(bytes);
        }
        bytes.extend(b);
    }
    None
}
fn text(engine: &Unicorn<Trace>, at: u64, count: i32, wide: bool) -> Option<String> {
    let b = raw(engine, at, count, wide)?;
    if wide {
        Encoding::Utf16.decode(&b).ok()
    } else {
        CodePage::Ansi1252.decode(&b)
    }
}
fn unsupported<T>(engine: &mut Unicorn<Trace>, reason: &str, value: T) -> T {
    let state = &mut engine.get_data_mut().apis.winstrings;
    if state.len() < 1024 && !state.iter().any(|s| s == reason) {
        state.push(reason.into());
    }
    value
}
pub(super) fn invoke(engine: &mut Unicorn<Trace>, args: &[u64], call: Call) -> Result<u64> {
    Ok(match call {
        Call::Ansi => 1252,
        Call::OemPage => 437,
        Call::Dbcs => 0,
        Call::ValidPage => u64::from(CodePage::resolve(args[0] as u32, 437).is_some()),
        Call::CpInfo => {
            let Some(page) = CodePage::resolve(args[0] as u32, 437) else {
                return Ok(fail(engine, 87));
            };
            if !accessible(engine, args[1], 20, P::WRITE) {
                return Ok(fail(engine, 87));
            }
            let mut b = [0; 20];
            b[..4].copy_from_slice(&(if page.utf8() { 4u32 } else { 1 }).to_le_bytes());
            b[4] = b'?';
            put(engine, args[1], &b)?;
            1
        }
        Call::Length(wide) => text(engine, args[0], -1, wide).map_or(0, |s| {
            if wide {
                s.encode_utf16().count() as u64
            } else {
                s.chars().count() as u64
            }
        }),
        Call::Compare(wide) => {
            let flags = args[1] as u32;
            if flags & !0x30001 != 0 {
                return Ok(fail(engine, 1004));
            }
            let (Some(mut left), Some(mut right)) = (
                text(engine, args[2], args[3] as i32, wide),
                text(engine, args[4], args[5] as i32, wide),
            ) else {
                return Ok(fail(engine, 87));
            };
            if !left.is_ascii() || !right.is_ascii() {
                unsupported(engine, "CompareString: non-ASCII collation unavailable", ());
                return Ok(fail(engine, 87));
            }
            if flags & 1 != 0 {
                left.make_ascii_lowercase();
                right.make_ascii_lowercase();
            }
            match left.cmp(&right) {
                std::cmp::Ordering::Less => 1,
                std::cmp::Ordering::Equal => 2,
                std::cmp::Ordering::Greater => 3,
            }
        }
        Call::Find => {
            let flags = args[0] as u32;
            if !matches!(flags, 0x100000 | 0x200000 | 0x400000 | 0x800000) {
                fail(engine, 1004);
                return Ok(u32::MAX.into());
            }
            let (Some(mut source), Some(mut value)) = (
                text(engine, args[1], args[2] as i32, true),
                text(engine, args[3], args[4] as i32, true),
            ) else {
                fail(engine, 87);
                return Ok(u32::MAX.into());
            };
            if args[5] as u32 > 1 {
                fail(engine, 87);
                return Ok(u32::MAX.into());
            }
            if args[5] as u32 == 1 {
                if !source.is_ascii() || !value.is_ascii() {
                    unsupported(
                        engine,
                        "FindStringOrdinal: non-ASCII case fold unavailable",
                        (),
                    );
                    fail(engine, 87);
                    return Ok(u32::MAX.into());
                }
                source.make_ascii_lowercase();
                value.make_ascii_lowercase();
            }
            let index = match flags {
                0x100000 => source.starts_with(&value).then_some(0),
                0x200000 => source.ends_with(&value).then(|| source.len() - value.len()),
                0x800000 => source.rfind(&value),
                _ => source.find(&value),
            };
            engine.get_data_mut().apis.last_error = 0;
            index.map_or(u32::MAX as u64, |i| {
                source[..i].encode_utf16().count() as u64
            })
        }
        Call::Upper | Call::Lower => {
            let address = args[0];
            if matches!(call, Call::Upper) && address <= 0xffff {
                return Ok(if address < 128 {
                    u64::from((address as u8).to_ascii_uppercase())
                } else {
                    unsupported(engine, "CharUpperW: non-ASCII mapping unavailable", address)
                });
            }
            let Some(value) = text(engine, address, -1, true) else {
                return Ok(unsupported(
                    engine,
                    "Case mapping: inaccessible string",
                    address,
                ));
            };
            if !value.is_ascii() {
                return Ok(unsupported(
                    engine,
                    "Case mapping: non-ASCII mapping unavailable",
                    address,
                ));
            }
            let mapped = if matches!(call, Call::Upper) {
                value.to_ascii_uppercase()
            } else {
                value.to_ascii_lowercase()
            };
            let b = Encoding::Utf16.encode(&mapped, true);
            if accessible(engine, address, b.len(), P::WRITE) {
                put(engine, address, &b)?;
            } else {
                unsupported(engine, "Case mapping: destination not writable", ());
            }
            address
        }
        Call::Trim => {
            let (Some(value), Some(chars)) = (
                text(engine, args[0], -1, true),
                text(engine, args[1], -1, true),
            ) else {
                return Ok(unsupported(engine, "StrTrimW: inaccessible string", 0));
            };
            let trimmed = value.trim_matches(|ch| chars.contains(ch));
            if trimmed == value {
                return Ok(0);
            }
            let b = Encoding::Utf16.encode(trimmed, true);
            if !accessible(engine, args[0], b.len(), P::WRITE) {
                return Ok(unsupported(engine, "StrTrimW: destination not writable", 0));
            }
            put(engine, args[0], &b)?;
            1
        }
        Call::Convert(wide) => convert(engine, args, wide)?,
        Call::Oem => {
            let capacity = args[1] as u32 as usize;
            let count = args[4] as u32 as usize;
            if count > LIMIT
                || capacity > LIMIT * 2
                || count != 0 && !accessible(engine, args[3], count, P::READ)
                || args[2] != 0 && !accessible(engine, args[2], 4, P::WRITE)
            {
                return Ok(0xc000000d);
            }
            let bytes = if count == 0 {
                vec![]
            } else {
                read(engine, args[3], count as u64)?
            };
            if !bytes.is_ascii() {
                return Ok(unsupported(
                    engine,
                    "RtlOemToUnicodeN: non-ASCII OEM unavailable",
                    0xc00000bb,
                ));
            }
            let units = count.min(capacity / 2);
            let mut image = bytes[..units]
                .iter()
                .flat_map(|b| [*b, 0])
                .collect::<Vec<_>>();
            if units == count && capacity >= image.len() + 2 {
                image.extend([0, 0]);
            }
            if !image.is_empty() {
                if !accessible(engine, args[0], image.len(), P::WRITE) {
                    return Ok(0xc000000d);
                }
                put(engine, args[0], &image)?;
            }
            if args[2] != 0 {
                put(engine, args[2], &((units * 2) as u32).to_le_bytes())?;
            }
            if units < count { 0x80000005 } else { 0 }
        }
        Call::Unicode => {
            let size = args[1] as u32 as usize;
            if size > 1024 * 1024
                || size != 0 && !accessible(engine, args[0], size, P::READ)
                || args[2] != 0
                    && (!accessible(engine, args[2], 4, P::READ)
                        || !accessible(engine, args[2], 4, P::WRITE))
            {
                return Ok(unsupported(
                    engine,
                    "RtlIsTextUnicode: inaccessible buffer",
                    0,
                ));
            }
            let b = if size == 0 {
                vec![]
            } else {
                read(engine, args[0], size as u64)?
            };
            let requested = if args[2] == 0 {
                u32::MAX
            } else {
                u32::from_le_bytes(read(engine, args[2], 4)?.try_into().unwrap())
            };
            let mut flags = 0;
            if size % 2 != 0 {
                flags = 0x200;
            } else if b.starts_with(&[255, 254]) {
                flags = 8;
            } else if b.starts_with(&[254, 255]) {
                flags = 0x80;
            } else if size >= 4 {
                let high = b.chunks_exact(2).filter(|p| p[1] == 0).count();
                let low = b
                    .chunks_exact(2)
                    .filter(|p| matches!(p[0],9|10|13|32..=126|160..=255))
                    .count();
                if high * 4 >= size / 2 * 3 && low * 4 >= size / 2 * 3 {
                    flags = 2;
                    if high == size / 2 {
                        flags |= 0x1000;
                        flags |= if b.chunks_exact(2).any(|p| matches!(p[0], 9 | 10 | 13 | 32)) {
                            4
                        } else {
                            1
                        };
                    }
                }
            }
            let selected = flags & requested;
            if args[2] != 0 {
                put(engine, args[2], &selected.to_le_bytes())?;
            }
            u64::from(selected & 0x10ff != 0)
        }
        Call::CharOem => {
            let Some(value) = text(engine, args[0], -1, false) else {
                return Ok(unsupported(engine, "CharToOemA: inaccessible source", 0));
            };
            if !value.is_ascii() {
                return Ok(unsupported(
                    engine,
                    "CharToOemA: non-ASCII source unavailable",
                    0,
                ));
            }
            let bytes = Encoding::Cp1252.encode(&value, true);
            if !accessible(engine, args[1], bytes.len(), P::WRITE) {
                return Ok(unsupported(
                    engine,
                    "CharToOemA: destination not writable",
                    0,
                ));
            }
            put(engine, args[1], &bytes)?;
            1
        }
        Call::Presence => {
            let width = engine.get_data().architecture.width();
            let header = if width == 8 { 16 } else { 8 };
            if !accessible(engine, args[0], header, P::READ)
                || !accessible(engine, args[1], 1, P::WRITE)
            {
                fail(engine, 87);
                return Ok(0xc000000d);
            }
            let b = read(engine, args[0], header as u64)?;
            let len = u16::from_le_bytes(b[..2].try_into().unwrap()) as usize;
            let maximum = u16::from_le_bytes(b[2..4].try_into().unwrap()) as usize;
            let pointer = if width == 8 {
                u64::from_le_bytes(b[8..].try_into().unwrap())
            } else {
                u32::from_le_bytes(b[4..].try_into().unwrap()) as u64
            };
            let name = if len != 0 && len % 2 == 0 && len <= maximum {
                text(engine, pointer, (len / 2) as i32, true)
            } else {
                None
            };
            let Some(name) = name else {
                fail(engine, 87);
                return Ok(0xc000000d);
            };
            let name = name.to_ascii_lowercase();
            if !name.starts_with("api-ms-win-") && !name.starts_with("ext-ms-win-") {
                fail(engine, 87);
                return Ok(0xc000000d);
            }
            let present = matches!(
                name.as_str(),
                "ext-ms-win-fsutilext-ulib-l1-1-0" | "ext-ms-win-ntuser-chartranslation-l1-1-0"
            );
            if !present {
                unsupported(
                    engine,
                    &format!("ApiSetQueryApiSetPresence: namespace {name} unavailable"),
                    (),
                );
            }
            put(engine, args[1], &[u8::from(present)])?;
            engine.get_data_mut().apis.last_error = 0;
            0
        }
    })
}
fn convert(engine: &mut Unicorn<Trace>, args: &[u64], wide: bool) -> Result<u64> {
    let flags = args[1] as u32;
    let count = args[3] as i32;
    let capacity = args[5] as i32;
    if count == 0
        || count < -1
        || count > LIMIT as i32
        || capacity < 0
        || capacity > LIMIT as i32 * 4
        || args[2] == 0
    {
        return Ok(fail(engine, 87));
    }
    if flags != 0 {
        unsupported(
            engine,
            "Character conversion: unsupported conversion flags",
            (),
        );
        return Ok(fail(engine, 1004));
    }
    let Some(page) = CodePage::resolve(args[0] as u32, 437) else {
        unsupported(engine, "Character conversion: unsupported code page", ());
        return Ok(fail(engine, 87));
    };
    if wide && page.utf8() && (args[6] != 0 || args[7] != 0) {
        return Ok(fail(engine, 87));
    }
    if wide
        && (args[6] != 0 && !accessible(engine, args[6], 1, P::READ)
            || args[7] != 0 && !accessible(engine, args[7], 4, P::WRITE))
    {
        return Ok(fail(engine, 87));
    }
    let Some(mut source) = raw(engine, args[2], count, wide) else {
        return Ok(fail(engine, 87));
    };
    if wide && count == -1 && source.len() >= LIMIT * 2 {
        return Ok(fail(engine, 87));
    }
    if count == -1 {
        source.extend(if wide { vec![0, 0] } else { vec![0] });
    }
    let (bytes, used, units) = if wide {
        let Ok(value) = Encoding::Utf16.decode(&source) else {
            return Ok(fail(engine, 87));
        };
        let replacement = if args[6] == 0 {
            b'?'
        } else {
            read(engine, args[6], 1)?[0]
        };
        if page.decode(&[replacement]).is_none() {
            return Ok(fail(engine, 87));
        }
        let (b, used) = page.encode(&value, replacement);
        let len = b.len();
        (b, used, len)
    } else {
        let Some(value) = page.decode(&source) else {
            return Ok(fail(engine, 1113));
        };
        let b = Encoding::Utf16.encode(&value, false);
        let len = b.len() / 2;
        (b, false, len)
    };
    if capacity != 0 {
        if args[4] != 0
            && args[4] < args[2] + source.len() as u64
            && args[2] < args[4].saturating_add(bytes.len() as u64)
        {
            return Ok(fail(engine, 87));
        }
        if args[4] == 0 || units > capacity as usize {
            return Ok(fail(engine, 122));
        }
        if !accessible(engine, args[4], bytes.len(), P::WRITE) {
            return Ok(fail(engine, 998));
        }
        put(engine, args[4], &bytes)?;
    }
    if wide && args[7] != 0 {
        put(engine, args[7], &u32::from(used).to_le_bytes())?;
    }
    engine.get_data_mut().apis.last_error = 0;
    Ok(units as u64)
}
