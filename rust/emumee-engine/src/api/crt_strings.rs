//! Legacy CRT string, case, span, tokenizer, radix and narrow/wide conversion
//! models. Byte and code-unit work only: no host libc, host locale or guest
//! pointer conversion, and every scan and write is bounded.
use super::*;
use anyhow::Context;
use emumee_core::virtual_memory as vm;

/// Characters scanned or produced by one call, as the frozen CRT extension bounds it.
const MAX_CHARS: u64 = 8192;
/// Bytes one secure copy may produce.
const MAX_OUTPUT: u64 = 65536;
const EINVAL: u64 = 22;
const ERANGE: u64 = 34;
const STRUNCATE: u64 = 80;
/// The one locale this profile models beside "C", matching the frozen CRT
/// extension's default persona locale and the 1252 ANSI code page already
/// reported by GetACP.
const PERSONA_LOCALE: &str = "en-US";

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Call {
    Concat { wide: bool, bounded: bool },
    ConcatSecure,
    CopySecure,
    Span { wide: bool, inside: bool },
    Search { wide: bool },
    Token,
    MemoryFold,
    FoldCompare { wide: bool, bounded: bool },
    FoldInPlace { wide: bool, upper: bool },
    FoldUnit { wide: bool, upper: bool },
    Digit,
    Integer,
    Radix { wide: bool, signed: bool },
    WideToBytes,
    BytesToWideSecure,
    ByteToWide,
    Date(bool),
    Locale(bool),
}
pub(super) fn definition(module: &str, name: &str) -> Option<(Call, usize, T)> {
    if !matches!(
        module,
        "msvcrt"
            | "ucrtbase"
            | "api-ms-win-crt-private-l1-1-0"
            | "api-ms-win-crt-string-l1-1-0"
            | "api-ms-win-crt-convert-l1-1-0"
            | "api-ms-win-crt-locale-l1-1-0"
    ) {
        return None;
    }
    let name = name.strip_prefix("_o_").unwrap_or(name);
    Some(match name {
        "strcat" | "wcscat" => (
            Call::Concat {
                wide: name.starts_with('w'),
                bounded: false,
            },
            2,
            T::Pointer,
        ),
        "strncat" | "wcsncat" => (
            Call::Concat {
                wide: name.starts_with('w'),
                bounded: true,
            },
            3,
            T::Pointer,
        ),
        "strncat_s" => (Call::ConcatSecure, 4, T::U32),
        "strncpy_s" => (Call::CopySecure, 4, T::U32),
        "strcspn" | "wcscspn" => (
            Call::Span {
                wide: name.starts_with('w'),
                inside: false,
            },
            2,
            T::Pointer,
        ),
        "strspn" | "wcsspn" => (
            Call::Span {
                wide: name.starts_with('w'),
                inside: true,
            },
            2,
            T::Pointer,
        ),
        "strstr" | "wcsstr" => (
            Call::Search {
                wide: name.starts_with('w'),
            },
            2,
            T::Pointer,
        ),
        "wcstok" => (Call::Token, 2, T::Pointer),
        "_memicmp" => (Call::MemoryFold, 3, T::U32),
        "_stricmp" | "_strcmpi" => (
            Call::FoldCompare {
                wide: false,
                bounded: false,
            },
            2,
            T::U32,
        ),
        "_wcsicmp" => (
            Call::FoldCompare {
                wide: true,
                bounded: false,
            },
            2,
            T::U32,
        ),
        "_strnicmp" => (
            Call::FoldCompare {
                wide: false,
                bounded: true,
            },
            3,
            T::U32,
        ),
        "_wcsnicmp" => (
            Call::FoldCompare {
                wide: true,
                bounded: true,
            },
            3,
            T::U32,
        ),
        "_strlwr" => (
            Call::FoldInPlace {
                wide: false,
                upper: false,
            },
            1,
            T::Pointer,
        ),
        "_strupr" => (
            Call::FoldInPlace {
                wide: false,
                upper: true,
            },
            1,
            T::Pointer,
        ),
        "_wcsupr" => (
            Call::FoldInPlace {
                wide: true,
                upper: true,
            },
            1,
            T::Pointer,
        ),
        "tolower" => (
            Call::FoldUnit {
                wide: false,
                upper: false,
            },
            1,
            T::U32,
        ),
        "toupper" => (
            Call::FoldUnit {
                wide: false,
                upper: true,
            },
            1,
            T::U32,
        ),
        "towupper" => (
            Call::FoldUnit {
                wide: true,
                upper: true,
            },
            1,
            T::U32,
        ),
        "towlower" => (
            Call::FoldUnit {
                wide: true,
                upper: false,
            },
            1,
            T::U32,
        ),
        "isdigit" | "iswdigit" => (Call::Digit, 1, T::U32),
        "atoi" => (Call::Integer, 1, T::U32),
        "_itoa" | "_ltoa" => (
            Call::Radix {
                wide: false,
                signed: true,
            },
            3,
            T::Pointer,
        ),
        "_itow" => (
            Call::Radix {
                wide: true,
                signed: true,
            },
            3,
            T::Pointer,
        ),
        "_ultow" => (
            Call::Radix {
                wide: true,
                signed: false,
            },
            3,
            T::Pointer,
        ),
        "wcstombs" => (Call::WideToBytes, 3, T::Pointer),
        "mbstowcs_s" => (Call::BytesToWideSecure, 5, T::U32),
        "mbtowc" => (Call::ByteToWide, 3, T::U32),
        "_strdate" => (Call::Date(false), 1, T::Pointer),
        "_strtime" => (Call::Date(true), 1, T::Pointer),
        "setlocale" => (Call::Locale(false), 2, T::Pointer),
        "_wsetlocale" => (Call::Locale(true), 2, T::Pointer),
        _ => return None,
    })
}
#[derive(Default)]
pub(super) struct State {
    /// Per-thread wcstok continuation, as the legacy two-argument form needs.
    tokens: std::collections::BTreeMap<u64, u64>,
    /// Locale name per LC_* category, index one through five.
    categories: [Option<String>; 6],
    /// Owned storage for the string setlocale hands back.
    locale_storage: Option<(u64, u64)>,
}
fn width(wide: bool) -> u64 {
    if wide { 2 } else { 1 }
}
/// Reads one NUL-terminated guest string as code units, bounded by MAX_CHARS.
fn units(engine: &Unicorn<Trace>, at: u64, wide: bool, limit: u64) -> Result<Vec<u16>> {
    ensure!(at != 0, "CRT string pointer is null");
    let step = width(wide);
    let mut out = Vec::new();
    for index in 0..limit.min(MAX_CHARS) {
        let address = at
            .checked_add(index * step)
            .context("CRT string pointer overflow")?;
        let bytes = read(engine, address, step)?;
        let unit = if wide {
            u16::from_le_bytes([bytes[0], bytes[1]])
        } else {
            u16::from(bytes[0])
        };
        if unit == 0 {
            return Ok(out);
        }
        out.push(unit);
    }
    if limit <= MAX_CHARS {
        return Ok(out);
    }
    bail!("CRT string exceeds the {MAX_CHARS} character bound")
}
fn encode(value: &[u16], wide: bool) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(value.len() * width(wide) as usize + 2);
    for unit in value {
        if wide {
            bytes.extend(unit.to_le_bytes());
        } else {
            bytes.push(*unit as u8);
        }
    }
    bytes.extend(std::iter::repeat_n(0, width(wide) as usize));
    bytes
}
fn put(engine: &mut Unicorn<Trace>, at: u64, bytes: &[u8]) -> Result<()> {
    require(engine, at, bytes.len() as u64, P::WRITE)?;
    crate::cpu::write(engine, at, bytes)
}
/// Case folding for the modeled locale: invariant ASCII plus the Latin-1 and
/// BMP mappings a single code unit can represent. Nothing changes width.
fn fold(unit: u16, upper: bool) -> u16 {
    let Some(character) = char::from_u32(u32::from(unit)) else {
        return unit;
    };
    let mut mapped: Box<dyn Iterator<Item = char>> = if upper {
        Box::new(character.to_uppercase())
    } else {
        Box::new(character.to_lowercase())
    };
    match (mapped.next(), mapped.next()) {
        (Some(single), None) => u32::from(single).try_into().unwrap_or(unit),
        _ => unit,
    }
}
fn ordering(left: &[u16], right: &[u16]) -> u64 {
    for index in 0..left.len().max(right.len()) {
        let a = left.get(index).copied().unwrap_or(0);
        let b = right.get(index).copied().unwrap_or(0);
        if a != b {
            return (i64::from(a) - i64::from(b)) as i32 as u32 as u64;
        }
    }
    0
}
fn folded(value: &[u16]) -> Vec<u16> {
    value.iter().map(|unit| fold(*unit, false)).collect()
}
fn radix_text(value: u64, radix: u64, signed: bool) -> Option<Vec<u16>> {
    if !(2..=36).contains(&radix) {
        return None;
    }
    const ALPHABET: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let truncated = value as u32;
    let (negative, mut magnitude) = if signed && radix == 10 && (truncated as i32) < 0 {
        (true, (truncated as i32).unsigned_abs() as u64)
    } else {
        (false, u64::from(truncated))
    };
    let mut digits = Vec::new();
    while magnitude != 0 {
        digits.push(u16::from(ALPHABET[(magnitude % radix) as usize]));
        magnitude /= radix;
    }
    if digits.is_empty() {
        digits.push(u16::from(b'0'));
    }
    if negative {
        digits.push(u16::from(b'-'));
    }
    digits.reverse();
    Some(digits)
}
/// The one persona clock, rendered as the CRT's fixed-width date and time
/// strings. No host date, timezone or DST rule is consulted.
fn clock_text(engine: &Unicorn<Trace>, time: bool) -> Result<Vec<u8>> {
    let clock = &engine.get_data().clock;
    let local = emumee_core::kernel_time::local_time(
        clock.utc_filetime as i64,
        clock.utc_offset_minutes,
    )
    .map_err(anyhow::Error::msg)?;
    let fields = emumee_core::kernel_time::time_fields(local).map_err(anyhow::Error::msg)?;
    let text = if time {
        format!(
            "{:02}:{:02}:{:02}",
            fields.hour, fields.minute, fields.second
        )
    } else {
        format!(
            "{:02}/{:02}/{:02}",
            fields.month,
            fields.day,
            fields.year.rem_euclid(100)
        )
    };
    let mut bytes = text.into_bytes();
    bytes.push(0);
    Ok(bytes)
}
pub(super) fn invoke(engine: &mut Unicorn<Trace>, args: &[u64], call: Call) -> Result<u64> {
    ensure!(
        !engine.get_data().apis.kernel_mode,
        "CRT string APIs require a user process"
    );
    match call {
        Call::Concat { wide, bounded } => {
            let step = width(wide);
            let mut destination = units(engine, args[0], wide, MAX_CHARS)?;
            let limit = if bounded { args[2] } else { MAX_CHARS };
            let source = units(engine, args[1], wide, limit)?;
            ensure!(
                destination.len() + source.len() <= MAX_CHARS as usize,
                "CRT concatenation exceeds the string bound"
            );
            let at = args[0] + destination.len() as u64 * step;
            destination.extend(source.iter().copied());
            put(engine, at, &encode(&destination[destination.len() - source.len()..], wide))?;
            Ok(args[0])
        }
        // strncat_s: EINVAL for unusable arguments, ERANGE when the result does
        // not fit, STRUNCATE when _TRUNCATE shortened it.
        Call::ConcatSecure => {
            let truncate = args[3] == u64::MAX || args[3] == u64::from(u32::MAX);
            if args[0] == 0 || args[2] == 0 || args[1] == 0 || args[1] > MAX_OUTPUT {
                return Ok(EINVAL);
            }
            let destination = units(engine, args[0], false, args[1])?;
            let room = args[1] - destination.len() as u64 - 1;
            let wanted = if truncate { room } else { args[3] };
            let source = units(engine, args[2], false, wanted.min(MAX_CHARS))?;
            if !truncate && source.len() as u64 > room {
                put(engine, args[0], &[0])?;
                return Ok(ERANGE);
            }
            let at = args[0] + destination.len() as u64;
            put(engine, at, &encode(&source, false))?;
            let complete = units(engine, args[2], false, MAX_CHARS)?;
            Ok(if truncate && complete.len() > source.len() {
                STRUNCATE
            } else {
                0
            })
        }
        Call::CopySecure => {
            let truncate = args[3] == u64::MAX || args[3] == u64::from(u32::MAX);
            if args[0] == 0 || args[2] == 0 || args[1] == 0 || args[1] > MAX_OUTPUT {
                return Ok(EINVAL);
            }
            let limit = if truncate { args[1] - 1 } else { args[3].min(args[1]) };
            let source = units(engine, args[2], false, limit.min(MAX_CHARS))?;
            if !truncate && source.len() as u64 == args[1] {
                put(engine, args[0], &[0])?;
                return Ok(ERANGE);
            }
            put(engine, args[0], &encode(&source, false))?;
            let complete = units(engine, args[2], false, MAX_CHARS)?;
            Ok(if truncate && complete.len() > source.len() {
                STRUNCATE
            } else {
                0
            })
        }
        Call::Span { wide, inside } => {
            let set = units(engine, args[1], wide, MAX_CHARS)?;
            let source = units(engine, args[0], wide, MAX_CHARS)?;
            let mut index = 0;
            while index < source.len() && set.contains(&source[index]) == inside {
                index += 1;
            }
            Ok(index as u64)
        }
        Call::Search { wide } => {
            let haystack = units(engine, args[0], wide, MAX_CHARS)?;
            let needle = units(engine, args[1], wide, MAX_CHARS)?;
            if needle.is_empty() {
                return Ok(args[0]);
            }
            Ok(haystack
                .windows(needle.len())
                .position(|window| window == needle.as_slice())
                .map_or(0, |at| args[0] + at as u64 * width(wide)))
        }
        // Legacy two-argument wcstok keeps its continuation per guest thread and
        // overwrites each delimiter it consumes.
        Call::Token => {
            ensure!(args[1] != 0, "wcstok delimiter pointer is null");
            let thread = crate::threads::thread_address(engine);
            let start = if args[0] != 0 {
                args[0]
            } else {
                engine
                    .get_data()
                    .apis
                    .crt_strings
                    .tokens
                    .get(&thread)
                    .copied()
                    .unwrap_or(0)
            };
            if start == 0 {
                return Ok(0);
            }
            let separators = units(engine, args[1], true, MAX_CHARS)?;
            let text = units(engine, start, true, MAX_CHARS)?;
            let Some(first) = text
                .iter()
                .position(|unit| !separators.contains(unit))
                .map(|at| at as u64)
            else {
                engine
                    .get_data_mut()
                    .apis
                    .crt_strings
                    .tokens
                    .insert(thread, 0);
                return Ok(0);
            };
            let token = start + first * 2;
            match text
                .iter()
                .skip(first as usize)
                .position(|unit| separators.contains(unit))
            {
                Some(offset) => {
                    let end = token + offset as u64 * 2;
                    put(engine, end, &[0, 0])?;
                    engine
                        .get_data_mut()
                        .apis
                        .crt_strings
                        .tokens
                        .insert(thread, end + 2);
                }
                None => {
                    engine
                        .get_data_mut()
                        .apis
                        .crt_strings
                        .tokens
                        .insert(thread, 0);
                }
            }
            Ok(token)
        }
        // The legacy CRT compares exactly the requested byte count, NULs
        // included, folding invariant ASCII only.
        Call::MemoryFold => {
            ensure!(
                args[2] <= MAX_OUTPUT,
                "CRT folded comparison exceeds the transfer bound"
            );
            if args[2] == 0 {
                return Ok(0);
            }
            let left = read(engine, args[0], args[2])?;
            let right = read(engine, args[1], args[2])?;
            for (a, b) in left.iter().zip(right.iter()) {
                let (a, b) = (a.to_ascii_lowercase(), b.to_ascii_lowercase());
                if a != b {
                    return Ok((i64::from(a) - i64::from(b)) as i32 as u32 as u64);
                }
            }
            Ok(0)
        }
        Call::FoldCompare { wide, bounded } => {
            let limit = if bounded { args[2] } else { MAX_CHARS };
            if limit == 0 {
                return Ok(0);
            }
            let left = folded(&units(engine, args[0], wide, limit.min(MAX_CHARS))?);
            let right = folded(&units(engine, args[1], wide, limit.min(MAX_CHARS))?);
            Ok(ordering(&left, &right))
        }
        Call::FoldInPlace { wide, upper } => {
            let source = units(engine, args[0], wide, MAX_CHARS)?;
            let mapped: Vec<u16> = source.iter().map(|unit| fold(*unit, upper)).collect();
            // The terminator already present stays; only the units change.
            let bytes = encode(&mapped, wide);
            put(engine, args[0], &bytes[..bytes.len() - width(wide) as usize])?;
            Ok(args[0])
        }
        Call::FoldUnit { wide, upper } => {
            let value = if wide {
                args[0] & 0xffff
            } else {
                args[0] & 0xff
            };
            if !wide && value > 0x7f {
                // Outside invariant ASCII the narrow classification depends on a
                // locale this profile does not model.
                return Ok(value);
            }
            Ok(u64::from(fold(value as u16, upper)))
        }
        Call::Digit => Ok(u64::from((0x30..=0x39).contains(&(args[0] & 0xffff)))),
        Call::Integer => {
            let text = units(engine, args[0], false, MAX_CHARS)?;
            let mut index = 0;
            while index < text.len() && (text[index] as u8).is_ascii_whitespace() {
                index += 1;
            }
            let negative = text.get(index) == Some(&u16::from(b'-'));
            if negative || text.get(index) == Some(&u16::from(b'+')) {
                index += 1;
            }
            let mut value: i64 = 0;
            while index < text.len() && (0x30..=0x39).contains(&text[index]) {
                value = value
                    .saturating_mul(10)
                    .saturating_add(i64::from(text[index] - 0x30));
                index += 1;
            }
            if negative {
                value = -value;
            }
            Ok(value.clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32 as u32 as u64)
        }
        Call::Radix { wide, signed } => {
            let Some(digits) = radix_text(args[0], args[2], signed) else {
                return Ok(0);
            };
            put(engine, args[1], &encode(&digits, wide))?;
            Ok(args[1])
        }
        Call::WideToBytes => {
            let source = units(engine, args[1], true, args[2].min(MAX_CHARS))?;
            ensure!(
                source.iter().all(|unit| *unit <= 0x7f),
                "CRT wide conversion outside invariant ASCII is not modeled"
            );
            if args[0] != 0 {
                put(engine, args[0], &encode(&source, false))?;
            }
            Ok(source.len() as u64)
        }
        Call::BytesToWideSecure => {
            if args[0] != 0 {
                put(engine, args[0], &0u32.to_le_bytes())?;
            }
            let truncate = args[4] == u64::MAX || args[4] == u64::from(u32::MAX);
            if args[3] == 0 || (args[2] > 0 && args[1] == 0) || (args[2] == 0 && args[1] != 0) {
                return Ok(EINVAL);
            }
            let source = units(engine, args[3], false, MAX_CHARS)?;
            ensure!(
                source.iter().all(|unit| *unit <= 0x7f),
                "CRT narrow conversion outside invariant ASCII is not modeled"
            );
            let needed = source.len() as u64 + 1;
            if args[1] == 0 {
                if args[0] != 0 {
                    put(engine, args[0], &(needed as u32).to_le_bytes())?;
                }
                return Ok(0);
            }
            let kept = if truncate {
                needed.min(args[2]) - 1
            } else {
                if needed > args[2] {
                    put(engine, args[1], &[0, 0])?;
                    return Ok(ERANGE);
                }
                source.len() as u64
            };
            put(engine, args[1], &encode(&source[..kept as usize], true))?;
            if args[0] != 0 {
                put(engine, args[0], &((kept + 1) as u32).to_le_bytes())?;
            }
            Ok(if truncate && kept < source.len() as u64 {
                STRUNCATE
            } else {
                0
            })
        }
        Call::ByteToWide => {
            if args[1] == 0 {
                return Ok(0);
            }
            if args[2] == 0 {
                return Ok(u64::from(u32::MAX));
            }
            let value = read(engine, args[1], 1)?[0];
            ensure!(
                value <= 0x7f,
                "CRT narrow conversion outside invariant ASCII is not modeled"
            );
            if args[0] != 0 {
                put(engine, args[0], &[value, 0])?;
            }
            Ok(u64::from(value != 0))
        }
        Call::Date(time) => {
            if args[0] == 0 {
                return Ok(0);
            }
            let bytes = clock_text(engine, time)?;
            put(engine, args[0], &bytes)?;
            Ok(args[0])
        }
        // Only the C locale and the persona's own locale exist here. Categories
        // are process state; the returned string is emulator-owned storage.
        Call::Locale(wide) => {
            ensure!(args[0] < 6, "CRT locale category is outside bounds");
            let persona = PERSONA_LOCALE.to_string();
            if args[1] != 0 {
                let requested = units(engine, args[1], wide, MAX_CHARS)?;
                let requested: String = requested
                    .iter()
                    .filter_map(|unit| char::from_u32(u32::from(*unit)))
                    .collect();
                let selected = if requested.is_empty() || requested.starts_with('.') {
                    persona.clone()
                } else {
                    requested
                };
                ensure!(
                    selected == "C" || selected == persona,
                    "CRT locale {selected} is not modeled"
                );
                let state = &mut engine.get_data_mut().apis.crt_strings;
                if args[0] == 0 {
                    for category in 1..6 {
                        state.categories[category] = Some(selected.clone());
                    }
                } else {
                    state.categories[args[0] as usize] = Some(selected);
                }
            }
            let state = &engine.get_data().apis.crt_strings;
            let names: Vec<String> = (1..6)
                .map(|index| {
                    state.categories[index]
                        .clone()
                        .unwrap_or_else(|| "C".into())
                })
                .collect();
            let text = if args[0] != 0 {
                names[args[0] as usize - 1].clone()
            } else if names.iter().all(|name| *name == names[0]) {
                names[0].clone()
            } else {
                ["LC_COLLATE", "LC_CTYPE", "LC_MONETARY", "LC_NUMERIC", "LC_TIME"]
                    .iter()
                    .zip(names.iter())
                    .map(|(category, name)| format!("{category}={name}"))
                    .collect::<Vec<_>>()
                    .join(";")
            };
            let encoded = encode(
                &text.encode_utf16().collect::<Vec<_>>(),
                wide,
            );
            let size = encoded.len() as u64;
            let address = match engine.get_data().apis.crt_strings.locale_storage {
                Some((address, capacity)) if capacity >= size => address,
                _ => {
                    let state = &engine.get_data().apis;
                    let plan = state.allocations.allocate(
                        &state.memory,
                        0,
                        size.max(512),
                        vm::RESERVE | vm::COMMIT,
                        4,
                    );
                    let Ok(plan) = plan else { return Ok(0) };
                    let address = plan.result;
                    allocation::apply(engine, plan)?;
                    engine.get_data_mut().apis.crt_strings.locale_storage =
                        Some((address, size.max(512)));
                    address
                }
            };
            crate::cpu::write(engine, address, &encoded)?;
            Ok(address)
        }
    }
}
