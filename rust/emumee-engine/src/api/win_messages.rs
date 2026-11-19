//! Bounded FormatMessageW over persona message text and guest insert strings.
//! No host message table, host locale or host allocation is consulted.
use super::*;
use emumee_core::heap::PROCESS_HEAP;

const MAX_CHARS: usize = 32767;
const ALLOCATE: u64 = 0x100;
const IGNORE_INSERTS: u64 = 0x200;
const FROM_STRING: u64 = 0x400;
const FROM_HMODULE: u64 = 0x800;
const FROM_SYSTEM: u64 = 0x1000;
const ARGUMENT_ARRAY: u64 = 0x2000;
const KNOWN: u64 = 0xff | ALLOCATE | IGNORE_INSERTS | FROM_STRING | FROM_HMODULE | FROM_SYSTEM
    | ARGUMENT_ARRAY;

/// en-US persona message text. These strings are modeled persona data; nothing
/// is read from a host message table.
const SYSTEM: &[(u32, &str)] = &[
    (0, "The operation completed successfully.\r\n"),
    (1, "Incorrect function.\r\n"),
    (2, "The system cannot find the file specified.\r\n"),
    (3, "The system cannot find the path specified.\r\n"),
    (5, "Access is denied.\r\n"),
    (6, "The handle is invalid.\r\n"),
    (
        8,
        "Not enough memory resources are available to process this command.\r\n",
    ),
    (
        14,
        "Not enough memory resources are available to complete this operation.\r\n",
    ),
    (18, "There are no more files.\r\n"),
    (
        32,
        "The process cannot access the file because it is being used by another process.\r\n",
    ),
    (50, "The request is not supported.\r\n"),
    (80, "The file exists.\r\n"),
    (87, "The parameter is incorrect.\r\n"),
    (109, "The pipe has been ended.\r\n"),
    (112, "There is not enough space on the disk.\r\n"),
    (122, "The data area passed to a system call is too small.\r\n"),
    (126, "The specified module could not be found.\r\n"),
    (127, "The specified procedure could not be found.\r\n"),
    (
        183,
        "Cannot create a file when that file already exists.\r\n",
    ),
    (234, "More data is available.\r\n"),
    (259, "No more data is available.\r\n"),
    (267, "The directory name is invalid.\r\n"),
    (
        995,
        "The I/O operation has been aborted because of either a thread exit or an application request.\r\n",
    ),
    (
        10013,
        "An attempt was made to access a socket in a way forbidden by its access permissions.\r\n",
    ),
];

pub(super) fn definition(module: &str, name: &str) -> Option<(usize, T)> {
    let localization = matches!(module, "kernel32" | "kernelbase")
        || module.starts_with("api-ms-win-core-localization-");
    (localization && name == "FormatMessageW").then_some((7, T::U32))
}
fn fail(engine: &mut Unicorn<Trace>, error: u32) -> Result<u64> {
    engine.get_data_mut().apis.last_error = error;
    Ok(0)
}
/// One bounded NUL-terminated wide guest string.
fn wide(engine: &Unicorn<Trace>, address: u64) -> Result<Option<String>> {
    if address == 0 {
        return Ok(None);
    }
    let mut units = Vec::new();
    for index in 0..=MAX_CHARS as u64 {
        let at = match address.checked_add(index * 2) {
            Some(at) => at,
            None => return Ok(None),
        };
        if !engine.get_data().apis.memory.allows(at, 2, P::READ) {
            return Ok(None);
        }
        let bytes = read(engine, at, 2)?;
        let unit = u16::from_le_bytes([bytes[0], bytes[1]]);
        if unit == 0 {
            return Ok(String::from_utf16(&units).ok());
        }
        units.push(unit);
    }
    Ok(None)
}
/// Message-table control escapes. `%0` ends the text; the others are literal
/// control characters. Insert markers are left for the insert pass.
fn escapes(message: &str) -> String {
    let message = message.split("%0").next().unwrap_or_default();
    let mut output = String::with_capacity(message.len());
    let mut chars = message.chars().peekable();
    while let Some(character) = chars.next() {
        if character != '%' {
            output.push(character);
            continue;
        }
        match chars.peek() {
            Some('%') => {
                output.push('%');
                chars.next();
            }
            Some('n') => {
                output.push_str("\r\n");
                chars.next();
            }
            Some('r') => {
                output.push('\r');
                chars.next();
            }
            Some('t') => {
                output.push('\t');
                chars.next();
            }
            _ => output.push('%'),
        }
    }
    output
}
/// Expands `%N` and `%N!spec!` inserts from guest string pointers. Only the
/// string specifiers the frozen reference models are accepted.
fn inserts(
    engine: &Unicorn<Trace>,
    message: &str,
    arguments: u64,
    array: bool,
) -> Result<Option<String>> {
    let chars: Vec<char> = message.chars().collect();
    if !chars
        .windows(2)
        .any(|pair| pair[0] == '%' && pair[1].is_ascii_digit() && pair[1] != '0')
    {
        return Ok(Some(message.to_string()));
    }
    if arguments == 0 {
        return Ok(None);
    }
    let width = engine.get_data().architecture.width() as u64;
    let base = if array {
        arguments
    } else {
        if !engine
            .get_data()
            .apis
            .memory
            .allows(arguments, width, P::READ)
        {
            return Ok(None);
        }
        let bytes = read(engine, arguments, width)?;
        let mut raw = [0; 8];
        raw[..width as usize].copy_from_slice(&bytes);
        u64::from_le_bytes(raw)
    };
    let mut output = String::new();
    let mut index = 0;
    while index < chars.len() {
        if chars[index] != '%' || !chars.get(index + 1).is_some_and(char::is_ascii_digit) {
            output.push(chars[index]);
            index += 1;
            continue;
        }
        let mut number = 0usize;
        index += 1;
        while index < chars.len() && chars[index].is_ascii_digit() && number < 10 {
            number = number * 10 + (chars[index] as usize - '0' as usize);
            index += 1;
        }
        if number == 0 || number > 99 {
            return Ok(None);
        }
        if chars.get(index) == Some(&'!') {
            let mut specifier = String::new();
            index += 1;
            while index < chars.len() && chars[index] != '!' {
                specifier.push(chars[index]);
                index += 1;
            }
            if chars.get(index) != Some(&'!') || !matches!(specifier.as_str(), "s" | "ls" | "ws") {
                return Ok(None);
            }
            index += 1;
        }
        let slot = match base.checked_add((number as u64 - 1) * width) {
            Some(slot) => slot,
            None => return Ok(None),
        };
        if !engine.get_data().apis.memory.allows(slot, width, P::READ) {
            return Ok(None);
        }
        let bytes = read(engine, slot, width)?;
        let mut raw = [0; 8];
        raw[..width as usize].copy_from_slice(&bytes);
        let Some(value) = wide(engine, u64::from_le_bytes(raw))? else {
            return Ok(None);
        };
        if output.chars().count() + value.chars().count() > MAX_CHARS {
            return Ok(None);
        }
        output.push_str(&value);
    }
    Ok(Some(output))
}
pub(super) fn invoke(engine: &mut Unicorn<Trace>, args: &[u64]) -> Result<u64> {
    let flags = args[0] & 0xffff_ffff;
    let identifier = args[2] as u32;
    let language = args[3] & 0xffff_ffff;
    let capacity = args[4 + 1] & 0xffff_ffff;
    let output = args[4];
    let from_string = flags & FROM_STRING != 0;
    let from_system = flags & FROM_SYSTEM != 0;
    let from_module = flags & FROM_HMODULE != 0;
    if output == 0
        || flags & !KNOWN != 0
        || (from_string && (from_system || from_module))
        || !(from_string || from_system || from_module)
    {
        return fail(engine, 87);
    }
    // The low byte is the output line width, which this profile does not model.
    if flags & 0xff != 0 {
        return fail(engine, 87);
    }
    let message = if from_string {
        match wide(engine, args[1])? {
            Some(message) => message,
            None => return fail(engine, 87),
        }
    } else {
        ensure!(
            !from_module,
            "FormatMessage message-table resources from a module are not modeled"
        );
        if !matches!(language, 0 | 0x0409 | 0x0809) {
            return fail(engine, 317);
        }
        match SYSTEM
            .iter()
            .find(|(code, _)| *code == identifier)
            .map(|(_, text)| (*text).to_string())
        {
            Some(message) => message,
            None => return fail(engine, 317),
        }
    };
    let message = escapes(&message);
    let message = if flags & IGNORE_INSERTS != 0 {
        message
    } else {
        match inserts(engine, &message, args[6], flags & ARGUMENT_ARRAY != 0)? {
            Some(message) => message,
            None => return fail(engine, 87),
        }
    };
    let units: Vec<u16> = message.encode_utf16().collect();
    if units.len() > MAX_CHARS {
        return fail(engine, 122);
    }
    let mut payload: Vec<u8> = units.iter().flat_map(|unit| unit.to_le_bytes()).collect();
    payload.extend([0, 0]);
    if flags & ALLOCATE != 0 {
        if capacity > MAX_CHARS as u64 + 1 {
            return fail(engine, 122);
        }
        let width = engine.get_data().architecture.width() as u64;
        if !engine.get_data().apis.memory.allows(output, width, P::RW) {
            return fail(engine, 87);
        }
        // The caller frees this block with LocalFree, so it comes from the same
        // process heap the Global/Local family uses.
        let size = (payload.len() as u64).max(capacity.min(MAX_CHARS as u64 + 1) * 2);
        let state = &engine.get_data().apis;
        let plan = state
            .heaps
            .allocate(&state.allocations, &state.memory, PROCESS_HEAP, 0, size);
        let address = heap::finish(engine, plan, true)?;
        if address == 0 {
            return fail(engine, 8);
        }
        crate::cpu::write(engine, address, &payload)?;
        crate::cpu::write(engine, output, &address.to_le_bytes()[..width as usize])?;
    } else {
        if capacity == 0 || capacity > MAX_CHARS as u64 + 1 {
            return fail(engine, 122);
        }
        if !engine
            .get_data()
            .apis
            .memory
            .allows(output, capacity * 2, P::RW)
        {
            return fail(engine, 87);
        }
        if units.len() as u64 + 1 > capacity {
            // Windows still fills the buffer it was given, then reports the
            // shortfall.
            let kept = capacity as usize - 1;
            let mut truncated: Vec<u8> = units[..kept]
                .iter()
                .flat_map(|unit| unit.to_le_bytes())
                .collect();
            truncated.extend([0, 0]);
            crate::cpu::write(engine, output, &truncated)?;
            return fail(engine, 122);
        }
        crate::cpu::write(engine, output, &payload)?;
    }
    engine.get_data_mut().apis.last_error = 0;
    Ok(units.len() as u64)
}
