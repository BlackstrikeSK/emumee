//! `shell32` model: known folders from the persona, command-line splitting,
//! virtual directory trees, and observed execution requests.
//!
//! A launch request is recorded, never performed: `ShellExecute` reports the
//! success a caller checks for while no process, host or guest, is started, so
//! the behavior stays visible in evidence without being carried out. Known
//! folders come from the persona and the process environment, so they are the
//! same on every run.
use super::*;
use emumee_core::persona::KnownFolder;

/// The persona process the user profile belongs to, matching `api/persona.rs`.
const OWNER: u64 = 1024;

const S_OK: u64 = 0;
const E_INVALIDARG: u64 = 0x8007_0057;
const E_FAIL: u64 = 0x8000_4005;
/// ShellExecute reports success as any value above 32.
const EXEC_OK: u64 = 42;

/// One observed shell request.
#[derive(Clone, Debug, Serialize)]
pub struct Event {
    pub api: &'static str,
    pub verb: String,
    pub file: String,
    pub parameters: String,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Report {
    pub execution_requests: u64,
    pub events: Vec<Event>,
    pub omitted_events: u64,
}

impl Report {
    /// A run that made no shell request serializes nothing.
    pub fn is_empty(&self) -> bool {
        self.execution_requests == 0 && self.events.is_empty() && self.omitted_events == 0
    }
}

#[derive(Default)]
pub(crate) struct State {
    pub report: Report,
}

#[derive(Clone, Copy)]
pub(super) enum Call {
    CommandLineToArgv { wide: bool },
    ExtractIcon,
    IsUserAnAdmin,
    ChangeNotify,
    CreateDirectoryEx { wide: bool },
    GetFolderPath { wide: bool },
    GetMalloc,
    ShellExecute { wide: bool },
    ShellExecuteEx,
}

pub(super) fn definition(module: &str, name: &str) -> Option<(Call, usize, T)> {
    use Call::*;
    if module != "shell32" {
        return None;
    }
    let row = match name {
        "CommandLineToArgvA" => (CommandLineToArgv { wide: false }, 2, T::Pointer),
        "CommandLineToArgvW" => (CommandLineToArgv { wide: true }, 2, T::Pointer),
        "ExtractIcon" | "ExtractIconA" | "ExtractIconW" => (ExtractIcon, 3, T::Pointer),
        // IsUserAnAdmin is an ordinal-only export (680) as well as a name.
        "IsUserAnAdmin" | "#680" => (IsUserAnAdmin, 0, T::U32),
        "SHChangeNotify" => (ChangeNotify, 4, T::Void),
        "SHCreateDirectoryExA" => (CreateDirectoryEx { wide: false }, 3, T::U32),
        "SHCreateDirectoryExW" => (CreateDirectoryEx { wide: true }, 3, T::U32),
        "SHGetFolderPathA" => (GetFolderPath { wide: false }, 5, T::U32),
        "SHGetFolderPathW" => (GetFolderPath { wide: true }, 5, T::U32),
        "SHGetMalloc" => (GetMalloc, 1, T::U32),
        "ShellExecuteA" => (ShellExecute { wide: false }, 6, T::Pointer),
        "ShellExecuteW" => (ShellExecute { wide: true }, 6, T::Pointer),
        "ShellExecuteEx" | "ShellExecuteExA" | "ShellExecuteExW" => (ShellExecuteEx, 1, T::U32),
        _ => return None,
    };
    Some(row)
}

fn ptr_width(engine: &Unicorn<Trace>) -> u64 {
    if engine.get_data().architecture == Architecture::X64 {
        8
    } else {
        4
    }
}

fn put(engine: &mut Unicorn<Trace>, address: u64, bytes: &[u8]) -> Result<()> {
    require(engine, address, bytes.len() as u64, P::WRITE)?;
    crate::cpu::write(engine, address, bytes)
}

fn write_pointer(engine: &mut Unicorn<Trace>, address: u64, value: u64) -> Result<()> {
    let width = ptr_width(engine) as usize;
    put(engine, address, &value.to_le_bytes()[..width])
}

fn read_pointer(engine: &Unicorn<Trace>, address: u64) -> Result<u64> {
    let width = ptr_width(engine);
    let bytes = read(engine, address, width)?;
    let mut value = [0u8; 8];
    value[..width as usize].copy_from_slice(&bytes);
    Ok(u64::from_le_bytes(value))
}

fn encode(text: &str, wide: bool) -> Vec<u8> {
    if wide {
        let mut bytes: Vec<u8> = text.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        bytes.extend([0, 0]);
        bytes
    } else {
        let mut bytes = text.as_bytes().to_vec();
        bytes.push(0);
        bytes
    }
}

fn optional_text(engine: &Unicorn<Trace>, address: u64, wide: bool) -> Result<String> {
    if address == 0 {
        return Ok(String::new());
    }
    files::path(engine, address, wide)
}

fn record(
    engine: &mut Unicorn<Trace>,
    api: &'static str,
    verb: String,
    file: String,
    parameters: String,
) {
    let state = &mut engine.get_data_mut().apis.shell;
    if api != "SHChangeNotify" {
        state.report.execution_requests += 1;
    }
    if state.report.events.len() < 64 {
        state.report.events.push(Event { api, verb, file, parameters });
    } else {
        state.report.omitted_events += 1;
    }
}

fn folder(csidl: u32) -> Option<KnownFolder> {
    // CSIDL_FLAG_CREATE and friends live in the high bits.
    Some(match csidl & 0xff {
        0x05 => KnownFolder::Documents,
        0x07 => KnownFolder::Startup,
        0x10 => KnownFolder::Desktop,
        0x1a => KnownFolder::AppData,
        0x1c => KnownFolder::LocalAppData,
        0x23 => KnownFolder::ProgramData,
        0x24 => KnownFolder::Windows,
        0x25 => KnownFolder::System,
        0x26 => KnownFolder::ProgramFiles,
        0x28 => KnownFolder::Profile,
        _ => return None,
    })
}

pub(super) fn invoke(engine: &mut Unicorn<Trace>, args: &[u64], call: Call) -> Result<u64> {
    match call {
        Call::IsUserAnAdmin => {
            // The default persona is an ordinary interactive user, not elevated.
            Ok(0)
        }
        Call::ExtractIcon => {
            // No icon model exists; reporting "no icon" is the honest answer and
            // keeps the request visible.
            let file = optional_text(engine, args[1], false)?;
            record(engine, "ExtractIcon", String::new(), file, String::new());
            Ok(0)
        }
        Call::ChangeNotify => {
            record(engine, "SHChangeNotify", String::new(), String::new(), String::new());
            Ok(0)
        }
        Call::GetFolderPath { wide } => {
            // SHGetFolderPath(hwnd, csidl, hToken, dwFlags, pszPath).
            if args[4] == 0 {
                return Ok(E_INVALIDARG);
            }
            let Some(folder) = folder(args[1] as u32) else {
                return Ok(E_FAIL);
            };
            let path = engine
                .get_data()
                .apis
                .persona
                .model
                .known_folder(OWNER, folder)?;
            put(engine, args[4], &encode(&path, wide))?;
            Ok(S_OK)
        }
        Call::CreateDirectoryEx { wide } => {
            // SHCreateDirectoryEx(hwnd, pszPath, psa): the whole tree is made.
            if args[1] == 0 {
                return Ok(E_INVALIDARG);
            }
            let raw = files::path(engine, args[1], wide)?;
            let path = engine.get_data().apis.files.path(&raw)?;
            // Create each ancestor in turn; an existing directory is not a
            // failure for the Ex spelling.
            let parts: Vec<&str> = path.split('\\').filter(|p| !p.is_empty()).collect();
            let mut prefix = String::new();
            let mut last: u64 = 0;
            for (index, part) in parts.iter().enumerate() {
                if index > 0 {
                    prefix.push('\\');
                }
                prefix.push_str(part);
                // A bare drive ("c:") is not a directory to create.
                if index == 0 && part.ends_with(':') {
                    continue;
                }
                match engine.get_data_mut().apis.files.create_directory(&prefix) {
                    Ok(()) => last = 0,
                    // ERROR_ALREADY_EXISTS is success for a tree create.
                    Err(error) if error.win32 == 183 => last = 0,
                    Err(error) => last = error.win32 as u64,
                }
            }
            Ok(last)
        }
        Call::CommandLineToArgv { wide } => command_line_to_argv(engine, args, wide),
        Call::GetMalloc => {
            // SHGetMalloc(ppMalloc): a real IMalloc over the guest heap.
            if args[0] == 0 {
                return Ok(E_INVALIDARG);
            }
            let object = com::activate_malloc(engine)?;
            write_pointer(engine, args[0], object)?;
            Ok(S_OK)
        }
        Call::ShellExecute { wide } => {
            // ShellExecute(hwnd, lpOperation, lpFile, lpParameters,
            // lpDirectory, nShowCmd): recorded, never carried out.
            let verb = optional_text(engine, args[1], wide)?;
            let file = optional_text(engine, args[2], wide)?;
            let parameters = optional_text(engine, args[3], wide)?;
            if file.is_empty() {
                return Ok(0);
            }
            record(engine, "ShellExecute", verb, file, parameters);
            Ok(EXEC_OK)
        }
        Call::ShellExecuteEx => {
            if args[0] == 0 {
                return Ok(0);
            }
            let wide64 = ptr_width(engine) == 8;
            // SHELLEXECUTEINFO field offsets differ by pointer width.
            let (verb_at, file_at, params_at, inst_at, process_at) = if wide64 {
                (16u64, 24, 32, 56, 104)
            } else {
                (12, 16, 20, 32, 56)
            };
            let base = args[0];
            let verb_ptr = read_pointer(engine, base + verb_at)?;
            let file_ptr = read_pointer(engine, base + file_at)?;
            let params_ptr = read_pointer(engine, base + params_at)?;
            // The struct carries no width tail; the narrow spelling is assumed
            // unless the caller used the wide export, which shares this model.
            let verb = optional_text(engine, verb_ptr, false)?;
            let file = optional_text(engine, file_ptr, false)?;
            let parameters = optional_text(engine, params_ptr, false)?;
            record(engine, "ShellExecuteEx", verb, file, parameters);
            write_pointer(engine, base + inst_at, EXEC_OK)?;
            // No process exists to hand back, so the handle stays null.
            write_pointer(engine, base + process_at, 0)?;
            Ok(1)
        }
    }
}

/// `CommandLineToArgv`: split per the documented quoting and backslash rules,
/// then publish a pointer array followed by the argument strings.
fn command_line_to_argv(engine: &mut Unicorn<Trace>, args: &[u64], wide: bool) -> Result<u64> {
    let line = optional_text(engine, args[0], wide)?;
    let argv = split_command_line(&line, || {
        engine
            .get_data()
            .apis
            .modules
            .primary()
            .map(|module| module.name.clone())
            .unwrap_or_default()
    });
    let width = ptr_width(engine);
    let encoded: Vec<Vec<u8>> = argv.iter().map(|a| encode(a, wide)).collect();
    let table = argv.len() as u64 * width;
    let total = table + encoded.iter().map(|e| e.len() as u64).sum::<u64>();
    let block = heap::alloc(engine, total.max(width))?;
    let mut cursor = block + table;
    for (index, bytes) in encoded.iter().enumerate() {
        write_pointer(engine, block + index as u64 * width, cursor)?;
        put(engine, cursor, bytes)?;
        cursor += bytes.len() as u64;
    }
    if args[1] != 0 {
        put(engine, args[1], &(argv.len() as u32).to_le_bytes())?;
    }
    Ok(block)
}

/// The documented `CommandLineToArgvW` rules: `argv[0]` takes no escapes, and
/// elsewhere `2n` backslashes before a quote are `n` backslashes plus a quote
/// toggle while `2n+1` are `n` backslashes plus a literal quote.
fn split_command_line(line: &str, module: impl Fn() -> String) -> Vec<String> {
    if line.trim().is_empty() {
        // An empty command line yields the image name alone.
        return vec![module()];
    }
    let chars: Vec<char> = line.chars().collect();
    let mut index = 0;
    let mut argv = Vec::new();

    // argv[0]: a quoted run, otherwise up to the first whitespace.
    let mut first = String::new();
    if chars.get(index) == Some(&'"') {
        index += 1;
        while index < chars.len() && chars[index] != '"' {
            first.push(chars[index]);
            index += 1;
        }
        index += 1; // closing quote
    } else {
        while index < chars.len() && !chars[index].is_whitespace() {
            first.push(chars[index]);
            index += 1;
        }
    }
    argv.push(first);

    loop {
        while index < chars.len() && chars[index].is_whitespace() {
            index += 1;
        }
        if index >= chars.len() {
            break;
        }
        let mut current = String::new();
        let mut quoted = false;
        while index < chars.len() {
            if !quoted && chars[index].is_whitespace() {
                break;
            }
            if chars[index] == '\\' {
                let mut slashes = 0;
                while chars.get(index) == Some(&'\\') {
                    slashes += 1;
                    index += 1;
                }
                if chars.get(index) == Some(&'"') {
                    for _ in 0..slashes / 2 {
                        current.push('\\');
                    }
                    if slashes % 2 == 1 {
                        current.push('"');
                    } else {
                        quoted = !quoted;
                    }
                    index += 1;
                } else {
                    for _ in 0..slashes {
                        current.push('\\');
                    }
                }
                continue;
            }
            if chars[index] == '"' {
                quoted = !quoted;
                index += 1;
                continue;
            }
            current.push(chars[index]);
            index += 1;
        }
        argv.push(current);
    }
    argv
}

#[cfg(test)]
mod tests {
    use super::*;

    fn split(line: &str) -> Vec<String> {
        split_command_line(line, || "sample.exe".into())
    }

    #[test]
    fn command_line_splitting_follows_the_documented_rules() {
        assert_eq!(split(""), vec!["sample.exe"]);
        assert_eq!(split("prog.exe one two"), vec!["prog.exe", "one", "two"]);
        // argv[0] in quotes keeps its spaces and takes no escapes.
        assert_eq!(
            split("\"C:\\Program Files\\a.exe\" arg"),
            vec![r"C:\Program Files\a.exe", "arg"]
        );
        // A quoted later argument keeps its spaces.
        assert_eq!(split("p.exe \"two words\""), vec!["p.exe", "two words"]);
        // 2n backslashes before a quote: n backslashes and a quote toggle.
        assert_eq!(split(r#"p.exe a\\"b c"#), vec!["p.exe", r"a\b c"]);
        // 2n+1 backslashes before a quote: n backslashes and a literal quote.
        assert_eq!(split(r#"p.exe a\"b"#), vec!["p.exe", "a\"b"]);
        // Plain backslashes stay literal.
        assert_eq!(split(r"p.exe C:\dir\file"), vec!["p.exe", r"C:\dir\file"]);
    }

    #[test]
    fn known_folder_csidl_mapping_ignores_the_create_flag() {
        assert!(matches!(folder(0x1a), Some(KnownFolder::AppData)));
        // CSIDL_FLAG_CREATE (0x8000) must not change the folder.
        assert!(matches!(folder(0x1a | 0x8000), Some(KnownFolder::AppData)));
        assert!(matches!(folder(0x24), Some(KnownFolder::Windows)));
        assert!(folder(0x99).is_none());
    }
}
