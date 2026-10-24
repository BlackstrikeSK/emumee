//! Config-supplied guest identity and process-local environment state.
//!
//! No host environment, user, current directory, clock, registry or filesystem
//! is queried. This is an initial persona subset, not the whole legacy persona
//! schema. CPU/time/network/security configuration remains in separate models.
//! The engine owns guest allocations, readable/writable checks, PEB/process
//! parameters and synchronization with the guest VFS. Pure buffer plans below
//! never turn a guest pointer into a host pointer or truncate a short output.
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;
use unicode_casefold::UnicodeCaseFold;

pub const MAX_ENTRIES: usize = 256;
pub const MAX_ENV_BYTES: usize = 1024 * 1024;
pub const MAX_STRING_UNITS: usize = 32_767;
pub const MAX_PROCESSES: usize = 128;
pub const MAX_BLOCKS: usize = 4096;
pub const MAX_ARGUMENTS: usize = 256;
pub const MAX_ARGUMENT_BYTES: usize = 1024 * 1024;
#[derive(Debug, Error)]
#[error("Guest persona: {reason} (Win32 {win32})")]
pub struct PersonaError {
    pub win32: u32,
    pub reason: &'static str,
}
pub type Result<T> = std::result::Result<T, PersonaError>;
fn error(win32: u32, reason: &'static str) -> PersonaError {
    PersonaError { win32, reason }
}
fn fold(text: &str) -> String {
    text.case_fold().collect()
}
fn bounded(text: &str, allow_empty: bool) -> Result<()> {
    if (!allow_empty && text.is_empty())
        || text.contains('\0')
        || text.encode_utf16().count() > MAX_STRING_UNITS
    {
        return Err(error(87, "empty, NUL-containing or oversized guest string"));
    }
    Ok(())
}
fn variable_name(name: &str) -> Result<()> {
    bounded(name, false)?;
    if name.contains('=') {
        return Err(error(87, "environment name contains equals"));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum Encoding {
    Cp437,
    Cp1252,
    Utf8,
    Utf16,
}
impl Encoding {
    pub fn width(self) -> usize {
        if self == Self::Utf16 { 2 } else { 1 }
    }
    pub fn encode(self, text: &str, nul: bool) -> Vec<u8> {
        let mut result = match self {
            Self::Cp1252 => crate::registry::encode_text(text, false, false),
            Self::Utf16 => text.encode_utf16().flat_map(u16::to_le_bytes).collect(),
            Self::Utf8 => text.as_bytes().to_vec(),
            Self::Cp437 => text
                .chars()
                .map(|value| {
                    if value.is_ascii() {
                        value as u8
                    } else {
                        CP437
                            .iter()
                            .position(|code| u32::from(*code) == value as u32)
                            .map_or(b'?', |index| index as u8 + 128)
                    }
                })
                .collect(),
        };
        if nul {
            result.extend(std::iter::repeat_n(0, self.width()));
        }
        result
    }
    /// Decode an already bounded, non-terminated guest name. Malformed UTF16
    /// and UTF8 stop explicitly rather than aliasing another guest name.
    pub fn decode(self, bytes: &[u8]) -> Result<String> {
        match self {
            Self::Cp1252 => Ok(crate::registry::decode_text(bytes, false)),
            Self::Cp437 => Ok(bytes
                .iter()
                .map(|byte| {
                    if *byte < 128 {
                        char::from(*byte)
                    } else {
                        char::from_u32(CP437[usize::from(*byte - 128)].into()).unwrap()
                    }
                })
                .collect()),
            Self::Utf8 => String::from_utf8(bytes.to_vec())
                .map_err(|_| error(50, "invalid UTF8 guest string")),
            Self::Utf16 => crate::registry::decode_name(bytes, true)
                .map_err(|_| error(50, "invalid UTF16 guest string")),
        }
    }
}
const CP437: [u16; 128] = [
    0xc7, 0xfc, 0xe9, 0xe2, 0xe4, 0xe0, 0xe5, 0xe7, 0xea, 0xeb, 0xe8, 0xef, 0xee, 0xec, 0xc4, 0xc5,
    0xc9, 0xe6, 0xc6, 0xf4, 0xf6, 0xf2, 0xfb, 0xf9, 0xff, 0xd6, 0xdc, 0xa2, 0xa3, 0xa5, 0x20a7,
    0x192, 0xe1, 0xed, 0xf3, 0xfa, 0xf1, 0xd1, 0xaa, 0xba, 0xbf, 0x2310, 0xac, 0xbd, 0xbc, 0xa1,
    0xab, 0xbb, 0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x2561, 0x2562, 0x2556, 0x2555, 0x2563,
    0x2551, 0x2557, 0x255d, 0x255c, 0x255b, 0x2510, 0x2514, 0x2534, 0x252c, 0x251c, 0x2500, 0x253c,
    0x255e, 0x255f, 0x255a, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256c, 0x2567, 0x2568, 0x2564,
    0x2565, 0x2559, 0x2558, 0x2552, 0x2553, 0x256b, 0x256a, 0x2518, 0x250c, 0x2588, 0x2584, 0x258c,
    0x2590, 0x2580, 0x3b1, 0xdf, 0x393, 0x3c0, 0x3a3, 0x3c3, 0xb5, 0x3c4, 0x3a6, 0x398, 0x3a9,
    0x3b4, 0x221e, 0x3c6, 0x3b5, 0x2229, 0x2261, 0xb1, 0x2265, 0x2264, 0x2320, 0x2321, 0xf7,
    0x2248, 0xb0, 0x2219, 0xb7, 0x221a, 0x207f, 0xb2, 0x25a0, 0xa0,
];

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Environment {
    entries: Vec<(String, String)>,
}
impl Environment {
    pub fn new(entries: Vec<(String, String)>) -> Result<Self> {
        if entries.len() > MAX_ENTRIES {
            return Err(error(8, "guest environment entry count limit"));
        }
        let mut result = Self::default();
        for (name, value) in entries {
            result.set(&name, Some(&value))?;
        }
        Ok(result)
    }
    pub fn entries(&self) -> &[(String, String)] {
        &self.entries
    }
    pub fn map(&self) -> BTreeMap<String, String> {
        self.entries.iter().cloned().collect()
    }
    pub fn get(&self, name: &str) -> Result<Option<&str>> {
        variable_name(name)?;
        Ok(self
            .entries
            .iter()
            .find(|(candidate, _)| fold(candidate) == fold(name))
            .map(|(_, value)| value.as_str()))
    }
    /// Set Some("") creates an empty variable; None removes it. Failed changes
    /// leave both the original value and insertion order intact.
    pub fn set(&mut self, name: &str, value: Option<&str>) -> Result<()> {
        variable_name(name)?;
        if let Some(value) = value {
            bounded(value, true)?;
        }
        let index = self
            .entries
            .iter()
            .position(|(candidate, _)| fold(candidate) == fold(name));
        let mut next = self.clone();
        match (index, value) {
            (Some(index), Some(value)) => next.entries[index].1 = value.into(),
            (Some(index), None) => {
                next.entries.remove(index);
            }
            (None, Some(value)) => next.entries.push((name.into(), value.into())),
            (None, None) => return Ok(()),
        }
        next.validate_size()?;
        *self = next;
        Ok(())
    }
    fn validate_size(&self) -> Result<()> {
        let units = if self.entries.is_empty() {
            2
        } else {
            1 + self
                .entries
                .iter()
                .map(|(name, value)| name.encode_utf16().count() + value.encode_utf16().count() + 2)
                .sum::<usize>()
        };
        if self.entries.len() > MAX_ENTRIES || units * 2 > MAX_ENV_BYTES {
            return Err(error(8, "guest environment count or byte limit"));
        }
        Ok(())
    }
    /// Stable insertion order matches legacy blocks. The copy is always double
    /// NUL terminated, including a completely empty environment.
    pub fn block(&self, encoding: Encoding) -> Result<Vec<u8>> {
        self.validate_size()?;
        let mut bytes = Vec::new();
        for (name, value) in &self.entries {
            bytes.extend(encoding.encode(&format!("{name}={value}"), true));
            if bytes.len() + encoding.width() > MAX_ENV_BYTES {
                return Err(error(8, "encoded guest environment byte limit"));
            }
        }
        bytes.extend(std::iter::repeat_n(
            0,
            encoding.width() * if self.entries.is_empty() { 2 } else { 1 },
        ));
        Ok(bytes)
    }
    /// Single-pass percent expansion preserves unknown names and never expands
    /// replacement text recursively. Percent syntax beyond %NAME% is literal.
    pub fn expand(&self, source: &str) -> Result<String> {
        bounded(source, true)?;
        let mut result = String::new();
        let mut rest = source;
        while let Some(start) = rest.find('%') {
            let after = &rest[start + 1..];
            let Some(end) = after.find('%') else {
                break;
            };
            result.push_str(&rest[..start]);
            if end == 0 {
                result.push('%');
                rest = after;
                continue;
            }
            let token = &after[..end];
            if let Some((_, value)) = self
                .entries
                .iter()
                .find(|(name, _)| fold(name) == fold(token))
            {
                result.push_str(value);
            } else {
                result.push_str(&rest[start..start + end + 2]);
            }
            if result.len() > MAX_ENV_BYTES {
                return Err(error(8, "expanded guest string byte limit"));
            }
            rest = &after[end + 1..];
        }
        result.push_str(rest);
        bounded(&result, true)?;
        Ok(result)
    }
}

/// Buffer plans separate guest writes from return/count/error contracts. None
/// for last_error means preserve the calling thread's current LastError.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BufferPlan {
    pub result: u32,
    pub count: Option<u32>,
    pub bytes: Option<Vec<u8>>,
    pub last_error: Option<u32>,
}
fn counted(text: &str, encoding: Encoding) -> (Vec<u8>, u32) {
    let bytes = encoding.encode(text, true);
    let required = (bytes.len() / encoding.width()) as u32;
    (bytes, required)
}
fn sized_string(
    text: &str,
    encoding: Encoding,
    capacity: u32,
    has_buffer: bool,
    include_nul_return: bool,
    success_error: Option<u32>,
) -> Result<BufferPlan> {
    let (bytes, required) = counted(text, encoding);
    if capacity < required {
        return Ok(BufferPlan {
            result: required,
            count: None,
            bytes: None,
            last_error: None,
        });
    }
    if !has_buffer {
        return Err(error(87, "null guest output buffer"));
    }
    Ok(BufferPlan {
        result: required - u32::from(!include_nul_return),
        count: None,
        bytes: Some(bytes),
        last_error: success_error,
    })
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PersonaConfig {
    pub hostname: String,
    pub domain: String,
    pub user_name: String,
    pub user_profile: String,
    pub current_directory: String,
    pub windows_directory: String,
    pub system_directory: String,
    pub temp_directory: String,
    pub logical_processors: u32,
    pub environment: Vec<(String, String)>,
}
impl PersonaConfig {
    /// Explicit generated literals for harmless tests; never host defaults.
    pub fn fixture() -> Self {
        Self {
            hostname: "DESKTOP-7F4M2Q9".into(),
            domain: "WORKGROUP".into(),
            user_name: "Alex".into(),
            user_profile: r"C:\Users\Alex".into(),
            current_directory: r"C:\Users\Alex\Downloads".into(),
            windows_directory: r"C:\Windows".into(),
            system_directory: r"C:\Windows\System32".into(),
            temp_directory: r"C:\Users\Alex\AppData\Local\Temp".into(),
            logical_processors: 12,
            environment: Vec::new(),
        }
    }
}
#[derive(Clone, Debug)]
pub struct ProcessConfig {
    pub image_path: String,
    pub arguments: Vec<String>,
    pub force_quotes: Vec<usize>,
    pub command_line: Option<String>,
    pub current_directory: Option<String>,
    pub environment_overrides: Vec<(String, Option<String>)>,
}
impl ProcessConfig {
    pub fn fixture() -> Self {
        Self {
            image_path: r"C:\Users\Alex\Downloads\fixture.exe".into(),
            arguments: Vec::new(),
            force_quotes: Vec::new(),
            command_line: None,
            current_directory: None,
            environment_overrides: Vec::new(),
        }
    }
}
#[derive(Clone, Debug)]
struct Process {
    environment: Environment,
    current_directory: String,
    command_line: String,
    argv: Vec<String>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuestBlock {
    pub owner: u64,
    pub address: u64,
    pub encoding: Encoding,
}
#[derive(Clone, Copy, Debug)]
pub enum Directory {
    Current,
    System,
    Windows,
    Temp,
}
#[derive(Clone, Debug)]
pub struct Persona {
    config: PersonaConfig,
    initial_environment: Environment,
    processes: BTreeMap<u64, Process>,
    blocks: BTreeMap<(u64, u64), GuestBlock>,
}

fn absolute(path: &str) -> Result<String> {
    bounded(path, false)?;
    let path = path.replace('/', "\\");
    let bytes = path.as_bytes();
    if bytes.len() < 3 || !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' || bytes[2] != b'\\' {
        return Err(error(
            50,
            "UNC, device, drive-relative or nonabsolute persona path",
        ));
    }
    let mut parts = Vec::new();
    for part in path[3..].split('\\') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            part => {
                if part.contains([':', '*', '?', '"', '<', '>', '|'])
                    || part.ends_with([' ', '.'])
                    || part.chars().any(|c| c < ' ')
                {
                    return Err(error(50, "unsupported persona path component"));
                }
                parts.push(part);
            }
        }
    }
    Ok(format!(
        "{}:\\{}",
        (bytes[0] as char).to_ascii_uppercase(),
        parts.join("\\")
    ))
}
fn relative(directory: &str, path: &str) -> Result<String> {
    bounded(path, false)?;
    if path.starts_with("\\\\") || path.starts_with("//") {
        return Err(error(
            50,
            "UNC/device guest current directory is not modeled",
        ));
    }
    if path.as_bytes().get(1) == Some(&b':') {
        absolute(path)
    } else if path.starts_with(['\\', '/']) {
        absolute(&format!("{}{}", &directory[..2], path))
    } else {
        absolute(&format!("{directory}\\{path}"))
    }
}
/// Microsoft CRT quoting, matching the legacy subprocess.list2cmdline builder.
/// Force-quoted arguments may not contain quote characters, as in legacy CLI.
pub fn command_line(argv: &[String], force_quotes: &[usize]) -> Result<String> {
    if argv.is_empty() || argv.len() > MAX_ARGUMENTS || force_quotes.len() > MAX_ARGUMENTS {
        return Err(error(87, "guest argument count limit"));
    }
    let forced: BTreeSet<_> = force_quotes.iter().copied().collect();
    if forced
        .iter()
        .any(|index| *index == 0 || *index >= argv.len() || argv[*index].contains('"'))
    {
        return Err(error(87, "invalid forced guest argument quote index/value"));
    }
    let mut rendered = Vec::new();
    for (index, value) in argv.iter().enumerate() {
        bounded(value, true)?;
        let quoted = value.is_empty() || value.contains([' ', '\t']);
        let mut out = String::new();
        if quoted {
            out.push('"');
        }
        let mut slashes = 0;
        for character in value.chars() {
            if character == '\\' {
                slashes += 1;
                continue;
            }
            if character == '"' {
                out.extend(std::iter::repeat_n('\\', slashes * 2 + 1));
            } else {
                out.extend(std::iter::repeat_n('\\', slashes));
            }
            out.push(character);
            slashes = 0;
        }
        out.extend(std::iter::repeat_n(
            '\\',
            slashes * if quoted { 2 } else { 1 },
        ));
        if quoted {
            out.push('"');
        }
        // The legacy --guest-quote-arg option wraps an otherwise unquoted
        // subprocess.list2cmdline result. Preserve that raw spelling (including
        // trailing backslashes), rather than reinterpreting it as CRT quoting.
        if forced.contains(&index) && !quoted {
            out = format!("\"{out}\"");
        }
        rendered.push(out);
    }
    let result = rendered.join(" ");
    if result.len() > MAX_ARGUMENT_BYTES || result.encode_utf16().count() >= MAX_STRING_UNITS {
        return Err(error(87, "guest command line exceeds profile"));
    }
    Ok(result)
}

impl Persona {
    pub fn new(mut config: PersonaConfig) -> Result<Self> {
        if config.environment.len() > MAX_ENTRIES {
            return Err(error(8, "guest persona environment override count limit"));
        }
        for text in [&config.hostname, &config.domain, &config.user_name] {
            bounded(text, false)?;
            if text.encode_utf16().count() > 255 || text.chars().any(|c| c < ' ') {
                return Err(error(87, "persona identity exceeds profile"));
            }
        }
        if !(1..=64).contains(&config.logical_processors) {
            return Err(error(50, "persona supports one logical processor group"));
        }
        config.user_profile = absolute(&config.user_profile)?;
        config.current_directory = absolute(&config.current_directory)?;
        config.windows_directory = absolute(&config.windows_directory)?;
        config.system_directory = absolute(&config.system_directory)?;
        config.temp_directory = absolute(&config.temp_directory)?;
        let system_drive = config.windows_directory[..2].to_owned();
        let home_drive = config.user_profile[..2].to_owned();
        let defaults = vec![
            ("USERPROFILE".into(), config.user_profile.clone()),
            ("USERNAME".into(), config.user_name.clone()),
            ("COMPUTERNAME".into(), config.hostname.clone()),
            ("USERDOMAIN".into(), config.hostname.clone()),
            ("HOMEDRIVE".into(), home_drive),
            ("HOMEPATH".into(), config.user_profile[2..].into()),
            ("SYSTEMDRIVE".into(), system_drive.clone()),
            ("SYSTEMROOT".into(), config.windows_directory.clone()),
            ("WINDIR".into(), config.windows_directory.clone()),
            ("OS".into(), "Windows_NT".into()),
            (
                "NUMBER_OF_PROCESSORS".into(),
                config.logical_processors.to_string(),
            ),
            ("PUBLIC".into(), format!("{system_drive}\\Users\\Public")),
            ("PROGRAMDATA".into(), format!("{system_drive}\\ProgramData")),
            (
                "PROGRAMFILES".into(),
                format!("{system_drive}\\Program Files"),
            ),
            (
                "PROGRAMFILES(X86)".into(),
                format!("{system_drive}\\Program Files (x86)"),
            ),
            (
                "PROGRAMW6432".into(),
                format!("{system_drive}\\Program Files"),
            ),
            (
                "COMMONPROGRAMFILES".into(),
                format!("{system_drive}\\Program Files\\Common Files"),
            ),
            (
                "COMMONPROGRAMFILES(X86)".into(),
                format!("{system_drive}\\Program Files (x86)\\Common Files"),
            ),
            (
                "COMMONPROGRAMW6432".into(),
                format!("{system_drive}\\Program Files\\Common Files"),
            ),
            (
                "PATH".into(),
                format!(
                    "{};{};{}\\Wbem",
                    config.system_directory, config.windows_directory, config.system_directory
                ),
            ),
            ("TEMP".into(), format!("{}\\", config.temp_directory)),
            ("TMP".into(), format!("{}\\", config.temp_directory)),
            (
                "APPDATA".into(),
                format!("{}\\AppData\\Roaming", config.user_profile),
            ),
            (
                "LOCALAPPDATA".into(),
                format!("{}\\AppData\\Local", config.user_profile),
            ),
        ];
        let mut initial_environment = Environment::new(defaults)?;
        for (name, value) in &config.environment {
            initial_environment.set(name, Some(value))?;
        }
        Ok(Self {
            config,
            initial_environment,
            processes: BTreeMap::new(),
            blocks: BTreeMap::new(),
        })
    }
    pub fn config(&self) -> &PersonaConfig {
        &self.config
    }
    fn process(&self, owner: u64) -> Result<&Process> {
        self.processes
            .get(&owner)
            .ok_or_else(|| error(6, "unknown or retired guest process environment"))
    }
    fn process_mut(&mut self, owner: u64) -> Result<&mut Process> {
        self.processes
            .get_mut(&owner)
            .ok_or_else(|| error(6, "unknown or retired guest process environment"))
    }
    pub fn add_process(&mut self, owner: u64, config: ProcessConfig) -> Result<()> {
        self.insert_process(
            owner,
            config,
            self.initial_environment.clone(),
            self.config.current_directory.clone(),
        )
    }
    pub fn inherit_process(
        &mut self,
        parent: u64,
        owner: u64,
        config: ProcessConfig,
    ) -> Result<()> {
        let parent = self.process(parent)?;
        self.insert_process(
            owner,
            config,
            parent.environment.clone(),
            parent.current_directory.clone(),
        )
    }
    fn insert_process(
        &mut self,
        owner: u64,
        config: ProcessConfig,
        mut environment: Environment,
        directory: String,
    ) -> Result<()> {
        if owner == 0 || self.processes.contains_key(&owner) {
            return Err(error(87, "invalid or duplicate guest process owner"));
        }
        if self.processes.len() >= MAX_PROCESSES {
            return Err(error(8, "guest process environment count limit"));
        }
        let directory = match config.current_directory {
            Some(path) => relative(&directory, &path)?,
            None => directory,
        };
        let image = relative(&directory, &config.image_path)?;
        if config.arguments.len() >= MAX_ARGUMENTS
            || config.environment_overrides.len() > MAX_ENTRIES
        {
            return Err(error(87, "guest argument count limit"));
        }
        let mut argv = vec![image];
        argv.extend(config.arguments);
        let quoted: Vec<_> = config
            .force_quotes
            .iter()
            .map(|index| {
                index
                    .checked_add(1)
                    .ok_or_else(|| error(87, "guest quote index overflow"))
            })
            .collect::<Result<_>>()?;
        let built_command = command_line(&argv, &quoted)?;
        let command_line = if let Some(command) = config.command_line {
            bounded(&command, true)?;
            if command.encode_utf16().count() >= MAX_STRING_UNITS {
                return Err(error(87, "guest command line exceeds profile"));
            }
            command
        } else {
            built_command
        };
        for (name, value) in config.environment_overrides {
            environment.set(&name, value.as_deref())?;
        }
        self.processes.insert(
            owner,
            Process {
                environment,
                current_directory: directory,
                command_line,
                argv,
            },
        );
        Ok(())
    }
    pub fn environment(&self, owner: u64) -> Result<&Environment> {
        Ok(&self.process(owner)?.environment)
    }
    pub fn set_variable(&mut self, owner: u64, name: &str, value: Option<&str>) -> Result<()> {
        self.process_mut(owner)?.environment.set(name, value)
    }
    pub fn environment_block(&self, owner: u64, encoding: Encoding) -> Result<Vec<u8>> {
        self.environment(owner)?.block(encoding)
    }
    pub fn command_line(&self, owner: u64, encoding: Encoding) -> Result<Vec<u8>> {
        Ok(encoding.encode(&self.process(owner)?.command_line, true))
    }
    pub fn argv(&self, owner: u64) -> Result<&[String]> {
        Ok(&self.process(owner)?.argv)
    }
    /// Returns owned addresses for engine cleanup. The caller must retire their
    /// guest mappings and stable commandline/PEB storage as part of process exit.
    pub fn remove_process(&mut self, owner: u64) -> Result<Vec<GuestBlock>> {
        self.process(owner)?;
        self.processes.remove(&owner);
        let blocks = self
            .blocks
            .values()
            .filter(|block| block.owner == owner)
            .copied()
            .collect();
        self.blocks.retain(|_, block| block.owner != owner);
        Ok(blocks)
    }
    pub fn track_block(&mut self, owner: u64, address: u64, encoding: Encoding) -> Result<()> {
        self.process(owner)?;
        if address == 0 || self.blocks.contains_key(&(owner, address)) {
            return Err(error(87, "invalid or already tracked environment block"));
        }
        if self.blocks.len() >= MAX_BLOCKS {
            return Err(error(8, "guest environment block count limit"));
        }
        self.blocks.insert(
            (owner, address),
            GuestBlock {
                owner,
                address,
                encoding,
            },
        );
        Ok(())
    }
    pub fn block(&self, owner: u64, address: u64, encoding: Encoding) -> Result<GuestBlock> {
        self.process(owner)?;
        self.blocks
            .get(&(owner, address))
            .filter(|block| block.owner == owner && block.encoding == encoding)
            .copied()
            .ok_or_else(|| error(87, "foreign, freed or wrong-encoding environment block"))
    }
    /// Call only after a validated engine unmap succeeds. A failed free must
    /// retain the block's metadata and backing for a later honest cleanup.
    pub fn retire_block(&mut self, owner: u64, address: u64, encoding: Encoding) -> Result<()> {
        self.block(owner, address, encoding)?;
        self.blocks.remove(&(owner, address));
        Ok(())
    }
    // Legacy GetEnvironmentVariableA uses CP437, W uses UTF16. Capacity is
    // encoded characters/units. https://learn.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-getenvironmentvariablew
    pub fn variable(
        &self,
        owner: u64,
        name: &str,
        encoding: Encoding,
        capacity: u32,
        has_buffer: bool,
    ) -> Result<BufferPlan> {
        let Some(text) = self.environment(owner)?.get(name)? else {
            return Ok(BufferPlan {
                result: 0,
                count: None,
                bytes: None,
                last_error: Some(203),
            });
        };
        let (bytes, required) = counted(text, encoding);
        if capacity < required {
            return Ok(BufferPlan {
                result: required,
                count: None,
                bytes: None,
                last_error: Some(122),
            });
        }
        if !has_buffer {
            return Err(error(87, "null guest environment-variable buffer"));
        }
        Ok(BufferPlan {
            result: required - 1,
            count: None,
            bytes: Some(bytes),
            last_error: Some(0),
        })
    }
    // https://learn.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-expandenvironmentstringsw
    pub fn expand(
        &self,
        owner: u64,
        source: &str,
        encoding: Encoding,
        capacity: u32,
        has_buffer: bool,
    ) -> Result<BufferPlan> {
        sized_string(
            &self.environment(owner)?.expand(source)?,
            encoding,
            capacity,
            has_buffer,
            true,
            None,
        )
    }
    pub fn resolve_directory(&self, owner: u64, path: &str) -> Result<String> {
        relative(&self.process(owner)?.current_directory, path)
    }
    /// Pure commit after the adapter verifies this canonical directory exists
    /// in the guest VFS. This function does not test a host or guest filesystem.
    pub fn commit_directory(&mut self, owner: u64, canonical: &str) -> Result<()> {
        let path = absolute(canonical)?;
        self.process_mut(owner)?.current_directory = path;
        Ok(())
    }
    pub fn directory(
        &self,
        owner: u64,
        kind: Directory,
        encoding: Encoding,
        capacity: u32,
        has_buffer: bool,
    ) -> Result<BufferPlan> {
        let process = self.process(owner)?;
        let text = match kind {
            Directory::Current => process.current_directory.clone(),
            Directory::System => self.config.system_directory.clone(),
            Directory::Windows => self.config.windows_directory.clone(),
            Directory::Temp => {
                let mut path = None;
                for name in ["TMP", "TEMP", "USERPROFILE"] {
                    if let Some(value) = process.environment.get(name)? {
                        if !value.is_empty() {
                            path = Some(value);
                            break;
                        }
                    }
                }
                let path = path.unwrap_or(&self.config.windows_directory);
                if path.encode_utf16().count() > 259 {
                    return Err(error(87, "guest temporary path exceeds legacy limit"));
                }
                format!("{}\\", absolute(path)?.trim_end_matches('\\'))
            }
        };
        sized_string(
            &text,
            encoding,
            capacity,
            has_buffer,
            false,
            if matches!(kind, Directory::Temp) {
                Some(0)
            } else {
                None
            },
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn identity(
        &self,
        text: &str,
        encoding: Encoding,
        capacity: u32,
        has_buffer: bool,
        short_error: u32,
        include_nul_count: bool,
        allow_null_query: bool,
    ) -> Result<BufferPlan> {
        if !has_buffer && (!allow_null_query || capacity != 0) {
            return Err(error(87, "null guest identity buffer"));
        }
        let (bytes, required) = counted(text, encoding);
        if capacity < required {
            return Ok(BufferPlan {
                result: 0,
                count: Some(required),
                bytes: None,
                last_error: Some(short_error),
            });
        }
        Ok(BufferPlan {
            result: 1,
            count: Some(required - u32::from(!include_nul_count)),
            bytes: Some(bytes),
            last_error: Some(0),
        })
    }
    pub fn computer_name(
        &self,
        encoding: Encoding,
        capacity: u32,
        has_buffer: bool,
    ) -> Result<BufferPlan> {
        self.identity(
            &self.config.hostname,
            encoding,
            capacity,
            has_buffer,
            111,
            false,
            false,
        )
    }
    pub fn computer_name_ex(
        &self,
        format: u32,
        encoding: Encoding,
        capacity: u32,
        has_buffer: bool,
    ) -> Result<BufferPlan> {
        let domain = if self.config.domain.eq_ignore_ascii_case("WORKGROUP") {
            ""
        } else {
            &self.config.domain
        };
        let text = match format {
            0 | 1 | 4 | 5 => self.config.hostname.clone(),
            2 | 6 => domain.into(),
            3 | 7 => format!(
                "{}{}{}",
                self.config.hostname,
                if domain.is_empty() { "" } else { "." },
                domain
            ),
            _ => return Err(error(87, "invalid computer name format")),
        };
        self.identity(&text, encoding, capacity, has_buffer, 234, false, true)
    }
    pub fn user_name(
        &self,
        encoding: Encoding,
        capacity: u32,
        has_buffer: bool,
    ) -> Result<BufferPlan> {
        self.identity(
            &self.config.user_name,
            encoding,
            capacity,
            has_buffer,
            122,
            true,
            false,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn code<T>(result: Result<T>) -> u32 {
        result.err().unwrap().win32
    }
    fn persona() -> Persona {
        let mut persona = Persona::new(PersonaConfig::fixture()).unwrap();
        persona.add_process(1, ProcessConfig::fixture()).unwrap();
        persona
    }
    #[test]
    fn encoding_profiles_keep_oem_ansi_utf8_and_utf16_distinct() {
        assert_eq!(Encoding::Cp437.encode("é€", true), [0x82, b'?', 0]);
        assert_eq!(Encoding::Cp1252.encode("é€", true), [0xe9, 0x80, 0]);
        assert_eq!(Encoding::Utf8.encode("é", true), [0xc3, 0xa9, 0]);
        assert_eq!(
            Encoding::Utf16.encode("😀", true),
            [0x3d, 0xd8, 0, 0xde, 0, 0]
        );
        for byte in 0..=255u8 {
            let text = Encoding::Cp437.decode(&[byte]).unwrap();
            assert_eq!(Encoding::Cp437.encode(&text, false), [byte]);
        }
        assert_eq!(code(Encoding::Utf16.decode(&[0, 0xd8])), 50);
        assert_eq!(code(Encoding::Utf8.decode(&[0xff])), 50);
    }
    #[test]
    fn environment_order_casefold_defaults_and_double_terminators() {
        let mut env = Environment::new(vec![
            ("TEMP".into(), "first".into()),
            ("User".into(), "é".into()),
        ])
        .unwrap();
        env.set("temp", Some("changed")).unwrap();
        assert_eq!(env.get("TeMp").unwrap(), Some("changed"));
        assert_eq!(env.entries()[0].0, "TEMP");
        assert_eq!(
            env.block(Encoding::Cp437).unwrap(),
            b"TEMP=changed\0User=\x82\0\0"
        );
        assert_eq!(
            env.block(Encoding::Utf16).unwrap(),
            Encoding::Utf16.encode("TEMP=changed\0User=é\0\0", false)
        );
        assert_eq!(
            Environment::default().block(Encoding::Cp437).unwrap(),
            b"\0\0"
        );
        assert_eq!(
            Environment::default().block(Encoding::Utf16).unwrap(),
            [0, 0, 0, 0]
        );
        env.set("TEMP", None).unwrap();
        assert_eq!(env.get("temp").unwrap(), None);
        env.set("TEMP", Some("")).unwrap();
        assert_eq!(env.get("temp").unwrap(), Some(""));
        assert_eq!(env.entries()[1].0, "TEMP");
    }
    #[test]
    fn environment_mutation_is_atomic_and_bounded() {
        let mut env = Environment::new(vec![("Keep".into(), "old".into())]).unwrap();
        assert_eq!(code(env.set("Bad=Name", Some("x"))), 87);
        assert_eq!(
            code(env.set("Keep", Some(&"x".repeat(MAX_STRING_UNITS + 1)))),
            87
        );
        assert_eq!(env.get("Keep").unwrap(), Some("old"));
        for index in 1..MAX_ENTRIES {
            env.set(&format!("K{index}"), Some("")).unwrap();
        }
        assert_eq!(code(env.set("Overflow", Some("x"))), 8);
        env.set("Keep", Some("replacement")).unwrap();
        assert_eq!(env.entries().len(), MAX_ENTRIES);
    }
    #[test]
    fn variable_buffer_contract_distinguishes_missing_empty_and_encoded_units() {
        let mut persona = persona();
        persona.set_variable(1, "TEXT", Some("é😀")).unwrap();
        let small = persona
            .variable(1, "text", Encoding::Utf16, 3, true)
            .unwrap();
        assert_eq!(
            small,
            BufferPlan {
                result: 4,
                count: None,
                bytes: None,
                last_error: Some(122)
            }
        );
        let full = persona
            .variable(1, "text", Encoding::Utf16, 4, true)
            .unwrap();
        assert_eq!(full.result, 3);
        assert_eq!(full.bytes.unwrap(), Encoding::Utf16.encode("é😀", true));
        assert_eq!(full.last_error, Some(0));
        assert_eq!(
            persona
                .variable(1, "missing", Encoding::Cp437, 0, false)
                .unwrap()
                .last_error,
            Some(203)
        );
        persona.set_variable(1, "EMPTY", Some("")).unwrap();
        assert_eq!(
            persona
                .variable(1, "EMPTY", Encoding::Cp437, 0, false)
                .unwrap()
                .result,
            1
        );
        let empty = persona
            .variable(1, "EMPTY", Encoding::Cp437, 1, true)
            .unwrap();
        assert_eq!(empty.result, 0);
        assert_eq!(empty.last_error, Some(0));
        assert_eq!(empty.bytes.unwrap(), b"\0");
        assert_eq!(
            code(persona.variable(1, "text", Encoding::Cp437, 20, false)),
            87
        );
    }
    #[test]
    fn expansion_preserves_unknown_tokens_and_avoids_recursive_substitution() {
        let mut persona = persona();
        persona.set_variable(1, "X", Some("%Y%")).unwrap();
        persona
            .set_variable(1, "Y", Some("unexpected recursive value"))
            .unwrap();
        let source = "%Unknown%|%x%|%%X%";
        let full = persona
            .expand(1, source, Encoding::Utf16, 64, true)
            .unwrap();
        assert_eq!(
            full.bytes.unwrap(),
            Encoding::Utf16.encode("%Unknown%|%Y%|%%Y%", true)
        );
        let required = full.result;
        assert_eq!(full.last_error, None);
        let query = persona
            .expand(1, source, Encoding::Utf16, 0, false)
            .unwrap();
        assert_eq!(query.result, required);
        assert!(query.bytes.is_none());
    }
    #[test]
    fn process_inheritance_and_cleanup_do_not_share_mutations() {
        let mut persona = persona();
        persona.set_variable(1, "MARK", Some("parent")).unwrap();
        persona
            .inherit_process(1, 2, ProcessConfig::fixture())
            .unwrap();
        persona.set_variable(1, "MARK", Some("changed")).unwrap();
        assert_eq!(
            persona.environment(2).unwrap().get("mark").unwrap(),
            Some("parent")
        );
        persona.track_block(1, 0x1000, Encoding::Utf16).unwrap();
        persona.track_block(2, 0x2000, Encoding::Cp437).unwrap();
        assert_eq!(code(persona.block(2, 0x1000, Encoding::Utf16)), 87);
        assert_eq!(code(persona.retire_block(1, 0x1000, Encoding::Cp437)), 87);
        persona.track_block(2, 0x1000, Encoding::Utf16).unwrap();
        let blocks = persona.remove_process(1).unwrap();
        assert_eq!(
            blocks,
            vec![GuestBlock {
                owner: 1,
                address: 0x1000,
                encoding: Encoding::Utf16
            }]
        );
        assert_eq!(code(persona.environment(1)), 6);
        assert!(persona.block(2, 0x1000, Encoding::Utf16).is_ok());
        persona.retire_block(2, 0x2000, Encoding::Cp437).unwrap();
        assert_eq!(code(persona.retire_block(2, 0x2000, Encoding::Cp437)), 87);
        assert!(persona.environment(2).is_ok());
    }
    #[test]
    fn identity_size_count_conventions_and_domain_formats_match_legacy() {
        let mut config = PersonaConfig::fixture();
        config.hostname = "Host".into();
        config.user_name = "é😀".into();
        config.domain = "guest.example".into();
        let persona = Persona::new(config).unwrap();
        let small = persona.computer_name(Encoding::Utf16, 4, true).unwrap();
        assert_eq!(small.count, Some(5));
        assert_eq!(small.last_error, Some(111));
        assert!(small.bytes.is_none());
        let full = persona.computer_name(Encoding::Utf16, 5, true).unwrap();
        assert_eq!(full.result, 1);
        assert_eq!(full.count, Some(4));
        assert_eq!(
            persona.user_name(Encoding::Utf16, 4, true).unwrap().count,
            Some(4)
        );
        assert_eq!(
            persona
                .computer_name_ex(3, Encoding::Cp1252, 64, true)
                .unwrap()
                .bytes
                .unwrap(),
            b"Host.guest.example\0"
        );
        assert_eq!(
            persona
                .computer_name_ex(3, Encoding::Utf16, 0, false)
                .unwrap()
                .last_error,
            Some(234)
        );
        assert_eq!(code(persona.computer_name(Encoding::Utf16, 0, false)), 87);
        assert_eq!(
            code(persona.computer_name_ex(8, Encoding::Utf16, 64, true)),
            87
        );
    }
    #[test]
    fn command_line_quoting_and_raw_override_are_config_owned() {
        let argv = vec![
            r"C:\Program Files\app.exe".into(),
            "".into(),
            "plain".into(),
            "quote\"x".into(),
            r"space \\".into(),
        ];
        assert_eq!(
            command_line(&argv, &[2]).unwrap(),
            r#""C:\Program Files\app.exe" "" "plain" quote\"x "space \\\\""#
        );
        assert_eq!(code(command_line(&argv, &[3])), 87);
        assert_eq!(
            command_line(&["app".into(), r"plain\".into()], &[1]).unwrap(),
            r#"app "plain\""#
        );
        let mut persona = persona();
        let mut config = ProcessConfig::fixture();
        config.arguments = vec!["argument".into()];
        config.command_line = Some("literal supplied command".into());
        persona.add_process(2, config).unwrap();
        assert_eq!(
            persona.command_line(2, Encoding::Cp1252).unwrap(),
            b"literal supplied command\0"
        );
        assert_eq!(persona.argv(2).unwrap()[1], "argument");
    }
    #[test]
    fn directory_normalization_temp_precedence_and_process_isolation() {
        let mut persona = persona();
        persona
            .inherit_process(1, 2, ProcessConfig::fixture())
            .unwrap();
        assert_eq!(
            persona.resolve_directory(1, r"..\Desktop").unwrap(),
            r"C:\Users\Alex\Desktop"
        );
        persona.commit_directory(1, r"C:\Guest\Directory").unwrap();
        let query = persona
            .directory(1, Directory::Current, Encoding::Utf16, 0, false)
            .unwrap();
        assert_eq!(query.result, 19);
        assert_eq!(
            persona
                .directory(2, Directory::Current, Encoding::Cp1252, 256, true)
                .unwrap()
                .bytes
                .unwrap(),
            b"C:\\Users\\Alex\\Downloads\0"
        );
        persona
            .set_variable(1, "TMP", Some(r"D:\GuestTemp"))
            .unwrap();
        assert_eq!(
            persona
                .directory(1, Directory::Temp, Encoding::Utf16, 256, true)
                .unwrap()
                .bytes
                .unwrap(),
            Encoding::Utf16.encode("D:\\GuestTemp\\", true)
        );
        assert_eq!(code(persona.resolve_directory(1, r"C:relative")), 50);
        assert_eq!(code(persona.resolve_directory(1, r"\\host\share")), 50);
    }
    #[test]
    fn command_lines_match_generated_legacy_reference_vectors() {
        let cases: &[(&[&str], &[usize], &str)] = &[
            (&["C:\\guest\\app.exe", ""], &[], "C:\\guest\\app.exe \"\""),
            (
                &["C:\\guest\\app.exe", "plain"],
                &[],
                "C:\\guest\\app.exe plain",
            ),
            (
                &["C:\\guest\\app.exe", "a b"],
                &[],
                "C:\\guest\\app.exe \"a b\"",
            ),
            (
                &["C:\\guest\\app.exe", "a\tb"],
                &[],
                "C:\\guest\\app.exe \"a\tb\"",
            ),
            (
                &["C:\\guest\\app.exe", "one\\"],
                &[],
                "C:\\guest\\app.exe one\\",
            ),
            (
                &["C:\\guest\\app.exe", "one\\\\"],
                &[],
                "C:\\guest\\app.exe one\\\\",
            ),
            (
                &["C:\\guest\\app.exe", "space \\"],
                &[],
                "C:\\guest\\app.exe \"space \\\\\"",
            ),
            (
                &["C:\\guest\\app.exe", "space \\\\"],
                &[],
                "C:\\guest\\app.exe \"space \\\\\\\\\"",
            ),
            (
                &["C:\\guest\\app.exe", "quote\"x"],
                &[],
                "C:\\guest\\app.exe quote\\\"x",
            ),
            (
                &["C:\\guest\\app.exe", "\\\""],
                &[],
                "C:\\guest\\app.exe \\\\\\\"",
            ),
            (
                &["C:\\guest\\app.exe", "\\\\\""],
                &[],
                "C:\\guest\\app.exe \\\\\\\\\\\"",
            ),
            (
                &["C:\\guest\\app.exe", "a\\\"b c"],
                &[],
                "C:\\guest\\app.exe \"a\\\\\\\"b c\"",
            ),
            (
                &["C:\\guest\\app.exe", "\"already quoted\""],
                &[],
                "C:\\guest\\app.exe \"\\\"already quoted\\\"\"",
            ),
            (
                &["C:\\guest\\app.exe", "x\ny"],
                &[],
                "C:\\guest\\app.exe x\ny",
            ),
            (
                &["C:\\guest\\app.exe", "x;y"],
                &[],
                "C:\\guest\\app.exe x;y",
            ),
            (
                &["C:\\guest\\app.exe", "C:\\path\\file"],
                &[],
                "C:\\guest\\app.exe C:\\path\\file",
            ),
            (&["C:\\guest\\app.exe", ""], &[1], "C:\\guest\\app.exe \"\""),
            (
                &["C:\\guest\\app.exe", "plain"],
                &[1],
                "C:\\guest\\app.exe \"plain\"",
            ),
            (
                &["C:\\guest\\app.exe", "plain\\"],
                &[1],
                "C:\\guest\\app.exe \"plain\\\"",
            ),
            (
                &["C:\\guest\\app.exe", "plain\\\\"],
                &[1],
                "C:\\guest\\app.exe \"plain\\\\\"",
            ),
            (
                &["C:\\guest\\app.exe", "a b"],
                &[1],
                "C:\\guest\\app.exe \"a b\"",
            ),
            (
                &["C:\\guest\\app.exe", "space \\"],
                &[1],
                "C:\\guest\\app.exe \"space \\\\\"",
            ),
        ];
        for (argv, forced, expected) in cases {
            let argv: Vec<String> = argv.iter().map(|arg| (*arg).into()).collect();
            assert_eq!(
                command_line(&argv, forced).unwrap(),
                *expected,
                "{argv:?} {forced:?}"
            );
        }
    }
}
