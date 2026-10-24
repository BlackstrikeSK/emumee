//! Deterministic guest console session. No terminal, host file/handle, stdin or
//! code page is queried. Standard-handle table lives in process-owned Stdio;
//! aliases and session modes here consume that table when classifying a handle.
use crate::{
    crt_stdio::{self, Encoding, WriteKind},
    persona,
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;
pub const MAX_ALIASES: usize = 128;
pub const ALIAS_FIRST: u64 = 0xf100;
pub const ALIAS_END: u64 = ALIAS_FIRST + MAX_ALIASES as u64;
pub const MAX_CONSOLE_WRITE: usize = 1024 * 1024;
pub const MAX_FILE_WRITE: usize = 16 * 1024 * 1024;
#[derive(Debug, Error)]
#[error("Guest console: {reason} (Win32 {win32})")]
pub struct ConsoleError {
    pub win32: u32,
    pub reason: &'static str,
}
pub type Result<T> = std::result::Result<T, ConsoleError>;
fn error(win32: u32, reason: &'static str) -> ConsoleError {
    ConsoleError { win32, reason }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Input,
    Output,
}
#[derive(Clone, Debug, Serialize)]
pub struct Alias {
    pub handle: u64,
    pub owner: u64,
    pub kind: Kind,
    pub read: bool,
    pub write: bool,
}
#[derive(Clone, Copy, Debug)]
pub struct AliasOptions {
    pub access: u32,
    pub share: u32,
    pub disposition: u32,
    pub security: u64,
    pub flags: u32,
    pub template: u64,
}
#[derive(Clone, Copy, Debug)]
pub enum WriteSource {
    File,
    Ansi,
    Wide,
}
#[derive(Clone, Debug)]
pub struct WritePlan {
    pub descriptor: i32,
    pub bytes: Vec<u8>,
    pub text: String,
    pub encoding: Encoding,
    pub kind: WriteKind,
    pub mode: u32,
    pub units: u32,
}
#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub code_page: u32,
    pub input_mode: u32,
    pub output_mode: u32,
    pub aliases: Vec<Alias>,
    pub retired_aliases: Vec<u64>,
    pub scope: &'static str,
}
#[derive(Clone, Debug)]
pub struct Console {
    code_page: u32,
    input_mode: u32,
    output_mode: u32,
    owners: BTreeSet<u64>,
    aliases: BTreeMap<u64, Alias>,
    retired: BTreeSet<u64>,
    issued: usize,
}
/// VFS must skip this bounded namespace. This checks reserved ranges, not only
/// currently live aliases, so a stale token cannot become a different file.
pub fn reserved_alias(handle: u64) -> bool {
    (ALIAS_FIRST..ALIAS_END).contains(&handle)
}
impl Console {
    pub fn new(code_page: u32) -> Result<Self> {
        if code_page != 437 {
            return Err(error(50, "initial console profile supports CP437 only"));
        }
        Ok(Self {
            code_page,
            input_mode: 0xf7,
            output_mode: 3,
            owners: BTreeSet::new(),
            aliases: BTreeMap::new(),
            retired: BTreeSet::new(),
            issued: 0,
        })
    }
    pub fn add_process(&mut self, owner: u64) -> Result<()> {
        if owner == 0 || self.owners.contains(&owner) {
            return Err(error(87, "invalid or duplicate console process"));
        }
        if self.owners.len() >= 128 {
            return Err(error(8, "console process limit"));
        }
        self.owners.insert(owner);
        Ok(())
    }
    fn owner(&self, owner: u64) -> Result<()> {
        if !self.owners.contains(&owner) {
            Err(error(6, "unknown or retired console process"))
        } else {
            Ok(())
        }
    }
    pub fn claimed(&self, handle: u64) -> bool {
        crt_stdio::CONSOLE_HANDLES.contains(&handle) || reserved_alias(handle)
    }
    pub fn kind(&self, owner: u64, handle: u64, standard: [u64; 3]) -> Result<Option<Kind>> {
        self.owner(owner)?;
        if let Some(alias) = self.aliases.get(&handle) {
            if alias.owner != owner {
                return Err(error(6, "foreign console alias"));
            }
            return Ok(Some(alias.kind));
        }
        if reserved_alias(handle) {
            return Err(error(6, "closed or unissued console alias"));
        }
        for (index, token) in crt_stdio::CONSOLE_HANDLES.into_iter().enumerate() {
            if handle == token {
                return if standard[index] == token {
                    Ok(Some(if index == 0 {
                        Kind::Input
                    } else {
                        Kind::Output
                    }))
                } else {
                    Err(error(6, "retired standard console token after redirection"))
                };
            }
        }
        Ok(None)
    }
    pub fn stream(&self, owner: u64, handle: u64, standard: [u64; 3]) -> Result<i32> {
        if self.kind(owner, handle, standard)? != Some(Kind::Output) {
            return Err(error(6, "not a console output handle"));
        }
        if handle == crt_stdio::CONSOLE_HANDLES[2] {
            Ok(2)
        } else {
            Ok(1)
        }
    }
    pub fn open(&mut self, owner: u64, name: &str, options: AliasOptions) -> Result<u64> {
        self.owner(owner)?;
        let kind = if name.eq_ignore_ascii_case("conin$") {
            Kind::Input
        } else if name.eq_ignore_ascii_case("conout$") {
            Kind::Output
        } else {
            return Err(error(123, "not a console device name"));
        };
        if options.disposition != 3 {
            return Err(error(87, "console aliases require OPEN_EXISTING"));
        }
        if options.security != 0
            || options.template != 0
            || options.flags & !0x80 != 0
            || options.access & !0xd0000000 != 0
            || options.share & !7 != 0
        {
            return Err(error(
                50,
                "console alias security/template/flags/access profile is not modeled",
            ));
        }
        if self.issued >= MAX_ALIASES {
            return Err(error(8, "console alias lifetime limit"));
        }
        let handle = ALIAS_FIRST + self.issued as u64;
        self.issued += 1;
        self.aliases.insert(
            handle,
            Alias {
                handle,
                owner,
                kind,
                read: options.access & 0x90000000 != 0,
                write: options.access & 0x50000000 != 0,
            },
        );
        Ok(handle)
    }
    pub fn close(&mut self, owner: u64, handle: u64) -> Result<()> {
        self.owner(owner)?;
        let alias = self
            .aliases
            .get(&handle)
            .filter(|alias| alias.owner == owner)
            .ok_or_else(|| error(6, "invalid, foreign or closed console alias"))?;
        let handle = alias.handle;
        self.aliases.remove(&handle);
        self.retired.insert(handle);
        Ok(())
    }
    pub fn cleanup_process(&mut self, owner: u64) -> usize {
        let handles: Vec<_> = self
            .aliases
            .values()
            .filter(|a| a.owner == owner)
            .map(|a| a.handle)
            .collect();
        for handle in &handles {
            self.aliases.remove(handle);
            self.retired.insert(*handle);
        }
        self.owners.remove(&owner);
        handles.len()
    }
    pub fn mode(&self, owner: u64, handle: u64, standard: [u64; 3]) -> Result<u32> {
        match self.kind(owner, handle, standard)? {
            Some(Kind::Input) => Ok(self.input_mode),
            Some(Kind::Output) => Ok(self.output_mode),
            None => Err(error(6, "not a console handle")),
        }
    }
    pub fn set_mode(
        &mut self,
        owner: u64,
        handle: u64,
        standard: [u64; 3],
        mode: u32,
    ) -> Result<()> {
        match self.kind(owner, handle, standard)? {
            Some(Kind::Input) => {
                if mode & 4 != 0 && mode & 2 == 0 {
                    return Err(error(87, "console echo requires line input"));
                }
                self.input_mode = mode;
            }
            Some(Kind::Output) => self.output_mode = mode,
            None => return Err(error(6, "not a console handle")),
        };
        Ok(())
    }
    pub fn code_page(&self) -> u32 {
        self.code_page
    }
    pub fn screen(&self, owner: u64, handle: u64, standard: [u64; 3]) -> Result<Vec<u8>> {
        self.stream(owner, handle, standard)?;
        Ok([80i16, 25, 0, 0, 7, 0, 0, 79, 24, 80, 25]
            .into_iter()
            .flat_map(i16::to_le_bytes)
            .collect())
    }
    pub fn write(
        &self,
        owner: u64,
        handle: u64,
        standard: [u64; 3],
        bytes: Vec<u8>,
        source: WriteSource,
    ) -> Result<WritePlan> {
        let descriptor = self.stream(owner, handle, standard)?;
        if self.aliases.get(&handle).is_some_and(|alias| !alias.write) {
            return Err(error(5, "console alias lacks write access"));
        }
        let max = if matches!(source, WriteSource::File) {
            MAX_FILE_WRITE
        } else {
            MAX_CONSOLE_WRITE
        };
        if bytes.len() > max {
            return Err(error(8, "console write exceeds bounded capacity"));
        }
        let (units, text, encoding, kind) = match source {
            WriteSource::Wide => {
                if bytes.len() % 2 != 0 {
                    return Err(error(87, "odd UTF16 console payload"));
                }
                let words: Vec<_> = bytes
                    .chunks_exact(2)
                    .map(|b| u16::from_le_bytes([b[0], b[1]]))
                    .collect();
                (
                    words.len(),
                    String::from_utf16_lossy(&words),
                    Encoding::Utf16LeLossy,
                    WriteKind::WriteConsoleW,
                )
            }
            WriteSource::Ansi => (
                bytes.len(),
                persona::Encoding::Cp437
                    .decode(&bytes)
                    .map_err(|_| error(50, "CP437 decoder failed"))?,
                Encoding::Cp437,
                WriteKind::WriteConsoleA,
            ),
            WriteSource::File => {
                let prefix = bytes.len().min(crt_stdio::MAX_CONSOLE_CHARS + 4);
                (
                    bytes.len(),
                    persona::Encoding::Cp437
                        .decode(&bytes[..prefix])
                        .map_err(|_| error(50, "CP437 decoder failed"))?,
                    Encoding::Cp437,
                    WriteKind::WriteFile,
                )
            }
        };
        Ok(WritePlan {
            descriptor,
            bytes,
            text,
            encoding,
            kind,
            mode: self.output_mode,
            units: units as u32,
        })
    }
    pub fn report(&self) -> Report {
        Report {
            code_page: self.code_page,
            input_mode: self.input_mode,
            output_mode: self.output_mode,
            aliases: self.aliases.values().cloned().collect(),
            retired_aliases: self.retired.iter().copied().collect(),
            scope: "Bounded guest console session, CP437, standard-table classification and process-owned aliases. Modes are bookkeeping; fixed screen geometry does not imply terminal parsing/cursor movement or stdin. UTF16 console text follows explicit legacy replacement while raw bytes remain exact.",
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn state() -> Console {
        let mut c = Console::new(437).unwrap();
        c.add_process(1).unwrap();
        c.add_process(2).unwrap();
        c
    }
    fn options(access: u32) -> AliasOptions {
        AliasOptions {
            access,
            share: 3,
            disposition: 3,
            security: 0,
            flags: 0,
            template: 0,
        }
    }
    #[test]
    fn aliases_are_bounded_owned_retired_and_never_reused() {
        let mut c = state();
        let a = c.open(1, "CONOUT$", options(0xc0000000)).unwrap();
        assert_eq!(a, ALIAS_FIRST);
        assert_eq!(c.kind(1, a, [0; 3]).unwrap(), Some(Kind::Output));
        assert_eq!(c.kind(2, a, [0; 3]).unwrap_err().win32, 6);
        c.close(1, a).unwrap();
        assert!(c.kind(1, a, [0; 3]).is_err());
        assert!(c.close(1, a).is_err());
        for _ in 1..MAX_ALIASES {
            c.open(1, "CONIN$", options(0x80000000)).unwrap();
        }
        assert_eq!(
            c.open(1, "CONOUT$", options(0x40000000)).unwrap_err().win32,
            8
        );
        assert_eq!(c.cleanup_process(1), MAX_ALIASES - 1);
        assert!(c.kind(1, 0xf001, crt_stdio::CONSOLE_HANDLES).is_err());
    }
    #[test]
    fn standard_redirection_modes_and_fixed_geometry_are_explicit() {
        let mut c = state();
        let std = crt_stdio::CONSOLE_HANDLES;
        assert_eq!(c.mode(1, 0xf001, std).unwrap(), 0xf7);
        assert_eq!(c.mode(1, 0xf002, std).unwrap(), 3);
        assert_eq!(c.set_mode(1, 0xf001, std, 4).unwrap_err().win32, 87);
        assert_eq!(c.mode(1, 0xf001, std).unwrap(), 0xf7);
        c.set_mode(1, 0xf003, std, 7).unwrap();
        assert_eq!(c.mode(1, 0xf002, std).unwrap(), 7);
        assert_eq!(c.screen(1, 0xf002, std).unwrap().len(), 22);
        assert!(c.kind(1, 0xf002, [0xf001, 0x100, 0xf003]).is_err());
        assert_eq!(c.kind(1, 0x100, std).unwrap(), None);
    }
    #[test]
    fn write_plans_preserve_raw_cp437_counts_lossy_utf16_and_rights() {
        let mut c = state();
        let std = crt_stdio::CONSOLE_HANDLES;
        let p = c
            .write(1, 0xf002, std, vec![0x82], WriteSource::Ansi)
            .unwrap();
        assert_eq!(p.text, "é");
        assert_eq!(p.units, 1);
        assert_eq!(p.bytes, [0x82]);
        let p = c
            .write(1, 0xf003, std, vec![0, 0xd8, 65, 0], WriteSource::Wide)
            .unwrap();
        assert_eq!(p.text, "�A");
        assert_eq!(p.units, 2);
        assert_eq!(p.descriptor, 2);
        let read = c.open(1, "CONOUT$", options(0x80000000)).unwrap();
        assert_eq!(
            c.write(1, read, std, b"x".to_vec(), WriteSource::File)
                .unwrap_err()
                .win32,
            5
        );
        assert!(c.write(1, 0xf001, std, vec![], WriteSource::File).is_err());
        assert_eq!(
            c.write(
                1,
                0xf002,
                std,
                vec![0; MAX_CONSOLE_WRITE + 1],
                WriteSource::Ansi
            )
            .unwrap_err()
            .win32,
            8
        );
    }
    #[test]
    fn shared_capture_keeps_crt_windows_and_formatted_write_order() {
        let console = state();
        let mut stdio = crt_stdio::Stdio::new(crate::pe::Architecture::X64);
        stdio.add_process(1, crt_stdio::CONSOLE_HANDLES).unwrap();
        stdio.write(1, 1, b"a").unwrap();
        let plan = console
            .write(
                1,
                0xf002,
                crt_stdio::CONSOLE_HANDLES,
                vec![0x82],
                WriteSource::File,
            )
            .unwrap();
        stdio
            .append_console(crt_stdio::ConsoleWrite {
                owner: 1,
                descriptor: plan.descriptor,
                data: &plan.bytes,
                text: &plan.text,
                encoding: plan.encoding,
                mode: plan.mode,
                kind: plan.kind,
            })
            .unwrap();
        stdio.formatted_write(1, 1, "z", true).unwrap();
        let report = stdio.report();
        assert_eq!(report.console.stdout, "aéz");
        assert_eq!(
            report
                .console
                .write_events
                .iter()
                .map(|e| e.raw_offset)
                .collect::<Vec<_>>(),
            [0, 1, 2]
        );
        assert_eq!(
            report
                .console
                .write_events
                .iter()
                .map(|e| e.bytes)
                .collect::<Vec<_>>(),
            [1, 1, 2]
        );
        assert_eq!(report.console.write_events[1].mode, 3);
        assert!(matches!(
            report.console.write_events[1].encoding,
            Encoding::Cp437
        ));
    }
}
