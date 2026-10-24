//! Bounded legacy CRT standard streams. Guest FILE/errno backing is supplied by
//! the engine; all handles below identify guest objects, never host CRT objects.
//! Formatting is a separate bounded model; locale, arbitrary file descriptors
//! and full CRT compatibility are not implied. Unsupported profiles stop.
use crate::pe::Architecture;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use thiserror::Error;

pub const O_TEXT: u32 = 0x4000;
pub const O_BINARY: u32 = 0x8000;
pub const O_WTEXT: u32 = 0x10000;
pub const O_U16TEXT: u32 = 0x20000;
pub const O_U8TEXT: u32 = 0x40000;
pub const MAX_WRITE: usize = 131072;
pub const MAX_CONSOLE_CHARS: usize = 128 * 1024;
pub const MAX_RAW: usize = 1024 * 1024;
pub const MAX_EVENTS: usize = 1024;
pub const MAX_PROCESSES: usize = 128;
pub const MAX_BACKINGS: usize = 4096;
pub const CONSOLE_HANDLES: [u64; 3] = [0xf001, 0xf002, 0xf003];
#[derive(Debug, Error)]
pub enum StdioError {
    #[error("CRT stdio profile unsupported: {0}")]
    Unsupported(&'static str),
    #[error("CRT stdio owned backing invalid: {0}")]
    Invalid(&'static str),
    #[error("CRT stdio resource limit")]
    Limit,
}
pub type Result<T> = std::result::Result<T, StdioError>;
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum BackingKind {
    LegacyIob,
    UcrtIob,
    Errno(u64),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Backing {
    pub owner: u64,
    pub kind: BackingKind,
    pub address: u64,
    pub size: u64,
}
#[derive(Debug)]
pub enum Request {
    Existing(u64),
    Allocate { image: Vec<u8>, size: u64 },
}
#[derive(Clone, Debug)]
struct Process {
    handles: [u64; 3],
    modes: [u32; 3],
}
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Encoding {
    Ascii,
    Utf16Le,
    Utf8,
    Cp437,
    Utf16LeLossy,
}
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WriteKind {
    Descriptor,
    FormattedNarrow,
    FormattedWide,
    WriteFile,
    WriteConsoleA,
    WriteConsoleW,
}
/// Validated guest output passed to the single bounded capture accumulator.
/// Fields retain origin/descriptor mode independently of byte encoding.
pub struct ConsoleWrite<'a> {
    pub owner: u64,
    pub descriptor: i32,
    pub data: &'a [u8],
    pub text: &'a str,
    pub encoding: Encoding,
    pub mode: u32,
    pub kind: WriteKind,
}
#[derive(Clone, Debug, Serialize)]
pub struct WriteEvent {
    pub kind: WriteKind,
    pub owner: u64,
    pub descriptor: u32,
    pub mode: u32,
    pub encoding: Encoding,
    pub bytes: usize,
    pub sha256: String,
    pub raw_offset: usize,
    pub retained_bytes: usize,
}
#[derive(Clone, Debug, Default)]
struct Console {
    stdout: String,
    stderr: String,
    stdout_chars: usize,
    stderr_chars: usize,
    stdout_truncated: bool,
    stderr_truncated: bool,
    raw: Vec<u8>,
    omitted_raw_bytes: u64,
    events: Vec<WriteEvent>,
    omitted_events: u64,
}
#[derive(Clone, Debug, Serialize)]
pub struct ConsoleReport {
    pub stdout: String,
    pub stderr: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub raw_base64: String,
    pub raw_bytes: usize,
    pub omitted_raw_bytes: u64,
    pub write_events: Vec<WriteEvent>,
    pub omitted_events: u64,
    pub scope: &'static str,
}
#[derive(Clone, Debug, Serialize)]
pub struct ProcessReport {
    pub owner: u64,
    pub standard_guest_handles: [u64; 3],
    pub modes: [u32; 3],
}
#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub console: ConsoleReport,
    pub processes: Vec<ProcessReport>,
    pub backings: Vec<Backing>,
    pub scope: &'static str,
}
#[derive(Clone, Debug, Serialize)]
pub struct StateReport {
    pub processes: Vec<ProcessReport>,
    pub backings: Vec<Backing>,
    pub scope: &'static str,
}
#[derive(Clone, Debug)]
pub struct Stdio {
    architecture: Architecture,
    processes: BTreeMap<u64, Process>,
    backings: BTreeMap<(u64, BackingKind), Backing>,
    console: Console,
}
/// Public legacy _iobuf layout used by the Python bridge, not UCRT's opaque FILE.
pub fn legacy_layout(architecture: Architecture) -> (usize, usize, usize) {
    if architecture == Architecture::X64 {
        (48, 24, 28)
    } else {
        (32, 12, 16)
    }
}
pub fn legacy_iob_image(architecture: Architecture) -> Vec<u8> {
    let (stride, flag, file) = legacy_layout(architecture);
    let mut image = vec![0; stride * 20];
    for descriptor in 0..3usize {
        image[descriptor * stride + flag..descriptor * stride + flag + 4]
            .copy_from_slice(&(if descriptor == 0 { 1u32 } else { 2 }).to_le_bytes());
        image[descriptor * stride + file..descriptor * stride + file + 4]
            .copy_from_slice(&(descriptor as u32).to_le_bytes());
    }
    image
}
impl Stdio {
    pub fn new(architecture: Architecture) -> Self {
        Self {
            architecture,
            processes: BTreeMap::new(),
            backings: BTreeMap::new(),
            console: Console::default(),
        }
    }
    pub fn add_process(&mut self, owner: u64, standard_guest_handles: [u64; 3]) -> Result<()> {
        if owner == 0 || self.processes.contains_key(&owner) {
            return Err(StdioError::Invalid("invalid/duplicate process owner"));
        }
        if self.processes.len() >= MAX_PROCESSES {
            return Err(StdioError::Limit);
        }
        if self.architecture == Architecture::X86
            && standard_guest_handles
                .iter()
                .any(|handle| *handle > u32::MAX as u64)
        {
            return Err(StdioError::Invalid(
                "guest handle exceeds architecture width",
            ));
        }
        self.processes.insert(
            owner,
            Process {
                handles: standard_guest_handles,
                modes: [O_TEXT; 3],
            },
        );
        Ok(())
    }
    fn process(&self, owner: u64) -> Result<&Process> {
        self.processes
            .get(&owner)
            .ok_or(StdioError::Invalid("unknown/retired process owner"))
    }
    pub fn standard_handles(&self, owner: u64) -> Result<[u64; 3]> {
        Ok(self.process(owner)?.handles)
    }
    /// Windows standard-table mutation validates selector/guest width, not the
    /// target object. I/O subsequently validates alias/console/VFS ownership.
    pub fn set_standard_handle(&mut self, owner: u64, index: usize, handle: u64) -> Result<()> {
        if index > 2 || (self.architecture == Architecture::X86 && handle > u32::MAX as u64) {
            return Err(StdioError::Invalid(
                "invalid standard selector/guest handle width",
            ));
        }
        self.processes
            .get_mut(&owner)
            .ok_or(StdioError::Invalid("unknown/retired process owner"))?
            .handles[index] = handle;
        Ok(())
    }
    pub fn backing(&self, owner: u64, kind: BackingKind) -> Result<Request> {
        self.process(owner)?;
        if let Some(backing) = self.backings.get(&(owner, kind)) {
            return Ok(Request::Existing(backing.address));
        }
        if self.backings.len() >= MAX_BACKINGS {
            return Err(StdioError::Limit);
        }
        if matches!(kind, BackingKind::Errno(0)) {
            return Err(StdioError::Invalid("zero guest thread identity"));
        }
        let image = match kind {
            BackingKind::LegacyIob => legacy_iob_image(self.architecture),
            BackingKind::UcrtIob => vec![0; 3 * 0x80],
            BackingKind::Errno(_) => vec![0; 4],
        };
        Ok(Request::Allocate { image, size: 4096 })
    }
    /// Engine commits this metadata only after real guest allocation/write.
    pub fn register_backing(
        &mut self,
        owner: u64,
        kind: BackingKind,
        address: u64,
        size: u64,
    ) -> Result<()> {
        self.process(owner)?;
        if !matches!(self.backing(owner, kind)?, Request::Allocate { .. }) {
            return Err(StdioError::Invalid("backing already registered"));
        }
        if address == 0
            || address % 4096 != 0
            || size != 4096
            || address.checked_add(size).is_none()
            || (self.architecture == Architecture::X86 && address + size > 1u64 << 32)
        {
            return Err(StdioError::Invalid(
                "backing does not match owned guest page",
            ));
        }
        if self.backings.values().any(|backing| {
            backing.owner == owner
                && address < backing.address + backing.size
                && backing.address < address + size
        }) {
            return Err(StdioError::Invalid("owned CRT backing pages overlap"));
        }
        self.backings.insert(
            (owner, kind),
            Backing {
                owner,
                kind,
                address,
                size,
            },
        );
        Ok(())
    }
    pub fn owned_overlap(&self, owner: u64, address: u64, size: u64) -> Result<bool> {
        let end = address
            .checked_add(size.max(1))
            .ok_or(StdioError::Invalid("allocation range overflow"))?;
        Ok(self.backings.values().any(|backing| {
            backing.owner == owner
                && address < backing.address + backing.size
                && backing.address < end
        }))
    }
    pub fn cleanup_process(&mut self, owner: u64) -> Vec<Backing> {
        self.processes.remove(&owner);
        let backings = self
            .backings
            .values()
            .filter(|backing| backing.owner == owner)
            .copied()
            .collect();
        self.backings
            .retain(|(candidate, _), _| *candidate != owner);
        backings
    }
    fn standard_index(&self, owner: u64, stream: u64) -> Option<i32> {
        if !self.processes.contains_key(&owner) {
            return None;
        }
        for (kind, stride) in [
            (
                BackingKind::LegacyIob,
                legacy_layout(self.architecture).0 as u64,
            ),
            (BackingKind::UcrtIob, 0x80),
        ] {
            if let Some(backing) = self.backings.get(&(owner, kind)) {
                for descriptor in 0..3u64 {
                    if stream == backing.address + descriptor * stride {
                        return Some(descriptor as i32);
                    }
                }
            }
        }
        None
    }
    pub fn fileno(&self, owner: u64, stream: u64) -> Result<i32> {
        if stream == 0 || !self.processes.contains_key(&owner) {
            return Ok(-1);
        }
        self.standard_index(owner, stream)
            .ok_or(StdioError::Unsupported(
                "nonstandard, foreign or retired FILE pointer",
            ))
    }
    pub fn fflush(&self, owner: u64, stream: u64) -> Result<i32> {
        if stream == 0 || self.standard_index(owner, stream).is_some() {
            Ok(0)
        } else {
            Err(StdioError::Unsupported(
                "nonstandard FILE flush; standard streams are unbuffered",
            ))
        }
    }
    pub fn setmode(&mut self, owner: u64, descriptor: i32, mode: u32) -> Result<u32> {
        if !(0..=2).contains(&descriptor)
            || !matches!(mode, O_TEXT | O_BINARY | O_WTEXT | O_U16TEXT | O_U8TEXT)
        {
            return Err(StdioError::Unsupported(
                "descriptor or text mode is not modeled",
            ));
        }
        let process = self
            .processes
            .get_mut(&owner)
            .ok_or(StdioError::Invalid("unknown/retired process owner"))?;
        let previous = process.modes[descriptor as usize];
        process.modes[descriptor as usize] = mode;
        Ok(previous)
    }
    pub fn isatty(&self, owner: u64, descriptor: i32) -> i32 {
        if !(0..=2).contains(&descriptor) {
            return 0;
        }
        self.processes.get(&owner).map_or(0, |process| {
            i32::from(process.handles[descriptor as usize] == CONSOLE_HANDLES[descriptor as usize])
        })
    }
    pub fn os_handle(&self, owner: u64, descriptor: i32) -> Result<u64> {
        if !(0..=2).contains(&descriptor) {
            return Err(StdioError::Unsupported("nonstandard CRT descriptor handle"));
        }
        Ok(self.process(owner)?.handles[descriptor as usize])
    }
    /// Preflight before engine reads a guest buffer. No input bytes are read
    /// for zero-length writes; redirected descriptors require a future VFS lane.
    pub fn validate_write(&self, owner: u64, descriptor: i32, count: usize) -> Result<()> {
        let process = self.process(owner)?;
        if !matches!(descriptor, 1 | 2) || count > MAX_WRITE {
            return Err(StdioError::Unsupported(
                "write descriptor or byte count is not modeled",
            ));
        }
        if process.handles[descriptor as usize] != CONSOLE_HANDLES[descriptor as usize] {
            return Err(StdioError::Unsupported(
                "redirected CRT writes require guest VFS binding",
            ));
        }
        Ok(())
    }
    pub fn write(&mut self, owner: u64, descriptor: i32, data: &[u8]) -> Result<u32> {
        self.validate_write(owner, descriptor, data.len())?;
        if data.is_empty() {
            return Ok(0);
        }
        let mode = self.process(owner)?.modes[descriptor as usize];
        let (encoding, text) = match mode {
            O_U16TEXT => {
                if data.len() % 2 != 0 {
                    return Err(StdioError::Unsupported("odd UTF16 CRT write byte count"));
                }
                let units: Vec<_> = data
                    .chunks_exact(2)
                    .map(|part| u16::from_le_bytes([part[0], part[1]]))
                    .collect();
                (
                    Encoding::Utf16Le,
                    String::from_utf16(&units)
                        .map_err(|_| StdioError::Unsupported("malformed UTF16 CRT write"))?,
                )
            }
            O_U8TEXT => (
                Encoding::Utf8,
                std::str::from_utf8(data)
                    .map_err(|_| StdioError::Unsupported("malformed UTF8 CRT write"))?
                    .to_owned(),
            ),
            // Legacy bridge intentionally decodes these three modes as ASCII.
            // This does not claim Windows binary/OEM/WTEXT conversion parity.
            O_TEXT | O_BINARY | O_WTEXT => {
                if !data.is_ascii() {
                    return Err(StdioError::Unsupported(
                        "ANSI/OEM non-ASCII CRT write encoding is not modeled",
                    ));
                }
                (Encoding::Ascii, String::from_utf8(data.to_vec()).unwrap())
            }
            _ => return Err(StdioError::Invalid("unrecognized stored stream mode")),
        };
        self.append_console(ConsoleWrite {
            owner,
            descriptor,
            data,
            text: &text,
            encoding,
            mode,
            kind: WriteKind::Descriptor,
        })
    }
    /// Formatting bypasses descriptor text modes in the legacy bridge. Capture
    /// the rendered bytes with an explicit origin instead of temporarily
    /// changing process modes or pretending formatted text came from _write.
    pub fn formatted_write(
        &mut self,
        owner: u64,
        descriptor: i32,
        text: &str,
        wide: bool,
    ) -> Result<u32> {
        self.validate_write(owner, descriptor, 0)?;
        if text.chars().count() > 65536 {
            return Err(StdioError::Unsupported("formatted output exceeds limit"));
        }
        if !wide && !text.is_ascii() {
            return Err(StdioError::Unsupported(
                "narrow formatted console requires ASCII",
            ));
        }
        let (bytes, encoding, kind) = if wide {
            (
                text.encode_utf16()
                    .flat_map(u16::to_le_bytes)
                    .collect::<Vec<_>>(),
                Encoding::Utf16Le,
                WriteKind::FormattedWide,
            )
        } else {
            (
                text.as_bytes().to_vec(),
                Encoding::Ascii,
                WriteKind::FormattedNarrow,
            )
        };
        let mode = self.process(owner)?.modes[descriptor as usize];
        self.append_console(ConsoleWrite {
            owner,
            descriptor,
            data: &bytes,
            text,
            encoding,
            mode,
            kind,
        })
    }
    /// One bounded raw/text accumulator shared by CRT and Windows console APIs.
    /// Callers classify their own guest handles before passing a descriptor;
    /// aliases can still reach the console when standard output is redirected.
    pub fn append_console(&mut self, input: ConsoleWrite<'_>) -> Result<u32> {
        self.process(input.owner)?;
        if !matches!(input.descriptor, 1 | 2)
            || input.data.len() > 16 * 1024 * 1024
            || input.text.chars().count() > 1024 * 1024
        {
            return Err(StdioError::Unsupported(
                "console capture input exceeds bounded descriptor/data/text profile",
            ));
        }
        let ConsoleWrite {
            owner,
            descriptor,
            data,
            text,
            encoding,
            mode,
            kind,
        } = input;
        if data.is_empty() {
            return Ok(0);
        }
        let console = &mut self.console;
        let (target, chars, truncated) = if descriptor == 1 {
            (
                &mut console.stdout,
                &mut console.stdout_chars,
                &mut console.stdout_truncated,
            )
        } else {
            (
                &mut console.stderr,
                &mut console.stderr_chars,
                &mut console.stderr_truncated,
            )
        };
        let remaining = MAX_CONSOLE_CHARS - *chars;
        let text_chars = text.chars().count();
        target.extend(text.chars().take(remaining));
        *chars += text_chars.min(remaining);
        *truncated |= text_chars > remaining;
        let retained = data.len().min(MAX_RAW - console.raw.len());
        let offset = console.raw.len();
        console.raw.extend_from_slice(&data[..retained]);
        console.omitted_raw_bytes += (data.len() - retained) as u64;
        if console.events.len() < MAX_EVENTS {
            console.events.push(WriteEvent {
                kind,
                owner,
                descriptor: descriptor as u32,
                mode,
                encoding,
                bytes: data.len(),
                sha256: format!("{:x}", Sha256::digest(data)),
                raw_offset: offset,
                retained_bytes: retained,
            });
        } else {
            console.omitted_events += 1;
        }
        Ok(data.len() as u32)
    }
    pub fn report(&self) -> Report {
        Report {
            console: ConsoleReport {
                stdout: self.console.stdout.clone(),
                stderr: self.console.stderr.clone(),
                stdout_truncated: self.console.stdout_truncated,
                stderr_truncated: self.console.stderr_truncated,
                raw_base64: STANDARD.encode(&self.console.raw),
                raw_bytes: self.console.raw.len(),
                omitted_raw_bytes: self.console.omitted_raw_bytes,
                write_events: self.console.events.clone(),
                omitted_events: self.console.omitted_events,
                scope: "Guest console text plus bounded exact raw write prefixes and origin/encoding/mode/hash provenance. No host stdio, newline translation or printf fallback. UTF16 replacement is explicit only for Windows console events.",
            },
            processes: self
                .processes
                .iter()
                .map(|(owner, process)| ProcessReport {
                    owner: *owner,
                    standard_guest_handles: process.handles,
                    modes: process.modes,
                })
                .collect(),
            backings: self.backings.values().copied().collect(),
            scope: "Legacy msvcrt FILE array, opaque UCRT standard tokens, standard descriptors, per-thread errno backing and bounded console writes. Bounded formatting is reported by its explicit origin; locale/numeric CRT APIs and redirected VFS writes remain separate migration work.",
        }
    }
    /// Metadata without duplicating potentially large console text/raw payloads.
    pub fn state_report(&self) -> StateReport {
        StateReport {
            processes: self
                .processes
                .iter()
                .map(|(owner, process)| ProcessReport {
                    owner: *owner,
                    standard_guest_handles: process.handles,
                    modes: process.modes,
                })
                .collect(),
            backings: self.backings.values().copied().collect(),
            scope: "Guest-owned CRT metadata only. Console tokens are guest-only and the Windows console model validates handle/alias ownership separately. No arbitrary FILE streams; formatted events come from the separate bounded grammar.",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn state(arch: Architecture) -> Stdio {
        let mut state = Stdio::new(arch);
        state.add_process(1, CONSOLE_HANDLES).unwrap();
        state
    }
    #[test]
    fn legacy_layout_and_independent_ucrt_slots_match_observable_guest_bytes() {
        for arch in [Architecture::X86, Architecture::X64] {
            let image = legacy_iob_image(arch);
            let (stride, flag, file) = legacy_layout(arch);
            assert_eq!(image.len(), stride * 20);
            for descriptor in 0..3 {
                assert_eq!(
                    &image[descriptor * stride + flag..descriptor * stride + flag + 4],
                    &(if descriptor == 0 { 1u32 } else { 2 }).to_le_bytes()
                );
                assert_eq!(
                    &image[descriptor * stride + file..descriptor * stride + file + 4],
                    &(descriptor as u32).to_le_bytes()
                );
            }
            assert!(image[stride * 3..].iter().all(|byte| *byte == 0));
            let mut state = state(arch);
            state
                .register_backing(1, BackingKind::LegacyIob, 0x2000, 4096)
                .unwrap();
            state
                .register_backing(1, BackingKind::UcrtIob, 0x3000, 4096)
                .unwrap();
            for descriptor in 0..3 {
                assert_eq!(
                    state
                        .fileno(1, 0x2000 + descriptor * stride as u64)
                        .unwrap(),
                    descriptor as i32
                );
                assert_eq!(
                    state.fileno(1, 0x3000 + descriptor * 0x80).unwrap(),
                    descriptor as i32
                );
            }
            assert_eq!(state.fileno(1, 0).unwrap(), -1);
            assert_eq!(state.fflush(1, 0).unwrap(), 0);
            assert!(state.fileno(1, 0x2001).is_err());
            assert!(state.fflush(1, 0x2001).is_err());
        }
    }
    #[test]
    fn backing_identity_process_thread_and_cleanup_are_isolated() {
        let mut state = state(Architecture::X64);
        state.add_process(2, CONSOLE_HANDLES).unwrap();
        for (owner, kind, address) in [
            (1, BackingKind::Errno(1), 0x1000),
            (1, BackingKind::Errno(2), 0x2000),
            (2, BackingKind::Errno(1), 0x3000),
        ] {
            assert!(matches!(
                state.backing(owner, kind).unwrap(),
                Request::Allocate { .. }
            ));
            state.register_backing(owner, kind, address, 4096).unwrap();
            assert!(
                matches!(state.backing(owner, kind).unwrap(), Request::Existing(at) if at==address)
            );
        }
        assert_eq!(state.cleanup_process(1).len(), 2);
        assert!(state.backing(1, BackingKind::Errno(1)).is_err());
        assert!(matches!(
            state.backing(2, BackingKind::Errno(1)).unwrap(),
            Request::Existing(0x3000)
        ));
        assert!(state.owned_overlap(2, 0x3000, 0).unwrap());
        assert!(!state.owned_overlap(2, 0x4000, 1).unwrap());
        assert!(state.owned_overlap(2, u64::MAX, 2).is_err());
    }
    #[test]
    fn descriptor_modes_and_guest_handles_never_become_host_handles() {
        let mut state = state(Architecture::X64);
        state.add_process(2, [0xf001, 0xf002, 0xbeef]).unwrap();
        assert_eq!(state.setmode(1, 1, O_U16TEXT).unwrap(), O_TEXT);
        assert_eq!(state.setmode(1, 1, O_U8TEXT).unwrap(), O_U16TEXT);
        assert_eq!(state.setmode(2, 1, O_BINARY).unwrap(), O_TEXT);
        assert_eq!(state.os_handle(2, 2).unwrap(), 0xbeef);
        assert_eq!(state.isatty(2, 2), 0);
        assert_eq!(state.isatty(2, 1), 1);
        assert_eq!(state.isatty(1, -1), 0);
        assert!(state.os_handle(1, 9).is_err());
        assert!(state.setmode(1, 1, 7).is_err());
        assert_eq!(state.setmode(1, 1, O_TEXT).unwrap(), O_U8TEXT);
    }
    #[test]
    fn writes_capture_exact_bytes_with_strict_encoding_and_no_newline_translation() {
        let mut state = state(Architecture::X64);
        assert_eq!(state.write(1, 1, b"a\n\0").unwrap(), 3);
        assert!(state.write(1, 1, &[0x80]).is_err());
        state.setmode(1, 2, O_U16TEXT).unwrap();
        let wide: Vec<_> = "é😀".encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert_eq!(state.write(1, 2, &wide).unwrap(), 6);
        assert!(state.write(1, 2, &[0]).is_err());
        assert!(state.write(1, 2, &[0, 0xd8]).is_err());
        state.setmode(1, 1, O_U8TEXT).unwrap();
        assert_eq!(state.write(1, 1, "é".as_bytes()).unwrap(), 2);
        assert!(state.write(1, 1, &[0xff]).is_err());
        let report = state.report();
        assert_eq!(report.console.stdout, "a\n\0é");
        assert_eq!(report.console.stderr, "é😀");
        assert_eq!(report.console.write_events.len(), 3);
        let expected = [b"a\n\0".as_slice(), &wide, "é".as_bytes()].concat();
        assert_eq!(
            STANDARD.decode(report.console.raw_base64).unwrap(),
            expected
        );
    }
    #[test]
    fn capture_limits_do_not_change_successful_write_counts_or_hide_omissions() {
        let mut state = state(Architecture::X86);
        let data = vec![b'x'; MAX_WRITE];
        for _ in 0..9 {
            assert_eq!(state.write(1, 1, &data).unwrap(), MAX_WRITE as u32);
        }
        let report = state.report();
        assert_eq!(report.console.stdout.len(), MAX_CONSOLE_CHARS);
        assert!(report.console.stdout_truncated);
        assert_eq!(report.console.raw_bytes, MAX_RAW);
        assert_eq!(report.console.omitted_raw_bytes, MAX_WRITE as u64);
        assert!(state.write(1, 1, &vec![0; MAX_WRITE + 1]).is_err());
        let before = state.report().console.write_events.len();
        assert_eq!(state.write(1, 1, b"").unwrap(), 0);
        assert_eq!(state.report().console.write_events.len(), before);
    }
}
