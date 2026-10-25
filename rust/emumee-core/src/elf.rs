//! Checked, read-only ELF metadata parsing. No ELF bytes are executed or mapped.
use crate::pe::{Architecture, MAX_INPUT};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

const MAX_PROGRAM_HEADERS: usize = 128;
const MAX_INTERPRETER: u64 = 4096;
const PT_LOAD: u32 = 1;
const PT_INTERP: u32 = 3;
const PF_X: u32 = 1;

#[derive(Debug, Error)]
#[error("Invalid ELF: {0}")]
pub struct ElfError(pub &'static str);
type Result<T> = std::result::Result<T, ElfError>;

fn bytes(data: &[u8], offset: u64, size: u64) -> Result<&[u8]> {
    let end = offset
        .checked_add(size)
        .ok_or(ElfError("offset overflow"))?;
    let start = usize::try_from(offset).map_err(|_| ElfError("offset overflow"))?;
    let end = usize::try_from(end).map_err(|_| ElfError("offset overflow"))?;
    data.get(start..end).ok_or(ElfError("truncated input"))
}

fn u16_at(data: &[u8], offset: u64) -> Result<u16> {
    Ok(u16::from_le_bytes(
        bytes(data, offset, 2)?.try_into().unwrap(),
    ))
}
fn u32_at(data: &[u8], offset: u64) -> Result<u32> {
    Ok(u32::from_le_bytes(
        bytes(data, offset, 4)?.try_into().unwrap(),
    ))
}
fn u64_at(data: &[u8], offset: u64) -> Result<u64> {
    Ok(u64::from_le_bytes(
        bytes(data, offset, 8)?.try_into().unwrap(),
    ))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Executable,
    Dynamic,
}

#[derive(Clone, Debug, Serialize)]
pub struct SampleInfo {
    pub format: &'static str,
    pub name: String,
    pub sha256: String,
    pub size: usize,
    pub architecture: Architecture,
    pub kind: Kind,
    pub entry: u64,
    pub interpreter: Option<String>,
    pub load_segments: usize,
    pub entry_in_executable_segment: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProgramHeader {
    pub kind: u32,
    pub flags: u32,
    pub offset: u64,
    pub virtual_address: u64,
    pub file_size: u64,
    pub memory_size: u64,
    pub alignment: u64,
}

#[derive(Debug, Serialize)]
pub struct ElfImage {
    pub sample: SampleInfo,
    pub os_abi: u8,
    pub abi_version: u8,
    pub program_headers: Vec<ProgramHeader>,
}

impl ElfImage {
    pub fn parse(data: &[u8], name: &str) -> Result<Self> {
        if data.len() > MAX_INPUT {
            return Err(ElfError("input exceeds 128 MiB"));
        }
        let ident = bytes(data, 0, 16)?;
        if &ident[..4] != b"\x7fELF" {
            return Err(ElfError("missing ELF signature"));
        }
        let (architecture, header_size, program_header_size) = match (ident[4], ident[5]) {
            (1, 1) => (Architecture::X86, 52u64, 32u64),
            (2, 1) => (Architecture::X64, 64u64, 56u64),
            (_, 2) => return Err(ElfError("big-endian ELF is unsupported")),
            _ => return Err(ElfError("unsupported ELF class or byte order")),
        };
        if ident[6] != 1 || (ident[7] != 0 && ident[7] != 3) {
            return Err(ElfError("unsupported ELF identification"));
        }
        bytes(data, 0, header_size)?;
        let kind = match u16_at(data, 16)? {
            2 => Kind::Executable,
            3 => Kind::Dynamic,
            _ => return Err(ElfError("unsupported ELF type")),
        };
        let machine = u16_at(data, 18)?;
        if u32_at(data, 20)? != 1
            || !matches!(
                (architecture, machine),
                (Architecture::X86, 3) | (Architecture::X64, 62)
            )
        {
            return Err(ElfError("unsupported ELF machine or version"));
        }
        let (entry, program_offset, header_size_at, program_size_at, program_count_at) =
            if architecture == Architecture::X64 {
                (u64_at(data, 24)?, u64_at(data, 32)?, 52, 54, 56)
            } else {
                (
                    u32_at(data, 24)? as u64,
                    u32_at(data, 28)? as u64,
                    40,
                    42,
                    44,
                )
            };
        let count = u16_at(data, program_count_at)? as usize;
        if u16_at(data, header_size_at)? as u64 != header_size
            || u16_at(data, program_size_at)? as u64 != program_header_size
            || !(1..=MAX_PROGRAM_HEADERS).contains(&count)
            || program_offset == 0
        {
            return Err(ElfError("unsupported ELF program header table"));
        }
        let table_size = (count as u64)
            .checked_mul(program_header_size)
            .ok_or(ElfError("program header size overflow"))?;
        bytes(data, program_offset, table_size)?;

        let mut program_headers = Vec::with_capacity(count);
        let mut interpreter = None;
        let mut load_segments = 0;
        let mut entry_in_executable_segment = false;
        for index in 0..count {
            let at = program_offset + index as u64 * program_header_size;
            let header = if architecture == Architecture::X64 {
                ProgramHeader {
                    kind: u32_at(data, at)?,
                    flags: u32_at(data, at + 4)?,
                    offset: u64_at(data, at + 8)?,
                    virtual_address: u64_at(data, at + 16)?,
                    file_size: u64_at(data, at + 32)?,
                    memory_size: u64_at(data, at + 40)?,
                    alignment: u64_at(data, at + 48)?,
                }
            } else {
                ProgramHeader {
                    kind: u32_at(data, at)?,
                    flags: u32_at(data, at + 24)?,
                    offset: u32_at(data, at + 4)? as u64,
                    virtual_address: u32_at(data, at + 8)? as u64,
                    file_size: u32_at(data, at + 16)? as u64,
                    memory_size: u32_at(data, at + 20)? as u64,
                    alignment: u32_at(data, at + 28)? as u64,
                }
            };
            if header.kind != 0 && header.file_size != 0 {
                bytes(data, header.offset, header.file_size)?;
            }
            if header.kind == PT_LOAD {
                if header.file_size > header.memory_size
                    || header
                        .virtual_address
                        .checked_add(header.memory_size)
                        .is_none()
                    || header.alignment > 1
                        && (!header.alignment.is_power_of_two()
                            || header.offset % header.alignment
                                != header.virtual_address % header.alignment)
                {
                    return Err(ElfError("invalid load segment"));
                }
                load_segments += 1;
                entry_in_executable_segment |= header.flags & PF_X != 0
                    && entry >= header.virtual_address
                    && entry - header.virtual_address < header.memory_size;
            } else if header.kind == PT_INTERP {
                if interpreter.is_some() || !(2..=MAX_INTERPRETER).contains(&header.file_size) {
                    return Err(ElfError("invalid interpreter segment"));
                }
                let path = bytes(data, header.offset, header.file_size)?;
                if path.last() != Some(&0) || path[..path.len() - 1].contains(&0) {
                    return Err(ElfError("invalid interpreter path"));
                }
                let path = std::str::from_utf8(&path[..path.len() - 1])
                    .map_err(|_| ElfError("interpreter path is not UTF-8"))?;
                interpreter = Some(path.to_owned());
            }
            program_headers.push(header);
        }
        if load_segments == 0 {
            return Err(ElfError("no load segments"));
        }
        Ok(Self {
            sample: SampleInfo {
                format: "elf",
                name: name.to_owned(),
                sha256: format!("{:x}", Sha256::digest(data)),
                size: data.len(),
                architecture,
                kind,
                entry,
                interpreter,
                load_segments,
                entry_in_executable_segment,
            },
            os_abi: ident[7],
            abi_version: ident[8],
            program_headers,
        })
    }
}

#[cfg(test)]
mod tests;
