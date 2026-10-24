//! Checked PE parsing. Guest bytes are data and are never mapped as host code.
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;
mod exports;
mod tls;
pub use exports::{Export, ExportTarget};
pub use tls::{MAX_TLS_CALLBACKS, TlsCallbackPlan, TlsError, TlsMirrorCheck};

pub const MAX_INPUT: usize = 128 * 1024 * 1024;
pub const MAX_IMAGE: u32 = 512 * 1024 * 1024;

#[derive(Debug, Error)]
#[error("Invalid PE: {0}")]
pub struct PeError(pub &'static str);
type Result<T> = std::result::Result<T, PeError>;

fn bytes(data: &[u8], at: usize, size: usize) -> Result<&[u8]> {
    data.get(at..at.checked_add(size).ok_or(PeError("offset overflow"))?)
        .ok_or(PeError("truncated input"))
}
fn u16_at(data: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(bytes(data, at, 2)?.try_into().unwrap()))
}
fn u32_at(data: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(bytes(data, at, 4)?.try_into().unwrap()))
}
fn u64_at(data: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(bytes(data, at, 8)?.try_into().unwrap()))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Architecture {
    X86,
    X64,
}
impl Architecture {
    pub fn width(self) -> usize {
        if self == Self::X64 { 8 } else { 4 }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Driver,
    Dll,
    Exe,
}
#[derive(Clone, Debug, Serialize)]
pub struct SampleInfo {
    pub name: String,
    pub sha256: String,
    pub size: usize,
    pub architecture: Architecture,
    pub kind: Kind,
    pub managed: bool,
    pub subsystem: u16,
    pub imports: Vec<String>,
}
#[derive(Clone, Debug, Serialize)]
pub struct Section {
    pub name: String,
    pub rva: u32,
    pub virtual_size: u32,
    pub raw_offset: u32,
    pub raw_size: u32,
    pub characteristics: u32,
}
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct Directory {
    pub rva: u32,
    pub size: u32,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum ImportName {
    Name(String),
    Ordinal { ordinal: u16 },
}
#[derive(Clone, Debug, Serialize)]
pub struct Import {
    pub module: String,
    pub name: ImportName,
    pub iat_rva: u32,
}
#[derive(Clone, Copy, Debug, Serialize)]
pub struct AcceptedHeaders {
    pub timestamp: u32,
    pub checksum: u32,
    pub preferred_base: u64,
}
#[derive(Debug, Serialize)]
pub struct PeImage {
    accepted_headers: AcceptedHeaders,
    pub sample: SampleInfo,
    pub characteristics: u16,
    pub image_base: u64,
    pub image_size: u32,
    pub headers_size: u32,
    pub entry_rva: u32,
    pub sections: Vec<Section>,
    pub directories: [Directory; 16],
    pub imports: Vec<Import>,
    pub exports: Vec<Export>,
}

impl PeImage {
    pub fn accepted_headers(&self) -> AcceptedHeaders {
        self.accepted_headers
    }
    pub fn parse(data: &[u8], name: &str) -> Result<Self> {
        if data.len() > MAX_INPUT {
            return Err(PeError("input exceeds 128 MiB"));
        }
        if bytes(data, 0, 2)? != b"MZ" {
            return Err(PeError("missing DOS signature"));
        }
        let at = u32_at(data, 0x3c)? as usize;
        if at > 1024 * 1024 || bytes(data, at, 4)? != b"PE\0\0" {
            return Err(PeError("invalid PE signature/header offset"));
        }
        let architecture = match u16_at(data, at + 4)? {
            0x14c => Architecture::X86,
            0x8664 => Architecture::X64,
            _ => return Err(PeError("unsupported machine")),
        };
        let count = u16_at(data, at + 6)? as usize;
        if !(1..=96).contains(&count) {
            return Err(PeError("section count exceeds bound"));
        }
        let opt_size = u16_at(data, at + 20)? as usize;
        let flags = u16_at(data, at + 22)?;
        let opt = bytes(data, at + 24, opt_size)?;
        let (magic, dd) = if architecture == Architecture::X64 {
            (0x20b, 112)
        } else {
            (0x10b, 96)
        };
        if opt_size < dd || u16_at(opt, 0)? != magic {
            return Err(PeError("optional header mismatch"));
        }
        let entry_rva = u32_at(opt, 16)?;
        let image_base = if architecture == Architecture::X64 {
            u64_at(opt, 24)?
        } else {
            u32_at(opt, 28)? as u64
        };
        let image_size = u32_at(opt, 56)?;
        let headers_size = u32_at(opt, 60)?;
        if image_size == 0
            || image_size > MAX_IMAGE
            || image_size & 4095 != 0
            || headers_size == 0
            || headers_size > image_size
            || headers_size as usize > data.len()
            || entry_rva >= image_size
        {
            return Err(PeError("invalid image/header/entry bounds"));
        }
        let section_alignment = u32_at(opt, 32)?;
        let file_alignment = u32_at(opt, 36)?;
        if section_alignment < 4096
            || !section_alignment.is_power_of_two()
            || !(512..=65536).contains(&file_alignment)
            || !file_alignment.is_power_of_two()
            || file_alignment > section_alignment
        {
            return Err(PeError("unsupported PE alignment"));
        }
        let subsystem = u16_at(opt, 68)?;
        if name.to_ascii_lowercase().ends_with(".sys") && subsystem != 1 {
            return Err(PeError("driver requires native subsystem"));
        }
        let kind = if subsystem == 1 {
            Kind::Driver
        } else if flags & 0x2000 != 0 {
            Kind::Dll
        } else {
            Kind::Exe
        };
        if kind == Kind::Driver && entry_rva == 0 {
            return Err(PeError("driver has no entry"));
        }
        let mut directories = [Directory::default(); 16];
        let dirs = (u32_at(opt, dd - 4)? as usize).min(16);
        for (index, directory) in directories.iter_mut().enumerate().take(dirs) {
            *directory = Directory {
                rva: u32_at(opt, dd + index * 8)?,
                size: u32_at(opt, dd + index * 8 + 4)?,
            };
            // The security directory uses a file offset; every other directory uses RVAs.
            if directory.rva == 0 && directory.size != 0 {
                return Err(PeError("directory has no address"));
            }
            let limit = if index == 4 {
                data.len() as u64
            } else {
                image_size as u64
            };
            if directory.rva as u64 + directory.size as u64 > limit {
                return Err(PeError("directory exceeds image/file"));
            }
        }
        let managed = directories[14].rva != 0 && directories[14].size != 0;
        if managed && kind == Kind::Driver {
            return Err(PeError("managed drivers unsupported"));
        }
        let table = at + 24 + opt_size;
        if table + count * 40 > headers_size as usize {
            return Err(PeError("section table exceeds headers"));
        }
        let mut sections: Vec<Section> = Vec::with_capacity(count);
        for index in 0..count {
            let row = bytes(data, table + index * 40, 40)?;
            let section = Section {
                name: String::from_utf8_lossy(&row[..8])
                    .trim_end_matches('\0')
                    .to_owned(),
                virtual_size: u32_at(row, 8)?,
                rva: u32_at(row, 12)?,
                raw_size: u32_at(row, 16)?,
                raw_offset: u32_at(row, 20)?,
                characteristics: u32_at(row, 36)?,
            };
            let end = section.rva as u64 + section.virtual_size.max(section.raw_size) as u64;
            if section.rva < headers_size
                || section.rva % section_alignment != 0
                || end > image_size as u64
            {
                return Err(PeError("invalid section virtual bounds"));
            }
            if section.raw_size != 0 {
                bytes(data, section.raw_offset as usize, section.raw_size as usize)?;
            }
            if sections.iter().any(|s| {
                (section.rva as u64) < s.rva as u64 + s.virtual_size.max(s.raw_size) as u64
                    && (s.rva as u64) < end
            }) {
                return Err(PeError("overlapping sections"));
            }
            sections.push(section);
        }
        let mut pe = Self {
            accepted_headers: AcceptedHeaders {
                timestamp: u32_at(data, at + 8)?,
                checksum: u32_at(opt, 64)?,
                preferred_base: image_base,
            },
            sample: SampleInfo {
                name: name.to_owned(),
                sha256: format!("{:x}", Sha256::digest(data)),
                size: data.len(),
                architecture,
                kind,
                managed,
                subsystem,
                imports: Vec::new(),
            },
            image_base,
            characteristics: flags,
            image_size,
            headers_size,
            entry_rva,
            sections,
            directories,
            imports: Vec::new(),
            exports: Vec::new(),
        };
        pe.parse_imports(data)?;
        pe.parse_exports(data)?;
        Ok(pe)
    }

    pub fn rva<'a>(&self, data: &'a [u8], rva: u32, size: usize) -> Result<&'a [u8]> {
        let end = (rva as u64)
            .checked_add(size as u64)
            .ok_or(PeError("RVA size overflow"))?;
        if end > self.image_size as u64 {
            return Err(PeError("RVA exceeds image"));
        }
        if rva < self.headers_size && end <= self.headers_size as u64 {
            return bytes(data, rva as usize, size);
        }
        for section in &self.sections {
            if rva >= section.rva && end <= section.rva as u64 + section.raw_size as u64 {
                return bytes(
                    data,
                    section.raw_offset as usize + (rva - section.rva) as usize,
                    size,
                );
            }
        }
        Err(PeError("RVA is not file-backed"))
    }
    fn ascii(&self, data: &[u8], rva: u32) -> Result<String> {
        let mut name = Vec::new();
        for offset in 0..512 {
            let address = rva
                .checked_add(offset)
                .ok_or(PeError("name RVA overflow"))?;
            let byte = self.rva(data, address, 1)?[0];
            if byte == 0 {
                return String::from_utf8(name).map_err(|_| PeError("invalid import name"));
            }
            if !byte.is_ascii() {
                return Err(PeError("non-ASCII import name"));
            }
            name.push(byte);
        }
        Err(PeError("unterminated import name"))
    }
    fn parse_imports(&mut self, data: &[u8]) -> Result<()> {
        let directory = self.directories[1];
        if directory.rva == 0 {
            return Ok(());
        }
        for index in 0..4096u32 {
            let offset = index * 20;
            if offset + 20 > directory.size {
                return Err(PeError("unterminated import descriptors"));
            }
            let row = self.rva(
                data,
                directory
                    .rva
                    .checked_add(offset)
                    .ok_or(PeError("import overflow"))?,
                20,
            )?;
            if row.iter().all(|&b| b == 0) {
                return Ok(());
            }
            let original = u32_at(row, 0)?;
            let iat = u32_at(row, 16)?;
            let module = self.ascii(data, u32_at(row, 12)?)?;
            if module.is_empty() || module.contains(['/', '\\', ':']) || iat == 0 {
                return Err(PeError("invalid import module/IAT"));
            }
            self.sample.imports.push(module.clone());
            let table = if original != 0 { original } else { iat };
            let width = self.sample.architecture.width();
            let mut terminated = false;
            for slot in 0..65536u32 {
                if self.imports.len() >= 65536 {
                    return Err(PeError("import count exceeds bound"));
                }
                let displacement = slot * width as u32;
                let raw = self.rva(
                    data,
                    table
                        .checked_add(displacement)
                        .ok_or(PeError("thunk overflow"))?,
                    width,
                )?;
                let value = if width == 8 {
                    u64_at(raw, 0)?
                } else {
                    u32_at(raw, 0)? as u64
                };
                if value == 0 {
                    terminated = true;
                    break;
                }
                let name = if value & (1u64 << (width * 8 - 1)) != 0 {
                    ImportName::Ordinal {
                        ordinal: value as u16,
                    }
                } else {
                    ImportName::Name(
                        self.ascii(
                            data,
                            u32::try_from(value)
                                .map_err(|_| PeError("import RVA exceeds32 bits"))?
                                .checked_add(2)
                                .ok_or(PeError("name overflow"))?,
                        )?,
                    )
                };
                let iat_rva = iat
                    .checked_add(displacement)
                    .ok_or(PeError("IAT overflow"))?;
                if iat_rva as u64 + width as u64 > self.image_size as u64 {
                    return Err(PeError("IAT exceeds image"));
                }
                self.imports.push(Import {
                    module: module.clone(),
                    name,
                    iat_rva,
                });
            }
            if !terminated {
                return Err(PeError("unterminated import table"));
            }
        }
        Err(PeError("import descriptors exceed bound"))
    }

    pub fn materialize(&self, data: &[u8], base: u64) -> Result<Vec<u8>> {
        let end = base
            .checked_add(self.image_size as u64)
            .ok_or(PeError("image address overflow"))?;
        if self.sample.architecture == Architecture::X86 && end > 1u64 << 32 {
            return Err(PeError("x86 image exceeds address space"));
        }
        let mut image = vec![0; self.image_size as usize];
        image[..self.headers_size as usize].copy_from_slice(bytes(
            data,
            0,
            self.headers_size as usize,
        )?);
        for section in &self.sections {
            if section.raw_size == 0 {
                continue;
            }
            let start = section.rva as usize;
            image[start..start + section.raw_size as usize].copy_from_slice(bytes(
                data,
                section.raw_offset as usize,
                section.raw_size as usize,
            )?);
        }
        if base == self.image_base {
            return Ok(image);
        }
        let directory = self.directories[5];
        if directory.rva == 0 || directory.size == 0 || self.characteristics & 1 != 0 {
            return Err(PeError("image cannot relocate"));
        }
        let mut offset = 0u32;
        while offset < directory.size {
            let header = self.rva(data, directory.rva + offset, 8)?;
            let page = u32_at(header, 0)?;
            let block_size = u32_at(header, 4)?;
            if block_size < 8 || block_size % 2 != 0 || block_size > directory.size - offset {
                return Err(PeError("invalid relocation block"));
            }
            let block = self.rva(data, directory.rva + offset, block_size as usize)?;
            for at in (8..block_size as usize).step_by(2) {
                let entry = u16_at(block, at)?;
                let kind = entry >> 12;
                if kind == 0 {
                    continue;
                }
                let target =
                    page.checked_add((entry & 0xfff) as u32)
                        .ok_or(PeError("relocation target overflow"))? as usize;
                let delta = base.wrapping_sub(self.image_base);
                match (kind, self.sample.architecture) {
                    (10, Architecture::X64) => {
                        let value = u64_at(&image, target)?.wrapping_add(delta);
                        image[target..target + 8].copy_from_slice(&value.to_le_bytes());
                    }
                    (3, Architecture::X86) => {
                        let value = u32_at(&image, target)?.wrapping_add(delta as u32);
                        image[target..target + 4].copy_from_slice(&value.to_le_bytes());
                    }
                    _ => return Err(PeError("unsupported relocation type")),
                }
            }
            offset += block_size;
        }
        Ok(image)
    }
}
