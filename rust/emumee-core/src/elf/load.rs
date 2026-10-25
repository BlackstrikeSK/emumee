//! Admission-only geometry for the initial static Linux x86-64 guest profile.
use super::{Architecture, ElfError, ElfImage, Kind, PF_X, PT_LOAD, Result};

const PAGE: u64 = 4096;
const MAX_MAPPED: u64 = 128 * 1024 * 1024;
const USER_MIN: u64 = 0x10000;
const STACK_BASE: u64 = 0x0000_7fff_0000_0000;
const PT_DYNAMIC: u32 = 2;
const PT_TLS: u32 = 7;
const PT_GNU_STACK: u32 = 0x6474_e551;
const PF_W: u32 = 2;

#[derive(Clone, Debug)]
pub struct LoadSegment {
    pub page_start: u64,
    pub page_size: u64,
    pub virtual_address: u64,
    pub file_offset: u64,
    pub file_size: u64,
    pub flags: u32,
}

#[derive(Clone, Debug)]
pub struct StaticLoadPlan {
    pub entry: u64,
    pub program_header_address: u64,
    pub program_header_entry_size: u16,
    pub program_header_count: u16,
    pub segments: Vec<LoadSegment>,
    pub sha256: String,
}

impl StaticLoadPlan {
    pub fn parse(data: &[u8]) -> Result<Self> {
        let image = ElfImage::parse(data, "guest")?;
        if image.sample.architecture != Architecture::X64
            || image.sample.kind != Kind::Executable
            || image.sample.interpreter.is_some()
            || !image.sample.entry_in_executable_segment
        {
            return Err(ElfError("static x86-64 executable required"));
        }
        if image.program_headers.iter().any(|header| {
            matches!(header.kind, PT_DYNAMIC | PT_TLS)
                || header.kind == PT_GNU_STACK && header.flags & PF_X != 0
        }) {
            return Err(ElfError("dynamic, TLS, or executable stack unsupported"));
        }

        let ph_size = (image.program_header_entry_size as u64)
            .checked_mul(image.program_headers.len() as u64)
            .ok_or(ElfError("program header size overflow"))?;
        let ph_end = image
            .program_header_offset
            .checked_add(ph_size)
            .ok_or(ElfError("program header range overflow"))?;
        let mut program_header_address = None;
        let mut segments = Vec::new();
        let mut mapped = 0u64;
        let mut entry_file_backed = false;
        for header in image
            .program_headers
            .iter()
            .filter(|header| header.kind == PT_LOAD)
        {
            if header.memory_size == 0
                || (header.flags & (PF_W | PF_X)) == (PF_W | PF_X)
                || header.virtual_address < USER_MIN
            {
                return Err(ElfError("unsafe load segment"));
            }
            let end = header
                .virtual_address
                .checked_add(header.memory_size)
                .ok_or(ElfError("load address overflow"))?;
            let page_start = header.virtual_address & !(PAGE - 1);
            let page_end = end
                .checked_add(PAGE - 1)
                .ok_or(ElfError("load page overflow"))?
                & !(PAGE - 1);
            let page_size = page_end - page_start;
            if end > STACK_BASE || page_size == 0 || page_size > MAX_MAPPED {
                return Err(ElfError("load segment exceeds guest profile"));
            }
            mapped = mapped
                .checked_add(page_size)
                .ok_or(ElfError("mapped size overflow"))?;
            if mapped > MAX_MAPPED
                || segments.iter().any(|segment: &LoadSegment| {
                    page_start < segment.page_start + segment.page_size
                        && segment.page_start < page_end
                })
            {
                return Err(ElfError("overlapping or oversized load maps"));
            }
            let file_end = header
                .offset
                .checked_add(header.file_size)
                .ok_or(ElfError("file segment overflow"))?;
            if image.program_header_offset >= header.offset && ph_end <= file_end {
                program_header_address =
                    Some(header.virtual_address + image.program_header_offset - header.offset);
            }
            entry_file_backed |= header.flags & PF_X != 0
                && image.sample.entry >= header.virtual_address
                && image.sample.entry - header.virtual_address < header.file_size;
            segments.push(LoadSegment {
                page_start,
                page_size,
                virtual_address: header.virtual_address,
                file_offset: header.offset,
                file_size: header.file_size,
                flags: header.flags,
            });
        }
        if !entry_file_backed {
            return Err(ElfError("entry is outside executable file bytes"));
        }
        Ok(Self {
            entry: image.sample.entry,
            program_header_address: program_header_address
                .ok_or(ElfError("program headers are not mapped"))?,
            program_header_entry_size: image.program_header_entry_size,
            program_header_count: image.program_headers.len() as u16,
            segments,
            sha256: image.sample.sha256,
        })
    }
}
