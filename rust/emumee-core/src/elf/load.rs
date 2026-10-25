//! Admission-only geometry for bounded Linux executable profiles.
use super::{Architecture, ElfError, ElfImage, Kind, PF_X, PT_LOAD, Result};

const PAGE: u64 = 4096;
const MAX_MAPPED: u64 = 128 * 1024 * 1024;
const USER_MIN: u64 = 0x10000;
const STACK_BASE: u64 = 0x0000_7fff_0000_0000;
const PT_DYNAMIC: u32 = 2;
const PT_TLS: u32 = 7;
const PT_GNU_STACK: u32 = 0x6474_e551;
const PF_W: u32 = 2;
pub(crate) const PIE_BIAS: u64 = 0x0000_0001_0000_0000;
const STACK32_BASE: u64 = 0xbfe0_0000;
const MAX_RELOCATIONS: usize = 4096;

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

#[derive(Clone, Debug)]
pub struct RelativeRelocation {
    pub target: u64,
    pub value: u64,
    pub width: u8,
}

#[derive(Clone, Debug)]
pub struct PieLoadPlan {
    pub image: StaticLoadPlan,
    pub relocations: Vec<RelativeRelocation>,
}

#[derive(Clone, Debug)]
pub struct Static32LoadPlan {
    pub image: StaticLoadPlan,
}

#[derive(Clone, Debug)]
pub struct Pie32LoadPlan {
    pub image: StaticLoadPlan,
    pub relocations: Vec<RelativeRelocation>,
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
        Self::from_image(&image, 0, true)
    }

    pub(crate) fn from_image(image: &ElfImage, bias: u64, require_entry: bool) -> Result<Self> {
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
            let virtual_address = header
                .virtual_address
                .checked_add(bias)
                .ok_or(ElfError("load bias overflow"))?;
            if header.memory_size == 0 {
                continue;
            }
            if (header.flags & (PF_W | PF_X)) == (PF_W | PF_X) || virtual_address < USER_MIN {
                return Err(ElfError("unsafe load segment"));
            }
            let end = virtual_address
                .checked_add(header.memory_size)
                .ok_or(ElfError("load address overflow"))?;
            let page_start = virtual_address & !(PAGE - 1);
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
                    Some(virtual_address + image.program_header_offset - header.offset);
            }
            entry_file_backed |= header.flags & PF_X != 0
                && image.sample.entry >= header.virtual_address
                && image.sample.entry - header.virtual_address < header.file_size;
            segments.push(LoadSegment {
                page_start,
                page_size,
                virtual_address,
                file_offset: header.offset,
                file_size: header.file_size,
                flags: header.flags,
            });
        }
        if require_entry && !entry_file_backed {
            return Err(ElfError("entry is outside executable file bytes"));
        }
        Ok(Self {
            entry: image
                .sample
                .entry
                .checked_add(bias)
                .ok_or(ElfError("entry bias overflow"))?,
            program_header_address: program_header_address
                .ok_or(ElfError("program headers are not mapped"))?,
            program_header_entry_size: image.program_header_entry_size,
            program_header_count: image.program_headers.len() as u16,
            segments,
            sha256: image.sample.sha256.clone(),
        })
    }
}

pub(crate) fn u64_entry(data: &[u8], at: u64) -> Result<u64> {
    Ok(u64::from_le_bytes(
        super::bytes(data, at, 8)?.try_into().unwrap(),
    ))
}

pub(crate) fn file_backed_address(image: &ElfImage, address: u64, size: u64) -> Result<u64> {
    let end = address
        .checked_add(size)
        .ok_or(ElfError("dynamic address overflow"))?;
    for segment in image
        .program_headers
        .iter()
        .filter(|header| header.kind == PT_LOAD)
    {
        let file_end = segment
            .virtual_address
            .checked_add(segment.file_size)
            .ok_or(ElfError("dynamic segment overflow"))?;
        if address >= segment.virtual_address && end <= file_end {
            return segment
                .offset
                .checked_add(address - segment.virtual_address)
                .ok_or(ElfError("dynamic file offset overflow"));
        }
    }
    Err(ElfError("dynamic table is not file-backed"))
}

impl PieLoadPlan {
    pub fn parse(data: &[u8]) -> Result<Self> {
        let image = ElfImage::parse(data, "guest")?;
        if image.sample.architecture != Architecture::X64
            || image.sample.kind != Kind::Dynamic
            || image.sample.interpreter.is_some()
            || !image.sample.entry_in_executable_segment
        {
            return Err(ElfError("static x86-64 PIE without interpreter required"));
        }
        if image.program_headers.iter().any(|header| {
            header.kind == PT_TLS || header.kind == PT_GNU_STACK && header.flags & PF_X != 0
        }) {
            return Err(ElfError("TLS or executable stack unsupported"));
        }
        let mut dynamic = image
            .program_headers
            .iter()
            .filter(|header| header.kind == PT_DYNAMIC);
        let table = dynamic
            .next()
            .ok_or(ElfError("PIE dynamic table missing"))?;
        if dynamic.next().is_some()
            || table.file_size == 0
            || table.file_size > 64 * 1024
            || table.file_size % 16 != 0
        {
            return Err(ElfError("invalid PIE dynamic table"));
        }
        let table_file = file_backed_address(&image, table.virtual_address, table.file_size)?;
        let mut rela = None;
        let mut rela_size = None;
        let mut rela_entry = None;
        let mut terminated = false;
        for index in 0..table.file_size / 16 {
            let at = table_file + index * 16;
            let tag = u64_entry(data, at)?;
            let value = u64_entry(data, at + 8)?;
            match tag {
                0 => {
                    terminated = true;
                    break;
                }
                7 if rela.replace(value).is_none() => {}
                8 if rela_size.replace(value).is_none() => {}
                9 if rela_entry.replace(value).is_none() => {}
                // Metadata emitted by GNU ld for a dependency-free static PIE.
                5 | 6 | 10 | 11 | 21 | 30 | 0x6fff_fef5 | 0x6fff_fffb | 0x6fff_fff9 => {}
                _ => return Err(ElfError("PIE dynamic feature unsupported")),
            }
        }
        if !terminated {
            return Err(ElfError("PIE dynamic table lacks terminator"));
        }
        let mut relocations = Vec::new();
        match (rela, rela_size, rela_entry) {
            (None, None, None) => {}
            (Some(address), Some(size), Some(24))
                if size % 24 == 0 && size / 24 <= MAX_RELOCATIONS as u64 =>
            {
                let file = file_backed_address(&image, address, size)?;
                for index in 0..size / 24 {
                    let at = file + index * 24;
                    let target = u64_entry(data, at)?;
                    let info = u64_entry(data, at + 8)?;
                    let addend =
                        i64::from_le_bytes(super::bytes(data, at + 16, 8)?.try_into().unwrap());
                    if info != 8 {
                        return Err(ElfError("PIE relocation type or symbol unsupported"));
                    }
                    let absolute = PIE_BIAS
                        .checked_add(target)
                        .ok_or(ElfError("PIE relocation address overflow"))?;
                    let target_end = absolute
                        .checked_add(8)
                        .ok_or(ElfError("PIE relocation target overflow"))?;
                    if !image.program_headers.iter().any(|segment| {
                        segment.kind == PT_LOAD
                            && segment.flags & PF_W != 0
                            && target >= segment.virtual_address
                            && target_end - PIE_BIAS
                                <= segment.virtual_address.saturating_add(segment.memory_size)
                    }) {
                        return Err(ElfError("PIE relocation target is not writable"));
                    }
                    let value = PIE_BIAS
                        .checked_add_signed(addend)
                        .ok_or(ElfError("PIE relocation value overflow"))?;
                    relocations.push(RelativeRelocation {
                        target: absolute,
                        value,
                        width: 8,
                    });
                }
            }
            _ => return Err(ElfError("invalid PIE relocation table")),
        }
        Ok(Self {
            image: StaticLoadPlan::from_image(&image, PIE_BIAS, true)?,
            relocations,
        })
    }
}

impl Static32LoadPlan {
    pub fn parse(data: &[u8]) -> Result<Self> {
        let image = ElfImage::parse(data, "guest")?;
        if image.sample.architecture != Architecture::X86
            || image.sample.kind != Kind::Executable
            || image.sample.interpreter.is_some()
            || !image.sample.entry_in_executable_segment
        {
            return Err(ElfError("static i386 executable required"));
        }
        if image.program_headers.iter().any(|header| {
            matches!(header.kind, PT_DYNAMIC | PT_TLS)
                || header.kind == PT_GNU_STACK && header.flags & PF_X != 0
        }) {
            return Err(ElfError("dynamic, TLS, or executable stack unsupported"));
        }
        let plan = StaticLoadPlan::from_image(&image, 0, true)?;
        if plan.segments.iter().any(|segment| {
            segment
                .page_start
                .checked_add(segment.page_size)
                .is_none_or(|end| end > STACK32_BASE)
        }) || plan.program_header_address > u32::MAX as u64
        {
            return Err(ElfError("i386 load map exceeds guest address space"));
        }
        Ok(Self { image: plan })
    }
}

impl Pie32LoadPlan {
    pub fn parse(data: &[u8]) -> Result<Self> {
        let image = ElfImage::parse(data, "guest")?;
        if image.sample.architecture != Architecture::X86
            || image.sample.kind != Kind::Dynamic
            || image.sample.interpreter.as_deref() != Some("/lib/ld-linux.so.2")
            || !image.sample.entry_in_executable_segment
        {
            return Err(ElfError("closed i386 dynamic PIE required"));
        }
        if image.program_headers.iter().any(|header| {
            header.kind == PT_TLS || header.kind == PT_GNU_STACK && header.flags & PF_X != 0
        }) {
            return Err(ElfError("i386 dynamic TLS or executable stack unsupported"));
        }
        let mut tables = image
            .program_headers
            .iter()
            .filter(|header| header.kind == PT_DYNAMIC);
        let table = tables
            .next()
            .ok_or(ElfError("i386 dynamic table missing"))?;
        if tables.next().is_some()
            || table.file_size == 0
            || table.file_size > 64 * 1024
            || table.file_size % 8 != 0
        {
            return Err(ElfError("invalid i386 dynamic table"));
        }
        let file = file_backed_address(&image, table.virtual_address, table.file_size)?;
        let mut rel = None;
        let mut size = None;
        let mut entry = None;
        let mut terminated = false;
        for index in 0..table.file_size / 8 {
            let at = file + index * 8;
            let tag = u32::from_le_bytes(super::bytes(data, at, 4)?.try_into().unwrap());
            let value =
                u32::from_le_bytes(super::bytes(data, at + 4, 4)?.try_into().unwrap()) as u64;
            match tag {
                0 => {
                    terminated = true;
                    break;
                }
                17 if rel.replace(value).is_none() => {}
                18 if size.replace(value).is_none() => {}
                19 if entry.replace(value).is_none() => {}
                5 | 6 | 10 | 11 | 21 | 30 | 0x6fff_fef5 | 0x6fff_fffb | 0x6fff_fffa => {}
                _ => return Err(ElfError("i386 dynamic feature unsupported")),
            }
        }
        if !terminated {
            return Err(ElfError("i386 dynamic table lacks terminator"));
        }
        let bias = 0x4000_0000u64;
        let mut relocations = Vec::new();
        match (rel, size, entry) {
            (Some(address), Some(size), Some(8))
                if size % 8 == 0 && size / 8 <= MAX_RELOCATIONS as u64 =>
            {
                let file = file_backed_address(&image, address, size)?;
                for index in 0..size / 8 {
                    let at = file + index * 8;
                    let target =
                        u32::from_le_bytes(super::bytes(data, at, 4)?.try_into().unwrap()) as u64;
                    let info =
                        u32::from_le_bytes(super::bytes(data, at + 4, 4)?.try_into().unwrap());
                    if info != 8 {
                        return Err(ElfError("i386 relocation type or symbol unsupported"));
                    }
                    if !image.program_headers.iter().any(|segment| {
                        segment.kind == PT_LOAD
                            && segment.flags & PF_W != 0
                            && target >= segment.virtual_address
                            && target.checked_add(4).is_some_and(|end| {
                                end <= segment.virtual_address.saturating_add(segment.memory_size)
                            })
                    }) {
                        return Err(ElfError("i386 relocation target is not writable"));
                    }
                    let addend_file = file_backed_address(&image, target, 4)?;
                    let addend =
                        u32::from_le_bytes(super::bytes(data, addend_file, 4)?.try_into().unwrap())
                            as u64;
                    let value = bias
                        .checked_add(addend)
                        .filter(|value| *value <= u32::MAX as u64)
                        .ok_or(ElfError("i386 relocation value overflow"))?;
                    relocations.push(RelativeRelocation {
                        target: bias + target,
                        value,
                        width: 4,
                    });
                }
            }
            _ => return Err(ElfError("invalid i386 REL relocation table")),
        }
        let plan = StaticLoadPlan::from_image(&image, bias, true)?;
        if plan.segments.iter().any(|segment| {
            segment
                .page_start
                .checked_add(segment.page_size)
                .is_none_or(|end| end > STACK32_BASE)
        }) {
            return Err(ElfError("i386 dynamic mapping exceeds guest address space"));
        }
        Ok(Self {
            image: plan,
            relocations,
        })
    }
}
