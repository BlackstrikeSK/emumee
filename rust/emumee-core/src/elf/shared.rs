//! Closed, staged x86-64 dynamic-link profile. No guest path is opened here.
use super::load::{PIE_BIAS, RelativeRelocation, StaticLoadPlan, file_backed_address, u64_entry};
use super::{Architecture, ElfError, ElfImage, Kind, PF_X, PT_LOAD, Result};

const PT_DYNAMIC: u32 = 2;
const PT_TLS: u32 = 7;
const PT_GNU_STACK: u32 = 0x6474_e551;
const PT_GNU_RELRO: u32 = 0x6474_e552;
const PF_W: u32 = 2;
const PAGE: u64 = 4096;
const LIB_BIAS: u64 = 0x0000_0002_0000_0000;
const LIB_STRIDE: u64 = 0x2000_0000;
const MAX_LIBRARIES: usize = 4;
const MAX_SYMBOLS: u64 = 4096;
const MAX_RELOCATIONS: u64 = 4096;
const MAX_TLS: u64 = 64 * 1024;

#[derive(Clone, Debug)]
pub struct TlsBlock {
    pub file_offset: u64,
    pub file_size: u64,
    pub memory_size: u64,
    pub offset_from_tp: i64,
}

#[derive(Clone, Debug)]
pub struct SharedLoadPlan {
    pub executable: StaticLoadPlan,
    pub libraries: Vec<StaticLoadPlan>,
    pub library_names: Vec<String>,
    pub relocations: Vec<RelativeRelocation>,
    pub relro: Vec<(u64, u64)>,
    pub tls: Vec<(usize, TlsBlock)>,
}

#[derive(Clone)]
struct Symbol {
    name: String,
    address: Option<u64>,
    tls_offset: Option<i64>,
}

struct RawRelocation {
    offset: u64,
    info: u64,
    addend: i64,
}

struct DynamicInfo {
    needed: Vec<String>,
    soname: Option<String>,
    symbols: Vec<Symbol>,
    relocations: Vec<RawRelocation>,
    relro: Vec<(u64, u64)>,
    tls: Option<TlsBlock>,
}

fn u32_entry(data: &[u8], at: u64) -> Result<u32> {
    Ok(u32::from_le_bytes(
        super::bytes(data, at, 4)?.try_into().unwrap(),
    ))
}

fn name(data: &[u8], offset: u64, size: u64, index: u64) -> Result<String> {
    if index >= size {
        return Err(ElfError("dynamic string offset outside table"));
    }
    let table = super::bytes(data, offset, size)?;
    let raw = &table[index as usize..];
    let end = raw
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(ElfError("unterminated dynamic string"))?;
    if end == 0 || end > 128 {
        return Err(ElfError("invalid dynamic string length"));
    }
    let value =
        std::str::from_utf8(&raw[..end]).map_err(|_| ElfError("dynamic string is not UTF-8"))?;
    Ok(value.to_owned())
}

fn library_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn relocation_table(
    image: &ElfImage,
    data: &[u8],
    address: u64,
    size: u64,
    entry: u64,
) -> Result<Vec<RawRelocation>> {
    if entry != 24 || size % 24 != 0 || size / 24 > MAX_RELOCATIONS {
        return Err(ElfError("invalid dynamic relocation size"));
    }
    let file = file_backed_address(image, address, size)?;
    let mut result = Vec::with_capacity((size / 24) as usize);
    for index in 0..size / 24 {
        let at = file + index * 24;
        result.push(RawRelocation {
            offset: u64_entry(data, at)?,
            info: u64_entry(data, at + 8)?,
            addend: i64::from_le_bytes(super::bytes(data, at + 16, 8)?.try_into().unwrap()),
        });
    }
    Ok(result)
}

fn parse_dynamic(image: &ElfImage, data: &[u8], bias: u64) -> Result<DynamicInfo> {
    let mut segments = image
        .program_headers
        .iter()
        .filter(|header| header.kind == PT_DYNAMIC);
    let dynamic = segments.next().ok_or(ElfError("dynamic segment missing"))?;
    if segments.next().is_some()
        || dynamic.file_size == 0
        || dynamic.file_size > 64 * 1024
        || dynamic.file_size % 16 != 0
    {
        return Err(ElfError("invalid dynamic segment"));
    }
    if image
        .program_headers
        .iter()
        .any(|header| header.kind == PT_GNU_STACK && header.flags & PF_X != 0)
    {
        return Err(ElfError("executable stack unsupported in shared profile"));
    }
    let mut tls_segments = image
        .program_headers
        .iter()
        .filter(|header| header.kind == PT_TLS);
    let tls = if let Some(header) = tls_segments.next() {
        if tls_segments.next().is_some()
            || header.memory_size == 0
            || header.memory_size > MAX_TLS
            || header.file_size > header.memory_size
            || header.alignment == 0
            || !header.alignment.is_power_of_two()
            || header.alignment > PAGE
            || header
                .virtual_address
                .checked_add(header.memory_size)
                .is_none()
        {
            return Err(ElfError("invalid TLS image"));
        }
        if !image.program_headers.iter().any(|segment| {
            segment.kind == PT_LOAD
                && header.virtual_address >= segment.virtual_address
                && header.virtual_address + header.memory_size
                    <= segment.virtual_address.saturating_add(segment.memory_size)
        }) {
            return Err(ElfError("TLS image outside mapped segment"));
        }
        let file_offset = file_backed_address(image, header.virtual_address, header.file_size)?;
        Some(TlsBlock {
            file_offset,
            file_size: header.file_size,
            memory_size: header.memory_size,
            offset_from_tp: 0,
        })
    } else {
        None
    };
    let file = file_backed_address(image, dynamic.virtual_address, dynamic.file_size)?;
    let mut needed_offsets = Vec::new();
    let mut soname_offset = None;
    let mut tags = std::collections::BTreeMap::new();
    let mut terminated = false;
    for index in 0..dynamic.file_size / 16 {
        let at = file + index * 16;
        let tag = u64_entry(data, at)?;
        let value = u64_entry(data, at + 8)?;
        match tag {
            0 => {
                terminated = true;
                break;
            }
            1 => needed_offsets.push(value),
            14 if soname_offset.replace(value).is_none() => {}
            2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 20 | 21 | 23 | 30 | 0x6fff_fef5
            | 0x6fff_fffb | 0x6fff_fff9 => {
                if tags.insert(tag, value).is_some() {
                    return Err(ElfError("duplicate dynamic tag"));
                }
            }
            _ => return Err(ElfError("dynamic feature unsupported")),
        }
    }
    if !terminated || needed_offsets.len() > MAX_LIBRARIES {
        return Err(ElfError("invalid dynamic dependency list"));
    }
    let get = |tag| {
        tags.get(&tag)
            .copied()
            .ok_or(ElfError("required dynamic tag missing"))
    };
    let str_size = get(10)?;
    if str_size == 0 || str_size > 64 * 1024 {
        return Err(ElfError("dynamic string table exceeds bound"));
    }
    let str_file = file_backed_address(image, get(5)?, str_size)?;
    let needed = needed_offsets
        .into_iter()
        .map(|offset| name(data, str_file, str_size, offset))
        .collect::<Result<Vec<_>>>()?;
    if needed.iter().any(|value| !library_name(value)) {
        return Err(ElfError("invalid dependency name"));
    }
    if needed
        .iter()
        .enumerate()
        .any(|(index, value)| needed[..index].contains(value))
    {
        return Err(ElfError("duplicate dynamic dependency"));
    }
    if tags.get(&30).is_some_and(|flags| flags & 4 != 0) {
        return Err(ElfError("dynamic text relocations unsupported"));
    }
    let soname = soname_offset
        .map(|offset| name(data, str_file, str_size, offset))
        .transpose()?;
    if soname.as_deref().is_some_and(|value| !library_name(value)) {
        return Err(ElfError("invalid shared object name"));
    }
    if get(11)? != 24 {
        return Err(ElfError("unsupported dynamic symbol entry size"));
    }
    let hash_file = file_backed_address(image, get(4)?, 8)?;
    let symbol_count = u32_entry(data, hash_file + 4)? as u64;
    if symbol_count == 0 || symbol_count > MAX_SYMBOLS {
        return Err(ElfError("dynamic symbol count exceeds bound"));
    }
    let symbol_file = file_backed_address(image, get(6)?, symbol_count * 24)?;
    let mut symbols = Vec::with_capacity(symbol_count as usize);
    for index in 0..symbol_count {
        let at = symbol_file + index * 24;
        let name_offset = u32_entry(data, at)? as u64;
        let binding = data[at as usize + 4] >> 4;
        let symbol_type = data[at as usize + 4] & 15;
        let section = u16::from_le_bytes(super::bytes(data, at + 6, 2)?.try_into().unwrap());
        let value = u64_entry(data, at + 8)?;
        let symbol_name = if name_offset == 0 {
            String::new()
        } else {
            name(data, str_file, str_size, name_offset)?
        };
        let address =
            if section != 0 && matches!(binding, 1 | 2) && matches!(symbol_type, 0..=2) {
                let address = bias
                    .checked_add(value)
                    .ok_or(ElfError("dynamic symbol address overflow"))?;
                if !image.program_headers.iter().any(|segment| {
                    segment.kind == PT_LOAD
                        && value >= segment.virtual_address
                        && value - segment.virtual_address < segment.memory_size
                }) {
                    return Err(ElfError("dynamic symbol outside loaded image"));
                }
                Some(address)
            } else {
                None
            };
        let tls_offset = if section != 0 && matches!(binding, 1 | 2) && symbol_type == 6 {
            let header = image
                .program_headers
                .iter()
                .find(|header| header.kind == PT_TLS)
                .ok_or(ElfError("TLS symbol without TLS segment"))?;
            if value >= header.memory_size {
                return Err(ElfError("TLS symbol outside TLS image"));
            }
            Some(i64::try_from(value).map_err(|_| ElfError("TLS symbol offset overflow"))?)
        } else {
            None
        };
        symbols.push(Symbol {
            name: symbol_name,
            address,
            tls_offset,
        });
    }
    let mut relocations = Vec::new();
    match (tags.get(&7), tags.get(&8), tags.get(&9)) {
        (None, None, None) => {}
        (Some(&address), Some(&size), Some(&entry)) => {
            relocations.extend(relocation_table(image, data, address, size, entry)?)
        }
        _ => return Err(ElfError("incomplete RELA table")),
    }
    match (tags.get(&23), tags.get(&2), tags.get(&20)) {
        (None, None, None) => {}
        (Some(&address), Some(&size), Some(&7)) => {
            relocations.extend(relocation_table(image, data, address, size, 24)?)
        }
        _ => return Err(ElfError("incomplete PLT relocation table")),
    }
    if relocations.len() > MAX_RELOCATIONS as usize {
        return Err(ElfError("too many dynamic relocations"));
    }
    let mut relro = Vec::new();
    for header in image
        .program_headers
        .iter()
        .filter(|header| header.kind == PT_GNU_RELRO)
    {
        let start = bias
            .checked_add(header.virtual_address)
            .ok_or(ElfError("RELRO address overflow"))?
            & !(PAGE - 1);
        let end = bias
            .checked_add(header.virtual_address)
            .and_then(|v| v.checked_add(header.memory_size))
            .ok_or(ElfError("RELRO range overflow"))?
            & !(PAGE - 1);
        if end > start {
            if !image.program_headers.iter().any(|segment| {
                segment.kind == PT_LOAD
                    && segment.flags & PF_W != 0
                    && start >= (bias.saturating_add(segment.virtual_address) & !(PAGE - 1))
                    && end
                        <= (bias
                            .saturating_add(segment.virtual_address)
                            .saturating_add(segment.memory_size)
                            .saturating_add(PAGE - 1)
                            & !(PAGE - 1))
            }) {
                return Err(ElfError("RELRO range outside writable load map"));
            }
            relro.push((start, end - start));
        }
    }
    Ok(DynamicInfo {
        needed,
        soname,
        symbols,
        relocations,
        relro,
        tls,
    })
}

fn resolve_relocations(
    image: &ElfImage,
    info: &DynamicInfo,
    bias: u64,
    all: &[&DynamicInfo],
) -> Result<Vec<RelativeRelocation>> {
    let mut output = Vec::with_capacity(info.relocations.len());
    for relocation in &info.relocations {
        let target = bias
            .checked_add(relocation.offset)
            .ok_or(ElfError("relocation address overflow"))?;
        let end = target
            .checked_add(8)
            .ok_or(ElfError("relocation target overflow"))?;
        if !image.program_headers.iter().any(|segment| {
            segment.kind == PT_LOAD
                && segment.flags & PF_W != 0
                && relocation.offset >= segment.virtual_address
                && end - bias <= segment.virtual_address.saturating_add(segment.memory_size)
        }) {
            return Err(ElfError("dynamic relocation target is not writable"));
        }
        let symbol_index = (relocation.info >> 32) as usize;
        let kind = relocation.info as u32;
        let base = match kind {
            8 if symbol_index == 0 => bias,
            18 => {
                let symbol = info
                    .symbols
                    .get(symbol_index)
                    .ok_or(ElfError("TLS relocation symbol index out of range"))?;
                let (owner, defining) = all
                    .iter()
                    .find_map(|object| {
                        object
                            .symbols
                            .iter()
                            .find(|candidate| {
                                candidate.name == symbol.name && candidate.tls_offset.is_some()
                            })
                            .map(|candidate| (*object, candidate))
                    })
                    .ok_or(ElfError("unresolved staged TLS symbol"))?;
                // TLS symbols carry offsets within their module's PT_TLS image.
                let block = owner.tls.as_ref().ok_or(ElfError("TLS block missing"))?;
                let offset = block
                    .offset_from_tp
                    .checked_add(defining.tls_offset.unwrap())
                    .and_then(|value| value.checked_add(relocation.addend))
                    .ok_or(ElfError("TLS relocation overflow"))?;
                output.push(RelativeRelocation {
                    target,
                    value: offset as u64,
                    width: 8,
                });
                continue;
            }
            1 | 6 | 7 => {
                let symbol = info
                    .symbols
                    .get(symbol_index)
                    .ok_or(ElfError("relocation symbol index out of range"))?;
                if symbol.name.is_empty() {
                    return Err(ElfError("unnamed relocation symbol"));
                }
                all.iter()
                    .flat_map(|object| &object.symbols)
                    .find(|candidate| candidate.name == symbol.name && candidate.address.is_some())
                    .and_then(|candidate| candidate.address)
                    .ok_or(ElfError("unresolved staged symbol"))?
            }
            _ => return Err(ElfError("dynamic relocation type unsupported")),
        };
        let value = base
            .checked_add_signed(relocation.addend)
            .ok_or(ElfError("dynamic relocation value overflow"))?;
        output.push(RelativeRelocation {
            target,
            value,
            width: 8,
        });
    }
    Ok(output)
}

impl SharedLoadPlan {
    pub fn parse(executable: &[u8], libraries: &[(&str, &[u8])]) -> Result<Self> {
        if libraries.is_empty() || libraries.len() > MAX_LIBRARIES {
            return Err(ElfError("shared profile requires staged libraries"));
        }
        if libraries.iter().enumerate().any(|(index, (name, _))| {
            !library_name(name)
                || libraries[..index]
                    .iter()
                    .any(|(previous, _)| previous == name)
        }) {
            return Err(ElfError("invalid or duplicate staged library name"));
        }
        let image = ElfImage::parse(executable, "guest")?;
        if image.sample.architecture != Architecture::X64
            || image.sample.kind != Kind::Dynamic
            || image.sample.interpreter.as_deref() != Some("/lib64/ld-linux-x86-64.so.2")
            || !image.sample.entry_in_executable_segment
        {
            return Err(ElfError("closed x86-64 dynamic executable required"));
        }
        let mut main_info = parse_dynamic(&image, executable, PIE_BIAS)?;
        if main_info.needed.len() != libraries.len() {
            return Err(ElfError("staged library count differs from DT_NEEDED"));
        }
        let executable_plan = StaticLoadPlan::from_image(&image, PIE_BIAS, true)?;
        let mut library_images = Vec::new();
        let mut library_plans = Vec::new();
        let mut library_infos = Vec::new();
        let mut names = Vec::new();
        for (index, needed) in main_info.needed.iter().enumerate() {
            let (_, data) = libraries
                .iter()
                .find(|(name, _)| name == needed)
                .ok_or(ElfError("DT_NEEDED library was not staged"))?;
            let library = ElfImage::parse(data, needed)?;
            if library.sample.architecture != Architecture::X64
                || library.sample.kind != Kind::Dynamic
                || library.sample.interpreter.is_some()
            {
                return Err(ElfError("staged library is not an x86-64 shared object"));
            }
            let bias = LIB_BIAS + index as u64 * LIB_STRIDE;
            let info = parse_dynamic(&library, data, bias)?;
            if !info.needed.is_empty() || info.soname.as_deref() != Some(needed) {
                return Err(ElfError("staged library dependency or SONAME mismatch"));
            }
            let plan = StaticLoadPlan::from_image(&library, bias, false)?;
            if plan.segments.is_empty()
                || plan
                    .segments
                    .iter()
                    .any(|segment| segment.page_start + segment.page_size > bias + LIB_STRIDE)
            {
                return Err(ElfError("staged library mapping exceeds slot"));
            }
            library_images.push(library);
            library_plans.push(plan);
            library_infos.push(info);
            names.push(needed.clone());
        }
        let mut tls = Vec::new();
        let mut used = 0u64;
        for (index, info) in std::iter::once(&mut main_info)
            .chain(library_infos.iter_mut())
            .enumerate()
        {
            if let Some(block) = info.tls.as_mut() {
                let header = if index == 0 {
                    &image
                } else {
                    &library_images[index - 1]
                };
                let alignment = header
                    .program_headers
                    .iter()
                    .find(|header| header.kind == PT_TLS)
                    .unwrap()
                    .alignment;
                used = used
                    .checked_add(block.memory_size)
                    .and_then(|value| value.checked_add(alignment - 1))
                    .map(|value| value & !(alignment - 1))
                    .ok_or(ElfError("TLS layout overflow"))?;
                if used > MAX_TLS {
                    return Err(ElfError("TLS layout exceeds bound"));
                }
                block.offset_from_tp = -(used as i64);
                tls.push((index, block.clone()));
            }
        }
        let mut all_info = Vec::with_capacity(library_infos.len() + 1);
        all_info.push(&main_info);
        all_info.extend(library_infos.iter());
        let mut relocations = resolve_relocations(&image, &main_info, PIE_BIAS, &all_info)?;
        let mut relro = main_info.relro.clone();
        for (index, library) in library_images.iter().enumerate() {
            let bias = LIB_BIAS + index as u64 * LIB_STRIDE;
            relocations.extend(resolve_relocations(
                library,
                &library_infos[index],
                bias,
                &all_info,
            )?);
            relro.extend(library_infos[index].relro.iter().copied());
        }
        let mut maps = Vec::new();
        for segment in executable_plan
            .segments
            .iter()
            .chain(library_plans.iter().flat_map(|plan| &plan.segments))
        {
            let end = segment
                .page_start
                .checked_add(segment.page_size)
                .ok_or(ElfError("shared mapping overflow"))?;
            if maps
                .iter()
                .any(|&(start, previous_end)| segment.page_start < previous_end && start < end)
            {
                return Err(ElfError("shared object mappings overlap"));
            }
            maps.push((segment.page_start, end));
        }
        if maps
            .iter()
            .try_fold(0u64, |total, &(start, end)| total.checked_add(end - start))
            .is_none_or(|total| total > 128 * 1024 * 1024)
        {
            return Err(ElfError("shared object mapping exceeds bound"));
        }
        let mut targets = std::collections::BTreeSet::new();
        if relocations
            .iter()
            .any(|relocation| !targets.insert(relocation.target))
        {
            return Err(ElfError("duplicate dynamic relocation target"));
        }
        Ok(Self {
            executable: executable_plan,
            libraries: library_plans,
            library_names: names,
            relocations,
            relro,
            tls,
        })
    }
}
