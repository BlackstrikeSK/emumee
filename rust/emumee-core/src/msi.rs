//! Bounded, static Compound File Binary streams for MSI/MSP/MST intake.
//!
//! Microsoft MS-CFB sections2.2--2.6 define the sector/header/directory layout:
//! https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/05060311-bfce-4b12-874d-71fd4ce63aea
//! No installer tables/actions, CAB decompression, filesystem writes, or guest
//! execution occur here. Names are display data. Per-stream32MiB and total64MiB
//! omissions match the legacy MSI lane; additional directory/depth/input bounds
//! reject resource-exhaustion structures. Malformed chains and shared allocation
//! are rejected even when a stream would otherwise be omitted for its size.
//!
//! The worker still needs an artifact/report adapter. CAB bytes are retained
//! verbatim. PE recognition uses the checked Rust PE parser; legacy fast PE
//! recognition and embedded PE carving/reconstruction remain adapter work.
//! Directory traversal validates ownership and cycles, not red-black balancing
//! or the complete MS-CFB Unicode collation rules. Invalid UTF-16 is rejected.

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const SIGNATURE: [u8; 8] = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
pub const MAX_INPUT_BYTES: usize = 128 * 1024 * 1024;
pub const MAX_STREAMS: usize = 2048;
pub const MAX_STREAM_BYTES: u64 = 32 * 1024 * 1024;
pub const MAX_TOTAL_STREAM_BYTES: u64 = 64 * 1024 * 1024;
const MAX_DIRECTORY_ENTRIES: usize = 8192;
const MAX_DIRECTORY_BYTES: usize = MAX_DIRECTORY_ENTRIES * 128;
const MAX_STORAGE_DEPTH: usize = 32;
const FREE: u32 = 0xffff_ffff;
const END: u32 = 0xffff_fffe;
const FAT: u32 = 0xffff_fffd;
const DIFAT: u32 = 0xffff_fffc;

#[derive(Debug, thiserror::Error)]
#[error("Invalid MSI compound file: {0}")]
pub struct MsiError(pub &'static str);
type Result<T> = std::result::Result<T, MsiError>;

fn demand(condition: bool, reason: &'static str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(MsiError(reason))
    }
}

fn range(raw: &[u8], offset: usize, count: usize) -> Result<&[u8]> {
    raw.get(
        offset
            ..offset
                .checked_add(count)
                .ok_or(MsiError("offset overflow"))?,
    )
    .ok_or(MsiError("truncated input"))
}
fn u16_at(raw: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(range(raw, at, 2)?.try_into().unwrap()))
}
fn u32_at(raw: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(range(raw, at, 4)?.try_into().unwrap()))
}
fn u64_at(raw: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(range(raw, at, 8)?.try_into().unwrap()))
}
fn sector(raw: &[u8], size: usize, id: usize) -> Result<&[u8]> {
    let offset = id
        .checked_add(1)
        .and_then(|n| n.checked_mul(size))
        .ok_or(MsiError("sector offset overflow"))?;
    range(raw, offset, size)
}
fn units(size: u64, width: usize) -> Result<usize> {
    let count = size
        .checked_add(width as u64 - 1)
        .ok_or(MsiError("stream size overflow"))?
        / width as u64;
    usize::try_from(count).map_err(|_| MsiError("stream count overflow"))
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum StreamType {
    Cabinet,
    Pe,
    Data,
}

#[derive(Debug, Serialize)]
pub struct Stream {
    /// The full hierarchy is never interpreted as a host path.
    pub path: Vec<String>,
    /// Legacy display name, truncated to256Unicode scalar values.
    pub name: String,
    pub size: u64,
    #[serde(rename = "type")]
    pub kind: StreamType,
    pub sha256: String,
    #[serde(skip)]
    pub data: Vec<u8>,
}

#[derive(Debug, Serialize)]
pub struct Omission {
    pub source: String,
    pub size: u64,
    pub reason: &'static str,
}

#[derive(Debug, Serialize)]
pub struct Inspection {
    pub format: &'static str,
    pub inspection: &'static str,
    pub version: u16,
    pub sector_size: usize,
    pub streams: Vec<Stream>,
    pub stream_count: usize,
    pub stream_bytes_read: u64,
    pub omissions: Vec<Omission>,
    pub limitations: [&'static str; 3],
}

#[derive(Debug)]
struct Entry {
    name: String,
    kind: u8,
    left: u32,
    right: u32,
    child: u32,
    start: u32,
    size: u64,
}

fn entries(raw: &[u8], version: u16) -> Result<Vec<Entry>> {
    demand(
        raw.len() % 128 == 0 && raw.len() <= MAX_DIRECTORY_BYTES,
        "directory byte limit or alignment",
    )?;
    let mut output = Vec::with_capacity(raw.len() / 128);
    for bytes in raw.chunks_exact(128) {
        let kind = bytes[66];
        demand(
            [0, 1, 2, 5].contains(&kind),
            "unsupported directory object type",
        )?;
        if kind == 0 {
            output.push(Entry {
                name: String::new(),
                kind,
                left: FREE,
                right: FREE,
                child: FREE,
                start: END,
                size: 0,
            });
            continue;
        }
        let length = u16_at(bytes, 64)? as usize;
        demand(
            (2..=64).contains(&length) && length % 2 == 0 && u16_at(bytes, length - 2)? == 0,
            "invalid directory name length or terminator",
        )?;
        let name_units: Vec<u16> = bytes[..length - 2]
            .chunks_exact(2)
            .map(|p| u16::from_le_bytes([p[0], p[1]]))
            .collect();
        demand(
            !name_units.is_empty() && !name_units.contains(&0),
            "empty or embedded-NUL directory name",
        )?;
        let name = String::from_utf16(&name_units)
            .map_err(|_| MsiError("invalid UTF-16 directory name"))?;
        demand(
            !name.chars().any(|c| ['/', '\\', ':', '!'].contains(&c)),
            "reserved directory name character",
        )?;
        demand(bytes[67] <= 1, "invalid directory color flag")?;
        let size = u64_at(bytes, 120)?;
        demand(
            version != 3 || size <= u32::MAX.into(),
            "version3 stream has nonzero high size",
        )?;
        if kind == 1 {
            demand(size == 0, "storage object has a stream size")?;
        }
        if kind == 2 {
            demand(u32_at(bytes, 76)? == FREE, "stream object has children")?;
        }
        output.push(Entry {
            name,
            kind,
            left: u32_at(bytes, 68)?,
            right: u32_at(bytes, 72)?,
            child: u32_at(bytes, 76)?,
            start: u32_at(bytes, 116)?,
            size,
        });
    }
    demand(
        !output.is_empty()
            && output[0].kind == 5
            && output[0].name == "Root Entry"
            && output[0].left == FREE
            && output[0].right == FREE,
        "missing or malformed root directory entry",
    )?;
    demand(
        output.iter().skip(1).all(|e| e.kind != 5),
        "duplicate root directory entry",
    )?;
    Ok(output)
}

fn paths(entries: &[Entry]) -> Result<Vec<(usize, Vec<String>)>> {
    let mut visited = vec![false; entries.len()];
    visited[0] = true;
    let mut stack = vec![(entries[0].child, Vec::new())];
    let mut siblings: BTreeMap<Vec<String>, BTreeSet<String>> = BTreeMap::new();
    let mut streams = Vec::new();
    while let Some((id, parent)) = stack.pop() {
        if id == FREE {
            continue;
        }
        let id = id as usize;
        demand(
            id < entries.len() && !visited[id],
            "directory cycle, duplicate parent, or invalid ID",
        )?;
        visited[id] = true;
        let entry = &entries[id];
        demand(
            [1, 2].contains(&entry.kind),
            "directory references an unallocated/root entry",
        )?;
        demand(
            siblings
                .entry(parent.clone())
                .or_default()
                .insert(entry.name.clone()),
            "duplicate sibling name",
        )?;
        stack.push((entry.left, parent.clone()));
        stack.push((entry.right, parent.clone()));
        let mut path = parent;
        path.push(entry.name.clone());
        demand(path.len() <= MAX_STORAGE_DEPTH, "storage depth limit")?;
        if entry.kind == 1 {
            stack.push((entry.child, path));
        } else {
            streams.push((id, path));
            demand(streams.len() <= MAX_STREAMS, "MSI stream count exceeds2048")?;
        }
    }
    demand(
        entries
            .iter()
            .enumerate()
            .all(|(i, e)| e.kind == 0 || visited[i]),
        "unreachable allocated directory entry",
    )?;
    streams.sort_by(|a, b| a.1.cmp(&b.1));
    Ok(streams)
}

/// Validate every FAT link, including unreferenced chains, in linear time.
fn validate_links(fat: &[u32], allow_metadata: bool) -> Result<()> {
    for &next in fat {
        demand(
            next == END
                || next == FREE
                || (allow_metadata && [FAT, DIFAT].contains(&next))
                || (next as usize) < fat.len(),
            "FAT link outside allocation table",
        )?;
    }
    let mut colors = vec![0_u8; fat.len()];
    for start in 0..fat.len() {
        if colors[start] != 0 {
            continue;
        }
        let mut trail = Vec::new();
        let mut at = start;
        loop {
            if colors[at] == 2 {
                break;
            }
            demand(colors[at] == 0, "FAT allocation cycle")?;
            colors[at] = 1;
            trail.push(at);
            let next = fat[at];
            if next as usize >= fat.len() {
                break;
            }
            at = next as usize;
        }
        for id in trail {
            colors[id] = 2;
        }
    }
    Ok(())
}

fn chain(
    fat: &[u32],
    start: u32,
    expected: Option<usize>,
    maximum: usize,
    owners: &mut [u8],
    owner: u8,
) -> Result<Vec<usize>> {
    if let Some(expected) = expected {
        demand(expected <= maximum, "stream exceeds available allocation")?;
    }
    let mut output = Vec::new();
    let mut at = start;
    while at != END {
        let id = at as usize;
        demand(
            id < fat.len() && id < owners.len() && output.len() < maximum,
            "invalid or overlong allocation chain",
        )?;
        demand(owners[id] == 0, "shared/cyclic stream allocation")?;
        if let Some(count) = expected {
            demand(output.len() < count, "overlong stream chain")?;
        }
        owners[id] = owner;
        output.push(id);
        at = fat[id];
    }
    if let Some(count) = expected {
        demand(output.len() == count, "truncated stream chain")?;
    }
    Ok(output)
}

fn materialize(raw: &[u8], width: usize, chain: &[usize], length: usize) -> Result<Vec<u8>> {
    demand(
        length
            <= chain
                .len()
                .checked_mul(width)
                .ok_or(MsiError("stream capacity overflow"))?,
        "stream exceeds chain",
    )?;
    let mut output = Vec::with_capacity(length);
    for &id in chain {
        let count = (length - output.len()).min(width);
        output.extend_from_slice(&sector(raw, width, id)?[..count]);
    }
    demand(output.len() == length, "truncated materialized stream")?;
    Ok(output)
}

/// Parse an already bounded input buffer. This performs no I/O or execution.
pub fn inspect(raw: &[u8]) -> Result<Inspection> {
    demand(
        raw.len() >= 512 && raw.len() <= MAX_INPUT_BYTES && raw[..8] == SIGNATURE,
        "input is not a bounded MSI compound file",
    )?;
    demand(
        raw[8..24].iter().all(|b| *b == 0)
            && u16_at(raw, 28)? == 0xfffe
            && u16_at(raw, 32)? == 6
            && raw[34..40].iter().all(|b| *b == 0),
        "invalid compound header fields",
    )?;
    let version = u16_at(raw, 26)?;
    let shift = u16_at(raw, 30)?;
    demand(
        (version == 3 && shift == 9) || (version == 4 && shift == 12),
        "unsupported compound version/sector shift",
    )?;
    let width = 1_usize << shift;
    demand(
        raw.len() % width == 0 && raw.len() >= width * 3 && raw[512..width].iter().all(|b| *b == 0),
        "truncated/unaligned compound sectors or nonzero header padding",
    )?;
    let count = raw.len() / width - 1;
    let directory_count = u32_at(raw, 40)? as usize;
    demand(
        version != 3 || directory_count == 0,
        "version3 has a directory sector count",
    )?;
    demand(u32_at(raw, 56)? == 4096, "invalid mini stream cutoff")?;
    let fat_count = u32_at(raw, 44)? as usize;
    let mini_count = u32_at(raw, 64)? as usize;
    let difat_count = u32_at(raw, 72)? as usize;
    demand(
        fat_count > 0 && fat_count <= count && mini_count <= count && difat_count <= count,
        "allocation table count exceeds input",
    )?;
    let mut owners = vec![0_u8; count];
    let mut fat_ids = Vec::with_capacity(fat_count);
    let mut accept_fat = |id: u32| -> Result<()> {
        if id != FREE {
            demand(
                (id as usize) < count && fat_ids.len() < fat_count,
                "DIFAT lists too many or invalid FAT sectors",
            )?;
            fat_ids.push(id as usize);
        }
        Ok(())
    };
    for offset in (76..512).step_by(4) {
        accept_fat(u32_at(raw, offset)?)?;
    }
    let mut difat_ids = Vec::with_capacity(difat_count);
    let mut at = u32_at(raw, 68)?;
    for _ in 0..difat_count {
        let id = at as usize;
        demand(
            id < count && owners[id] == 0,
            "DIFAT cycle or invalid sector",
        )?;
        owners[id] = 1;
        difat_ids.push(id);
        let bytes = sector(raw, width, id)?;
        for offset in (0..width - 4).step_by(4) {
            accept_fat(u32_at(bytes, offset)?)?;
        }
        at = u32_at(bytes, width - 4)?;
    }
    demand(
        at == END && fat_ids.len() == fat_count,
        "DIFAT count/termination disagrees with header",
    )?;
    for &id in &fat_ids {
        demand(owners[id] == 0, "duplicate/shared FAT sector")?;
        owners[id] = 1;
    }
    let mut fat = Vec::with_capacity(count);
    for &id in &fat_ids {
        for offset in (0..width).step_by(4) {
            let next = u32_at(sector(raw, width, id)?, offset)?;
            if fat.len() < count {
                fat.push(next);
            } else {
                demand(next == FREE, "FAT padding references nonexistent sectors")?;
            }
        }
    }
    demand(fat.len() == count, "FAT does not cover input sectors")?;
    validate_links(&fat, true)?;
    for &id in &fat_ids {
        demand(fat[id] == FAT, "FAT sector missing its allocation marker")?;
    }
    for &id in &difat_ids {
        demand(
            fat[id] == DIFAT,
            "DIFAT sector missing its allocation marker",
        )?;
    }
    for (id, &marker) in fat.iter().enumerate() {
        demand(
            ![FAT, DIFAT].contains(&marker) || owners[id] == 1,
            "unlisted allocation table sector",
        )?;
    }
    let directory = chain(
        &fat,
        u32_at(raw, 48)?,
        if version == 4 {
            Some(directory_count)
        } else {
            None
        },
        count.min(MAX_DIRECTORY_BYTES / width),
        &mut owners,
        2,
    )?;
    demand(!directory.is_empty(), "missing directory stream")?;
    let directory_bytes = materialize(raw, width, &directory, directory.len() * width)?;
    let entries = entries(&directory_bytes, version)?;
    let paths = paths(&entries)?;
    let root = &entries[0];
    demand(
        root.size <= raw.len() as u64 && root.size % 64 == 0,
        "invalid mini stream size",
    )?;
    let root_chain = chain(
        &fat,
        root.start,
        Some(units(root.size, width)?),
        count,
        &mut owners,
        3,
    )?;
    let mini_sectors =
        usize::try_from(root.size / 64).map_err(|_| MsiError("mini stream count overflow"))?;
    let mini_chain = chain(
        &fat,
        u32_at(raw, 60)?,
        Some(mini_count),
        count,
        &mut owners,
        4,
    )?;
    let mut mini_fat = Vec::with_capacity(mini_sectors);
    for id in mini_chain {
        let bytes = sector(raw, width, id)?;
        for offset in (0..width).step_by(4) {
            let next = u32_at(bytes, offset)?;
            if mini_fat.len() < mini_sectors {
                mini_fat.push(next);
            } else {
                demand(
                    next == FREE,
                    "mini FAT padding references outside root stream",
                )?;
            }
        }
    }
    demand(
        mini_fat.len() == mini_sectors,
        "mini FAT does not cover root stream",
    )?;
    validate_links(&mini_fat, false)?;
    let mut mini_owners = vec![0_u8; mini_sectors];
    let mut streams = Vec::new();
    let mut omissions = Vec::new();
    let mut total = 0_u64;
    for (id, path) in paths {
        let entry = &entries[id];
        let name = path.join("/");
        let small = entry.size < 4096;
        let allocation = if small {
            chain(
                &mini_fat,
                entry.start,
                Some(units(entry.size, 64)?),
                mini_sectors,
                &mut mini_owners,
                1,
            )?
        } else {
            chain(
                &fat,
                entry.start,
                Some(units(entry.size, width)?),
                count,
                &mut owners,
                5,
            )?
        };
        let reason = if entry.size > MAX_STREAM_BYTES {
            Some("msi_stream_size_limit")
        } else if entry.size > MAX_TOTAL_STREAM_BYTES - total {
            Some("msi_total_stream_limit")
        } else {
            None
        };
        if let Some(reason) = reason {
            omissions.push(Omission {
                source: format!("msi_stream:{name}"),
                size: entry.size,
                reason,
            });
            continue;
        }
        let length = usize::try_from(entry.size).map_err(|_| MsiError("stream length overflow"))?;
        let data = if small {
            let mut output = Vec::with_capacity(length);
            for mini_id in allocation {
                let offset = mini_id
                    .checked_mul(64)
                    .ok_or(MsiError("mini sector offset overflow"))?;
                let regular_id = *root_chain
                    .get(offset / width)
                    .ok_or(MsiError("mini sector outside root allocation"))?;
                let count = (length - output.len()).min(64);
                output.extend_from_slice(range(
                    sector(raw, width, regular_id)?,
                    offset % width,
                    count,
                )?);
            }
            demand(output.len() == length, "mini stream length mismatch")?;
            output
        } else {
            materialize(raw, width, &allocation, length)?
        };
        total += entry.size;
        let kind = if data.starts_with(b"MSCF") {
            StreamType::Cabinet
        } else if crate::pe::PeImage::parse(&data, "msi-embedded-stream.pe").is_ok() {
            StreamType::Pe
        } else {
            StreamType::Data
        };
        let sha256 = format!("{:x}", Sha256::digest(&data));
        streams.push(Stream {
            path,
            name: name.chars().take(256).collect(),
            size: entry.size,
            kind,
            sha256,
            data,
        });
    }
    Ok(Inspection {
        format: "msi",
        inspection: "static_streams",
        version,
        sector_size: width,
        stream_count: streams.len(),
        streams,
        stream_bytes_read: total,
        omissions,
        limitations: [
            "Windows Installer tables and custom actions were not executed",
            "Embedded CAB files were retained but not unpacked",
            "Legacy PE carving and artifact/report filesystem adapters remain separate",
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put16(raw: &mut [u8], at: usize, value: u16) {
        raw[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn put32(raw: &mut [u8], at: usize, value: u32) {
        raw[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn put64(raw: &mut [u8], at: usize, value: u64) {
        raw[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn header(version: u16, sectors: usize) -> Vec<u8> {
        let width = if version == 3 { 512 } else { 4096 };
        let mut raw = vec![0; width * (sectors + 1)];
        raw[..8].copy_from_slice(&SIGNATURE);
        put16(&mut raw, 24, 0x3e);
        put16(&mut raw, 26, version);
        put16(&mut raw, 28, 0xfffe);
        put16(&mut raw, 30, if version == 3 { 9 } else { 12 });
        put16(&mut raw, 32, 6);
        put32(&mut raw, 40, if version == 3 { 0 } else { 1 });
        put32(&mut raw, 44, 1);
        put32(&mut raw, 48, 1);
        put32(&mut raw, 56, 4096);
        put32(&mut raw, 60, END);
        put32(&mut raw, 68, END);
        for offset in (76..512).step_by(4) {
            put32(&mut raw, offset, FREE);
        }
        put32(&mut raw, 76, 0);
        for offset in (width..width * 2).step_by(4) {
            put32(&mut raw, offset, FREE);
        }
        put32(&mut raw, width, FAT);
        put32(&mut raw, width + 4, END);
        raw
    }

    #[allow(clippy::too_many_arguments)]
    fn directory(
        raw: &mut [u8],
        at: usize,
        name: &str,
        kind: u8,
        right: u32,
        child: u32,
        start: u32,
        size: u64,
    ) {
        let units: Vec<u16> = name.encode_utf16().collect();
        assert!(units.len() <= 31);
        for (i, unit) in units.iter().enumerate() {
            put16(raw, at + i * 2, *unit);
        }
        put16(raw, at + 64, ((units.len() + 1) * 2) as u16);
        raw[at + 66] = kind;
        raw[at + 67] = 1;
        put32(raw, at + 68, FREE);
        put32(raw, at + 72, right);
        put32(raw, at + 76, child);
        put32(raw, at + 116, start);
        put64(raw, at + 120, size);
    }

    fn small(version: u16) -> Vec<u8> {
        let width = if version == 3 { 512 } else { 4096 };
        let mut raw = header(version, 4);
        put32(&mut raw, 60, 2);
        put32(&mut raw, 64, 1);
        put32(&mut raw, width + 8, END);
        put32(&mut raw, width + 12, END);
        let dir = width * 2;
        directory(&mut raw, dir, "Root Entry", 5, FREE, 1, 3, 192);
        directory(&mut raw, dir + 128, "Binary", 1, FREE, 2, 0, 0);
        directory(&mut raw, dir + 256, "Cabinet", 2, 3, FREE, 0, 6);
        directory(&mut raw, dir + 384, "Payload", 2, FREE, FREE, 1, 70);
        for offset in (width * 3..width * 4).step_by(4) {
            put32(&mut raw, offset, FREE);
        }
        put32(&mut raw, width * 3, END);
        put32(&mut raw, width * 3 + 4, 2);
        put32(&mut raw, width * 3 + 8, END);
        raw[width * 4..width * 4 + 6].copy_from_slice(b"MSCF\0\xff");
        for i in 0..70 {
            raw[width * 4 + 64 + i] = i as u8;
        }
        raw
    }

    fn regular(version: u16) -> Vec<u8> {
        let width = if version == 3 { 512 } else { 4096 };
        let payload_sectors = 4096 / width;
        let mut raw = header(version, 2 + payload_sectors);
        let dir = width * 2;
        directory(&mut raw, dir, "Root Entry", 5, FREE, 1, END, 0);
        directory(&mut raw, dir + 128, "Cabinet", 2, FREE, FREE, 2, 4096);
        for i in 0..payload_sectors {
            put32(
                &mut raw,
                width + (i + 2) * 4,
                if i + 1 == payload_sectors {
                    END
                } else {
                    (i + 3) as u32
                },
            );
        }
        raw[width * 3..width * 3 + 4].copy_from_slice(b"MSCF");
        raw
    }

    fn extended_difat() -> Vec<u8> {
        let mut raw = header(3, 112);
        put32(&mut raw, 44, 110);
        put32(&mut raw, 48, 110);
        put32(&mut raw, 68, 111);
        put32(&mut raw, 72, 1);
        for i in 0..109 {
            put32(&mut raw, 76 + i * 4, i as u32);
        }
        for id in 0..110 {
            raw[(id + 1) * 512..(id + 2) * 512].fill(0xff);
        }
        for id in 0..110 {
            put32(&mut raw, 512 + id * 4, FAT);
        }
        put32(&mut raw, 512 + 110 * 4, END);
        put32(&mut raw, 512 + 111 * 4, DIFAT);
        directory(&mut raw, 111 * 512, "Root Entry", 5, FREE, FREE, END, 0);
        raw[112 * 512..113 * 512].fill(0xff);
        put32(&mut raw, 112 * 512, 109);
        put32(&mut raw, 113 * 512 - 4, END);
        raw
    }

    fn empty_streams(count: usize) -> Vec<u8> {
        let directories = (count + 1).div_ceil(4);
        let mut fats = 1;
        while (fats + directories).div_ceil(128) > fats {
            fats += 1;
        }
        let mut raw = header(3, fats + directories);
        put32(&mut raw, 44, fats as u32);
        put32(&mut raw, 48, fats as u32);
        for i in 0..fats {
            put32(&mut raw, 76 + i * 4, i as u32);
            raw[(i + 1) * 512..(i + 2) * 512].fill(0xff);
        }
        for i in 0..fats + directories {
            let next = if i < fats {
                FAT
            } else if i + 1 == fats + directories {
                END
            } else {
                (i + 1) as u32
            };
            let page = i / 128;
            let index = i % 128;
            put32(&mut raw, (page + 1) * 512 + index * 4, next);
        }
        let first = (fats + 1) * 512;
        directory(
            &mut raw,
            first,
            "Root Entry",
            5,
            FREE,
            if count == 0 { FREE } else { 1 },
            END,
            0,
        );
        for i in 1..=count {
            directory(
                &mut raw,
                first + i * 128,
                &format!("S{i:04}"),
                2,
                if i == count { FREE } else { (i + 1) as u32 },
                FREE,
                END,
                0,
            );
        }
        raw
    }

    fn deep_storages(count: usize) -> Vec<u8> {
        let directories = (count + 2).div_ceil(4);
        let mut raw = header(3, directories + 1);
        for i in 1..=directories {
            put32(
                &mut raw,
                512 + i * 4,
                if i == directories {
                    END
                } else {
                    (i + 1) as u32
                },
            );
        }
        directory(&mut raw, 1024, "Root Entry", 5, FREE, 1, END, 0);
        for i in 1..=count {
            directory(
                &mut raw,
                1024 + i * 128,
                &format!("Storage{i}"),
                1,
                FREE,
                (i + 1) as u32,
                0,
                0,
            );
        }
        directory(
            &mut raw,
            1024 + (count + 1) * 128,
            "Payload",
            2,
            FREE,
            FREE,
            END,
            0,
        );
        raw
    }

    #[test]
    fn mini_streams_preserve_hierarchy_bytes_and_cabinets_in_both_sector_versions() {
        for version in [3, 4] {
            let raw = small(version);
            let result = inspect(&raw).unwrap();
            assert_eq!(result.stream_count, 2);
            assert_eq!(result.stream_bytes_read, 76);
            assert_eq!(result.streams[0].path, ["Binary", "Cabinet"]);
            assert_eq!(result.streams[0].data, b"MSCF\0\xff");
            assert_eq!(result.streams[0].kind, StreamType::Cabinet);
            assert_eq!(result.streams[1].data, (0_u8..70).collect::<Vec<_>>());
            assert!(result.omissions.is_empty());
            let json = serde_json::to_string(&result).unwrap();
            assert!(!json.contains("\"data\":"));
            assert!(json.contains("not unpacked"));
        }
    }

    #[test]
    fn cutoff_stream_uses_regular_fat_and_retains_exact_cabinet_bytes() {
        for version in [3, 4] {
            let result = inspect(&regular(version)).unwrap();
            assert_eq!(result.stream_count, 1);
            assert_eq!(result.streams[0].size, 4096);
            assert_eq!(result.streams[0].data.len(), 4096);
            assert_eq!(&result.streams[0].data[..4], b"MSCF");
            assert_eq!(result.streams[0].kind, StreamType::Cabinet);
            assert_eq!(
                result.streams[0].sha256,
                format!("{:x}", Sha256::digest(&result.streams[0].data))
            );
        }
    }

    #[test]
    fn extended_difat_is_followed_and_cycles_duplicates_and_bad_markers_fail() {
        let raw = extended_difat();
        assert_eq!(inspect(&raw).unwrap().stream_count, 0);
        let mut bad = raw.clone();
        put32(&mut bad, 113 * 512 - 4, 111);
        assert!(inspect(&bad).is_err());
        let mut bad = raw.clone();
        put32(&mut bad, 112 * 512, 0);
        assert!(inspect(&bad).is_err());
        let mut bad = raw.clone();
        put32(&mut bad, 512 + 111 * 4, END);
        assert!(inspect(&bad).is_err());
        let mut bad = raw.clone();
        put32(&mut bad, 72, u32::MAX);
        assert!(inspect(&bad).is_err());
    }

    #[test]
    fn fat_and_minifat_cycles_shared_sectors_and_overlong_chains_are_rejected() {
        let raw = small(3);
        for (offset, value) in [
            (512 + 3 * 4, 3),
            (512 + 3 * 4, 1),
            (512 + 2 * 4, FREE),
            (1536, 0),
            (1536 + 4, 0),
            (1024 + 384 + 116, 0),
        ] {
            let mut bad = raw.clone();
            put32(&mut bad, offset, value);
            assert!(inspect(&bad).is_err(), "offset{offset}");
        }
        let raw = regular(3);
        for (offset, value) in [
            (512 + 2 * 4, END),
            (512 + 9 * 4, 2),
            (512 + 2 * 4, 0xffff_fffa),
            (1024 + 128 + 116, 0),
        ] {
            let mut bad = raw.clone();
            put32(&mut bad, offset, value);
            assert!(inspect(&bad).is_err(), "offset{offset}");
        }
    }

    #[test]
    fn directory_graph_names_and_declared_sizes_are_checked_before_exposing_streams() {
        let raw = small(3);
        for (offset, value) in [
            (1024 + 76, FREE),
            (1024 + 128 + 76, 1),
            (1024 + 384 + 72, 1),
            (1024 + 256 + 76, 3),
            (1024 + 384 + 116, u32::MAX),
        ] {
            let mut bad = raw.clone();
            put32(&mut bad, offset, value);
            assert!(inspect(&bad).is_err(), "offset{offset}");
        }
        let mut bad = raw.clone();
        put16(&mut bad, 1024 + 256, 0xd800);
        assert!(inspect(&bad).is_err());
        let mut bad = raw.clone();
        put16(&mut bad, 1024 + 256 + 64, 65);
        assert!(inspect(&bad).is_err());
        let mut bad = raw.clone();
        put16(&mut bad, 1024 + 256, '/' as u16);
        assert!(inspect(&bad).is_err());
        let mut bad = raw.clone();
        put64(&mut bad, 1024 + 256 + 120, u64::MAX);
        assert!(inspect(&bad).is_err());
        let mut bad = small(4);
        put64(&mut bad, 8192 + 256 + 120, u64::MAX);
        assert!(inspect(&bad).is_err());
    }

    #[test]
    fn every_truncation_and_inconsistent_header_fails_without_partial_success() {
        for version in [3, 4] {
            let raw = small(version);
            for length in 0..raw.len() {
                assert!(
                    inspect(&raw[..length]).is_err(),
                    "version{version} length{length}"
                );
            }
            for (offset, value) in [(28, 0), (30, 15), (32, 9)] {
                let mut bad = raw.clone();
                put16(&mut bad, offset, value);
                assert!(inspect(&bad).is_err());
            }
            let mut bad = raw.clone();
            put32(&mut bad, 44, u32::MAX);
            assert!(inspect(&bad).is_err());
            let mut bad = raw.clone();
            put32(&mut bad, 56, 512);
            assert!(inspect(&bad).is_err());
        }
    }

    #[test]
    fn generated_directory_count_and_storage_depth_limits_reject_excess_without_recursion() {
        let permitted = inspect(&empty_streams(MAX_STREAMS)).unwrap();
        assert_eq!(permitted.stream_count, MAX_STREAMS);
        assert_eq!(permitted.stream_bytes_read, 0);
        assert!(inspect(&empty_streams(MAX_STREAMS + 1)).is_err());
        let permitted = inspect(&deep_storages(MAX_STORAGE_DEPTH - 1)).unwrap();
        assert_eq!(permitted.streams[0].path.len(), MAX_STORAGE_DEPTH);
        assert!(inspect(&deep_storages(MAX_STORAGE_DEPTH)).is_err());
    }
}
