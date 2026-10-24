//! Bounded PE evidence carving; none of these outputs certify driver unpacking.
//!
//! This follows the legacy artifact scanner's raw-end and mapped-image evidence
//! rules. It does not load code, resolve imports, apply relocations, alter the
//! preferred ImageBase, repair headers/checksums/IAT, or write host paths. A PE
//! capture is structural evidence; executable validity remains the loader's job.
//! PE32/PE32+ headers and at most96 complete section rows are supported. Weird
//! loader alignments/import contents remain opaque, as in legacy fast carving.
//! Extra candidate/work/retained-byte bounds stop adversarial overlapping input
//! with explicit omissions, rather than claiming an exhaustive completed scan.
//! The host/worker artifact filesystem/report adapter remains separate.

use crate::capture_profile::CaptureProfile;
use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_SCAN_BYTES: usize = 128 * 1024 * 1024;
pub const MAX_ARTIFACT_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_RETAINED_BYTES: usize = 128 * 1024 * 1024;
const MAX_CANDIDATES: usize = 10_000;
#[cfg(test)]
const MAX_WORK_BYTES: u64 = 256 * 1024 * 1024;
const MAX_OBSERVATIONS: usize = 10_000;
const MAX_MANIFEST_BYTES: usize = 1024 * 1024;

#[derive(Debug, thiserror::Error)]
#[error("Invalid carving options: {0}")]
pub struct CarveError(pub &'static str);

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum CaptureKind {
    Pe,
    Memory,
}

#[derive(Debug, Serialize)]
pub struct Payload {
    pub sha256: String,
    pub size: usize,
    #[serde(skip)]
    pub data: Vec<u8>,
}

#[derive(Debug, Serialize)]
pub struct Observation {
    #[serde(skip)]
    pub payload: usize,
    pub sha256: String,
    pub size: usize,
    pub kind: CaptureKind,
    pub source: String,
    pub guest_path: String,
    /// Content-addressed display name only; no file is created by this module.
    pub file: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<Map<String, Value>>,
}

#[derive(Debug, Serialize)]
pub struct Omission {
    pub source: String,
    pub reason: &'static str,
    pub bytes: u64,
}

#[derive(Debug, Default, Serialize)]
pub struct Omitted {
    pub omitted_observations: u64,
    pub omitted_bytes: u64,
    pub reasons: BTreeMap<&'static str, u64>,
    pub examples: Vec<Omission>,
}
impl Omitted {
    fn note(&mut self, source: &str, bytes: usize, reason: &'static str) {
        if bytes == 0 {
            return;
        }
        self.omitted_observations = self.omitted_observations.saturating_add(1);
        self.omitted_bytes = self.omitted_bytes.saturating_add(bytes as u64);
        *self.reasons.entry(reason).or_default() += 1;
        if self.examples.len() < 20 {
            self.examples.push(Omission {
                source: source.chars().take(256).collect(),
                reason,
                bytes: bytes as u64,
            });
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Scan {
    #[serde(skip)]
    profile: CaptureProfile,
    pub scanned_bytes: usize,
    pub scan_complete: bool,
    pub header_candidates: usize,
    pub structurally_rejected: usize,
    pub work_bytes_reserved: u64,
    pub payloads: Vec<Payload>,
    pub observations: Vec<Observation>,
    pub artifact_capture: Omitted,
    pub scope: &'static str,
    #[serde(skip)]
    retained_bytes: usize,
    #[serde(skip)]
    manifest_bytes: usize,
    #[serde(skip)]
    payload_indices: BTreeMap<String, usize>,
    #[serde(skip)]
    seen: BTreeSet<String>,
}

#[derive(Debug)]
struct Section {
    raw: usize,
    rva: usize,
    size: usize,
}
#[derive(Debug)]
struct Layout {
    end: usize,
    image_size: usize,
    sections: Vec<Section>,
}

fn u16_at(raw: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        raw.get(at..at.checked_add(2)?)?.try_into().ok()?,
    ))
}
fn u32_at(raw: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        raw.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}

// Structural extraction deliberately does not call PeImage::parse: its loader
// rejects alignments/imports that legacy pefile(fast_load=True) merely preserves.
fn layout_with_profile(raw: &[u8], profile: CaptureProfile) -> Option<Layout> {
    if raw.len() < 512 || raw.get(..2)? != b"MZ" {
        return None;
    }
    let pe = u32_at(raw, 0x3c)? as usize;
    if raw.get(pe..pe.checked_add(4)?)? != b"PE\0\0" {
        return None;
    }
    let count = u16_at(raw, pe.checked_add(6)?)? as usize;
    if !(1..=96).contains(&count) {
        return None;
    }
    let optional_size = u16_at(raw, pe.checked_add(20)?)? as usize;
    let optional = pe.checked_add(24)?;
    let header = raw.get(optional..optional.checked_add(optional_size)?)?;
    let minimum = match u16_at(header, 0)? {
        0x10b => 96,
        0x20b => 112,
        _ => return None,
    };
    if optional_size < minimum {
        return None;
    }
    let image_size = u32_at(header, 56)? as usize;
    let headers = u32_at(header, 60)? as usize;
    if profile == CaptureProfile::Driver128V1 && image_size > profile.limits().single {
        return None;
    }
    if image_size == 0 || headers == 0 || headers > raw.len() {
        return None;
    }
    let table = optional.checked_add(optional_size)?;
    raw.get(table..table.checked_add(count.checked_mul(40)?)?)?;
    let mut end = headers;
    let mut sections = Vec::with_capacity(count);
    for index in 0..count {
        let at = table.checked_add(index.checked_mul(40)?)?;
        let size = u32_at(raw, at + 16)? as usize;
        let raw_offset = u32_at(raw, at + 20)? as usize;
        end = end.max(raw_offset.checked_add(size)?);
        sections.push(Section {
            raw: raw_offset,
            rva: u32_at(raw, at + 12)? as usize,
            size,
        });
    }
    if end == 0 || end > raw.len() || end > profile.limits().single {
        return None;
    }
    Some(Layout {
        end,
        image_size,
        sections,
    })
}

fn ascii_compact_len(value: &Value) -> Option<usize> {
    let json = serde_json::to_string(value).ok()?;
    Some(
        json.chars()
            .map(|c| {
                if c as u32 >= 0x7f {
                    if c as u32 > 0xffff { 12 } else { 6 }
                } else {
                    1
                }
            })
            .sum(),
    )
}

impl Scan {
    pub fn profile(&self) -> CaptureProfile {
        self.profile
    }

    fn add_payload(
        &mut self,
        raw: Cow<'_, [u8]>,
        kind: CaptureKind,
        source: &str,
        context: Option<&Map<String, Value>>,
    ) {
        let bytes = raw.as_ref();
        let length = raw.len();
        if raw.is_empty() {
            return;
        }
        if length > self.profile.limits().single {
            self.artifact_capture
                .note(source, length, "artifact_size_limit");
            return;
        }
        let sha256 = format!("{:x}", Sha256::digest(bytes));
        let file = format!(
            "{}.{}",
            &sha256[..20],
            if kind == CaptureKind::Pe { "pe" } else { "bin" }
        );
        let context = context.filter(|c| !c.is_empty()).cloned();
        let mut record = serde_json::json!({"sha256":sha256,"size":length,"kind":kind,"source":source,"guest_path":"","file":file});
        if let Some(context) = &context {
            record["context"] = Value::Object(context.clone());
        }
        let key = serde_json::to_string(&record).expect("bounded evidence serializes");
        if self.seen.contains(&key) {
            return;
        }
        if self.observations.len() >= MAX_OBSERVATIONS {
            self.artifact_capture
                .note(source, length, "artifact_observation_limit");
            return;
        }
        let size = ascii_compact_len(&record).expect("bounded evidence serializes");
        let separator = usize::from(!self.observations.is_empty());
        if self
            .manifest_bytes
            .checked_add(size)
            .and_then(|n| n.checked_add(separator))
            .is_none_or(|n| n > MAX_MANIFEST_BYTES)
        {
            self.artifact_capture
                .note(source, length, "artifact_manifest_limit");
            return;
        }
        let payload = if let Some(index) = self.payload_indices.get(&sha256) {
            *index
        } else {
            if length > self.profile.limits().retained - self.retained_bytes {
                self.artifact_capture
                    .note(source, length, "capture_total_limit");
                return;
            }
            let index = self.payloads.len();
            self.payload_indices.insert(sha256.clone(), index);
            self.retained_bytes += length;
            self.payloads.push(Payload {
                sha256: sha256.clone(),
                size: length,
                data: raw.into_owned(),
            });
            index
        };
        self.manifest_bytes += size + separator;
        self.seen.insert(key);
        self.observations.push(Observation {
            payload,
            sha256,
            size: length,
            kind,
            source: source.to_owned(),
            guest_path: String::new(),
            file,
            context,
        });
    }
}

/// Carve a bounded memory/blob view, preserving exact bytes and observation
/// provenance. `context` is display-only, never a source of executable repairs.
pub fn scan(
    blob: &[u8],
    source: &str,
    skip_offset_zero: bool,
    context: Option<&Map<String, Value>>,
) -> Result<Scan, CarveError> {
    scan_with_profile(
        blob,
        source,
        skip_offset_zero,
        context,
        CaptureProfile::Legacy32V1,
    )
}
pub fn scan_with_profile(
    blob: &[u8],
    source: &str,
    skip_offset_zero: bool,
    context: Option<&Map<String, Value>>,
    profile: CaptureProfile,
) -> Result<Scan, CarveError> {
    scan_with_budget(
        blob,
        source,
        skip_offset_zero,
        context,
        profile,
        profile.limits().scan,
        profile.limits().work,
    )
}
pub fn scan_with_budget(
    blob: &[u8],
    source: &str,
    skip_offset_zero: bool,
    context: Option<&Map<String, Value>>,
    profile: CaptureProfile,
    scan_limit: usize,
    work_limit: u64,
) -> Result<Scan, CarveError> {
    scan_with_layout_budget(
        blob,
        source,
        skip_offset_zero,
        context,
        profile,
        ScanBudget {
            scan_limit,
            work_limit,
            root_layout: RootLayout::Unknown,
        },
    )
}
#[derive(Clone, Copy)]
enum RootLayout {
    Unknown,
    MappedImage,
}
struct ScanBudget {
    scan_limit: usize,
    work_limit: u64,
    root_layout: RootLayout,
}
fn scan_with_layout_budget(
    blob: &[u8],
    source: &str,
    skip_offset_zero: bool,
    context: Option<&Map<String, Value>>,
    profile: CaptureProfile,
    budget: ScanBudget,
) -> Result<Scan, CarveError> {
    let ScanBudget {
        scan_limit,
        work_limit,
        root_layout,
    } = budget;
    if matches!(root_layout, RootLayout::MappedImage) && profile != CaptureProfile::Driver128V1 {
        return Err(CarveError("Explicit mapped root requires Driver128"));
    }
    if scan_limit > profile.limits().scan || work_limit > profile.limits().work {
        return Err(CarveError("aggregate scan/work bounds"));
    }

    if source.chars().count() > 4000 {
        return Err(CarveError("source label exceeds4000characters"));
    }
    if context.is_some_and(|c| serde_json::to_vec(c).map_or(true, |v| v.len() > MAX_MANIFEST_BYTES))
    {
        return Err(CarveError("context exceeds manifest byte bound"));
    }
    let length = blob.len().min(scan_limit);
    let raw = &blob[..length];
    let mut result = Scan {
        profile,
        scanned_bytes: length,
        scan_complete: blob.len() <= scan_limit,
        header_candidates: 0,
        structurally_rejected: 0,
        work_bytes_reserved: 0,
        payloads: Vec::new(),
        observations: Vec::new(),
        artifact_capture: Omitted::default(),
        scope: "Carved structural PE/memory evidence; not confirmed unpacking or executable validity",
        retained_bytes: 0,
        manifest_bytes: 2,
        payload_indices: BTreeMap::new(),
        seen: BTreeSet::new(),
    };
    if blob.len() > length {
        result
            .artifact_capture
            .note(source, blob.len() - length, "memory_scan_input_limit");
    }
    let mut at = usize::from(skip_offset_zero);
    while at.checked_add(1).is_some_and(|end| end < raw.len()) {
        if raw[at..at + 2] != *b"MZ" {
            at += 1;
            continue;
        }
        let offset = at;
        at += 2;
        let candidate_len = (raw.len() - offset).min(profile.limits().single);
        if candidate_len < 0x40 {
            break;
        }
        let candidate = &raw[offset..offset + candidate_len];
        let pe = u32_at(candidate, 0x3c).expect("prefilter header available") as usize;
        if pe > candidate_len - 24 || candidate.get(pe..pe + 4) != Some(b"PE\0\0".as_slice()) {
            continue;
        }
        if result.header_candidates == MAX_CANDIDATES {
            result
                .artifact_capture
                .note(source, raw.len() - offset, "pe_candidate_limit");
            result.scan_complete = false;
            break;
        }
        result.header_candidates += 1;
        let Some(layout) = layout_with_profile(candidate, profile) else {
            result.structurally_rejected += 1;
            continue;
        };
        if profile == CaptureProfile::Driver128V1
            && layout.sections.iter().enumerate().any(|(i, a)| {
                layout.sections[..i].iter().any(|b| {
                    a.size > 0
                        && b.size > 0
                        && (a.raw < b.raw.saturating_add(b.size)
                            && b.raw < a.raw.saturating_add(a.size)
                            || a.rva < b.rva.saturating_add(b.size)
                                && b.rva < a.rva.saturating_add(a.size))
                })
            })
        {
            result.structurally_rejected += 1;
            continue;
        }
        let mapped_possible = layout.image_size <= candidate.len()
            && layout.image_size <= profile.limits().single
            && layout.sections.iter().all(|s| {
                s.size == 0
                    || s.raw.checked_add(s.size).is_some_and(|e| e <= layout.end)
                        && s.rva
                            .checked_add(s.size)
                            .is_some_and(|e| e <= layout.image_size)
            });
        let declared_mapped_root = offset == 0 && matches!(root_layout, RootLayout::MappedImage);
        if declared_mapped_root && (!mapped_possible || layout.image_size != blob.len()) {
            result.structurally_rejected += 1;
            result
                .artifact_capture
                .note(source, blob.len(), "mapped_root_extent_invalid");
            continue;
        }
        let span_work = if mapped_possible {
            layout
                .sections
                .iter()
                .map(|s| s.size as u64 * 2)
                .sum::<u64>()
        } else {
            0
        };
        let work = layout.end as u64 * 2
            + span_work
            + if mapped_possible {
                layout.image_size as u64 * 2 + layout.end as u64
            } else {
                0
            };
        if work > work_limit - result.work_bytes_reserved {
            result
                .artifact_capture
                .note(source, raw.len() - offset, "carving_work_byte_limit");
            result.scan_complete = false;
            break;
        }
        result.work_bytes_reserved += work;
        let mapped = mapped_possible
            && (declared_mapped_root
                || layout.sections.iter().any(|s| {
                    s.size > 0
                        && s.raw != s.rva
                        && candidate[s.raw..s.raw + s.size].iter().all(|b| *b == 0)
                        && candidate[s.rva..s.rva + s.size].iter().any(|b| *b != 0)
                }));
        // The caller-authorized whole mapped root has its own exact source
        // identity. Embedded candidates retain their offset-qualified labels.
        let label = if declared_mapped_root {
            source.to_owned()
        } else {
            format!("{source}@0x{offset:x}")
        };
        if mapped {
            let mut recovered = candidate[..layout.end].to_vec();
            for section in layout.sections.iter().filter(|s| s.size > 0) {
                recovered[section.raw..section.raw + section.size]
                    .copy_from_slice(&candidate[section.rva..section.rva + section.size]);
            }
            let mut details = context.cloned().unwrap_or_default();
            details.insert(
                "layout".to_owned(),
                Value::String("mapped_image".to_owned()),
            );
            details.insert(
                "reconstruction".to_owned(),
                Value::String("section_rva_to_raw".to_owned()),
            );
            details.insert("image_size".to_owned(), Value::from(layout.image_size));
            if declared_mapped_root {
                details.insert(
                    "layout_authority".into(),
                    Value::String("caller_verified_root_mapping".into()),
                );
            }
            if profile == CaptureProfile::Driver128V1 {
                details.insert("raw_end".into(), Value::from(layout.end));
                details.insert("source_offset".into(), Value::from(offset));
                details.insert(
                    "source_snapshot_sha256".into(),
                    Value::String(format!(
                        "{:x}",
                        Sha256::digest(&candidate[..layout.image_size])
                    )),
                );
                details.insert("section_extents".into(),serde_json::json!(layout.sections.iter().map(|s|serde_json::json!({"rva":s.rva,"raw_offset":s.raw,"size":s.size})).collect::<Vec<_>>()));
            }
            result.add_payload(
                Cow::Borrowed(&candidate[..layout.image_size]),
                CaptureKind::Memory,
                &label,
                Some(&details),
            );
            result.add_payload(
                Cow::Owned(recovered),
                CaptureKind::Pe,
                &label,
                Some(&details),
            );
        } else {
            result.add_payload(
                Cow::Borrowed(&candidate[..layout.end]),
                CaptureKind::Pe,
                &label,
                context,
            );
        }
    }
    Ok(result)
}

/// Owned driver capture drops the input on return; exact whole-input evidence
/// reuses its allocation. Legacy scan remains an unchanged borrowing wrapper.
pub fn scan_owned_with_profile(
    blob: Vec<u8>,
    source: &str,
    skip_offset_zero: bool,
    context: Option<&Map<String, Value>>,
    profile: CaptureProfile,
) -> Result<Scan, CarveError> {
    let mut result = scan_with_profile(&blob, source, skip_offset_zero, context, profile)?;
    let label = format!("{source}@0x0");
    if let Some(index) = result
        .observations
        .iter()
        .find(|o| {
            o.source == label
                && o.size == blob.len()
                && (o.kind == CaptureKind::Memory
                    || o.context
                        .as_ref()
                        .and_then(|c| c.get("layout"))
                        .and_then(Value::as_str)
                        != Some("mapped_image"))
        })
        .map(|o| o.payload)
    {
        result.payloads[index].data = blob;
    }
    Ok(result)
}

pub fn scan_owned_budgeted(
    blob: Vec<u8>,
    source: &str,
    context: Option<&Map<String, Value>>,
    profile: CaptureProfile,
    scan_limit: usize,
    work_limit: u64,
    retain_memory: bool,
) -> Result<Scan, CarveError> {
    let mut result = scan_with_budget(
        &blob, source, false, context, profile, scan_limit, work_limit,
    )?;
    let label = format!("{source}@0x0");
    let existing = result
        .observations
        .iter()
        .find(|o| o.source == label && o.kind == CaptureKind::Memory && o.size == blob.len())
        .map(|o| o.payload);
    if let Some(index) = existing {
        result.payloads[index].data = blob;
    } else if retain_memory {
        result.add_payload(Cow::Owned(blob), CaptureKind::Memory, &label, context);
    }
    Ok(result)
}

/// Only callers that acquired one complete mapped root may select this route.
/// Memory origin/context strings alone are not mapping authority. Other MZ
/// offsets still use legacy inference. Invalid root metadata retains the full
/// owned snapshot with an omission rather than inventing raw reconstruction.
pub fn scan_owned_mapped_root(
    blob: Vec<u8>,
    source: &str,
    context: Option<&Map<String, Value>>,
    profile: CaptureProfile,
    scan_limit: usize,
    work_limit: u64,
) -> Result<Scan, CarveError> {
    let mut result = scan_with_layout_budget(
        &blob,
        source,
        false,
        context,
        profile,
        ScanBudget {
            scan_limit,
            work_limit,
            root_layout: RootLayout::MappedImage,
        },
    )?;
    let label = source;
    if let Some(index) = result
        .observations
        .iter()
        .find(|o| o.source == label && o.kind == CaptureKind::Memory && o.size == blob.len())
        .map(|o| o.payload)
    {
        result.payloads[index].data = blob;
    } else {
        if result.artifact_capture.omitted_observations == 0 {
            result.artifact_capture.note(
                source,
                blob.len(),
                "mapped_root_reconstruction_unavailable",
            );
        }
        result.add_payload(Cow::Owned(blob), CaptureKind::Memory, label, context);
    }
    Ok(result)
}

#[cfg(test)]
#[path = "pe_carve/layout_tests.rs"]
mod layout_tests;
#[cfg(test)]
mod tests {
    use super::*;

    fn put16(raw: &mut [u8], at: usize, value: u16) {
        raw[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn put32(raw: &mut [u8], at: usize, value: u32) {
        raw[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn fixture() -> Vec<u8> {
        let mut raw = vec![0_u8; 1024];
        raw[..2].copy_from_slice(b"MZ");
        put32(&mut raw, 0x3c, 0x80);
        raw[0x80..0x84].copy_from_slice(b"PE\0\0");
        put16(&mut raw, 0x84, 0x8664);
        put16(&mut raw, 0x86, 1);
        put16(&mut raw, 0x94, 0xf0);
        put16(&mut raw, 0x98, 0x20b);
        put32(&mut raw, 0x98 + 16, 0x1000);
        put32(&mut raw, 0x98 + 32, 0x1000);
        put32(&mut raw, 0x98 + 36, 0x200);
        put32(&mut raw, 0x98 + 56, 0x2000);
        put32(&mut raw, 0x98 + 60, 0x200);
        let section = 0x188;
        raw[section..section + 8].copy_from_slice(b".owned\0\0");
        put32(&mut raw, section + 8, 0x200);
        put32(&mut raw, section + 12, 0x1000);
        put32(&mut raw, section + 16, 0x200);
        put32(&mut raw, section + 20, 0x200);
        raw[512..].fill(0x52);
        raw
    }

    #[test]
    fn many_false_mz_pairs_do_not_reach_parser_and_real_embedded_pe_is_retained() {
        let mut packed = vec![0_u8; 8 * 1024 * 1024];
        for offset in (0..packed.len()).step_by(1024) {
            packed[offset..offset + 2].copy_from_slice(b"MZ");
        }
        let raw = fixture();
        packed.extend_from_slice(&raw);
        let result = scan(&packed, "packed", false, None).unwrap();
        assert_eq!(result.header_candidates, 1);
        assert_eq!(result.observations.len(), 1);
        assert_eq!(result.payloads[0].data, raw);
        assert_eq!(result.observations[0].source, "packed@0x800000");
    }

    #[test]
    fn reconstruction_requires_zero_raw_nonzero_rva_and_preserves_unmodified_header() {
        let raw = fixture();
        let mut image = vec![0_u8; 0x2000];
        image[..512].copy_from_slice(&raw[..512]);
        image[0x1000..0x1200].copy_from_slice(&raw[512..]);
        let mut context = Map::new();
        context.insert("layout".into(), Value::String("caller".into()));
        context.insert("fixture".into(), Value::Bool(true));
        let result = scan(&image, "memory", false, Some(&context)).unwrap();
        assert_eq!(result.observations.len(), 2);
        assert_eq!(result.observations[0].kind, CaptureKind::Memory);
        assert_eq!(result.observations[1].kind, CaptureKind::Pe);
        assert_eq!(result.payloads[result.observations[0].payload].data, image);
        assert_eq!(result.payloads[result.observations[1].payload].data, raw);
        for item in &result.observations {
            assert_eq!(item.context.as_ref().unwrap()["layout"], "mapped_image");
            assert_eq!(
                item.context.as_ref().unwrap()["reconstruction"],
                "section_rva_to_raw"
            );
            assert_eq!(item.context.as_ref().unwrap()["fixture"], true);
        }
        image[512] = 1;
        let result = scan(&image, "ambiguous", false, None).unwrap();
        assert_eq!(result.observations.len(), 1);
        assert!(result.observations[0].context.is_none());
    }

    #[test]
    fn duplicate_bytes_keep_distinct_offsets_but_share_retained_payload() {
        let raw = fixture();
        let mut blob = raw.clone();
        blob.extend_from_slice(b"padding");
        blob.extend_from_slice(&raw);
        let result = scan(&blob, "stages", false, None).unwrap();
        assert_eq!(result.payloads.len(), 1);
        assert_eq!(result.observations.len(), 2);
        assert_ne!(result.observations[0].source, result.observations[1].source);
        assert_eq!(
            result.observations[0].payload,
            result.observations[1].payload
        );
        let result = scan(&blob, "stages", true, None).unwrap();
        assert_eq!(result.observations.len(), 1);
        assert_eq!(result.observations[0].source, "stages@0x407");
    }

    #[test]
    fn truncation_bad_extents_and_section_counts_never_produce_fabricated_files() {
        let raw = fixture();
        for length in 0..raw.len() {
            assert!(
                scan(&raw[..length], "short", false, None)
                    .unwrap()
                    .observations
                    .is_empty()
            );
        }
        for (offset, value) in [
            (0x3c, u32::MAX),
            (0x98 + 56, 0),
            (0x188 + 20, u32::MAX),
            (0x188 + 16, u32::MAX),
        ] {
            let mut bad = raw.clone();
            put32(&mut bad, offset, value);
            assert!(
                scan(&bad, "bad", false, None)
                    .unwrap()
                    .observations
                    .is_empty()
            );
        }
        let mut bad = raw;
        put16(&mut bad, 0x86, 97);
        assert!(
            scan(&bad, "many-sections", false, None)
                .unwrap()
                .observations
                .is_empty()
        );
    }

    #[test]
    fn adversarial_overlapping_pe_candidates_stop_with_explicit_work_omission() {
        let raw = fixture();
        let mut packed = Vec::new();
        for _ in 0..MAX_CANDIDATES + 1 {
            packed.extend_from_slice(&raw);
        }
        let result = scan(&packed, "repeated", false, None).unwrap();
        assert!(!result.scan_complete);
        assert!(
            result
                .artifact_capture
                .reasons
                .contains_key("carving_work_byte_limit")
                || result
                    .artifact_capture
                    .reasons
                    .contains_key("pe_candidate_limit")
        );
        assert!(result.work_bytes_reserved <= MAX_WORK_BYTES);
        assert!(
            result.retained_bytes <= MAX_RETAINED_BYTES
                && result.manifest_bytes <= MAX_MANIFEST_BYTES
        );
    }

    #[test]
    fn metadata_omissions_and_scan_limits_are_reported_without_success_invention() {
        let mut context = Map::new();
        context.insert("label".into(), Value::String("😀".repeat(100_000)));
        let result = scan(&fixture(), "context", false, Some(&context)).unwrap();
        assert!(result.observations.is_empty());
        assert_eq!(
            result.artifact_capture.reasons["artifact_manifest_limit"],
            1
        );
        assert!(scan(&fixture(), &"x".repeat(4001), false, None).is_err());
        let serialized = serde_json::to_string(&result).unwrap();
        assert!(!serialized.contains("\"data\":"));
    }
}
