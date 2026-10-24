//! Strict separate Driver128 evidence envelope. No unpacking certification.
use crate::{
    artifacts::{ArtifactCatalog, ArtifactKind, valid_observation_json_with_profile},
    capture_profile::CaptureProfile,
    report_bundle::{bounded_json, digest},
    reports,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
pub const PROFILE: &str = "driver128_v1";
pub const SCHEMA: &str = "emumee.driver_capture.v1";
const MIB: usize = 1024 * 1024;
#[derive(Debug, thiserror::Error)]
#[error("Driver128 report: {0}")]
pub struct Error(pub &'static str);
type Result<T> = std::result::Result<T, Error>;
fn check(ok: bool, reason: &'static str) -> Result<()> {
    if ok { Ok(()) } else { Err(Error(reason)) }
}
fn encode(value: &impl Serialize, limit: usize) -> Result<Vec<u8>> {
    bounded_json(value, limit).map_err(|_| Error("JSON byte budget"))
}
fn sha(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub request_sha256: String,
    pub input_sha256: String,
    pub input_bytes: u64,
    pub recipe: String,
    pub source_tree_sha256: String,
    pub containment_sha256: String,
}
impl Binding {
    /// Project a bounded general request into the existing Driver128 report identity.
    /// This verifies request identity against owned intake and projects a report
    /// binding only. It never authorizes execution. The parent must still re-read
    /// staged bytes before expecting a worker report.
    pub fn for_general_commitment(
        raw_request: &[u8],
        intake: &crate::analysis_plan::PreparedIntake,
        source_tree_sha256: &str,
        containment_sha256: &str,
    ) -> Result<Self> {
        let request = crate::general_execution_commitment::Request::parse(raw_request)
            .map_err(|_| Error("general commitment schema"))?;
        request
            .verify(intake)
            .map_err(|_| Error("general commitment differs from owned intake"))?;
        Self::project_general_commitment(
            &request,
            raw_request,
            source_tree_sha256,
            containment_sha256,
        )
    }

    fn project_general_commitment(
        request: &crate::general_execution_commitment::Request,
        raw_request: &[u8],
        source_tree_sha256: &str,
        containment_sha256: &str,
    ) -> Result<Self> {
        check(
            request.report_profile == "large_driver_v1",
            "general request is not a large-driver report",
        )?;
        let target = request
            .public_inputs
            .iter()
            .find(|slot| slot.id == request.target_input_id)
            .ok_or(Error("general public target missing"))?;
        check(
            target.size > 0 && target.size <= 128 * MIB as u64,
            "general target exceeds Driver128 report input bound",
        )?;
        let binding = Self {
            request_sha256: digest(raw_request),
            input_sha256: target.sha256.clone(),
            input_bytes: target.size,
            recipe: request.service_name.clone(),
            source_tree_sha256: source_tree_sha256.into(),
            containment_sha256: containment_sha256.into(),
        };
        check(
            binding.valid() && crate::driver_input::service_name_valid(&binding.recipe),
            "general Driver128 report binding invalid",
        )?;
        Ok(binding)
    }

    fn valid(&self) -> bool {
        [
            &self.request_sha256,
            &self.input_sha256,
            &self.source_tree_sha256,
            &self.containment_sha256,
        ]
        .iter()
        .all(|v| sha(v))
            && self.input_bytes <= 128 * MIB as u64
            && !self.recipe.is_empty()
            && self.recipe.len() <= 64
            && self.recipe.is_ascii()
    }
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    StaticGeneratedCapture,
    GeneratedDriverEntry,
    GeneratedDriverCapture,
    SubmittedDriverCapture,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Stop {
    Normal,
    Timeout,
    WorkerFailure,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Chunk {
    offset: u64,
    size: u64,
    sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Projection {
    size: u64,
    sha256: String,
    chunks: Vec<Chunk>,
    preview: String,
    preview_encoding: String,
    pe_header: Option<Value>,
    range_hashes: Vec<Chunk>,
}
/// Safe-read proof cannot be deserialized from a report or constructed by fields.
pub struct VerifiedProjection(Projection);
impl VerifiedProjection {
    pub fn from_bytes(raw: &[u8]) -> Result<Self> {
        Projection::from_bytes(raw).map(Self)
    }
    pub fn from_reader(
        length: u64,
        read: impl FnMut(u64, usize) -> Option<Vec<u8>>,
    ) -> Result<Self> {
        Projection::from_reader(length, read).map(Self)
    }
    pub fn for_record(
        record: &Record,
        read: impl FnMut(u64, usize) -> Option<Vec<u8>>,
    ) -> Result<Self> {
        Projection::from_reader_ranges(
            record.size,
            &range_specs(&record.observations, record.size)?,
            read,
        )
        .map(Self)
    }
}
impl Projection {
    pub fn size(&self) -> u64 {
        self.size
    }
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
    pub fn from_bytes(raw: &[u8]) -> Result<Self> {
        Self::from_reader(raw.len() as u64, |offset, count| {
            raw.get(offset as usize..(offset as usize).checked_add(count)?)
                .map(<[u8]>::to_vec)
        })
    }
    /// Caller supplies bounded ranges from one identity-pinned safe handle.
    /// Whole hash/chunks, prefix and structural metadata all use that same source.
    pub fn from_reader(
        length: u64,
        read: impl FnMut(u64, usize) -> Option<Vec<u8>>,
    ) -> Result<Self> {
        Self::from_reader_ranges(length, &[], read)
    }
    fn from_reader_ranges(
        length: u64,
        ranges: &[(u64, u64)],
        mut read: impl FnMut(u64, usize) -> Option<Vec<u8>>,
    ) -> Result<Self> {
        let limits = CaptureProfile::Driver128V1.limits();
        check(
            length > 0 && length <= limits.single as u64,
            "payload length",
        )?;
        let mut hash = Sha256::new();
        let mut chunks = Vec::new();
        let mut offset = 0u64;
        let mut prefix = Vec::new();
        let mut range_hashes = ranges.iter().map(|_| Sha256::new()).collect::<Vec<_>>();
        while offset < length {
            let count = (length - offset).min(limits.chunk as u64) as usize;
            let raw = read(offset, count).ok_or(Error("payload safe read"))?;
            check(raw.len() == count, "short payload read")?;
            if offset == 0 {
                prefix.extend_from_slice(&raw[..raw.len().min(256)]);
            }
            hash.update(&raw);
            for ((start, size), hash) in ranges.iter().zip(&mut range_hashes) {
                let begin = offset.max(*start);
                let end = (offset + count as u64).min(start + size);
                if begin < end {
                    hash.update(&raw[(begin - offset) as usize..(end - offset) as usize]);
                }
            }
            chunks.push(Chunk {
                offset,
                size: count as u64,
                sha256: digest(&raw),
            });
            offset += count as u64;
        }
        let printable = prefix
            .iter()
            .all(|b| b.is_ascii_graphic() || b.is_ascii_whitespace());
        let preview = if printable {
            String::from_utf8(prefix).map_err(|_| Error("prefix text"))?
        } else {
            prefix
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join("")
        };
        let pe_header = header(length, &mut read);
        Ok(Self {
            size: length,
            sha256: format!("{:x}", hash.finalize()),
            chunks,
            preview,
            preview_encoding: if printable { "text" } else { "hex" }.into(),
            pe_header,
            range_hashes: ranges
                .iter()
                .zip(range_hashes)
                .map(|((offset, size), hash)| Chunk {
                    offset: *offset,
                    size: *size,
                    sha256: format!("{:x}", hash.finalize()),
                })
                .collect(),
        })
    }
}
fn range_specs(observations: &[Value], length: u64) -> Result<Vec<(u64, u64)>> {
    let mut ranges = BTreeSet::new();
    for observation in observations {
        let context = &observation["context"];
        if observation["kind"] == "memory_snapshot" {
            if let Some(markers) = context.get("runtime_marker_rvas") {
                let markers = markers.as_array().ok_or(Error("runtime marker list"))?;
                check(markers.len() <= 2, "runtime marker count")?;
                for marker in markers {
                    let offset = marker.as_u64().ok_or(Error("runtime marker RVA"))?;
                    check(offset < length, "runtime marker bounds")?;
                    ranges.insert((offset, 1));
                }
            }
        }
        let Some(segments) = context.get("reconstruction_segments") else {
            continue;
        };
        let segments = segments
            .as_array()
            .ok_or(Error("reconstruction segment list"))?;
        check(segments.len() <= 193, "reconstruction segment count")?;
        let source = observation["kind"] == "memory_snapshot";
        for segment in segments {
            let offset = segment[if source { "source" } else { "destination" }]
                .as_u64()
                .ok_or(Error("range offset"))?;
            let size = segment["size"].as_u64().ok_or(Error("range size"))?;
            check(
                size > 0 && offset.checked_add(size).is_some_and(|n| n <= length),
                "range bounds",
            )?;
            ranges.insert((offset, size));
        }
    }
    check(ranges.len() <= 512, "range work count")?;
    let work = ranges
        .iter()
        .try_fold(0u64, |n, (_, size)| n.checked_add(*size))
        .ok_or(Error("range work overflow"))?;
    check(work <= 256 * MIB as u64, "range hash work")?;
    Ok(ranges.into_iter().collect())
}
fn reconstruction_bindings(records: &[Record]) -> Result<()> {
    for record in records {
        for observation in &record.observations {
            let context = &observation["context"];
            if observation["kind"] != "carved_image" {
                continue;
            }
            if context["source_layout"] != "mapped_image" {
                check(
                    context["layout"] != "mapped_image"
                        && (context["reconstruction"].is_null()
                            || context["reconstruction"] == "none")
                        && context["source_snapshot_sha256"].is_null(),
                    "unbound reconstruction provenance",
                )?;
                continue;
            }
            check(
                context["layout"] == "raw_file"
                    && context["reconstruction"] == "section_rva_to_raw"
                    && context["structural_only"] == true
                    && context["no_fixups"] == true,
                "reconstruction method",
            )?;
            let hash = context["source_snapshot_sha256"]
                .as_str()
                .ok_or(Error("source snapshot digest"))?;
            let snapshot = records
                .iter()
                .find(|r| {
                    r.sha256 == hash
                        && r.observations
                            .iter()
                            .any(|o| o["kind"] == "memory_snapshot")
                })
                .ok_or(Error("source snapshot absent"))?;
            check(
                context["image_size"].as_u64() == Some(snapshot.size)
                    && context["raw_end"].as_u64() == Some(record.size),
                "reconstruction lengths",
            )?;
            let segments = context["reconstruction_segments"]
                .as_array()
                .ok_or(Error("reconstruction segments absent"))?;
            check(
                !segments.is_empty() && segments.len() <= 193,
                "reconstruction segment count",
            )?;
            let mut cursor = 0u64;
            for segment in segments {
                let source = segment["source"].as_u64().ok_or(Error("source segment"))?;
                let destination = segment["destination"]
                    .as_u64()
                    .ok_or(Error("destination segment"))?;
                let size = segment["size"].as_u64().ok_or(Error("segment size"))?;
                check(
                    size > 0
                        && destination == cursor
                        && source.checked_add(size).is_some_and(|n| n <= snapshot.size),
                    "reconstruction ordered complete source coverage",
                )?;
                cursor = cursor
                    .checked_add(size)
                    .ok_or(Error("reconstruction coverage overflow"))?;
                let source_hash = snapshot
                    .projection
                    .range_hashes
                    .iter()
                    .find(|r| r.offset == source && r.size == size)
                    .ok_or(Error("source segment hash absent"))?;
                let destination_hash = record
                    .projection
                    .range_hashes
                    .iter()
                    .find(|r| r.offset == destination && r.size == size)
                    .ok_or(Error("destination segment hash absent"))?;
                check(
                    source_hash.sha256 == destination_hash.sha256,
                    "reconstructed output differs from source ranges",
                )?;
            }
            check(
                cursor == record.size,
                "reconstruction incomplete raw coverage",
            )?;
        }
    }
    Ok(())
}
fn header(length: u64, read: &mut impl FnMut(u64, usize) -> Option<Vec<u8>>) -> Option<Value> {
    fn u16at(raw: &[u8], at: usize) -> Option<u16> {
        Some(u16::from_le_bytes(
            raw.get(at..at.checked_add(2)?)?.try_into().ok()?,
        ))
    }
    fn u32at(raw: &[u8], at: usize) -> Option<u32> {
        Some(u32::from_le_bytes(
            raw.get(at..at.checked_add(4)?)?.try_into().ok()?,
        ))
    }
    if length < 512 {
        return None;
    }
    let dos = read(0, 64)?;
    if dos.len() != 64 {
        return None;
    }
    if dos.get(..2)? != b"MZ" {
        return None;
    }
    let at = u32at(&dos, 60)? as u64;
    if at > length.checked_sub(24)? {
        return None;
    }
    let coff = read(at, 24)?;
    if coff.len() != 24 {
        return None;
    }
    if coff.get(..4)? != b"PE\0\0" {
        return None;
    }
    let count = u16at(&coff, 6)? as usize;
    let optional = u16at(&coff, 20)? as usize;
    if !(1..=96).contains(&count) || !(96..=4096).contains(&optional) {
        return None;
    }
    let size = optional.checked_add(count.checked_mul(40)?)?;
    if at.checked_add(24)?.checked_add(size as u64)? > length {
        return None;
    }
    let raw = read(at + 24, size)?;
    if raw.len() != size {
        return None;
    }
    let magic = u16at(&raw, 0)?;
    if ![0x10b, 0x20b].contains(&magic) || magic == 0x20b && optional < 112 {
        return None;
    }
    let image = u32at(&raw, 56)?;
    if image == 0 || image as usize > CaptureProfile::Driver128V1.limits().single {
        return None;
    }
    let mut sections = Vec::new();
    for index in 0..count {
        let at = optional + 40 * index;
        let name = &raw[at..at + 8];
        let end = name.iter().position(|b| *b == 0).unwrap_or(8);
        sections.push(json!({"name":String::from_utf8_lossy(&name[..end]),"rva":u32at(&raw,at+12)?,"raw_offset":u32at(&raw,at+20)?,"raw_size":u32at(&raw,at+16)?}));
    }
    Some(
        json!({"machine":u16at(&coff,4)?,"optional_magic":magic,"image_size":image,"entry_rva":u32at(&raw,16)?,"sections":sections,"scope":"Bounded structural header/sections only; no import or executable validity claim"}),
    )
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub filename: String,
    pub sha256: String,
    pub size: u64,
    pub observations: Vec<Value>,
    pub projection: Projection,
}
fn record_valid(record: &Record) -> bool {
    sha(&record.sha256)
        && record.filename == format!("{}.bin", record.sha256)
        && record.size > 0
        && record.size <= 128 * MIB as u64
        && record.projection.sha256 == record.sha256
        && record.projection.size == record.size
        && !record.observations.is_empty()
        && record.observations.len() <= 10000
        && record
            .observations
            .iter()
            .all(|o| valid_observation_json_with_profile(o, CaptureProfile::Driver128V1))
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    schema: String,
    profile: String,
    binding: Binding,
    pub payloads: Vec<Record>,
}
impl Manifest {
    pub fn parse(raw: &[u8]) -> Result<Self> {
        check(raw.len() <= MIB, "manifest byte limit")?;
        let value: Self = serde_json::from_slice(raw).map_err(|_| Error("manifest schema"))?;
        check(
            value.schema == "emumee.driver_payloads.v1"
                && value.profile == PROFILE
                && value.binding.valid(),
            "manifest profile/binding",
        )?;
        let mut total = 0u64;
        let mut observations = 0usize;
        let mut metadata = 0usize;
        let mut seen = BTreeSet::new();
        check(value.payloads.len() <= 10000, "payload count")?;
        for record in &value.payloads {
            check(
                record_valid(record) && seen.insert(&record.sha256),
                "payload metadata",
            )?;
            total = total
                .checked_add(record.size)
                .ok_or(Error("payload total overflow"))?;
            observations = observations
                .checked_add(record.observations.len())
                .ok_or(Error("observation overflow"))?;
            for observation in &record.observations {
                metadata = metadata
                    .checked_add(encode(observation, 64 * 1024 + 1024)?.len() + 256)
                    .ok_or(Error("observation metadata overflow"))?;
                check(metadata <= MIB, "observation metadata budget")?;
            }
        }
        check(
            total <= 256 * MIB as u64 && observations <= 10000,
            "catalog total/count",
        )?;
        Ok(value)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Summary {
    schema: String,
    profile: String,
    pub summary: State,
    pub binding: Binding,
    pub engine_sha256: String,
    pub engine_bytes: u64,
    pub network_sha256: String,
    pub network_bytes: u64,
    pub manifest_sha256: String,
    pub checkpoint_sha256: String,
    pub artifacts: Vec<Record>,
    pub omissions: Omissions,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Omissions {
    omitted_observations: u64,
    omitted_bytes: u64,
    reasons: std::collections::BTreeMap<String, u64>,
}
impl Omissions {
    fn from_catalog(catalog: &ArtifactCatalog) -> Self {
        Self {
            omitted_observations: catalog.summary.omitted_observations,
            omitted_bytes: catalog.summary.omitted_bytes,
            reasons: catalog.summary.reasons.clone(),
        }
    }
    fn valid(&self) -> bool {
        let value = crate::artifacts::CaptureSummary {
            omitted_observations: self.omitted_observations,
            omitted_bytes: self.omitted_bytes,
            reasons: self.reasons.clone(),
        };
        ArtifactCatalog::default().merge_omissions(&value)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogRecord {
    filename: String,
    sha256: String,
    size: u64,
    observations: Vec<Value>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub id: String,
    pub status: String,
    pub completion_reason: String,
    pub guest_entry_return: Option<u64>,
    pub instruction_count: u64,
    pub checkpoint_recovered: bool,
    pub guest_trace_complete: bool,
    pub network_broker_complete: bool,
    pub scope: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Engine {
    schema: String,
    profile: String,
    binding: Binding,
    mode: Mode,
    execution: Value,
    catalog: Vec<CatalogRecord>,
    omissions: Omissions,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Network {
    schema: String,
    profile: String,
    coverage: String,
    complete: bool,
}
pub struct Bundle<'a> {
    pub summary: Vec<u8>,
    pub engine: Vec<u8>,
    pub network: Vec<u8>,
    pub manifest: Vec<u8>,
    pub checkpoint: Vec<u8>,
    pub payloads: Vec<(&'a str, &'a [u8])>,
}
fn state(id: &str, mode: Mode, execution: &Value, stop: Stop, recovered: bool) -> Result<State> {
    check(reports::valid_run_id(id), "run identity")?;
    let count = execution["instruction_count"]
        .as_u64()
        .ok_or(Error("instruction evidence"))?;
    let returned = match execution.get("guest_entry_return").filter(|v| !v.is_null()) {
        Some(v) => Some(v.as_u64().ok_or(Error("return evidence type"))?),
        None => None,
    };
    let reason = execution["completion_reason"]
        .as_str()
        .ok_or(Error("completion evidence"))?;
    let (status, completion) = match stop {
        Stop::Timeout => ("timeout", "timeout"),
        Stop::WorkerFailure => ("failed", "worker_failure"),
        Stop::Normal => {
            if matches!(
                mode,
                Mode::GeneratedDriverEntry
                    | Mode::GeneratedDriverCapture
                    | Mode::SubmittedDriverCapture
            ) && reason == "entry_return"
                && returned.is_some()
                && count > 0
                && execution.get("error").is_none_or(Value::is_null)
                && (!matches!(
                    mode,
                    Mode::GeneratedDriverCapture | Mode::SubmittedDriverCapture
                ) || execution["capture_runtime"]["capture_complete"] == true)
            {
                ("completed", "entry_return")
            } else if mode == Mode::StaticGeneratedCapture {
                check(
                    reason == "static_inspection" && count == 0 && returned.is_none(),
                    "static recipe fabricated execution",
                )?;
                ("partial", "static_inspection")
            } else {
                (
                    "partial",
                    if execution.get("error").is_some_and(|value| !value.is_null())
                        || (reason == "entry_return" && (returned.is_none() || count == 0))
                    {
                        "error"
                    } else if matches!(
                        mode,
                        Mode::GeneratedDriverCapture | Mode::SubmittedDriverCapture
                    ) && reason == "entry_return"
                    {
                        "capture_incomplete"
                    } else if reason == "instruction_budget" {
                        "instruction_limit"
                    } else {
                        "error"
                    },
                )
            }
        }
    };
    Ok(State{id:id.into(),status:status.into(),completion_reason:completion.into(),guest_entry_return:returned,instruction_count:count,checkpoint_recovered:recovered,guest_trace_complete:false,network_broker_complete:false,
        scope:if mode == Mode::SubmittedDriverCapture {
            "Submitted x64 driver execution and structural capture evidence only; neither successful initialization nor unpacking is certified"
        } else {
            "Closed synthetic Driver128 capture fixture; structural memory/PE evidence only, never confirmed unpacking or arbitrary driver execution"
        }.into()})
}
pub fn build<'a>(
    id: &str,
    binding: &Binding,
    mode: Mode,
    execution: &Value,
    stop: Stop,
    recovered: bool,
    catalog: &'a ArtifactCatalog,
) -> Result<Bundle<'a>> {
    check(
        binding.valid() && catalog.profile() == CaptureProfile::Driver128V1,
        "binding/catalog profile",
    )?;
    let mut records = Vec::new();
    let mut payloads = Vec::new();
    let mut count = 0usize;
    let mut total = 0usize;
    let mut unique = BTreeSet::new();
    for artifact in &catalog.items {
        check(
            artifact.size == artifact.data.len() && unique.insert(artifact.sha256.as_str()),
            "catalog payload identity",
        )?;
        let observations = artifact
            .observations
            .iter()
            .map(serde_json::to_value)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| Error("observation encoding"))?;
        let projection = Projection::from_reader_ranges(
            artifact.data.len() as u64,
            &range_specs(&observations, artifact.data.len() as u64)?,
            |offset, count| {
                artifact
                    .data
                    .get(offset as usize..(offset as usize).checked_add(count)?)
                    .map(<[u8]>::to_vec)
            },
        )?;
        check(
            projection.sha256 == artifact.sha256
                && artifact.filename == format!("{}.bin", artifact.sha256),
            "actual payload digest/filename",
        )?;
        let record = Record {
            filename: artifact.filename.clone(),
            sha256: artifact.sha256.clone(),
            size: artifact.size as u64,
            observations,
            projection,
        };
        check(record_valid(&record), "typed observations")?;
        if artifact
            .observations
            .iter()
            .any(|o| o.kind == ArtifactKind::CarvedImage)
        {
            check(
                record.projection.pe_header.is_some(),
                "carved output lacks structural PE header",
            )?;
        }
        count = count
            .checked_add(record.observations.len())
            .ok_or(Error("observation overflow"))?;
        total = total
            .checked_add(artifact.size)
            .ok_or(Error("payload overflow"))?;
        check(count <= 10000 && total <= 256 * MIB, "catalog bound")?;
        payloads.push((artifact.filename.as_str(), artifact.data.as_slice()));
        records.push(record);
    }
    runtime_check(
        mode,
        execution,
        &records,
        &serde_json::to_value(&catalog.items).map_err(|_| Error("runtime catalog encoding"))?,
        &serde_json::to_value(&catalog.summary).map_err(|_| Error("runtime omission encoding"))?,
        binding,
    )?;
    let manifest = Manifest {
        schema: "emumee.driver_payloads.v1".into(),
        profile: PROFILE.into(),
        binding: binding.clone(),
        payloads: records.clone(),
    };
    reconstruction_bindings(&manifest.payloads)?;
    check(
        Omissions::from_catalog(catalog).valid(),
        "capture omission counters",
    )?;
    let manifest = encode(&manifest, MIB)?;
    Manifest::parse(&manifest)?;
    let engine = Engine {
        schema: "emumee.driver_engine.v1".into(),
        profile: PROFILE.into(),
        binding: binding.clone(),
        mode,
        execution: execution.clone(),
        catalog: catalog
            .items
            .iter()
            .map(|artifact| serde_json::to_value(artifact).and_then(serde_json::from_value))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| Error("catalog encoding"))?,
        omissions: Omissions::from_catalog(catalog),
    };
    let engine = encode(&engine, reports::MAX_ENGINE_BYTES)?;
    let network = encode(
        &Network {
            schema: "emumee.driver_network.v1".into(),
            profile: PROFILE.into(),
            coverage: "not_monitored".into(),
            complete: false,
        },
        reports::MAX_NETWORK_REPORT_BYTES,
    )?;
    let summary = Summary {
        schema: SCHEMA.into(),
        profile: PROFILE.into(),
        summary: state(id, mode, execution, stop, recovered)?,
        binding: binding.clone(),
        engine_sha256: digest(&engine),
        engine_bytes: engine.len() as u64,
        network_sha256: digest(&network),
        network_bytes: network.len() as u64,
        manifest_sha256: digest(&manifest),
        checkpoint_sha256: digest(&manifest),
        artifacts: records,
        omissions: Omissions::from_catalog(catalog),
    };
    let summary = encode(&summary, reports::MAX_SUMMARY_BYTES)?;
    Ok(Bundle {
        summary,
        engine,
        network,
        checkpoint: manifest.clone(),
        manifest,
        payloads,
    })
}
impl Summary {
    pub fn parse(raw: &[u8]) -> Result<Self> {
        check(raw.len() <= reports::MAX_SUMMARY_BYTES, "summary bytes")?;
        let value: Self = serde_json::from_slice(raw).map_err(|_| Error("summary schema"))?;
        check(
            value.schema == SCHEMA
                && value.profile == PROFILE
                && value.binding.valid()
                && reports::valid_run_id(&value.summary.id)
                && !value.summary.guest_trace_complete
                && !value.summary.network_broker_complete,
            "summary profile/identity",
        )?;
        Ok(value)
    }
}
pub fn verify(
    raw: &[u8],
    engine: &[u8],
    network: &[u8],
    manifest: &[u8],
    checkpoint: &[u8],
    expected: &Binding,
    mut load: impl FnMut(&Record) -> Result<VerifiedProjection>,
) -> Result<Summary> {
    let summary = Summary::parse(raw)?;
    check(
        &summary.binding == expected,
        "parent request/source binding",
    )?;
    check(
        engine.len() <= reports::MAX_ENGINE_BYTES
            && network.len() <= reports::MAX_NETWORK_REPORT_BYTES
            && summary.engine_bytes == engine.len() as u64
            && summary.network_bytes == network.len() as u64
            && summary.engine_sha256 == digest(engine)
            && summary.network_sha256 == digest(network)
            && summary.manifest_sha256 == digest(manifest)
            && summary.checkpoint_sha256 == digest(checkpoint)
            && manifest == checkpoint,
        "document hash/length/checkpoint",
    )?;
    let manifest = Manifest::parse(manifest)?;
    check(
        manifest.binding == *expected && manifest.payloads == summary.artifacts,
        "manifest provenance",
    )?;
    let engine: Engine = serde_json::from_slice(engine).map_err(|_| Error("engine schema"))?;
    let network: Network = serde_json::from_slice(network).map_err(|_| Error("network schema"))?;
    check(
        summary.omissions.valid() && summary.omissions == engine.omissions,
        "capture omission counters",
    )?;
    check(
        engine.schema == "emumee.driver_engine.v1"
            && engine.profile == PROFILE
            && engine.binding == *expected
            && network.schema == "emumee.driver_network.v1"
            && network.profile == PROFILE
            && network.coverage == "not_monitored"
            && !network.complete,
        "engine/network profile",
    )?;
    let stop = match summary.summary.status.as_str() {
        "failed" => Stop::WorkerFailure,
        "timeout" => Stop::Timeout,
        "partial" | "completed" => Stop::Normal,
        _ => return Err(Error("status")),
    };
    check(
        state(
            &summary.summary.id,
            engine.mode,
            &engine.execution,
            stop,
            summary.summary.checkpoint_recovered,
        )? == summary.summary,
        "derived execution status",
    )?;
    check(
        engine.catalog.len() == manifest.payloads.len(),
        "typed catalog count",
    )?;
    for (record, typed) in manifest.payloads.iter().zip(&engine.catalog) {
        check(
            !record
                .observations
                .iter()
                .any(|o| o["kind"] == "carved_image")
                || record.projection.pe_header.is_some(),
            "carved output lacks structural PE header",
        )?;
        check(
            typed.filename == record.filename
                && typed.sha256 == record.sha256
                && typed.size == record.size
                && typed.observations == record.observations,
            "typed catalog/manifest binding",
        )?;
        check(
            load(record)?.0 == record.projection,
            "actual payload/chunk/header/preview mismatch",
        )?;
    }
    reconstruction_bindings(&manifest.payloads)?;
    runtime_check(
        engine.mode,
        &engine.execution,
        &manifest.payloads,
        &serde_json::to_value(&engine.catalog).map_err(|_| Error("runtime catalog encoding"))?,
        &serde_json::to_value(&engine.omissions).map_err(|_| Error("runtime omission encoding"))?,
        expected,
    )?;
    Ok(summary)
}
/// Parent calls this only after full verification, applying its actual stop.
pub fn restamp(
    mut verified: Summary,
    engine: &[u8],
    stop: Stop,
    recovered: bool,
) -> Result<Vec<u8>> {
    check(
        verified.engine_sha256 == digest(engine),
        "restamp engine binding",
    )?;
    let engine: Engine =
        serde_json::from_slice(engine).map_err(|_| Error("restamp engine schema"))?;
    verified.summary = state(
        &verified.summary.id,
        engine.mode,
        &engine.execution,
        stop,
        recovered,
    )?;
    encode(&verified, reports::MAX_SUMMARY_BYTES)
}
/// Submitted drivers have no compiler-owned marker or expected-output oracle.
/// This binds actual capture evidence without inferring initialization or unpacking.
fn submitted_runtime_check(
    execution: &Value,
    records: &[Record],
    catalog: &Value,
    omissions: &Value,
    binding: &Binding,
) -> Result<()> {
    check(
        crate::driver_input::service_name_valid(&binding.recipe),
        "submitted service identity",
    )?;
    let receipt: crate::driver_runtime::Receipt =
        serde_json::from_slice(&encode(&execution["capture_runtime"], 64 * 1024)?)
            .map_err(|_| Error("submitted runtime receipt schema"))?;
    check(
        receipt.input_sha256 == binding.input_sha256
            && receipt.markers.is_empty()
            && receipt.validate(execution, catalog, omissions)
            && receipt.image_bytes <= CaptureProfile::Driver128V1.limits().single as u64
            && execution["image_load"]["size"] == receipt.image_bytes
            && execution["image_load"]["base"] == receipt.image_base
            && execution["kernel_entry"]["registry_name"]
                == format!(
                    r"\Registry\Machine\System\CurrentControlSet\Services\{}",
                    binding.recipe
                )
            && execution["loaded_modules"]
                .as_array()
                .is_some_and(|modules| {
                    modules.iter().any(|module| {
                        module["name"] == format!("{}.sys", binding.recipe.to_ascii_lowercase())
                    })
                }),
        "submitted execution/capture/identity binding",
    )?;
    if receipt.selected_read_complete {
        let post = receipt
            .post_image_sha256
            .as_deref()
            .ok_or(Error("submitted post-image hash absent"))?;
        if receipt.capture_complete {
            check(
                records.iter().any(|record| {
                    record.sha256 == post
                        && record.size == receipt.image_bytes
                        && record.observations.iter().any(|observation| {
                            observation["kind"] == "memory_snapshot"
                                && observation["source"] == "settled_root_image"
                                && observation["context"]["capture_boundary"] == "settled"
                                && observation["context"]["guest_base"] == receipt.image_base
                                && observation["context"]["layout"] == "mapped_image"
                                && observation["context"]["image_size"] == receipt.image_bytes
                        })
                }),
                "submitted settled snapshot absent or unbound",
            )?;
        }
    }
    Ok(())
}
fn runtime_check(
    mode: Mode,
    execution: &Value,
    records: &[Record],
    catalog: &Value,
    omissions: &Value,
    binding: &Binding,
) -> Result<()> {
    if mode == Mode::SubmittedDriverCapture {
        return submitted_runtime_check(execution, records, catalog, omissions, binding);
    }
    if mode != Mode::GeneratedDriverCapture {
        return Ok(());
    }
    let receipt: crate::driver_runtime::Receipt =
        serde_json::from_slice(&encode(&execution["capture_runtime"], 64 * 1024)?)
            .map_err(|_| Error("runtime capture receipt schema"))?;
    check(
        receipt.input_sha256 == binding.input_sha256
            && receipt.validate(execution, catalog, omissions),
        "runtime execution/catalog/ledger binding",
    )?;
    let case = crate::driver_capture_fixture::Case::parse(&binding.recipe)
        .and_then(|c| c.runtime_case())
        .ok_or(Error("closed runtime recipe identity"))?;
    let reference = case.reference();
    check(
        binding.input_bytes == case.input_bytes() as u64
            && reference["image_bytes"] == receipt.image_bytes
            && execution["image_load"]["size"] == receipt.image_bytes
            && execution["image_load"]["base"] == receipt.image_base,
        "runtime actual image/input extent binding",
    )?;
    check(
        reference["input_sha256"] == receipt.input_sha256
            && reference["initial_image_sha256"] == receipt.initial_image_sha256
            && reference["post_image_sha256"]
                == serde_json::to_value(&receipt.post_image_sha256)
                    .map_err(|_| Error("runtime expected post hash"))?
            && reference["selected_read_complete"] == receipt.selected_read_complete
            && reference["capture_complete"] == receipt.capture_complete,
        "closed expected initial/post capture evidence",
    )?;
    let expected = reference["payloads"]
        .as_array()
        .ok_or(Error("runtime payload reference"))?;
    check(
        records.len() == expected.len()
            && expected.iter().all(|item| {
                records
                    .iter()
                    .any(|r| item["size"] == r.size && item["sha256"] == r.sha256)
            }),
        "runtime captured/reconstructed bytes differ from independent reference",
    )?;
    if receipt.capture_complete {
        check(
            receipt.markers.len() == 2
                && receipt.markers[0].rva == 0x2010
                && receipt.markers[0].expected == 0xa7
                && receipt.markers[1].rva == receipt.image_bytes - 16
                && receipt.markers[1].expected == 0xb3,
            "closed runtime fixture marker identity",
        )?;
        check(
            receipt.post_image_sha256.as_deref() != Some(receipt.initial_image_sha256.as_str()),
            "runtime unchanged initial image",
        )?;
        let snapshot = records
            .iter()
            .find(|r| {
                Some(r.sha256.as_str()) == receipt.post_image_sha256.as_deref()
                    && r.size == receipt.image_bytes
                    && r.observations
                        .iter()
                        .any(|o| o["kind"] == "memory_snapshot")
            })
            .ok_or(Error("runtime snapshot absent"))?;
        for marker in &receipt.markers {
            check(
                marker.initial != marker.expected && marker.observed == Some(marker.expected),
                "runtime guest marker effect",
            )?;
            check(
                snapshot.projection.range_hashes.iter().any(|range| {
                    range.offset == marker.rva
                        && range.size == 1
                        && range.sha256 == digest(&[marker.expected])
                }),
                "runtime marker byte range binding",
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn binding() -> Binding {
        Binding {
            request_sha256: "1".repeat(64),
            input_sha256: "2".repeat(64),
            input_bytes: 512,
            recipe: "small".into(),
            source_tree_sha256: "3".repeat(64),
            containment_sha256: "4".repeat(64),
        }
    }
    #[test]
    fn submitted_driver_runtime_accepts_only_bound_incomplete_evidence() {
        let mut binding = binding();
        binding.recipe = "TestDrv".into();
        let receipt = json!({
            "version":"emumee.driver-runtime.v1", "profile":"driver128_v1",
            "sources":["guest_files","registry_binary","memory_snapshots","structural_pe"],
            "input_sha256":binding.input_sha256, "initial_image_sha256":"5".repeat(64),
            "initial_image_phase":"materialized_relocated_before_imports",
            "post_image_sha256":null, "image_base":4096, "image_bytes":512,
            "selected_read_complete":false, "capture_complete":false,
            "read_limit":192 * MIB, "scan_limit":128 * MIB,
            "work_limit":1024 * MIB, "retention_limit":256 * MIB,
            "ledger":{"read_bytes":0,"read_reserved_bytes":0,"scan_bytes":0,"carving_work_bytes":0},
            "boundary_instructions":7, "boundary_pc":8192,
            "markers":[], "omissions":[], "scope":"submitted fixture receipt"
        });
        let mut execution = json!({
            "instruction_count":7, "final_pc":8192,
            "image_load":{"base":4096,"size":512},
            "kernel_entry":{"registry_name":r"\Registry\Machine\System\CurrentControlSet\Services\TestDrv"},
            "loaded_modules":[{"name":"testdrv.sys"}],
            "artifacts":[],
            "capture_summary":{"omitted_observations":0,"omitted_bytes":0,"reasons":{}},
            "capture_runtime":receipt
        });
        let omissions = execution["capture_summary"].clone();
        assert!(submitted_runtime_check(&execution, &[], &json!([]), &omissions, &binding).is_ok());
        execution["loaded_modules"][0]["name"] = json!("other.sys");
        assert!(
            submitted_runtime_check(&execution, &[], &json!([]), &omissions, &binding).is_err()
        );
        execution["loaded_modules"][0]["name"] = json!("testdrv.sys");
        execution["capture_runtime"]["markers"] =
            json!([{"rva":1,"initial":0,"expected":1,"observed":null}]);
        assert!(
            submitted_runtime_check(&execution, &[], &json!([]), &omissions, &binding).is_err()
        );
        execution["capture_runtime"]["markers"] = json!([]);
        execution["capture_runtime"]["boundary_pc"] = json!(8193);
        assert!(
            submitted_runtime_check(&execution, &[], &json!([]), &omissions, &binding).is_err()
        );
        execution["capture_runtime"]["boundary_pc"] = json!(8192);
        execution["capture_runtime"]["selected_read_complete"] = json!(true);
        execution["capture_runtime"]["capture_complete"] = json!(true);
        execution["capture_runtime"]["post_image_sha256"] = json!("6".repeat(64));
        execution["capture_runtime"]["ledger"]["read_bytes"] = json!(512);
        execution["capture_runtime"]["ledger"]["read_reserved_bytes"] = json!(512);
        assert!(
            submitted_runtime_check(&execution, &[], &json!([]), &omissions, &binding).is_err(),
            "A completed capture needs its actual settled snapshot record"
        );
    }
    #[test]
    fn submitted_guest_error_and_incomplete_read_remain_partial() {
        let id = "20261019T120000Z-12345678";
        let mut execution = json!({
            "completion_reason":"entry_return", "instruction_count":7,
            "guest_entry_return":17, "error":null,
            "capture_runtime":{"capture_complete":false}
        });
        let incomplete = state(
            id,
            Mode::SubmittedDriverCapture,
            &execution,
            Stop::Normal,
            false,
        )
        .unwrap();
        assert_eq!(incomplete.status, "partial");
        assert_eq!(incomplete.completion_reason, "capture_incomplete");
        execution["error"] = json!("guest fault after boundary");
        execution["capture_runtime"]["capture_complete"] = json!(true);
        let fault = state(
            id,
            Mode::SubmittedDriverCapture,
            &execution,
            Stop::Normal,
            false,
        )
        .unwrap();
        assert_eq!(fault.status, "partial");
        assert_eq!(fault.completion_reason, "error");
        execution["error"] = Value::Null;
        execution["guest_entry_return"] = Value::Null;
        let unknown = state(
            id,
            Mode::SubmittedDriverCapture,
            &execution,
            Stop::Normal,
            false,
        )
        .unwrap();
        assert_eq!(unknown.status, "partial");
        assert_eq!(unknown.completion_reason, "error");
    }
    #[test]
    fn new_schema_is_separate_actual_bytes_are_authority_and_status_cannot_be_forged() {
        let mut catalog = ArtifactCatalog::with_profile(CaptureProfile::Driver128V1);
        catalog.add(
            vec![0, 255, 77],
            ArtifactKind::MemorySnapshot,
            "synthetic",
            "display-only",
        );
        let binding = binding();
        let execution = json!({"completion_reason":"static_inspection","instruction_count":0,"guest_entry_return":null});
        let bundle = build(
            "20261018T120000Z-12345678",
            &binding,
            Mode::StaticGeneratedCapture,
            &execution,
            Stop::Normal,
            false,
            &catalog,
        )
        .unwrap();
        assert!(reports::parse_summary(&bundle.summary).is_err());
        let verified = verify(
            &bundle.summary,
            &bundle.engine,
            &bundle.network,
            &bundle.manifest,
            &bundle.checkpoint,
            &binding,
            |_| VerifiedProjection::from_bytes(&[0, 255, 77]),
        )
        .unwrap();
        assert_eq!(verified.summary.status, "partial");
        assert!(
            verify(
                &bundle.summary,
                &bundle.engine,
                &bundle.network,
                &bundle.manifest,
                &bundle.checkpoint,
                &binding,
                |_| VerifiedProjection::from_bytes(&[0, 255, 78])
            )
            .is_err()
        );
        let mut forged: Value = serde_json::from_slice(&bundle.summary).unwrap();
        forged["summary"]["status"] = json!("completed");
        assert!(
            verify(
                &serde_json::to_vec(&forged).unwrap(),
                &bundle.engine,
                &bundle.network,
                &bundle.manifest,
                &bundle.checkpoint,
                &binding,
                |_| VerifiedProjection::from_bytes(&[0, 255, 77])
            )
            .is_err()
        );
        let recovered = build(
            "20261018T120000Z-12345678",
            &binding,
            Mode::StaticGeneratedCapture,
            &execution,
            Stop::Timeout,
            true,
            &catalog,
        )
        .unwrap();
        assert_eq!(
            Summary::parse(&recovered.summary).unwrap().summary.status,
            "timeout"
        );
    }
    #[test]
    fn general_commitment_binding_projects_exact_raw_identity_without_authorizing_it() {
        use crate::{
            analysis_plan::{Arch, PreparedIntake},
            general_execution_commitment::Request,
            plan_runtime::Case,
        };
        let mut generated = Case::Kernel17.generated(Arch::X64).unwrap();
        let mut plan: Value = serde_json::from_slice(&generated.plan).unwrap();
        plan["target"]["service_name"] = json!("TestDrv");
        generated.plan = serde_json::to_vec(&plan).unwrap();
        let intake = PreparedIntake::prepare(generated.plan, generated.inputs).unwrap();
        let original = Request::from_intake(&intake, "20261019T120000Z-12345678".into()).unwrap();
        let legacy_raw = serde_json::to_vec(&original).unwrap();
        assert!(
            Binding::for_general_commitment(&legacy_raw, &intake, &"1".repeat(64), &"2".repeat(64))
                .is_err()
        );

        // Large-report resolution is still closed. The changed projection is
        // deliberately not an owned-intake-verified request.
        let mut projected = original.clone();
        projected.report_profile = "large_driver_v1".into();
        assert!(projected.verify(&intake).is_err());
        let raw = serde_json::to_vec(&projected).unwrap();
        assert!(
            Binding::for_general_commitment(&raw, &intake, &"1".repeat(64), &"2".repeat(64))
                .is_err()
        );
        let binding =
            Binding::project_general_commitment(&projected, &raw, &"1".repeat(64), &"2".repeat(64))
                .unwrap();
        assert_eq!(binding.request_sha256, digest(&raw));
        assert_eq!(binding.input_sha256, projected.public_inputs[0].sha256);
        assert_eq!(binding.input_bytes, projected.public_inputs[0].size);
        assert_eq!(binding.recipe, "TestDrv");

        let mut changed = raw.clone();
        changed.push(b' ');
        let rebound = Binding::project_general_commitment(
            &projected,
            &changed,
            &"1".repeat(64),
            &"2".repeat(64),
        )
        .unwrap();
        assert_ne!(rebound.request_sha256, binding.request_sha256);
        assert!(
            Binding::project_general_commitment(&projected, &raw, "bad", &"2".repeat(64)).is_err()
        );
        let mut unknown: Value = serde_json::from_slice(&raw).unwrap();
        unknown["unknown"] = json!(true);
        assert!(
            Binding::for_general_commitment(
                &serde_json::to_vec(&unknown).unwrap(),
                &intake,
                &"1".repeat(64),
                &"2".repeat(64)
            )
            .is_err()
        );
    }

    #[test]
    fn oversized_and_short_streams_reject_before_large_allocation() {
        assert!(
            Projection::from_reader(134217729, |_, _| panic!("oversize must preflight")).is_err()
        );
        assert!(Projection::from_reader(512, |_, _| Some(vec![0; 3])).is_err());
    }
    #[test]
    fn a_short_structural_reread_cannot_panic_or_create_header_evidence() {
        let raw = crate::driver_capture_fixture::Case::SmallRaw
            .small_bytes()
            .unwrap();
        let mut calls = 0usize;
        let value = Projection::from_reader(raw.len() as u64, |offset, count| {
            calls += 1;
            if calls == 4 {
                Some(vec![0; 1])
            } else {
                Some(raw[offset as usize..offset as usize + count].to_vec())
            }
        })
        .unwrap();
        assert!(value.pe_header.is_none());
    }
}
