//! Pure typed capture adapters. No host file, registry, or sample execution.
//! A carved PE/reconstructed image is evidence, never confirmed unpacking.

use crate::artifacts::{ArtifactCatalog, ArtifactKind, CaptureSummary};
use crate::pe_carve::{self, CaptureKind, Scan};
use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Debug, thiserror::Error)]
#[error("Invalid artifact bridge input: {0}")]
pub struct BridgeError(pub &'static str);

#[derive(Clone, Copy, Debug)]
pub enum Origin {
    Memory,
    ContainerStream,
    RegistryValue,
}
impl Origin {
    fn label(self) -> &'static str {
        match self {
            Self::Memory => "memory",
            Self::ContainerStream => "container_stream",
            Self::RegistryValue => "registry_value",
        }
    }
}

#[derive(Debug, Serialize)]
pub struct BridgeStats {
    pub observations_offered: usize,
    pub observations_retained: usize,
    pub new_payloads: usize,
    pub scan_complete: bool,
    pub scanner_omitted_observations: u64,
    pub catalog_omitted_observations: u64,
}

fn display_source(source: &str) -> &str {
    let mut end = source.len().min(256);
    while !source.is_char_boundary(end) {
        end -= 1;
    }
    &source[..end]
}

fn observation_count(catalog: &ArtifactCatalog) -> usize {
    catalog.items.iter().map(|p| p.observations.len()).sum()
}

/// Transfer a bounded scanner result into the shared content-addressed catalog.
/// Public Scan fields are verified before changing the destination catalog.
/// Catalog resource omissions remain explicit; the function does not report
/// every offered observation as retained merely because input validation passed.
pub fn capture_scan(
    catalog: &mut ArtifactCatalog,
    scan: &Scan,
    origin: Origin,
) -> Result<BridgeStats, BridgeError> {
    if scan.payloads.len() > 10_000 || scan.observations.len() > 10_000 {
        return Err(BridgeError("scanner count exceeds bound"));
    }
    let mut retained_bytes = 0_usize;
    for payload in &scan.payloads {
        retained_bytes = retained_bytes
            .checked_add(payload.data.len())
            .ok_or(BridgeError("retained byte total overflow"))?;
        if retained_bytes > pe_carve::MAX_RETAINED_BYTES {
            return Err(BridgeError("scanner retained byte total exceeds bound"));
        }
        if payload.data.is_empty()
            || payload.data.len() > pe_carve::MAX_ARTIFACT_BYTES
            || payload.size != payload.data.len()
            || payload.sha256 != format!("{:x}", Sha256::digest(&payload.data))
        {
            return Err(BridgeError("scanner payload hash/size mismatch"));
        }
    }
    let mut offered_bytes = 0_u64;
    let mut context_bytes = 0_usize;
    for observation in &scan.observations {
        let Some(payload) = scan.payloads.get(observation.payload) else {
            return Err(BridgeError("scanner payload index outside catalog"));
        };
        if observation.sha256 != payload.sha256
            || observation.size != payload.size
            || observation.source.len() > 32768
            || observation.guest_path.len() > 32768
        {
            return Err(BridgeError(
                "scanner observation binding or context rejected",
            ));
        }
        if let Some(context) = &observation.context {
            let bytes = serde_json::to_vec(context)
                .map_err(|_| BridgeError("scanner context serialization failed"))?
                .len();
            context_bytes = context_bytes
                .checked_add(bytes)
                .ok_or(BridgeError("scanner context total overflow"))?;
            if context_bytes > 1024 * 1024 {
                return Err(BridgeError("scanner aggregate context byte limit"));
            }
        }
        offered_bytes = offered_bytes
            .checked_add(payload.size as u64)
            .ok_or(BridgeError("offered byte total overflow"))?;
        if offered_bytes > 256 * 1024 * 1024 {
            return Err(BridgeError("offered byte work limit"));
        }
    }
    let summary = CaptureSummary {
        omitted_observations: scan.artifact_capture.omitted_observations,
        omitted_bytes: scan.artifact_capture.omitted_bytes,
        reasons: scan
            .artifact_capture
            .reasons
            .iter()
            .map(|(reason, count)| (reason.to_string(), *count))
            .collect(),
    };
    if !ArtifactCatalog::default().merge_omissions(&summary) {
        return Err(BridgeError("scanner omission counters rejected"));
    }
    let before_count = observation_count(catalog);
    let before_payloads = catalog.items.len();
    let before_omitted = catalog.summary.omitted_observations;
    for observation in &scan.observations {
        let payload = &scan.payloads[observation.payload];
        let mut context = observation.context.clone().unwrap_or_default();
        context.insert(
            "capture_origin".into(),
            Value::String(origin.label().into()),
        );
        context.insert(
            "carve_source".into(),
            Value::String(observation.source.clone()),
        );
        let kind = match observation.kind {
            CaptureKind::Pe => {
                context.insert("carved_kind".into(), Value::String("structural_pe".into()));
                ArtifactKind::CarvedImage
            }
            CaptureKind::Memory => ArtifactKind::MemorySnapshot,
        };
        catalog.add_with_context(
            payload.data.clone(),
            kind,
            display_source(&observation.source),
            &observation.guest_path,
            Some(context),
        );
    }
    let catalog_omitted = catalog
        .summary
        .omitted_observations
        .saturating_sub(before_omitted);
    let merged = catalog.merge_omissions(&summary);
    debug_assert!(merged);
    Ok(BridgeStats {
        observations_offered: scan.observations.len(),
        observations_retained: observation_count(catalog) - before_count,
        new_payloads: catalog.items.len() - before_payloads,
        scan_complete: scan.scan_complete,
        scanner_omitted_observations: summary.omitted_observations,
        catalog_omitted_observations: catalog_omitted,
    })
}

/// Match legacy successful REG_BINARY writes: retain the value and then carve
/// embedded PEs. Call only after the guest registry update actually succeeded.
/// This function never changes registry state, API status, or LastError.
pub fn capture_registry_binary(
    catalog: &mut ArtifactCatalog,
    key: &str,
    name: &str,
    raw: &[u8],
) -> Result<BridgeStats, BridgeError> {
    if raw.len() > crate::registry::MAX_VALUE
        || key.is_empty()
        || key.contains('\0')
        || name.contains('\0')
        || key.encode_utf16().count() > 32767
        || name.encode_utf16().count() > 16383
    {
        return Err(BridgeError("registry provenance exceeds model bounds"));
    }
    let context: Map<String, Value> =
        serde_json::json!({"registry_key":key,"registry_value":name,"registry_type":3})
            .as_object()
            .expect("owned context object")
            .clone();
    if catalog.profile() == crate::capture_profile::CaptureProfile::Driver128V1 {
        let full_name = format!("{key}\\{name}");
        catalog.add_with_context(
            raw.to_vec(),
            ArtifactKind::RegistryValue,
            "registry_value",
            &full_name,
            Some(context.clone()),
        );
        return capture_owned_budgeted(
            catalog,
            raw.to_vec(),
            "registry_value",
            Some(&context),
            Origin::RegistryValue,
            false,
        );
    }
    let scan = pe_carve::scan(raw, "registry_value", false, Some(&context))
        .map_err(|_| BridgeError("registry carving options rejected"))?;
    let full_name = format!("{key}\\{name}");
    catalog.add_with_context(
        raw.to_vec(),
        ArtifactKind::RegistryValue,
        "registry_value",
        &full_name,
        Some(context),
    );
    capture_scan(catalog, &scan, Origin::RegistryValue)
}

/// Match legacy MSI stream capture scope: retain direct CAB/PE streams, carve
/// PEs from data streams, and preserve the complete container hierarchy as data.
/// CAB bytes are retained verbatim; no CAB extraction or actions are performed.
pub fn capture_container_stream(
    catalog: &mut ArtifactCatalog,
    stream: &crate::msi::Stream,
) -> Result<Option<BridgeStats>, BridgeError> {
    if stream.path.is_empty()
        || stream.path.len() > 32
        || stream
            .path
            .iter()
            .any(|p| p.is_empty() || p.encode_utf16().count() > 31)
    {
        return Err(BridgeError("container stream hierarchy rejected"));
    }
    if stream.data.len() as u64 != stream.size
        || stream.data.len() > pe_carve::MAX_ARTIFACT_BYTES
        || stream.sha256 != format!("{:x}", Sha256::digest(&stream.data))
    {
        return Err(BridgeError("container payload hash/size mismatch"));
    }
    let context: Map<String, Value> = serde_json::json!({"container_stream_path":stream.path})
        .as_object()
        .expect("owned context object")
        .clone();
    let source = format!("msi_stream:{}", stream.path.join("/"));
    if matches!(
        stream.kind,
        crate::msi::StreamType::Cabinet | crate::msi::StreamType::Pe
    ) {
        catalog.add_with_context(
            stream.data.clone(),
            ArtifactKind::ContainerStream,
            display_source(&source),
            "",
            Some(context),
        );
        Ok(None)
    } else {
        if catalog.profile() == crate::capture_profile::CaptureProfile::Driver128V1 {
            return capture_owned_budgeted(
                catalog,
                stream.data.clone(),
                &source,
                Some(&context),
                Origin::ContainerStream,
                false,
            )
            .map(Some);
        }
        let scan = pe_carve::scan(&stream.data, &source, false, Some(&context))
            .map_err(|_| BridgeError("container carving options rejected"))?;
        capture_scan(catalog, &scan, Origin::ContainerStream).map(Some)
    }
}

/// Convert MSI omission metadata to the same bounded catalog summary without
/// exposing container stream names as host paths or duplicating omitted bytes.
pub fn merge_container_omissions(
    catalog: &mut ArtifactCatalog,
    inspection: &crate::msi::Inspection,
) -> bool {
    let mut reasons = BTreeMap::new();
    let mut bytes = 0_u64;
    for omission in &inspection.omissions {
        bytes = bytes.saturating_add(omission.size);
        *reasons.entry(omission.reason.to_owned()).or_default() += 1;
    }
    catalog.merge_omissions(&CaptureSummary {
        omitted_observations: inspection.omissions.len() as u64,
        omitted_bytes: bytes,
        reasons,
    })
}

/// Consume one verified scanner result: move each unique payload once, retain
/// bounded typed provenance, and never hash/copy a large buffer per observation.
pub fn capture_scan_owned(
    catalog: &mut ArtifactCatalog,
    scan: Scan,
    origin: Origin,
) -> Result<BridgeStats, BridgeError> {
    use crate::{
        artifacts::{Observation, valid_observation_json_with_profile},
        capture_profile::CaptureProfile,
    };
    let profile = catalog.profile();
    if scan.profile() != profile {
        return Err(BridgeError("scanner/catalog capture profile differs"));
    }
    let limits = profile.limits();
    if scan.payloads.len() > 10000 || scan.observations.len() > 10000 {
        return Err(BridgeError("scanner count exceeds bound"));
    }
    let mut retained = 0usize;
    let mut hashes = std::collections::BTreeSet::new();
    for payload in &scan.payloads {
        retained = retained
            .checked_add(payload.data.len())
            .ok_or(BridgeError("scanner retained overflow"))?;
        if payload.data.is_empty()
            || payload.size != payload.data.len()
            || payload.size > limits.single
            || retained > limits.retained
            || payload.sha256 != format!("{:x}", Sha256::digest(&payload.data))
            || !hashes.insert(payload.sha256.as_str())
        {
            return Err(BridgeError("scanner payload hash/size/unique bound"));
        }
    }
    let mut grouped: Vec<Vec<Observation>> = (0..scan.payloads.len()).map(|_| Vec::new()).collect();
    let mut metadata = 0usize;
    let snapshots = scan
        .observations
        .iter()
        .filter(|o| o.kind == CaptureKind::Memory)
        .map(|o| (o.source.as_str(), o.sha256.as_str()))
        .collect::<BTreeMap<_, _>>();
    for observation in &scan.observations {
        let payload = scan
            .payloads
            .get(observation.payload)
            .ok_or(BridgeError("scanner payload index outside catalog"))?;
        if observation.sha256 != payload.sha256
            || observation.size != payload.size
            || observation.source.len() > 32768
            || observation.guest_path.len() > 32768
        {
            return Err(BridgeError("scanner observation binding rejected"));
        }
        let mut context = observation.context.clone().unwrap_or_default();
        context.insert(
            "capture_origin".into(),
            Value::String(origin.label().into()),
        );
        context.insert(
            "carve_source".into(),
            Value::String(observation.source.clone()),
        );
        let kind = if observation.kind == CaptureKind::Pe {
            context.insert("carved_kind".into(), Value::String("structural_pe".into()));
            ArtifactKind::CarvedImage
        } else {
            ArtifactKind::MemorySnapshot
        };
        if profile == CaptureProfile::Driver128V1 {
            context.insert(
                "capture_profile".into(),
                Value::String("driver128_v1".into()),
            );
            context.insert("structural_only".into(), Value::Bool(true));
            context.insert("no_fixups".into(), Value::Bool(true));
            if context.get("layout").and_then(Value::as_str) == Some("mapped_image") {
                let source = context
                    .get("source_snapshot_sha256")
                    .and_then(Value::as_str)
                    .ok_or(BridgeError("mapped source hash absent"))?;
                if snapshots.get(observation.source.as_str()).copied() != Some(source) {
                    return Err(BridgeError(
                        "mapped reconstruction source hash has no bound snapshot",
                    ));
                }
                let image = context
                    .get("image_size")
                    .and_then(Value::as_u64)
                    .ok_or(BridgeError("mapped image size"))?;
                let end = context
                    .get("raw_end")
                    .and_then(Value::as_u64)
                    .ok_or(BridgeError("mapped raw end"))?;
                let sections = context
                    .get("section_extents")
                    .and_then(Value::as_array)
                    .ok_or(BridgeError("mapped section extents"))?;
                if image == 0
                    || image > limits.single as u64
                    || end == 0
                    || end > limits.single as u64
                    || sections.len() > 96
                {
                    return Err(BridgeError("mapped extent profile"));
                }
                let mut extents = Vec::new();
                for section in sections {
                    let rva = section["rva"].as_u64().ok_or(BridgeError("mapped RVA"))?;
                    let raw = section["raw_offset"]
                        .as_u64()
                        .ok_or(BridgeError("mapped raw offset"))?;
                    let size = section["size"]
                        .as_u64()
                        .ok_or(BridgeError("mapped extent size"))?;
                    if raw.checked_add(size).is_none_or(|n| n > end)
                        || rva.checked_add(size).is_none_or(|n| n > image)
                    {
                        return Err(BridgeError("mapped extent bounds"));
                    }
                    if size > 0 {
                        extents.push((raw, rva, size));
                    }
                }
                extents.sort();
                let mut cursor = 0u64;
                let mut segments = Vec::new();
                for (raw, rva, size) in extents {
                    if raw < cursor {
                        return Err(BridgeError("mapped extent overlap"));
                    }
                    if raw > cursor {
                        segments.push(serde_json::json!({"source":cursor,"destination":cursor,"size":raw-cursor}));
                    }
                    segments.push(serde_json::json!({"source":rva,"destination":raw,"size":size}));
                    cursor = raw + size;
                }
                if cursor < end {
                    segments.push(
                        serde_json::json!({"source":cursor,"destination":cursor,"size":end-cursor}),
                    );
                }
                context.insert("reconstruction_segments".into(), Value::Array(segments));
                if kind == ArtifactKind::MemorySnapshot {
                    context.insert("reconstruction".into(), Value::String("none".into()));
                } else {
                    context.insert("source_layout".into(), Value::String("mapped_image".into()));
                    context.insert("layout".into(), Value::String("raw_file".into()));
                }
            }
        }
        let typed = Observation {
            kind,
            source: display_source(&observation.source).to_owned(),
            guest_path: observation.guest_path.clone(),
            context: Some(context),
        };
        let value =
            serde_json::to_value(&typed).map_err(|_| BridgeError("scanner typed serialization"))?;
        if !valid_observation_json_with_profile(&value, profile) {
            return Err(BridgeError("scanner typed profile/context rejected"));
        }
        metadata = metadata
            .checked_add(
                serde_json::to_vec(&typed)
                    .map_err(|_| BridgeError("scanner metadata serialization"))?
                    .len()
                    + 256,
            )
            .ok_or(BridgeError("scanner metadata overflow"))?;
        if metadata > limits.metadata {
            return Err(BridgeError("scanner metadata budget"));
        }
        grouped[observation.payload].push(typed);
    }
    if grouped.iter().any(Vec::is_empty) {
        return Err(BridgeError("scanner payload without an observation"));
    }
    let summary = CaptureSummary {
        omitted_observations: scan.artifact_capture.omitted_observations,
        omitted_bytes: scan.artifact_capture.omitted_bytes,
        reasons: scan
            .artifact_capture
            .reasons
            .iter()
            .map(|(k, v)| (k.to_string(), *v))
            .collect(),
    };
    if !ArtifactCatalog::default().merge_omissions(&summary) {
        return Err(BridgeError("scanner omission counters rejected"));
    }
    let before_count = observation_count(catalog);
    let before_payloads = catalog.items.len();
    let before_omitted = catalog.summary.omitted_observations;
    let offered = scan.observations.len();
    let complete = scan.scan_complete;
    for (payload, observations) in scan.payloads.into_iter().zip(grouped) {
        catalog.add_owned_observations(payload.data, observations);
    }
    let catalog_omitted = catalog
        .summary
        .omitted_observations
        .saturating_sub(before_omitted);
    let merged = catalog.merge_omissions(&summary);
    debug_assert!(merged);
    Ok(BridgeStats {
        observations_offered: offered,
        observations_retained: observation_count(catalog) - before_count,
        new_payloads: catalog.items.len() - before_payloads,
        scan_complete: complete,
        scanner_omitted_observations: summary.omitted_observations,
        catalog_omitted_observations: catalog_omitted,
    })
}

/// Runtime Driver scans consume one aggregate catalog ledger across all sources.
pub fn capture_owned_budgeted(
    catalog: &mut ArtifactCatalog,
    data: Vec<u8>,
    source: &str,
    context: Option<&Map<String, Value>>,
    origin: Origin,
    retain_memory: bool,
) -> Result<BridgeStats, BridgeError> {
    capture_owned_with_layout(
        catalog,
        data,
        source,
        context,
        origin,
        RetainLayout::Inferred { retain_memory },
    )
}
#[derive(Clone, Copy)]
enum RetainLayout {
    Inferred { retain_memory: bool },
    MappedRoot,
}
/// The caller acquired a full mapped root; arbitrary memory must use inference.
pub fn capture_owned_mapped_root(
    catalog: &mut ArtifactCatalog,
    data: Vec<u8>,
    source: &str,
    context: Option<&Map<String, Value>>,
) -> Result<BridgeStats, BridgeError> {
    capture_owned_with_layout(
        catalog,
        data,
        source,
        context,
        Origin::Memory,
        RetainLayout::MappedRoot,
    )
}
fn capture_owned_with_layout(
    catalog: &mut ArtifactCatalog,
    data: Vec<u8>,
    source: &str,
    context: Option<&Map<String, Value>>,
    origin: Origin,
    layout: RetainLayout,
) -> Result<BridgeStats, BridgeError> {
    let retain_memory = match layout {
        RetainLayout::MappedRoot => true,
        RetainLayout::Inferred { retain_memory } => retain_memory,
    };
    use crate::capture_profile::CaptureProfile;
    if catalog.profile() != CaptureProfile::Driver128V1 {
        return Err(BridgeError("budgeted scan requires Driver128"));
    }
    let (scan_limit, work_limit) = catalog.selected_carving_remaining();
    if data.len() > scan_limit {
        let _ = catalog.merge_omissions(&CaptureSummary {
            omitted_observations: 1,
            omitted_bytes: data.len() as u64,
            reasons: BTreeMap::from([("aggregate_scan_limit".into(), 1)]),
        });
        let before = catalog.items.len();
        let before_observations = catalog
            .items
            .iter()
            .map(|p| p.observations.len())
            .sum::<usize>();
        let before_omitted = catalog.summary.omitted_observations;
        if retain_memory {
            catalog.add_with_context(
                data,
                ArtifactKind::MemorySnapshot,
                display_source(source),
                "",
                context.cloned(),
            );
        }
        return Ok(BridgeStats {
            observations_offered: usize::from(retain_memory),
            observations_retained: catalog
                .items
                .iter()
                .map(|p| p.observations.len())
                .sum::<usize>()
                - before_observations,
            new_payloads: catalog.items.len() - before,
            scan_complete: false,
            scanner_omitted_observations: 1,
            catalog_omitted_observations: catalog.summary.omitted_observations - before_omitted,
        });
    }
    let scan = match layout {
        RetainLayout::MappedRoot => pe_carve::scan_owned_mapped_root(
            data,
            source,
            context,
            CaptureProfile::Driver128V1,
            scan_limit,
            work_limit,
        ),
        RetainLayout::Inferred { .. } => pe_carve::scan_owned_budgeted(
            data,
            source,
            context,
            CaptureProfile::Driver128V1,
            scan_limit,
            work_limit,
            retain_memory,
        ),
    }
    .map_err(|_| BridgeError("budgeted scan options"))?;
    if !catalog.charge_carving(scan.scanned_bytes, scan.work_bytes_reserved) {
        return Err(BridgeError("aggregate carving charge"));
    }
    capture_scan_owned(catalog, scan, origin)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn pe() -> Vec<u8> {
        let mut raw = vec![0_u8; 1024];
        raw[..2].copy_from_slice(b"MZ");
        raw[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
        raw[0x80..0x84].copy_from_slice(b"PE\0\0");
        for (at, value) in [(0x84, 0x8664_u16), (0x86, 1), (0x94, 0xf0), (0x98, 0x20b)] {
            raw[at..at + 2].copy_from_slice(&value.to_le_bytes());
        }
        for (at, value) in [
            (0x98 + 56, 0x2000_u32),
            (0x98 + 60, 0x200),
            (0x188 + 12, 0x1000),
            (0x188 + 16, 0x200),
            (0x188 + 20, 0x200),
        ] {
            raw[at..at + 4].copy_from_slice(&value.to_le_bytes());
        }
        raw[512..].fill(0x52);
        raw
    }
    #[test]
    fn mapped_snapshot_and_reconstructed_pe_remain_distinct_typed_observations() {
        let raw = pe();
        let mut image = vec![0_u8; 8192];
        image[..512].copy_from_slice(&raw[..512]);
        image[4096..4608].copy_from_slice(&raw[512..]);
        let scan = pe_carve::scan(&image, "memory:fixture", false, None).unwrap();
        let mut catalog = ArtifactCatalog::default();
        let stats = capture_scan(&mut catalog, &scan, Origin::Memory).unwrap();
        assert_eq!(stats.observations_retained, 2);
        assert_eq!(
            catalog.items[0].observations[0].kind,
            ArtifactKind::MemorySnapshot
        );
        assert_eq!(
            catalog.items[1].observations[0].kind,
            ArtifactKind::CarvedImage
        );
        assert_eq!(catalog.items[0].data, image);
        assert_eq!(catalog.items[1].data, raw);
        for item in &catalog.items {
            assert_eq!(item.filename, format!("{}.bin", item.sha256));
            assert!(crate::artifacts::valid_observation_json(
                &serde_json::to_value(&item.observations[0]).unwrap()
            ));
        }
        assert_eq!(
            catalog.items[1].observations[0].context.as_ref().unwrap()["carved_kind"],
            "structural_pe"
        );
    }
    #[test]
    fn binary_registry_value_and_its_carved_image_share_exact_bytes_without_claiming_guest_files() {
        let mut catalog = ArtifactCatalog::default();
        let raw = pe();
        let stats =
            capture_registry_binary(&mut catalog, "HKCU\\Fixture", "Payload", &raw).unwrap();
        assert_eq!(stats.observations_retained, 1);
        assert_eq!(catalog.items.len(), 1);
        assert_eq!(catalog.items[0].observations.len(), 2);
        assert_eq!(
            catalog.items[0].observations[0].kind,
            ArtifactKind::RegistryValue
        );
        assert_eq!(
            catalog.items[0].observations[1].kind,
            ArtifactKind::CarvedImage
        );
        assert_eq!(catalog.items[0].data, raw);
        assert_eq!(
            catalog.items[0].observations[0].guest_path,
            "HKCU\\Fixture\\Payload"
        );
    }
    #[test]
    fn cabinets_remain_opaque_container_streams_while_data_streams_can_supply_pe_evidence() {
        let mut catalog = ArtifactCatalog::default();
        let raw = b"MSCF-owned-cabinet".to_vec();
        let cabinet = crate::msi::Stream {
            path: vec!["_Streams".into(), "Cabinet".into()],
            name: "_Streams/Cabinet".into(),
            size: raw.len() as u64,
            kind: crate::msi::StreamType::Cabinet,
            sha256: format!("{:x}", Sha256::digest(&raw)),
            data: raw,
        };
        assert!(
            capture_container_stream(&mut catalog, &cabinet)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            catalog.items[0].observations[0].kind,
            ArtifactKind::ContainerStream
        );
        let mut data = b"prefix".to_vec();
        data.extend_from_slice(&pe());
        let stream = crate::msi::Stream {
            path: vec!["Binary".into(), "Payload".into()],
            name: "Binary/Payload".into(),
            size: data.len() as u64,
            kind: crate::msi::StreamType::Data,
            sha256: format!("{:x}", Sha256::digest(&data)),
            data,
        };
        let stats = capture_container_stream(&mut catalog, &stream)
            .unwrap()
            .unwrap();
        assert_eq!(stats.observations_retained, 1);
        let observation = &catalog.items[1].observations[0];
        assert_eq!(observation.kind, ArtifactKind::CarvedImage);
        assert_eq!(
            observation.context.as_ref().unwrap()["capture_origin"],
            "container_stream"
        );
    }
    #[test]
    fn tampered_scan_bindings_are_rejected_before_altering_catalog() {
        let mut scan = pe_carve::scan(&pe(), "fixture", false, None).unwrap();
        scan.payloads[0].data[0] = 0;
        let mut catalog = ArtifactCatalog::default();
        assert!(capture_scan(&mut catalog, &scan, Origin::Memory).is_err());
        assert!(catalog.items.is_empty());
        let mut scan = pe_carve::scan(&pe(), "fixture", false, None).unwrap();
        scan.observations[0].payload = 99;
        assert!(capture_scan(&mut catalog, &scan, Origin::Memory).is_err());
        assert!(catalog.items.is_empty());
    }
}
