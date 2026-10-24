//! Content-addressed guest evidence. A capture is never a claim of unpacking.
use crate::capture_profile::CaptureProfile;
use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const MAX_METADATA: usize = 1024 * 1024;
pub const MAX_CONTEXT_BYTES: usize = 64 * 1024;
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    GuestFile,
    MemorySnapshot,
    ContainerStream,
    RegistryValue,
    /// Structural PE evidence, including reconstructed images; never a claim
    /// that execution completed or a driver was successfully unpacked.
    CarvedImage,
}
#[derive(Debug, Serialize)]
pub struct Observation {
    pub kind: ArtifactKind,
    pub source: String,
    pub guest_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<Map<String, Value>>,
}
#[derive(Debug, Serialize)]
pub struct Artifact {
    pub filename: String,
    pub sha256: String,
    pub size: usize,
    pub observations: Vec<Observation>,
    #[serde(skip)]
    pub data: Vec<u8>,
}
#[derive(Debug, Default, Serialize)]
pub struct CaptureSummary {
    pub omitted_observations: u64,
    pub omitted_bytes: u64,
    pub reasons: BTreeMap<String, u64>,
}
#[derive(Default)]
pub struct ArtifactCatalog {
    profile: CaptureProfile,
    retention_budget: Option<usize>,
    scan_bytes: usize,
    carving_work: u64,
    scan_limit: Option<usize>,
    work_limit: Option<u64>,
    pub items: Vec<Artifact>,
    pub summary: CaptureSummary,
    seen: BTreeMap<String, usize>,
    bytes: usize,
    metadata: usize,
    observations: usize,
}
impl ArtifactCatalog {
    /// Rebuild the verified ordinary engine catalog by moving buffers, not cloning.
    pub fn from_owned_parts(
        profile: CaptureProfile,
        items: Vec<Artifact>,
        summary: CaptureSummary,
        retained: usize,
    ) -> Result<Self, &'static str> {
        let mut result =
            Self::with_retention_budget(profile, retained).ok_or("retention budget")?;
        for item in items {
            if item.size != item.data.len()
                || item.sha256 != format!("{:x}", Sha256::digest(&item.data))
                || item.filename != format!("{}.bin", item.sha256)
                || result.seen.contains_key(&item.sha256)
            {
                return Err("owned catalog identity");
            }
            if !result.add_owned_observations(item.data, item.observations) {
                return Err("owned catalog bounds");
            }
        }
        if !result.merge_omissions(&summary) {
            return Err("owned catalog omissions");
        }
        Ok(result)
    }
    pub fn with_retention_budget(profile: CaptureProfile, retained: usize) -> Option<Self> {
        if retained > profile.limits().retained {
            return None;
        }
        let mut result = Self::with_profile(profile);
        result.retention_budget = Some(retained);
        Some(result)
    }
    pub fn retention_limit(&self) -> usize {
        self.retention_budget
            .unwrap_or(self.profile.limits().retained)
    }
    pub fn carving_totals(&self) -> (usize, u64) {
        (self.scan_bytes, self.carving_work)
    }
    pub fn carving_remaining(&self) -> (usize, u64) {
        (
            self.profile.limits().scan - self.scan_bytes,
            self.profile.limits().work - self.carving_work,
        )
    }
    pub fn set_carving_limits(&mut self, scan: usize, work: u64) -> bool {
        if self.profile != CaptureProfile::Driver128V1
            || self.scan_bytes != 0
            || self.carving_work != 0
            || scan > self.profile.limits().scan
            || work > self.profile.limits().work
        {
            return false;
        }
        self.scan_limit = Some(scan);
        self.work_limit = Some(work);
        true
    }
    pub fn selected_carving_remaining(&self) -> (usize, u64) {
        (
            self.scan_limit.unwrap_or(self.profile.limits().scan) - self.scan_bytes,
            self.work_limit.unwrap_or(self.profile.limits().work) - self.carving_work,
        )
    }
    pub fn charge_carving(&mut self, scan: usize, work: u64) -> bool {
        let (s, w) = self.selected_carving_remaining();
        if scan > s || work > w {
            return false;
        }
        self.scan_bytes += scan;
        self.carving_work += work;
        true
    }

    pub fn with_profile(profile: CaptureProfile) -> Self {
        Self {
            profile,
            ..Self::default()
        }
    }
    pub fn profile(&self) -> CaptureProfile {
        self.profile
    }
    /// Atomic owned batch: one full-payload hash, no per-observation data clones.
    /// Context/metadata failure records omissions and does not mint an identity.
    pub fn add_owned_observations(
        &mut self,
        data: Vec<u8>,
        observations: Vec<Observation>,
    ) -> bool {
        if data.is_empty() {
            return false;
        }
        let limits = self.profile.limits();
        let mut metadata = 0usize;
        let valid = data.len() <= limits.single
            && !observations.is_empty()
            && observations.len() <= 10000
            && observations.iter().all(|observation| {
                let Ok(value) = serde_json::to_value(observation) else {
                    return false;
                };
                if !valid_observation_json_with_profile(&value, self.profile) {
                    return false;
                }
                let Ok(encoded) = serde_json::to_vec(observation) else {
                    return false;
                };
                let Some(next) = metadata.checked_add(encoded.len() + 256) else {
                    return false;
                };
                metadata = next;
                true
            });
        if !valid
            || self
                .observations
                .checked_add(observations.len())
                .is_none_or(|n| n > 10000)
            || self
                .metadata
                .checked_add(metadata)
                .is_none_or(|n| n > MAX_METADATA)
        {
            for _ in &observations {
                self.omit(data.len(), "owned_observation_or_metadata_limit");
            }
            return false;
        }
        let hash = format!("{:x}", Sha256::digest(&data));
        let index = if let Some(index) = self.seen.get(&hash) {
            *index
        } else {
            if data.len() > self.retention_limit().saturating_sub(self.bytes) {
                for _ in &observations {
                    self.omit(data.len(), "capture_total_limit");
                }
                return false;
            }
            let index = self.items.len();
            self.bytes += data.len();
            self.seen.insert(hash.clone(), index);
            self.items.push(Artifact {
                filename: format!("{hash}.bin"),
                sha256: hash,
                size: data.len(),
                observations: Vec::new(),
                data,
            });
            index
        };
        self.observations += observations.len();
        self.metadata += metadata;
        self.items[index].observations.extend(observations);
        true
    }

    fn omit(&mut self, bytes: usize, reason: &str) {
        self.summary.omitted_observations = self.summary.omitted_observations.saturating_add(1);
        self.summary.omitted_bytes = self.summary.omitted_bytes.saturating_add(bytes as u64);
        *self.summary.reasons.entry(reason.to_owned()).or_default() += 1;
    }
    pub fn add(&mut self, data: Vec<u8>, kind: ArtifactKind, source: &str, path: &str) {
        self.add_with_context(data, kind, source, path, None);
    }
    pub fn add_with_context(
        &mut self,
        data: Vec<u8>,
        kind: ArtifactKind,
        source: &str,
        path: &str,
        context: Option<Map<String, Value>>,
    ) {
        if data.is_empty() {
            return;
        }
        if data.len() > self.profile.limits().single {
            self.omit(data.len(), "artifact_size_limit");
            return;
        }
        if source.len() > 256 || path.len() > 32768 {
            self.omit(data.len(), "observation_field_limit");
            return;
        }
        if context.as_ref().is_some_and(|c| !valid_context(c)) {
            self.omit(data.len(), "observation_context_limit");
            return;
        }
        if self.observations >= 10000 {
            self.omit(data.len(), "observation_count_limit");
            return;
        }
        let observation = Observation {
            kind,
            source: source.to_owned(),
            guest_path: path.to_owned(),
            context,
        };
        if (observation.context.is_some()
            || matches!(
                kind,
                ArtifactKind::ContainerStream
                    | ArtifactKind::RegistryValue
                    | ArtifactKind::CarvedImage
            ))
            && !valid_observation_json_with_profile(
                &serde_json::to_value(&observation).expect("bounded observation serializes"),
                self.profile,
            )
        {
            self.omit(data.len(), "observation_context_invalid");
            return;
        }
        let estimate = serde_json::to_vec(&observation)
            .expect("bounded observation serializes")
            .len()
            + 256;
        if self.metadata + estimate > MAX_METADATA {
            self.omit(data.len(), "manifest_size_limit");
            return;
        }
        let sha256 = format!("{:x}", Sha256::digest(&data));
        if let Some(index) = self.seen.get(&sha256) {
            self.items[*index].observations.push(observation);
        } else {
            if self.bytes + data.len() > self.retention_limit() {
                self.omit(data.len(), "capture_total_limit");
                return;
            }
            self.bytes += data.len();
            self.seen.insert(sha256.clone(), self.items.len());
            self.items.push(Artifact {
                filename: format!("{sha256}.bin"),
                sha256,
                size: data.len(),
                observations: vec![observation],
                data,
            });
        }
        self.metadata += estimate;
        self.observations += 1;
    }

    /// Propagate exact grouped omissions from another bounded capture stage.
    /// Invalid counters are rejected without altering the current summary.
    pub fn merge_omissions(&mut self, other: &CaptureSummary) -> bool {
        let sum = other
            .reasons
            .values()
            .try_fold(0_u64, |sum, count| sum.checked_add(*count));
        if other.omitted_observations > 1_000_000
            || other.omitted_bytes > 1 << 50
            || other.reasons.len() > 32
            || other
                .reasons
                .keys()
                .any(|reason| reason.is_empty() || reason.len() > 64)
            || sum != Some(other.omitted_observations)
        {
            return false;
        }
        self.summary.omitted_observations = self
            .summary
            .omitted_observations
            .saturating_add(other.omitted_observations);
        self.summary.omitted_bytes = self
            .summary
            .omitted_bytes
            .saturating_add(other.omitted_bytes);
        for (reason, count) in &other.reasons {
            let slot = self.summary.reasons.entry(reason.clone()).or_default();
            *slot = slot.saturating_add(*count);
        }
        true
    }
}

/// The optional context is bounded data. It never selects a host output path.
pub fn valid_context(context: &Map<String, Value>) -> bool {
    fn cost(value: &Value, depth: usize, nodes: &mut usize) -> Option<usize> {
        *nodes += 1;
        if depth > 16 || *nodes > 4096 {
            return None;
        }
        let length = match value {
            Value::Object(map) => {
                if map.len() > 256 {
                    return None;
                }
                let mut sum = 2 + map.len().saturating_sub(1);
                for (key, value) in map {
                    if key.len() > 128 {
                        return None;
                    }
                    sum += serde_json::to_vec(key).ok()?.len() + 1 + cost(value, depth + 1, nodes)?;
                    if sum > MAX_CONTEXT_BYTES {
                        return None;
                    }
                }
                sum
            }
            Value::Array(values) => {
                if values.len() > 256 {
                    return None;
                }
                let mut sum = 2 + values.len().saturating_sub(1);
                for value in values {
                    sum += cost(value, depth + 1, nodes)?;
                    if sum > MAX_CONTEXT_BYTES {
                        return None;
                    }
                }
                sum
            }
            Value::String(s) => {
                if s.len() > 32768 {
                    return None;
                }
                serde_json::to_vec(s).ok()?.len()
            }
            _ => serde_json::to_vec(value).ok()?.len(),
        };
        (length <= MAX_CONTEXT_BYTES).then_some(length)
    }
    if context.len() > 256 {
        return false;
    }
    let mut nodes = 1;
    let mut sum = 2 + context.len().saturating_sub(1);
    for (key, value) in context {
        if key.len() > 128 {
            return false;
        }
        let Some(value_cost) = cost(value, 1, &mut nodes) else {
            return false;
        };
        let Ok(key) = serde_json::to_vec(key) else {
            return false;
        };
        sum += key.len() + 1 + value_cost;
        if sum > MAX_CONTEXT_BYTES {
            return false;
        }
    }
    true
}

/// Validate provenance crossing the worker boundary. Payload bytes still need
/// the parent's regular-file, content-addressed filename, size, and hash gates.
/// Existing kinds permit absent context; new kinds require their typed context.
pub fn valid_observation_json(value: &Value) -> bool {
    valid_observation_json_with_profile(value, CaptureProfile::Legacy32V1)
}
pub fn valid_observation_json_with_profile(value: &Value, profile: CaptureProfile) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    let kind = object.get("kind").and_then(Value::as_str);
    if !kind.is_some_and(|kind| {
        [
            "guest_file",
            "memory_snapshot",
            "container_stream",
            "registry_value",
            "carved_image",
        ]
        .contains(&kind)
    }) || object
        .get("source")
        .and_then(Value::as_str)
        .is_none_or(|s| s.len() > 256)
        || object
            .get("guest_path")
            .and_then(Value::as_str)
            .is_none_or(|s| s.len() > 32768)
    {
        return false;
    }
    let context = if let Some(value) = object.get("context") {
        let Some(context) = value.as_object() else {
            return false;
        };
        if !valid_context(context) {
            return false;
        }
        Some(context)
    } else {
        None
    };
    let Some(kind) = kind else {
        return false;
    };
    match kind {
        "container_stream" => context
            .and_then(|c| c.get("container_stream_path"))
            .and_then(Value::as_array)
            .is_some_and(|path| {
                !path.is_empty()
                    && path.len() <= 32
                    && path.iter().all(|part| {
                        part.as_str().is_some_and(|s| {
                            !s.is_empty()
                                && s.encode_utf16().count() <= 31
                                && !s.contains(['\0', '/', '\\', ':', '!'])
                        })
                    })
            }),
        "registry_value" => context.is_some_and(|c| {
            c.get("registry_key")
                .and_then(Value::as_str)
                .is_some_and(|s| {
                    !s.is_empty() && s.encode_utf16().count() <= 32767 && !s.contains('\0')
                })
                && c.get("registry_value")
                    .and_then(Value::as_str)
                    .is_some_and(|s| s.encode_utf16().count() <= 16383 && !s.contains('\0'))
                && c.get("registry_type").and_then(Value::as_u64) == Some(3)
        }),
        "carved_image" => context.is_some_and(|c| {
            c.get("carved_kind").and_then(Value::as_str) == Some("structural_pe")
                && c.get("capture_origin")
                    .and_then(Value::as_str)
                    .is_some_and(|s| ["memory", "container_stream", "registry_value"].contains(&s))
                && mapped_context_valid(c, profile)
        }),
        "memory_snapshot" => context.is_none_or(|c| {
            if profile == CaptureProfile::Driver128V1
                && c.get("layout").and_then(Value::as_str) == Some("mapped_image")
            {
                c.get("reconstruction").and_then(Value::as_str) == Some("none")
                    && c.get("image_size")
                        .and_then(Value::as_u64)
                        .is_some_and(|n| n > 0 && n <= profile.limits().single as u64)
            } else {
                mapped_context_valid(c, profile)
            }
        }),
        _ => true,
    }
}

fn mapped_context_valid(context: &Map<String, Value>, profile: CaptureProfile) -> bool {
    context.get("layout").and_then(Value::as_str) != Some("mapped_image")
        || context.get("reconstruction").and_then(Value::as_str) == Some("section_rva_to_raw")
            && context
                .get("image_size")
                .and_then(Value::as_u64)
                .is_some_and(|n| n > 0 && n <= profile.limits().single as u64)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shared_content_retains_distinct_guest_paths_without_using_them_as_filenames() {
        let mut catalog = ArtifactCatalog::default();
        for path in ["C:\\guest\\file.bin", "../../host.exe"] {
            catalog.add(
                b"RUST".to_vec(),
                ArtifactKind::GuestFile,
                "virtual_file",
                path,
            );
        }
        assert_eq!(catalog.items.len(), 1);
        let item = &catalog.items[0];
        assert_eq!(item.observations.len(), 2);
        assert_eq!(item.data, b"RUST");
        assert_eq!(item.size, 4);
        assert_eq!(item.filename, format!("{:x}.bin", Sha256::digest(b"RUST")));
        let json = serde_json::to_string(item).unwrap();
        assert!(!json.contains("\"data\""));
        assert_eq!(catalog.summary.omitted_observations, 0);
    }
    #[test]
    fn metadata_limits_record_omissions_instead_of_silently_dropping_evidence() {
        let mut catalog = ArtifactCatalog::default();
        catalog.add(
            vec![1],
            ArtifactKind::MemorySnapshot,
            "memory",
            &"a".repeat(32769),
        );
        assert_eq!(catalog.summary.reasons["observation_field_limit"], 1);
        for _ in 0..40 {
            catalog.add(
                vec![1],
                ArtifactKind::MemorySnapshot,
                "memory",
                &"b".repeat(32768),
            );
        }
        assert!(catalog.summary.reasons["manifest_size_limit"] > 0);
        assert_eq!(catalog.items.len(), 1);
        assert!(catalog.metadata <= MAX_METADATA);
    }

    #[test]
    fn legacy_add_keeps_its_exact_json_shape_without_a_context_field() {
        let mut catalog = ArtifactCatalog::default();
        catalog.add(
            b"RUST".to_vec(),
            ArtifactKind::GuestFile,
            "virtual_file",
            "C:\\fixture",
        );
        let value = serde_json::to_value(&catalog.items[0]).unwrap();
        assert_eq!(
            value["observations"][0],
            serde_json::json!({"kind":"guest_file","source":"virtual_file","guest_path":"C:\\fixture"})
        );
        assert!(value["observations"][0].get("context").is_none());
        let mut second = ArtifactCatalog::default();
        second.add_with_context(
            b"RUST".to_vec(),
            ArtifactKind::GuestFile,
            "virtual_file",
            "C:\\fixture",
            None,
        );
        assert_eq!(
            serde_json::to_value(&catalog.items).unwrap(),
            serde_json::to_value(&second.items).unwrap()
        );
    }

    #[test]
    fn new_provenance_requires_typed_bounded_context_and_preserves_shared_payloads() {
        let mut catalog = ArtifactCatalog::default();
        let context=serde_json::json!({"registry_key":"HKCU\\Fixture","registry_value":"Payload","registry_type":3}).as_object().unwrap().clone();
        catalog.add_with_context(
            b"RUST".to_vec(),
            ArtifactKind::RegistryValue,
            "registry_value",
            "HKCU\\Fixture\\Payload",
            Some(context),
        );
        catalog.add(b"RUST".to_vec(), ArtifactKind::MemorySnapshot, "memory", "");
        assert_eq!(catalog.items.len(), 1);
        assert_eq!(catalog.items[0].observations.len(), 2);
        assert!(
            catalog.items[0]
                .observations
                .iter()
                .all(|item| valid_observation_json(&serde_json::to_value(item).unwrap()))
        );
        catalog.add_with_context(
            b"invalid".to_vec(),
            ArtifactKind::CarvedImage,
            "carved",
            "",
            None,
        );
        assert_eq!(catalog.items.len(), 1);
        assert_eq!(catalog.summary.reasons["observation_context_invalid"], 1);
        for kind in [
            "unpacked_driver",
            "host_file",
            "registry_value",
            "carved_image",
            "container_stream",
        ] {
            assert!(!valid_observation_json(
                &serde_json::json!({"kind":kind,"source":"fixture","guest_path":""})
            ));
        }
        let mut large = Map::new();
        large.insert("value".into(), Value::String("x".repeat(32769)));
        assert!(!valid_context(&large));
        let mut deep = Value::Bool(true);
        for _ in 0..18 {
            deep = serde_json::json!({"nested":deep});
        }
        assert!(!valid_context(deep.as_object().unwrap()));
    }

    #[test]
    fn grouped_omissions_merge_exactly_and_inconsistent_counts_leave_summary_untouched() {
        let mut catalog = ArtifactCatalog::default();
        let good = CaptureSummary {
            omitted_observations: 2,
            omitted_bytes: 14,
            reasons: BTreeMap::from([("source_limit".to_owned(), 2)]),
        };
        assert!(catalog.merge_omissions(&good));
        assert_eq!(catalog.summary.omitted_observations, 2);
        assert_eq!(catalog.summary.omitted_bytes, 14);
        let mut bad = good;
        bad.omitted_observations = 3;
        assert!(!catalog.merge_omissions(&bad));
        assert_eq!(catalog.summary.omitted_observations, 2);
        assert_eq!(catalog.summary.omitted_bytes, 14);
    }
}
