//! Pure bounded legacy report production from verified typed guest evidence.
//! No filesystem, sample execution, HTML rendering or unpacking certification.
use crate::{
    artifacts::{Artifact, ArtifactKind, CaptureSummary, valid_observation_json},
    reports,
};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{self, Write},
};
pub const MAX_PAYLOAD_BYTES: usize = 128 * 1024 * 1024;
pub const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
pub const MAX_METADATA_BYTES: usize = 256 * 1024;
const ORIGIN: &str = "_emumee_typed_origin";
#[derive(Debug, thiserror::Error)]
#[error("Report generation rejected: {0}")]
pub struct BuildError(pub &'static str);
type Result<T> = std::result::Result<T, BuildError>;
fn check(ok: bool, why: &'static str) -> Result<()> {
    if ok { Ok(()) } else { Err(BuildError(why)) }
}
pub fn digest(raw: &[u8]) -> String {
    format!("{:x}", Sha256::digest(raw))
}
struct Limited {
    bytes: Vec<u8>,
    maximum: usize,
}
impl Write for Limited {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.maximum - self.bytes.len() {
            return Err(io::Error::other("bounded JSON limit"));
        }
        self.bytes.extend(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
pub fn bounded_json(value: &impl Serialize, maximum: usize) -> Result<Vec<u8>> {
    let mut writer = Limited {
        bytes: Vec::new(),
        maximum,
    };
    serde_json::to_writer(&mut writer, value)
        .map_err(|_| BuildError("JSON serialization/byte bound"))?;
    Ok(writer.bytes)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Termination {
    Normal,
    Timeout,
    WorkerFailure,
    Cancelled,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkCoverage {
    NotMonitored,
    ModelOnly,
}
/// Versioned legacy envelope limits. A future large-driver profile needs its own
/// reviewed validator/schema; this profile cannot hold an entire >32MiB driver.
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    LegacyV1,
}
impl Profile {
    fn payload_limits(self) -> (usize, usize) {
        match self {
            Self::LegacyV1 => (reports::MAX_ARTIFACT_BYTES, MAX_PAYLOAD_BYTES),
        }
    }
}
pub struct Input<'p, 'm> {
    pub run_id: &'m str,
    pub started_at: &'m str,
    pub finished_at: &'m str,
    pub sample: &'m Value,
    pub execution: &'m Value,
    pub execution_mode: &'m str,
    pub manifest: &'m Value,
    pub network: &'m Value,
    pub network_coverage: NetworkCoverage,
    pub termination: Termination,
    pub checkpoint_recovered: bool,
    pub profile: Profile,
    pub artifacts: &'p [Artifact],
    pub omissions: &'m CaptureSummary,
}
pub struct Payload<'a> {
    pub filename: String,
    pub bytes: &'a [u8],
    pub sha256: String,
}
pub struct Bundle<'a> {
    pub summary: Vec<u8>,
    pub engine: Vec<u8>,
    pub network: Vec<u8>,
    pub manifest: Vec<u8>,
    pub checkpoint: Vec<u8>,
    pub payloads: Vec<Payload<'a>>,
}
#[derive(Serialize)]
struct Engine<'a> {
    schema: u32,
    role: &'static str,
    execution: &'a Value,
    run_manifest: &'a Value,
    scope: &'static str,
}
#[derive(Serialize)]
struct Network<'a> {
    schema: u32,
    coverage: NetworkCoverage,
    broker_monitoring_complete: bool,
    report: &'a Value,
    scope: &'static str,
}
fn short_name(names: &mut BTreeMap<String, String>, hash: &str) -> Result<String> {
    check(
        hash.len() == 64
            && hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "artifact digest syntax",
    )?;
    let name = format!("{}.bin", &hash[..20]);
    if let Some(previous) = names.get(&name) {
        check(previous == hash, "artifact prefix collision")?;
    } else {
        names.insert(name.clone(), hash.to_owned());
    }
    Ok(name)
}
fn status(
    execution: &Value,
    termination: Termination,
) -> Result<(&'static str, &'static str, Vec<String>)> {
    let reason = execution
        .get("completion_reason")
        .and_then(Value::as_str)
        .ok_or(BuildError("missing engine completion reason"))?;
    let mut errors = Vec::new();
    if let Some(error) = execution.get("error").filter(|v| !v.is_null()) {
        let error = error
            .as_str()
            .ok_or(BuildError("invalid engine error type"))?;
        check(error.len() <= 8192, "engine error bound")?;
        errors.push(error.to_owned());
    }
    Ok(match termination {
        Termination::Timeout => {
            errors.push("Worker watchdog expired; guest completion is not assumed".into());
            ("timeout", "timeout", errors)
        }
        Termination::WorkerFailure => {
            errors.push("Worker did not complete its report lifecycle".into());
            ("failed", "worker_failure", errors)
        }
        Termination::Cancelled => {
            errors.push("Analysis cancelled".into());
            ("partial", "cancelled", errors)
        }
        Termination::Normal => match reason {
            "entry_return" | "exit_process" => {
                let observed = if reason == "entry_return" {
                    execution
                        .get("guest_entry_return")
                        .and_then(Value::as_u64)
                        .is_some()
                } else {
                    execution.get("exit_process_observed") == Some(&Value::Bool(true))
                        && execution
                            .get("guest_exit_code")
                            .and_then(Value::as_u64)
                            .is_some_and(|n| n <= u32::MAX as u64)
                };
                if !observed {
                    errors.push(
                        "Completion reason lacks the required modeled return/exit evidence".into(),
                    );
                }
                (
                    if errors.is_empty() {
                        "completed"
                    } else {
                        "partial"
                    },
                    if reason == "entry_return" {
                        "entry_return"
                    } else {
                        "exit_process"
                    },
                    errors,
                )
            }
            "instruction_budget" | "instruction_limit" => ("partial", "instruction_limit", errors),
            "timeout" => {
                errors.push("Engine timeout reached".into());
                ("timeout", "timeout", errors)
            }
            "static_inspection" => ("partial", "static_inspection", errors),
            "error" => {
                if errors.is_empty() {
                    errors.push("Guest execution stopped with an error".into());
                }
                ("partial", "error", errors)
            }
            _ => {
                errors.push("Guest completion path was not observed".into());
                ("partial", "unknown", errors)
            }
        },
    })
}
pub fn build<'p>(input: Input<'p, '_>) -> Result<Bundle<'p>> {
    let (single_payload_limit, total_payload_limit) = input.profile.payload_limits();
    check(reports::valid_run_id(input.run_id), "run identity")?;
    check(
        input.sample.is_object()
            && input.execution.is_object()
            && input.manifest.is_object()
            && input.network.is_object(),
        "report object shape",
    )?;
    check(
        matches!(input.execution_mode, "kernel" | "user"),
        "execution mode",
    )?;
    for time in [input.started_at, input.finished_at] {
        check(
            !time.is_empty() && time.len() <= 64 && time.is_ascii(),
            "timestamp bound",
        )?;
    }
    bounded_json(input.sample, MAX_METADATA_BYTES)?;
    bounded_json(input.manifest, MAX_METADATA_BYTES)?;
    let count = input
        .execution
        .get("instruction_count")
        .and_then(Value::as_u64)
        .ok_or(BuildError("engine instruction count"))?;
    let full_return = match input
        .execution
        .get("guest_entry_return")
        .filter(|v| !v.is_null())
    {
        Some(v) => Some(v.as_u64().ok_or(BuildError("engine return type"))?),
        None => None,
    };
    check(
        crate::memory_observation::valid_execution(input.execution),
        "indicator execution authority",
    )?;
    check(
        crate::memory_observation::valid_declaration(input.manifest, input.execution),
        "indicator profile/case declaration",
    )?;
    let (state, reason, errors) = status(input.execution, input.termination)?;
    let mut run_manifest = input.manifest.clone();
    for key in ["engine_report_integrity", "network_broker_report_integrity"] {
        if let Some(value) = run_manifest.get(key) {
            check(
                value == reports::ENGINE_INTEGRITY,
                "manifest integrity declaration",
            )?;
        }
        run_manifest[key] = json!(reports::ENGINE_INTEGRITY);
    }
    run_manifest["analysis_role"] = json!("closed_generated_fixture");
    run_manifest["report_profile"] = json!(input.profile);
    let engine = bounded_json(
        &Engine {
            schema: 1,
            role: "closed_generated_analysis",
            execution: input.execution,
            run_manifest: &run_manifest,
            scope: "Bounded engine evidence for an owned generated fixture; no host execution or successful unpacking claim",
        },
        reports::MAX_ENGINE_BYTES,
    )?;
    let network = bounded_json(
        &Network {
            schema: 1,
            coverage: input.network_coverage,
            broker_monitoring_complete: false,
            report: input.network,
            scope: "Limited generated-fixture network coverage; this document does not certify a complete broker journal",
        },
        reports::MAX_NETWORK_REPORT_BYTES,
    )?;
    check(input.artifacts.len() <= 10_000, "artifact count")?;
    let mut total = 0usize;
    let mut metadata = 2usize;
    let mut observations = Vec::new();
    let mut representatives = Vec::new();
    let mut payloads = Vec::new();
    let mut names = BTreeMap::new();
    let mut by_hash = BTreeMap::new();
    let mut seen = BTreeSet::new();
    let mut provenance: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    let mut omission_check = crate::artifacts::ArtifactCatalog::default();
    check(
        omission_check.merge_omissions(input.omissions),
        "invalid capture omission counters",
    )?;
    for artifact in input.artifacts {
        check(
            artifact.size > 0
                && artifact.size == artifact.data.len()
                && artifact.size <= single_payload_limit,
            "artifact size outside report profile",
        )?;
        check(
            artifact.sha256.len() == 64 && artifact.filename.len() == 68,
            "artifact hash/catalog syntax",
        )?;
        check(
            artifact.filename == format!("{}.bin", artifact.sha256)
                && artifact.sha256 == digest(&artifact.data),
            "artifact hash/catalog binding",
        )?;
        check(
            seen.insert(artifact.sha256.as_str()),
            "duplicate typed payload",
        )?;
        total = total
            .checked_add(artifact.size)
            .ok_or(BuildError("artifact byte overflow"))?;
        check(
            total <= total_payload_limit,
            "artifact total bytes outside report profile",
        )?;
        check(
            !artifact.observations.is_empty(),
            "missing artifact observations",
        )?;
        let filename = short_name(&mut names, &artifact.sha256)?;
        by_hash.insert(artifact.sha256.as_str(), artifact.data.as_slice());
        payloads.push(Payload {
            filename: filename.clone(),
            bytes: &artifact.data,
            sha256: artifact.sha256.clone(),
        });
        let has_pe_metadata = reports::bounded_pe_metadata(&artifact.data).is_some();
        for (index, observation) in artifact.observations.iter().enumerate() {
            let typed: Value = serde_json::from_slice(&bounded_json(observation, 128 * 1024)?)
                .map_err(|_| BuildError("typed observation encode"))?;
            check(valid_observation_json(&typed), "typed observation context")?;
            check(observations.len() < 10_000, "observation count")?;
            let mut context = observation.context.clone().unwrap_or_default();
            check(
                !context.contains_key(ORIGIN),
                "reserved origin context collision",
            )?;
            context.insert(ORIGIN.into(),json!({"kind":typed["kind"],"source":observation.source,"guest_path":observation.guest_path,
                "catalog_filename":artifact.filename,"legacy_guest_path_truncated":observation.guest_path.chars().count()>4096}));
            let mapped = observation.kind == ArtifactKind::MemorySnapshot;
            let kind = if mapped {
                "memory"
            } else if has_pe_metadata {
                "pe"
            } else if [b"#!".as_slice(), b"<script", b"<?xml", b"powershell"]
                .iter()
                .any(|p| artifact.data.starts_with(p))
                || [
                    ".ps1", ".vbs", ".js", ".jse", ".hta", ".bat", ".cmd", ".wsf",
                ]
                .iter()
                .any(|e| observation.guest_path.to_ascii_lowercase().ends_with(e))
            {
                "script"
            } else {
                "binary"
            };
            if observation.kind == ArtifactKind::CarvedImage {
                check(kind == "pe", "carved image lacks bounded PE metadata")?;
            }
            let item = json!({"file":filename,"sha256":artifact.sha256,"size":artifact.size,"kind":kind,"source":observation.source,
                "guest_path":observation.guest_path.chars().take(4096).collect::<String>(),"context":context});
            check(
                reports::valid_artifact_metadata(&item),
                "legacy artifact metadata",
            )?;
            let size = bounded_json(&item, MAX_MANIFEST_BYTES)?.len();
            metadata = metadata
                .checked_add(size + 256)
                .ok_or(BuildError("metadata overflow"))?;
            check(metadata <= MAX_MANIFEST_BYTES, "manifest metadata budget")?;
            provenance
                .entry(artifact.sha256.clone())
                .or_default()
                .push(reports::group_observation(&item).ok_or(BuildError("group observation"))?);
            if index == 0 {
                representatives.push(item.clone());
            }
            observations.push(item);
        }
    }
    // Hash/group one representative per unique payload; duplicate provenance does
    // not trigger repeated full-buffer clones or hashing.
    let mut loader = |item: &Value| by_hash.get(item["sha256"].as_str()?).copied();
    let mut groups = reports::groups_from_verified_payloads(&representatives, &mut loader)
        .ok_or(BuildError("verified group generation"))?;
    for group in groups.as_array_mut().ok_or(BuildError("group shape"))? {
        let hash = group["sha256"]
            .as_str()
            .ok_or(BuildError("group digest"))?
            .to_owned();
        group["observations"] = Value::Array(
            provenance
                .remove(&hash)
                .ok_or(BuildError("group observation binding"))?,
        );
    }
    let manifest = bounded_json(&observations, MAX_MANIFEST_BYTES)?;
    let checkpoint = manifest.clone();
    let omissions = json!({"omitted_observations":input.omissions.omitted_observations,"omitted_bytes":input.omissions.omitted_bytes,
        "reasons":input.omissions.reasons,"examples":[]});
    let mut summary = json!({"id":input.run_id,"started_at":input.started_at,"finished_at":input.finished_at,"sample":input.sample,
        "execution_mode":input.execution_mode,"status":state,"completion_reason":reason,"errors":errors,"instruction_count":count,
        "instruction_limit_reached":reason=="instruction_limit","timeout_reached":reason=="timeout","guest_entry_return":full_return.filter(|n|*n<=u32::MAX as u64),
        "guest_trace_complete":false,"trace_coverage":"bounded_tail_and_counters","artifact_checkpoint_recovered":input.checkpoint_recovered,
        "artifacts":observations,"artifact_groups":groups,"artifact_capture":omissions,"run_manifest":run_manifest,
        "engine_report":"engine-report.json","engine_report_sha256":digest(&engine),"engine_report_size":engine.len(),
        "network_broker_report":"network-broker.json","network_broker_report_sha256":digest(&network),"network_broker_report_size":network.len(),
        "network_broker_complete":false,"network_coverage":input.network_coverage,
        "scope":"Closed generated analysis/report path; general sample execution and confirmed unpacking remain gated"});
    for field in ["memory_strings", "memory_string_sources"] {
        if let Some(value) = input.execution.get(field) {
            summary[field] = value.clone();
        }
    }
    check(
        crate::memory_observation::summary_matches(&summary, input.execution),
        "indicator summary binding",
    )?;
    if reason == "exit_process"
        && input.execution.get("exit_process_observed") == Some(&Value::Bool(true))
    {
        if let Some(code) = input
            .execution
            .get("guest_exit_code")
            .and_then(Value::as_u64)
            .filter(|n| *n <= u32::MAX as u64)
        {
            summary["guest_exit_code"] = json!(code);
        }
    }
    if full_return.is_some_and(|n| n > u32::MAX as u64) {
        summary["guest_entry_return_full"] = json!(full_return);
        summary["legacy_return_scope"] =
            json!("Full u64 retained; legacy uint32 field is null and was not truncated");
    }
    check(
        reports::valid_summary(&summary),
        "generated summary envelope",
    )?;
    check(
        reports::verified_report(&summary, reports::BoundReport::Engine, &engine).is_some()
            && reports::verified_report(&summary, reports::BoundReport::NetworkBroker, &network)
                .is_some(),
        "generated report binding",
    )?;
    let summary = bounded_json(&summary, reports::MAX_SUMMARY_BYTES)?;
    Ok(Bundle {
        summary,
        engine,
        network,
        manifest,
        checkpoint,
        payloads,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifacts::ArtifactCatalog;
    fn build_test<'a>(
        execution: &Value,
        captures: &'a ArtifactCatalog,
        termination: Termination,
    ) -> Bundle<'a> {
        // Only artifacts are borrowed by the output; metadata is serialized here.
        build(Input {
            run_id: "20261018T120000Z-12345678",
            started_at: "2026-10-18T12:00:00Z",
            finished_at: "2026-10-18T12:00:01Z",
            sample: &json!({"name":"owned.exe"}),
            execution,
            execution_mode: "user",
            manifest: &json!({}),
            network: &json!({"events":[]}),
            network_coverage: NetworkCoverage::NotMonitored,
            termination,
            checkpoint_recovered: false,
            profile: Profile::LegacyV1,
            artifacts: &captures.items,
            omissions: &captures.summary,
        })
        .unwrap()
    }
    #[test]
    fn completion_budget_static_and_worker_outcomes_do_not_guess_success() {
        let captures = ArtifactCatalog::default();
        for (reason, termination, expected) in [
            ("entry_return", Termination::Normal, "completed"),
            ("instruction_budget", Termination::Normal, "partial"),
            ("static_inspection", Termination::Normal, "partial"),
            ("error", Termination::Normal, "partial"),
            ("unknown", Termination::Normal, "partial"),
            ("entry_return", Termination::Timeout, "timeout"),
            ("entry_return", Termination::WorkerFailure, "failed"),
            ("entry_return", Termination::Cancelled, "partial"),
        ] {
            let b = build_test(
                &json!({"completion_reason":reason,"instruction_count":17,"guest_entry_return":u64::MAX,"error":null}),
                &captures,
                termination,
            );
            let s: Value = serde_json::from_slice(&b.summary).unwrap();
            assert_eq!(s["status"], expected);
            assert!(s["guest_entry_return"].is_null());
            assert_eq!(s["guest_entry_return_full"], u64::MAX);
            assert_eq!(s["guest_trace_complete"], false);
            assert_eq!(s["network_broker_complete"], false);
            assert_eq!(s["network_coverage"], "not_monitored");
        }
        for (execution, expected) in [
            (
                json!({"completion_reason":"entry_return","instruction_count":0,"guest_entry_return":null}),
                "partial",
            ),
            (
                json!({"completion_reason":"exit_process","instruction_count":0,"guest_exit_code":17}),
                "partial",
            ),
            (
                json!({"completion_reason":"exit_process","instruction_count":0,"guest_exit_code":17,"exit_process_observed":true}),
                "completed",
            ),
            (
                json!({"completion_reason":"error","instruction_count":0,"guest_entry_return":17,"error":null}),
                "partial",
            ),
        ] {
            let b = build_test(&execution, &captures, Termination::Normal);
            let s: Value = serde_json::from_slice(&b.summary).unwrap();
            assert_eq!(s["status"], expected);
        }
    }
    #[test]
    fn binary_payloads_and_typed_provenance_bind_legacy_groups_without_losing_full_identity() {
        let mut captures = ArtifactCatalog::default();
        captures.add(
            vec![0, 255, 128],
            ArtifactKind::GuestFile,
            "managed_write_all_bytes",
            "C:\\owned.bin",
        );
        captures.add(
            vec![0, 255, 128],
            ArtifactKind::MemorySnapshot,
            "memory",
            "guest-only",
        );
        let b = build_test(
            &json!({"completion_reason":"entry_return","instruction_count":3,"guest_entry_return":17}),
            &captures,
            Termination::Normal,
        );
        assert_eq!(b.payloads.len(), 1);
        assert_eq!(b.payloads[0].bytes, [0, 255, 128]);
        assert_eq!(
            b.payloads[0].filename,
            format!("{}.bin", &digest(&[0, 255, 128])[..20])
        );
        let s: Value = serde_json::from_slice(&b.summary).unwrap();
        assert_eq!(s["artifacts"].as_array().unwrap().len(), 2);
        assert_eq!(
            s["artifact_groups"][0]["observations"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            s["artifacts"][0]["context"][ORIGIN]["catalog_filename"],
            captures.items[0].filename
        );
        assert_eq!(s["artifacts"][1]["kind"], "memory");
        assert_eq!(b.manifest, b.checkpoint);
        assert!(reports::verified_artifact_manifest(
            &b.manifest,
            &s["artifacts"],
            Some(&s["artifact_groups"]),
            |_| Some(vec![0, 255, 128])
        ));
    }
    #[test]
    fn digest_prefix_collisions_reserved_context_and_bounded_writes_fail_without_overwrite() {
        let mut names = BTreeMap::new();
        let first = "a".repeat(64);
        let second = format!("{}{}", "a".repeat(20), "b".repeat(44));
        short_name(&mut names, &first).unwrap();
        assert!(short_name(&mut names, &second).is_err());
        assert_eq!(names.values().next().unwrap(), &first);
        assert!(bounded_json(&json!({"text":"<script>not HTML</script>"}), 8).is_err());
        let mut captures = ArtifactCatalog::default();
        captures.add(vec![1], ArtifactKind::GuestFile, "fixture", "x");
        captures.items[0].sha256 = "0".repeat(64);
        let result = build(Input {
            run_id: "20261018T120000Z-12345678",
            started_at: "x",
            finished_at: "x",
            sample: &json!({}),
            execution: &json!({"completion_reason":"entry_return","instruction_count":0}),
            execution_mode: "user",
            manifest: &json!({}),
            network: &json!({}),
            network_coverage: NetworkCoverage::NotMonitored,
            termination: Termination::Normal,
            checkpoint_recovered: false,
            profile: Profile::LegacyV1,
            artifacts: &captures.items,
            omissions: &captures.summary,
        });
        assert!(result.is_err());
    }
    #[test]
    fn caller_origin_omission_and_empty_observation_forgery_are_rejected() {
        let execution = json!({"completion_reason":"entry_return","instruction_count":1,"guest_entry_return":17});
        let sample = json!({});
        let manifest = json!({});
        let network = json!({});
        let mut captures = ArtifactCatalog::default();
        captures.add(vec![1, 2], ArtifactKind::GuestFile, "fixture", "x");
        let rejected = |captures: &ArtifactCatalog| {
            build(Input {
                run_id: "20261018T120000Z-12345678",
                started_at: "x",
                finished_at: "x",
                sample: &sample,
                execution: &execution,
                execution_mode: "user",
                manifest: &manifest,
                network: &network,
                network_coverage: NetworkCoverage::NotMonitored,
                termination: Termination::Normal,
                checkpoint_recovered: false,
                profile: Profile::LegacyV1,
                artifacts: &captures.items,
                omissions: &captures.summary,
            })
            .is_err()
        };
        captures.items[0].observations[0].context = Some(serde_json::Map::from_iter([(
            ORIGIN.into(),
            json!({"kind":"carved_image"}),
        )]));
        assert!(rejected(&captures));
        captures.items[0].observations[0].context = None;
        captures.summary.omitted_observations = 1;
        assert!(rejected(&captures));
        captures.summary = CaptureSummary::default();
        captures.items[0].observations.clear();
        assert!(rejected(&captures));
    }
    #[test]
    fn serialized_timing_floats_preserve_report_bytes_and_hashes_after_parent_reparse() {
        // Saved owned native-capture66 exposed a one-ULP default-parser drift:
        // 107824.16367155101 ->107824.163671551, changing engine length+digest.
        // Correct float decoding preserves the exact envelope comparison; no
        // payload/group/provenance verification is relaxed.
        let mut captures = ArtifactCatalog::default();
        captures.add(
            b"RUST".to_vec(),
            ArtifactKind::GuestFile,
            "virtual_file_at_stop",
            r"c:\workspace\rust-fixture.bin",
        );
        let execution = json!({"completion_reason":"entry_return","instruction_count":39,"guest_entry_return":1414747474u64,
            "engine_seconds":0.0003617f64,"instructions_per_second":107824.16367155101f64,"error":null});
        let first = build_test(&execution, &captures, Termination::Normal);
        let reparsed: Value = serde_json::from_slice(&first.engine).unwrap();
        assert_eq!(
            reparsed["execution"]["instructions_per_second"]
                .as_f64()
                .unwrap()
                .to_bits(),
            0x40fa53029e660f6eu64
        );
        let rebuilt = build_test(&reparsed["execution"], &captures, Termination::Normal);
        assert_eq!(rebuilt.engine, first.engine);
        assert_eq!(digest(&rebuilt.engine), digest(&first.engine));
        assert_eq!(rebuilt.summary, first.summary);
        assert_eq!(rebuilt.network, first.network);
        assert_eq!(rebuilt.manifest, first.manifest);
    }
}
