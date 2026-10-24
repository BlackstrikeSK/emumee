//! Controller for closed generated analysis/report qualification only.
use super::worker::{launch_generated, save_new, verified_bundle};
use anyhow::{Context, Result, ensure};
use emumee_core::{
    analysis_fixture::{self, Arch, Case, Fault, Request},
    artifacts::{Artifact, ArtifactKind, CaptureSummary, Observation},
    pe::Architecture,
    report_bundle::{self, Input, NetworkCoverage, Profile, Termination},
    reports,
};
use emumee_platform::windows::{OutputLimits, WorkerStop, read_regular};
use serde_json::{Value, json};
use std::{collections::BTreeMap, ffi::OsString, path::Path};
fn now() -> Result<(String, String)> {
    let time = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
    let nonce = (time.as_nanos() as u32) ^ std::process::id();
    analysis_fixture::identity(time.as_secs(), nonce).map_err(anyhow::Error::msg)
}
fn parse_kind(s: &str) -> Result<ArtifactKind> {
    Ok(match s {
        "guest_file" => ArtifactKind::GuestFile,
        "memory_snapshot" => ArtifactKind::MemorySnapshot,
        "container_stream" => ArtifactKind::ContainerStream,
        "registry_value" => ArtifactKind::RegistryValue,
        "carved_image" => ArtifactKind::CarvedImage,
        _ => anyhow::bail!("Unknown typed artifact kind"),
    })
}
pub(crate) fn typed_catalog(
    execution: &Value,
    mut payloads: BTreeMap<String, Vec<u8>>,
) -> Result<(Vec<Artifact>, CaptureSummary)> {
    let items = execution["artifacts"]
        .as_array()
        .context("Engine typed artifact catalog missing")?;
    ensure!(items.len() <= 10000, "Typed artifact count limit");
    let mut captures = Vec::new();
    let mut count = 0usize;
    let mut metadata = 0usize;
    for item in items {
        let hash = item["sha256"].as_str().context("Typed hash missing")?;
        let filename = item["filename"]
            .as_str()
            .context("Typed filename missing")?;
        ensure!(
            hash.len() == 64 && filename == format!("{hash}.bin"),
            "Typed catalog hash/filename mismatch"
        );
        let data = payloads
            .remove(hash)
            .context("Typed catalog references unverified/missing payload")?;
        ensure!(
            item["size"].as_u64() == Some(data.len() as u64),
            "Typed size mismatch"
        );
        let source = item["observations"]
            .as_array()
            .context("Typed observations missing")?;
        ensure!(!source.is_empty(), "Typed observations empty");
        let mut observations = Vec::new();
        for value in source {
            count += 1;
            ensure!(count <= 10000, "Global observation count limit");
            metadata = metadata
                .checked_add(report_bundle::bounded_json(value, 128 * 1024)?.len() + 256)
                .context("Metadata overflow")?;
            ensure!(
                metadata <= report_bundle::MAX_MANIFEST_BYTES,
                "Global observation metadata limit"
            );
            ensure!(
                emumee_core::artifacts::valid_observation_json(value),
                "Typed observation validation failed"
            );
            observations.push(Observation {
                kind: parse_kind(value["kind"].as_str().context("kind missing")?)?,
                source: value["source"]
                    .as_str()
                    .context("source missing")?
                    .to_owned(),
                guest_path: value["guest_path"]
                    .as_str()
                    .context("guest path missing")?
                    .to_owned(),
                context: value
                    .get("context")
                    .map(|v| v.as_object().cloned().context("context type"))
                    .transpose()?,
            });
        }
        captures.push(Artifact {
            filename: filename.to_owned(),
            sha256: hash.to_owned(),
            size: data.len(),
            observations,
            data,
        });
    }
    ensure!(
        payloads.is_empty(),
        "Legacy report contains a payload absent from typed engine catalog"
    );
    let value = &execution["capture_summary"];
    let reasons = value["reasons"]
        .as_object()
        .context("Capture omissions missing")?;
    ensure!(reasons.len() <= 32, "Omission reason count");
    let summary = CaptureSummary {
        omitted_observations: value["omitted_observations"]
            .as_u64()
            .context("Omission count")?,
        omitted_bytes: value["omitted_bytes"].as_u64().context("Omission bytes")?,
        reasons: reasons
            .iter()
            .map(|(k, v)| Ok((k.clone(), v.as_u64().context("Omission reason value")?)))
            .collect::<Result<_>>()?,
    };
    let mut check = emumee_core::artifacts::ArtifactCatalog::default();
    ensure!(check.merge_omissions(&summary), "Omission summary invalid");
    Ok((captures, summary))
}
pub(crate) fn payloads(root: &Path, summary: &Value) -> Result<BTreeMap<String, Vec<u8>>> {
    let items = summary["artifacts"]
        .as_array()
        .context("Legacy observations missing")?;
    ensure!(items.len() <= 10000, "Legacy observation count");
    let mut values = BTreeMap::new();
    let mut names = BTreeMap::new();
    let mut bytes = 0usize;
    for item in items {
        ensure!(
            reports::valid_artifact_metadata(item),
            "Invalid legacy artifact path/envelope"
        );
        let hash = item["sha256"].as_str().unwrap();
        let filename = item["file"].as_str().unwrap();
        ensure!(
            filename == format!("{}.bin", &hash[..20]),
            "Closed report artifact filename changed"
        );
        if let Some(previous) = names.insert(filename.to_owned(), hash.to_owned()) {
            ensure!(previous == hash, "Artifact prefix collision");
        }
        if values.contains_key(hash) {
            continue;
        }
        let size = item["size"].as_u64().unwrap() as usize;
        bytes = bytes.checked_add(size).context("Artifact total overflow")?;
        ensure!(
            bytes <= report_bundle::MAX_PAYLOAD_BYTES,
            "Artifact total read limit"
        );
        let data = read_regular(&root.join("artifacts").join(filename), size, Some(root))?;
        ensure!(
            reports::verified_artifact(item, &data).is_some(),
            "Artifact payload hash/size mismatch"
        );
        values.insert(hash.to_owned(), data);
    }
    Ok(values)
}
fn finalize(
    root: &Path,
    request: &Request,
    request_hash: &str,
    witness: &[u8],
    termination: Termination,
    recovered: bool,
    receipt: Option<&Value>,
) -> Result<Value> {
    let draft_raw = read_regular(
        &root.join("worker-summary.json"),
        reports::MAX_SUMMARY_BYTES,
        Some(root),
    )?;
    let draft = reports::parse_summary(&draft_raw)?;
    let manifest = read_regular(
        &root.join("artifacts/manifest.json"),
        report_bundle::MAX_MANIFEST_BYTES,
        Some(root),
    )?;
    let checkpoint = read_regular(
        &root.join("artifact-checkpoint.json"),
        report_bundle::MAX_MANIFEST_BYTES,
        Some(root),
    )?;
    ensure!(
        manifest == checkpoint,
        "Artifact checkpoint/manifest changed"
    );
    ensure!(
        reports::manifest_matches(&manifest, &draft["artifacts"]),
        "Artifact manifest/provenance changed"
    );
    let engine_raw = read_regular(
        &root.join("engine-report.json"),
        reports::MAX_ENGINE_BYTES,
        Some(root),
    )?;
    let network_raw = read_regular(
        &root.join("network-broker.json"),
        reports::MAX_NETWORK_REPORT_BYTES,
        Some(root),
    )?;
    ensure!(
        reports::verified_report(&draft, reports::BoundReport::Engine, &engine_raw).is_some(),
        "Engine report hash/size mismatch"
    );
    ensure!(
        reports::verified_report(&draft, reports::BoundReport::NetworkBroker, &network_raw)
            .is_some(),
        "Network report hash/size mismatch"
    );
    if let Some(receipt) = receipt {
        ensure!(
            receipt["schema"] == 1
                && receipt["role"] == "closed_generated_analysis"
                && receipt["request_sha256"] == request_hash
                && receipt["input_sha256"] == request.input_sha256,
            "Analysis worker receipt binding mismatch"
        );
        ensure!(
            receipt["summary_sha256"] == report_bundle::digest(&draft_raw)
                && receipt["manifest_sha256"] == report_bundle::digest(&manifest)
                && receipt["engine_sha256"] == report_bundle::digest(&engine_raw)
                && receipt["network_sha256"] == report_bundle::digest(&network_raw),
            "Analysis receipt document hashes changed"
        );
    }
    let engine: Value = serde_json::from_slice(&engine_raw)?;
    let network: Value = serde_json::from_slice(&network_raw)?;
    ensure!(
        engine["schema"] == 1
            && engine["role"] == "closed_generated_analysis"
            && engine["run_manifest"] == draft["run_manifest"],
        "Engine role/manifest binding changed"
    );
    let run_manifest = &draft["run_manifest"];
    ensure!(
        draft["id"] == request.run_id
            && run_manifest["request_sha256"] == request_hash
            && run_manifest["input_sha256"] == request.input_sha256
            && run_manifest["input_size"] == request.input_size
            && run_manifest["case"] == serde_json::to_value(request.case)?
            && run_manifest["source_tree_sha256"] == env!("EMUMEE_BUILD_SOURCE_SHA256")
            && run_manifest["containment_sha256"] == report_bundle::digest(witness)
            && run_manifest["report_profile"] == "legacy_v1",
        "Analysis run identity/source/input binding changed"
    );
    ensure!(
        network["schema"] == 1 && network["broker_monitoring_complete"] == false,
        "Limited network document changed"
    );
    let coverage = match network["coverage"].as_str() {
        Some("model_only") => NetworkCoverage::ModelOnly,
        Some("not_monitored") => NetworkCoverage::NotMonitored,
        _ => anyhow::bail!("Unsupported network coverage claim"),
    };
    ensure!(
        emumee_core::memory_observation::summary_matches(&draft, &engine["execution"]),
        "Indicator summary/engine authority changed"
    );
    if let Some(profile) = request.case.observation_profile() {
        ensure!(
            run_manifest["memory_string_profile"] == profile
                && Some(engine["execution"]["memory_string_sources"]["case"].clone())
                    == request.case.observation_case(),
            "Indicator case/profile/request identity changed"
        );
    } else {
        ensure!(
            run_manifest.get("memory_string_profile").is_none()
                && engine["execution"].get("memory_strings").is_none()
                && engine["execution"].get("memory_string_sources").is_none(),
            "Unrequested indicator authority on an old role"
        );
    }
    let (captures, omissions) = typed_catalog(&engine["execution"], payloads(root, &draft)?)?;
    let input = |termination, checkpoint_recovered| Input {
        run_id: &request.run_id,
        started_at: draft["started_at"].as_str().unwrap_or_default(),
        finished_at: draft["finished_at"].as_str().unwrap_or_default(),
        sample: &draft["sample"],
        execution: &engine["execution"],
        execution_mode: draft["execution_mode"].as_str().unwrap_or_default(),
        manifest: run_manifest,
        network: &network["report"],
        network_coverage: coverage,
        termination,
        checkpoint_recovered,
        profile: Profile::LegacyV1,
        artifacts: &captures,
        omissions: &omissions,
    };
    let expected = report_bundle::build(input(Termination::Normal, false))?;
    let expected_summary: Value = serde_json::from_slice(&expected.summary)?;
    ensure!(
        expected_summary == draft
            && expected.engine == engine_raw
            && expected.network == network_raw
            && expected.manifest == manifest,
        "Legacy groups/status or typed engine provenance changed"
    );
    let final_bundle = report_bundle::build(input(termination, recovered))?;
    let mut summary = reports::parse_summary(&final_bundle.summary)?;
    summary["controller_integrity"] = json!("verified");
    Ok(summary)
}
pub fn run(root: &Path, name: &str, architecture: Architecture, fault_name: &str) -> Result<Value> {
    let tamper = match name {
        "tamper-request" => Some("Analysis request hash changed"),
        "tamper-input" => Some("Analysis input hash/size/generated bytes changed"),
        "unknown-request-field" => Some("Analysis request schema/enum decode rejected"),
        "foreign-owned-fixture" => Some("Analysis request is not the closed generated fixture"),
        _ => None,
    };
    let case = if tamper.is_some() {
        Case::ManagedCapture
    } else {
        Case::parse(name).context("Unknown closed analysis case")?
    };
    let fault = Fault::parse(fault_name).context("Unknown closed analysis fault")?;
    ensure!(
        tamper.is_none() || fault == Fault::None,
        "Do not combine request tamper and worker faults"
    );
    let arch = if architecture == Architecture::X64 {
        Arch::X64
    } else {
        Arch::X86
    };
    let verified = verified_bundle()?;
    let root = std::path::absolute(root)?;
    std::fs::create_dir(&root).context("Analysis output root must be fresh")?;
    let (run_id, started) = now()?;
    let canonical = Request::generated(case, fault, arch, run_id, started);
    let mut input = case.input(arch);
    let mut request = serde_json::to_value(&canonical)?;
    if name == "unknown-request-field" {
        request["host_path"] = json!("forbidden-field");
    }
    if name == "foreign-owned-fixture" {
        input[0] ^= 1;
        request["input_sha256"] = json!(report_bundle::digest(&input));
    }
    let mut raw = report_bundle::bounded_json(&request, analysis_fixture::MAX_REQUEST)?;
    let hash = report_bundle::digest(&raw);
    if name == "tamper-request" {
        raw.push(b' ');
    }
    if name == "tamper-input" {
        input[0] ^= 1;
    }
    save_new(&root.join("request.json"), &raw)?;
    save_new(&root.join("input.bin"), &input)?;
    let arguments = [
        OsString::from("--analysis-fixture"),
        root.as_os_str().to_owned(),
        OsString::from(&hash),
    ];
    let limits = OutputLimits {
        max_bytes: case.output_limit(),
        max_entries: 10064,
        max_directories: 8,
        max_depth: 4,
    };
    let stopped = launch_generated(
        &verified,
        &root,
        &arguments,
        limits,
        if fault == Fault::TimeoutAfterCheckpoint {
            5000
        } else {
            120000
        },
    )?;
    let witness = read_regular(&root.join("worker-containment.json"), 4096, Some(&root))?;
    let containment: Value = serde_json::from_slice(&witness)?;
    ensure!(
        containment["app_container"] == true
            && containment["job_object"] == true
            && containment["child_process_blocked"] == true
            && containment["network_capabilities"] == 0,
        "Analysis worker containment witness invalid"
    );
    let normal = stopped.reason == WorkerStop::Exited && stopped.exit_code == 0;
    let termination = if stopped.reason == WorkerStop::Timeout {
        Termination::Timeout
    } else if normal {
        Termination::Normal
    } else {
        Termination::WorkerFailure
    };
    let receipt = if normal {
        read_regular(&root.join("analysis-result.json"), 65536, Some(&root))
            .ok()
            .and_then(|raw| serde_json::from_slice::<Value>(&raw).ok())
    } else {
        None
    };
    let effective = if normal && receipt.is_none() {
        Termination::WorkerFailure
    } else {
        termination
    };
    let checked = (|| -> Result<Value> {
        ensure!(
            read_regular(
                &root.join("request.json"),
                analysis_fixture::MAX_REQUEST,
                Some(&root)
            )? == raw,
            "Staged request drifted during worker execution"
        );
        ensure!(
            read_regular(
                &root.join("input.bin"),
                analysis_fixture::MAX_INPUT,
                Some(&root)
            )? == input,
            "Staged input drifted during worker execution"
        );
        ensure!(tamper.is_none(), "Request tamper rejected before analysis");
        finalize(
            &root,
            &canonical,
            &hash,
            &witness,
            effective,
            effective != Termination::Normal,
            receipt.as_ref(),
        )
    })();
    let (mut summary, integrity_error) = match checked {
        Ok(summary) => (summary, None),
        Err(error) => {
            let detail = format!("{error:#}").chars().take(8192).collect::<String>();
            let unverified = read_regular(
                &root.join("worker-summary.json"),
                reports::MAX_SUMMARY_BYTES,
                Some(&root),
            )
            .ok()
            .and_then(|raw| serde_json::from_slice::<Value>(&raw).ok())
            .and_then(|v| v["artifacts"].as_array().map(Vec::len))
            .unwrap_or(0)
            .min(10000);
            (
                json!({"id":canonical.run_id,"sample":{"name":"owned-generated","sha256":canonical.input_sha256,"size":canonical.input_size},"status":"failed","completion_reason":"worker_failure",
                "errors":[detail],"artifacts":[],"artifact_groups":[],"artifact_integrity":"failed","unverified_artifact_count":unverified,"guest_trace_complete":false,"network_broker_complete":false,
                "run_manifest":{"analysis_role":"closed_generated_fixture","request_sha256":hash,"source_tree_sha256":verified.receipt["source_tree_sha256"]},"controller_integrity":"failed",
                "scope":"Failed closed generated report verification; unverified worker artifacts are preserved but not exposed as recovered output"}),
                Some(detail),
            )
        }
    };
    if let Some(expected) = tamper {
        ensure!(
            stopped.reason == WorkerStop::Exited && stopped.exit_code == 2,
            "Request tamper control did not reject before execution"
        );
        let error = read_regular(&root.join("worker-error.txt"), 32768, Some(&root))?;
        ensure!(
            String::from_utf8_lossy(&error).contains(expected),
            "Request tamper rejection reason differs"
        );
        ensure!(
            !root.join("worker-summary.json").exists() && !root.join("artifacts").exists(),
            "Request tamper fabricated analysis outputs"
        );
    }
    summary["worker_exit_code"] = json!(stopped.exit_code);
    summary["worker_stop"] = serde_json::to_value(stopped.reason)?;
    ensure!(
        reports::valid_summary(&summary),
        "Controller final summary invalid"
    );
    let summary_raw = report_bundle::bounded_json(&summary, reports::MAX_SUMMARY_BYTES)?;
    save_new(&root.join("summary.json"), &summary_raw)?;
    let manifest = json!({"schema":1,"role":"closed_generated_analysis_controller","qualified":integrity_error.is_none()&&effective==Termination::Normal,"request_sha256":hash,"staged_request_sha256":report_bundle::digest(&raw),
        "input_sha256":report_bundle::digest(&input),"summary_sha256":report_bundle::digest(&summary_raw),"case":name,"fault":fault,"architecture":arch,"status":summary["status"],"completion_reason":summary["completion_reason"],
        "source_tree_sha256":verified.receipt["source_tree_sha256"],"controller_sha256":verified.receipt["controller_sha256"],"worker_sha256":verified.receipt["worker_sha256"],"cleanup":"restored",
        "controller_recovery":verified.recovery,"output_limits":limits,"integrity_error":integrity_error,"scope":"Closed owned fixture report lifecycle; no arbitrary sample execution or driver unpacking claim"});
    save_new(
        &root.join("manifest.json"),
        &report_bundle::bounded_json(&manifest, 1024 * 1024)?,
    )?;
    Ok(manifest)
}
