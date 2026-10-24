//! Read-only legacy report inspection through the existing platform safe reader.
//! No worker or sample is launched and no report, artifact, or directory is written.

use anyhow::Result;
use serde_json::Value;
use std::path::Path;

#[cfg(windows)]
pub fn inspect(root: &Path, verify_artifacts: bool) -> Result<Value> {
    use anyhow::{Context, anyhow, ensure};
    use emumee_core::reports::{
        BoundReport, MAX_ARTIFACT_BYTES, MAX_ENGINE_BYTES, MAX_NETWORK_REPORT_BYTES,
        MAX_SUMMARY_BYTES, parse_summary, verified_artifact_manifest, verified_report,
    };
    use emumee_platform::windows::read_regular;
    use sha2::{Digest, Sha256};

    let root = std::path::absolute(root).context("Invalid report directory")?;
    let raw = read_regular(&root.join("summary.json"), MAX_SUMMARY_BYTES, Some(&root))
        .context("Summary could not be safely read")?;
    let summary = parse_summary(&raw).context("Summary envelope validation failed")?;
    let mut bindings = serde_json::Map::new();
    for (label, name, hash, filename, kind, maximum) in [
        (
            "engine",
            "engine_report",
            "engine_report_sha256",
            "engine-report.json",
            BoundReport::Engine,
            MAX_ENGINE_BYTES,
        ),
        (
            "network_broker",
            "network_broker_report",
            "network_broker_report_sha256",
            "network-broker.json",
            BoundReport::NetworkBroker,
            MAX_NETWORK_REPORT_BYTES,
        ),
    ] {
        let declared = summary.get(name).filter(|v| !v.is_null());
        let Some(declared) = declared else {
            // parse_summary already requires both filename and digest when the
            // completed/partial manifest demands a sha256-v1 binding.
            bindings.insert(
                label.to_owned(),
                serde_json::json!({"declared":false,"integrity":"not_declared"}),
            );
            continue;
        };
        ensure!(
            declared.as_str() == Some(filename),
            "Invalid fixed {label} report filename"
        );
        let bytes = read_regular(&root.join(filename), maximum, Some(&root))
            .with_context(|| format!("Declared {label} report could not be safely read"))?;
        ensure!(
            verified_report(&summary, kind, &bytes).is_some(),
            "Declared {label} report failed its hash or length binding"
        );
        if label == "engine" {
            let engine: Value = serde_json::from_slice(&bytes).context("Bound engine JSON")?;
            if emumee_core::memory_observation::requires_typed_binding(&summary, &engine) {
                ensure!(
                    summary.get(hash).is_some_and(|v| !v.is_null())
                        && emumee_core::memory_observation::verified_binding(&summary, &engine),
                    "Indicator summary/engine authority changed or unbound"
                );
            }
        }
        let bound = summary.get(hash).is_some_and(|v| !v.is_null());
        bindings.insert(
            label.to_owned(),
            serde_json::json!({
                "declared":true,
                "integrity":if bound {"verified_sha256_v1"} else {"legacy_unbound"},
                "bytes":bytes.len(),
                "sha256":format!("{:x}",Sha256::digest(&bytes))
            }),
        );
    }

    if emumee_core::memory_observation::requires_typed_binding(&summary, &Value::Null) {
        ensure!(
            bindings
                .get("engine")
                .is_some_and(|v| v["integrity"] == "verified_sha256_v1"),
            "Indicator authority needs a declared hash-bound engine"
        );
    }
    let no_artifacts = Value::Array(Vec::new());
    let artifacts = summary.get("artifacts").unwrap_or(&no_artifacts);
    let observations = artifacts
        .as_array()
        .context("Invalid artifact observation list")?
        .len();
    let artifact_result = if verify_artifacts {
        let manifest = read_regular(
            &root.join("artifacts/manifest.json"),
            MAX_SUMMARY_BYTES,
            Some(&root),
        )
        .context("Artifact manifest could not be safely read")?;
        let groups = summary.get("artifact_groups").filter(|v| !v.is_null());
        const MAX_TOTAL: u64 = 128 * 1024 * 1024;
        let mut inspected_bytes = 0_u64;
        let mut payload_reads = 0_u64;
        let mut load_failure = None;
        let verified = verified_artifact_manifest(&manifest, artifacts, groups, |item| {
            // The core helper calls this only after validating the content-
            // addressed filename, integer size, hash, and metadata field types.
            let requested = item.get("size")?.as_u64()?;
            if requested > MAX_TOTAL.saturating_sub(inspected_bytes) {
                load_failure = Some(anyhow!(
                    "Artifact verification exceeds its 128 MiB cumulative read budget"
                ));
                return None;
            }
            let filename = item.get("file")?.as_str()?;
            let path = root.join("artifacts").join(filename);
            match read_regular(
                &path,
                (requested as usize).min(MAX_ARTIFACT_BYTES),
                Some(&root),
            ) {
                Ok(bytes) => {
                    inspected_bytes += bytes.len() as u64;
                    payload_reads += 1;
                    Some(bytes)
                }
                Err(error) => {
                    load_failure = Some(error.context("Artifact payload could not be safely read"));
                    None
                }
            }
        });
        if !verified {
            return Err(load_failure.unwrap_or_else(|| anyhow!("Artifact manifest, payload hash/size, or reconstructed groups failed verification")));
        }
        serde_json::json!({
            "integrity":"verified", "observations":observations,
            "groups":if groups.is_some() {"reconstructed_and_verified"} else {"not_declared"},
            "payload_reads":payload_reads,"inspected_bytes":inspected_bytes,
            "cumulative_read_budget_bytes":MAX_TOTAL
        })
    } else {
        serde_json::json!({"integrity":"not_checked","observations":observations})
    };
    Ok(serde_json::json!({
        "version":1,
        "id":summary["id"],"status":summary["status"],
        "execution_mode":summary.get("execution_mode"),
        "completion_reason":summary.get("completion_reason"),
        "instruction_count":summary.get("instruction_count"),
        "summary":{"integrity":"envelope_validated","bytes":raw.len(),"sha256":format!("{:x}",Sha256::digest(&raw))},
        "reports":bindings,"artifacts":artifact_result,
        "reported_artifact_integrity":summary.get("artifact_integrity"),
        "scope":"Read-only legacy report inspection; no sample execution or unpacking claim"
    }))
}

#[cfg(not(windows))]
pub fn inspect(root: &Path, verify_artifacts: bool) -> Result<Value> {
    let _ = (root, verify_artifacts);
    anyhow::bail!("Verified report inspection requires the Windows regular-file reader")
}
