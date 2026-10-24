//! Read-only structural inspection of the legacy batch NDJSON stream.
//! Declared statuses never certify execution, reports, or artifacts.
#[cfg(not(windows))]
use anyhow::bail;
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::Path;

const MAX_LOG_BYTES: usize = 8 * 1024 * 1024;
const MAX_RUNS: usize = 1000;

pub fn parse(raw: &[u8]) -> Result<Value> {
    ensure!(
        !raw.is_empty() && raw.len() <= MAX_LOG_BYTES,
        "Batch log byte bound"
    );
    let mut lines = Vec::with_capacity(MAX_RUNS + 2);
    for line in raw.split(|byte| *byte == b'\n') {
        ensure!(lines.len() < MAX_RUNS + 2, "Batch log record count bound");
        lines.push(line);
    }
    if lines.last().is_some_and(|line| line.is_empty()) {
        lines.pop();
    }
    ensure!(
        (2..=MAX_RUNS + 1).contains(&lines.len()),
        "Batch log record count bound"
    );

    let mut counts = BTreeMap::<String, u64>::new();
    for line in &lines[..lines.len() - 1] {
        let value: Value = serde_json::from_slice(line).context("Invalid batch run JSON")?;
        ensure!(value["type"] == "run", "Expected batch run record");
        let sample = value["sample"]
            .as_str()
            .context("Batch run sample must be text")?;
        ensure!(
            !sample.is_empty() && sample.len() <= 32767,
            "Batch run sample length bound"
        );
        let exit = value["exit_code"]
            .as_i64()
            .context("Batch run exit code must be integer")?;
        ensure!((0..=255).contains(&exit), "Batch run exit code bound");
        let status = value["status"]
            .as_str()
            .context("Batch run status must be text")?;
        ensure!(
            !status.is_empty() && status.len() <= 128 && !status.chars().any(char::is_control),
            "Batch run status length/content bound"
        );
        ensure!(
            value["error"].is_null() || value["error"].as_str().is_some(),
            "Batch run error must be text or null"
        );
        let expected_status = if let Some(result) = value["result"].as_object() {
            result
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("failed")
        } else {
            "rejected"
        };
        ensure!(
            status == expected_status,
            "Batch run/result status mismatch"
        );
        *counts.entry(status.to_owned()).or_default() += 1;
    }

    let final_record: Value =
        serde_json::from_slice(lines[lines.len() - 1]).context("Invalid batch summary JSON")?;
    ensure!(
        final_record["type"] == "batch_summary",
        "Expected final batch summary"
    );
    ensure!(
        final_record["sequential"] == true,
        "Batch summary must declare sequential execution"
    );
    let declared_total = final_record["total"]
        .as_u64()
        .context("Batch summary total must be unsigned integer")?;
    ensure!(
        declared_total == (lines.len() - 1) as u64,
        "Batch summary run count mismatch"
    );
    let declared_counts = final_record["counts"]
        .as_object()
        .context("Batch summary counts must be an object")?;
    ensure!(
        declared_counts.len() == counts.len(),
        "Batch summary status set mismatch"
    );
    for (status, count) in &counts {
        ensure!(
            declared_counts.get(status).and_then(Value::as_u64) == Some(*count),
            "Batch summary status count mismatch"
        );
    }

    use sha2::{Digest, Sha256};
    Ok(json!({
        "version": 1,
        "kind": "legacy_batch_log_inspection",
        "log_sha256": format!("{:x}", Sha256::digest(raw)),
        "declared_run_count": declared_total,
        "declared_status_counts": counts,
        "legacy_summary_consistent": true,
        "sample_bytes_verified": false,
        "execution_verified": false,
        "reports_verified": false,
        "artifacts_verified": false,
        "scope": "Legacy batch NDJSON structure only; declarations do not prove sample execution or unpacking"
    }))
}

#[cfg(windows)]
pub fn inspect(path: &Path) -> Result<Value> {
    let raw = emumee_platform::windows::read_regular(path, MAX_LOG_BYTES, None)?;
    parse(&raw)
}

#[cfg(not(windows))]
pub fn inspect(path: &Path) -> Result<Value> {
    let _ = path;
    bail!("Batch log inspection requires the Windows regular-file reader")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generated_log() -> Vec<u8> {
        let records = [
            json!({"type":"run","sample":"A.exe","exit_code":0,"status":"completed",
                   "result":{"status":"completed"},"error":null}),
            json!({"type":"run","sample":"B.sys","exit_code":1,"status":"failed",
                   "result":{"status":"failed"},"error":null}),
            json!({"type":"batch_summary","total":2,
                   "counts":{"completed":1,"failed":1},"sequential":true}),
        ];
        records
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join("\n")
            .into_bytes()
    }

    #[test]
    fn generated_legacy_counts_are_structural_only() {
        let report = parse(&generated_log()).unwrap();
        assert_eq!(report["declared_run_count"], 2);
        assert_eq!(report["declared_status_counts"]["completed"], 1);
        assert_eq!(report["declared_status_counts"]["failed"], 1);
        assert_eq!(report["legacy_summary_consistent"], true);
        assert_eq!(report["execution_verified"], false);
        assert_eq!(report["artifacts_verified"], false);
    }

    #[test]
    fn mismatched_counts_or_result_status_are_rejected() {
        let raw = String::from_utf8(generated_log()).unwrap();
        assert!(parse(raw.replace("\"total\":2", "\"total\":3").as_bytes()).is_err());
        assert!(
            parse(
                raw.replacen("\"status\":\"completed\"", "\"status\":\"partial\"", 1)
                    .as_bytes()
            )
            .is_err()
        );
        assert!(parse(format!("{raw}\n{{}}\n").as_bytes()).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn linked_log_is_refused_by_regular_file_gate() {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("emumee-batch-log-{}-{stamp}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        let original = root.join("original.ndjson");
        let linked = root.join("linked.ndjson");
        std::fs::write(&original, generated_log()).unwrap();
        std::fs::hard_link(&original, &linked).unwrap();
        assert!(inspect(&linked).is_err());
        std::fs::remove_file(&linked).unwrap();
        std::fs::remove_file(&original).unwrap();
        std::fs::remove_dir(&root).unwrap();
    }
}
