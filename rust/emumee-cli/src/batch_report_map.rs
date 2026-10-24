//! Read-only legacy batch to summary consistency; never proves execution.
use anyhow::Result;
use serde_json::Value;
use std::path::Path;

#[cfg(windows)]
pub fn inspect(log_path: &Path, report_root: &Path) -> Result<Value> {
    use anyhow::{Context, ensure};
    use emumee_core::reports::{MAX_SUMMARY_BYTES, parse_summary, valid_run_id};
    use emumee_platform::windows::read_regular;
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use std::collections::BTreeSet;
    use std::os::windows::fs::MetadataExt;

    const MAX_LOG_BYTES: usize = 8 * 1024 * 1024;
    const MAX_SUMMARY_READ: usize = 32 * 1024 * 1024;
    const REPARSE_POINT: u32 = 0x400;

    let root = std::path::absolute(report_root).context("Invalid batch report root")?;
    let metadata = std::fs::symlink_metadata(&root).context("Batch report root unavailable")?;
    ensure!(
        metadata.is_dir() && metadata.file_attributes() & REPARSE_POINT == 0,
        "Batch report root must be an ordinary directory"
    );
    let raw_log = read_regular(log_path, MAX_LOG_BYTES, None)
        .context("Batch log could not be safely read")?;
    let contract = crate::batch_log::parse(&raw_log)?;
    let mut seen_ids = BTreeSet::new();
    let mut matched = Vec::new();
    let mut rejected_without_report = 0usize;
    let mut summary_read = 0usize;
    for line in raw_log.split(|byte| *byte == b'\n') {
        if line.is_empty() {
            continue;
        }
        let record: Value = serde_json::from_slice(line).context("Bound batch record JSON")?;
        if record["type"] == "batch_summary" {
            break;
        }
        let Some(result) = record["result"].as_object() else {
            rejected_without_report += 1;
            continue;
        };
        let id = result
            .get("run")
            .and_then(Value::as_str)
            .context("Batch run has no report identity")?;
        ensure!(valid_run_id(id), "Invalid batch run identity");
        ensure!(
            seen_ids.insert(id.to_owned()),
            "Duplicate batch run identity"
        );
        let summary_path = root.join(id).join("summary.json");
        let declared_path = result
            .get("report")
            .and_then(Value::as_str)
            .context("Batch run has no report path")?;
        ensure!(
            Path::new(declared_path) == summary_path,
            "Batch run report path does not bind to supplied root"
        );
        let directory = std::fs::symlink_metadata(root.join(id))
            .context("Declared batch run directory unavailable")?;
        ensure!(
            directory.is_dir() && directory.file_attributes() & REPARSE_POINT == 0,
            "Declared batch run directory is not ordinary"
        );
        let summary_raw = read_regular(&summary_path, MAX_SUMMARY_BYTES, Some(&root))
            .context("Declared batch summary could not be safely read")?;
        summary_read = summary_read
            .checked_add(summary_raw.len())
            .context("Batch summary aggregate read overflow")?;
        ensure!(
            summary_read <= MAX_SUMMARY_READ,
            "Batch summary aggregate read limit exceeded"
        );
        let summary = parse_summary(&summary_raw).context("Invalid batch summary envelope")?;
        ensure!(summary["id"] == id, "Batch summary identity mismatch");
        ensure!(
            summary["status"] == record["status"],
            "Batch summary status mismatch"
        );
        let sample = record["sample"]
            .as_str()
            .context("Bound batch sample path missing")?;
        let name = Path::new(sample)
            .file_name()
            .and_then(|name| name.to_str())
            .context("Batch sample filename missing")?;
        ensure!(
            summary["sample"]["name"] == name,
            "Batch summary sample name mismatch"
        );
        matched.push(json!({
            "id": id,
            "declared_status": record["status"],
            "summary_sha256": format!("{:x}", Sha256::digest(&summary_raw))
        }));
    }
    Ok(json!({
        "version": 1,
        "kind": "legacy_batch_summary_binding",
        "batch_log_sha256": format!("{:x}", Sha256::digest(&raw_log)),
        "declared_run_count": contract["declared_run_count"],
        "declared_status_counts": contract["declared_status_counts"],
        "matched_summary_count": matched.len(),
        "rejected_without_report_count": rejected_without_report,
        "matched_summaries": matched,
        "summary_bytes_read": summary_read,
        "summary_read_budget_bytes": MAX_SUMMARY_READ,
        "summary_envelopes_consistent": true,
        "sample_bytes_verified": false,
        "worker_execution_verified": false,
        "engine_reports_verified": false,
        "artifacts_verified": false,
        "scope": "Declared batch-to-summary identity, path, status, and sample-name consistency only"
    }))
}

#[cfg(not(windows))]
pub fn inspect(log_path: &Path, report_root: &Path) -> Result<Value> {
    let _ = (log_path, report_root);
    anyhow::bail!("Batch report binding requires Windows regular-file checks")
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use serde_json::json;

    const ID: &str = "20261019T120000Z-deadbeef";
    const OTHER: &str = "20261019T130000Z-feedface";

    struct Fixture(std::path::PathBuf);

    impl Fixture {
        fn new() -> Self {
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir()
                .join(format!("emumee-batch-map-{}-{stamp}", std::process::id()));
            std::fs::create_dir(&path).unwrap();
            std::fs::create_dir(path.join("reports")).unwrap();
            std::fs::create_dir(path.join("reports").join(ID)).unwrap();
            Self(path)
        }

        fn log(&self) -> std::path::PathBuf {
            self.0.join("batch.ndjson")
        }

        fn reports(&self) -> std::path::PathBuf {
            self.0.join("reports")
        }

        fn summary(&self) -> std::path::PathBuf {
            self.reports().join(ID).join("summary.json")
        }

        fn write(&self, summary_id: &str, summary_status: &str, summary_name: &str) {
            std::fs::write(self.summary(), serde_json::to_vec(
                &json!({"id":summary_id,"sample":{"name":summary_name},"status":summary_status})
            ).unwrap()).unwrap();
            let records = [
                json!({"type":"run","sample":"alpha.exe","exit_code":0,
                       "status":"completed","result":{"run":ID,"status":"completed",
                       "report":self.summary().to_str().unwrap()},"error":null}),
                json!({"type":"run","sample":"bad.sys","exit_code":2,
                       "status":"rejected","result":null,"error":"refused"}),
                json!({"type":"batch_summary","total":2,
                       "counts":{"completed":1,"rejected":1},"sequential":true}),
            ];
            let raw = records
                .iter()
                .map(Value::to_string)
                .collect::<Vec<_>>()
                .join("\n");
            std::fs::write(self.log(), raw).unwrap();
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(self.log());
            let _ = std::fs::remove_file(self.summary());
            let _ = std::fs::remove_dir(self.reports().join(ID));
            let _ = std::fs::remove_dir(self.reports());
            let _ = std::fs::remove_dir(&self.0);
        }
    }

    #[test]
    fn generated_batch_binds_one_summary_and_one_rejection() {
        let fixture = Fixture::new();
        fixture.write(ID, "completed", "alpha.exe");
        let result = inspect(&fixture.log(), &fixture.reports()).unwrap();
        assert_eq!(result["matched_summary_count"], 1);
        assert_eq!(result["rejected_without_report_count"], 1);
        assert_eq!(result["matched_summaries"][0]["id"], ID);
        assert_eq!(result["worker_execution_verified"], false);
        assert_eq!(result["artifacts_verified"], false);
    }

    #[test]
    fn wrong_summary_identity_status_or_sample_name_refuses() {
        let fixture = Fixture::new();
        for (id, status, name) in [
            (OTHER, "completed", "alpha.exe"),
            (ID, "failed", "alpha.exe"),
            (ID, "completed", "other.exe"),
        ] {
            fixture.write(id, status, name);
            assert!(inspect(&fixture.log(), &fixture.reports()).is_err());
        }
    }

    #[test]
    fn linked_summary_and_wrong_declared_path_refuse() {
        let fixture = Fixture::new();
        fixture.write(ID, "completed", "alpha.exe");
        let original = fixture.0.join("original.json");
        std::fs::rename(fixture.summary(), &original).unwrap();
        std::fs::hard_link(&original, fixture.summary()).unwrap();
        assert!(inspect(&fixture.log(), &fixture.reports()).is_err());
        std::fs::remove_file(fixture.summary()).unwrap();
        std::fs::remove_file(original).unwrap();
        fixture.write(ID, "completed", "alpha.exe");
        let raw = std::fs::read_to_string(fixture.log()).unwrap();
        std::fs::write(fixture.log(), raw.replace("summary.json", "foreign.json")).unwrap();
        assert!(inspect(&fixture.log(), &fixture.reports()).is_err());
    }
}
