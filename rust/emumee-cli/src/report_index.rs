//! Bounded, read-only index of legacy report summary envelopes.
//! Declared statuses are not execution or artifact-integrity verdicts.
use anyhow::Result;
use serde_json::Value;
use std::path::Path;

#[cfg(windows)]
pub fn inspect(root: &Path) -> Result<Value> {
    use anyhow::{Context, ensure};
    use emumee_core::reports::{MAX_SUMMARY_BYTES, parse_summary, valid_run_id};
    use emumee_platform::windows::read_regular;
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;
    use std::os::windows::fs::MetadataExt;

    const REPARSE_POINT: u32 = 0x400;
    const MAX_ENTRIES: usize = 4096;
    const MAX_RUNS: usize = 1000;
    const MAX_TOTAL_READ: usize = 32 * 1024 * 1024;

    let root = std::path::absolute(root).context("Invalid report index root")?;
    let metadata = std::fs::symlink_metadata(&root).context("Report index root unavailable")?;
    ensure!(
        metadata.is_dir() && metadata.file_attributes() & REPARSE_POINT == 0,
        "Report index root must be an ordinary directory"
    );

    let mut scanned_entries = 0usize;
    let mut candidates = Vec::new();
    for entry in std::fs::read_dir(&root).context("Cannot enumerate report index root")? {
        scanned_entries += 1;
        ensure!(
            scanned_entries <= MAX_ENTRIES,
            "Report index entry limit exceeded"
        );
        let entry = entry?;
        let name = entry.file_name();
        let Some(id) = name.to_str() else { continue };
        if !valid_run_id(id) {
            continue;
        }
        let kind = std::fs::symlink_metadata(entry.path())?;
        if !kind.is_dir() || kind.file_attributes() & REPARSE_POINT != 0 {
            continue;
        }
        candidates.push((id.to_owned(), entry.path()));
        ensure!(
            candidates.len() <= MAX_RUNS,
            "Report index run limit exceeded"
        );
    }
    candidates.sort_unstable_by(|left, right| right.0.cmp(&left.0));

    let mut read_bytes = 0usize;
    let mut rejected_run_directories = 0usize;
    let mut declared_status_counts = BTreeMap::<String, usize>::new();
    let mut runs = Vec::with_capacity(candidates.len());
    for (id, directory) in candidates {
        let raw = match read_regular(
            &directory.join("summary.json"),
            MAX_SUMMARY_BYTES,
            Some(&root),
        ) {
            Ok(raw) => raw,
            Err(_) => {
                rejected_run_directories += 1;
                continue;
            }
        };
        read_bytes = read_bytes
            .checked_add(raw.len())
            .context("Report index byte count overflow")?;
        ensure!(
            read_bytes <= MAX_TOTAL_READ,
            "Report index cumulative read limit exceeded"
        );
        let Ok(summary) = parse_summary(&raw) else {
            rejected_run_directories += 1;
            continue;
        };
        if summary["id"].as_str() != Some(id.as_str()) {
            rejected_run_directories += 1;
            continue;
        }
        let status = summary["status"]
            .as_str()
            .context("Validated status absent")?;
        *declared_status_counts.entry(status.to_owned()).or_default() += 1;
        runs.push(json!({
            "id": id,
            "declared_status": status,
            "summary_bytes": raw.len(),
            "summary_sha256": format!("{:x}", Sha256::digest(&raw))
        }));
    }
    let accepted_run_directories = runs.len();
    Ok(json!({
        "version": 1,
        "kind": "report_summary_index",
        "runs": runs,
        "accepted_run_directories": accepted_run_directories,
        "rejected_run_directories": rejected_run_directories,
        "scanned_entries": scanned_entries,
        "summary_bytes_read": read_bytes,
        "summary_read_budget_bytes": MAX_TOTAL_READ,
        "declared_status_counts": declared_status_counts,
        "engine_reports_verified": false,
        "artifacts_verified": false,
        "scope": "Read-only summary-envelope index; reported statuses are not guest execution or unpacking evidence"
    }))
}

#[cfg(not(windows))]
pub fn inspect(root: &Path) -> Result<Value> {
    let _ = root;
    anyhow::bail!("Report index requires the Windows regular-file reader")
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use serde_json::json;

    struct FixtureRoot(std::path::PathBuf);

    impl FixtureRoot {
        fn new() -> Self {
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let root = std::env::temp_dir().join(format!(
                "emumee-report-index-{}-{stamp}",
                std::process::id()
            ));
            std::fs::create_dir(&root).unwrap();
            Self(root)
        }

        fn summary(&self, directory: &str, declared_id: &str, status: &str) {
            let dir = self.0.join(directory);
            std::fs::create_dir(&dir).unwrap();
            let raw =
                serde_json::to_vec(&json!({"id":declared_id,"sample":{},"status":status})).unwrap();
            std::fs::write(dir.join("summary.json"), raw).unwrap();
        }
    }

    impl Drop for FixtureRoot {
        fn drop(&mut self) {
            if let Ok(children) = std::fs::read_dir(&self.0) {
                for child in children.flatten() {
                    if child.file_type().is_ok_and(|kind| kind.is_dir()) {
                        if let Ok(files) = std::fs::read_dir(child.path()) {
                            for file in files.flatten() {
                                let _ = std::fs::remove_file(file.path());
                            }
                        }
                        let _ = std::fs::remove_dir(child.path());
                    } else {
                        let _ = std::fs::remove_file(child.path());
                    }
                }
            }
            let _ = std::fs::remove_dir(&self.0);
        }
    }

    #[test]
    fn generated_index_counts_only_bound_summary_envelopes() {
        let root = FixtureRoot::new();
        root.summary(
            "20261018T120000Z-deadbeef",
            "20261018T120000Z-deadbeef",
            "partial",
        );
        root.summary(
            "20261018T130000Z-feedface",
            "20261018T130000Z-feedface",
            "failed",
        );
        root.summary(
            "20261018T140000Z-1234abcd",
            "20261018T120000Z-deadbeef",
            "partial",
        );
        let result = inspect(&root.0).unwrap();
        assert_eq!(result["accepted_run_directories"], 2);
        assert_eq!(result["rejected_run_directories"], 1);
        assert_eq!(result["declared_status_counts"]["partial"], 1);
        assert_eq!(result["declared_status_counts"]["failed"], 1);
        assert_eq!(result["runs"][0]["id"], "20261018T130000Z-feedface");
        assert_eq!(result["engine_reports_verified"], false);
        assert_eq!(result["artifacts_verified"], false);
    }

    #[test]
    fn linked_summary_is_rejected_without_leaking_payloads() {
        let root = FixtureRoot::new();
        let id = "20261018T120000Z-deadbeef";
        let source = root.0.join("outside.json");
        std::fs::write(
            &source,
            serde_json::to_vec(&json!({"id":id,"sample":{},"status":"completed"})).unwrap(),
        )
        .unwrap();
        let run = root.0.join(id);
        std::fs::create_dir(&run).unwrap();
        std::fs::hard_link(&source, run.join("summary.json")).unwrap();
        let result = inspect(&root.0).unwrap();
        assert_eq!(result["accepted_run_directories"], 0);
        assert_eq!(result["rejected_run_directories"], 1);
        assert_eq!(result["declared_status_counts"], json!({}));
    }
}
