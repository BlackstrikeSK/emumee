//! Aggregate existing read-only batch declaration and per-run summary bindings.
//! Digesting these declarations does not authenticate worker execution.
use anyhow::Result;
use serde_json::Value;
use std::path::Path;

#[cfg(windows)]
pub fn inspect(
    log_path: &Path,
    input_root: &Path,
    report_root: &Path,
    options: &crate::batch_inventory::Options,
) -> Result<Value> {
    use anyhow::ensure;
    use serde_json::json;
    use sha2::{Digest, Sha256};

    let sequence = crate::batch_sequence::inspect(log_path, input_root, options)?;
    let reports = crate::batch_report_map::inspect(log_path, report_root)?;
    ensure!(
        sequence["manifest"]["batch_log_sha256"] == reports["batch_log_sha256"],
        "Batch log changed between inventory and summary reads"
    );
    ensure!(
        sequence["declared_run_count"] == reports["declared_run_count"]
            && sequence["manifest"]["declared_status_counts"] == reports["declared_status_counts"],
        "Batch sequence and summary declarations disagree"
    );
    let count = sequence["declared_run_count"]
        .as_u64()
        .ok_or_else(|| anyhow::anyhow!("Batch run count missing"))?;
    let matched = reports["matched_summary_count"]
        .as_u64()
        .ok_or_else(|| anyhow::anyhow!("Matched summary count missing"))?;
    let rejected = reports["rejected_without_report_count"]
        .as_u64()
        .ok_or_else(|| anyhow::anyhow!("Rejected count missing"))?;
    ensure!(
        matched.checked_add(rejected) == Some(count),
        "Batch summary partition differs from declared run count"
    );
    ensure!(
        sequence["inventory_order_consistent"] == true
            && reports["summary_envelopes_consistent"] == true,
        "Batch inputs or report envelopes are not internally consistent"
    );
    let manifest = json!({
        "schema":1,
        "batch_log_sha256":reports["batch_log_sha256"],
        "sequence_declaration_sha256":sequence["manifest_sha256"],
        "declared_run_count":count,
        "declared_status_counts":reports["declared_status_counts"],
        "matched_summaries":reports["matched_summaries"],
        "rejected_without_report_count":rejected
    });
    let bytes = serde_json::to_vec(&manifest)?;
    Ok(json!({
        "version":1,
        "kind":"legacy_batch_aggregate_declaration",
        "manifest":manifest,
        "manifest_sha256":format!("{:x}",Sha256::digest(&bytes)),
        "sequence_and_summary_declarations_consistent":true,
        "declared_sequential":true,
        "actual_sequential_execution_verified":false,
        "input_bytes_verified":false,
        "worker_execution_verified":false,
        "engine_reports_verified":false,
        "artifacts_verified":false,
        "snapshot_atomicity_verified":false,
        "scope":"Current input metadata and saved summary envelopes bound to legacy batch declarations only"
    }))
}

#[cfg(not(windows))]
pub fn inspect(
    log_path: &Path,
    input_root: &Path,
    report_root: &Path,
    options: &crate::batch_inventory::Options,
) -> Result<Value> {
    let _ = (log_path, input_root, report_root, options);
    anyhow::bail!("Batch aggregate binding requires Windows regular-file checks")
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use serde_json::json;

    const ID: &str = "20261019T120000Z-deadbeef";

    struct Fixture(std::path::PathBuf);

    impl Fixture {
        fn new() -> Self {
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let root = std::env::temp_dir().join(format!(
                "emumee-batch-aggregate-{}-{stamp}",
                std::process::id()
            ));
            std::fs::create_dir(&root).unwrap();
            std::fs::create_dir(root.join("inputs")).unwrap();
            std::fs::create_dir(root.join("reports")).unwrap();
            std::fs::create_dir(root.join("reports").join(ID)).unwrap();
            std::fs::write(root.join("inputs/a.exe"), b"generated").unwrap();
            std::fs::write(root.join("inputs/b.msi"), b"fixture").unwrap();
            Self(root)
        }

        fn inputs(&self) -> std::path::PathBuf {
            self.0.join("inputs")
        }

        fn reports(&self) -> std::path::PathBuf {
            self.0.join("reports")
        }

        fn log(&self) -> std::path::PathBuf {
            self.0.join("batch.ndjson")
        }

        fn summary(&self) -> std::path::PathBuf {
            self.reports().join(ID).join("summary.json")
        }

        fn options(&self) -> crate::batch_inventory::Options {
            crate::batch_inventory::parse(
                [self.inputs().to_string_lossy().into_owned()].into_iter(),
            )
            .unwrap()
            .1
        }

        fn write(&self) {
            std::fs::write(
                self.summary(),
                serde_json::to_vec(&json!({
                    "id":ID,"sample":{"name":"a.exe"},"status":"partial"
                }))
                .unwrap(),
            )
            .unwrap();
            let records = [
                json!({"type":"run","sample":self.inputs().join("a.exe").to_str().unwrap(),
                       "exit_code":1,"status":"partial",
                       "result":{"run":ID,"report":self.summary().to_str().unwrap(),
                                 "status":"partial"},"error":null}),
                json!({"type":"run","sample":self.inputs().join("b.msi").to_str().unwrap(),
                       "exit_code":2,"status":"rejected","result":null,
                       "error":"generated rejection"}),
                json!({"type":"batch_summary","total":2,
                       "counts":{"partial":1,"rejected":1},"sequential":true}),
            ];
            std::fs::write(
                self.log(),
                records
                    .iter()
                    .map(Value::to_string)
                    .collect::<Vec<_>>()
                    .join("\n"),
            )
            .unwrap();
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(self.log());
            let _ = std::fs::remove_file(self.summary());
            let _ = std::fs::remove_file(self.inputs().join("a.exe"));
            let _ = std::fs::remove_file(self.inputs().join("b.msi"));
            let _ = std::fs::remove_dir(self.reports().join(ID));
            let _ = std::fs::remove_dir(self.reports());
            let _ = std::fs::remove_dir(self.inputs());
            let _ = std::fs::remove_dir(&self.0);
        }
    }

    #[test]
    fn generated_aggregate_binds_sequence_and_one_summary_without_execution_claim() {
        let fixture = Fixture::new();
        fixture.write();
        let first = inspect(
            &fixture.log(),
            &fixture.inputs(),
            &fixture.reports(),
            &fixture.options(),
        )
        .unwrap();
        assert_eq!(first["manifest"]["declared_run_count"], 2);
        assert_eq!(first["manifest"]["matched_summaries"][0]["id"], ID);
        assert_eq!(first["worker_execution_verified"], false);
        assert_eq!(first["artifacts_verified"], false);
        assert_eq!(first["snapshot_atomicity_verified"], false);
        std::fs::write(fixture.inputs().join("a.exe"), b"generated changed").unwrap();
        let changed = inspect(
            &fixture.log(),
            &fixture.inputs(),
            &fixture.reports(),
            &fixture.options(),
        )
        .unwrap();
        assert_ne!(first["manifest_sha256"], changed["manifest_sha256"]);
    }

    #[test]
    fn changed_summary_status_or_missing_input_refuses() {
        let fixture = Fixture::new();
        fixture.write();
        let mut summary: Value =
            serde_json::from_slice(&std::fs::read(fixture.summary()).unwrap()).unwrap();
        summary["status"] = json!("failed");
        std::fs::write(fixture.summary(), serde_json::to_vec(&summary).unwrap()).unwrap();
        assert!(
            inspect(
                &fixture.log(),
                &fixture.inputs(),
                &fixture.reports(),
                &fixture.options()
            )
            .is_err()
        );
        fixture.write();
        std::fs::remove_file(fixture.inputs().join("b.msi")).unwrap();
        assert!(
            inspect(
                &fixture.log(),
                &fixture.inputs(),
                &fixture.reports(),
                &fixture.options()
            )
            .is_err()
        );
    }
}
