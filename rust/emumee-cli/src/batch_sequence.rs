//! Bind a saved legacy batch declaration to an ordinary-file input inventory.
//! The NDJSON "sequential" field is a declaration, not an execution witness.
use anyhow::Result;
use serde_json::Value;
use std::path::Path;

#[cfg(windows)]
pub fn inspect(
    log_path: &Path,
    input_root: &Path,
    options: &crate::batch_inventory::Options,
) -> Result<Value> {
    use anyhow::{Context, ensure};
    use emumee_platform::windows::read_regular;
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use std::collections::BTreeSet;

    const MAX_LOG_BYTES: usize = 8 * 1024 * 1024;
    let root = std::path::absolute(input_root).context("Invalid batch input root")?;
    let inventory = crate::batch_inventory::inspect(&root, options)?;
    let samples = inventory["samples"]
        .as_array()
        .context("Batch inventory samples missing")?;
    let log = read_regular(log_path, MAX_LOG_BYTES, None)
        .context("Legacy batch log could not be safely read")?;
    let contract = crate::batch_log::parse(&log)?;
    ensure!(
        contract["declared_run_count"].as_u64() == Some(samples.len() as u64),
        "Batch log run count differs from the current input inventory"
    );
    let mut seen_keys = BTreeSet::new();
    let mut sequence = Vec::with_capacity(samples.len());
    for (index, line) in log
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .take(samples.len())
        .enumerate()
    {
        let record: Value = serde_json::from_slice(line).context("Invalid batch run JSON")?;
        let sample = &samples[index];
        let relative = sample["relative_path"]
            .as_str()
            .context("Batch inventory relative path missing")?;
        ensure!(
            relative.is_ascii(),
            "Non-ASCII batch relative order needs a separate Python casefold binding"
        );
        ensure!(
            seen_keys.insert(relative.to_ascii_lowercase()),
            "Casefold-tied batch order is ambiguous without directory enumeration evidence"
        );
        let expected = root.join(relative.replace('/', "\\"));
        ensure!(
            record["sample"]
                .as_str()
                .is_some_and(|actual| Path::new(actual) == expected),
            "Batch record path or sequence differs from the current input inventory"
        );
        sequence.push(json!({
            "index": index,
            "relative_path": relative,
            "observed_size_bytes": sample["observed_size_bytes"],
            "declared_status": record["status"],
            "declared_exit_code": record["exit_code"]
        }));
    }
    ensure!(
        sequence.len() == samples.len(),
        "Batch run sequence is shorter than the input inventory"
    );
    let manifest = json!({
        "version":1,
        "input_root":root.to_str().context("Batch input root is not Unicode")?,
        "batch_log_sha256":format!("{:x}",Sha256::digest(&log)),
        "declared_status_counts":contract["declared_status_counts"],
        "ordered_declarations":sequence
    });
    let encoded = serde_json::to_vec(&manifest)?;
    Ok(json!({
        "version":1,
        "kind":"legacy_batch_sequence_declaration",
        "manifest":manifest,
        "manifest_sha256":format!("{:x}",Sha256::digest(&encoded)),
        "declared_run_count":samples.len(),
        "declared_sequential":true,
        "inventory_order_consistent":true,
        "input_bytes_verified":false,
        "actual_sequential_execution_verified":false,
        "worker_execution_verified":false,
        "reports_verified":false,
        "artifacts_verified":false,
        "scope":"Current ordinary-file metadata inventory bound to ordered legacy NDJSON declarations only"
    }))
}

#[cfg(not(windows))]
pub fn inspect(
    log_path: &Path,
    input_root: &Path,
    options: &crate::batch_inventory::Options,
) -> Result<Value> {
    let _ = (log_path, input_root, options);
    anyhow::bail!("Batch sequence binding requires Windows regular-file checks")
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use serde_json::json;

    struct Fixture(std::path::PathBuf);

    impl Fixture {
        fn new() -> Self {
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let root = std::env::temp_dir().join(format!(
                "emumee-batch-sequence-{}-{stamp}",
                std::process::id()
            ));
            std::fs::create_dir(&root).unwrap();
            std::fs::create_dir(root.join("inputs")).unwrap();
            std::fs::write(root.join("inputs/a.exe"), b"generated").unwrap();
            std::fs::write(root.join("inputs/b.msi"), b"fixture").unwrap();
            Self(root)
        }

        fn inputs(&self) -> std::path::PathBuf {
            self.0.join("inputs")
        }

        fn log(&self) -> std::path::PathBuf {
            self.0.join("batch.ndjson")
        }

        fn options(&self) -> crate::batch_inventory::Options {
            crate::batch_inventory::parse(
                [self.inputs().to_string_lossy().into_owned()].into_iter(),
            )
            .unwrap()
            .1
        }

        fn write(&self, reversed: bool) {
            let mut runs = vec![
                json!({"type":"run","sample":self.inputs().join("a.exe").to_str().unwrap(),
                       "exit_code":1,"status":"partial",
                       "result":{"status":"partial"},"error":null}),
                json!({"type":"run","sample":self.inputs().join("b.msi").to_str().unwrap(),
                       "exit_code":2,"status":"rejected",
                       "result":null,"error":"generated rejection"}),
            ];
            if reversed {
                runs.reverse();
            }
            runs.push(json!({"type":"batch_summary","total":2,
                             "counts":{"partial":1,"rejected":1},"sequential":true}));
            let raw = runs
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
            let _ = std::fs::remove_file(self.inputs().join("a.exe"));
            let _ = std::fs::remove_file(self.inputs().join("b.msi"));
            let _ = std::fs::remove_dir(self.inputs());
            let _ = std::fs::remove_dir(&self.0);
        }
    }

    #[test]
    fn generated_order_and_counts_bind_to_current_metadata_only() {
        let fixture = Fixture::new();
        fixture.write(false);
        let first = inspect(&fixture.log(), &fixture.inputs(), &fixture.options()).unwrap();
        assert_eq!(first["declared_run_count"], 2);
        assert_eq!(
            first["manifest"]["ordered_declarations"][0]["relative_path"],
            "a.exe"
        );
        assert_eq!(first["actual_sequential_execution_verified"], false);
        assert_eq!(first["input_bytes_verified"], false);
        assert_eq!(first["reports_verified"], false);
        std::fs::write(fixture.inputs().join("a.exe"), b"generated changed").unwrap();
        let changed = inspect(&fixture.log(), &fixture.inputs(), &fixture.options()).unwrap();
        assert_ne!(first["manifest_sha256"], changed["manifest_sha256"]);
    }

    #[test]
    fn reordered_declarations_or_changed_inventory_refuse() {
        let fixture = Fixture::new();
        fixture.write(true);
        assert!(inspect(&fixture.log(), &fixture.inputs(), &fixture.options()).is_err());
        fixture.write(false);
        std::fs::remove_file(fixture.inputs().join("b.msi")).unwrap();
        assert!(inspect(&fixture.log(), &fixture.inputs(), &fixture.options()).is_err());
    }

    #[test]
    fn linked_log_refuses_before_manifest() {
        let fixture = Fixture::new();
        fixture.write(false);
        let original = fixture.0.join("original.ndjson");
        std::fs::rename(fixture.log(), &original).unwrap();
        std::fs::hard_link(&original, fixture.log()).unwrap();
        assert!(inspect(&fixture.log(), &fixture.inputs(), &fixture.options()).is_err());
        std::fs::remove_file(fixture.log()).unwrap();
        std::fs::rename(original, fixture.log()).unwrap();
    }
}
