//! Read-only binding of a saved legacy static-MSI report to its summary and,
//! optionally, to the original compound file. No installer actions are run.
use anyhow::Result;
use serde_json::Value;
use std::path::Path;

#[cfg(windows)]
pub fn inspect(run: &Path, source: Option<&Path>) -> Result<Value> {
    use anyhow::{Context, ensure};
    use emumee_core::reports::{
        BoundReport, MAX_ENGINE_BYTES, MAX_SUMMARY_BYTES, parse_summary, verified_report,
    };
    use emumee_platform::windows::read_regular;
    use sha2::{Digest, Sha256};

    let run = std::path::absolute(run).context("Invalid MSI report directory")?;
    let raw = read_regular(&run.join("summary.json"), MAX_SUMMARY_BYTES, Some(&run))
        .context("MSI summary could not be safely read")?;
    let summary = parse_summary(&raw).context("Invalid MSI summary envelope")?;
    ensure!(
        run.file_name().and_then(|s| s.to_str()) == summary["id"].as_str(),
        "MSI run directory and summary identity differ"
    );
    ensure!(
        summary["sample"]["kind"] == "msi"
            && summary["sample"]["architecture"] == "container"
            && summary["sample"]["managed"] == false,
        "Summary does not declare a static MSI sample"
    );
    ensure!(
        summary["status"] == "partial"
            && summary["completion_reason"] == "static_inspection"
            && summary["instruction_count"] == 0
            && summary["guest_trace_complete"] == false,
        "MSI summary invents guest execution or is not a completed static inspection"
    );
    ensure!(
        summary["engine_report"] == "engine-report.json"
            && summary["engine_report_sha256"].is_string()
            && summary["engine_report_size"].is_number(),
        "MSI engine report needs an explicit hash and length"
    );
    let engine_raw = read_regular(
        &run.join("engine-report.json"),
        MAX_ENGINE_BYTES,
        Some(&run),
    )
    .context("MSI engine report could not be safely read")?;
    ensure!(
        verified_report(&summary, BoundReport::Engine, &engine_raw).is_some(),
        "MSI engine report hash or length differs from summary"
    );
    let engine: Value =
        serde_json::from_slice(&engine_raw).context("Invalid bound MSI engine JSON")?;
    ensure!(
        engine["format"] == "msi" && engine["inspection"] == "static_streams",
        "Engine report does not describe static MSI streams"
    );
    let streams = engine["streams"]
        .as_array()
        .context("MSI engine streams missing")?;
    ensure!(
        streams.len() <= 2048,
        "MSI engine stream count exceeds limit"
    );
    ensure!(
        engine["stream_count"].as_u64() == Some(streams.len() as u64),
        "MSI stream count differs from the list"
    );
    let mut stream_bytes = 0_u64;
    let mut declared = Vec::with_capacity(streams.len());
    for stream in streams {
        let name = stream["name"].as_str().context("MSI stream name missing")?;
        ensure!(name.chars().count() <= 256, "MSI stream name exceeds limit");
        let size = stream["size"].as_u64().context("MSI stream size missing")?;
        let kind = stream["type"].as_str().context("MSI stream type missing")?;
        ensure!(
            matches!(kind, "cabinet" | "pe" | "data"),
            "Invalid MSI stream type"
        );
        stream_bytes = stream_bytes
            .checked_add(size)
            .context("MSI stream byte sum overflow")?;
        declared.push((name.to_owned(), size, kind.to_owned()));
    }
    ensure!(
        stream_bytes <= 64 * 1024 * 1024
            && engine["stream_bytes_read"].as_u64() == Some(stream_bytes),
        "MSI stream bytes differ from the list or exceed the legacy budget"
    );
    ensure!(
        engine["artifact_capture"].is_object()
            && summary["artifact_capture"].is_object()
            && engine["artifact_capture"] == summary["artifact_capture"],
        "MSI artifact capture summary differs from bound engine"
    );
    let limits = engine["limitations"]
        .as_array()
        .context("MSI inspection limitations missing")?;
    ensure!(
        limits
            .iter()
            .any(|v| v == "Windows Installer tables and custom actions were not executed")
            && limits
                .iter()
                .any(|v| v == "Embedded CAB files were retained but not unpacked"),
        "MSI static inspection limitations missing"
    );

    let source_sha = summary["sample"]["sha256"]
        .as_str()
        .context("MSI sample digest missing")?;
    ensure!(
        source_sha.len() == 64
            && source_sha
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "MSI sample digest is not lowercase SHA-256"
    );
    let mut source_streams_checked = false;
    if let Some(source) = source {
        let bytes = read_regular(source, emumee_core::msi::MAX_INPUT_BYTES, None)
            .context("MSI source could not be safely read")?;
        ensure!(
            format!("{:x}", Sha256::digest(&bytes)) == source_sha,
            "MSI source bytes differ from the saved sample digest"
        );
        let source_inspection = emumee_core::msi::inspect(&bytes)
            .context("MSI source failed bounded static compound inspection")?;
        let mut observed: Vec<_> = source_inspection
            .streams
            .iter()
            .map(|s| {
                (
                    s.name.clone(),
                    s.size,
                    format!("{:?}", s.kind).to_lowercase(),
                )
            })
            .collect();
        declared.sort();
        observed.sort();
        ensure!(
            declared == observed,
            "Saved MSI stream list differs from the supplied source"
        );
        source_streams_checked = true;
    }
    Ok(serde_json::json!({
        "version":1,"kind":"legacy_msi_report_binding",
        "run_id":summary["id"],"declared_status":summary["status"],
        "summary_sha256":format!("{:x}",Sha256::digest(&raw)),
        "engine_report_sha256":format!("{:x}",Sha256::digest(&engine_raw)),
        "source_sha256":source_sha,
        "source_streams_checked":source_streams_checked,
        "declared_stream_count":streams.len(),
        "declared_stream_bytes":stream_bytes,
        "report_internal_bindings_consistent":true,
        "artifact_payloads_verified":false,
        "installer_execution_verified":false,
        "scope":"Saved static MSI report consistency only; generated or forged reports can pass"
    }))
}

#[cfg(not(windows))]
pub fn inspect(run: &Path, source: Option<&Path>) -> Result<Value> {
    let _ = (run, source);
    anyhow::bail!("Verified MSI report inspection requires the Windows regular-file reader")
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use emumee_core::msi_fixture::{Case, input};
    use serde_json::json;
    use sha2::{Digest, Sha256};

    const ID: &str = "20261019T120000Z-deadbeef";

    struct Fixture(std::path::PathBuf);

    impl Fixture {
        fn new() -> Self {
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir()
                .join(format!("emumee-msi-report-{}-{stamp}", std::process::id()));
            std::fs::create_dir(&path).unwrap();
            std::fs::create_dir(path.join(ID)).unwrap();
            Self(path)
        }

        fn run(&self) -> std::path::PathBuf {
            self.0.join(ID)
        }

        fn source(&self) -> std::path::PathBuf {
            self.0.join("generated.msi")
        }

        fn summary(&self) -> std::path::PathBuf {
            self.run().join("summary.json")
        }

        fn engine(&self) -> std::path::PathBuf {
            self.run().join("engine-report.json")
        }

        fn write(&self) {
            let source = input(Case::RegularV3);
            std::fs::write(self.source(), &source).unwrap();
            let inspected = emumee_core::msi::inspect(&source).unwrap();
            let streams: Vec<_> = inspected
                .streams
                .iter()
                .map(|s| {
                    json!({"name":s.name,"size":s.size,
                           "type":format!("{:?}",s.kind).to_lowercase()})
                })
                .collect();
            let capture = json!({"omitted_observations":0,"omitted_bytes":0,
                                 "reasons":{},"examples":[]});
            let engine = json!({
                "format":"msi","inspection":"static_streams",
                "streams":streams,"stream_count":streams.len(),
                "stream_bytes_read":inspected.stream_bytes_read,
                "artifact_capture":capture,
                "limitations":[
                    "Windows Installer tables and custom actions were not executed",
                    "Embedded CAB files were retained but not unpacked"
                ]
            });
            let engine_raw = serde_json::to_vec(&engine).unwrap();
            std::fs::write(self.engine(), &engine_raw).unwrap();
            let summary = json!({
                "id":ID,"status":"partial","completion_reason":"static_inspection",
                "instruction_count":0,"guest_trace_complete":false,
                "sample":{"name":"generated.msi","kind":"msi",
                          "managed":false,"architecture":"container",
                          "sha256":format!("{:x}",Sha256::digest(&source))},
                "artifact_capture":capture,
                "engine_report":"engine-report.json",
                "engine_report_size":engine_raw.len(),
                "engine_report_sha256":format!("{:x}",Sha256::digest(&engine_raw)),
                "run_manifest":{"engine_report_integrity":"sha256-v1"}
            });
            std::fs::write(self.summary(), serde_json::to_vec(&summary).unwrap()).unwrap();
        }

        fn replace_engine(&self, engine: &Value) {
            let engine_raw = serde_json::to_vec(engine).unwrap();
            std::fs::write(self.engine(), &engine_raw).unwrap();
            let mut summary: Value =
                serde_json::from_slice(&std::fs::read(self.summary()).unwrap()).unwrap();
            summary["engine_report_size"] = json!(engine_raw.len());
            summary["engine_report_sha256"] = json!(format!("{:x}", Sha256::digest(&engine_raw)));
            std::fs::write(self.summary(), serde_json::to_vec(&summary).unwrap()).unwrap();
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(self.source());
            let _ = std::fs::remove_file(self.summary());
            let _ = std::fs::remove_file(self.engine());
            let _ = std::fs::remove_dir(self.run());
            let _ = std::fs::remove_dir(&self.0);
        }
    }

    #[test]
    fn generated_static_report_binds_to_source_without_execution_claim() {
        let fixture = Fixture::new();
        fixture.write();
        let result = inspect(&fixture.run(), Some(&fixture.source())).unwrap();
        assert_eq!(result["declared_stream_count"], 1);
        assert_eq!(result["source_streams_checked"], true);
        assert_eq!(result["installer_execution_verified"], false);
        assert_eq!(result["artifact_payloads_verified"], false);
    }

    #[test]
    fn changed_source_or_engine_bytes_refuse() {
        let fixture = Fixture::new();
        fixture.write();
        std::fs::write(fixture.source(), b"changed").unwrap();
        assert!(inspect(&fixture.run(), Some(&fixture.source())).is_err());
        assert!(inspect(&fixture.run(), None).is_ok());
        std::fs::write(fixture.engine(), b"{}").unwrap();
        assert!(inspect(&fixture.run(), None).is_err());
    }

    #[test]
    fn internally_rehashed_false_stream_count_and_capture_refuse() {
        let fixture = Fixture::new();
        fixture.write();
        let mut engine: Value =
            serde_json::from_slice(&std::fs::read(fixture.engine()).unwrap()).unwrap();
        engine["stream_count"] = json!(2);
        fixture.replace_engine(&engine);
        assert!(inspect(&fixture.run(), None).is_err());
        engine["stream_count"] = json!(1);
        engine["artifact_capture"]["omitted_bytes"] = json!(1);
        fixture.replace_engine(&engine);
        assert!(inspect(&fixture.run(), None).is_err());
    }

    #[test]
    fn linked_summary_and_invented_execution_refuse() {
        let fixture = Fixture::new();
        fixture.write();
        let outside = fixture.0.join("outside.json");
        std::fs::rename(fixture.summary(), &outside).unwrap();
        std::fs::hard_link(&outside, fixture.summary()).unwrap();
        assert!(inspect(&fixture.run(), None).is_err());
        std::fs::remove_file(fixture.summary()).unwrap();
        std::fs::rename(outside, fixture.summary()).unwrap();
        let mut summary: Value =
            serde_json::from_slice(&std::fs::read(fixture.summary()).unwrap()).unwrap();
        summary["instruction_count"] = json!(1);
        std::fs::write(fixture.summary(), serde_json::to_vec(&summary).unwrap()).unwrap();
        assert!(inspect(&fixture.run(), None).is_err());
    }
}
