//! Read-only internal binding check for legacy PowerShell report envelopes.
//! It does not authenticate a Docker observer or prove script execution.
use anyhow::Result;
use serde_json::Value;
use std::path::Path;

#[cfg(windows)]
fn decoded_source_text(bytes: &[u8]) -> String {
    if bytes.starts_with(&[0xff, 0xfe]) || bytes.starts_with(&[0xfe, 0xff]) {
        let little = bytes[0] == 0xff;
        let mut units = Vec::with_capacity((bytes.len() - 2) / 2);
        let mut pairs = bytes[2..].chunks_exact(2);
        for pair in &mut pairs {
            units.push(if little {
                u16::from_le_bytes([pair[0], pair[1]])
            } else {
                u16::from_be_bytes([pair[0], pair[1]])
            });
        }
        let mut text = String::from_utf16_lossy(&units);
        if !pairs.remainder().is_empty() {
            text.push('\u{fffd}');
        }
        text
    } else {
        let source = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes);
        String::from_utf8_lossy(source).into_owned()
    }
}

#[cfg(windows)]
pub fn inspect(run: &Path, source_path: Option<&Path>) -> Result<Value> {
    use anyhow::{Context, ensure};
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use emumee_core::reports::{
        BoundReport, MAX_ENGINE_BYTES, MAX_SUMMARY_BYTES, parse_summary, verified_report,
    };
    use emumee_platform::windows::read_regular;
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use std::os::windows::fs::MetadataExt;

    const REPARSE_POINT: u32 = 0x400;
    const MAX_SCRIPT_BYTES: usize = 1024 * 1024;
    let run = std::path::absolute(run).context("Invalid PowerShell report directory")?;
    let meta =
        std::fs::symlink_metadata(&run).context("PowerShell report directory unavailable")?;
    ensure!(
        meta.is_dir() && meta.file_attributes() & REPARSE_POINT == 0,
        "PowerShell report directory must be ordinary"
    );
    let summary_raw = read_regular(&run.join("summary.json"), MAX_SUMMARY_BYTES, Some(&run))
        .context("PowerShell summary could not be safely read")?;
    let summary = parse_summary(&summary_raw).context("Invalid PowerShell summary envelope")?;
    ensure!(
        summary["id"].as_str() == run.file_name().and_then(|n| n.to_str()),
        "PowerShell run directory and summary ID differ"
    );
    ensure!(
        summary["engine"] == "powershell-container"
            && summary["status"] == "partial"
            && summary["sample"]["kind"] == "powershell"
            && summary["sample"]["architecture"] == "x64"
            && summary["sample"]["managed"] == true,
        "Not a legacy PowerShell report envelope"
    );
    ensure!(
        summary["guest_trace_complete"] == false,
        "PowerShell report must retain incomplete guest trace declaration"
    );
    ensure!(
        summary["run_manifest"]["engine_report_integrity"] == "sha256-v1",
        "PowerShell engine report binding not declared"
    );
    ensure!(
        summary["engine_report"] == "engine-report.json",
        "PowerShell engine report filename differs"
    );
    let engine_raw = read_regular(
        &run.join("engine-report.json"),
        MAX_ENGINE_BYTES,
        Some(&run),
    )
    .context("PowerShell engine report could not be safely read")?;
    ensure!(
        verified_report(&summary, BoundReport::Engine, &engine_raw).is_some(),
        "PowerShell engine report hash/length binding differs"
    );
    let engine: Value =
        serde_json::from_slice(&engine_raw).context("Invalid PowerShell engine JSON")?;
    let evidence = engine["execution_evidence"]
        .as_object()
        .context("PowerShell execution evidence is not an object")?;
    let encoded = evidence
        .get("input_bytes_base64")
        .and_then(Value::as_str)
        .context("PowerShell source bytes are absent")?;
    ensure!(
        !encoded.is_empty() && encoded.len() <= MAX_SCRIPT_BYTES.div_ceil(3) * 4,
        "PowerShell encoded source byte bound"
    );
    let script = STANDARD
        .decode(encoded)
        .context("Invalid PowerShell source Base64")?;
    ensure!(
        (1..=MAX_SCRIPT_BYTES).contains(&script.len()),
        "PowerShell source byte bound"
    );
    let source_sha = format!("{:x}", Sha256::digest(&script));
    ensure!(
        summary["sample"]["sha256"] == source_sha
            && evidence.get("sample_sha256").and_then(Value::as_str) == Some(source_sha.as_str()),
        "PowerShell source digest binding differs"
    );
    let sample_name = summary["sample"]["name"]
        .as_str()
        .context("PowerShell sample name absent")?;
    ensure!(
        evidence.get("sample_name").and_then(Value::as_str) == Some(sample_name),
        "PowerShell sample name binding differs"
    );
    let displayed_source = engine["submitted_script_source"]
        .as_str()
        .context("Submitted script source absent")?;
    ensure!(
        evidence.get("source").and_then(Value::as_str) == Some(displayed_source),
        "Submitted script source projection differs"
    );
    ensure!(
        displayed_source == decoded_source_text(&script),
        "Submitted script text differs from embedded source bytes"
    );
    let commands = engine["command_events"]
        .as_array()
        .context("PowerShell command events absent")?;
    let network = engine["network_events"]
        .as_array()
        .context("PowerShell network events absent")?;
    ensure!(
        evidence.get("command_events") == Some(&engine["command_events"])
            && evidence.get("network_events") == Some(&engine["network_events"]),
        "PowerShell event projections differ"
    );
    let observer_complete = evidence
        .get("observer_trace_complete")
        .and_then(Value::as_bool)
        .context("PowerShell observer state absent")?;
    let capture = &engine["command_capture"];
    ensure!(
        capture["complete"] == false
            && capture["event_loss_unknown"] == !observer_complete
            && capture["observer_state"]
                == if observer_complete {
                    "no_interruption_observed"
                } else {
                    "terminated"
                },
        "PowerShell capture limitations differ"
    );
    let expected_network = Value::Array(network.iter().take(1000).cloned().collect());
    ensure!(
        summary["network_attempts"] == expected_network
            && summary["network_attempts_omitted"].as_u64()
                == Some(network.len().saturating_sub(1000) as u64),
        "PowerShell summary network projection differs"
    );
    let original_source_checked = if let Some(path) = source_path {
        ensure!(
            path.extension()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.eq_ignore_ascii_case("ps1")),
            "Supplied source must be .ps1"
        );
        let source = read_regular(path, MAX_SCRIPT_BYTES, None)
            .context("Supplied PowerShell source could not be safely read")?;
        ensure!(
            source == script,
            "Supplied PowerShell source differs from report bytes"
        );
        true
    } else {
        false
    };
    Ok(json!({
        "version":1,
        "kind":"legacy_powershell_report_binding",
        "run_id":summary["id"],
        "declared_status":"partial",
        "source_name":sample_name,
        "source_bytes":script.len(),
        "source_sha256":source_sha,
        "summary_sha256":format!("{:x}",Sha256::digest(&summary_raw)),
        "engine_report_sha256":format!("{:x}",Sha256::digest(&engine_raw)),
        "declared_command_events":commands.len(),
        "declared_network_events":network.len(),
        "original_source_checked":original_source_checked,
        "report_internal_bindings_consistent":true,
        "observer_authenticity_verified":false,
        "script_execution_verified":false,
        "artifacts_verified":false,
        "scope":"Saved PowerShell report consistency only; generated or forged reports can pass"
    }))
}

#[cfg(not(windows))]
pub fn inspect(run: &Path, source_path: Option<&Path>) -> Result<Value> {
    let _ = (run, source_path);
    anyhow::bail!("PowerShell report inspection requires Windows regular-file checks")
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use serde_json::json;
    use sha2::{Digest, Sha256};

    const ID: &str = "20261019T120000Z-deadbeef";
    const SCRIPT: &[u8] = b"Write-Output 'fixture'\n";

    struct Fixture(std::path::PathBuf);

    impl Fixture {
        fn new() -> Self {
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir()
                .join(format!("emumee-ps-report-{}-{stamp}", std::process::id()));
            std::fs::create_dir(&path).unwrap();
            std::fs::create_dir(path.join(ID)).unwrap();
            Self(path)
        }

        fn run(&self) -> std::path::PathBuf {
            self.0.join(ID)
        }

        fn source(&self) -> std::path::PathBuf {
            self.0.join("fixture.ps1")
        }

        fn summary(&self) -> std::path::PathBuf {
            self.run().join("summary.json")
        }

        fn engine(&self) -> std::path::PathBuf {
            self.run().join("engine-report.json")
        }

        fn write(&self) {
            std::fs::write(self.source(), SCRIPT).unwrap();
            let digest = format!("{:x}", Sha256::digest(SCRIPT));
            let evidence = json!({
                "input_bytes_base64":STANDARD.encode(SCRIPT),
                "sample_name":"fixture.ps1","sample_sha256":digest,
                "source":"Write-Output 'fixture'\n",
                "observer_trace_complete":true,
                "command_events":[],"network_events":[]
            });
            let engine = json!({
                "execution_evidence":evidence,
                "submitted_script_source":"Write-Output 'fixture'\n",
                "command_events":[],"network_events":[],
                "command_capture":{"complete":false,"event_loss_unknown":false,
                                   "observer_state":"no_interruption_observed"}
            });
            let engine_raw = serde_json::to_vec(&engine).unwrap();
            std::fs::write(self.engine(), &engine_raw).unwrap();
            let summary = json!({
                "id":ID,"status":"partial","engine":"powershell-container",
                "sample":{"name":"fixture.ps1","kind":"powershell",
                          "managed":true,"architecture":"x64","sha256":digest},
                "guest_trace_complete":false,
                "engine_report":"engine-report.json",
                "engine_report_size":engine_raw.len(),
                "engine_report_sha256":format!("{:x}",Sha256::digest(&engine_raw)),
                "run_manifest":{"engine_report_integrity":"sha256-v1"},
                "network_attempts":[],"network_attempts_omitted":0
            });
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
    fn generated_source_and_report_bind_internally_without_execution_claim() {
        let fixture = Fixture::new();
        fixture.write();
        let result = inspect(&fixture.run(), Some(&fixture.source())).unwrap();
        assert_eq!(result["source_bytes"], SCRIPT.len());
        assert_eq!(result["declared_command_events"], 0);
        assert_eq!(result["original_source_checked"], true);
        assert_eq!(result["observer_authenticity_verified"], false);
        assert_eq!(result["script_execution_verified"], false);
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
    fn linked_summary_and_wrong_sample_digest_refuse() {
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
        summary["sample"]["sha256"] = json!("0".repeat(64));
        std::fs::write(fixture.summary(), serde_json::to_vec(&summary).unwrap()).unwrap();
        assert!(inspect(&fixture.run(), None).is_err());
    }

    #[test]
    fn source_text_projection_matches_python_bom_decoding() {
        assert_eq!(decoded_source_text(b"\xef\xbb\xbfabc"), "abc");
        assert_eq!(decoded_source_text(&[0xff, 0xfe, 0x41, 0, 0x42, 0]), "AB");
        assert_eq!(decoded_source_text(&[0xfe, 0xff, 0, 0x41, 0, 0x42]), "AB");
        assert_eq!(decoded_source_text(&[0xff, 0xfe, 0x41]), "\u{fffd}");
    }
}
