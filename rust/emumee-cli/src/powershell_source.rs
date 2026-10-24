//! Bounded PowerShell source inspection. No script interpreter or container launch.
use anyhow::{Result, bail, ensure};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::Path;

pub const MAX_SCRIPT_BYTES: usize = 1024 * 1024;

fn inspect_bytes(name: &str, bytes: &[u8]) -> Result<Value> {
    ensure!(
        (1..=MAX_SCRIPT_BYTES).contains(&bytes.len()),
        "PowerShell input must contain 1..1048576 bytes"
    );
    Ok(json!({
        "schema": 1,
        "kind": "powershell_source_inspection",
        "status": "inspection_only",
        "sample": {"name": name, "kind": "powershell", "sha256": format!("{:x}", Sha256::digest(bytes))},
        "source_bytes": bytes.len(),
        "execution_authorized": false,
        "engine_applied": false,
        "report_generated": false,
        "reason": "Rust PowerShell execution and offline Docker observer are not implemented"
    }))
}

#[cfg(windows)]
pub fn inspect(path: &Path) -> Result<Value> {
    use anyhow::Context;
    if !path
        .extension()
        .and_then(|suffix| suffix.to_str())
        .is_some_and(|suffix| suffix.eq_ignore_ascii_case("ps1"))
    {
        bail!("PowerShell input must be a .ps1 file");
    }
    let bytes = emumee_platform::windows::read_regular(path, MAX_SCRIPT_BYTES, None)
        .context("PowerShell source could not be safely read")?;
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    inspect_bytes(&name, &bytes)
}

#[cfg(not(windows))]
pub fn inspect(path: &Path) -> Result<Value> {
    let _ = path;
    bail!("Verified PowerShell source inspection requires the Windows regular-file reader")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_source_hash_and_nonexecution_are_explicit() {
        let result = inspect_bytes("probe.ps1", b"Write-Output 'fixture'\n").unwrap();
        assert_eq!(result["schema"], 1);
        assert_eq!(result["status"], "inspection_only");
        assert_eq!(result["execution_authorized"], false);
        assert_eq!(result["engine_applied"], false);
        assert_eq!(result["report_generated"], false);
        assert_eq!(result["source_bytes"], 23);
        assert_eq!(result["sample"]["sha256"].as_str().unwrap().len(), 64);
    }

    #[test]
    fn source_size_bound_matches_python_command() {
        assert!(inspect_bytes("empty.ps1", b"").is_err());
        assert!(inspect_bytes("limit.ps1", &vec![b'x'; MAX_SCRIPT_BYTES]).is_ok());
        assert!(inspect_bytes("excess.ps1", &vec![b'x'; MAX_SCRIPT_BYTES + 1]).is_err());
    }
}
