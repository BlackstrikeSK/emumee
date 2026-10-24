//! Read-only static MSI-family compound stream inspection. No host extraction.
use anyhow::Result;
use serde_json::Value;
use std::path::Path;

#[cfg(windows)]
pub fn inspect(path: &Path) -> Result<Value> {
    use anyhow::Context;
    let bytes =
        emumee_platform::windows::read_regular(path, emumee_core::msi::MAX_INPUT_BYTES, None)
            .context("MSI input could not be safely read")?;
    let inspection = emumee_core::msi::inspect(&bytes)
        .context("Static compound-file stream inspection failed")?;
    // Each stream's data Vec is serde(skip). Only bounded names, lengths,
    // classifications, digests, omissions, and scope limitations cross stdout.
    Ok(serde_json::to_value(inspection)?)
}

#[cfg(not(windows))]
pub fn inspect(path: &Path) -> Result<Value> {
    let _ = path;
    anyhow::bail!("Verified MSI inspection requires the Windows regular-file reader")
}
