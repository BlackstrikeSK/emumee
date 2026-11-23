//! Bound metadata for the **submitted-sample** memory-string indicator capture.
//!
//! This is the live-run counterpart to the closed `memory_observation` indicator
//! slice. Unlike that slice it admits caller-configured custom patterns (the
//! bounded matcher's `custom_<i>` matches) and a variable image size, because the
//! submitted sample is not the fixed closed fixture. It is a purely additive
//! report profile: the closed indicator fields (`memory_strings` /
//! `memory_string_sources`) and their validators are untouched, so a run uses
//! exactly one of the two profiles and never both.
use crate::{report_bundle, reports};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const VERSION: &str = "emumee.user-memory-indicators.v1";

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Coverage {
    /// The whole readable image root was within the scan budget and scanned.
    CompleteSelectedRoot,
    /// Only a scan-budget-bounded prefix of the readable root was scanned.
    SelectedRootPrefix,
    /// Capture disabled for this run.
    Disabled,
    /// Capture was enabled but produced no scanned bytes (see `omissions`).
    Omitted,
}
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Omission {
    ImageNotReadable,
    ReadBudget,
    ImageReadFailed,
    ScanBudget,
    ScannerSourceRefused,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub version: String,
    pub source: String,
    pub coverage: Coverage,
    pub enabled: bool,
    /// The configured custom patterns; must equal the capture report `regex` array.
    pub patterns: Vec<String>,
    pub input_sha256: String,
    pub image_base: u64,
    pub image_bytes: u64,
    pub scan_limit: u64,
    pub read_limit: u64,
    pub read_reserved_bytes: u64,
    pub read_bytes: u64,
    pub selected_bytes: u64,
    pub capture_sha256: String,
    pub boundary_instructions: u64,
    pub boundary_pc: u64,
    pub omissions: Vec<Omission>,
}
fn is_hex64(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
/// Validate the submitted-sample memory-string profile on an execution Value.
/// Returns true when neither user field is present (the common no-capture run),
/// so it composes additively with the closed-indicator `valid_execution`.
pub fn valid_execution(execution: &Value) -> bool {
    let capture = execution.get("user_memory_strings");
    let sources = execution.get("user_memory_capture");
    let (Some(capture), Some(sources)) = (capture, sources) else {
        return capture.is_none() && sources.is_none();
    };
    let Ok(receipt) = serde_json::from_value::<Receipt>(sources.clone()) else {
        return false;
    };
    if receipt.version != VERSION
        || !reports::valid_memory_capture(capture)
        || capture.get("enabled").and_then(Value::as_bool) != Some(receipt.enabled)
        || capture.get("regex") != Some(&serde_json::json!(receipt.patterns))
        || receipt.patterns.len() > crate::memory_strings::MAX_PATTERNS
        || memory_capture_hash(capture).as_deref() != Some(receipt.capture_sha256.as_str())
        || !is_hex64(&receipt.input_sha256)
        || receipt.image_base.checked_add(receipt.image_bytes).is_none()
        || image_load_u64(execution, "size") != Some(receipt.image_bytes)
        || image_load_u64(execution, "base") != Some(receipt.image_base)
        || receipt.read_bytes > receipt.read_reserved_bytes
        || receipt.read_reserved_bytes > receipt.read_limit
        || receipt.selected_bytes > receipt.scan_limit
        || capture.get("scanned_bytes").and_then(Value::as_u64) != Some(receipt.selected_bytes)
        || execution.get("instruction_count").and_then(Value::as_u64)
            != Some(receipt.boundary_instructions)
        || execution.get("final_pc").and_then(Value::as_u64) != Some(receipt.boundary_pc)
    {
        return false;
    }
    // Consistency between coverage, enablement and scanned bytes.
    let matches_empty = capture
        .get("matches")
        .and_then(Value::as_array)
        .is_some_and(|m| m.is_empty());
    match receipt.coverage {
        Coverage::Disabled => !receipt.enabled && receipt.selected_bytes == 0 && matches_empty,
        Coverage::Omitted => receipt.enabled && receipt.selected_bytes == 0,
        Coverage::CompleteSelectedRoot | Coverage::SelectedRootPrefix => {
            receipt.enabled && receipt.selected_bytes > 0
        }
    }
}
fn image_load_u64(execution: &Value, key: &str) -> Option<u64> {
    execution
        .get("image_load")
        .and_then(|value| value.get(key))
        .and_then(Value::as_u64)
}
/// Canonical capture digest, shared shape with the closed indicator slice.
pub fn memory_capture_hash(capture: &Value) -> Option<String> {
    reports::valid_memory_capture(capture)
        .then(|| report_bundle::bounded_json(capture, 2 * 1024 * 1024).ok())
        .flatten()
        .map(|raw| report_bundle::digest(&raw))
}
/// True when the execution carries the submitted-sample memory-string profile,
/// so the report builder must bind and re-check the user fields in the summary.
pub fn present(execution: &Value) -> bool {
    execution.get("user_memory_capture").is_some()
}
/// The summary must carry the same user memory fields as the execution.
pub fn summary_matches(summary: &Value, execution: &Value) -> bool {
    valid_execution(execution)
        && ["user_memory_strings", "user_memory_capture"]
            .iter()
            .all(|field| summary.get(*field) == execution.get(*field))
}

#[cfg(test)]
mod tests;
