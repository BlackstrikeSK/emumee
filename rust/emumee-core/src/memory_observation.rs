//! Bound metadata for the closed native/kernel settled-root indicator slice.
//! It does not certify every live mapping, custom patterns or checkpoints.
use crate::{
    indicator_fixture::{self, Case},
    report_bundle, reports,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const VERSION: &str = "emumee.settled-root-indicators.v1";
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Coverage {
    CompleteSelectedRoot,
    SelectedRootPrefix,
    Disabled,
    Omitted,
}
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Omission {
    RootNotReadable,
    ReadBudget,
    RootReadFailed,
    ScanProfileLimit,
    ScannerSourceRefused,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub version: String,
    pub case: Case,
    pub source: String,
    pub coverage: Coverage,
    pub all_guest_memory_complete: bool,
    pub enabled: bool,
    pub input_sha256: String,
    pub initial_image_sha256: String,
    pub settled_image_sha256: Option<String>,
    pub initial_patches_absent: bool,
    pub runtime_patches_verified: bool,
    pub capture_sha256: String,
    pub image_base: u64,
    pub image_bytes: u64,
    pub read_limit: u64,
    pub scan_limit: u64,
    pub read_reserved_bytes: u64,
    pub read_bytes: u64,
    pub selected_bytes: u64,
    pub boundary_instructions: u64,
    pub boundary_pc: u64,
    pub retained_snapshot: bool,
    pub omissions: Vec<Omission>,
}
fn hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
/// Canonical Value encoding, never a lossy string/debug or float representation.
pub fn capture_hash(capture: &Value) -> Option<String> {
    reports::valid_memory_capture(capture)
        .then(|| report_bundle::bounded_json(capture, 2 * 1024 * 1024).ok())
        .flatten()
        .map(|raw| report_bundle::digest(&raw))
}
pub fn valid_execution(execution: &Value) -> bool {
    if execution["memory_string_sources"]["version"] == crate::managed_observation::VERSION {
        return crate::managed_observation::valid_execution(execution);
    }
    let capture = execution.get("memory_strings");
    let sources = execution.get("memory_string_sources");
    let (Some(capture), Some(sources)) = (capture, sources) else {
        return capture.is_none() && sources.is_none();
    };
    let Ok(receipt) = serde_json::from_value::<Receipt>(sources.clone()) else {
        return false;
    };
    if receipt.version != VERSION
        || receipt.source != indicator_fixture::SOURCE
        || receipt.all_guest_memory_complete
        || receipt.enabled != receipt.case.enabled()
        || capture.get("enabled").and_then(Value::as_bool) != Some(receipt.enabled)
        || capture.get("regex") != Some(&serde_json::json!([]))
        || capture_hash(capture).as_deref() != Some(receipt.capture_sha256.as_str())
        || !hash(&receipt.input_sha256)
        || !hash(&receipt.initial_image_sha256)
        || receipt
            .settled_image_sha256
            .as_deref()
            .is_some_and(|v| !hash(v))
        || receipt.image_bytes != indicator_fixture::IMAGE_BYTES as u64
        || receipt
            .image_base
            .checked_add(receipt.image_bytes)
            .is_none()
        || execution
            .get("image_load")
            .and_then(|value| value.get("size"))
            .and_then(Value::as_u64)
            != Some(receipt.image_bytes)
        || receipt.read_limit != receipt.case.read_limit()
        || receipt.scan_limit != receipt.case.scan_limit() as u64
        || receipt.read_bytes > receipt.read_reserved_bytes
        || receipt.read_reserved_bytes > receipt.read_limit
        || receipt.selected_bytes > receipt.scan_limit
        || capture.get("scanned_bytes").and_then(Value::as_u64) != Some(receipt.selected_bytes)
        || execution.get("instruction_count").and_then(Value::as_u64)
            != Some(receipt.boundary_instructions)
        || execution.get("final_pc").and_then(Value::as_u64) != Some(receipt.boundary_pc)
        || execution
            .get("image_load")
            .and_then(|v| v.get("base"))
            .and_then(Value::as_u64)
            != Some(receipt.image_base)
    {
        return false;
    }
    let architecture = match execution.get("architecture").and_then(Value::as_str) {
        Some("x86") => crate::pe::Architecture::X86,
        Some("x64") => crate::pe::Architecture::X64,
        _ => return false,
    };
    let input = receipt.case.input(architecture);
    let Ok(pe) = crate::pe::PeImage::parse(&input, "closed-indicators.pe") else {
        return false;
    };
    let Ok(initial) = pe.materialize(&input, receipt.image_base) else {
        return false;
    };
    if receipt.input_sha256 != report_bundle::digest(&input)
        || receipt.initial_image_sha256 != report_bundle::digest(&initial)
        || !receipt.initial_patches_absent
    {
        return false;
    }
    let complete_read = receipt.read_bytes == receipt.image_bytes;
    let valid_coverage = match receipt.coverage {
        Coverage::Disabled => {
            !receipt.enabled
                && receipt.read_bytes == 0
                && receipt.read_reserved_bytes == 0
                && receipt.selected_bytes == 0
                && receipt.omissions.is_empty()
        }
        Coverage::Omitted => {
            receipt.enabled
                && receipt.selected_bytes == 0
                && receipt.omissions.len() == 1
                && matches!(
                    receipt.omissions[0],
                    Omission::RootNotReadable
                        | Omission::ReadBudget
                        | Omission::RootReadFailed
                        | Omission::ScannerSourceRefused
                )
        }
        Coverage::CompleteSelectedRoot => {
            receipt.enabled
                && complete_read
                && receipt.selected_bytes == receipt.image_bytes
                && receipt.omissions.is_empty()
        }
        Coverage::SelectedRootPrefix => {
            receipt.enabled
                && complete_read
                && receipt.selected_bytes < receipt.image_bytes
                && receipt.selected_bytes == receipt.scan_limit
                && receipt.omissions == [Omission::ScanProfileLimit]
        }
    };
    if !valid_coverage
        || receipt.settled_image_sha256.is_some() != complete_read
        || (receipt.retained_snapshot && (!complete_read || !receipt.case.retain()))
    {
        return false;
    }
    if !receipt.enabled
        && capture
            .get("matches")
            .and_then(Value::as_array)
            .is_none_or(|v| !v.is_empty())
    {
        return false;
    }
    let Some(artifacts) = execution.get("artifacts").and_then(Value::as_array) else {
        return false;
    };
    if artifacts.len() != usize::from(receipt.retained_snapshot) {
        return false;
    }
    if receipt.retained_snapshot
        && (artifacts[0].get("sha256").and_then(Value::as_str)
            != receipt.settled_image_sha256.as_deref()
            || artifacts[0].get("size").and_then(Value::as_u64) != Some(receipt.image_bytes)
            || artifacts[0]
                .get("observations")
                .and_then(Value::as_array)
                .is_none_or(|observations| {
                    observations.len() != 1
                        || observations[0]["kind"] != "memory_snapshot"
                        || observations[0]["source"] != indicator_fixture::SOURCE
                }))
    {
        return false;
    }
    capture["matches"].as_array().is_some_and(|matches| {
        matches.iter().all(|item| {
            item["source"] == indicator_fixture::SOURCE
                && matches!(item["encoding"].as_str(), Some("ascii" | "utf-16le"))
                && item["offset"].as_u64().is_some_and(|offset| {
                    let expected = format!("0x{:x}", receipt.image_base + offset);
                    offset < receipt.selected_bytes
                        && item["address"].as_str() == Some(expected.as_str())
                })
        })
    })
}
/// Only the new explicit typed role is governed by this extension. Legacy Python
/// memory_strings reports without this profile retain existing reader semantics.
pub fn requires_typed_binding(summary: &Value, engine: &Value) -> bool {
    summary.get("memory_string_sources").is_some()
        || engine
            .get("execution")
            .is_some_and(|value| value.get("memory_string_sources").is_some())
        || [summary.get("run_manifest"), engine.get("run_manifest")]
            .into_iter()
            .flatten()
            .any(|manifest| {
                manifest.get("memory_string_profile").is_some()
                    || manifest
                        .get("case")
                        .and_then(Value::as_str)
                        .and_then(crate::analysis_fixture::Case::parse)
                        .and_then(crate::analysis_fixture::Case::observation_profile)
                        .is_some()
            })
}
/// The explicit profile is bound to a closed case, never inferred from matches.
pub fn valid_declaration(manifest: &Value, execution: &Value) -> bool {
    let case = manifest
        .get("case")
        .and_then(Value::as_str)
        .and_then(crate::analysis_fixture::Case::parse);
    if let Some(sources) = execution.get("memory_string_sources") {
        let profile = case.and_then(crate::analysis_fixture::Case::observation_profile);
        profile.is_some()
            && profile
                == manifest
                    .get("memory_string_profile")
                    .and_then(Value::as_str)
            && profile == sources.get("version").and_then(Value::as_str)
            && case
                .and_then(crate::analysis_fixture::Case::observation_case)
                .as_ref()
                == sources.get("case")
    } else {
        manifest.get("memory_string_profile").is_none()
            && case
                .and_then(crate::analysis_fixture::Case::observation_profile)
                .is_none()
    }
}
/// Optional fields must be present together and exactly match hash-bound engine data.
pub fn summary_matches(summary: &Value, execution: &Value) -> bool {
    valid_execution(execution)
        && valid_declaration(&summary["run_manifest"], execution)
        && ["memory_strings", "memory_string_sources"]
            .iter()
            .all(|field| summary.get(*field) == execution.get(*field))
}
/// Called only when the reader identifies the explicit new typed extension.
/// Legacy capture fields without this declaration keep previous reader semantics.
pub fn verified_binding(summary: &Value, engine: &Value) -> bool {
    engine.get("execution").is_some_and(|execution| {
        execution.get("memory_string_sources").is_some()
            && summary_matches(summary, execution)
            && summary.get("run_manifest") == engine.get("run_manifest")
    })
}

#[cfg(test)]
mod tests;
