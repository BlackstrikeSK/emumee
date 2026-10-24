//! Legacy worker-to-host report envelopes, validated without filesystem access.
//!
//! The caller must obtain each byte slice through the platform's bounded,
//! regular-file/no-reparse gate and keep the handle's identity pinned. These
//! helpers do not make a path safe or certify that captured bytes are unpacked.
//! `valid_summary` preserves the legacy envelope's deliberately shallow artifact
//! checks; use `verified_artifact` separately before exposing a payload. Unknown
//! fields remain accepted for forward compatibility. JSON parsing rejects lone
//! UTF-16 surrogates and excessive nesting rather than carrying Python-only
//! strings into the UI. Checking group structure alone does not verify its
//! preview or provenance; `verified_artifact_manifest` reconstructs both from
//! hash-verified payloads. Rendering and safe filesystem adapters remain separate.

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_SUMMARY_BYTES: usize = 5 * 1024 * 1024;
pub const MAX_ENGINE_BYTES: usize = 50 * 1024 * 1024;
pub const MAX_NETWORK_REPORT_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_ARTIFACT_BYTES: usize = 32 * 1024 * 1024;
pub const ENGINE_INTEGRITY: &str = "sha256-v1";
const MAX_CONSOLE_CHARS: usize = 128 * 1024;
const MAX_MEMORY_SCAN: u64 = 128 * 1024 * 1024;
const MAX_CAPTURE_BYTES: usize = 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum ReportError {
    #[error("summary exceeds its byte limit")]
    Oversized,
    #[error("malformed report JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid summary envelope")]
    InvalidSummary,
}

/// Parse only an already safely-read bounded buffer. This performs no I/O.
pub fn parse_summary(raw: &[u8]) -> Result<Value, ReportError> {
    if raw.len() > MAX_SUMMARY_BYTES {
        return Err(ReportError::Oversized);
    }
    let summary = serde_json::from_slice(raw)?;
    if !valid_summary(&summary) {
        return Err(ReportError::InvalidSummary);
    }
    Ok(summary)
}

fn require(condition: bool) -> Option<()> {
    condition.then_some(())
}

fn text(value: Option<&Value>, maximum: usize, nonempty: bool) -> bool {
    value
        .and_then(Value::as_str)
        .is_some_and(|s| (!nonempty || !s.is_empty()) && s.chars().count() <= maximum)
}

fn integer(value: Option<&Value>, maximum: u64) -> bool {
    value.and_then(Value::as_u64).is_some_and(|n| n <= maximum)
}

fn one_of(value: Option<&Value>, allowed: &[&str]) -> bool {
    value
        .and_then(Value::as_str)
        .is_some_and(|s| allowed.contains(&s))
}

fn nonnull<'a>(object: &'a Map<String, Value>, key: &str) -> Option<&'a Value> {
    object.get(key).filter(|v| !v.is_null())
}

fn lowercase_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn valid_run_id(value: &str) -> bool {
    let b = value.as_bytes();
    b.len() == 25
        && b[8] == b'T'
        && b[15] == b'Z'
        && b[16] == b'-'
        && b[..8].iter().chain(&b[9..15]).all(u8::is_ascii_digit)
        && lowercase_hex(&value[17..], 8)
}

fn hex_address(value: Option<&Value>) -> bool {
    value.and_then(Value::as_str).is_some_and(|s| {
        s.strip_prefix("0x")
            .is_some_and(|tail| (1..=16).contains(&tail.len()) && lowercase_hex(tail, tail.len()))
    })
}

fn valid_driver(driver: &Value, mode: Option<&Value>) -> Option<()> {
    let d = driver.as_object()?;
    require(mode.and_then(Value::as_str) == Some("kernel"))?;
    let status = nonnull(d, "entry_status");
    if let Some(status) = status {
        require(integer(Some(status), u32::MAX.into()))?;
    }
    for key in [
        "initialization_succeeded",
        "unload_requested",
        "unload_registered",
        "unload_completed",
    ] {
        require(d.get(key)?.is_boolean())?;
    }
    require(
        d["initialization_succeeded"].as_bool()?
            == status
                .and_then(Value::as_u64)
                .is_some_and(|s| s & 0x8000_0000 == 0),
    )?;
    for key in ["registry_path", "driver_object", "scope"] {
        require(text(d.get(key), 32767, false))?;
    }
    let devices = d.get("devices_created")?.as_array()?;
    require(devices.len() <= 64)?;
    for item in devices {
        let item = item.as_object()?;
        require(text(item.get("name"), 1024, false) && text(item.get("address"), 1024, false))?;
    }
    let routines = d.get("dispatch_routines")?.as_object()?;
    require(routines.len() <= 28)?;
    for (key, address) in routines {
        require((0..28).any(|i| key == &i.to_string()) && hex_address(Some(address)))?;
    }
    Some(())
}

fn valid_capture_omissions(value: &Value) -> Option<()> {
    let c = value.as_object()?;
    require(
        integer(c.get("omitted_observations"), 1_000_000)
            && integer(c.get("omitted_bytes"), 1 << 50),
    )?;
    let reasons = c.get("reasons")?.as_object()?;
    require(reasons.len() <= 32)?;
    for (name, count) in reasons {
        require(name.chars().count() <= 64 && integer(Some(count), 1_000_000))?;
    }
    let examples = c.get("examples")?.as_array()?;
    require(examples.len() <= 20)?;
    for item in examples {
        let item = item.as_object()?;
        require(
            text(item.get("source"), 256, false)
                && text(item.get("reason"), 64, false)
                && integer(item.get("bytes"), 1 << 50),
        )?;
    }
    Some(())
}

fn valid_api_coverage(value: &Value) -> Option<()> {
    let c = value.as_object()?;
    require(integer(c.get("api_calls"), 10_000_000))?;
    let total = c["api_calls"].as_u64()?;
    let signatures = c.get("signature_only_calls")?.as_array()?;
    require(signatures.len() <= 10_000)?;
    let mut sum = 0_u64;
    for item in signatures {
        let item = item.as_object()?;
        require(text(item.get("api"), 256, false) && integer(item.get("count"), total))?;
        let count = item["count"].as_u64()?;
        require(count > 0)?;
        sum += count;
    }
    require(sum <= total)?;
    if ["observed_apis", "observed_calls", "other_calls"]
        .iter()
        .any(|key| c.contains_key(*key))
    {
        let observed = c.get("observed_calls")?.as_array()?;
        require(
            observed.len() <= 100
                && integer(c.get("other_calls"), total)
                && integer(c.get("observed_apis"), total),
        )?;
        require(observed.len() as u64 <= c["observed_apis"].as_u64()?)?;
        let mut names = BTreeSet::new();
        let mut sum = c["other_calls"].as_u64()?;
        for item in observed {
            let item = item.as_object()?;
            require(text(item.get("api"), 256, true) && integer(item.get("count"), total))?;
            let count = item["count"].as_u64()?;
            require(count > 0 && integer(item.get("signature_only_count"), count))?;
            require(names.insert(item["api"].as_str()?))?;
            sum += count;
        }
        require(sum == total)?;
    }
    Some(())
}

fn valid_cil_coverage(value: &Value) -> Option<()> {
    let c = value.as_object()?;
    for (total_key, distinct_key, top_key, other_key, label, limit) in [
        (
            "opcode_attempts",
            "tracked_opcodes",
            "top_opcodes",
            "other_opcode_attempts",
            "opcode",
            128,
        ),
        (
            "framework_calls",
            "tracked_framework_methods",
            "top_framework_calls",
            "other_framework_calls",
            "method",
            256,
        ),
    ] {
        require(integer(c.get(total_key), 10_000_000) && integer(c.get(distinct_key), 10_000))?;
        let total = c[total_key].as_u64()?;
        require(integer(c.get(other_key), total))?;
        let top = c.get(top_key)?.as_array()?;
        require(top.len() <= 100 && top.len() as u64 <= c[distinct_key].as_u64()?)?;
        let mut names = BTreeSet::new();
        let mut sum = c[other_key].as_u64()?;
        for item in top {
            let item = item.as_object()?;
            require(text(item.get(label), limit, true) && integer(item.get("count"), total))?;
            let count = item["count"].as_u64()?;
            require(count > 0 && names.insert(item[label].as_str()?))?;
            sum += count;
        }
        require(sum == total)?;
    }
    require(integer(
        c.get("untracked_framework_calls"),
        c["other_framework_calls"].as_u64()?,
    ))
}

fn group_shape(groups: &Value, artifacts: &[Value]) -> Option<()> {
    let groups = groups.as_array()?;
    require(groups.len() <= artifacts.len())?;
    let mut first = BTreeMap::new();
    let mut counts = BTreeMap::new();
    for item in artifacts {
        let item = item.as_object()?;
        let digest = item.get("sha256")?.as_str()?;
        require(lowercase_hex(digest, 64))?;
        first.entry(digest).or_insert(item);
        *counts.entry(digest).or_insert(0_usize) += 1;
    }
    require(groups.len() == first.len())?;
    let mut seen = BTreeSet::new();
    for group in groups {
        let group = group.as_object()?;
        let digest = group.get("sha256")?.as_str()?;
        let item = first.get(digest)?;
        require(seen.insert(digest))?;
        require(
            python_optional_equal(group.get("file"), item.get("file"))
                && python_optional_equal(group.get("size"), item.get("size")),
        )?;
        require(
            group.get("kind")?.is_string()
                && one_of(group.get("preview_encoding"), &["text", "hex"]),
        )?;
        require(group.get("observations")?.as_array()?.len() == counts[digest])?;
        require(text(group.get("preview"), 256, false))?;
    }
    Some(())
}

#[derive(Clone, Copy, Debug)]
pub enum BoundReport {
    Engine,
    NetworkBroker,
}

impl BoundReport {
    fn fields(
        self,
    ) -> (
        &'static str,
        &'static str,
        &'static str,
        &'static str,
        &'static str,
        usize,
    ) {
        match self {
            Self::Engine => (
                "engine_report",
                "engine_report_sha256",
                "engine_report_size",
                "engine_report_integrity",
                "engine-report.json",
                MAX_ENGINE_BYTES,
            ),
            Self::NetworkBroker => (
                "network_broker_report",
                "network_broker_report_sha256",
                "network_broker_report_size",
                "network_broker_report_integrity",
                "network-broker.json",
                MAX_NETWORK_REPORT_BYTES,
            ),
        }
    }
}

fn required_binding(summary: &Map<String, Value>, report: BoundReport) -> bool {
    let (_, _, _, integrity, _, _) = report.fields();
    summary
        .get("run_manifest")
        .and_then(Value::as_object)
        .and_then(|m| m.get(integrity))
        .and_then(Value::as_str)
        == Some(ENGINE_INTEGRITY)
        && one_of(summary.get("status"), &["completed", "partial"])
}

fn binding_shape(summary: &Map<String, Value>, report: BoundReport) -> Option<()> {
    let (name, hash, size, _, expected, maximum) = report.fields();
    let digest = nonnull(summary, hash);
    let length = nonnull(summary, size);
    if digest.is_some() || length.is_some() {
        require(summary.get(name).and_then(Value::as_str) == Some(expected))?;
        require(
            digest
                .and_then(Value::as_str)
                .is_some_and(|s| lowercase_hex(s, 64)),
        )?;
        require(integer(length, maximum as u64) && length?.as_u64()? > 0)?;
    }
    require(!required_binding(summary, report) || digest.is_some())
}

/// Validate legacy report metadata without asserting payload integrity.
pub fn valid_summary(value: &Value) -> bool {
    check_summary(value).is_some()
}

fn check_summary(value: &Value) -> Option<()> {
    let v = value.as_object()?;
    if let Some(capture) = v.get("memory_strings") {
        require(valid_memory_capture(capture))?;
    }
    require(v.get("id")?.as_str().is_some_and(valid_run_id) && v.get("sample")?.is_object())?;
    if v.contains_key("execution_mode") {
        require(one_of(v.get("execution_mode"), &["kernel", "user"]))?;
    }
    if let Some(driver) = nonnull(v, "driver") {
        valid_driver(driver, v.get("execution_mode"))?;
    }
    require(one_of(
        v.get("status"),
        &["running", "completed", "partial", "failed", "timeout"],
    ))?;
    let empty = Vec::new();
    let artifacts = match v.get("artifacts") {
        Some(items) => items.as_array()?,
        None => &empty,
    };
    require(artifacts.len() <= 10_000 && artifacts.iter().all(Value::is_object))?;
    let errors = match v.get("errors") {
        Some(items) => items.as_array()?,
        None => &empty,
    };
    require(errors.iter().all(Value::is_string))?;
    if let Some(integrity) = nonnull(v, "artifact_integrity") {
        require(
            one_of(Some(integrity), &["failed", "unverified"])
                && !one_of(v.get("status"), &["completed", "partial"]),
        )?;
    }
    for (key, maximum) in [
        ("unverified_artifact_count", 10_000),
        ("instruction_count", u64::MAX),
        ("denied_operations", 100_000_000),
        ("network_attempts_omitted", 50_000),
    ] {
        if let Some(n) = v.get(key) {
            require(integer(Some(n), maximum))?;
        }
    }
    for key in [
        "instruction_limit_reached",
        "timeout_reached",
        "guest_trace_complete",
        "artifact_checkpoint_recovered",
    ] {
        if let Some(flag) = v.get(key) {
            require(flag.is_boolean())?;
        }
    }
    for key in ["guest_exit_code", "guest_entry_return"] {
        if let Some(code) = nonnull(v, key) {
            require(integer(Some(code), u32::MAX.into()))?;
        }
    }
    if v.contains_key("completion_reason") {
        require(one_of(
            v.get("completion_reason"),
            &[
                "exit_process",
                "entry_return",
                "instruction_limit",
                "timeout",
                "error",
                "worker_failure",
                "unknown",
                "static_inspection",
                "cancelled",
            ],
        ))?;
    }
    if one_of(v.get("status"), &["completed"]) {
        if nonnull(v, "completion_reason").is_some() {
            require(one_of(
                v.get("completion_reason"),
                &["exit_process", "entry_return"],
            ))?;
        }
        require(
            errors.is_empty()
                && v.get("timeout_reached").and_then(Value::as_bool) != Some(true)
                && v.get("instruction_limit_reached").and_then(Value::as_bool) != Some(true),
        )?;
    }
    if let Some(attempts) = v.get("network_attempts") {
        let attempts = attempts.as_array()?;
        require(attempts.len() <= 1000 && attempts.iter().all(Value::is_object))?;
    }
    if let Some(capture) = nonnull(v, "artifact_capture") {
        valid_capture_omissions(capture)?;
    }
    for key in ["run_manifest", "persona"] {
        if let Some(object) = nonnull(v, key) {
            require(object.is_object())?;
        }
    }
    binding_shape(v, BoundReport::Engine)?;
    binding_shape(v, BoundReport::NetworkBroker)?;
    if let Some(groups) = nonnull(v, "artifact_groups") {
        group_shape(groups, artifacts)?;
    }
    if let Some(console) = nonnull(v, "console_output") {
        let console = console.as_object()?;
        for (stream, truncated) in [
            ("stdout", "stdout_truncated"),
            ("stderr", "stderr_truncated"),
        ] {
            require(
                text(console.get(stream), MAX_CONSOLE_CHARS, false)
                    && console.get(truncated)?.is_boolean(),
            )?;
        }
    }
    if let Some(coverage) = nonnull(v, "api_coverage") {
        valid_api_coverage(coverage)?;
    }
    if let Some(coverage) = nonnull(v, "cil_coverage") {
        valid_cil_coverage(coverage)?;
    }
    Some(())
}

/// Same bounded envelope as legacy `memory_strings.valid_capture`, not a scan.
pub fn valid_memory_capture(value: &Value) -> bool {
    check_memory_capture(value).is_some()
}

fn check_memory_capture(value: &Value) -> Option<()> {
    let c = value.as_object()?;
    require(
        c.get("enabled")?.is_boolean()
            && c.get("truncated")?.is_boolean()
            && integer(c.get("scanned_bytes"), MAX_MEMORY_SCAN),
    )?;
    let patterns = c.get("regex")?.as_array()?;
    let matches = c.get("matches")?.as_array()?;
    let limits = c.get("limits")?.as_array()?;
    require(patterns.len() <= 16 && matches.len() <= 1000 && limits.len() <= 21)?;
    require(
        patterns.iter().all(|v| text(Some(v), 1024, true))
            && limits.iter().all(|v| text(Some(v), 64, false)),
    )?;
    let mut bytes = 0;
    for item in matches {
        let item = item.as_object()?;
        require(
            item.len() == 6
                && ["format", "encoding", "value", "source", "offset", "address"]
                    .iter()
                    .all(|k| item.contains_key(*k)),
        )?;
        let format = item["format"].as_str()?;
        require(
            ["ipv4", "ipv6", "url"].contains(&format)
                || (1..=patterns.len()).any(|i| format == format!("custom_{i}")),
        )?;
        require(
            one_of(item.get("encoding"), &["ascii", "utf-16le", "managed"])
                && text(item.get("value"), 1024, true)
                && text(item.get("source"), 256, false)
                && integer(item.get("offset"), u64::MAX),
        )?;
        require(item["address"].is_null() || hex_address(item.get("address")))?;
        bytes += ascii_object_len(item);
        require(bytes <= MAX_CAPTURE_BYTES)?;
    }
    Some(())
}

// Python json.dumps(..., ensure_ascii=True) includes a space after ':' and ','.
// Matches contain only already-validated primitive fields, so no recursion is
// necessary for this byte accounting; non-BMP scalars become surrogate pairs.
fn ascii_string_len(s: &str) -> usize {
    2 + s
        .chars()
        .map(|c| match c {
            '"' | '\\' | '\u{8}' | '\u{c}' | '\n' | '\r' | '\t' => 2,
            c if (c as u32) < 0x20 || (c as u32) >= 0x7f => {
                if c as u32 > 0xffff {
                    12
                } else {
                    6
                }
            }
            _ => 1,
        })
        .sum::<usize>()
}

fn ascii_object_len(object: &Map<String, Value>) -> usize {
    2 + object.len().saturating_sub(1) * 2
        + object
            .iter()
            .map(|(key, v)| {
                ascii_string_len(key)
                    + 2
                    + match v {
                        Value::String(s) => ascii_string_len(s),
                        Value::Null => 4,
                        Value::Number(n) => n.to_string().len(),
                        _ => unreachable!("validated memory-capture primitive"),
                    }
            })
            .sum::<usize>()
}

/// Verify the post-run digest/length binding of safely-read opaque report bytes.
/// Legacy unbound reports remain readable unless the manifest requires binding.
pub fn verified_report<'a>(
    summary: &Value,
    report: BoundReport,
    raw: &'a [u8],
) -> Option<&'a [u8]> {
    let s = summary.as_object()?;
    let (name, hash, size, _, expected, maximum) = report.fields();
    require(raw.len() <= maximum)?;
    if let Some(name) = nonnull(s, name) {
        require(name.as_str() == Some(expected))?;
    }
    let digest = nonnull(s, hash);
    let length = nonnull(s, size);
    if required_binding(s, report) || digest.is_some() || length.is_some() {
        require(s.get(name).and_then(Value::as_str) == Some(expected))?;
        require(integer(length, maximum as u64) && length?.as_u64()? == raw.len() as u64)?;
        require(
            digest
                .and_then(Value::as_str)
                .is_some_and(|s| lowercase_hex(s, 64) && format!("{:x}", Sha256::digest(raw)) == s),
        )?;
    }
    Some(raw)
}

/// Validate metadata before choosing an artifact filename. Does not read a path.
pub fn valid_artifact_metadata(item: &Value) -> bool {
    check_artifact_metadata(item).is_some()
}

fn check_artifact_metadata(item: &Value) -> Option<()> {
    let item = item.as_object()?;
    let name = item.get("file")?.as_str()?;
    let (prefix, extension) = name.split_once('.')?;
    require(lowercase_hex(prefix, 20) && ["pe", "txt", "bin"].contains(&extension))?;
    let digest = item.get("sha256")?.as_str()?;
    require(lowercase_hex(digest, 64) && digest.starts_with(prefix))?;
    require(integer(item.get("size"), MAX_ARTIFACT_BYTES as u64) && item["size"].as_u64()? > 0)?;
    for key in ["kind", "source", "guest_path"] {
        require(text(item.get(key), 4096, false))?;
    }
    if let Some(context) = item.get("context") {
        require(context.is_object())?;
    }
    Some(())
}

/// Hash and length verification on one already safely-read artifact buffer.
pub fn verified_artifact<'a>(item: &Value, raw: &'a [u8]) -> Option<&'a [u8]> {
    check_artifact_metadata(item)?;
    require(item["size"].as_u64()? == raw.len() as u64)?;
    require(item["sha256"].as_str()? == format!("{:x}", Sha256::digest(raw)))?;
    Some(raw)
}

/// Compare a safely-read manifest with the report's ordered observations.
/// Payload and derived-group verification must additionally use verified bytes.
pub fn manifest_matches(raw: &[u8], artifacts: &Value) -> bool {
    if raw.len() > MAX_SUMMARY_BYTES {
        return false;
    }
    serde_json::from_slice::<Value>(raw)
        .is_ok_and(|manifest| python_json_equal(&manifest, artifacts))
}

/// Decode only structurally valid checkpoint observations; does not recover any
/// bytes or claim a checkpoint is usable until the caller verifies every file.
pub fn checkpoint_observations(raw: &[u8]) -> Option<Vec<Value>> {
    require(raw.len() <= MAX_SUMMARY_BYTES)?;
    let value: Value = serde_json::from_slice(raw).ok()?;
    let items = value.as_array()?;
    require(items.len() <= 10_000 && items.iter().all(valid_artifact_metadata))?;
    Some(items.clone())
}

/// Verify the exact manifest and every payload before accepting derived groups.
/// The loader must return bytes from one bounded, identity-pinned safe handle.
/// It receives only metadata that already passed `valid_artifact_metadata`.
pub fn verified_artifact_manifest(
    raw: &[u8],
    artifacts: &Value,
    groups: Option<&Value>,
    mut loader: impl FnMut(&Value) -> Option<Vec<u8>>,
) -> bool {
    if !manifest_matches(raw, artifacts) {
        return false;
    }
    let Some(items) = artifacts.as_array() else {
        return false;
    };
    let Some(actual) = groups_from_verified_payloads(items, &mut loader) else {
        return false;
    };
    groups.is_none_or(|expected| python_json_equal(expected, &actual))
}

/// Recover complete observations and display groups only after verifying every
/// referenced payload. No status or successful-unpacking claim is synthesized.
pub fn verified_checkpoint(
    raw: &[u8],
    mut loader: impl FnMut(&Value) -> Option<Vec<u8>>,
) -> Option<(Vec<Value>, Value)> {
    let items = checkpoint_observations(raw)?;
    let groups = groups_from_verified_payloads(&items, &mut loader)?;
    Some((items, groups))
}

/// Derive display groups from bounded verified payloads. Callers must bound total
/// payload/hash work; this helper performs no I/O or unpacking certification.
pub fn groups_from_verified_payloads<T: AsRef<[u8]>>(
    items: &[Value],
    loader: &mut impl FnMut(&Value) -> Option<T>,
) -> Option<Value> {
    require(items.len() <= 10_000)?;
    let mut groups: Vec<Value> = Vec::new();
    let mut by_hash = BTreeMap::new();
    for item in items {
        check_artifact_metadata(item)?;
        let raw = loader(item)?;
        let raw = raw.as_ref();
        verified_artifact(item, raw)?;
        let digest = item["sha256"].as_str()?;
        let index = if let Some(index) = by_hash.get(digest) {
            *index
        } else {
            let metadata = bounded_pe_metadata(raw);
            let mapped_memory = item["kind"].as_str() == Some("memory")
                && item
                    .get("context")
                    .and_then(|c| c.get("layout"))
                    .and_then(Value::as_str)
                    == Some("mapped_image");
            let kind = if mapped_memory {
                "memory"
            } else if metadata.is_some() {
                "pe"
            } else if raw.starts_with(b"PK\x03\x04") {
                "zip"
            } else if raw.starts_with(b"\x1f\x8b") {
                "gzip"
            } else if [b"#!".as_slice(), b"<script", b"<?xml", b"powershell"]
                .iter()
                .any(|p| raw.starts_with(p))
            {
                "script"
            } else {
                "binary"
            };
            let snippet = &raw[..raw.len().min(256)];
            let printable = snippet
                .iter()
                .all(|b| [9, 10, 13].contains(b) || (32..127).contains(b));
            let preview = if printable {
                String::from_utf8(snippet.to_vec()).ok()?
            } else {
                raw[..raw.len().min(32)]
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect()
            };
            let mut group = serde_json::json!({
                "sha256": digest, "file": item["file"], "size": item["size"],
                "kind": kind, "preview": preview,
                "preview_encoding": if printable {"text"} else {"hex"}, "observations": []
            });
            if kind == "pe" {
                group["pe_metadata"] = metadata?;
            }
            let index = groups.len();
            groups.push(group);
            by_hash.insert(digest.to_owned(), index);
            index
        };
        let observation = group_observation(item)?;
        groups[index]["observations"]
            .as_array_mut()?
            .push(observation);
    }
    groups.sort_by_key(|group| {
        (
            group["kind"].as_str() != Some("pe"),
            !["script", "zip", "gzip"].contains(&group["kind"].as_str().unwrap_or_default()),
            std::cmp::Reverse(group["size"].as_u64().unwrap_or_default()),
        )
    });
    Some(Value::Array(groups))
}

pub fn group_observation(item: &Value) -> Option<Value> {
    check_artifact_metadata(item)?;
    let source = item["source"].as_str()?;
    let stage = if ["virtual_file_final", "managed_file_write"].contains(&source) {
        "final"
    } else if source.starts_with("file_write") {
        "intermediate"
    } else if source.contains("memory")
        || [
            "managed_array",
            "managed_aes_plaintext",
            "managed_aes_decrypt",
        ]
        .iter()
        .any(|prefix| source.starts_with(prefix))
    {
        "memory"
    } else {
        "other"
    };
    let mut observation = serde_json::json!({"source": source, "guest_path": item["guest_path"], "kind": item["kind"], "stage": stage});
    if let Some(context) = item.get("context") {
        observation["context"] = context.clone();
    }
    Some(observation)
}

fn ascii_replacement(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| {
            if b.is_ascii() {
                char::from(*b)
            } else {
                '\u{fffd}'
            }
        })
        .collect()
}

/// Display-only PE metadata, equivalent to the legacy bounded host parser.
/// This intentionally makes no executable-validity or unpacking assertion.
pub fn bounded_pe_metadata(raw: &[u8]) -> Option<Value> {
    bounded_pe_metadata_with_profile(raw, crate::capture_profile::CaptureProfile::Legacy32V1)
}
pub fn bounded_pe_metadata_with_profile(
    raw: &[u8],
    profile: crate::capture_profile::CaptureProfile,
) -> Option<Value> {
    if raw.len() < 512 || !raw.starts_with(b"MZ") || raw.len() > profile.limits().single {
        return None;
    }
    fn u16_at(raw: &[u8], offset: usize) -> Option<u16> {
        Some(u16::from_le_bytes(
            raw.get(offset..offset.checked_add(2)?)?.try_into().ok()?,
        ))
    }
    fn u32_at(raw: &[u8], offset: usize) -> Option<u32> {
        Some(u32::from_le_bytes(
            raw.get(offset..offset.checked_add(4)?)?.try_into().ok()?,
        ))
    }
    let pe = u32_at(raw, 0x3c)? as usize;
    require(pe <= raw.len() - 24 && raw.get(pe..pe + 4)? == b"PE\0\0")?;
    let machine = u16_at(raw, pe + 4)?;
    let section_count = u16_at(raw, pe + 6)? as usize;
    let optional_size = u16_at(raw, pe + 20)? as usize;
    require(section_count <= 96)?;
    let optional = pe + 24;
    require(optional_size >= 96 && optional + optional_size <= raw.len())?;
    let magic = u16_at(raw, optional)?;
    require([0x10b, 0x20b].contains(&magic) && (magic != 0x20b || optional_size >= 112))?;
    let image_size = u32_at(raw, optional + 56)?;
    let headers = u32_at(raw, optional + 60)? as usize;
    require((1..=0x7fff_ffff).contains(&image_size) && headers > 0 && headers <= raw.len())?;
    let table = optional + optional_size;
    require(table + section_count * 40 <= raw.len())?;
    let mut sections = Vec::new();
    let mut section_names = Vec::new();
    for index in 0..section_count {
        let offset = table + index * 40;
        if index < 32 {
            let name = raw.get(offset..offset + 8)?;
            let end = name.iter().rposition(|b| *b != 0).map_or(0, |i| i + 1);
            section_names.push(ascii_replacement(&name[..end]));
        }
        sections.push((
            u32_at(raw, offset + 12)? as usize,
            u32_at(raw, offset + 8)? as usize,
            u32_at(raw, offset + 20)? as usize,
            u32_at(raw, offset + 16)? as usize,
        ));
    }
    let file_offset = |rva: usize, count: usize| -> Option<usize> {
        let end = rva.checked_add(count)?;
        if rva < headers && end <= headers.min(raw.len()) {
            return Some(rva);
        }
        for &(virtual_address, virtual_size, address, size) in &sections {
            if let Some(relative) = rva.checked_sub(virtual_address) {
                let relative_end = relative.checked_add(count)?;
                if relative_end <= virtual_size.max(size).min(size)
                    && address.checked_add(relative_end)? <= raw.len()
                {
                    return address.checked_add(relative);
                }
            }
        }
        None
    };
    let mut imports = Vec::new();
    let (count_offset, directory_offset) = if magic == 0x10b { (92, 96) } else { (108, 112) };
    if optional_size >= directory_offset + 16 && u32_at(raw, optional + count_offset)? >= 2 {
        let import_rva = u32_at(raw, optional + directory_offset + 8)? as usize;
        let import_size = u32_at(raw, optional + directory_offset + 12)? as usize;
        for index in 0..if import_rva == 0 {
            0
        } else {
            (import_size / 20).min(64)
        } {
            let Some(descriptor) = file_offset(import_rva + index * 20, 20) else {
                break;
            };
            if raw[descriptor..descriptor + 20].iter().all(|b| *b == 0) {
                break;
            }
            let Some(name) = file_offset(u32_at(raw, descriptor + 12)? as usize, 1) else {
                break;
            };
            let bytes = &raw[name..(name + 256).min(raw.len())];
            let Some(end) = bytes.iter().position(|b| *b == 0) else {
                break;
            };
            imports.push(ascii_replacement(&bytes[..end]));
        }
    }
    Some(
        serde_json::json!({"architecture": match machine {0x14c => "x86".to_owned(), 0x8664 => "x64".to_owned(), _ => format!("0x{machine:x}")},
        "entry_rva":u32_at(raw, optional + 16)?, "image_size":image_size, "import_dlls":imports, "sections":section_names}),
    )
}

fn python_optional_equal(a: Option<&Value>, b: Option<&Value>) -> bool {
    python_json_equal(a.unwrap_or(&Value::Null), b.unwrap_or(&Value::Null))
}

// Legacy JSON equality permits 1 == 1.0 == True in non-type-checked metadata
// comparisons. Integer validators above still strictly reject bool and floats.
fn python_json_equal(a: &Value, b: &Value) -> bool {
    fn integral(v: &Value) -> Option<i128> {
        match v {
            Value::Bool(b) => Some(u8::from(*b).into()),
            Value::Number(n) => n
                .as_i64()
                .map(i128::from)
                .or_else(|| n.as_u64().map(i128::from)),
            _ => None,
        }
    }
    fn integer_float(integer: i128, float: Option<f64>) -> bool {
        float.is_some_and(|f| {
            f.fract() == 0.0
                && f >= i64::MIN as f64
                && f < 18_446_744_073_709_551_616.0
                && f as i128 == integer
        })
    }
    match (a, b) {
        (Value::Array(a), Value::Array(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(a, b)| python_json_equal(a, b))
        }
        (Value::Object(a), Value::Object(b)) => {
            a.len() == b.len()
                && a.iter()
                    .all(|(key, a)| b.get(key).is_some_and(|b| python_json_equal(a, b)))
        }
        (Value::Bool(_) | Value::Number(_), Value::Bool(_) | Value::Number(_)) => {
            match (integral(a), integral(b)) {
                (Some(a), Some(b)) => a == b,
                (Some(a), None) => integer_float(a, b.as_f64()),
                (None, Some(b)) => integer_float(b, a.as_f64()),
                (None, None) => a.as_f64() == b.as_f64(),
            }
        }
        _ => a == b,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn summary() -> Value {
        json!({"id":"20261018T120000Z-deadbeef", "sample":{}, "status":"partial"})
    }

    #[test]
    fn completed_requires_observed_reason_and_no_failure_indicators() {
        let mut s = summary();
        s["status"] = json!("completed");
        assert!(valid_summary(&s));
        for reason in [
            "unknown",
            "instruction_limit",
            "timeout",
            "static_inspection",
            "cancelled",
        ] {
            s["completion_reason"] = json!(reason);
            assert!(!valid_summary(&s));
        }
        s["completion_reason"] = json!("entry_return");
        assert!(valid_summary(&s));
        for (key, value) in [
            ("errors", json!(["fault"])),
            ("timeout_reached", json!(true)),
            ("instruction_limit_reached", json!(true)),
        ] {
            let mut bad = s.clone();
            bad[key] = value;
            assert!(!valid_summary(&bad));
        }
        s["status"] = json!("partial");
        s["errors"] = json!(["fault"]);
        assert!(valid_summary(&s));
    }

    #[test]
    fn counters_preserve_long_runs_without_accepting_boolean_or_fractional_values() {
        let mut s = summary();
        s["instruction_count"] = json!(u64::MAX);
        assert!(valid_summary(&s));
        for value in [json!(true), json!(-1), json!(1.0), json!("1")] {
            s["instruction_count"] = value;
            assert!(!valid_summary(&s));
        }
        s["instruction_count"] = json!(1);
        s["denied_operations"] = json!(100_000_001);
        assert!(!valid_summary(&s));
    }

    #[test]
    fn report_bindings_detect_replacement_truncation_and_missing_required_hash() {
        let raw = b"{\"trace\":[]}";
        let mut s = summary();
        s["run_manifest"] = json!({"engine_report_integrity":ENGINE_INTEGRITY});
        assert!(!valid_summary(&s));
        assert!(verified_report(&s, BoundReport::Engine, raw).is_none());
        s["engine_report"] = json!("engine-report.json");
        s["engine_report_size"] = json!(raw.len());
        s["engine_report_sha256"] = json!(format!("{:x}", Sha256::digest(raw)));
        assert!(valid_summary(&s));
        assert_eq!(
            verified_report(&s, BoundReport::Engine, raw),
            Some(raw.as_slice())
        );
        assert!(verified_report(&s, BoundReport::Engine, &raw[..raw.len() - 1]).is_none());
        assert!(verified_report(&s, BoundReport::Engine, b"{\"trace\":{}}").is_none());
        s["status"] = json!("running");
        s.as_object_mut().unwrap().remove("engine_report_sha256");
        s.as_object_mut().unwrap().remove("engine_report_size");
        assert!(valid_summary(&s));
        assert!(verified_report(&s, BoundReport::Engine, raw).is_some());
    }

    #[test]
    fn artifact_metadata_rejects_paths_and_unbound_or_changed_bytes() {
        let raw = b"harmless data";
        let hash = format!("{:x}", Sha256::digest(raw));
        let item = json!({"file":format!("{}.bin", &hash[..20]), "sha256":hash, "size":raw.len(), "kind":"memory", "source":"memory", "guest_path":"../../guest-only"});
        assert_eq!(verified_artifact(&item, raw), Some(raw.as_slice()));
        for name in [
            "../payload.bin",
            "C:\\payload.bin",
            "aaaaaaaaaaaaaaaaaaaa.bin",
            "AAAAAAAAAAAAAAAAAAAA.bin",
            "aaaaaaaaaaaaaaaaaaaa.bin.extra",
        ] {
            let mut bad = item.clone();
            bad["file"] = json!(name);
            assert!(!valid_artifact_metadata(&bad));
        }
        let mut bad = item.clone();
        bad["size"] = json!(true);
        assert!(!valid_artifact_metadata(&bad));
        assert!(verified_artifact(&item, b"changed bytes").is_none());
        let manifest = serde_json::to_vec(&json!([item.clone()])).unwrap();
        assert!(manifest_matches(&manifest, &json!([item.clone()])));
        assert_eq!(checkpoint_observations(&manifest), Some(vec![item]));
        assert!(checkpoint_observations(br#"[{}]"#).is_none());
    }

    #[test]
    fn shallow_summary_groups_never_certify_fabricated_previews() {
        let mut s = summary();
        let hash = "a".repeat(64);
        s["artifacts"] = json!([{"sha256":hash,"file":"same.bin","size":1},{"sha256":hash,"file":"other.bin","size":2}]);
        s["artifact_groups"] = json!([{"sha256":hash,"file":"same.bin","size":1,"kind":"binary","preview_encoding":"text","preview":"fabricated display text","observations":[{},{}]}]);
        assert!(valid_summary(&s));
        s["artifact_groups"][0]["observations"] = json!([{}]);
        assert!(!valid_summary(&s));
        s["artifact_groups"][0]["observations"] = json!([{}, {}]);
        s["artifact_groups"][0]["size"] = json!(2);
        assert!(!valid_summary(&s));
    }

    #[test]
    fn memory_capture_requires_exact_fields_and_accounts_for_ascii_escaped_budget() {
        let item = json!({"format":"url","encoding":"managed","value":"https://fixture.invalid/😀","source":"fixture","offset":u64::MAX,"address":null});
        let mut c = json!({"enabled":true,"truncated":false,"scanned_bytes":0,"regex":[],"matches":[item.clone()],"limits":[]});
        assert!(valid_memory_capture(&c));
        c["matches"][0]["extra"] = json!(true);
        assert!(!valid_memory_capture(&c));
        c["matches"] = json!([item]);
        c["matches"][0]["format"] = json!("custom_1");
        assert!(!valid_memory_capture(&c));
        c["regex"] = json!(["fixture"]);
        assert!(valid_memory_capture(&c));
        c["matches"][0]["value"] = json!("😀".repeat(1024));
        let long = c["matches"][0].clone();
        c["matches"] = json!(vec![long; 1000]);
        assert!(!valid_memory_capture(&c));
        assert_eq!(ascii_string_len("é😀\n\u{7f}"), 28);
    }

    #[test]
    fn malformed_untrusted_enums_fail_without_panicking_and_parse_is_bounded() {
        for key in [
            "status",
            "execution_mode",
            "completion_reason",
            "artifact_integrity",
        ] {
            let mut s = summary();
            s[key] = json!([]);
            assert!(!valid_summary(&s));
        }
        assert!(parse_summary(&vec![b' '; MAX_SUMMARY_BYTES + 1]).is_err());
        assert!(
            parse_summary(br#"{"id":"20261018T120000Z-deadbeef","sample":{},"status":"partial"}"#)
                .is_ok()
        );
        assert!(!valid_run_id("20261018T120000Z-😀😀"));
    }

    #[test]
    fn checkpoint_groups_are_reconstructed_from_verified_bytes_and_preserve_provenance() {
        let raw = b"#!/fixture\n";
        let hash = format!("{:x}", Sha256::digest(raw));
        let item = serde_json::json!({"file":format!("{}.txt", &hash[..20]),"sha256":hash,"size":raw.len(),"kind":"script","source":"file_write_1","guest_path":"fixture.ps1"});
        let mut final_item = item.clone();
        final_item["source"] = serde_json::json!("virtual_file_final");
        let artifacts = serde_json::json!([item, final_item]);
        let manifest = serde_json::to_vec(&artifacts).unwrap();
        let (observations, groups) =
            verified_checkpoint(&manifest, |_| Some(raw.to_vec())).unwrap();
        assert_eq!(observations.len(), 2);
        assert_eq!(groups[0]["kind"], "script");
        assert_eq!(groups[0]["observations"][0]["stage"], "intermediate");
        assert_eq!(groups[0]["observations"][1]["stage"], "final");
        assert!(verified_artifact_manifest(
            &manifest,
            &artifacts,
            Some(&groups),
            |_| Some(raw.to_vec())
        ));
        let mut false_group = groups.clone();
        false_group[0]["preview"] = serde_json::json!("fabricated evidence");
        assert!(!verified_artifact_manifest(
            &manifest,
            &artifacts,
            Some(&false_group),
            |_| Some(raw.to_vec())
        ));
        assert!(verified_checkpoint(&manifest, |_| Some(b"modified".to_vec())).is_none());
        assert!(verified_checkpoint(&manifest, |_| None).is_none());
    }

    #[test]
    fn display_metadata_is_bounded_and_mapped_memory_retains_its_evidence_kind() {
        let mut raw = vec![0_u8; 512];
        raw[..2].copy_from_slice(b"MZ");
        raw[0x3c..0x40].copy_from_slice(&0x80_u32.to_le_bytes());
        raw[0x80..0x84].copy_from_slice(b"PE\0\0");
        raw[0x84..0x86].copy_from_slice(&0x8664_u16.to_le_bytes());
        raw[0x94..0x96].copy_from_slice(&0xf0_u16.to_le_bytes());
        raw[0x98..0x9a].copy_from_slice(&0x20b_u16.to_le_bytes());
        raw[0xd0..0xd4].copy_from_slice(&0x1000_u32.to_le_bytes());
        raw[0xd4..0xd8].copy_from_slice(&512_u32.to_le_bytes());
        assert_eq!(bounded_pe_metadata(&raw).unwrap()["architecture"], "x64");
        let hash = format!("{:x}", Sha256::digest(&raw));
        let item = serde_json::json!({"file":format!("{}.bin", &hash[..20]),"sha256":hash,"size":raw.len(),"kind":"memory","source":"memory","guest_path":"","context":{"layout":"mapped_image"}});
        let manifest = serde_json::to_vec(&serde_json::json!([item])).unwrap();
        let (_, groups) = verified_checkpoint(&manifest, |_| Some(raw.clone())).unwrap();
        assert_eq!(groups[0]["kind"], "memory");
        assert!(groups[0].get("pe_metadata").is_none());
        raw[0x85] = 0xff;
        raw[0x86..0x88].copy_from_slice(&97_u16.to_le_bytes());
        assert!(bounded_pe_metadata(&raw).is_none());
        assert!(bounded_pe_metadata(b"MZ truncated").is_none());
    }
}
