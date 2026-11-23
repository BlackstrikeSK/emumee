use super::*;
use crate::memory_strings::{Capture, Options};
use serde_json::json;

/// Scan a blob with the given patterns and build a matching execution Value.
fn execution(patterns: &[&str], blob: &[u8], base: u64, scan_limit: u64) -> Value {
    let options = Options::decode(Some(&json!({
        "enabled": true,
        "regex": patterns,
    })))
    .unwrap();
    let mut capture = Capture::new(options);
    capture.scan_memory(blob, "guest_image_at_stop", base).unwrap();
    let scanned = capture.report().scanned_bytes();
    let capture_value = serde_json::to_value(capture.report()).unwrap();
    let capture_sha256 = memory_capture_hash(&capture_value).unwrap();
    let receipt = Receipt {
        version: VERSION.into(),
        source: "guest_image_at_stop".into(),
        coverage: if scanned > 0 {
            Coverage::CompleteSelectedRoot
        } else {
            Coverage::Omitted
        },
        enabled: true,
        patterns: patterns.iter().map(|p| p.to_string()).collect(),
        input_sha256: "a".repeat(64),
        image_base: base,
        image_bytes: blob.len() as u64,
        scan_limit,
        read_limit: blob.len() as u64,
        read_reserved_bytes: blob.len() as u64,
        read_bytes: blob.len() as u64,
        selected_bytes: scanned,
        capture_sha256,
        boundary_instructions: 42,
        boundary_pc: base + 0x100,
        omissions: vec![],
    };
    json!({
        "instruction_count": 42,
        "final_pc": base + 0x100,
        "image_load": {"base": base, "size": blob.len() as u64},
        "user_memory_strings": capture_value,
        "user_memory_capture": serde_json::to_value(&receipt).unwrap(),
    })
}

#[test]
fn absent_user_profile_validates_and_is_not_present() {
    let empty = json!({"instruction_count": 0, "final_pc": 0});
    assert!(valid_execution(&empty));
    assert!(!present(&empty));
}

#[test]
fn user_profile_with_custom_matches_is_valid_and_binds_in_summary() {
    let value = execution(
        &["[a-f0-9]{8}", "cat|dog"],
        b"xx deadbeef a cat here",
        0x400000,
        128 * 1024 * 1024,
    );
    assert!(valid_execution(&value), "{value:#}");
    assert!(present(&value));
    // Custom matches are present and labelled per the envelope.
    let formats: Vec<&str> = value["user_memory_strings"]["matches"]
        .as_array()
        .unwrap()
        .iter()
        .map(|m| m["format"].as_str().unwrap())
        .collect();
    assert!(formats.contains(&"custom_1"));
    assert!(formats.contains(&"custom_2"));
    // Summary binding.
    let mut summary = json!({});
    for field in ["user_memory_strings", "user_memory_capture"] {
        summary[field] = value[field].clone();
    }
    assert!(summary_matches(&summary, &value));
    let mut wrong = summary.clone();
    wrong["user_memory_strings"]["matches"][0]["value"] = json!("tampered");
    assert!(!summary_matches(&wrong, &value));
}

#[test]
fn tampering_with_bound_fields_is_rejected() {
    let base = execution(&["cat"], b"a cat sat", 0x10000, 64 * 1024 * 1024);
    // capture digest no longer matches
    let mut forged = base.clone();
    forged["user_memory_strings"]["matches"][0]["value"] = json!("dog");
    assert!(!valid_execution(&forged));
    // patterns disagree with regex array
    let mut forged = base.clone();
    forged["user_memory_capture"]["patterns"] = json!(["dog"]);
    assert!(!valid_execution(&forged));
    // scanned_bytes disagreement
    let mut forged = base.clone();
    forged["user_memory_capture"]["selected_bytes"] = json!(0);
    assert!(!valid_execution(&forged));
    // image size disagreement
    let mut forged = base.clone();
    forged["image_load"]["size"] = json!(1);
    assert!(!valid_execution(&forged));
    // over-budget selection
    let mut forged = base.clone();
    forged["user_memory_capture"]["selected_bytes"] = json!(u64::MAX);
    assert!(!valid_execution(&forged));
    // boundary mismatch
    let mut forged = base.clone();
    forged["instruction_count"] = json!(9);
    assert!(!valid_execution(&forged));
    // unknown receipt field (deny_unknown_fields)
    let mut forged = base;
    forged["user_memory_capture"]["sneaky"] = json!(true);
    assert!(!valid_execution(&forged));
}

#[test]
fn one_field_without_the_other_is_rejected() {
    let value = execution(&["cat"], b"a cat", 0x10000, 64 * 1024 * 1024);
    let mut only_capture = value.clone();
    only_capture.as_object_mut().unwrap().remove("user_memory_strings");
    assert!(!valid_execution(&only_capture));
    let mut only_sources = value;
    only_sources.as_object_mut().unwrap().remove("user_memory_capture");
    assert!(!valid_execution(&only_sources));
}
