use super::*;
use crate::{
    indicator_fixture::Case,
    memory_strings::Capture,
    pe::{Architecture, PeImage},
};
use serde_json::json;
fn generated_metadata() -> Value {
    // This is static synthetic validator input, not execution evidence.
    let case = Case::NativeNone;
    let input = case.input(Architecture::X64);
    let pe = PeImage::parse(&input, "closed.pe").unwrap();
    let mut root = pe.materialize(&input, pe.image_base).unwrap();
    let initial = report_bundle::digest(&root);
    for (rva, payload) in case.patches() {
        root[rva..rva + payload.len()].copy_from_slice(&payload);
    }
    let mut capture = Capture::default();
    capture
        .scan_memory(&root, indicator_fixture::SOURCE, pe.image_base)
        .unwrap();
    let capture = serde_json::to_value(capture.into_report()).unwrap();
    let receipt = Receipt {
        version: VERSION.into(),
        case,
        source: indicator_fixture::SOURCE.into(),
        coverage: Coverage::CompleteSelectedRoot,
        all_guest_memory_complete: false,
        enabled: true,
        input_sha256: report_bundle::digest(&input),
        initial_image_sha256: initial,
        settled_image_sha256: Some(report_bundle::digest(&root)),
        initial_patches_absent: true,
        runtime_patches_verified: true,
        capture_sha256: capture_hash(&capture).unwrap(),
        image_base: pe.image_base,
        image_bytes: root.len() as u64,
        read_limit: case.read_limit(),
        scan_limit: case.scan_limit() as u64,
        read_reserved_bytes: root.len() as u64,
        read_bytes: root.len() as u64,
        selected_bytes: root.len() as u64,
        boundary_instructions: 7,
        boundary_pc: 0x1234,
        retained_snapshot: false,
        omissions: vec![],
    };
    json!({"architecture":"x64","completion_reason":"entry_return","instruction_count":7,
        "guest_entry_return":17,"error":null,"final_pc":0x1234,"image_load":{"base":pe.image_base,"size":root.len()},
        "memory_strings":capture,"memory_string_sources":receipt,"artifacts":[]})
}
#[test]
fn optional_capture_and_receipt_are_an_exact_pair_with_canonical_hash_and_scope() {
    let execution = generated_metadata();
    assert!(valid_execution(&execution));
    let summary = json!({"run_manifest":{"memory_string_profile":VERSION,"case":"native-indicators-none"},"memory_strings":execution["memory_strings"],"memory_string_sources":execution["memory_string_sources"]});
    assert!(summary_matches(&summary, &execution));
    for field in ["memory_strings", "memory_string_sources"] {
        let mut changed = execution.clone();
        changed.as_object_mut().unwrap().remove(field);
        assert!(!valid_execution(&changed));
        let mut changed = summary.clone();
        changed.as_object_mut().unwrap().remove(field);
        assert!(!summary_matches(&changed, &execution));
    }
    let mut changed = execution.clone();
    changed["memory_strings"]["matches"][0]["value"] = json!("203.0.113.1");
    assert!(!valid_execution(&changed));
    assert!(valid_execution(&json!({"artifacts":[]})));
}
#[test]
fn report_generation_projects_only_valid_actual_extension_and_rejects_later_disagreement() {
    let execution = generated_metadata();
    let captures = crate::artifacts::ArtifactCatalog::default();
    let sample = json!({"name":"owned.exe"});
    let manifest = json!({"memory_string_profile":VERSION,"case":"native-indicators-none"});
    let network = json!({"events":[]});
    let bundle = report_bundle::build(report_bundle::Input {
        run_id: "20261019T120000Z-12345678",
        started_at: "2026-10-19T12:00:00Z",
        finished_at: "2026-10-19T12:00:01Z",
        sample: &sample,
        execution: &execution,
        execution_mode: "user",
        manifest: &manifest,
        network: &network,
        network_coverage: report_bundle::NetworkCoverage::NotMonitored,
        termination: report_bundle::Termination::Normal,
        checkpoint_recovered: false,
        profile: report_bundle::Profile::LegacyV1,
        artifacts: &captures.items,
        omissions: &captures.summary,
    })
    .unwrap();
    let mut summary: Value = serde_json::from_slice(&bundle.summary).unwrap();
    assert_eq!(summary["memory_strings"], execution["memory_strings"]);
    assert!(
        reports::verified_report(&summary, reports::BoundReport::Engine, &bundle.engine).is_some()
    );
    assert!(summary_matches(&summary, &execution));
    summary["memory_string_sources"]["all_guest_memory_complete"] = json!(true);
    assert!(!summary_matches(&summary, &execution));
}

#[test]
fn legacy_capture_is_not_reclassified_as_a_new_typed_role() {
    let legacy = json!({"memory_strings":{"enabled":true,"regex":[],"matches":[],"scanned_bytes":0,"truncated":false,"limits":[]}});
    assert!(!requires_typed_binding(&legacy, &json!({})));
    let typed = json!({"run_manifest":{"case":"native-indicators-none"}});
    assert!(requires_typed_binding(&typed, &Value::Null));
    assert!(requires_typed_binding(
        &json!({}),
        &json!({"run_manifest":{"memory_string_profile":VERSION}})
    ));
}
