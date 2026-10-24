use emumee_core::{
    artifact_bridge::{Origin, capture_owned_budgeted},
    artifacts::{ArtifactCatalog, ArtifactKind, CaptureSummary},
    capture_profile::CaptureProfile,
    driver_runtime_fixture::Case,
};
#[test]
fn small_recipe_bytes_match_the_pinned_independent_runtime_reference() {
    use sha2::{Digest, Sha256};
    let raw = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/data/driver_runtime_reference.json"),
    )
    .unwrap();
    assert_eq!(
        format!("{:x}", Sha256::digest(&raw)),
        "d6bf26fa2a07224fb0470571c305abbf628c8d5c3bd87dc3b864598efb369141"
    );
    let value: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    let cases = value["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 9);
    for (case, name) in [
        (Case::Tiny, "runtime-tiny"),
        (Case::Image64, "runtime64"),
        (Case::Image128, "runtime128"),
        (Case::Gap, "runtime-gap"),
        (Case::ReadBudget, "runtime-read-budget"),
        (Case::ScanBudget, "runtime-scan-budget"),
        (Case::WorkBudget, "runtime-work-budget"),
        (Case::RetentionBudget, "runtime-retention-budget"),
    ] {
        let row = cases.iter().find(|r| r["case"] == name).unwrap();
        assert_eq!(
            format!("{:x}", Sha256::digest(case.bytes())),
            row["input_sha256"].as_str().unwrap()
        );
        assert_eq!(case.input_bytes(), 1536);
        assert_eq!(
            case.image_bytes() as u64,
            row["image_bytes"].as_u64().unwrap()
        );
    }
    assert_eq!(Case::Raw64Image128.input_bytes(), 64 * 1024 * 1024);
}
#[test]
fn scanner_budget_is_one_catalog_total_across_registry_container_and_memory() {
    let mut catalog = ArtifactCatalog::with_profile(CaptureProfile::Driver128V1);
    assert!(catalog.set_carving_limits(32, 1024));
    capture_owned_budgeted(
        &mut catalog,
        vec![0; 16],
        "registry",
        None,
        Origin::RegistryValue,
        false,
    )
    .unwrap();
    capture_owned_budgeted(
        &mut catalog,
        vec![0; 16],
        "container",
        None,
        Origin::ContainerStream,
        false,
    )
    .unwrap();
    assert_eq!(catalog.carving_totals(), (32, 0));
    let stats = capture_owned_budgeted(
        &mut catalog,
        vec![0x52; 8],
        "memory",
        None,
        Origin::Memory,
        true,
    )
    .unwrap();
    assert!(!stats.scan_complete);
    assert_eq!(catalog.carving_totals(), (32, 0));
    assert_eq!(catalog.items.len(), 1);
    assert_eq!(catalog.items[0].data, vec![0x52; 8]);
    assert_eq!(
        catalog.items[0].observations[0].kind,
        ArtifactKind::MemorySnapshot
    );
    assert_eq!(catalog.summary.reasons["aggregate_scan_limit"], 1);
}
#[test]
fn work_exhaustion_retains_a_complete_snapshot_without_fabricating_a_carve() {
    let mut catalog = ArtifactCatalog::with_profile(CaptureProfile::Driver128V1);
    assert!(catalog.set_carving_limits(8192, 0));
    let bytes = Case::Tiny.bytes();
    let expected = bytes.clone();
    let stats =
        capture_owned_budgeted(&mut catalog, bytes, "owned", None, Origin::Memory, true).unwrap();
    assert!(!stats.scan_complete);
    assert_eq!(catalog.carving_totals(), (1536, 0));
    assert_eq!(catalog.items.len(), 1);
    assert_eq!(catalog.items[0].data, expected);
    assert_eq!(
        catalog.items[0].observations[0].kind,
        ArtifactKind::MemorySnapshot
    );
    assert_eq!(catalog.summary.reasons["carving_work_byte_limit"], 1);
}
#[test]
fn owned_engine_catalog_handoff_moves_bytes_and_refuses_identity_metadata_budget_lies() {
    let mut original = ArtifactCatalog::with_profile(CaptureProfile::Driver128V1);
    original.add(vec![1, 2, 3], ArtifactKind::MemorySnapshot, "owned", "");
    let allocation = original.items[0].data.as_ptr();
    let handed = ArtifactCatalog::from_owned_parts(
        CaptureProfile::Driver128V1,
        original.items,
        original.summary,
        256 * 1024 * 1024,
    )
    .unwrap();
    assert_eq!(handed.items[0].data.as_ptr(), allocation);
    let mut items = handed.items;
    items[0].sha256 = "0".repeat(64);
    assert!(
        ArtifactCatalog::from_owned_parts(
            CaptureProfile::Driver128V1,
            items,
            CaptureSummary::default(),
            256 * 1024 * 1024
        )
        .is_err()
    );
}
