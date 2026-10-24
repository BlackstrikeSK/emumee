//! Small source controls. Near-limit allocation tests belong to sequential workers.
use emumee_core::{
    artifact_bridge::{Origin, capture_scan_owned},
    artifacts::{ArtifactCatalog, ArtifactKind, Observation},
    capture_profile::CaptureProfile,
    driver_capture_fixture::Case,
    driver_capture_reports::{self as reports, Binding, Mode, Stop, VerifiedProjection},
    pe_carve::scan_owned_with_profile,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
#[test]
fn independent_recipe_reference_pins_small_bytes_and_large_shapes_without_large_source_allocations()
{
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/driver_capture_reference.json");
    let raw = std::fs::read(path).unwrap();
    assert_eq!(
        format!("{:x}", Sha256::digest(&raw)),
        "d887b337285924203e17d426993726e52d891ac41aa17a1739196750d674a66e"
    );
    let value: Value = serde_json::from_slice(&raw).unwrap();
    let rows = value["cases"].as_array().unwrap();
    assert_eq!(rows.len(), 12);
    for row in rows {
        let case = Case::parse(row["case"].as_str().unwrap()).unwrap();
        assert_eq!(case.input_len() as u64, row["input_size"].as_u64().unwrap());
        if case.input_len() <= 8192 {
            assert_eq!(
                format!("{:x}", Sha256::digest(case.small_bytes().unwrap())),
                row["input_sha256"].as_str().unwrap()
            );
        }
    }
}
fn binding() -> Binding {
    Binding {
        request_sha256: "1".repeat(64),
        input_sha256: "2".repeat(64),
        input_bytes: 8192,
        recipe: "tiny-mapped".into(),
        source_tree_sha256: "3".repeat(64),
        containment_sha256: "4".repeat(64),
    }
}
fn execution() -> Value {
    json!({"instruction_count":0,"completion_reason":"static_inspection","guest_entry_return":null,"error":null})
}
fn mapped() -> Vec<u8> {
    let mut image = Case::SmallRaw.small_bytes().unwrap();
    // Owned synthetic one-section layout: 512 raw bytes at512, mapped at4096.
    image[392 + 8..392 + 12].copy_from_slice(&512u32.to_le_bytes());
    image[392 + 16..392 + 20].copy_from_slice(&512u32.to_le_bytes());
    image[392 + 20..392 + 24].copy_from_slice(&512u32.to_le_bytes());
    image[512..].fill(0);
    image[4096..4608].fill(0x52);
    image
}
fn catalog(image: Vec<u8>) -> ArtifactCatalog {
    let scan =
        scan_owned_with_profile(image, "owned", false, None, CaptureProfile::Driver128V1).unwrap();
    let mut catalog = ArtifactCatalog::with_profile(CaptureProfile::Driver128V1);
    capture_scan_owned(&mut catalog, scan, Origin::Memory).unwrap();
    catalog
}
#[test]
fn mapped_bytes_move_with_distinct_snapshot_and_total_range_verified_reconstruction() {
    let image = mapped();
    let catalog = catalog(image.clone());
    assert_eq!(catalog.items.len(), 2);
    let snapshot = catalog
        .items
        .iter()
        .find(|p| p.observations[0].kind == ArtifactKind::MemorySnapshot)
        .unwrap();
    let carved = catalog
        .items
        .iter()
        .find(|p| p.observations[0].kind == ArtifactKind::CarvedImage)
        .unwrap();
    assert_eq!(snapshot.data, image);
    assert_eq!(carved.data.len(), 1024);
    assert_eq!(&carved.data[512..], &[0x52; 512]);
    assert_eq!(
        snapshot.observations[0].context.as_ref().unwrap()["reconstruction"],
        "none"
    );
    assert_eq!(
        carved.observations[0].context.as_ref().unwrap()["source_layout"],
        "mapped_image"
    );
    let binding = binding();
    let bundle = reports::build(
        "20261018T120000Z-12345678",
        &binding,
        Mode::StaticGeneratedCapture,
        &execution(),
        Stop::Normal,
        false,
        &catalog,
    )
    .unwrap();
    let good = reports::verify(
        &bundle.summary,
        &bundle.engine,
        &bundle.network,
        &bundle.manifest,
        &bundle.checkpoint,
        &binding,
        |record| {
            let raw = catalog
                .items
                .iter()
                .find(|p| p.sha256 == record.sha256)
                .unwrap();
            VerifiedProjection::for_record(record, |offset, count| {
                Some(raw.data[offset as usize..offset as usize + count].to_vec())
            })
        },
    )
    .unwrap();
    assert_eq!(good.summary.status, "partial");
    // Rehashing modified source or output bytes cannot preserve verified range evidence.
    assert!(
        reports::verify(
            &bundle.summary,
            &bundle.engine,
            &bundle.network,
            &bundle.manifest,
            &bundle.checkpoint,
            &binding,
            |record| {
                let raw = catalog
                    .items
                    .iter()
                    .find(|p| p.sha256 == record.sha256)
                    .unwrap();
                let mut bytes = raw.data.clone();
                bytes[512] ^= 1;
                VerifiedProjection::for_record(record, |offset, count| {
                    Some(bytes[offset as usize..offset as usize + count].to_vec())
                })
            }
        )
        .is_err()
    );
}
#[test]
fn coordinated_metadata_hashes_do_not_make_a_wrong_reconstruction_valid() {
    let mut catalog = catalog(mapped());
    // Change actual carved payload and every ordinary identity to match; the
    // snapshot-to-output range proof still rejects this fabricated reconstruction.
    let carved = catalog
        .items
        .iter_mut()
        .find(|p| p.observations[0].kind == ArtifactKind::CarvedImage)
        .unwrap();
    carved.data[512] ^= 1;
    carved.sha256 = emumee_core::report_bundle::digest(&carved.data);
    carved.filename = format!("{}.bin", carved.sha256);
    assert!(
        reports::build(
            "20261018T120000Z-12345678",
            &binding(),
            Mode::StaticGeneratedCapture,
            &execution(),
            Stop::Normal,
            false,
            &catalog
        )
        .is_err()
    );
}
#[test]
fn owned_catalog_rejects_bad_batch_atomically_and_deduplicates_without_claiming_execution() {
    let mut catalog = ArtifactCatalog::with_profile(CaptureProfile::Driver128V1);
    let observation = |source: &str| Observation {
        kind: ArtifactKind::MemorySnapshot,
        source: source.into(),
        guest_path: String::new(),
        context: None,
    };
    assert!(!catalog.add_owned_observations(vec![1, 2, 3], vec![observation(&"x".repeat(257))]));
    assert!(catalog.items.is_empty());
    assert!(catalog.add_owned_observations(
        vec![1, 2, 3],
        vec![observation("first"), observation("alias")]
    ));
    assert!(catalog.add_owned_observations(vec![1, 2, 3], vec![observation("second")]));
    assert_eq!(catalog.items.len(), 1);
    assert_eq!(catalog.items[0].observations.len(), 3);
    assert!(catalog.summary.omitted_observations > 0);
}
#[test]
fn contradictory_completion_and_unknown_profiles_never_upgrade_static_evidence() {
    let catalog = ArtifactCatalog::with_profile(CaptureProfile::Driver128V1);
    for execution in [
        json!({"instruction_count":4,"completion_reason":"entry_return","guest_entry_return":null,"error":null}),
        json!({"instruction_count":4,"completion_reason":"entry_return","guest_entry_return":17,"error":"stopped"}),
    ] {
        let value = reports::build(
            "20261018T120000Z-12345678",
            &binding(),
            Mode::GeneratedDriverEntry,
            &execution,
            Stop::Normal,
            false,
            &catalog,
        )
        .unwrap();
        assert_ne!(
            reports::Summary::parse(&value.summary)
                .unwrap()
                .summary
                .status,
            "completed"
        );
    }
    let bundle = reports::build(
        "20261018T120000Z-12345678",
        &binding(),
        Mode::StaticGeneratedCapture,
        &execution(),
        Stop::Normal,
        false,
        &catalog,
    )
    .unwrap();
    let mut summary: Value = serde_json::from_slice(&bundle.summary).unwrap();
    summary["profile"] = json!("legacy32_v1");
    assert!(reports::Summary::parse(&serde_json::to_vec(&summary).unwrap()).is_err());
}
