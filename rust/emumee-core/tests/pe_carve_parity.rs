//! Synthetic buffers compared byte-for-byte with legacy artifact carving.
use base64::{Engine as _, engine::general_purpose::STANDARD};
use emumee_core::pe_carve::scan;
use serde_json::Value;
use sha2::{Digest, Sha256};

#[test]
fn raw_and_mapped_pe_captures_match_generated_legacy_bytes_and_provenance() {
    use std::io::Read;
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/pe_carve_reference.json");
    let mut raw = Vec::new();
    std::fs::File::open(path)
        .expect("owned carving corpus")
        .take(512 * 1024 + 1)
        .read_to_end(&mut raw)
        .unwrap();
    assert!(raw.len() <= 512 * 1024);
    assert_eq!(
        format!("{:x}", Sha256::digest(&raw)),
        "33036eb3e0f429545491b293a69f36aec3f46248845d18d429683dafd973cbcd"
    );
    let corpus: Value = serde_json::from_slice(&raw).unwrap();
    let rows = corpus["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 32);
    let mut observations = 0;
    for row in rows {
        let blob = STANDARD
            .decode(row["blob_base64"].as_str().unwrap())
            .unwrap();
        assert_eq!(format!("{:x}", Sha256::digest(&blob)), row["sha256"]);
        let actual = scan(
            &blob,
            row["source"].as_str().unwrap(),
            row["skip_offset_zero"].as_bool().unwrap(),
            row["context"].as_object(),
        )
        .unwrap();
        assert!(actual.scan_complete, "{}", row["name"]);
        let expected = row["observations"].as_array().unwrap();
        assert_eq!(actual.observations.len(), expected.len(), "{}", row["name"]);
        assert_eq!(
            serde_json::to_value(&actual.artifact_capture).unwrap(),
            row["artifact_capture"]
        );
        for (actual_item, expected) in actual.observations.iter().zip(expected) {
            let data = STANDARD
                .decode(expected["data_base64"].as_str().unwrap())
                .unwrap();
            assert_eq!(
                actual.payloads[actual_item.payload].data, data,
                "{}",
                row["name"]
            );
            let mut expected_record = expected.clone();
            expected_record
                .as_object_mut()
                .unwrap()
                .remove("data_base64");
            assert_eq!(
                serde_json::to_value(actual_item).unwrap(),
                expected_record,
                "{}",
                row["name"]
            );
        }
        observations += expected.len();
    }
    assert_eq!(observations, 30);
}
