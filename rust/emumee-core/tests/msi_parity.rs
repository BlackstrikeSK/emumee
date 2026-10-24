//! Synthetic CFB stream bytes cross-checked against the legacy olefile parser.
use base64::{Engine as _, engine::general_purpose::STANDARD};
use emumee_core::msi::{StreamType, inspect};
use serde_json::Value;
use sha2::{Digest, Sha256};

#[test]
fn generated_compound_files_match_legacy_stream_paths_lengths_and_hashes() {
    use std::io::Read;
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/msi_reference.json");
    let file = std::fs::File::open(path).expect("generated CFB reference corpus");
    let mut raw = Vec::new();
    file.take(256 * 1024 + 1).read_to_end(&mut raw).unwrap();
    assert!(raw.len() <= 256 * 1024);
    assert_eq!(
        format!("{:x}", Sha256::digest(&raw)),
        "dc0433a90bd660485401f22254788e0dbd0c6d1e555f88dc91776da766d05344"
    );
    let corpus: Value = serde_json::from_slice(&raw).unwrap();
    let rows = corpus["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 5);
    for row in rows {
        let bytes = STANDARD
            .decode(row["raw_base64"].as_str().unwrap())
            .unwrap();
        assert_eq!(format!("{:x}", Sha256::digest(&bytes)), row["sha256"]);
        let fixture_case =
            emumee_core::msi_fixture::Case::parse(row["name"].as_str().unwrap()).unwrap();
        assert_eq!(
            emumee_core::msi_fixture::input(fixture_case),
            bytes,
            "closed fixture matches pinned legacy bytes"
        );
        let parsed = inspect(&bytes).unwrap_or_else(|error| panic!("{}: {error}", row["name"]));
        let expected = row["streams"].as_array().unwrap();
        assert_eq!(parsed.stream_count, expected.len(), "{}", row["name"]);
        assert_eq!(u64::from(parsed.version), row["version"].as_u64().unwrap());
        assert_eq!(
            parsed.sector_size as u64,
            row["sector_size"].as_u64().unwrap()
        );
        assert_eq!(
            parsed.stream_bytes_read,
            row["stream_bytes_read"].as_u64().unwrap()
        );
        assert!(parsed.omissions.is_empty());
        for (actual, expected) in parsed.streams.iter().zip(expected) {
            assert_eq!(
                serde_json::to_value(&actual.path).unwrap(),
                expected["path"]
            );
            assert_eq!(actual.name, expected["name"].as_str().unwrap());
            assert_eq!(
                actual.data,
                STANDARD
                    .decode(expected["data_base64"].as_str().unwrap())
                    .unwrap()
            );
            assert_eq!(actual.size, expected["size"].as_u64().unwrap());
            assert_eq!(actual.data.len() as u64, actual.size);
            assert_eq!(actual.sha256, expected["sha256"].as_str().unwrap());
            assert_eq!(format!("{:x}", Sha256::digest(&actual.data)), actual.sha256);
            assert_eq!(
                actual.kind == StreamType::Cabinet,
                expected["cabinet"].as_bool().unwrap()
            );
        }
    }
}
