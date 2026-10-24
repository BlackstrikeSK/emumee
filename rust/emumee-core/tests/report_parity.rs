//! Differential envelope cases generated solely from harmless synthetic JSON.
use emumee_core::reports::valid_summary;
use serde_json::Value;
use sha2::{Digest, Sha256};

#[test]
fn legacy_generated_summary_envelopes_keep_their_acceptance_contract() {
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/report_parity.json");
    let file = std::fs::File::open(&path).expect("generated parity corpus exists");
    use std::io::Read;
    let mut raw = Vec::new();
    file.take(5 * 1024 * 1024 + 1)
        .read_to_end(&mut raw)
        .expect("read generated parity corpus");
    assert!(raw.len() <= 5 * 1024 * 1024, "parity fixture byte bound");
    assert_eq!(
        format!("{:x}", Sha256::digest(&raw)),
        "726dd0e8b18d7c0c4fdfcc0d2bb2702700cb815a8687779a39504956b5c78b74",
        "generated parity fixture identity changed"
    );
    let corpus: Value = serde_json::from_slice(&raw).expect("valid synthetic fixture JSON");
    let rows = corpus["rows"].as_array().expect("corpus rows");
    assert_eq!(rows.len(), 543);
    assert_eq!(rows.iter().filter(|r| r["valid"] == true).count(), 127);
    assert_eq!(
        rows.iter()
            .filter(|r| r.get("legacy_exception").is_some())
            .count(),
        7
    );
    for (index, row) in rows.iter().enumerate() {
        let expected = row["valid"].as_bool().expect("legacy acceptance bool");
        assert_eq!(
            valid_summary(&row["value"]),
            expected,
            "legacy case {index}: {} (legacy exception: {})",
            row["name"],
            row.get("legacy_exception").unwrap_or(&Value::Null)
        );
    }
}
