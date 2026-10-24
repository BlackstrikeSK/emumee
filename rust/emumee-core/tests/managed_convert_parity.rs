use emumee_core::managed_convert;
use sha2::{Digest, Sha256};
#[test]
fn generated_legacy_convert_corpus_is_bound_and_decodes_identically() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/managed_convert_reference.json");
    let raw = std::fs::read(path).unwrap();
    assert_eq!(raw.len(), 884566);
    assert_eq!(
        format!("{:x}", Sha256::digest(&raw)),
        "caa98839026465d98cb84b51a6e5f152fe5c545873f3c3e6558516666911694f"
    );
    let corpus: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    let cases = corpus["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 3583);
    let mut accepted = 0;
    for (index, row) in cases.iter().enumerate() {
        let units: Vec<u16> = row["utf16"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| u16::try_from(n.as_u64().unwrap()).unwrap())
            .collect();
        let result = managed_convert::decode(&units, 32 * 1024 * 1024);
        if let Some(expected) = row["decoded_hex"].as_str() {
            let result =
                result.unwrap_or_else(|e| panic!("case {index} {}: {e}", row["description"]));
            let actual = result
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>();
            assert_eq!(actual, expected, "case {index}: {}", row["description"]);
            assert_eq!(
                managed_convert::decoded_length(&units, result.len()).unwrap(),
                result.len()
            );
            accepted += 1;
        } else {
            assert!(result.is_err(), "case {index}: {}", row["description"]);
        }
    }
    assert_eq!(accepted, 883);
}
