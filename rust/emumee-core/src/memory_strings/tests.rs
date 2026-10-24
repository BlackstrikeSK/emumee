use super::*;
use serde_json::json;

fn bytes(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0);
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
#[test]
fn pinned_actual_legacy_reports_match_default_scanner_and_utf16_heap_view() {
    let raw = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/data/memory_strings_default_reference.json"),
    )
    .unwrap();
    assert_eq!(
        crate::report_bundle::digest(&raw),
        "0fa60a4b4666b35ed09801075949e7e5cabdf9b18aa207c39e3ad917a8344437"
    );
    let reference: Value = serde_json::from_slice(&raw).unwrap();
    assert_eq!(reference["cases"].as_array().unwrap().len(), 46);
    for row in reference["cases"].as_array().unwrap() {
        for utf16 in [false, true] {
            let options = Options::decode(row.get("options").filter(|v| !v.is_null())).unwrap();
            let mut capture = Capture::new(options);
            for (name, value) in row["constant_overrides"].as_object().unwrap() {
                let n = value.as_u64().unwrap();
                match name.as_str() {
                    "MAX_MEMORY_SCAN" => capture.limits.scan = n,
                    "MAX_MATCHES" => capture.limits.matches = n as usize,
                    "MAX_CAPTURE_BYTES" => capture.limits.bytes = n as usize,
                    other => panic!("Unreviewed oracle override: {other}"),
                }
            }
            for operation in row["operations"].as_array().unwrap() {
                let source = operation["source"].as_str().unwrap();
                match operation["kind"].as_str().unwrap() {
                    "memory" => capture
                        .scan_memory(
                            &bytes(operation["hex"].as_str().unwrap()),
                            source,
                            operation["base"].as_u64().unwrap(),
                        )
                        .unwrap(),
                    "managed" => {
                        let text = operation["text"].as_str().unwrap();
                        if utf16 {
                            capture
                                .scan_managed_utf16(
                                    &text.encode_utf16().collect::<Vec<_>>(),
                                    source,
                                )
                                .unwrap();
                        } else {
                            capture.scan_string(text, source).unwrap();
                        }
                    }
                    other => panic!("Unreviewed oracle source: {other}"),
                }
            }
            let actual = serde_json::to_value(capture.report()).unwrap();
            assert_eq!(actual, row["expected"], "{} / UTF16={utf16}", row["name"]);
            assert!(
                crate::reports::valid_memory_capture(&actual),
                "{}",
                row["name"]
            );
        }
    }
}
#[test]
fn options_never_silently_ignore_custom_grammar_or_bad_types() {
    for value in [
        json!({"regex":["(?<=prefix\\s+)TOKEN"]}),
        json!({"regex":["(?P<r>a(?&r)?b)"]}),
        json!({"enabled":false,"regex":["TOKEN"]}),
    ] {
        assert_eq!(
            Options::decode(Some(&value)).unwrap_err(),
            Error::UnsupportedLegacyRegex
        );
    }
    for value in [
        json!({"regex":[""]}),
        json!({"regex":vec!["x";17]}),
        json!({"regex":"TOKEN"}),
        json!({"enabled":1}),
        json!({"ignored":true}),
    ] {
        assert_eq!(
            Options::decode(Some(&value)).unwrap_err(),
            Error::InvalidOptions
        );
    }
    assert!(Options::decode(None).is_ok());
    assert!(Options::decode(Some(&Value::Null)).is_ok());
    assert!(Options::decode(Some(&json!({"regex":[],"enabled":false}))).is_ok());
}
#[test]
fn lone_surrogate_is_an_explicit_atomic_pending_capture_not_lossy_guest_text() {
    let mut capture = Capture::default();
    capture
        .scan_string("http://retained.test/", "managed_return:Good")
        .unwrap();
    let before = serde_json::to_value(capture.report()).unwrap();
    let mut units = "http://example.test/".encode_utf16().collect::<Vec<_>>();
    units.push(0xd800);
    units.extend(" 192.0.2.1".encode_utf16());
    assert_eq!(
        capture
            .scan_managed_utf16(&units, "managed_return:Pending")
            .unwrap_err(),
        Error::UnpairedSurrogatePending
    );
    let after = serde_json::to_value(capture.report()).unwrap();
    assert_eq!(after["matches"], before["matches"]);
    assert_eq!(after["scanned_bytes"], before["scanned_bytes"]);
    assert_eq!(after["limits"], json!(["unpaired_surrogate_pending"]));
    assert_eq!(after["truncated"], true);
    assert!(crate::reports::valid_memory_capture(&after));
    assert_eq!(units[20], 0xd800);
}
#[test]
fn source_and_address_bounds_are_explicit_without_false_scanned_bytes() {
    let mut capture = Capture::default();
    assert_eq!(
        capture
            .scan_memory(b"http://x/", &"s".repeat(MAX_SOURCE_BYTES + 1), 0x1000)
            .unwrap_err(),
        Error::SourceLimit
    );
    assert_eq!(
        capture
            .scan_memory(b"http://x/", "memory:overflow", u64::MAX - 1)
            .unwrap_err(),
        Error::AddressOverflow
    );
    assert_eq!(capture.report().scanned_bytes(), 0);
    assert!(capture.report().matches().is_empty());
    assert!(crate::reports::valid_memory_capture(
        &serde_json::to_value(capture.into_report()).unwrap()
    ));
    let mut disabled = Capture::new(Options::disabled());
    disabled
        .scan_memory(b"http://x/", &"s".repeat(MAX_SOURCE_BYTES + 1), u64::MAX)
        .unwrap();
    disabled.scan_managed_utf16(&[0xd800], "ignored").unwrap();
    assert_eq!(
        serde_json::to_value(disabled.report()).unwrap(),
        json!({"enabled":false,"regex":[],"matches":[],"scanned_bytes":0,"truncated":false,"limits":[]})
    );
}
#[test]
fn json_accounting_preserves_unicode_escape_cost_and_zero_offset_null_address() {
    let item = Match {
        format: Format::Url,
        value: "http://x/😀\u{0}\"\\".into(),
        source: "managed\nsource".into(),
        encoding: Encoding::Managed,
        offset: 0,
        address: None,
    };
    // Independently computed Python json.dumps ensure_ascii=True observation.
    assert_eq!(item.legacy_json_bytes(), 143);
    let mut capture = Capture::default();
    capture.scan_string("😀 http://x/", "managed").unwrap();
    let report = capture.into_report();
    assert_eq!(report.scanned_bytes(), 22);
    assert_eq!(report.matches()[0].offset, 2);
    assert_eq!(report.matches()[0].address, None);
}
#[test]
fn compact_unicode_ranges_are_ordered_bounded_and_keep_combining_marks_nonword() {
    assert_eq!(BUILTIN_UNICODE_VERSION, "15.1.0");
    assert!(unicode::word('é') && unicode::word('你') && unicode::word('_'));
    assert!(!unicode::word('\u{301}') && !unicode::word('😀'));
    assert!(unicode::space('\u{1c}') && unicode::space('\u{a0}'));
    assert!(unicode::nfkc_reserved('\u{ff0f}') && !unicode::nfkc_reserved('日'));
    for ranges in [unicode::WORD, unicode::SPACE] {
        assert!(ranges.len() <= 800);
        assert!(
            ranges
                .iter()
                .all(|(first, last)| first <= last && *last <= 0x10ffff)
        );
        assert!(ranges.windows(2).all(|w| w[0].1 < w[1].0));
    }
}

#[test]
fn every_well_formed_codepoint_agrees_with_pinned_actual_python_builtin_classes() {
    let raw = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/data/memory_strings_unicode_reference.json"),
    )
    .unwrap();
    assert_eq!(
        crate::report_bundle::digest(&raw),
        "a6cec2e19e692bd82c587bf97c136f42a41d4a760c7c3c1b1f35f25900d4c32e"
    );
    let reference: Value = serde_json::from_slice(&raw).unwrap();
    assert_eq!(reference["python_unicode"], BUILTIN_UNICODE_VERSION);
    let mut expected_word = vec![false; 0x110000];
    let mut expected_space = vec![false; 0x110000];
    let mut expected_reserved = vec![false; 0x110000];
    for (key, expected) in [("word", &mut expected_word), ("space", &mut expected_space)] {
        for range in reference[key].as_array().unwrap() {
            let first = range[0].as_u64().unwrap() as usize;
            let last = range[1].as_u64().unwrap() as usize;
            expected[first..=last].fill(true);
        }
    }
    for row in reference["nfkc_reserved_expansions"].as_array().unwrap() {
        expected_reserved[row[0].as_u64().unwrap() as usize] = true;
    }
    for code in 0..0x110000 {
        if let Some(c) = char::from_u32(code as u32) {
            assert_eq!(unicode::word(c), expected_word[code], "word U+{code:04x}");
            assert_eq!(
                unicode::space(c),
                expected_space[code],
                "space U+{code:04x}"
            );
            assert_eq!(
                unicode::nfkc_reserved(c),
                expected_reserved[code],
                "NFKC reserved U+{code:04x}"
            );
        }
    }
}
