use super::*;
use crate::{
    analysis_fixture::{Arch, Case as AnalysisCase, Fault, Request},
    managed::Metadata,
    pe::Architecture,
};
use serde_json::json;
fn corpus() -> Value {
    let raw = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/data/managed_indicators_reference.json"),
    )
    .unwrap();
    assert_eq!(
        report_bundle::digest(&raw),
        "5a44ce7fbd1fe04e9deb8b2f498af8b731a3272ecf1fba63b5630f2b6e3769d1"
    );
    serde_json::from_slice(&raw).unwrap()
}
#[test]
fn closed_actual_metadata_and_request_bytes_preserve_raw_utf16_and_refuse_config_fields() {
    for row in corpus()["cases"].as_array().unwrap() {
        for architecture in [Architecture::X86, Architecture::X64] {
            let case: Case = serde_json::from_value(row["case"].clone()).unwrap();
            let input = case.input(architecture);
            let metadata = Metadata::parse(&input, "owned.exe").unwrap();
            assert!(!metadata.cli.native_entry_point);
            assert!(
                !metadata
                    .method_body(metadata.cli.entry_point)
                    .unwrap()
                    .more_sections
            );
            assert!(metadata.user_string(1).unwrap().len() <= 64);
            if case == Case::Surrogate {
                assert_eq!(metadata.user_string(1).unwrap().last(), Some(&0xd800));
            }
            let parsed = AnalysisCase::parse(row["analysis_case"].as_str().unwrap()).unwrap();
            assert_eq!(parsed.managed_indicator(), Some(case));
            assert_eq!(parsed.observation_profile(), Some(VERSION));
            let arch = if architecture == Architecture::X64 {
                Arch::X64
            } else {
                Arch::X86
            };
            let request = Request::generated(
                parsed,
                Fault::None,
                arch,
                "20261019T120000Z-12345678".into(),
                "2026-10-19T12:00:00Z".into(),
            );
            let raw = serde_json::to_vec(&request).unwrap();
            assert!(Request::parse(&raw).unwrap().verifies_input(&input));
            let mut bad: Value = serde_json::from_slice(&raw).unwrap();
            bad["memory_strings"] = json!({"regex":[".*"]});
            assert!(Request::parse(&serde_json::to_vec(&bad).unwrap()).is_err());
            assert_eq!(
                parsed.output_limit(),
                crate::analysis_fixture::MAX_OUTPUT + crate::indicator_fixture::REPORT_RESERVATION
            );
        }
    }
}
#[test]
fn independent_event_oracle_and_validator_detect_alias_and_utf16_tamper() {
    for row in corpus()["cases"].as_array().unwrap() {
        let case: Case = serde_json::from_value(row["case"].clone()).unwrap();
        assert_eq!(
            serde_json::to_value(expected_events(case)).unwrap(),
            row["events"]
        );
        // Synthetic validator metadata only. Actual execution is tested in the engine.
        let events: Vec<Event> = serde_json::from_value(row["events"].clone()).unwrap();
        let receipt = Receipt {
            version: VERSION.into(),
            case,
            enabled: case.enabled(),
            all_managed_strings_complete: false,
            all_guest_memory_complete: false,
            input_sha256: report_bundle::digest(&case.input(Architecture::X64)),
            capture_sha256: memory_observation::capture_hash(&row["expected"]).unwrap(),
            event_sources: ["managed_ldstr", "managed_argument", "managed_return"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            events_seen: events.len() as u64,
            events_omitted: 0,
            events,
            source_utf16_bytes_observed: row["source_utf16_bytes_observed"].as_u64().unwrap(),
            max_source_utf16_bytes: MAX_SOURCE_UTF16_BYTES,
            boundary_instructions: row["instruction_count"].as_u64().unwrap(),
            boundary_method: 0x06000001,
            boundary_offset: row["final_offset"].as_u64().unwrap() as u32,
            omitted_sources: row["omitted_sources"].as_u64().unwrap(),
        };
        let strings:Vec<_>=row["heap_utf16"].as_array().unwrap().iter().enumerate().map(|(i,units)|
            json!({"reference":i+1,"utf16_length":units.as_array().unwrap().len(),"utf16_preview":units,"preview_truncated":false})).collect();
        let original = json!({"architecture":"x64","instruction_count":row["instruction_count"],"final_method":0x06000001,
            "final_offset":row["final_offset"],"max_instructions":case.budget(),"memory_strings":row["expected"],
            "memory_string_sources":receipt,"heap":{"strings":strings}});
        assert!(valid_execution(&original), "{case:?}");
        let mut bad = original.clone();
        bad["memory_string_sources"]["all_managed_strings_complete"] = json!(true);
        assert!(!valid_execution(&bad));
        if case == Case::Events {
            let mut bad = original.clone();
            bad["memory_string_sources"]["events"][5]["reference"] = json!(4);
            assert!(!valid_execution(&bad));
        }
    }
}
