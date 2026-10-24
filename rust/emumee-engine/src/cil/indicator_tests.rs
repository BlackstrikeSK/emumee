use super::*;
use emumee_core::{managed_indicator_fixture::Case, managed_observation};
use serde_json::{Value as Json, json};
fn corpus() -> Json {
    let raw = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../emumee-core/tests/data/managed_indicators_reference.json"),
    )
    .unwrap();
    assert_eq!(
        emumee_core::report_bundle::digest(&raw),
        "5a44ce7fbd1fe04e9deb8b2f498af8b731a3272ecf1fba63b5630f2b6e3769d1"
    );
    serde_json::from_slice(&raw).unwrap()
}
#[test]
fn actual_utf16_event_transitions_and_heap_aliases_match_the_independent_collector_oracle() {
    for architecture in [Architecture::X86, Architecture::X64] {
        for row in corpus()["cases"].as_array().unwrap() {
            let case: Case = serde_json::from_value(row["case"].clone()).unwrap();
            let input = case.input(architecture);
            let execution = run_indicator_fixture(architecture, case, &input).unwrap();
            let actual = serde_json::to_value(&execution).unwrap();
            assert_eq!(
                actual["memory_strings"], row["expected"],
                "{architecture:?}/{case:?}"
            );
            let receipt = &actual["memory_string_sources"];
            assert_eq!(
                receipt["events"], row["events"],
                "{architecture:?}/{case:?}"
            );
            assert_eq!(
                receipt["source_utf16_bytes_observed"],
                row["source_utf16_bytes_observed"]
            );
            assert_eq!(receipt["omitted_sources"], row["omitted_sources"]);
            assert_eq!(actual["instruction_count"], row["instruction_count"]);
            assert_eq!(actual["final_offset"], row["final_offset"]);
            assert_eq!(actual["managed_calls"], row["managed_calls"]);
            assert_eq!(actual["framework"]["attempts"], row["framework_attempts"]);
            assert_eq!(
                actual["framework"]["completed_calls"],
                row["framework_completed"]
            );
            assert_eq!(actual["guest_entry_return"], row["guest_entry_return"]);
            assert_eq!(actual["completion_reason"], row["completion_reason"]);
            assert_eq!(execution.error.is_some(), case == Case::FrameworkFailure);
            let units: Vec<_> = execution
                .heap
                .strings
                .iter()
                .map(|string| json!(string.utf16_preview))
                .collect();
            assert_eq!(json!(units), row["heap_utf16"]);
            assert_eq!(execution.heap.string_objects, units.len());
            assert!(managed_observation::valid_execution(&actual));
            assert!(emumee_core::memory_observation::valid_execution(&actual));
        }
    }
}
#[test]
fn capture_disabled_and_budgeted_do_not_change_guest_identity_or_invent_unexecuted_literals() {
    let architecture = Architecture::X64;
    let enabled = run_indicator_fixture(
        architecture,
        Case::Events,
        &Case::Events.input(architecture),
    )
    .unwrap();
    let disabled = run_indicator_fixture(
        architecture,
        Case::Disabled,
        &Case::Disabled.input(architecture),
    )
    .unwrap();
    assert_eq!(enabled.guest_entry_return, disabled.guest_entry_return);
    assert_eq!(enabled.instruction_count, disabled.instruction_count);
    assert_eq!(
        serde_json::to_value(&enabled.heap).unwrap(),
        serde_json::to_value(&disabled.heap).unwrap()
    );
    assert_eq!(
        serde_json::to_value(&enabled.framework).unwrap(),
        serde_json::to_value(&disabled.framework).unwrap()
    );
    let input = Case::Budget.input(architecture);
    let needle: Vec<_> = "http://managed.example/"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    assert!(input.windows(needle.len()).any(|window| window == needle));
    let budgeted = run_indicator_fixture(architecture, Case::Budget, &input).unwrap();
    assert_eq!(budgeted.instruction_count, 2);
    assert!(
        budgeted
            .memory_strings
            .unwrap()
            .matches()
            .iter()
            .all(|item| item.format != emumee_core::memory_strings::Format::Url)
    );
    let surrogate = run_indicator_fixture(
        architecture,
        Case::Surrogate,
        &Case::Surrogate.input(architecture),
    )
    .unwrap();
    assert_eq!(surrogate.guest_entry_return, Some(17));
    assert!(surrogate.error.is_none());
    assert_eq!(
        surrogate.heap.strings[0].utf16_preview.last(),
        Some(&0xd800)
    );
}
#[test]
fn rebound_alias_token_boundary_and_physical_unit_ledger_are_refused() {
    let case = Case::Events;
    let value =
        run_indicator_fixture(Architecture::X64, case, &case.input(Architecture::X64)).unwrap();
    let original = serde_json::to_value(value).unwrap();
    for mutation in 0..7 {
        let mut changed = original.clone();
        match mutation {
            0 => changed["memory_string_sources"]["events"][5]["reference"] = json!(4),
            1 => changed["memory_string_sources"]["events"][0]["token"] = json!(0x70000011),
            2 => changed["memory_string_sources"]["events"][4]["instruction_count"] = json!(2),
            3 => changed["memory_string_sources"]["source_utf16_bytes_observed"] = json!(0),
            4 => changed["memory_string_sources"]["all_managed_strings_complete"] = json!(true),
            5 => changed["heap"]["strings"][0]["utf16_preview"][0] = json!(0xfffd),
            _ => {
                changed["memory_strings"]["matches"][0]["offset"] = json!(0);
                changed["memory_string_sources"]["capture_sha256"] = json!(
                    emumee_core::memory_observation::capture_hash(&changed["memory_strings"])
                        .unwrap()
                );
            }
        }
        assert!(
            !managed_observation::valid_execution(&changed),
            "mutation{mutation}"
        );
    }
    let mut input = case.input(Architecture::X64);
    input[0] ^= 1;
    assert!(run_indicator_fixture(Architecture::X64, case, &input).is_err());
    let old = run_fixture(Architecture::X64, CilFixture::FrameworkStrings, 17, 1000).unwrap();
    let old = serde_json::to_value(old).unwrap();
    assert!(old.get("memory_strings").is_none() && old.get("memory_string_sources").is_none());
}
