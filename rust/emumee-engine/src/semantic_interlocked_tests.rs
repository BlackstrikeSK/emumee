//! Submitted interlocked calls use frozen scalar and complete-memory oracles.
use super::*;
use emumee_core::fixtures::{InterlockedFixtureCase, interlocked_dynamic_probe, interlocked_probe};
use emumee_core::report_bundle::digest;
use std::collections::BTreeMap;

fn case(value: &serde_json::Value) -> InterlockedFixtureCase {
    InterlockedFixtureCase {
        old: value["old"].as_u64().unwrap() as u32,
        arguments: value["arguments"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_u64().unwrap())
            .collect(),
        result: value["result"].as_u64().unwrap_or(0) as u32,
        new: value["new"].as_u64().unwrap() as u32,
    }
}

fn reference() -> serde_json::Value {
    serde_json::from_str(include_str!("api/interlocked_reference.json")).unwrap()
}

#[test]
fn interlocked_submitted_vectors_preserve_results_errors_full_memory_and_width_aliases() {
    let reference = reference();
    for architecture in [Architecture::X86, Architecture::X64] {
        let arch = if architecture == Architecture::X86 {
            "x86"
        } else {
            "x64"
        };
        let mut groups: BTreeMap<String, Vec<&serde_json::Value>> = BTreeMap::new();
        for value in reference["cases"].as_array().unwrap() {
            if value["architecture"] == arch && value["error"].is_null() {
                groups
                    .entry(value["export"].as_str().unwrap().into())
                    .or_default()
                    .push(value);
            }
        }
        for (export, values) in groups {
            for (group, chunk) in values.chunks(4).enumerate() {
                let label = format!("{architecture:?}-semantic-interlocked-{export}-{group:03}");
                let cases = chunk.iter().map(|v| case(v)).collect::<Vec<_>>();
                let result = crate::semantic_literals_tests::run(
                    &label,
                    interlocked_probe(architecture, &export, &cases, false, None),
                );
                assert_eq!(result.error, None, "{label}: {result:#?}");
                assert_eq!(result.guest_entry_return, Some(1), "{label}");
                let events = result
                    .api_events
                    .iter()
                    .filter(|e| e.api.starts_with("kernel32.Interlocked"))
                    .collect::<Vec<_>>();
                assert_eq!(events.len(), cases.len() * 3, "{label}");
                for (value, events) in chunk.iter().zip(events.chunks(3)) {
                    for event in events {
                        assert_eq!(event.result, value["result"].as_u64(), "{label}");
                        assert_eq!(event.last_error, 0x12345678, "{label}");
                        assert!(!event.pending && event.error.is_none(), "{label}");
                    }
                }
                let arena = result
                    .artifacts
                    .iter()
                    .find(|a| {
                        a.observations
                            .iter()
                            .any(|o| o.guest_path.ends_with("interlocked-memory.bin"))
                    })
                    .unwrap();
                assert_eq!(arena.size, 65536);
                assert_eq!(
                    digest(&arena.data),
                    chunk.last().unwrap()["arena_sha256"].as_str().unwrap(),
                    "{label}"
                );
            }
        }
    }
}

#[test]
fn interlocked_submitted_overflow_and_denied_memory_never_return_success() {
    let reference = reference();
    for (index, value) in reference["cases"].as_array().unwrap().iter().enumerate() {
        if value["error"].is_null() {
            continue;
        }
        let architecture = if value["architecture"] == "x86" {
            Architecture::X86
        } else {
            Architecture::X64
        };
        let export = value["export"].as_str().unwrap();
        let protection = value
            .get("synthetic_access")
            .map(|access| if access["readable"] == false { 1 } else { 2 });
        let label = format!("{architecture:?}-semantic-interlocked-error-{export}-{index:03}");
        let result = crate::semantic_literals_tests::run(
            &label,
            interlocked_probe(architecture, export, &[case(value)], true, protection),
        );
        assert!(result.error.is_some(), "{label}");
        assert_eq!(result.guest_entry_return, None, "{label}");
        let event = result
            .api_events
            .iter()
            .find(|e| e.api == format!("kernel32.{export}"))
            .unwrap();
        assert!(event.error.is_some() && !event.pending, "{label}");
        assert_eq!(event.result, None);
        assert_eq!(event.last_error, 0x12345678);
        if value["error"] == "OverflowError" {
            assert!(event.error.as_ref().unwrap().contains("integer conversion"));
        }
    }
}

#[test]
fn interlocked_dynamic_exports_execute_without_static_target_imports() {
    let reference = reference();
    for architecture in [Architecture::X86, Architecture::X64] {
        let arch = if architecture == Architecture::X86 {
            "x86"
        } else {
            "x64"
        };
        let mut selected = Vec::new();
        let mut final_hash = String::new();
        for name in [
            "InterlockedIncrement",
            "InterlockedDecrement",
            "InterlockedExchangeAdd",
            "InterlockedExchange",
            "InterlockedCompareExchange",
        ] {
            let value = reference["cases"]
                .as_array()
                .unwrap()
                .iter()
                .find(|v| {
                    let args = v["arguments"].as_array().unwrap();
                    v["architecture"] == arch
                        && v["export"] == name
                        && v["error"].is_null()
                        && v["old"] == u32::MAX
                        && (args.len() == 1 || args[1] == 1)
                        && (args.len() < 3 || args[2] == u32::MAX)
                })
                .unwrap();
            selected.push((name.to_string(), case(value)));
            final_hash = value["arena_sha256"].as_str().unwrap().into();
        }
        let label = format!("{architecture:?}-semantic-interlocked-dynamic");
        let result = crate::semantic_literals_tests::run(
            &label,
            interlocked_dynamic_probe(architecture, &selected),
        );
        assert_eq!(result.error, None, "{label}: {result:#?}");
        assert_eq!(result.guest_entry_return, Some(1));
        let events = result
            .api_events
            .iter()
            .filter(|e| e.api.starts_with("kernel32.Interlocked"))
            .collect::<Vec<_>>();
        assert_eq!(events.len(), 15);
        assert!(
            events
                .iter()
                .all(|e| e.last_error == 0x12345678 && !e.pending && e.error.is_none())
        );
        let arena = result
            .artifacts
            .iter()
            .find(|a| {
                a.observations
                    .iter()
                    .any(|o| o.guest_path.ends_with("interlocked-memory.bin"))
            })
            .unwrap();
        assert_eq!(digest(&arena.data), final_hash);
    }
}
