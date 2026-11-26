//! Guest ABI and full-arena canaries for explicit frozen return-only handlers.
use super::*;
use emumee_core::{
    artifacts::ArtifactKind,
    fixtures::{LegacyLiteralArguments, LegacyLiteralFixture, legacy_literal_probe},
    report_bundle::digest,
    user_input::{PROFILE, Request},
};
use std::collections::BTreeMap;

pub(super) fn run(label: &str, bytes: Vec<u8>) -> Execution {
    let request = Request {
        schema: 2,
        profile: PROFILE.into(),
        run_id: "20261124T120000Z-12345678".into(),
        input_sha256: digest(&bytes),
        input_size: bytes.len() as u64,
        module_name: "sample.exe".into(),
        arguments: vec![],
        max_instructions: 100_000,
        timeout_us: 30_000_000,
        persona_sha256: None,
        clock_utc_filetime: crate::m6_tests::CLOCK,
        staged: vec![],
        invocation: Default::default(),
        capture: None,
        output: None,
    };
    crate::user_test_fixtures::fixture(label, &request, &bytes, &[], None);
    let result = user::run(&request, &bytes, None).unwrap();
    crate::user_test_fixtures::execution(label, &result);
    result
}

#[test]
fn semantic_legacy_literals_preserve_frozen_results_errors_memory_and_width_aliases() {
    for (family, manifest) in [
        ("literal", include_str!("api/legacy_literals.json")),
        ("local", include_str!("api/legacy_locals.json")),
    ] {
        let document: serde_json::Value = serde_json::from_str(manifest).unwrap();
        for architecture in [Architecture::X86, Architecture::X64] {
            let architecture_name = if architecture == Architecture::X86 {
                "x86"
            } else {
                "x64"
            };
            let mut modules: BTreeMap<String, Vec<LegacyLiteralFixture>> = BTreeMap::new();
            for entry in document["entries"].as_array().unwrap() {
                if entry["architecture"] != architecture_name {
                    continue;
                }
                let module = entry["module"].as_str().unwrap();
                modules
                    .entry(module.into())
                    .or_default()
                    .push(LegacyLiteralFixture {
                        export: entry["export"].as_str().unwrap().into(),
                        argc: entry["argc"].as_u64().unwrap() as usize,
                        value: entry["value"].as_u64().unwrap() as u32,
                        width_aliases: module != "ntdll",
                    });
            }
            for (module, mut entries) in modules {
                entries.sort_by(|a, b| a.export.cmp(&b.export));
                for (group, calls) in entries.chunks(4).enumerate() {
                    for arguments in [
                        LegacyLiteralArguments::Zero,
                        LegacyLiteralArguments::Poison,
                        LegacyLiteralArguments::Arena,
                    ] {
                        let label = format!(
                            "{architecture:?}-semantic-{family}-{module}-{group:03}-{arguments:?}"
                        );
                        let bytes = legacy_literal_probe(architecture, &module, calls, arguments);
                        let result = run(&label, bytes);
                        assert_eq!(result.error, None, "{label}: {result:#?}");
                        assert_eq!(result.guest_entry_return, Some(1), "{label}");
                        assert!(result.api_events.iter().all(|e| !e.pending), "{label}");
                        let expected_calls: usize = calls
                            .iter()
                            .map(|c| if c.width_aliases { 3 } else { 1 })
                            .sum();
                        let observed: Vec<_> = result
                            .api_events
                            .iter()
                            .filter(|e| e.effect == Some("frozen_legacy_placeholder"))
                            .collect();
                        assert_eq!(observed.len(), expected_calls, "{label}");
                        assert!(
                            observed.iter().all(|e| e.last_error == 0x12345678),
                            "{label}"
                        );
                        let arena = result
                            .artifacts
                            .iter()
                            .find(|a| {
                                a.observations.iter().any(|o| {
                                    o.kind == ArtifactKind::GuestFile
                                        && o.guest_path.ends_with("literal-memory.bin")
                                })
                            })
                            .unwrap();
                        assert_eq!(arena.size, 0x10000, "{label}");
                        assert!(arena.data.iter().all(|byte| *byte == 0xa5), "{label}");
                    }
                }
            }
        }
    }
}

#[test]
fn semantic_legacy_literal_width_aliases_resolve_without_static_alias_imports() {
    for architecture in [Architecture::X86, Architecture::X64] {
        for (family, bytes, names) in [
            (
                "literal",
                emumee_core::fixtures::legacy_literal_dynamic_probe(architecture),
                ["gdi32.GetMapMode", "gdi32.GetMapModeA", "gdi32.GetMapModeW"],
            ),
            (
                "local",
                emumee_core::fixtures::legacy_local_dynamic_probe(architecture),
                [
                    "comctl32.InitCommonControlsEx",
                    "comctl32.InitCommonControlsExA",
                    "comctl32.InitCommonControlsExW",
                ],
            ),
        ] {
            let label = format!("{architecture:?}-semantic-{family}-dynamic");
            let result = run(&label, bytes);
            assert_eq!(result.error, None, "{label}: {result:#?}");
            assert_eq!(result.guest_entry_return, Some(1));
            let calls: Vec<_> = result
                .api_events
                .iter()
                .filter(|e| e.effect == Some("frozen_legacy_placeholder"))
                .collect();
            assert_eq!(calls.len(), 3, "{label}");
            for name in names {
                let event = calls.iter().find(|e| e.api == name).unwrap();
                assert_eq!(event.result, Some(1));
                assert!(!event.pending && event.error.is_none());
                if name != names[0] {
                    assert_eq!(event.last_error, 0x12345678);
                }
            }
            assert!(result.artifacts.is_empty());
        }
    }
}
