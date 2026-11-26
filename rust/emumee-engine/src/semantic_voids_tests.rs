//! Submitted void APIs preserve seeded registers, error state and guest memory.
use super::*;
use emumee_core::fixtures::{LegacyVoidFixture, legacy_void_dynamic_probe, legacy_void_probe};
use std::collections::BTreeMap;

#[test]
fn frozen_void_calls_preserve_seeded_registers_errors_and_the_complete_arena() {
    let document: serde_json::Value =
        serde_json::from_str(include_str!("api/legacy_voids.json")).unwrap();
    for architecture in [Architecture::X86, Architecture::X64] {
        let arch = if architecture == Architecture::X86 {
            "x86"
        } else {
            "x64"
        };
        let mut modules: BTreeMap<String, Vec<LegacyVoidFixture>> = BTreeMap::new();
        for entry in document["entries"].as_array().unwrap() {
            if entry["architecture"] != arch {
                continue;
            }
            modules
                .entry(entry["module"].as_str().unwrap().into())
                .or_default()
                .push(LegacyVoidFixture {
                    export: entry["export"].as_str().unwrap().into(),
                    argc: entry["argc"].as_u64().unwrap() as usize,
                });
        }
        for (module, mut entries) in modules {
            entries.sort_by(|a, b| a.export.cmp(&b.export));
            for (group, calls) in entries.chunks(4).enumerate() {
                for (mode, kind) in [(0, "Zero"), (1, "Poison"), (2, "Arena")] {
                    let label =
                        format!("{architecture:?}-semantic-void-{module}-{group:03}-{kind}");
                    let result = crate::semantic_literals_tests::run(
                        &label,
                        legacy_void_probe(architecture, &module, calls, mode),
                    );
                    assert_eq!(result.error, None, "{label}: {result:#?}");
                    assert_eq!(result.guest_entry_return, Some(1), "{label}");
                    let observed: Vec<_> = result
                        .api_events
                        .iter()
                        .filter(|e| e.effect == Some("frozen_legacy_placeholder"))
                        .collect();
                    assert_eq!(observed.len(), calls.len() * 3, "{label}");
                    assert!(
                        observed.iter().all(|e| e.result.is_none()
                            && e.last_error == 0x12345678
                            && !e.pending
                            && e.error.is_none()),
                        "{label}"
                    );
                    let arena = result
                        .artifacts
                        .iter()
                        .find(|a| {
                            a.observations
                                .iter()
                                .any(|o| o.guest_path.ends_with("void-memory.bin"))
                        })
                        .unwrap();
                    assert_eq!(arena.size, 0x10000, "{label}");
                    assert!(arena.data.iter().all(|b| *b == 0xa5), "{label}");
                }
            }
        }
    }
}

#[test]
fn frozen_void_width_aliases_resolve_dynamically_and_preserve_full_return_registers() {
    for architecture in [Architecture::X86, Architecture::X64] {
        let label = format!("{architecture:?}-semantic-void-dynamic");
        let result =
            crate::semantic_literals_tests::run(&label, legacy_void_dynamic_probe(architecture));
        assert_eq!(result.error, None, "{label}: {result:#?}");
        assert_eq!(result.guest_entry_return, Some(1));
        let observed: Vec<_> = result
            .api_events
            .iter()
            .filter(|e| e.effect == Some("frozen_legacy_placeholder"))
            .collect();
        assert_eq!(observed.len(), 3);
        assert!(
            observed
                .iter()
                .all(|e| e.result.is_none() && !e.pending && e.error.is_none())
        );
        assert!(observed[1..].iter().all(|e| e.last_error == 0x12345678));
        assert!(result.artifacts.is_empty());
    }
}
