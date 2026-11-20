//! Registry control family: value deletion, the legacy enumeration spelling,
//! the generic information spelling, service control handlers and the access
//! boundary that must refuse.
use super::*;
use emumee_core::fixtures::{M6RegistryFixture as F, m6_registry_probe};

fn control(arch: Architecture, kind: F, unicode: bool) -> Execution {
    let suffix = if unicode { "W" } else { "A" };
    let label = format!("{arch:?}-m6-registry-{kind:?}{suffix}");
    let result = run(&label, m6_registry_probe(arch, kind, unicode), &[], 40_000);
    succeeded(&label, &result);
    result
}

#[test]
fn m6_registry_value_deletion_enumeration_information_and_handlers_are_guest_decided() {
    for arch in [Architecture::X86, Architecture::X64] {
        for unicode in [false, true] {
            for kind in [F::DeleteValue, F::EnumKey, F::KeyInfo, F::ServiceHandler] {
                let result = control(arch, kind, unicode);
                // No registry value in this family is binary, so nothing is
                // captured as an artifact.
                assert!(result.artifacts.is_empty(), "{kind:?}: {:?}", result.artifacts);
                assert_eq!(result.capture_summary.omitted_observations, 0);
                if matches!(kind, F::ServiceHandler) {
                    // Four registrations were accepted and two refused; none is
                    // ever dispatched, so no callback ran.
                    assert_eq!(
                        result
                            .api_events
                            .iter()
                            .filter(|event| event.api.contains("RegisterServiceCtrlHandler"))
                            .count(),
                        5
                    );
                }
            }
        }
    }
}

#[test]
fn m6_registry_delete_without_set_access_is_refused_and_leaves_the_value() {
    for arch in [Architecture::X86, Architecture::X64] {
        for unicode in [false, true] {
            let result = control(arch, F::DeleteDenied, unicode);
            let refused = result
                .api_events
                .iter()
                .filter(|event| event.api.contains("RegDeleteValue") && event.result == Some(5))
                .count();
            assert_eq!(refused, 1, "{arch:?}/{unicode}: {:#?}", result.api_events);
        }
    }
}
