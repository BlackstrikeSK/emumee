use super::*;
use emumee_core::fixtures::{ApiFixture, RegistryFixture as F};
use sha2::{Digest, Sha256};

fn check_registry_capture(result: &Execution, expected: usize) {
    assert_eq!(result.artifacts.len(), expected);
    assert_eq!(result.capture_summary.omitted_observations, 0);
    assert_eq!(result.capture_summary.omitted_bytes, 0);
    assert!(result.capture_summary.reasons.is_empty());
    if expected == 0 {
        return;
    }
    assert_eq!(expected, 1);
    let raw = [0xf0, 0x00, 0x80, 0xff];
    let sha = format!("{:x}", Sha256::digest(raw));
    let artifact = &result.artifacts[0];
    assert_eq!(artifact.data, raw);
    assert_eq!(artifact.size, 4);
    assert_eq!(artifact.sha256, sha);
    assert_eq!(artifact.filename, format!("{sha}.bin"));
    assert_eq!(artifact.observations.len(), 1);
    let observation = &artifact.observations[0];
    assert_eq!(
        observation.kind,
        emumee_core::artifacts::ArtifactKind::RegistryValue
    );
    assert_eq!(observation.source, "registry_value");
    assert_eq!(
        observation.guest_path,
        "HKEY_CURRENT_USER\\Software\\EmumeeRegistryFixture\\Raw"
    );
    assert_eq!(observation.context.as_ref().unwrap(),serde_json::json!({"registry_key":"HKEY_CURRENT_USER\\Software\\EmumeeRegistryFixture","registry_value":"Raw","registry_type":3}).as_object().unwrap());
}
fn successful_binary_writes(result: &Execution) -> usize {
    result
        .api_events
        .iter()
        .filter(|event| {
            event.api.starts_with("advapi32.RegSetValueEx")
                && event.result == Some(0)
                && event.arguments.get(3) == Some(&3)
                && event.arguments.get(5).is_some_and(|n| *n > 0)
        })
        .count()
}
#[test]
fn registry_calls_observe_bytes_names_sizes_lstatus_and_owned_handles_on_both_abis() {
    for arch in [Architecture::X86, Architecture::X64] {
        for unicode in [false, true] {
            for fixture in [
                F::Lifecycle,
                F::Enumeration,
                F::SmallBuffer,
                F::DefaultValue,
                F::InvalidHandle,
                F::ClosedHandle,
                F::ReadOnly,
            ] {
                let result =
                    run_api_fixture(arch, ApiFixture::Registry(fixture, unicode), 2000).unwrap();
                assert_eq!(
                    result.error, None,
                    "{arch:?} {unicode} {fixture:?}: {result:#?}"
                );
                assert_eq!(result.guest_entry_return, Some(17));
                let expected = usize::from(matches!(
                    fixture,
                    F::Lifecycle | F::Enumeration | F::SmallBuffer
                ));
                assert_eq!(successful_binary_writes(&result), expected);
                check_registry_capture(&result, expected);
                assert_eq!(result.network.calls, 0);
                assert!(
                    result
                        .api_events
                        .iter()
                        .filter(|event| event.api.starts_with("advapi32."))
                        .all(|event| event.last_error == 0x12345678)
                );
            }
            let denied =
                run_api_fixture(arch, ApiFixture::Registry(F::Options, unicode), 2000).unwrap();
            assert!(
                denied
                    .error
                    .as_deref()
                    .unwrap()
                    .contains("Registry creation options"),
                "{:?}",
                denied.error
            );
            assert_eq!(denied.guest_entry_return, None);
        }
    }
}
#[test]
fn registry_every_budget_prefix_never_invents_completion_or_host_network_activity() {
    for arch in [Architecture::X86, Architecture::X64] {
        for unicode in [false, true] {
            for fixture in [F::Lifecycle, F::Enumeration, F::SmallBuffer] {
                let full =
                    run_api_fixture(arch, ApiFixture::Registry(fixture, unicode), 2000).unwrap();
                assert_eq!(
                    full.guest_entry_return,
                    Some(17),
                    "{arch:?} {unicode} {fixture:?}: {:?}",
                    full.error
                );
                for budget in 1..full.instruction_count {
                    let partial =
                        run_api_fixture(arch, ApiFixture::Registry(fixture, unicode), budget)
                            .unwrap();
                    assert_eq!(partial.completion_reason, "instruction_budget");
                    assert_eq!(partial.error, None);
                    assert_eq!(partial.guest_entry_return, None);
                    assert_eq!(partial.network.calls, 0);
                    let expected = successful_binary_writes(&partial);
                    assert!(expected <= 1);
                    check_registry_capture(&partial, expected);
                }
            }
        }
    }
}
