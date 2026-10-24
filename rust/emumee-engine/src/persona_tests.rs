use super::*;
use emumee_core::fixtures::{ApiFixture, PersonaFixture as F};
#[test]
fn persona_callers_check_environment_bytes_lengths_errors_identity_and_owned_command_lines() {
    for arch in [Architecture::X86, Architecture::X64] {
        for unicode in [false, true] {
            for kind in [
                F::Variable,
                F::Mutation,
                F::Expansion,
                F::Directories,
                F::Identity,
                F::CommandLine,
            ] {
                let result =
                    run_api_fixture(arch, ApiFixture::Persona(kind, unicode), 2000).unwrap();
                assert_eq!(
                    result.error, None,
                    "{arch:?} {kind:?}/{unicode}: {result:#?}"
                );
                assert_eq!(result.guest_entry_return, Some(17));
                assert_eq!(result.network.calls, 0);
                assert!(result.artifacts.is_empty());
            }
            for kind in [
                F::CommandFree,
                F::CommandProtect,
                F::CommandRecommit,
                F::BlocksUnsupported,
                F::CwdUnsupported,
            ] {
                let result =
                    run_api_fixture(arch, ApiFixture::Persona(kind, unicode), 2000).unwrap();
                assert!(
                    result.error.is_some(),
                    "{arch:?} {kind:?}/{unicode}: {result:#?}"
                );
                assert_eq!(result.guest_entry_return, None);
            }
        }
    }
}
#[test]
fn persona_budget_prefixes_preserve_only_executed_guest_effects() {
    for arch in [Architecture::X86, Architecture::X64] {
        for unicode in [false, true] {
            for kind in [F::Variable, F::Mutation, F::Identity, F::CommandLine] {
                let full = run_api_fixture(arch, ApiFixture::Persona(kind, unicode), 2000).unwrap();
                assert_eq!(
                    full.guest_entry_return,
                    Some(17),
                    "{arch:?} {kind:?}/{unicode}: {:?}",
                    full.error
                );
                for budget in 1..full.instruction_count {
                    let result =
                        run_api_fixture(arch, ApiFixture::Persona(kind, unicode), budget).unwrap();
                    assert_eq!(result.error, None);
                    assert_eq!(result.completion_reason, "instruction_budget");
                    assert_eq!(result.guest_entry_return, None);
                }
            }
        }
    }
}
