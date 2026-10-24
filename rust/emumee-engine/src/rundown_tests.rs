use super::*;
use emumee_core::fixtures::{ApiFixture, RundownFixture as F};
#[test]
fn rundown_owned_callers_check_fastcall_references_blocked_phase_and_opaque_access() {
    for architecture in [Architecture::X86, Architecture::X64] {
        for kind in [
            F::Lifecycle,
            F::Free,
            F::Zero,
            F::BlockedWait,
            F::BlockedFree,
            F::Underflow,
            F::InvalidPointer,
            F::DoubleFree,
            F::PoolFree,
            F::BodyRead,
            F::BodyWrite,
            F::BodyCall,
            F::ApiRead,
            F::ApiWrite,
            F::IrqlAllocate,
            F::IrqlAccess,
            F::IrqlTeardown,
            F::UnsupportedPool,
            F::Reenable,
        ] {
            let result = run_api_fixture(architecture, ApiFixture::Rundown(kind), 1000).unwrap();
            let report = result.kernel_cache_aware_rundown.as_ref().unwrap();
            assert_eq!(result.network.calls, 0);
            assert!(result.artifacts.is_empty());
            if kind.negative() {
                assert!(
                    result.error.is_some(),
                    "{architecture:?} {kind:?}: {result:#?}"
                );
                assert_eq!(result.guest_entry_return, None);
            } else {
                assert_eq!(result.error, None, "{architecture:?} {kind:?}: {result:#?}");
                assert_eq!(result.guest_entry_return, Some(1));
            }
            if matches!(kind, F::BlockedWait | F::BlockedFree) {
                assert_eq!(report.references.len(), 1);
                assert_eq!(report.references[0].references, 3);
                assert_eq!(
                    report.references[0].running_down,
                    matches!(kind, F::BlockedWait)
                );
                assert_eq!(report.blocked_teardowns.len(), 1);
            }
        }
    }
}
#[test]
fn rundown_budget_prefixes_never_fabricate_teardown_or_entry_return() {
    for architecture in [Architecture::X86, Architecture::X64] {
        for kind in [F::Lifecycle, F::Free, F::Zero] {
            let full = run_api_fixture(architecture, ApiFixture::Rundown(kind), 1000).unwrap();
            assert_eq!(full.error, None, "{architecture:?} {kind:?}: {full:#?}");
            for budget in 1..full.instruction_count {
                let partial =
                    run_api_fixture(architecture, ApiFixture::Rundown(kind), budget).unwrap();
                assert_eq!(partial.completion_reason, "instruction_budget");
                assert_eq!(partial.error, None);
                assert_eq!(partial.guest_entry_return, None);
                assert!(
                    partial
                        .kernel_cache_aware_rundown
                        .unwrap()
                        .blocked_teardowns
                        .is_empty()
                );
            }
        }
    }
}
