use super::*;
use emumee_core::fixtures::{ApiFixture, ObjectFixture as F};
#[test]
fn owned_kernel_identity_callers_preserve_system_driver_and_type_ownership() {
    for architecture in [Architecture::X86, Architecture::X64] {
        for kind in [
            F::Lifecycle,
            F::DataOnly,
            F::KernelMismatch,
            F::UserMismatch,
            F::UserAccess,
            F::Mode,
            F::Underflow,
            F::Foreign,
            F::Irql,
            F::GlobalWrite,
            F::GlobalCall,
            F::IdentityRead,
            F::IdentityCall,
            F::TypeRead,
            F::TypeCall,
            F::ApiIdentityRead,
            F::ApiIdentityWrite,
            F::ByHandle,
        ] {
            let result = run_api_fixture(architecture, ApiFixture::Objects(kind), 1000).unwrap();
            let report = result.kernel_objects.as_ref().unwrap();
            let layout = emumee_core::kernel_layout::KernelLayout::for_architecture(architecture);
            assert_eq!(report.system_process, Some(layout.driver_object + 0x3000));
            assert_eq!(report.system_pid, 4);
            assert_eq!(report.driver_object, Some(layout.driver_object));
            assert!(report.driver_object_initialized);
            assert_eq!(report.types.len(), 12);
            assert_eq!(report.storage.len(), 13);
            assert!(!report.native_effect_failure);
            assert_eq!(result.network.calls, 0);
            assert!(result.artifacts.is_empty());
            assert_eq!(report.objects.len(), 3);
            assert!(
                report
                    .objects
                    .iter()
                    .all(|record| record.permanent_references == 1
                        && record.api_references == 0
                        && record.live)
            );
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
            if matches!(kind, F::DataOnly) {
                assert_eq!(result.api_calls, 0);
            }
            if matches!(kind, F::Lifecycle) {
                assert_eq!(report.events.len(), 6);
                assert_eq!(result.api_calls, 9);
            }
            if matches!(kind, F::KernelMismatch) {
                assert_eq!(report.events.len(), 2);
            }
            if matches!(
                kind,
                F::UserMismatch
                    | F::UserAccess
                    | F::Mode
                    | F::Underflow
                    | F::Foreign
                    | F::Irql
                    | F::ByHandle
            ) {
                assert!(report.events.is_empty());
            }
        }
    }
}
#[test]
fn owned_identity_budget_stops_do_not_fabricate_reference_effects_or_entry_return() {
    for architecture in [Architecture::X86, Architecture::X64] {
        for kind in [
            F::Lifecycle,
            F::DataOnly,
            F::KernelMismatch,
            F::UserMismatch,
        ] {
            let full = run_api_fixture(architecture, ApiFixture::Objects(kind), 1000).unwrap();
            assert_eq!(full.error, None);
            for budget in [1, full.instruction_count - 1] {
                let partial =
                    run_api_fixture(architecture, ApiFixture::Objects(kind), budget).unwrap();
                assert_eq!(partial.completion_reason, "instruction_budget");
                assert_eq!(partial.guest_entry_return, None);
                assert_eq!(partial.error, None);
                if budget == 1 {
                    assert!(partial.kernel_objects.as_ref().unwrap().events.is_empty());
                }
            }
        }
    }
}
