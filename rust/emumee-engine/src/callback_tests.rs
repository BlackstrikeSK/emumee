use super::*;
use emumee_core::fixtures::{ApiFixture, CallbackFixture as F};
#[test]
fn callback_fresh_kernel_and_submitted_driver_own_closed_directory_without_fixture_override() {
    for arch in [Architecture::X86, Architecture::X64] {
        for kind in [
            F::NamedCreate,
            F::NamedMissing,
            F::NamedSystem,
            F::NamedReopen,
        ] {
            let bytes = emumee_core::fixtures::api_probe(arch, ApiFixture::Callback(kind));
            for submitted in [false, true] {
                if submitted && arch == Architecture::X86 {
                    continue; // The submitted-driver entry point requires x64.
                }
                let result = if submitted {
                    run_submitted_driver(&bytes, "CallbackFixture", 2000, 30_000_000).unwrap()
                } else {
                    run_generated_image(&bytes, 2000, 30_000_000).unwrap()
                };
                assert_eq!(
                    result.error, None,
                    "{arch:?} {kind:?} submitted={submitted}: {result:#?}"
                );
                assert_eq!(result.guest_entry_return, Some(1));
                let report = result.kernel_callbacks.unwrap();
                let serialized = serde_json::to_value(&report).unwrap();
                assert_eq!(
                    serialized["namespace_authority"],
                    "OwnedFreshKernelDirectory"
                );
                assert_eq!(report.directory, Some(r"\Callback"));
                assert_eq!(report.named.callbacks_executed, 0);
                assert!(!report.named.create_requests.is_empty());
                for request in &report.named.create_requests {
                    assert!(request.error.is_none());
                    assert!(!request.name_truncated);
                    assert!(request.name.as_ref().unwrap().starts_with(r"\Callback\"));
                    assert_eq!(
                        request.result,
                        Some(if matches!(kind, F::NamedMissing) {
                            emumee_core::kernel_callbacks::STATUS_OBJECT_NAME_NOT_FOUND
                        } else {
                            0
                        })
                    );
                    assert_eq!(request.object.is_some(), request.result == Some(0));
                }
            }
        }
    }
}
#[test]
fn callback_generated_callers_preserve_registration_refs_and_never_fake_dispatch() {
    for arch in [Architecture::X86, Architecture::X64] {
        for kind in [
            F::NamespaceUnavailable,
            F::BugRegister,
            F::BugDuplicate,
            F::BugDeregister,
            F::BugTwice,
            F::BugMissing,
            F::BugReason,
            F::BugReadOnly,
            F::BugTwoRecords,
            F::NamedCreate,
            F::NamedMissing,
            F::NamedSystem,
            F::NamedReopen,
            F::NamedRegister,
            F::NamedDuplicate,
            F::NamedMultiple,
            F::NamedUnregister,
            F::NamedUnregisterTwice,
            F::NamedNotifyEmpty,
            F::NamedNotifyActive,
            F::NamedNotifySystem,
            F::NamedDereference,
            F::NamedPermanent,
            F::NamedBodyRead,
            F::NamedBodyWrite,
            F::NamedBodyCall,
            F::NamedApiRead,
            F::NamedApiWrite,
            F::NamedTokenRead,
            F::NamedIrql,
            F::NamedBadLength,
            F::NamedOddUnicode,
            F::NamedSecurity,
        ] {
            let result = run_api_fixture(arch, ApiFixture::Callback(kind), 2000).unwrap();
            let report = result.kernel_callbacks.as_ref().unwrap();
            assert_eq!(report.bugcheck.callbacks_executed, 0);
            assert_eq!(report.named.callbacks_executed, 0);
            assert_eq!(report.named.pending_invocations, 0);
            assert_eq!(result.network.calls, 0);
            if kind.negative() {
                assert!(result.error.is_some(), "{arch:?} {kind:?}: {result:#?}");
                assert_eq!(result.guest_entry_return, None);
            } else {
                assert_eq!(result.error, None, "{arch:?} {kind:?}: {result:#?}");
                assert_eq!(result.guest_entry_return, Some(1));
            }
        }
    }
}
#[test]
fn callback_budget_prefixes_never_advance_registration_or_invent_a_return() {
    for arch in [Architecture::X86, Architecture::X64] {
        for kind in [
            F::BugTwoRecords,
            F::NamedRegister,
            F::NamedUnregister,
            F::NamedNotifyEmpty,
            F::NamedDereference,
        ] {
            let full = run_api_fixture(arch, ApiFixture::Callback(kind), 2000).unwrap();
            assert_eq!(
                full.guest_entry_return,
                Some(1),
                "{arch:?} {kind:?}: {:?}",
                full.error
            );
            for budget in 1..full.instruction_count {
                let result = run_api_fixture(arch, ApiFixture::Callback(kind), budget).unwrap();
                assert_eq!(result.completion_reason, "instruction_budget");
                assert_eq!(result.error, None);
                assert_eq!(result.guest_entry_return, None);
                let report = result.kernel_callbacks.as_ref().unwrap();
                assert_eq!(report.bugcheck.callbacks_executed, 0);
                assert_eq!(report.named.callbacks_executed, 0);
            }
        }
    }
}
