use super::*;
use emumee_core::fixtures::{ApiFixture, NativeRegistryFixture as F};
const POSITIVES: [F; 13] = [
    F::Basic,
    F::Full,
    F::Retry,
    F::Relative,
    F::Roots,
    F::Missing,
    F::Rights,
    F::TypedClose,
    F::Default,
    F::Counted,
    F::Sid,
    F::InvalidClass,
    F::Truncated,
];
const NEGATIVES: [F; 8] = [
    F::ClassUnsupported,
    F::AttributesUnsupported,
    F::BadOutput,
    F::QueryReadonly,
    F::OutputOverlap,
    F::IrqlOpen,
    F::IrqlQuery,
    F::IrqlClose,
];
fn root_last_error(result: &Execution, arch: Architecture, kind: F, completed_apis: bool) {
    let root = result
        .api_events
        .iter()
        .filter(|e| e.thread_id == 1 && e.execution_domain == "ordinary_thread")
        .collect::<Vec<_>>();
    assert!(
        !root.is_empty(),
        "{arch:?} {kind:?}: missing actual root API events"
    );
    for event in &root {
        assert_eq!(
            event.last_error, 0x12345678,
            "{arch:?} {kind:?}: root {} changed LastError: {event:#?}",
            event.api
        );
    }
    let observed = root
        .iter()
        .filter(|e| e.api.ends_with(".GetLastError"))
        .collect::<Vec<_>>();
    assert_eq!(
        observed.len(),
        usize::from(completed_apis),
        "{arch:?} {kind:?}: actual root GetLastError evidence"
    );
    for event in observed {
        assert_eq!(
            event.result,
            Some(0x12345678),
            "{arch:?} {kind:?}: root GetLastError result: {event:#?}"
        );
    }
    for event in result.api_events.iter().filter(|e| e.thread_id != 1) {
        assert!(
            matches!(kind, F::TypedClose),
            "{arch:?} {kind:?}: unexpected non-root caller: {event:#?}"
        );
        assert_eq!(
            event.execution_domain, "ordinary_thread",
            "{arch:?} {kind:?}: {event:#?}"
        );
        assert_eq!(
            event.last_error, 0,
            "{arch:?} {kind:?}: fresh child API context changed LastError: {event:#?}"
        );
    }
}
#[test]
fn configured_nt_key_callers_observe_real_bytes_counts_status_lifetimes_and_last_error() {
    for arch in [Architecture::X86, Architecture::X64] {
        for kind in POSITIVES {
            let result = run_api_fixture(arch, ApiFixture::NativeRegistry(kind), 20000).unwrap();
            assert_eq!(result.error, None, "{arch:?} {kind:?}: {result:#?}");
            assert_eq!(result.guest_entry_return, Some(17), "{arch:?} {kind:?}");
            assert_eq!(result.completion_reason, "entry_return");
            assert!(result.configuration.as_ref().unwrap().initialized);
            assert_eq!(
                result.configuration.as_ref().unwrap().seeded_registry_keys,
                4
            );
            assert_eq!(result.network.calls, 0);
            assert!(result.artifacts.is_empty());
            assert_eq!(result.api_events_omitted, 0);
            assert!(result.api_events.iter().all(|e| e.error.is_none()));
            root_last_error(&result, arch, kind, true);
            let native = result.kernel_registry.as_ref().unwrap();
            assert_eq!(native.handles.live, 0, "{arch:?} {kind:?}");
            assert!(!native.native_effect_failure);
            assert_eq!(native.events_omitted, 0);
            for row in native
                .events
                .iter()
                .filter(|e| e.operation == "open" && e.status == 0)
            {
                assert!(
                    row.handle
                        >= if arch == Architecture::X64 {
                            0xffffffff80010000
                        } else {
                            0x80010000
                        }
                );
            }
            if matches!(kind, F::Retry) {
                let queries = native
                    .events
                    .iter()
                    .filter(|e| e.operation == "query")
                    .collect::<Vec<_>>();
                assert_eq!(
                    queries.iter().map(|e| e.status).collect::<Vec<_>>(),
                    [0xc0000023, 0xc0000023, 0x80000005, 0x80000005, 0]
                );
                assert_eq!(
                    queries.iter().map(|e| e.copied).collect::<Vec<_>>(),
                    [0, 0, 12, 14, 16]
                );
                assert!(queries.iter().all(|e| e.required == Some(16)));
            }
            if matches!(kind, F::TypedClose) {
                let threads = result.kernel_threads.as_ref().unwrap();
                assert_eq!(threads.count, 2);
                assert_eq!(threads.open_thread_handles, 0);
            }
        }
    }
}
#[test]
fn nt_registry_valid_unported_profiles_and_protected_outputs_stop_without_success_or_handle_leak() {
    for arch in [Architecture::X86, Architecture::X64] {
        for kind in NEGATIVES {
            let result = run_api_fixture(arch, ApiFixture::NativeRegistry(kind), 20000).unwrap();
            assert!(
                result
                    .error
                    .as_deref()
                    .unwrap()
                    .contains(kind.error().unwrap()),
                "{arch:?} {kind:?}: {result:#?}"
            );
            assert_eq!(result.guest_entry_return, None);
            assert_eq!(result.completion_reason, "error");
            let native = result.kernel_registry.as_ref().unwrap();
            let expected = usize::from(!matches!(
                kind,
                F::AttributesUnsupported | F::BadOutput | F::IrqlOpen
            ));
            assert_eq!(native.handles.live, expected, "{arch:?} {kind:?}");
            assert_eq!(native.handles.lifetime_issues, expected as u64);
            if matches!(kind, F::IrqlOpen | F::IrqlQuery | F::IrqlClose) {
                assert_eq!(result.kernel_state.as_ref().unwrap().irql, 2);
                assert_eq!(native.events.len(), expected);
                assert!(native.events.iter().all(|e| e.operation == "open"));
                if arch == Architecture::X64 {
                    assert_eq!(result.cpu.cr8_writes, 1);
                }
            }
            assert!(!native.native_effect_failure);
            assert!(result.artifacts.is_empty());
            assert_eq!(result.network.calls, 0);
            root_last_error(&result, arch, kind, false);
        }
    }
}
#[test]
fn nt_registry_exact_budget_prefixes_preserve_actual_effects_without_entry_completion() {
    for arch in [Architecture::X86, Architecture::X64] {
        for kind in POSITIVES {
            let full = run_api_fixture(arch, ApiFixture::NativeRegistry(kind), 20000).unwrap();
            assert_eq!(
                full.guest_entry_return,
                Some(17),
                "{arch:?} {kind:?}: {full:#?}"
            );
            let budget = full.instruction_count - 1;
            let prefix = run_api_fixture(arch, ApiFixture::NativeRegistry(kind), budget).unwrap();
            assert_eq!(prefix.error, None, "{arch:?} {kind:?}: {prefix:#?}");
            assert_eq!(prefix.completion_reason, "instruction_budget");
            assert_eq!(prefix.guest_entry_return, None);
            assert_eq!(prefix.instruction_count, budget);
            assert_eq!(prefix.kernel_registry.as_ref().unwrap().handles.live, 0);
            assert!(prefix.configuration.as_ref().unwrap().initialized);
        }
    }
}
