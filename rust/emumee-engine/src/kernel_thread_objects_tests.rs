use super::*;
use emumee_core::fixtures::{ApiFixture, ThreadObjectFixture as F};
const CASES: [F; 24] = [
    F::Lifecycle,
    F::ChildReturn,
    F::CloseAfterExit,
    F::InvalidHandle,
    F::ClosedHandle,
    F::TypeMismatch,
    F::UserTypeMismatch,
    F::KernelAccess,
    F::UserMode,
    F::ReadonlyOutput,
    F::InformationOutput,
    F::Irql,
    F::ForeignHandle,
    F::ReleasedWait,
    F::ReleasedReference,
    F::ReleasedRead,
    F::RootHeader,
    F::RootPrivateCross,
    F::RootPreviousPageCross,
    F::RootHeaderWrite,
    F::RootApiWrite,
    F::RootTerminate,
    F::HeaderReadBenchmark,
    F::OrdinaryReadBenchmark,
];
fn budget(kind: F) -> u64 {
    if kind.benchmark() { 100000 } else { 1000 }
}
#[test]
fn generated_x64_system_thread_accepts_unnamed_kernel_handle_attributes_only() {
    let accepted = run_api_fixture(
        Architecture::X64,
        ApiFixture::ThreadObjects(F::ObjectAttributes),
        1000,
    )
    .unwrap();
    assert_eq!(accepted.error, None);
    assert_eq!(accepted.guest_entry_return, Some(1));
    assert!(accepted.api_events.iter().any(|event| {
        event.api == "ntoskrnl.PsCreateSystemThread"
            && event.arguments[1] == 0x1fffff
            && event.arguments[2] == 0x140002e00
            && event.arguments[3] == 0
            && event.result == Some(0)
    }));
    let report = accepted.kernel_thread_objects.as_ref().unwrap();
    assert!(
        report
            .threads
            .iter()
            .any(|thread| thread.slot == 2 && thread.terminated)
    );

    let named = run_api_fixture(
        Architecture::X64,
        ApiFixture::ThreadObjects(F::ObjectAttributesNamed),
        1000,
    )
    .unwrap();
    assert!(
        named
            .error
            .as_deref()
            .unwrap_or("")
            .contains("System-thread OBJECT_ATTRIBUTES name/root/security/flags are not modeled")
    );
    assert_eq!(named.guest_entry_return, None);
    assert!(
        !named.api_events.iter().any(|event| {
            event.api == "ntoskrnl.PsCreateSystemThread" && event.result == Some(0)
        })
    );
    let report = named.kernel_thread_objects.as_ref().unwrap();
    assert_eq!(report.threads.len(), 1);
    assert!(report.handles.is_empty());
}
#[test]
fn actual_scheduler_handles_joins_and_refcounts_share_the_same_thread_object_lifetime() {
    for architecture in [Architecture::X86, Architecture::X64] {
        for kind in CASES {
            let result =
                run_api_fixture(architecture, ApiFixture::ThreadObjects(kind), budget(kind))
                    .unwrap();
            let report = result.kernel_thread_objects.as_ref().unwrap();
            let objects = result.kernel_objects.as_ref().unwrap();
            let layout = emumee_core::kernel_layout::KernelLayout::for_architecture(architecture);
            assert!(report.read_guard_installed);
            assert!(!report.native_effect_failure);
            assert_eq!(result.network.calls, 0);
            assert!(result.artifacts.is_empty());
            let root = report
                .threads
                .iter()
                .find(|record| record.slot == 1)
                .unwrap();
            assert_eq!(root.address, layout.root_thread);
            assert!(root.root_caller && root.executing && !root.terminated && !root.retired);
            assert_eq!(root.open_handles, 0);
            if kind.negative() {
                let error = result.error.as_deref().unwrap_or("");
                let expected = match kind {
                    F::UserMode => "UserMode thread handle security",
                    F::ReadonlyOutput => "lacks permission",
                    F::InformationOutput => "handle-information",
                    F::Irql => "PASSIVE_LEVEL",
                    F::ForeignHandle => "Foreign process/file",
                    F::ReleasedWait => "released thread object",
                    F::ReleasedReference => "live owned object body",
                    F::ReleasedRead => "READ_PROT",
                    F::RootPrivateCross | F::RootPreviousPageCross => {
                        "private or released kernel thread body read"
                    }
                    F::RootHeaderWrite => "WRITE_PROT",
                    F::RootApiWrite => "private or released kernel thread body access",
                    F::RootTerminate => "outside a spawned system thread",
                    _ => unreachable!(),
                };
                assert!(
                    error.contains(expected)
                        || matches!(kind, F::ReleasedRead)
                            && error.contains("private or released kernel thread body read"),
                    "{architecture:?} {kind:?}: {result:#?}"
                );
                assert_eq!(result.guest_entry_return, None);
            } else {
                assert_eq!(result.error, None, "{architecture:?} {kind:?}: {result:#?}");
                assert_eq!(result.guest_entry_return, Some(1));
            }
            if kind.root_only() {
                assert_eq!(report.threads.len(), 1);
                assert!(report.handles.is_empty());
                if matches!(kind, F::RootTerminate) {
                    assert!(
                        result
                            .kernel_threads
                            .as_ref()
                            .is_none_or(|threads| threads.exited == 0
                                && threads.root_entry_return.is_none())
                    );
                }
            } else {
                let child = report
                    .threads
                    .iter()
                    .find(|record| record.slot == 2)
                    .unwrap();
                assert_eq!(child.address, layout.thread_object(2).unwrap());
                let record = objects
                    .objects
                    .iter()
                    .find(|record| record.address == child.address)
                    .unwrap();
                if !kind.negative()
                    || matches!(
                        kind,
                        F::ReleasedWait | F::ReleasedReference | F::ReleasedRead
                    )
                {
                    assert!(child.terminated && child.retired && !child.executing);
                    assert_eq!(child.open_handles, 0);
                    assert!(report.handles.is_empty());
                    assert_eq!(record.api_references, 0);
                    assert_eq!(record.permanent_references, 0);
                    assert!(!record.live);
                    assert!(
                        result
                            .api_events
                            .iter()
                            .any(|event| event.effect == Some("thread_signaled") && !event.pending)
                    );
                } else {
                    assert!(child.executing && !child.terminated && !child.retired);
                    assert_eq!(child.open_handles, 1);
                    assert_eq!(report.handles.len(), 1);
                    assert_eq!(report.handles[0].object, child.address);
                    assert_eq!(report.handles[0].owner, 4);
                    assert!(report.handles[0].kernel_only);
                    assert_eq!(record.api_references, 0);
                    assert_eq!(record.permanent_references, 2);
                }
                if matches!(kind, F::KernelAccess) {
                    assert!(
                        result
                            .api_events
                            .iter()
                            .any(|event| event.api == "ntoskrnl.PsCreateSystemThread"
                                && event.arguments[1] == 0)
                    );
                    assert!(
                        result
                            .api_events
                            .iter()
                            .any(|event| event.api == "ntoskrnl.ObReferenceObjectByHandle"
                                && event.arguments[1] == 0x100000
                                && event.result == Some(0))
                    );
                }
            }
        }
    }
}
#[test]
fn actual_thread_reference_budget_prefixes_preserve_caller_and_do_not_invent_child_exit() {
    for architecture in [Architecture::X86, Architecture::X64] {
        for kind in CASES.into_iter().filter(|kind| !kind.negative()) {
            let full = run_api_fixture(architecture, ApiFixture::ThreadObjects(kind), budget(kind))
                .unwrap();
            assert_eq!(full.error, None);
            for budget in [1, full.instruction_count - 1] {
                let partial =
                    run_api_fixture(architecture, ApiFixture::ThreadObjects(kind), budget).unwrap();
                assert_eq!(partial.completion_reason, "instruction_budget");
                assert_eq!(partial.guest_entry_return, None);
                assert_eq!(partial.error, None);
                let report = partial.kernel_thread_objects.as_ref().unwrap();
                assert!(!report.threads[0].retired && !report.threads[0].terminated);
                if budget == 1 {
                    assert_eq!(report.threads.len(), 1);
                    assert!(report.handles.is_empty());
                }
            }
        }
    }
}
#[test]
fn owned_repeat_read_programs_record_guard_cost_without_claiming_a_speedup() {
    for architecture in [Architecture::X86, Architecture::X64] {
        let header = run_api_fixture(
            architecture,
            ApiFixture::ThreadObjects(F::HeaderReadBenchmark),
            100000,
        )
        .unwrap();
        let ordinary = run_api_fixture(
            architecture,
            ApiFixture::ThreadObjects(F::OrdinaryReadBenchmark),
            100000,
        )
        .unwrap();
        assert_eq!(header.error, None);
        assert_eq!(ordinary.error, None);
        assert_eq!(header.instruction_count, ordinary.instruction_count);
        assert!(
            header
                .kernel_thread_objects
                .as_ref()
                .unwrap()
                .read_guard_checks
                >= 10000
        );
        assert!(
            ordinary
                .kernel_thread_objects
                .as_ref()
                .unwrap()
                .read_guard_checks
                >= 10000
        );
        assert!(header.engine_seconds > 0.0 && ordinary.engine_seconds > 0.0);
    }
}

#[test]
fn actual_child_priority_returns_previous_base_in_both_architectures() {
    for architecture in [Architecture::X86, Architecture::X64] {
        let layout = emumee_core::kernel_layout::KernelLayout::for_architecture(architecture);
        let child = layout.thread_object(2).unwrap();
        for (kind, valid) in [
            (F::Priority, true),
            (F::PriorityInvalid, false),
            (F::PriorityForeign, false),
        ] {
            let result =
                run_api_fixture(architecture, ApiFixture::ThreadObjects(kind), 1000).unwrap();
            let thread = result
                .kernel_threads
                .as_ref()
                .unwrap()
                .states
                .iter()
                .find(|thread| thread.slot == 2)
                .unwrap();
            assert_eq!(thread.priority, if valid { 15 } else { 8 });
            let event = result
                .api_events
                .iter()
                .find(|event| event.api == "ntoskrnl.KeSetActualBasePriorityThread")
                .unwrap();
            assert_eq!(
                event.arguments,
                vec![
                    if matches!(kind, F::PriorityForeign) {
                        if architecture == Architecture::X64 {
                            0x140002c30
                        } else {
                            0x402c30
                        }
                    } else {
                        child
                    },
                    if matches!(kind, F::PriorityInvalid) {
                        0
                    } else {
                        15
                    }
                ]
            );
            assert_eq!(event.result, if valid { Some(8) } else { None });
            assert_eq!(event.thread_id, 2);
            if valid {
                assert_eq!(result.completion_reason, "entry_return", "{result:#?}");
                assert_eq!(result.guest_entry_return, Some(1));
                assert_eq!(event.error, None);
            } else {
                assert_eq!(result.completion_reason, "error");
                assert_eq!(result.guest_entry_return, None);
                assert!(event.error.is_some());
            }
        }
    }
}
