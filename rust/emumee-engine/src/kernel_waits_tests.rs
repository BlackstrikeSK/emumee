use super::*;
use emumee_core::fixtures::{ApiFixture, WaitFixture as W};
const CASES: [W; 27] = [
    W::DelayRelative,
    W::DelayAbsolute,
    W::DelayZero,
    W::DelayChild,
    W::DelayMode,
    W::DelayAlertable,
    W::DelayIrql,
    W::DelayUnreadable,
    W::Any,
    W::All,
    W::AllBlocked,
    W::Mixed,
    W::Timeout,
    W::Poll,
    W::Four,
    W::CountZero,
    W::Count65,
    W::Type,
    W::Duplicate,
    W::UserMode,
    W::Alertable,
    W::MissingBlocks,
    W::ReadonlyBlocks,
    W::BadArray,
    W::Unknown,
    W::Irql,
    W::Tamper,
];
fn refusal(kind: W) -> &'static str {
    match kind {
        W::DelayMode | W::DelayAlertable => "Alertable/UserMode kernel delay",
        W::DelayIrql => "delay above APC_LEVEL",
        W::DelayUnreadable | W::ReadonlyBlocks | W::BadArray => {
            "System-thread argument range is not accessible"
        }
        W::CountZero | W::Count65 | W::Type => "Invalid multiple kernel wait count/type",
        W::Duplicate => "Duplicate dispatcher objects",
        W::UserMode | W::Alertable => "Alertable/UserMode multiple kernel wait",
        W::MissingBlocks => "wait-block storage",
        W::Unknown => "unknown event",
        W::Irql => "blocking wait above APC_LEVEL",
        W::Tamper => "Guest event state diverges from scheduler",
        _ => unreachable!(),
    }
}
#[test]
fn actual_wait_any_all_mixed_and_delay_continuations_preserve_owned_state_and_status() {
    for architecture in [Architecture::X86, Architecture::X64] {
        for kind in CASES {
            let result = run_api_fixture(architecture, ApiFixture::Waits(kind), 10000).unwrap();
            assert_eq!(result.network.calls, 0);
            assert!(result.artifacts.is_empty());
            let threads = result.kernel_threads.as_ref().unwrap();
            assert!(
                !threads.native_wait_effect_failure,
                "{architecture:?} {kind:?}: {result:#?}"
            );
            let owned = result.kernel_thread_objects.as_ref().unwrap();
            assert!(!owned.native_effect_failure);
            let caller = owned
                .threads
                .iter()
                .find(|record| record.slot == 1)
                .unwrap();
            assert!(
                caller.root_caller && caller.executing && !caller.terminated && !caller.retired
            );
            if kind.negative() {
                assert_eq!(result.completion_reason, "error");
                assert_eq!(result.guest_entry_return, None);
                assert!(
                    result
                        .error
                        .as_deref()
                        .unwrap_or("")
                        .contains(refusal(kind)),
                    "{architecture:?} {kind:?}: {result:#?}"
                );
                assert_eq!(threads.exited, 0);
                assert_eq!(threads.waits, 0);
                assert_eq!(threads.resumed_waits, 0);
            } else {
                assert_eq!(result.error, None, "{architecture:?} {kind:?}: {result:#?}");
                assert_eq!(result.guest_entry_return, Some(1));
                assert_eq!(result.completion_reason, "entry_return");
                if matches!(kind, W::DelayRelative | W::DelayAbsolute | W::DelayChild) {
                    assert!(threads.resumed_waits >= 1);
                    assert!(result.api_events.iter().any(|event| event.api
                        == "ntoskrnl.KeDelayExecutionThread"
                        && event.result == Some(0)
                        && event.effect == Some("delay_elapsed")
                        && !event.pending));
                }
                if matches!(kind, W::AllBlocked | W::Mixed) {
                    assert!(result.api_events.iter().any(|event| event.api
                        == "ntoskrnl.KeWaitForMultipleObjects"
                        && event.result == Some(0)
                        && event.effect == Some("multiple_wait_satisfied")
                        && !event.pending));
                }
                if matches!(kind, W::Timeout) {
                    assert!(result.api_events.iter().any(|event| event.api
                        == "ntoskrnl.KeWaitForMultipleObjects"
                        && event.result == Some(0x102)
                        && event.effect == Some("wait_timeout")
                        && !event.pending));
                }
                if kind.child() {
                    assert_eq!(threads.count, 2);
                    assert_eq!(threads.exited, 2);
                    assert_eq!(threads.open_thread_handles, 0);
                    let child = owned
                        .threads
                        .iter()
                        .find(|record| record.slot == 2)
                        .unwrap();
                    assert!(
                        child.terminated
                            && child.retired
                            && !child.executing
                            && child.open_handles == 0
                    );
                    assert!(owned.handles.is_empty());
                } else {
                    assert_eq!(threads.count, 1);
                    assert_eq!(threads.exited, 1);
                }
            }
        }
    }
}
#[test]
fn wait_budget_prefixes_never_complete_a_pending_api_or_consume_root_caller_ownership() {
    for architecture in [Architecture::X86, Architecture::X64] {
        for kind in CASES.into_iter().filter(|kind| !kind.negative()) {
            let full = run_api_fixture(architecture, ApiFixture::Waits(kind), 10000).unwrap();
            assert_eq!(full.error, None);
            for budget in [1, full.instruction_count - 1] {
                let partial =
                    run_api_fixture(architecture, ApiFixture::Waits(kind), budget).unwrap();
                assert_eq!(
                    partial.error, None,
                    "{architecture:?} {kind:?}: {partial:#?}"
                );
                assert_eq!(partial.completion_reason, "instruction_budget");
                assert_eq!(partial.guest_entry_return, None);
                assert_eq!(partial.instruction_count, budget);
                let caller = &partial.kernel_thread_objects.as_ref().unwrap().threads[0];
                assert!(caller.root_caller && caller.executing && !caller.terminated);
                for event in partial.api_events.iter().filter(|event| event.pending) {
                    assert_eq!(event.result, None);
                }
            }
        }
    }
}
