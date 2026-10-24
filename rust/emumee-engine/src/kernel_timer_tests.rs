use super::*;
use emumee_core::fixtures::{ApiFixture, TimerFixture as F};
const POSITIVE: [F; 14] = [
    F::Initialize,
    F::Relative,
    F::Synchronization,
    F::AbsolutePast,
    F::AbsoluteFuture,
    F::LargeDue,
    F::Replacement,
    F::Periodic,
    F::Polling,
    F::MixedAny,
    F::MixedAll,
    F::Child,
    F::DpcCancel,
    F::PoolLifetime,
];
const NEGATIVE: [F; 15] = [
    F::DueDpc,
    F::PendingDpc,
    F::DpcRead,
    F::DpcWait,
    F::Reinitialize,
    F::NegativePeriod,
    F::UnknownDpc,
    F::Readonly,
    F::Paged,
    F::DirectWrite,
    F::ApiWrite,
    F::InsertedFree,
    F::AliasAfter,
    F::HighIrql,
    F::DpcRoutine,
];
fn metadata(e: &Execution, arch: Architecture, kind: F, partial: bool) {
    assert_eq!(e.network.calls, 0);
    assert_eq!(e.api_events_omitted, 0);
    assert!(e.artifacts.is_empty());
    assert!(
        e.kernel_ipi
            .as_ref()
            .unwrap()
            .rendezvous
            .broadcasts
            .is_empty()
    );
    let pool = e.kernel_pool.as_ref().unwrap();
    let (allocations, frees) = match kind {
        F::PoolLifetime => (2, 2),
        F::Paged | F::InsertedFree => (1, 0),
        _ => (0, 0),
    };
    assert_eq!(
        (pool.total_allocations, pool.total_frees),
        (allocations, frees),
        "{arch:?} {kind:?}"
    );
    assert_eq!(pool.allocations.len(), (allocations - frees) as usize);
    for event in &e.api_events {
        assert!(matches!(event.thread_id, 1 | 2));
        assert_eq!(event.execution_domain, "ordinary_thread");
        assert_eq!(
            event.last_error,
            if event.thread_id == 1 {
                0x12345678
            } else {
                0x87654321
            },
            "{arch:?} {kind:?}: {event:?}"
        );
        if event.api.ends_with(".KeInitializeTimer")
            || event.api.ends_with(".KeInitializeTimerEx")
            || event.api.ends_with(".KeInitializeDpc")
        {
            assert_eq!(event.result, None);
        }
    }
    if matches!(kind, F::Readonly | F::Paged | F::DpcRoutine) {
        assert!(e.kernel_threads.is_none());
        return;
    }
    let threads = e.kernel_threads.as_ref().unwrap();
    assert_eq!(threads.count, if matches!(kind, F::Child) { 2 } else { 1 });
    assert!(!threads.native_wait_effect_failure);
    assert_eq!(
        threads.timer_native_effect_failure,
        matches!(kind, F::DirectWrite)
    );
    assert!(threads.timer_guards_installed);
    assert_eq!(
        threads.timer_guest_denials,
        u64::from(matches!(kind, F::DirectWrite))
    );
    assert_eq!(threads.timer_stop.is_some(), matches!(kind, F::DirectWrite));
    let initializations = if matches!(kind, F::Initialize | F::MixedAny | F::PoolLifetime) {
        2
    } else {
        1
    };
    assert_eq!(threads.timer_initializations, initializations);
    assert_eq!(
        threads.timers.len(),
        if matches!(kind, F::PoolLifetime) {
            0
        } else {
            initializations as usize
        }
    );
    let dispatch = &threads.dpc;
    let ran = matches!(kind, F::DueDpc | F::DpcRead | F::DpcWait);
    assert_eq!(dispatch.version, "cpu0-dpc-dispatch-v1");
    assert!(!dispatch.native_effect_failure);
    assert_eq!(
        dispatch.counters.started,
        u64::from(ran),
        "{arch:?} {kind:?}"
    );
    assert_eq!(
        dispatch.counters.returned,
        u64::from(ran),
        "{arch:?} {kind:?}"
    );
    assert_eq!(
        dispatch.counters.restored,
        u64::from(ran),
        "{arch:?} {kind:?}"
    );
    if ran {
        assert!(dispatch.invocations[0].caller_restored);
        assert!(dispatch.invocations[0].return_instruction.is_some());
        assert!(e.api_events.iter().all(|event| !event.pending));
        assert!(
            dispatch.invocations[0].return_instruction.unwrap()
                > dispatch.invocations[0].start_instruction
        );
    }
    let dpcs = u64::from(kind.dpc());
    assert_eq!(threads.dpc_initializations, dpcs);
    assert_eq!(threads.dpcs_initialized.len(), dpcs as usize);
    let inserted = matches!(
        kind,
        F::PendingDpc | F::Reinitialize | F::InsertedFree | F::BudgetPending
    );
    for timer in &threads.timers {
        assert_eq!(timer.architecture, arch);
        assert_eq!(timer.inserted, inserted);
        if matches!(
            kind,
            F::Relative
                | F::AbsolutePast
                | F::AbsoluteFuture
                | F::Polling
                | F::MixedAny
                | F::Child
                | F::Periodic
                | F::DueDpc
                | F::DpcRead
                | F::DpcWait
        ) {
            assert!(timer.signaled, "{arch:?} {kind:?}: {timer:?}");
        } else {
            assert!(!timer.signaled, "{arch:?} {kind:?}: {timer:?}");
        }
        if matches!(kind, F::Periodic) {
            assert_eq!(timer.period_ms, 1);
            assert!(timer.due > e.virtual_uptime_ms * 10_000);
        } else {
            assert_eq!(timer.period_ms, 0);
        }
        if matches!(kind, F::DueDpc | F::DpcRead | F::DpcWait) {
            assert_ne!(timer.dpc, 0);
        }
        if matches!(kind, F::LargeDue) {
            assert!(timer.due > 523812000u64 * 10_000 + 0x100000000);
        }
    }
    if matches!(kind, F::AbsoluteFuture) {
        assert_eq!(threads.timers[0].due, 523812000u64 * 10_000 + 100000);
        assert!(e.virtual_uptime_ms >= 523812010);
    }
    if matches!(kind, F::Child) {
        assert!(threads.switches >= 2);
        assert!(
            e.api_events.iter().any(
                |event| event.thread_id == 2 && event.api.ends_with(".PsTerminateSystemThread")
            )
        );
    }
    if matches!(kind, F::Periodic | F::Child) {
        let delays: Vec<_> = e
            .api_events
            .iter()
            .filter(|v| v.api.ends_with(".KeDelayExecutionThread"))
            .collect();
        assert_eq!(delays.len(), 1);
        assert_eq!(delays[0].effect, Some("delay_elapsed"));
        assert_eq!(delays[0].result, Some(0));
        assert!(!delays[0].pending);
        assert!(
            e.virtual_uptime_ms
                >= if matches!(kind, F::Periodic) {
                    523812004
                } else {
                    523812003
                }
        );
    }
    if matches!(kind, F::PendingDpc) {
        assert_eq!(threads.root_entry_return, Some(17));
    } else if partial || kind.error().is_some() || kind.budget() {
        assert_eq!(threads.root_entry_return, None);
    } else {
        assert_eq!(threads.root_entry_return, Some(17));
    }
}
#[test]
fn actual_timers_expire_wait_consume_cancel_coalesce_poll_and_preserve_context_in_both_abis() {
    for arch in [Architecture::X86, Architecture::X64] {
        for kind in POSITIVE {
            let e = run_api_fixture(arch, ApiFixture::KernelTimers(kind), 20000).unwrap();
            assert_eq!(e.error, None, "{arch:?} {kind:?}: {e:#?}");
            assert_eq!(e.guest_entry_return, Some(17), "{arch:?} {kind:?}");
            assert_eq!(e.completion_reason, "entry_return");
            metadata(&e, arch, kind, false);
            assert!(
                e.api_events
                    .iter()
                    .all(|event| event.error.is_none() && !event.pending)
            );
            let last = e.api_events.last().unwrap();
            assert!(last.api.ends_with(".GetLastError"));
            assert_eq!(last.result, Some(0x12345678));
        }
    }
}
#[test]
fn literal_bad_marker_callbacks_really_execute_and_invalid_profiles_still_refuse() {
    for arch in [Architecture::X86, Architecture::X64] {
        for kind in NEGATIVE {
            let e = run_api_fixture(arch, ApiFixture::KernelTimers(kind), 20000).unwrap();
            assert!(
                e.error.as_deref().unwrap().contains(kind.error().unwrap()),
                "{arch:?} {kind:?}: {e:#?}"
            );
            assert_eq!(e.guest_entry_return, None);
            assert_eq!(e.completion_reason, "error");
            metadata(&e, arch, kind, false);
            if matches!(
                kind,
                F::PendingDpc | F::DueDpc | F::DpcRead | F::DpcWait | F::DirectWrite
            ) {
                assert!(e.api_events.iter().all(|event| event.error.is_none()));
            } else {
                assert!(e.api_events.last().unwrap().error.is_some());
            }
        }
    }
}
#[test]
fn future_pending_dpc_budget_retains_metadata_without_inventing_callback_or_root_return() {
    for arch in [Architecture::X86, Architecture::X64] {
        let e = run_api_fixture(arch, ApiFixture::KernelTimers(F::BudgetPending), 2000).unwrap();
        assert_eq!(e.error, None, "{arch:?}: {e:#?}");
        assert_eq!(e.instruction_count, 2000);
        assert_eq!(e.completion_reason, "instruction_budget");
        assert_eq!(e.guest_entry_return, None);
        metadata(&e, arch, F::BudgetPending, true);
        assert!(
            e.api_events
                .iter()
                .all(|event| event.error.is_none() && !event.pending)
        );
    }
}
#[test]
fn before_return_timer_prefixes_keep_true_expiration_and_wait_effects_without_success_label() {
    for arch in [Architecture::X86, Architecture::X64] {
        for kind in POSITIVE {
            let full = run_api_fixture(arch, ApiFixture::KernelTimers(kind), 20000).unwrap();
            assert_eq!(
                full.guest_entry_return,
                Some(17),
                "{arch:?} {kind:?}: {full:#?}"
            );
            let budget = full.instruction_count - 1;
            let e = run_api_fixture(arch, ApiFixture::KernelTimers(kind), budget).unwrap();
            assert_eq!(e.error, None, "{arch:?} {kind:?}: {e:#?}");
            assert_eq!(e.instruction_count, budget);
            assert_eq!(e.completion_reason, "instruction_budget");
            assert_eq!(e.guest_entry_return, None);
            metadata(&e, arch, kind, true);
        }
    }
}
