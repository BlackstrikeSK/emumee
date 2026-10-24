use super::*;
use emumee_core::fixtures::{ApiFixture, SpinFixture as F};
const POSITIVE: [F; 10] = [
    F::Basic,
    F::Nested,
    F::OldApc,
    F::Critical,
    F::Pool,
    F::ReusedPool,
    F::Scheduler,
    F::NativeQuantum,
    F::ApcQuantum,
    F::IpiRestored,
];
const NEGATIVE: [F; 21] = [
    F::Recursive,
    F::ReleaseUnowned,
    F::SavedIrql,
    F::OutOfOrder,
    F::HeldExit,
    F::HeldFree,
    F::LowerHeld,
    F::DirectLowerHeld,
    F::DirectWrite,
    F::ApiWrite,
    F::Readonly,
    F::Unaligned,
    F::InvalidRange,
    F::Paged,
    F::UnsupportedBacking,
    F::AliasFirst,
    F::AliasAfter,
    F::LiteralAlias,
    F::HighIrql,
    F::IpiWhileHeld,
    F::ReuseUninitialized,
];
fn expected(kind: F) -> (u64, u64, usize, u8) {
    use F::*;
    match kind {
        Basic | Critical | Pool | Scheduler | IpiRestored => (1, 3, 0, 0),
        OldApc => (1, 3, 0, 0),
        Nested | ReusedPool => (2, 6, 0, 0),
        NativeQuantum | ApcQuantum | Readonly | Unaligned | InvalidRange | Paged
        | UnsupportedBacking | AliasFirst | LiteralAlias => (0, 0, 0, 0),
        Recursive | SavedIrql | HeldExit | HeldFree | LowerHeld | DirectWrite | IpiWhileHeld
        | HeldBudget => (1, 2, 1, 2),
        DirectLowerHeld => (1, 2, 1, 0),
        ReleaseUnowned | ApiWrite | AliasAfter => (1, 1, 0, 0),
        OutOfOrder => (2, 4, 2, 2),
        HighIrql => (1, 1, 0, 3),
        ReuseUninitialized => (1, 3, 0, 0),
        NativeBudget => (0, 0, 0, 2),
    }
}
fn metadata(result: &Execution, arch: Architecture, kind: F) {
    let k = result.kernel_state.as_ref().unwrap();
    let (initializations, transitions, held, irql) = expected(kind);
    assert_eq!(
        (
            k.spin.initializations,
            k.spin.transitions,
            k.spin.held().count(),
            k.irql
        ),
        (initializations, transitions, held, irql),
        "{arch:?} {kind:?}: {k:#?}"
    );
    assert_eq!(k.spin.native_effect_failure, matches!(kind, F::DirectWrite));
    assert_eq!(
        k.spin_guest_denials,
        u64::from(matches!(kind, F::DirectWrite))
    );
    assert_eq!(k.spin_guard_installed, initializations != 0);
    for record in k.spin.records() {
        assert_eq!(record.width, arch.width());
        assert!(record.address.is_multiple_of(arch.width() as u64));
        if let Some(owner) = record.held {
            assert_eq!(owner.owner.processor, 0);
            assert_eq!(
                owner.owner.thread,
                emumee_core::kernel_layout::KernelLayout::for_architecture(arch).root_thread
            );
        }
    }
    assert_eq!(k.critical_depth, 0);
    assert_eq!(k.owned_mutexes, 0);
    assert_eq!(result.api_events_omitted, 0);
    assert_eq!(result.network.calls, 0);
    for event in &result.api_events {
        assert_eq!(
            event.execution_domain, "ordinary_thread",
            "{arch:?} {kind:?}: {event:?}"
        );
        assert_eq!(
            event.last_error,
            if event.thread_id == 1 {
                0x12345678
            } else {
                0x87654321
            },
            "{arch:?} {kind:?}: {event:?}"
        );
        assert!(matches!(event.thread_id, 1 | 2));
    }
    let pool = result.kernel_pool.as_ref().unwrap();
    let (allocs, frees) = match kind {
        F::Pool => (1, 1),
        F::ReusedPool => (2, 2),
        F::ReuseUninitialized => (2, 1),
        F::HeldFree | F::Paged | F::AliasAfter => (1, 0),
        F::AliasFirst => (2, 0),
        _ => (0, 0),
    };
    assert_eq!(
        (
            pool.total_allocations,
            pool.total_frees,
            pool.allocations.len()
        ),
        (allocs, frees, (allocs - frees) as usize),
        "{arch:?} {kind:?}"
    );
    if matches!(kind, F::Pool | F::ReusedPool | F::ReuseUninitialized) {
        assert!(k.spin.records().all(|r| !r.live));
    }
    if matches!(kind, F::AliasFirst) {
        assert_eq!(result.artifacts.len(), 2);
        assert!(
            result.artifacts.iter().all(|a| a
                .observations
                .iter()
                .all(|o| o.kind == ArtifactKind::MemorySnapshot
                    && o.source.starts_with("kernel_mdl_")))
        );
    } else {
        assert!(result.artifacts.is_empty(), "{arch:?} {kind:?}");
    }
    let ipi = result.kernel_ipi.as_ref().unwrap();
    if matches!(kind, F::IpiRestored) {
        assert_eq!(ipi.rendezvous.broadcasts.len(), 1);
        assert!(ipi.rendezvous.broadcasts[0].completed);
        assert_eq!(ipi.rendezvous.broadcasts[0].source_result, Some(0xbeef));
        assert_eq!(ipi.current_processor, 0);
    } else {
        assert!(ipi.rendezvous.broadcasts.is_empty());
    }
    if kind.scheduler() {
        let t = result.kernel_threads.as_ref().unwrap();
        assert_eq!(t.count, 2);
        assert!(!t.native_wait_effect_failure);
        if matches!(kind, F::ApcQuantum) {
            assert_eq!(t.suppressed_quanta, 0);
        } else {
            assert!(t.suppressed_quanta > 0, "{arch:?} {kind:?}: {t:#?}");
        }
        if kind.budget() {
            assert_eq!(t.switches, 0);
            assert_eq!(t.exited, 0);
            assert!(t.root_entry_return.is_none());
            assert!(result.api_events.iter().all(|e| e.thread_id == 1));
        } else {
            assert!(t.switches > 0);
            assert!(
                result
                    .api_events
                    .iter()
                    .any(|e| e.thread_id == 2 && e.api.ends_with(".PsTerminateSystemThread"))
            );
        }
    }
}
#[test]
fn genuine_word_saved_irql_critical_depth_pool_lifetimes_and_context_exclusion_execute() {
    for arch in [Architecture::X86, Architecture::X64] {
        for kind in POSITIVE {
            let r = run_api_fixture(arch, ApiFixture::KernelSpin(kind), 20000).unwrap();
            assert_eq!(r.error, None, "{arch:?} {kind:?}: {r:#?}");
            assert_eq!(r.guest_entry_return, Some(17), "{arch:?} {kind:?}");
            assert_eq!(r.completion_reason, "entry_return");
            metadata(&r, arch, kind);
            assert!(r.api_events.iter().all(|e| e.error.is_none() && !e.pending));
            let last = r.api_events.last().unwrap();
            assert!(last.api.ends_with(".GetLastError"));
            assert_eq!(last.result, Some(0x12345678));
        }
    }
}
#[test]
fn unsupported_ownership_backing_aliases_lifetime_and_actual_irql_fail_without_fake_acquire() {
    for arch in [Architecture::X86, Architecture::X64] {
        for kind in NEGATIVE {
            let r = run_api_fixture(arch, ApiFixture::KernelSpin(kind), 20000).unwrap();
            assert!(
                r.error.as_deref().unwrap().contains(kind.error().unwrap()),
                "{arch:?} {kind:?}: {r:#?}"
            );
            assert_eq!(r.guest_entry_return, None);
            assert_eq!(r.completion_reason, "error");
            metadata(&r, arch, kind);
            if matches!(kind, F::DirectWrite | F::HeldExit) {
                assert!(r.api_events.iter().all(|e| e.error.is_none()));
            } else {
                assert!(r.api_events.last().unwrap().error.is_some());
            }
        }
    }
}
#[test]
fn actual_high_irql_budget_and_held_word_prefix_do_not_run_ready_child_or_report_return() {
    for arch in [Architecture::X86, Architecture::X64] {
        for kind in [F::NativeBudget, F::HeldBudget] {
            let r = run_api_fixture(arch, ApiFixture::KernelSpin(kind), 2000).unwrap();
            assert_eq!(r.error, None, "{arch:?} {kind:?}: {r:#?}");
            assert_eq!(r.completion_reason, "instruction_budget");
            assert_eq!(r.instruction_count, 2000);
            assert_eq!(r.guest_entry_return, None);
            metadata(&r, arch, kind);
        }
    }
}
#[test]
fn exact_before_return_spin_prefix_keeps_real_effects_without_inventing_entry_completion() {
    for arch in [Architecture::X86, Architecture::X64] {
        for kind in POSITIVE {
            let full = run_api_fixture(arch, ApiFixture::KernelSpin(kind), 20000).unwrap();
            assert_eq!(
                full.guest_entry_return,
                Some(17),
                "{arch:?} {kind:?}: {full:#?}"
            );
            let budget = full.instruction_count - 1;
            let r = run_api_fixture(arch, ApiFixture::KernelSpin(kind), budget).unwrap();
            assert_eq!(r.error, None, "{arch:?} {kind:?}: {r:#?}");
            assert_eq!(r.completion_reason, "instruction_budget");
            assert_eq!(r.instruction_count, budget);
            assert_eq!(r.guest_entry_return, None);
            metadata(&r, arch, kind);
        }
    }
}
