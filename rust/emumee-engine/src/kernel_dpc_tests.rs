use super::*;
use emumee_core::fixtures::{ApiFixture, DpcFixture as F, TimerFixture};
fn run(arch: Architecture, kind: F, budget: u64) -> Execution {
    run_api_fixture(arch, ApiFixture::KernelDpc(kind), budget).unwrap()
}
fn honest(e: &Execution, arch: Architecture, kind: F) {
    assert_eq!(e.architecture, arch);
    assert_eq!(e.network.calls, 0);
    assert!(e.artifacts.is_empty());
    assert_eq!(e.api_events_omitted, 0);
    assert!(
        e.kernel_ipi
            .as_ref()
            .unwrap()
            .rendezvous
            .broadcasts
            .is_empty()
    );
    let t = e.kernel_threads.as_ref().unwrap();
    let d = &t.dpc;
    assert_eq!(d.version, "cpu0-dpc-dispatch-v1");
    assert!(d.environment_prepared);
    assert_eq!(t.dpc_initializations, 2);
    assert_eq!(t.count, if kind == F::ThreadParked { 2 } else { 1 });
    assert_eq!(
        d.layout.base,
        if arch == Architecture::X64 {
            0xffffc50000000000
        } else {
            0xc5000000
        }
    );
    assert_eq!(d.counters.started, d.invocations.len() as u64);
    assert_eq!(d.omitted_invocations, 0);
    for invocation in &d.invocations {
        assert_eq!(invocation.processor, 0);
        assert_eq!(
            invocation.thread,
            emumee_core::kernel_layout::KernelLayout::for_architecture(arch).root_thread
        );
        assert_eq!(invocation.thread_slot, 1);
        if let Some(at) = invocation.return_instruction {
            assert!(at > invocation.start_instruction);
            assert!(invocation.caller_restored);
        }
    }
    for event in e.api_events.iter().filter(|e| e.execution_domain == "dpc") {
        assert_eq!(event.thread_id, 1);
        assert_eq!(event.processor, 0);
        assert_eq!(
            event.current_thread,
            emumee_core::kernel_layout::KernelLayout::for_architecture(arch).root_thread
        );
        assert!(!event.pending);
    }
}
#[test]
fn actual_dpc_fifo_removal_duplicates_callbacks_timers_waits_and_caller_context_in_both_abis() {
    for arch in [Architecture::X86, Architecture::X64] {
        for kind in F::ALL
            .into_iter()
            .filter(|k| k.error().is_none() && !k.budget())
        {
            let e = run(arch, kind, 20000);
            assert_eq!(e.error, None, "{arch:?} {kind:?}: {e:#?}");
            assert_eq!(
                e.completion_reason, "entry_return",
                "{arch:?} {kind:?}: {e:#?}"
            );
            assert_eq!(e.guest_entry_return, Some(17));
            honest(&e, arch, kind);
            let t = e.kernel_threads.as_ref().unwrap();
            let d = &t.dpc;
            let count = if matches!(kind, F::Remove | F::TimerCancel | F::TimerReplacement) {
                0
            } else if matches!(kind, F::Fifo | F::CallbackQueue) {
                2
            } else {
                1
            };
            assert_eq!(d.counters.started, count, "{arch:?} {kind:?}");
            assert_eq!(d.counters.returned, count);
            assert_eq!(d.counters.restored, count);
            assert!(!d.active);
            assert!(d.queued.is_empty());
            assert!(!d.native_effect_failure);
            assert_eq!(t.root_entry_return, Some(17));
            assert_eq!(e.kernel_state.as_ref().unwrap().irql, 0);
            assert_eq!(e.kernel_state.as_ref().unwrap().critical_depth, 0);
            if kind == F::Duplicate {
                assert_eq!(d.counters.duplicates, 1);
                assert_eq!(
                    d.invocations[0].work.arguments,
                    if arch == Architecture::X64 {
                        [0xfedcba9876543210, 0xabcdef0187654321]
                    } else {
                        [0x76543210, 0x87654321]
                    }
                );
            }
            if kind == F::Remove {
                assert_eq!((d.counters.accepted, d.counters.removed), (1, 1));
            }
            if matches!(kind, F::Timer | F::TimerWait | F::TimerRead | F::Periodic) {
                assert_eq!(d.invocations[0].work.arguments, d.layout.timer_arguments);
                assert!(matches!(
                    d.invocations[0].work.origin,
                    emumee_core::scheduler::DpcOrigin::Timer { .. }
                ));
            }
            if kind == F::ThreadParked {
                let callback_end = d.invocations[0].return_instruction.unwrap();
                assert!(
                    e.api_events
                        .iter()
                        .any(|a| a.execution_domain == "dpc" && a.api == "ntoskrnl.KeSetEvent")
                );
                assert!(t.switches >= 2);
                assert!(callback_end > d.invocations[0].start_instruction);
                assert!(
                    e.api_events
                        .iter()
                        .any(|a| a.thread_id == 2 && a.api == "ntoskrnl.PsTerminateSystemThread")
                );
            }
            assert!(
                e.api_events
                    .iter()
                    .all(|event| event.error.is_none() && !event.pending)
            );
            let last = e
                .api_events
                .iter()
                .rev()
                .find(|event| event.thread_id == 1 && event.api == "kernel32.GetLastError")
                .unwrap();
            assert_eq!(last.result, Some(0x12345678));
            let prefix = run(arch, kind, e.instruction_count - 1);
            assert_eq!(prefix.instruction_count, e.instruction_count - 1);
            assert_eq!(
                prefix.completion_reason, "instruction_budget",
                "{arch:?} {kind:?}: {prefix:#?}"
            );
            assert_eq!(prefix.error, None);
            assert_eq!(prefix.guest_entry_return, None);
            assert_eq!(
                prefix.kernel_threads.as_ref().unwrap().root_entry_return,
                None
            );
        }
    }
}
#[test]
fn actual_callback_failures_owned_environment_and_invalid_returns_cannot_fake_completion() {
    for arch in [Architecture::X86, Architecture::X64] {
        for kind in F::ALL.into_iter().filter(|k| k.error().is_some()) {
            let e = run(arch, kind, 20000);
            assert!(
                e.error.as_deref().unwrap().contains(kind.error().unwrap()),
                "{arch:?} {kind:?}: {e:#?}"
            );
            assert_eq!(e.completion_reason, "error");
            assert_eq!(e.guest_entry_return, None);
            honest(&e, arch, kind);
            let t = e.kernel_threads.as_ref().unwrap();
            let d = &t.dpc;
            let started = !matches!(kind, F::Protect | F::Free | F::Recommit);
            assert_eq!(d.counters.started, u64::from(started));
            assert_eq!(d.counters.restored, 0);
            assert_eq!(d.active, started);
            assert_eq!(
                t.root_entry_return,
                if kind == F::RootFault { Some(17) } else { None }
            );
            if started {
                assert!(
                    e.api_events
                        .iter()
                        .any(|event| event.execution_domain == "dpc"
                            && event.api == "ntoskrnl.KeGetCurrentIrql")
                );
                assert!(matches!(
                    t.dpcs_initialized[0].phase,
                    emumee_core::scheduler::DpcPhase::Running(_)
                ));
            }
        }
    }
}
#[test]
fn shared_global_budget_in_actual_callback_preserves_prior_root_return_only_when_observed() {
    for arch in [Architecture::X86, Architecture::X64] {
        for kind in [F::CallbackBudget, F::RootBudget] {
            let e = run(arch, kind, 2000);
            assert_eq!(e.instruction_count, 2000);
            assert_eq!(e.error, None, "{arch:?} {kind:?}: {e:#?}");
            assert_eq!(e.completion_reason, "instruction_budget");
            assert_eq!(e.guest_entry_return, None);
            honest(&e, arch, kind);
            let t = e.kernel_threads.as_ref().unwrap();
            assert_eq!(
                t.root_entry_return,
                if kind == F::RootBudget {
                    Some(17)
                } else {
                    None
                }
            );
            assert_eq!(t.dpc.counters.started, 1);
            assert_eq!(t.dpc.counters.returned, 0);
            assert!(t.dpc.active);
            assert!(!t.dpc.native_effect_failure);
        }
    }
}
#[test]
fn generated_idle_and_active_dpc_budget_loops_share_exact_code_pc() {
    assert!(matches!(
        emumee_core::protocol::FixtureKind::parse("kernel-dpc-idle-budget"),
        Some(emumee_core::protocol::FixtureKind::KernelDpcIdleBudget)
    ));
    let arch = Architecture::X64;
    let active_image = emumee_core::fixtures::kernel_dpc_probe(arch, F::CallbackBudget);
    let idle_image = emumee_core::fixtures::kernel_dpc_idle_budget_probe(arch);
    let mut only_entry_changed = active_image.clone();
    only_entry_changed[0x98 + 16..0x98 + 20].copy_from_slice(&idle_image[0x98 + 16..0x98 + 20]);
    assert_eq!(only_entry_changed, idle_image);
    let budget = 20_000;
    let idle = run_api_fixture(arch, ApiFixture::KernelDpcIdleBudget, budget).unwrap();
    let active = run(arch, F::CallbackBudget, budget);
    for result in [&idle, &active] {
        assert_eq!(result.error, None, "{result:#?}");
        assert_eq!(result.instruction_count, budget);
        assert_eq!(result.completion_reason, "instruction_budget");
        assert_eq!(result.guest_entry_return, None);
    }
    assert!(idle.kernel_threads.is_none());
    let active_threads = active.kernel_threads.as_ref().unwrap();
    assert_eq!(active_threads.dpc.counters.started, 1);
    assert!(active_threads.dpc.active);
    let idle_loop = idle.instruction_tail.last().unwrap().pc;
    assert_eq!(active.instruction_tail.last().unwrap().pc, idle_loop);
    assert!(
        idle.instruction_tail
            .iter()
            .all(|entry| entry.pc == idle_loop)
    );
    assert!(
        active
            .instruction_tail
            .iter()
            .all(|entry| entry.pc == idle_loop)
    );
}
#[test]
fn generated_active_dpc_refuses_forbidden_processor_opcode_before_native_execution() {
    let arch = Architecture::X64;
    let mut image = emumee_core::fixtures::kernel_dpc_probe(arch, F::CallbackBudget);
    let idle = emumee_core::fixtures::kernel_dpc_idle_budget_probe(arch);
    let rva = u32::from_le_bytes(idle[0x98 + 16..0x98 + 20].try_into().unwrap()) as usize;
    assert!((0x1000..0x3000).contains(&rva));
    // The generated .text section has RVA 0x1000 and raw offset 0x200.
    let raw = 0x200 + rva - 0x1000;
    assert_eq!(&image[raw..raw + 2], &[0xeb, 0xfe]);
    image[raw..raw + 3].copy_from_slice(&[0x0f, 0x01, 0xf8]); // SWAPGS
    let result = run_generated_image(&image, 20_000, 30_000_000).unwrap();
    assert_eq!(result.completion_reason, "error");
    assert_eq!(result.guest_entry_return, None);
    assert!(
        result
            .error
            .as_deref()
            .unwrap()
            .contains("DPC architectural processor mutation is unsupported")
    );
    let threads = result.kernel_threads.as_ref().unwrap();
    assert_eq!(threads.dpc.counters.started, 1);
    assert!(threads.dpc.active);
    assert!(threads.dpc.native_effect_failure);
    assert_eq!(result.network.calls, 0);
    assert!(result.artifacts.is_empty());
}
#[test]
fn literal_legacy_bad_marker_callback_really_runs_then_guest_poison_assertion_fails() {
    for arch in [Architecture::X86, Architecture::X64] {
        for kind in [
            TimerFixture::DueDpc,
            TimerFixture::DpcRead,
            TimerFixture::DpcWait,
        ] {
            let e = run_api_fixture(arch, ApiFixture::KernelTimers(kind), 20000).unwrap();
            assert!(
                e.error.as_deref().unwrap().contains("EXCEPTION"),
                "{arch:?} {kind:?}: {e:#?}"
            );
            let t = e.kernel_threads.as_ref().unwrap();
            assert_eq!(t.dpc.counters.restored, 1);
            assert!(!t.timers[0].inserted);
            assert!(t.timers[0].signaled);
            assert!(
                t.dpc.invocations[0].return_instruction.unwrap()
                    > t.dpc.invocations[0].start_instruction
            );
            assert!(
                e.api_events
                    .iter()
                    .all(|event| event.error.is_none() && !event.pending)
            );
            assert_eq!(t.root_entry_return, None);
        }
    }
}
#[test]
fn exact_budget_before_callback_admission_retains_real_queued_work_without_zero_instruction_start()
{
    for arch in [Architecture::X86, Architecture::X64] {
        let full = run(arch, F::Basic, 20000);
        assert_eq!(full.error, None, "{arch:?}: {full:#?}");
        let first = full.kernel_threads.as_ref().unwrap().dpc.invocations[0].start_instruction;
        let prefix = run(arch, F::Basic, first);
        assert_eq!(prefix.instruction_count, first);
        assert_eq!(
            prefix.completion_reason, "instruction_budget",
            "{arch:?}: {prefix:#?}"
        );
        assert_eq!(prefix.guest_entry_return, None);
        assert_eq!(prefix.error, None);
        let t = prefix.kernel_threads.as_ref().unwrap();
        assert_eq!(t.root_entry_return, None);
        assert_eq!(t.dpc.counters.accepted, 1);
        assert_eq!(t.dpc.counters.started, 0);
        assert_eq!(t.dpc.counters.returned, 0);
        assert!(!t.dpc.active);
        assert!(t.dpc.invocations.is_empty());
        assert_eq!(t.dpc.queued.len(), 1);
        assert!(
            prefix
                .api_events
                .iter()
                .any(|event| event.api == "ntoskrnl.KeInsertQueueDpc" && event.result == Some(1))
        );
    }
}
