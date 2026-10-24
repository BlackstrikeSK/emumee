//! Compiler-owned coverage for the saved Python53 kernel tail shape.
//! No test loads external driver images or changes a mutex decision.
use super::*;
use emumee_core::fixtures::{TailDiagnostic as T, kernel_tail_probe, native_files_document};

fn run(kind: T, budget: u64) -> Execution {
    let validated = emumee_core::fullpersona::decode(
        &native_files_document(),
        &emumee_core::fullpersona::ResolveContext::default(),
    )
    .unwrap();
    let prepared = configured::Prepared::new(
        validated,
        configured::Request {
            architecture: Architecture::X64,
            kernel: true,
            initial_processor: 0,
            process: None,
            budget,
            timeout_us: 30_000_000,
        },
    )
    .unwrap();
    run_generated_with_fixture_configuration(
        &kernel_tail_probe(kind),
        &[],
        budget,
        30_000_000,
        GeneratedConfiguration {
            configured: Some(prepared),
            ..Default::default()
        },
    )
    .unwrap()
}

#[test]
fn generated_kernel_tail_api_events_bind_gate_and_instruction_position() {
    let result = run(T::FileEventMutex, 20000);
    assert_eq!(result.completion_reason, "entry_return");
    assert!(result.api_events.len() > 5);
    let region = result.api_region.as_ref().unwrap();
    for (index, event) in result.api_events.iter().enumerate() {
        assert!(event.api_gate_pc >= region.base);
        assert!(event.api_gate_pc < region.base + region.size);
        assert!(event.instruction_ordinal < result.instruction_count);
        if index > 0 {
            assert!(
                event.instruction_ordinal > result.api_events[index - 1].instruction_ordinal,
                "distinct API gates must have a counted instruction between dispatches"
            );
        }
    }
    let first = &result.api_events[0];
    assert_eq!(first.api, "ntoskrnl.ExAllocatePoolWithTag");
    let encoded = serde_json::to_value(first).unwrap();
    assert_eq!(encoded["api_gate_pc"], first.api_gate_pc);
    assert_eq!(encoded["instruction_ordinal"], first.instruction_ordinal);
}

#[test]
fn refused_guarded_mutex_api_keeps_position_without_implying_success() {
    let result = run(T::SchedulerZeroOwner, 10000);
    assert_eq!(result.completion_reason, "error");
    assert_eq!(result.guest_entry_return, None);
    let event = result
        .api_events
        .iter()
        .find(|event| event.api == "ntoskrnl.KeAcquireGuardedMutex")
        .unwrap();
    assert!(event.error.as_deref().unwrap().contains("no tracked owner"));
    assert_eq!(event.result, None);
    assert_eq!(event.effect, None);
    let region = result.api_region.as_ref().unwrap();
    assert!(event.api_gate_pc >= region.base && event.api_gate_pc < region.base + region.size);
    assert!(event.instruction_ordinal < result.instruction_count);
}

#[test]
fn active_scheduler_zero_count_zero_owner_refuses_without_granting_a_mutex() {
    let result = run(T::SchedulerZeroOwner, 10000);
    assert_eq!(result.completion_reason, "error");
    assert_eq!(result.guest_entry_return, None);
    assert!(result.error.unwrap().contains("no tracked owner"));
    assert_eq!(result.kernel_threads.as_ref().unwrap().count, 2);
    assert_eq!(result.kernel_state.as_ref().unwrap().irql, 0);
    assert_eq!(result.kernel_state.as_ref().unwrap().owned_mutexes, 0);
    let trace = &result.kernel_state.as_ref().unwrap().guarded_mutex_trace;
    let attempt = trace
        .iter()
        .find(|row| row.operation == "acquire_attempt")
        .unwrap();
    assert_eq!(attempt.guest_count, Some(0));
    assert_eq!(attempt.guest_owner, Some(0));
    assert!(!attempt.modeled_owned);
    assert!(!attempt.initialized_since_watch);
    assert!(
        !trace
            .iter()
            .any(|row| row.operation == "guest_write_pending")
    );
    assert!(
        result
            .api_events
            .iter()
            .any(|event| event.api == "ntoskrnl.KeAcquireGuardedMutex" && event.error.is_some())
    );
    assert!(
        !result
            .api_events
            .iter()
            .any(|event| event.effect == Some("mutex_acquired"))
    );
}

#[test]
fn file_write_flush_event_signal_and_mutex_release_share_one_generated_tail() {
    let result = run(T::FileEventMutex, 20000);
    assert_eq!(
        result.completion_reason, "entry_return",
        "{:?}",
        result.error
    );
    assert_eq!(result.guest_entry_return, Some(1));
    let files = result.kernel_files.as_ref().unwrap();
    assert!(!files.native_effect_failure);
    assert_eq!(
        files
            .events
            .iter()
            .map(|event| event.operation)
            .collect::<Vec<_>>(),
        ["create", "write", "flush", "close"]
    );
    assert_eq!(files.events[1].information, 4);
    assert!(files.handles.live.is_empty());
    let pool = result.kernel_pool.as_ref().unwrap();
    assert_eq!(pool.total_allocations, 1);
    assert_eq!(pool.total_frees, 1);
    assert!(pool.allocations.is_empty());
    assert!(
        result
            .api_events
            .iter()
            .any(|event| event.api == "ntoskrnl.KeSetEvent" && event.result == Some(0))
    );
    assert!(
        result
            .api_events
            .iter()
            .any(|event| event.api == "ntoskrnl.KeReleaseGuardedMutex" && event.error.is_none())
    );
    assert_eq!(result.kernel_state.as_ref().unwrap().irql, 0);
    assert_eq!(result.kernel_state.as_ref().unwrap().owned_mutexes, 0);
    assert_eq!(result.network.calls, 0);
    let partial = run(T::FileEventMutex, result.instruction_count - 1);
    assert_eq!(partial.completion_reason, "instruction_budget");
    assert_eq!(partial.guest_entry_return, None);
}

#[test]
fn waiter_mutex_handoff_and_logger_multiple_wait_keep_distinct_continuations() {
    let result = run(T::WaitManyMutexHandoff, 50000);
    assert_eq!(
        result.completion_reason, "entry_return",
        "{:?}",
        result.error
    );
    assert_eq!(result.guest_entry_return, Some(1));
    let threads = result.kernel_threads.as_ref().unwrap();
    assert_eq!(threads.count, 3);
    assert!(threads.waits >= 2);
    assert!(threads.resumed_waits >= 2);
    assert!(result.api_events.iter().any(|event| {
        event.api == "ntoskrnl.KeAcquireGuardedMutex"
            && event.effect == Some("mutex_acquired")
            && !event.pending
    }));
    assert!(result.api_events.iter().any(|event| {
        event.api == "ntoskrnl.KeWaitForMultipleObjects"
            && event.effect == Some("multiple_wait_satisfied")
            && !event.pending
    }));
    assert_eq!(result.kernel_state.as_ref().unwrap().owned_mutexes, 0);
    assert_eq!(result.kernel_state.as_ref().unwrap().irql, 0);
}

#[test]
fn guest_zeroing_a_live_owner_refuses_instead_of_synthesizing_handoff() {
    let result = run(T::GuestOwnerZeroed, 10000);
    assert_eq!(result.completion_reason, "error");
    assert_eq!(result.guest_entry_return, None);
    assert!(result.error.unwrap().contains("no tracked owner"));
    assert_eq!(result.kernel_threads.as_ref().unwrap().count, 2);
    assert_eq!(result.kernel_state.as_ref().unwrap().owned_mutexes, 1);
    let kernel = result.kernel_state.as_ref().unwrap();
    let attempts = kernel
        .guarded_mutex_trace
        .iter()
        .filter(|row| row.operation == "acquire_attempt")
        .collect::<Vec<_>>();
    assert_eq!(attempts.len(), 2);
    let refused = attempts[1];
    assert_eq!(refused.guest_count, Some(0));
    assert_eq!(refused.guest_owner, Some(0));
    assert!(refused.modeled_owned);
    assert!(refused.initialized_since_watch);
    assert!(
        kernel
            .guarded_mutex_trace
            .iter()
            .filter(|row| row.operation == "guest_write_pending" && row.mutex == refused.mutex)
            .count()
            >= 3
    );
    assert_eq!(kernel.guarded_mutex_trace_omitted, 0);
    assert!(
        !result
            .api_events
            .iter()
            .any(|event| event.effect == Some("mutex_acquired"))
    );
}

#[test]
fn guarded_mutex_provenance_is_bounded_under_generated_guest_write_burst() {
    let result = run(T::GuestWriteBurst, 10000);
    assert_eq!(
        result.completion_reason, "entry_return",
        "{:?}",
        result.error
    );
    let kernel = result.kernel_state.as_ref().unwrap();
    assert_eq!(kernel.guarded_mutex_trace.len(), 256);
    assert!(kernel.guarded_mutex_trace_omitted >= 46);
    assert_eq!(kernel.guarded_mutex_watch_omitted, 0);
    assert_eq!(kernel.guarded_mutex_watch_failures, 0);
    assert_eq!(kernel.owned_mutexes, 0);
}
