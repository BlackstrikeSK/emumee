use super::*;
use emumee_core::fixtures::{ApiFixture, SyncFixture as S};
#[test]
fn scalar_rundown_push_and_real_irql_obey_abi_memory_and_instruction_budgets() {
    for architecture in [Architecture::X86, Architecture::X64] {
        for kind in [
            S::Rundown,
            S::Push,
            S::PushFlagWidth,
            S::Irql,
            S::NativeIrql,
            S::LowerAlias,
        ] {
            let e = run_api_fixture(architecture, ApiFixture::Sync(kind), 10000).unwrap();
            assert_eq!(e.error, None, "{architecture:?}/{kind:?}: {e:#?}");
            assert_eq!(e.guest_entry_return, Some(1));
            assert_eq!(e.completion_reason, "entry_return");
            let state = e.kernel_state.as_ref().unwrap();
            assert_eq!(state.irql, 0);
            assert_eq!(state.critical_depth, 0);
            assert!(state.scalar_sync.iter().all(|o| o.completed));
            assert_eq!(state.scalar_sync_omitted, 0);
            assert_eq!(e.kernel_cpu.as_ref().unwrap().pcr_irql, 0);
            assert!(e.kernel_threads.is_none()); // This lane never manufactures a scheduler.
            assert!(e.api_events.iter().all(|event| event.error.is_none()));
            assert_eq!(e.network.calls, 0);
            assert!(e.artifacts.is_empty());
            let partial = run_api_fixture(
                architecture,
                ApiFixture::Sync(kind),
                e.instruction_count - 1,
            )
            .unwrap();
            assert_eq!(partial.error, None);
            assert_eq!(partial.completion_reason, "instruction_budget");
            assert_eq!(partial.guest_entry_return, None);
            assert_eq!(partial.instruction_count, e.instruction_count - 1);
            assert_eq!(partial.api_calls, e.api_calls);
        }
    }
}
#[test]
fn scalar_contention_faults_do_not_publish_return_or_waiter_and_show_committed_words() {
    for architecture in [Architecture::X86, Architecture::X64] {
        for kind in [
            S::RundownBlocked,
            S::RundownRelease,
            S::RundownOverflow,
            S::PushBlocked,
            S::PushRelease,
            S::PushTamper,
            S::PushFlags,
            S::PushApcs,
            S::Unaligned,
            S::ReadOnly,
            S::InvalidRange,
            S::HighIrql,
            S::InvalidRaise,
            S::InvalidLower,
        ] {
            let e = run_api_fixture(architecture, ApiFixture::Sync(kind), 10000).unwrap();
            assert_eq!(
                e.guest_entry_return, None,
                "{architecture:?}/{kind:?}: {e:#?}"
            );
            assert_eq!(e.completion_reason, "error");
            assert!(
                e.error
                    .as_deref()
                    .unwrap()
                    .to_ascii_lowercase()
                    .contains(&kind.error().unwrap().to_ascii_lowercase()),
                "{architecture:?}/{kind:?}: {e:#?}"
            );
            assert!(e.kernel_threads.is_none());
            assert_eq!(e.api_events.last().unwrap().result, None);
            let state = e.kernel_state.as_ref().unwrap();
            match kind {
                S::RundownBlocked => {
                    let last = state.scalar_sync.last().unwrap();
                    assert_eq!(
                        (last.before, last.after, last.wrote, last.completed),
                        (2, 3, true, false)
                    );
                }
                S::PushBlocked => {
                    let last = state.scalar_sync.last().unwrap();
                    assert_eq!(
                        (last.before, last.after, last.wrote, last.completed),
                        (1, 1, false, false)
                    );
                }
                S::RundownOverflow
                | S::Unaligned
                | S::ReadOnly
                | S::InvalidRange
                | S::HighIrql
                | S::InvalidRaise
                | S::InvalidLower => assert!(state.scalar_sync.is_empty()),
                _ => assert!(state.scalar_sync.iter().all(|row| row.completed)),
            }
            if matches!(kind, S::InvalidRaise | S::InvalidLower) {
                assert_eq!(state.irql, 0);
                assert_eq!(e.kernel_cpu.as_ref().unwrap().pcr_irql, 0);
            }
        }
    }
}
