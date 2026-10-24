use super::*;
use emumee_core::fixtures::{ApiFixture, EnvironmentBlockFixture as F};
#[test]
fn native_environment_snapshots_and_owned_frees_are_actual_and_bounded() {
    for architecture in [Architecture::X86, Architecture::X64] {
        for unicode in [false, true] {
            for (kind, allocations, live) in [
                (F::Snapshot, 2, 0),
                (F::Empty, 1, 0),
                (F::FreeErrors, 1, 0),
                (F::Quota, 64, 0),
                (F::Live, 1, 1),
                (F::RetiredReallocation, 1, 0),
            ] {
                let result = run_api_fixture(
                    architecture,
                    ApiFixture::EnvironmentBlock(kind, unicode),
                    10000,
                )
                .unwrap();
                assert_eq!(
                    result.error, None,
                    "{architecture:?} {kind:?}/{unicode}: {result:#?}"
                );
                assert_eq!(result.guest_entry_return, Some(17));
                assert_eq!(result.api_events.last().unwrap().last_error, 0x12345678);
                assert!(result.artifacts.is_empty());
                assert_eq!(result.network.calls, 0);
                let blocks = result.environment_blocks.as_ref().unwrap();
                assert_eq!(blocks.live.len(), live);
                assert_eq!(blocks.lifetime_allocations, allocations);
                assert_eq!(blocks.mapped_bytes, live as u64 * 4096);
                assert_eq!(blocks.events_omitted, 0);
                assert_eq!(blocks.events.len(), (allocations * 2) as usize - live);
                assert!(
                    blocks
                        .live
                        .iter()
                        .all(|b| b.initialized && b.owner == 1024 && b.size == 4096)
                );
                if architecture == Architecture::X64 {
                    assert!(blocks.events.iter().all(|e| e.address > u32::MAX as u64));
                }
                let partial = run_api_fixture(
                    architecture,
                    ApiFixture::EnvironmentBlock(kind, unicode),
                    result.instruction_count - 1,
                )
                .unwrap();
                assert_eq!(partial.error, None);
                assert_eq!(partial.completion_reason, "instruction_budget");
                assert_eq!(partial.guest_entry_return, None);
            }
        }
    }
}
#[test]
fn environment_block_owned_pages_and_real_freed_pages_stop_invalid_guest_access() {
    for architecture in [Architecture::X86, Architecture::X64] {
        for unicode in [false, true] {
            for (kind, error, live) in [
                (F::Write, "WRITE_PROT", 1),
                (F::Protect, "system-owned environment-block storage", 1),
                (F::Free, "system-owned environment-block storage", 1),
                (F::Recommit, "system-owned environment-block storage", 1),
                (F::RetiredRead, "READ_UNMAPPED", 0),
                (F::RetiredExecute, "FETCH_UNMAPPED", 0),
            ] {
                let result = run_api_fixture(
                    architecture,
                    ApiFixture::EnvironmentBlock(kind, unicode),
                    10000,
                )
                .unwrap();
                assert!(
                    result.error.as_ref().is_some_and(|e| e.contains(error)),
                    "{architecture:?} {kind:?}/{unicode}: {result:#?}"
                );
                assert_eq!(result.guest_entry_return, None);
                assert!(result.artifacts.is_empty());
                let blocks = result.environment_blocks.unwrap();
                assert_eq!(blocks.live.len(), live);
                assert_eq!(blocks.mapped_bytes, live as u64 * 4096);
                assert_eq!(blocks.lifetime_allocations, 1);
            }
        }
    }
}
