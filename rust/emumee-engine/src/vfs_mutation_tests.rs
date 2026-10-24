use super::*;
use emumee_core::fixtures::{ApiFixture, MutationFixture as F};
#[test]
fn real_namespace_mutation_retains_backing_and_preserves_failure_state() {
    for architecture in [Architecture::X86, Architecture::X64] {
        for unicode in [false, true] {
            for (kind, names, bytes, artifacts) in [
                (F::Delete, 0, 0, 1),
                (F::Unlink, 1, 4, 2),
                (F::Copy, 2, 8, 1),
                (F::CopySharing, 2, 8, 1),
                (F::Move, 1, 4, 2),
                (F::MoveSharing, 2, 8, 2),
                (F::Rename, 1, 4, 1),
                (F::RenameErrors, 1, 4, 1),
                (F::Failures, 2, 8, 2),
            ] {
                let result =
                    run_api_fixture(architecture, ApiFixture::Mutation(kind, unicode), 6000)
                        .unwrap();
                assert_eq!(
                    result.error, None,
                    "{architecture:?} {kind:?}/{unicode}: {result:#?}"
                );
                assert_eq!(result.guest_entry_return, Some(17));
                assert_eq!(result.api_events.last().unwrap().last_error, 0x12345678);
                assert_eq!(result.network.calls, 0);
                let state = result.file_storage.as_ref().unwrap();
                assert_eq!(state.named_files, names);
                assert_eq!(state.named_bytes, bytes);
                assert_eq!(state.accounted_bytes, bytes);
                assert_eq!(state.unlinked_objects, 0);
                assert_eq!(state.unlinked_bytes, 0);
                assert_eq!(state.open_handles, 0);
                assert!(state.scope.contains("legacy immediate unlink"));
                assert_eq!(result.artifacts.len(), artifacts);
                assert!(result.artifacts.iter().all(|a| {
                    [b"RUST".as_slice(), b"TARG".as_slice(), b"NEW!".as_slice()]
                        .contains(&a.data.as_slice())
                }));
                if matches!(kind, F::Delete | F::Unlink) {
                    assert!(
                        result
                            .artifacts
                            .iter()
                            .flat_map(|a| &a.observations)
                            .any(|o| o.source == "virtual_file_delete")
                    );
                }
                if matches!(kind, F::Move) {
                    assert!(
                        result
                            .artifacts
                            .iter()
                            .flat_map(|a| &a.observations)
                            .any(|o| o.source == "virtual_file_move_replaced")
                    );
                }
                let partial = run_api_fixture(
                    architecture,
                    ApiFixture::Mutation(kind, unicode),
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
fn unsupported_file_mutation_profiles_remain_explicit_and_do_not_publish_success() {
    for architecture in [Architecture::X86, Architecture::X64] {
        for unicode in [false, true] {
            for (kind, reason) in [
                (
                    F::FlagsUnsupported,
                    "MoveFileEx flags outside same-volume file profile",
                ),
                (
                    F::CrossVolumeUnsupported,
                    "cross-volume file mutation is not modeled",
                ),
                (
                    F::DirectoryUnsupported,
                    "directory copy/move/delete is not modeled",
                ),
                (
                    F::RootUnsupported,
                    "FILE_RENAME_INFO RootDirectory handles are not modeled",
                ),
                (
                    F::ClassUnsupported,
                    "SetFileInformationByHandle classes outside FileRenameInfo are not modeled",
                ),
            ] {
                let result =
                    run_api_fixture(architecture, ApiFixture::Mutation(kind, unicode), 6000)
                        .unwrap();
                assert!(
                    result.error.as_ref().is_some_and(|e| e.contains(reason)),
                    "{architecture:?} {kind:?}/{unicode}: {result:#?}"
                );
                assert_eq!(result.guest_entry_return, None);
                assert!(result.artifacts.is_empty());
                let state = result.file_storage.unwrap();
                assert_eq!(state.named_bytes, 0);
                assert_eq!(state.unlinked_objects, 0);
                assert_eq!(state.accounted_bytes, 0);
            }
        }
    }
}
