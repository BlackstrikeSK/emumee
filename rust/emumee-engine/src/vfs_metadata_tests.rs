use super::*;
use emumee_core::fixtures::{ApiFixture, VfsFixture as F};
#[test]
fn guest_vfs_metadata_searches_paths_and_persona_cwd_use_one_real_catalog() {
    for architecture in [Architecture::X86, Architecture::X64] {
        for unicode in [false, true] {
            for kind in [
                F::Directory,
                F::Metadata,
                F::Enumeration,
                F::Snapshot,
                F::Retry,
                F::Wildcard,
                F::CurrentDirectory,
                F::Paths,
                F::Missing,
                F::ReadOnly,
                F::TypedHandles,
            ] {
                let result =
                    run_api_fixture(architecture, ApiFixture::Vfs(kind, unicode), 5000).unwrap();
                assert_eq!(
                    result.error, None,
                    "{architecture:?} {kind:?}/{unicode}: {result:#?}"
                );
                assert_eq!(result.guest_entry_return, Some(17));
                assert_eq!(result.api_events.last().unwrap().last_error, 0x12345678);
                assert_eq!(result.network.calls, 0);
                let enumeration = result.file_enumeration.as_ref().unwrap();
                assert!(enumeration.active.is_empty());
                assert_eq!(enumeration.snapshot_bytes, 0);
                assert_eq!(
                    enumeration.lifetime_handles,
                    match kind {
                        F::Enumeration | F::Snapshot | F::Retry => 1,
                        F::Wildcard | F::TypedHandles => 2,
                        _ => 0,
                    }
                );
                if matches!(kind, F::Metadata | F::Enumeration | F::ReadOnly) {
                    assert_eq!(result.artifacts.len(), 1);
                    assert_eq!(result.artifacts[0].data, b"RUST");
                } else {
                    assert!(result.artifacts.is_empty());
                }
                let console = result.console.as_ref().unwrap();
                assert!(console.stdout.is_empty());
                assert!(console.stderr.is_empty());
                assert!(console.write_events.is_empty());
                let partial = run_api_fixture(
                    architecture,
                    ApiFixture::Vfs(kind, unicode),
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
fn vfs_unmodeled_attributes_masks_security_and_short_aliases_stay_explicit() {
    for architecture in [Architecture::X86, Architecture::X64] {
        for unicode in [false, true] {
            for (kind, reason) in [
                (
                    F::AttributesUnsupported,
                    "file attributes outside modeled mutable profile",
                ),
                (
                    F::MaskUnsupported,
                    "search grammar or short-name matching is not modeled",
                ),
                (
                    F::SecurityUnsupported,
                    "Directory security attributes are not modeled",
                ),
                (
                    F::ShortNameUnsupported,
                    "short-name expansion is not modeled",
                ),
            ] {
                let result =
                    run_api_fixture(architecture, ApiFixture::Vfs(kind, unicode), 5000).unwrap();
                assert!(
                    result
                        .error
                        .as_ref()
                        .is_some_and(|error| error.contains(reason)),
                    "{architecture:?} {kind:?}/{unicode}: {:?}",
                    result.error
                );
                assert_eq!(result.guest_entry_return, None);
                assert!(result.artifacts.is_empty());
                assert_eq!(result.file_enumeration.unwrap().lifetime_handles, 0);
            }
        }
    }
}
