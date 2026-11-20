//! Filesystem control family: handle-directed size, position, times,
//! by-handle information and the legacy file API.
use super::*;
use emumee_core::fixtures::{
    M6FileFixture as F, M6PathFixture as P, m6_file_probe, m6_path_probe,
};

fn control(arch: Architecture, kind: F, unicode: bool) -> Execution {
    let suffix = if unicode { "W" } else { "A" };
    let label = format!("{arch:?}-m6-file-{kind:?}{suffix}");
    // One staged byte sequence gives the family a real existing file and the
    // directory the controls create their own files in.
    let staged = [Staged {
        kind: InputKind::File,
        path: r"C:\emumee\m6.dat",
        bytes: b"emumee-m6".to_vec(),
    }];
    let result = run(&label, m6_file_probe(arch, kind, unicode), &staged, 60_000);
    succeeded(&label, &result);
    result
}

#[test]
fn m6_file_handle_size_position_times_and_information_are_guest_decided() {
    for arch in [Architecture::X86, Architecture::X64] {
        for unicode in [false, true] {
            for kind in [F::Size, F::Times, F::Information, F::Legacy] {
                let result = control(arch, kind, unicode);
                assert_eq!(result.capture_summary.omitted_observations, 0, "{kind:?}");
                // Guest bytes written to a file are captured; the times control
                // writes none, so it leaves no artifact behind.
                assert_eq!(
                    result.artifacts.is_empty(),
                    matches!(kind, F::Times),
                    "{kind:?}: {:?}",
                    result.artifacts
                );
                let storage = result.file_storage.as_ref().unwrap();
                assert_eq!(storage.open_handles, 0, "{kind:?}: {storage:#?}");
            }
        }
    }
}

#[test]
fn m6_file_stamping_and_truncation_respect_the_handle_access_they_require() {
    for arch in [Architecture::X86, Architecture::X64] {
        for unicode in [false, true] {
            let result = control(arch, F::Denied, unicode);
            let refusals = result
                .api_events
                .iter()
                .filter(|event| {
                    (event.api.contains("SetEndOfFile") || event.api.contains("SetFileTime"))
                        && event.result == Some(0)
                })
                .count();
            // Two access refusals, one end-of-file refusal under append and one
            // unknown-handle refusal.
            assert_eq!(refusals, 4, "{arch:?}/{unicode}: {:#?}", result.api_events);
        }
    }
}

fn path_control(arch: Architecture, kind: P, unicode: bool) -> Execution {
    let suffix = if unicode { "W" } else { "A" };
    let label = format!("{arch:?}-m6-path-{kind:?}{suffix}");
    // Two generated PE byte sequences, one per machine, give GetBinaryType
    // something to classify from its own headers, and a plain byte sequence
    // gives it something that is not a PE at all.
    let staged = [
        Staged {
            kind: InputKind::File,
            path: r"C:\emumee\m6.dat",
            bytes: b"emumee-m6".to_vec(),
        },
        Staged {
            kind: InputKind::File,
            path: r"C:\emumee\m6x86.bin",
            bytes: emumee_core::fixtures::counted_driver(Architecture::X86, 1),
        },
        Staged {
            kind: InputKind::File,
            path: r"C:\emumee\m6x64.bin",
            bytes: emumee_core::fixtures::counted_driver(Architecture::X64, 1),
        },
    ];
    run(&label, m6_path_probe(arch, kind, unicode), &staged, 60_000)
}

#[test]
fn m6_short_paths_extended_searches_temporary_names_and_binary_types_are_guest_decided() {
    for arch in [Architecture::X86, Architecture::X64] {
        for unicode in [false, true] {
            for kind in [
                P::ShortPath,
                P::FindExStandard,
                P::FindExBasic,
                P::TempName,
                P::BinaryType,
            ] {
                let suffix = if unicode { "W" } else { "A" };
                let label = format!("{arch:?}-m6-path-{kind:?}{suffix}");
                let result = path_control(arch, kind, unicode);
                succeeded(&label, &result);
                let enumeration = result.file_enumeration.as_ref().unwrap();
                assert!(enumeration.active.is_empty(), "{label}");
                assert_eq!(
                    enumeration.lifetime_handles,
                    u64::from(matches!(kind, P::FindExStandard | P::FindExBasic)),
                    "{label}"
                );
            }
        }
    }
}

#[test]
fn m6_short_name_aliases_and_unmodeled_search_levels_stop_explicitly() {
    for arch in [Architecture::X86, Architecture::X64] {
        for unicode in [false, true] {
            for (kind, reason) in [
                (P::ShortNameUnsupported, "short-name expansion is not modeled"),
                (
                    P::SearchLevelUnsupported,
                    "FindFirstFileEx information level, search operation, filter or flags are not modeled",
                ),
            ] {
                let result = path_control(arch, kind, unicode);
                assert_eq!(result.completion_reason, "error", "{kind:?}: {result:#?}");
                assert!(
                    result.error.as_deref().is_some_and(|e| e.contains(reason)),
                    "{kind:?}: {:?}",
                    result.error
                );
                assert_eq!(result.guest_entry_return, None, "{kind:?}");
            }
        }
    }
}
