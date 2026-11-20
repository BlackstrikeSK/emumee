//! Volume and console-session control families.
use super::*;
use emumee_core::fixtures::{
    M6ConsoleFixture as C, M6VolumeFixture as F, m6_console_probe, m6_volume_probe,
};

fn volume(arch: Architecture, kind: F, unicode: bool) -> Execution {
    let suffix = if unicode { "W" } else { "A" };
    let label = format!("{arch:?}-m6-volume-{kind:?}{suffix}");
    // The staged byte sequence gives the volume family a real path on the
    // modeled volume to ask about.
    let staged = [Staged {
        kind: InputKind::File,
        path: r"C:\emumee\m6.dat",
        bytes: b"emumee-m6".to_vec(),
    }];
    let result = run(&label, m6_volume_probe(arch, kind, unicode), &staged, 60_000);
    succeeded(&label, &result);
    result
}

fn console(arch: Architecture, kind: C, unicode: bool) -> Execution {
    let suffix = if unicode { "W" } else { "A" };
    let label = format!("{arch:?}-m6-console-{kind:?}{suffix}");
    let result = run(&label, m6_console_probe(arch, kind, unicode), &[], 60_000);
    succeeded(&label, &result);
    result
}

#[test]
fn m6_volume_identity_capacity_and_mount_paths_are_persona_reported() {
    for arch in [Architecture::X86, Architecture::X64] {
        for unicode in [false, true] {
            for kind in [F::Identity, F::Space, F::MountPaths] {
                let result = volume(arch, kind, unicode);
                // The reported capacity is persona identity, not an allocator:
                // the virtual filesystem keeps its own, far smaller, accounting
                // and the controls opened no handle of their own.
                let storage = result.file_storage.as_ref().unwrap();
                assert_eq!(storage.open_handles, 0, "{kind:?}: {storage:#?}");
                assert!(
                    (storage.accounted_bytes as u64) < 549_755_813_888,
                    "{kind:?}: {storage:#?}"
                );
            }
        }
    }
}

#[test]
fn m6_volume_enumeration_devices_and_wow64_cookies_round_trip_in_their_own_ranges() {
    for arch in [Architecture::X86, Architecture::X64] {
        for unicode in [false, true] {
            for kind in [F::Enumerate, F::DosDevice, F::Redirection] {
                let result = volume(arch, kind, unicode);
                // Volume searches never become file searches: the file
                // enumeration model issued no handle at all.
                let enumeration = result.file_enumeration.as_ref().unwrap();
                assert_eq!(enumeration.lifetime_handles, 0, "{kind:?}");
                assert!(enumeration.active.is_empty(), "{kind:?}");
            }
        }
    }
}

#[test]
fn m6_console_title_window_handlers_and_history_are_guest_decided() {
    for arch in [Architecture::X86, Architecture::X64] {
        for unicode in [false, true] {
            for kind in [C::Title, C::Window, C::Handlers, C::History] {
                let result = console(arch, kind, unicode);
                // A recorded Ctrl handler is never dispatched, so the guest
                // wrote nothing to its own console streams.
                let output = result.console.as_ref().unwrap();
                assert!(output.stdout.is_empty(), "{kind:?}");
                assert!(output.stderr.is_empty(), "{kind:?}");
            }
        }
    }
}
