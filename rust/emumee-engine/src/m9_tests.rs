//! M9 cross-family operational controls.
//!
//! The M5-M8 families each qualify one API partition in isolation. M9 is the
//! operational gate: every control is a single generated x86/x64 program that
//! chains several modeled families in one contained execution and decides its
//! own outcome inline, so the families are proved to interoperate — one
//! family's output feeds the next — rather than only to answer alone. Each
//! control is emitted as a contained fixture so the packaged worker replays the
//! same bytes through the public CLI.
use super::*;
use crate::m6_tests::{Staged, run, succeeded};
use emumee_core::fixtures::{M9Fixture, PROVISIONING_FILE, PROVISIONING_SEED, m9_probe};
use emumee_core::user_input::InputKind;

/// Run one operational control and emit its contained fixture and outcome. The
/// controls carry no capture configuration. The provisioning control reads a
/// staged file (which also makes its `C:\emumee` directory exist); the others
/// stage nothing. The operational obligation is family interoperation, which
/// the controls decide for themselves.
fn control(arch: Architecture, kind: M9Fixture) -> Execution {
    let label = format!("{arch:?}-m9-operational-{kind:?}");
    let staged: Vec<Staged> = match kind {
        M9Fixture::Provisioning => vec![Staged {
            kind: InputKind::File,
            path: PROVISIONING_FILE,
            bytes: PROVISIONING_SEED.to_vec(),
        }],
        _ => vec![],
    };
    let result = run(&label, m9_probe(arch, kind), &staged, 60_000);
    succeeded(&label, &result);
    // An operational control produces no submitted-sample capture: its families
    // run but nothing configures the memory-string or carving obligations.
    assert!(result.artifacts.is_empty(), "{label}: {:?}", result.artifacts);
    assert!(result.user_memory_strings.is_none(), "{label}");
    assert!(result.user_memory_capture.is_none(), "{label}");
    result
}

/// Every named API substring must appear among the recorded API events, so the
/// assertion proves each family actually ran rather than being compiled away.
fn reached(result: &Execution, label: &str, apis: &[&str]) {
    for api in apis {
        assert!(
            result.api_events.iter().any(|event| event.api.contains(api)),
            "{label}: {api} never reached; events: {:#?}",
            result
                .api_events
                .iter()
                .map(|event| event.api.as_str())
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn m9_provisioning_chains_allocation_filesystem_and_registry() {
    for arch in [Architecture::X86, Architecture::X64] {
        let result = control(arch, M9Fixture::Provisioning);
        // The reservation and its write, the staged-file read and the registry
        // round trip all ran in the one program.
        reached(
            &result,
            "provisioning",
            &[
                "VirtualAlloc",
                "WriteProcessMemory",
                "CreateFileW",
                "ReadFile",
                "CloseHandle",
                "RegCreateKeyExW",
                "RegSetValueExW",
                "RegQueryValueExW",
            ],
        );
        // The file read is served by the virtual filesystem, not the host, and
        // the guest never reached the real network.
        assert_eq!(result.network.calls, 0, "{arch:?}");
    }
}

#[test]
fn m9_integrity_hashes_the_bytes_the_registry_returned() {
    for arch in [Architecture::X86, Architecture::X64] {
        let result = control(arch, M9Fixture::Integrity);
        reached(
            &result,
            "integrity",
            &[
                "RegSetValueExW",
                "RegQueryValueExW",
                "CryptCreateHash",
                "CryptHashData",
                "CryptGetHashParam",
            ],
        );
    }
}

#[test]
fn m9_networking_parses_an_address_staged_in_a_reserved_buffer() {
    for arch in [Architecture::X86, Architecture::X64] {
        let result = control(arch, M9Fixture::Networking);
        reached(
            &result,
            "networking",
            &[
                "VirtualAlloc",
                "WriteProcessMemory",
                "WSAStartup",
                "inet_pton",
                "inet_ntop",
                "gethostname",
            ],
        );
        // The network model is offline: the real host network is never touched.
        assert_eq!(result.network.calls, 0, "{arch:?}");
    }
}
