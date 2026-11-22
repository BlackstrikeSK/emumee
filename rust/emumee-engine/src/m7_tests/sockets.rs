//! Winsock control family: startup bookkeeping, byte order and address text,
//! the socket lifecycle, the recorded outbound attempts and the inbound denial.
use super::*;
use emumee_core::fixtures::{M7SocketFixture as F, m7_socket_probe};

fn control(arch: Architecture, kind: F) -> Execution {
    let label = format!("{arch:?}-m7-socket-{kind:?}");
    let result = run(&label, m7_socket_probe(arch, kind), &[], 60_000);
    succeeded(&label, &result);
    result
}

#[test]
fn m7_socket_startup_addresses_lifecycle_and_denials_are_guest_decided() {
    for arch in [Architecture::X86, Architecture::X64] {
        for kind in [F::Core, F::Transfer] {
            let result = control(arch, kind);
            // No HTTP broker path is reached by the socket surface.
            assert_eq!(result.network.calls, 0, "{kind:?}");
            if matches!(kind, F::Transfer) {
                // The destination and the payload are both recorded, and the
                // inbound attempt is recorded as a denial.
                assert_eq!(result.sockets.sockets_opened, 1, "{kind:?}");
                assert_eq!(result.sockets.connect_attempts, 1, "{kind:?}");
                assert_eq!(result.sockets.bytes_offered, 14, "{kind:?}");
                assert!(
                    result
                        .sockets
                        .events
                        .iter()
                        .any(|event| event.api == "connect" && event.detail == "10.0.2.15:8080"),
                    "{kind:?}: {:?}",
                    result.sockets.events
                );
                assert!(
                    result
                        .sockets
                        .events
                        .iter()
                        .any(|event| event.api == "listen" && event.denied),
                    "{kind:?}: {:?}",
                    result.sockets.events
                );
                // The offered payload is captured even though it never left.
                assert_eq!(result.artifacts.len(), 1, "{kind:?}: {:?}", result.artifacts);
            }
        }
    }
}
