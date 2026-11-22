//! COM control family: activation and vtable identity, reference-count
//! lifetime, the WMI locator/services/enumerator chain, BSTR and VARIANT
//! handling, deterministic GUID/UUID generation, and the shell surface
//! (known folders, directory trees, argv splitting, observed execution and
//! IMalloc).
use super::*;
use emumee_core::fixtures::{M7ComFixture as F, m7_com_probe};

fn control(arch: Architecture, kind: F) -> Execution {
    let label = format!("{arch:?}-m7-com-{kind:?}");
    let result = run(&label, m7_com_probe(arch, kind), &[], 80_000);
    succeeded(&label, &result);
    result
}

#[test]
fn m7_com_activation_vtables_refcounts_bstrs_guids_and_shell_are_guest_decided() {
    for arch in [Architecture::X86, Architecture::X64] {
        for kind in [F::Activation, F::Wbem, F::Bstr, F::Guid, F::Uuid, F::Shell] {
            let result = control(arch, kind);
            assert_eq!(result.network.calls, 0, "{kind:?} reached the network");
            match kind {
                F::Activation => {
                    // One successful activation and one refused IID.
                    assert_eq!(result.com.activations, 1, "{kind:?}");
                    assert_eq!(result.com.queries, 0);
                }
                F::Wbem => {
                    // The WQL text is recorded without any provider running.
                    assert_eq!(result.com.queries, 1, "{kind:?}");
                    assert!(
                        result
                            .com
                            .events
                            .iter()
                            .any(|event| event.detail.contains("Win32_Process")),
                        "{kind:?}: {:?}",
                        result.com.events
                    );
                }
                F::Shell => {
                    // The launch request is observed, never carried out.
                    assert!(result.shell.execution_requests >= 1, "{kind:?}");
                    assert!(
                        result
                            .shell
                            .events
                            .iter()
                            .any(|event| event.file.contains("payload.exe")),
                        "{kind:?}: {:?}",
                        result.shell.events
                    );
                }
                _ => {}
            }
        }
    }
}
