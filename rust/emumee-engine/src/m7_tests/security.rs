//! Security control family: SID construction and comparison, token query and
//! the partial-success privilege adjustment, account translation, extended user
//! names, the service control manager, and audit/LSA enumeration.
use super::*;
use emumee_core::fixtures::{M7SecurityFixture as F, m7_security_probe};

fn control(arch: Architecture, kind: F) -> Execution {
    let label = format!("{arch:?}-m7-security-{kind:?}");
    let result = run(&label, m7_security_probe(arch, kind), &[], 80_000);
    succeeded(&label, &result);
    result
}

#[test]
fn m7_security_sids_tokens_accounts_services_and_audit_are_guest_decided() {
    for arch in [Architecture::X86, Architecture::X64] {
        for kind in [F::Sid, F::Token, F::Account, F::UserName, F::Service, F::Audit] {
            let result = control(arch, kind);
            assert_eq!(result.network.calls, 0, "{kind:?} reached the network");
            match kind {
                F::Token => {
                    // The refused SeDebugPrivilege attempt is recorded as not
                    // granted, which is the evidence an elevation attempt leaves.
                    assert!(
                        result.security.events.iter().any(|event| {
                            event.api == "AdjustTokenPrivileges"
                                && event.detail.contains("SeDebugPrivilege")
                                && !event.granted
                        }),
                        "{kind:?}: {:?}",
                        result.security.events
                    );
                }
                F::Service => {
                    // Persistence is observed in full and nothing was executed.
                    assert_eq!(result.services.created, 1, "{kind:?}");
                    assert_eq!(result.services.start_requests, 1, "{kind:?}");
                    assert_eq!(result.services.deleted, 1, "{kind:?}");
                    assert_eq!(result.services.dispatcher_attempts, 1, "{kind:?}");
                    assert!(
                        result
                            .services
                            .events
                            .iter()
                            .any(|event| event.binary.contains("svc.exe")),
                        "{kind:?}: {:?}",
                        result.services.events
                    );
                }
                F::Audit => {
                    // The credential-enumeration attempt is recorded.
                    assert_eq!(result.lsa.package_calls, 1, "{kind:?}");
                    assert!(result.lsa.audit_queries >= 1, "{kind:?}");
                }
                _ => {}
            }
        }
    }
}
