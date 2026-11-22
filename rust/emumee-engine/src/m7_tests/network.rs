//! Network control family: the IP Helper enumeration, ICMP echo, DNS
//! resolution, the LAN Manager workstation and redirector surfaces, and the
//! WinINet/WinHTTP URL and option surfaces.
//!
//! Each control decides its own outcome inside the guest; the assertions here
//! are about what the run *recorded*, which is the evidence a report carries.
use super::*;
use emumee_core::fixtures::{M7NetworkFixture as F, m7_network_probe};

fn control(arch: Architecture, kind: F) -> Execution {
    let label = format!("{arch:?}-m7-network-{kind:?}");
    let result = run(&label, m7_network_probe(arch, kind), &[], 60_000);
    succeeded(&label, &result);
    result
}

#[test]
fn m7_ip_helper_enumeration_is_guest_decided_and_persona_consistent() {
    for arch in [Architecture::X86, Architecture::X64] {
        let result = control(arch, F::Adapter);
        // Two size queries and two filled answers.
        assert_eq!(result.adapters.queries, 4, "{arch:?}");
        assert!(
            result
                .adapters
                .events
                .iter()
                .any(|event| event.api == "GetAdaptersInfo" && event.status == 0),
            "{arch:?}: {:?}",
            result.adapters.events
        );
        let expected = if arch == Architecture::X64 { 704 } else { 648 };
        assert!(
            result
                .adapters
                .events
                .iter()
                .any(|event| event.api == "GetAdaptersInfo" && event.required == expected),
            "{arch:?}: {:?}",
            result.adapters.events
        );

        let result = control(arch, F::Addresses);
        assert_eq!(result.adapters.queries, 4, "{arch:?}");
        // An unmodeled flag set and an IPv6-only enumeration are both refused
        // rather than answered with a partial graph.
        assert!(
            result
                .adapters
                .events
                .iter()
                .any(|event| event.status == 50),
            "{arch:?}: {:?}",
            result.adapters.events
        );
        assert!(
            result
                .adapters
                .events
                .iter()
                .any(|event| event.status == 232),
            "{arch:?}: {:?}",
            result.adapters.events
        );

        let result = control(arch, F::Tables);
        assert_eq!(result.adapters.queries, 7, "{arch:?}");
        assert!(
            result.adapters.events.iter().any(|event| event.api
                == "GetExtendedTcpTable"
                && event.detail == "no established connection"),
            "{arch:?}: {:?}",
            result.adapters.events
        );
        // The tables are persona-derived, so no HTTP broker path is reached.
        assert_eq!(result.network.calls, 0, "{arch:?}");
    }
}

#[test]
fn m7_icmp_echo_captures_its_payload_and_reports_the_unreachable_peer() {
    for arch in [Architecture::X86, Architecture::X64] {
        let result = control(arch, F::Icmp);
        assert_eq!(result.icmp.handles_opened, 1, "{arch:?}");
        assert_eq!(result.icmp.echo_attempts, 2, "{arch:?}");
        assert_eq!(result.icmp.replies, 1, "{arch:?}");
        assert_eq!(result.icmp.bytes_offered, 22, "{arch:?}");
        assert!(
            result
                .icmp
                .events
                .iter()
                .any(|event| event.host == "10.0.2.99" && event.status == 11010),
            "{arch:?}: {:?}",
            result.icmp.events
        );
        assert!(
            result
                .icmp
                .events
                .iter()
                .any(|event| event.host == "127.0.0.1" && event.replied),
            "{arch:?}: {:?}",
            result.icmp.events
        );
        // Both echo payloads are preserved as evidence, whether or not
        // anything replied. They carry the same bytes, so capture stores them
        // once with one observation per echo.
        assert_eq!(result.artifacts.len(), 1, "{arch:?}: {:?}", result.artifacts);
        assert_eq!(
            result.artifacts[0].observations.len(),
            2,
            "{arch:?}: {:?}",
            result.artifacts
        );
    }
}

#[test]
fn m7_dns_answers_the_guests_own_catalog_and_records_what_it_cannot_resolve() {
    for arch in [Architecture::X86, Architecture::X64] {
        let result = control(arch, F::Dns);
        assert_eq!(result.dns.queries, 5, "{arch:?}");
        assert_eq!(result.dns.answered, 1, "{arch:?}");
        assert_eq!(result.dns.unresolved, 4, "{arch:?}");
        assert!(
            result.dns.events.iter().any(|event| event.name
                == "desktop-7f4m2q9"
                && event.answers == vec!["10.0.2.15".to_string()]),
            "{arch:?}: {:?}",
            result.dns.events
        );
        // The name this profile cannot resolve is recorded, never invented.
        assert!(
            result
                .dns
                .events
                .iter()
                .any(|event| event.name == "no-such-host.invalid" && event.status == 9003),
            "{arch:?}: {:?}",
            result.dns.events
        );
    }
}

#[test]
fn m7_workstation_and_redirector_record_the_account_and_share_attempts() {
    for arch in [Architecture::X86, Architecture::X64] {
        let result = control(arch, F::Workstation);
        assert_eq!(result.lanman.queries, 4, "{arch:?}");
        assert_eq!(result.lanman.accounts_added, 1, "{arch:?}");
        // The attempted account is recorded in full, and the password is
        // noted as supplied without being copied into evidence.
        let added = result
            .lanman
            .events
            .iter()
            .find(|event| event.api == "NetUserAdd")
            .unwrap_or_else(|| panic!("{arch:?}: {:?}", result.lanman.events));
        assert!(
            added.detail.contains("svc-backdoor")
                && added.detail.contains("privilege 2")
                && added.detail.contains("password supplied")
                && !added.detail.contains("Pa55w0rd"),
            "{arch:?}: {}",
            added.detail
        );

        let result = control(arch, F::Redirector);
        assert_eq!(result.lanman.queries, 6, "{arch:?}");
        assert_eq!(result.lanman.share_attempts, 3, "{arch:?}");
        let mapped = result
            .lanman
            .events
            .iter()
            .find(|event| event.api == "WNetAddConnection2" && event.status == 1222)
            .unwrap_or_else(|| panic!("{arch:?}: {:?}", result.lanman.events));
        assert!(
            mapped.detail.contains("\\\\10.0.2.20\\payroll")
                && mapped.detail.contains("Z:")
                && mapped.detail.contains("WORKGROUP\\admin")
                && mapped.detail.contains("password supplied")
                && !mapped.detail.contains("Pa55w0rd"),
            "{arch:?}: {}",
            mapped.detail
        );
    }
}

#[test]
fn m7_http_url_cracking_and_options_are_guest_decided() {
    for arch in [Architecture::X86, Architecture::X64] {
        let result = control(arch, F::CrackUrl);
        assert_eq!(result.http_config.urls_cracked, 3, "{arch:?}");
        assert!(
            result.http_config.events.iter().any(|event| event.api
                == "InternetCrackUrl"
                && event.detail == "https://files.example:8443/drop/p.bin?id=7"),
            "{arch:?}: {:?}",
            result.http_config.events
        );

        let result = control(arch, F::Options);
        assert_eq!(result.http_config.option_queries, 5, "{arch:?}");
        assert_eq!(result.http_config.option_sets, 2, "{arch:?}");
        assert!(
            result
                .http_config
                .events
                .iter()
                .any(|event| event.detail == "option 2 = 7500"),
            "{arch:?}: {:?}",
            result.http_config.events
        );

        let result = control(arch, F::WinHttp);
        assert_eq!(result.http_config.urls_cracked, 2, "{arch:?}");
        assert_eq!(result.http_config.proxy_queries, 2, "{arch:?}");
        assert_eq!(result.http_config.option_sets, 2, "{arch:?}");
        assert_eq!(result.http_config.headers_added, 3, "{arch:?}");
        // The URL a sample wanted a proxy route for is recorded even though
        // autodetection has nothing to find.
        assert!(
            result.http_config.events.iter().any(|event| event.api
                == "WinHttpGetProxyForUrl"
                && event.detail.starts_with("http://files.example/drop")),
            "{arch:?}: {:?}",
            result.http_config.events
        );
    }
}
