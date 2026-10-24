use super::*;
fn broadcast(a: Ipv4Addr, guest: Ipv4Addr, prefix: u32) -> bool {
    a == Ipv4Addr::BROADCAST
        || (prefix < 31 && u32::from(a) == ((u32::from(guest) & mask(prefix)) | !mask(prefix)))
}
fn canonical_ip(v: &Value, p: &str, version: u32) -> Result<String> {
    let a: IpAddr = text(v, p)?
        .parse()
        .map_err(|_| error(p, "invalid IP address"))?;
    match (a, version) {
        (IpAddr::V4(a), 4) => Ok(a.to_string()),
        (IpAddr::V6(a), 6) => Ok(a.to_string()),
        _ => Err(error(p, "IP address family mismatch")),
    }
}
pub(super) fn validate_network(p: &Value, clock: &ClockProjection) -> Result<()> {
    let discovery = &p["domain_discovery"];
    fields(
        discovery,
        "domain_discovery",
        &[
            "guid",
            "netbios_name",
            "forest_name",
            "site_name",
            "controllers",
            "trusts",
        ],
        &[],
    )?;
    guid(&discovery["guid"], "domain_discovery.guid")?;
    if !discovery["netbios_name"].is_null() {
        chars(
            &discovery["netbios_name"],
            "domain_discovery.netbios_name",
            1,
            15,
            |c| c.is_ascii_alphanumeric() || "_-".contains(c),
        )?;
    }
    if !discovery["forest_name"].is_null() {
        domain(&discovery["forest_name"], "domain_discovery.forest_name")?;
    }
    chars(
        &discovery["site_name"],
        "domain_discovery.site_name",
        1,
        64,
        |c| c.is_ascii_alphanumeric() || "_. -".contains(c),
    )?;
    let controllers = array(
        &discovery["controllers"],
        "domain_discovery.controllers",
        16,
    )?;
    let trusts = array(&discovery["trusts"], "domain_discovery.trusts", 16)?;
    require(
        (controllers.is_empty() && trusts.is_empty())
            || p["device_registration"]["domain_joined"] == true,
        "domain_discovery",
        "records require joined domain",
    )?;
    let mut names = BTreeSet::new();
    let mut pdc = 0;
    for c in controllers {
        fields(
            c,
            "domain_discovery.controllers[]",
            &["name", "address", "site_name", "pdc"],
            &[],
        )?;
        domain(&c["name"], "domain_discovery.controllers[].name")?;
        unique(
            &mut names,
            text(&c["name"], "domain_discovery.controllers[].name")?,
            "domain_discovery.controllers[].name",
        )?;
        require(
            unicast(ipv4(
                &c["address"],
                "domain_discovery.controllers[].address",
            )?),
            "domain_discovery.controllers[].address",
            "invalid controller address",
        )?;
        chars(
            &c["site_name"],
            "domain_discovery.controllers[].site_name",
            1,
            64,
            |c| c.is_ascii_alphanumeric() || "_. -".contains(c),
        )?;
        pdc += u32::from(boolean(&c["pdc"], "domain_discovery.controllers[].pdc")?);
    }
    require(
        pdc <= 1,
        "domain_discovery.controllers",
        "multiple primary controllers",
    )?;
    names.clear();
    names.insert(fold(text(&p["domain"], "domain")?));
    for t in trusts {
        fields(
            t,
            "domain_discovery.trusts[]",
            &["netbios_name", "dns_name", "direction"],
            &[],
        )?;
        chars(
            &t["netbios_name"],
            "domain_discovery.trusts[].netbios_name",
            1,
            15,
            |c| c.is_ascii_alphanumeric() || "_-".contains(c),
        )?;
        domain(&t["dns_name"], "domain_discovery.trusts[].dns_name")?;
        unique(
            &mut names,
            text(&t["dns_name"], "domain_discovery.trusts[].dns_name")?,
            "domain_discovery.trusts[].dns_name",
        )?;
        choices(
            &t["direction"],
            "domain_discovery.trusts[].direction",
            &["Inbound", "Outbound", "Bidirectional"],
        )?;
    }
    let a = &p["network_adapter"];
    fields(
        a,
        "network_adapter",
        &[
            "guid",
            "name",
            "description",
            "mac",
            "ipv4",
            "prefix_length",
            "gateway",
            "dns_servers",
            "dhcp_enabled",
            "mtu",
            "if_index",
            "pnp_instance_id",
        ],
        &[],
    )?;
    guid(&a["guid"], "network_adapter.guid")?;
    for name in ["name", "description"] {
        bounded_text(&a[name], &format!("network_adapter.{name}"), 1, 128)?;
    }
    let mac = text(&a["mac"], "network_adapter.mac")?;
    let bytes: Vec<_> = mac.split('-').collect();
    require(
        bytes.len() == 6
            && bytes
                .iter()
                .all(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_hexdigit())),
        "network_adapter.mac",
        "invalid MAC",
    )?;
    chars(
        &a["pnp_instance_id"],
        "network_adapter.pnp_instance_id",
        1,
        200,
        |c| c.is_ascii_alphanumeric() || "_&\\.:-".contains(c),
    )?;
    let prefix = unsigned(&a["prefix_length"], "network_adapter.prefix_length", 1, 32)? as u32;
    unsigned(&a["mtu"], "network_adapter.mtu", 576, 9000)?;
    unsigned(&a["if_index"], "network_adapter.if_index", 1, 65535)?;
    boolean(&a["dhcp_enabled"], "network_adapter.dhcp_enabled")?;
    let guest = ipv4(&a["ipv4"], "network_adapter.ipv4")?;
    let gateway = ipv4(&a["gateway"], "network_adapter.gateway")?;
    require(
        unicast(guest)
            && !gateway.is_multicast()
            && !gateway.is_loopback()
            && guest != gateway
            && (u32::from(guest) & mask(prefix)) == (u32::from(gateway) & mask(prefix)),
        "network_adapter",
        "invalid/offlink gateway or guest address",
    )?;
    let servers = array(&a["dns_servers"], "network_adapter.dns_servers", 4)?;
    require(
        !servers.is_empty(),
        "network_adapter.dns_servers",
        "empty DNS server list",
    )?;
    for server in servers {
        ipv4(server, "network_adapter.dns_servers[]")?;
    }
    let host = text(&p["hostname"], "hostname")?.to_lowercase();
    let domain_name = text(&p["domain"], "domain")?.to_lowercase();
    let fqdn = if domain_name == "workgroup" {
        host.clone()
    } else {
        format!("{host}.{domain_name}")
    };
    let reverse = |a: Ipv4Addr| {
        let b = a.octets();
        format!("{}.{}.{}.{}.in-addr.arpa", b[3], b[2], b[1], b[0])
    };
    let mut owned: BTreeMap<(String, String), String> = BTreeMap::new();
    owned.insert((host.clone(), "A".into()), guest.to_string());
    owned.insert((fqdn.clone(), "A".into()), guest.to_string());
    owned.insert((reverse(guest), "PTR".into()), fqdn.clone());
    if host != "localhost" {
        owned.insert(("localhost".into(), "A".into()), "127.0.0.1".into());
        owned.insert(
            ("1.0.0.127.in-addr.arpa".into(), "PTR".into()),
            "localhost".into(),
        );
    }
    for c in controllers {
        let name = text(&c["name"], "controller.name")?.to_lowercase();
        let address = ipv4(&c["address"], "controller.address")?;
        owned.insert((name.clone(), "A".into()), address.to_string());
        owned.insert((reverse(address), "PTR".into()), name);
    }
    let mut records = BTreeSet::new();
    for r in array(&p["dns_records"], "dns_records", 64)? {
        fields(r, "dns_records[]", &["name", "type", "data", "ttl"], &[])?;
        let name = dns(&r["name"], "dns_records[].name")?;
        choices(&r["type"], "dns_records[].type", &["A", "PTR", "AAAA"])?;
        let kind = text(&r["type"], "dns_records[].type")?;
        unsigned(&r["ttl"], "dns_records[].ttl", 0, 604800)?;
        let data = if kind == "PTR" {
            dns(&r["data"], "dns_records[].data")?
        } else {
            canonical_ip(
                &r["data"],
                "dns_records[].data",
                if kind == "A" { 4 } else { 6 },
            )?
        };
        require(
            records.insert((name.clone(), kind.to_owned(), data.clone())),
            "dns_records",
            "duplicate DNS record",
        )?;
        if let Some(expected) = owned.get(&(name.clone(), kind.into())) {
            require(
                expected == &data,
                "dns_records",
                "record contradicts guest identity",
            )?;
        }
    }
    let mut destinations = BTreeSet::new();
    for r in array(&p["icmp_responses"], "icmp_responses", 64)? {
        fields(
            r,
            "icmp_responses[]",
            &["address", "round_trip_ms", "ttl"],
            &["hops", "responds", "reply_pattern"],
        )?;
        let address = ipv4(&r["address"], "icmp_responses[].address")?;
        require(
            unicast(address)
                && address != guest
                && !broadcast(address, guest, prefix)
                && destinations.insert(address),
            "icmp_responses[].address",
            "duplicate/reserved/guest/broadcast address",
        )?;
        unsigned(
            &r["round_trip_ms"],
            "icmp_responses[].round_trip_ms",
            0,
            60000,
        )?;
        unsigned(&r["ttl"], "icmp_responses[].ttl", 1, 255)?;
        if let Some(v) = r.get("responds") {
            boolean(v, "icmp_responses[].responds")?;
        }
        if let Some(v) = r.get("reply_pattern") {
            let values = array(v, "icmp_responses[].reply_pattern", 1024)?;
            require(
                !values.is_empty(),
                "icmp_responses[].reply_pattern",
                "empty reply pattern",
            )?;
            for v in values {
                boolean(v, "icmp_responses[].reply_pattern[]")?;
            }
        }
        if let Some(v) = r.get("hops") {
            for hop in array(v, "icmp_responses[].hops", 254)? {
                if hop.is_null() {
                    continue;
                }
                fields(
                    hop,
                    "icmp_responses[].hops[]",
                    &["address", "round_trip_ms", "ttl"],
                    &[],
                )?;
                let hop_address = ipv4(&hop["address"], "icmp_responses[].hops[].address")?;
                require(
                    unicast(hop_address)
                        && hop_address != guest
                        && hop_address != address
                        && !broadcast(hop_address, guest, prefix),
                    "icmp_responses[].hops[].address",
                    "reserved or endpoint hop address",
                )?;
                unsigned(
                    &hop["round_trip_ms"],
                    "icmp_responses[].hops[].round_trip_ms",
                    0,
                    60000,
                )?;
                unsigned(&hop["ttl"], "icmp_responses[].hops[].ttl", 1, 255)?;
            }
        }
    }
    let t = &p["time_service"];
    fields(
        t,
        "time_service",
        &[
            "type",
            "source",
            "reference_ipv4",
            "stratum",
            "last_sync_utc",
            "poll_interval",
            "precision",
            "root_delay_ms",
            "root_dispersion_ms",
            "peers",
        ],
        &[],
    )?;
    choices(&t["type"], "time_service.type", &["NoSync", "NTP", "NT5DS"])?;
    let stratum = unsigned(&t["stratum"], "time_service.stratum", 0, 15)?;
    unsigned(&t["poll_interval"], "time_service.poll_interval", 4, 17)?;
    signed(&t["precision"], "time_service.precision", -30, 0)?;
    for k in ["root_delay_ms", "root_dispersion_ms"] {
        unsigned(&t[k], "time_service.delay", 0, 86400000)?;
    }
    let source = text(&t["source"], "time_service.source")?;
    require(
        source.len() <= 253,
        "time_service.source",
        "source exceeds bound",
    )?;
    let local = ["Local CMOS Clock", "Free-running System Clock"].contains(&source);
    let normalized = if local {
        source.into()
    } else {
        dns(&t["source"], "time_service.source")?
    };
    let reference = if t["reference_ipv4"].is_null() {
        None
    } else {
        Some(ipv4(&t["reference_ipv4"], "time_service.reference_ipv4")?)
    };
    let mut names = BTreeSet::new();
    let mut active = BTreeMap::new();
    let peers = array(&t["peers"], "time_service.peers", 8)?;
    for peer in peers {
        fields(
            peer,
            "time_service.peers[]",
            &["name", "state", "stratum", "poll_interval", "mode"],
            &[],
        )?;
        let name = dns(&peer["name"], "time_service.peers[].name")?;
        unique(&mut names, &name, "time_service.peers[].name")?;
        choices(
            &peer["state"],
            "time_service.peers[].state",
            &["Active", "Pending"],
        )?;
        unsigned(&peer["stratum"], "time_service.peers[].stratum", 0, 15)?;
        unsigned(
            &peer["poll_interval"],
            "time_service.peers[].poll_interval",
            4,
            17,
        )?;
        let mode = unsigned(&peer["mode"], "time_service.peers[].mode", 1, 3)?;
        require(
            matches!(mode, 1 | 3),
            "time_service.peers[].mode",
            "invalid mode",
        )?;
        if peer["state"] == "Active" {
            active.insert(name, peer);
        }
    }
    require(
        t["type"] != "NT5DS" || p["device_registration"]["domain_joined"] == true,
        "time_service.type",
        "NT5DS requires domain membership",
    )?;
    require(
        t["type"] != "NoSync" || (peers.is_empty() && local && stratum <= 1),
        "time_service",
        "NoSync cannot claim network source",
    )?;
    if stratum < 2 {
        require(
            reference.is_none() && local,
            "time_service",
            "local synchronization state inconsistent",
        )?;
    } else {
        let peer = active
            .get(&normalized)
            .ok_or_else(|| error("time_service.source", "missing active source peer"))?;
        let reference = reference.ok_or_else(|| {
            error(
                "time_service.reference_ipv4",
                "synchronized source needs reference",
            )
        })?;
        require(
            peer["stratum"].as_u64() == Some(stratum - 1) && reference != guest,
            "time_service",
            "reference/peer stratum inconsistent",
        )?;
        let known: Vec<_> = owned
            .iter()
            .filter(|((n, k), _)| n == &normalized && k == "A")
            .map(|(_, v)| v)
            .chain(
                records
                    .iter()
                    .filter(|(n, k, _)| n == &normalized && k == "A")
                    .map(|(_, _, v)| v),
            )
            .collect();
        if !known.is_empty() {
            let reference_text = reference.to_string();
            require(
                known.iter().any(|v| **v == reference_text),
                "time_service.reference_ipv4",
                "reference conflicts with guest DNS",
            )?;
        }
        if let Ok(literal) = source.parse::<Ipv4Addr>() {
            require(
                literal == reference,
                "time_service.reference_ipv4",
                "reference conflicts with literal source",
            )?;
        }
    }
    require(
        t["last_sync_utc"].is_null() == (stratum == 0),
        "time_service.last_sync_utc",
        "synchronization timestamp state inconsistent",
    )?;
    if !t["last_sync_utc"].is_null() {
        let last = timestamp(
            text(&t["last_sync_utc"], "time_service.last_sync_utc")?,
            "time_service.last_sync_utc",
            true,
        )?;
        require(
            last <= clock.utc_filetime,
            "time_service.last_sync_utc",
            "synchronization timestamp in future",
        )?;
    }
    Ok(())
}
