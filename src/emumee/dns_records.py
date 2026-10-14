"""Bounded offline DNS records derived from guest identity and explicit fixtures."""

import ipaddress
import re


TYPES = {"A": 1, "PTR": 12, "AAAA": 28}


def dns_name(value):
    if not isinstance(value, str):
        raise ValueError("DNS name must be text")
    value = (value[:-1] if value.endswith(".") else value).lower()
    if (not 1 <= len(value) <= 253 or any(not re.fullmatch(
            r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?", label) for label in value.split("."))):
        raise ValueError("Invalid guest DNS name")
    return value


def identity_records(persona):
    host = persona["hostname"].lower()
    domain = persona["domain"].lower()
    fqdn = host if domain == "workgroup" else host + "." + domain
    result = [{"name": host, "type": "A", "data": persona["network_adapter"]["ipv4"], "ttl": 60}]
    if fqdn != host:
        result.append({"name": fqdn, "type": "A", "data": persona["network_adapter"]["ipv4"], "ttl": 60})
    result.append({"name": ipaddress.IPv4Address(persona["network_adapter"]["ipv4"]).reverse_pointer,
                   "type": "PTR", "data": fqdn, "ttl": 60})
    for controller in persona["domain_discovery"]["controllers"]:
        result.extend((
            {"name": controller["name"].lower(), "type": "A", "data": controller["address"], "ttl": 60},
            {"name": ipaddress.IPv4Address(controller["address"]).reverse_pointer,
             "type": "PTR", "data": controller["name"].lower(), "ttl": 60}))
    return result


def validate_records(persona):
    records = persona["dns_records"]
    if not isinstance(records, list) or len(records) > 64:
        raise ValueError("Persona dns_records must be an array of at most 64 records")
    owned = {(r["name"], r["type"]): r["data"] for r in identity_records(persona)}
    seen = set()
    for record in records:
        if (not isinstance(record, dict) or set(record) != {"name", "type", "data", "ttl"} or
                not isinstance(record["type"], str) or record["type"] not in TYPES or
                not isinstance(record["data"], str) or
                type(record["ttl"]) is not int or not 0 <= record["ttl"] <= 604800):
            raise ValueError("Persona dns_records fields are invalid")
        try:
            name = dns_name(record["name"])
            if record["type"] == "PTR":
                data = dns_name(record["data"])
            else:
                address = ipaddress.ip_address(record["data"])
                if address.version != (4 if record["type"] == "A" else 6):
                    raise ValueError("record address family differs")
                data = str(address)
        except (ValueError, TypeError) as exc:
            raise ValueError("Persona dns_records name or data is invalid") from exc
        if (name, record["type"], data) in seen:
            raise ValueError("Persona dns_records contains a duplicate")
        seen.add((name, record["type"], data))
        if (name, record["type"]) in owned and owned[(name, record["type"])] != data:
            raise ValueError("Persona dns_records contradicts guest identity")


def record_catalog(persona):
    result = identity_records(persona)
    for record in persona["dns_records"]:
        normalized = dict(record, name=dns_name(record["name"]), data=(dns_name(record["data"])
            if record["type"] == "PTR" else str(ipaddress.ip_address(record["data"]))))
        if not any((r["name"], r["type"], r["data"]) ==
                   (normalized["name"], normalized["type"], normalized["data"]) for r in result):
            result.append(normalized)
    return result
