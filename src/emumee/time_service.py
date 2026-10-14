"""Windows Time read views from guest service, clock, and peer metadata."""

import datetime as dt
import ipaddress

from .clock import VirtualClock
from .dns_records import dns_name, record_catalog


COMMANDS = ("/query /source", "/query /status", "/query /configuration",
            "/query /peers", "/query /status /verbose")
LOCAL_SOURCES = ("Local CMOS Clock", "Free-running System Clock")


def validate_time_service(persona):
    value = persona["time_service"]
    fields = {"type", "source", "reference_ipv4", "stratum", "last_sync_utc",
              "poll_interval", "precision", "root_delay_ms", "root_dispersion_ms", "peers"}
    if not isinstance(value, dict) or set(value) != fields or value["type"] not in ("NoSync", "NTP", "NT5DS"):
        raise ValueError("Persona time_service fields are invalid")
    for name, low, high in (("stratum", 0, 15), ("poll_interval", 4, 17), ("precision", -30, 0),
                            ("root_delay_ms", 0, 86400000), ("root_dispersion_ms", 0, 86400000)):
        if type(value[name]) is not int or not low <= value[name] <= high:
            raise ValueError("Persona time_service " + name + " is invalid")
    if not isinstance(value["source"], str) or len(value["source"]) > 253:
        raise ValueError("Persona time_service source is invalid")
    try:
        source = value["source"] if value["source"] in LOCAL_SOURCES else dns_name(value["source"])
        reference = (None if value["reference_ipv4"] is None else
                     str(ipaddress.IPv4Address(value["reference_ipv4"])))
    except (ValueError, TypeError) as error:
        raise ValueError("Persona time_service source or reference address is invalid") from error
    if value["reference_ipv4"] is not None and not isinstance(value["reference_ipv4"], str):
        raise ValueError("Persona time_service reference address must be text")
    peers = value["peers"]
    if not isinstance(peers, list) or len(peers) > 8:
        raise ValueError("Persona time_service peers must have at most eight entries")
    names = set()
    active = {}
    for peer in peers:
        if (not isinstance(peer, dict) or set(peer) != {"name", "state", "stratum", "poll_interval", "mode"} or
                peer["state"] not in ("Active", "Pending") or type(peer["mode"]) is not int or
                peer["mode"] not in (1, 3) or type(peer["stratum"]) is not int or
                not 0 <= peer["stratum"] <= 15 or type(peer["poll_interval"]) is not int or
                not 4 <= peer["poll_interval"] <= 17):
            raise ValueError("Persona time_service peer fields are invalid")
        try:
            name = dns_name(peer["name"])
        except ValueError as error:
            raise ValueError("Persona time_service peer name is invalid") from error
        if name in names:
            raise ValueError("Persona time_service peer names must be unique")
        names.add(name)
        if peer["state"] == "Active":
            active[name] = peer
    if value["type"] == "NT5DS" and not persona["device_registration"]["domain_joined"]:
        raise ValueError("Persona time_service NT5DS requires domain membership")
    if value["type"] == "NoSync" and (peers or source not in LOCAL_SOURCES or value["stratum"] > 1):
        raise ValueError("Persona time_service NoSync cannot claim a network source")
    if value["stratum"] < 2:
        if reference is not None or source not in LOCAL_SOURCES:
            raise ValueError("Persona time_service local/unsynchronized state is inconsistent")
    else:
        peer = active.get(source)
        if (peer is None or reference is None or peer["stratum"] != value["stratum"] - 1 or
                reference == persona["network_adapter"]["ipv4"]):
            raise ValueError("Persona time_service synchronized source and peer are inconsistent")
        known = [r["data"] for r in record_catalog(persona) if r["name"] == source and r["type"] == "A"]
        try:
            literal = str(ipaddress.IPv4Address(source))
        except ValueError:
            literal = None
        if (known and reference not in known) or literal is not None and literal != reference:
            raise ValueError("Persona time_service reference conflicts with guest DNS")
    last = value["last_sync_utc"]
    if (last is None) != (value["stratum"] == 0):
        raise ValueError("Persona time_service synchronization timestamp is inconsistent")
    if last is not None:
        try:
            if not isinstance(last, str):
                raise ValueError()
            parsed = dt.datetime.strptime(last, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)
            if parsed > VirtualClock(persona).utc:
                raise ValueError()
        except (ValueError, TypeError) as error:
            raise ValueError("Persona time_service last_sync_utc is invalid or in the future") from error


def configuration(persona):
    value = persona["time_service"]
    manual = " ".join(peer["name"] + (",0x9" if peer["mode"] == 3 else ",0x5")
                      for peer in value["peers"]) if value["type"] == "NTP" else ""
    return {"Config": {"MinPollInterval": 4, "MaxPollInterval": 17},
            "Parameters": {"Type": value["type"], "NtpServer": manual},
            "TimeProviders\\NtpClient": {"Enabled": int(value["type"] != "NoSync"),
                                          "InputProvider": 1, "SpecialPollInterval": 2 ** value["poll_interval"]},
            "TimeProviders\\NtpServer": {"Enabled": 0, "InputProvider": 0}}


def query_status(persona):
    if not persona["user_is_admin"]:
        return 0x80070005, "Access is denied."
    service = next((s for s in persona["services"] if s["name"].casefold() == "w32time"), None)
    if service is None:
        return 0x80070424, "The specified service does not exist as an installed service."
    if service["start"] == 4 or not any(p.casefold() == service["process"].casefold() for p in persona["processes"]):
        return 0x80070426, "The service has not been started."
    return 0, ""


def time_service_text(persona, arguments):
    argument = arguments.casefold()
    if not argument:
        return "Usage: w32tm /query {/source | /status | /configuration | /peers} [/verbose]\r\n"
    if argument not in COMMANDS:
        raise ValueError("unsupported w32tm arguments")
    status, error = query_status(persona)
    if status:
        return f"The following error occurred: {error} (0x{status:08X})\r\n"
    value = persona["time_service"]
    if argument == "/query /source":
        return value["source"] + "\r\n"
    if argument == "/query /configuration":
        groups = configuration(persona)
        rows = ["[Configuration]", ""]
        rows.extend(f"{name}: {data} (Local)" for name, data in groups["Config"].items())
        rows.extend(f"{name}: {data} (Local)" for name, data in groups["Parameters"].items())
        rows.extend(("", "[TimeProviders]", ""))
        for provider in ("NtpClient", "NtpServer"):
            rows.append(provider + " (Local)")
            rows.extend(f"{name}: {data} (Local)" for name, data in groups["TimeProviders\\" + provider].items())
            rows.append("")
        return "\r\n".join(rows) + "\r\n"
    if argument == "/query /peers":
        rows = [f"#Peers: {len(value['peers'])}", ""]
        for peer in value["peers"]:
            mode = "Client" if peer["mode"] == 3 else "Symmetric Active"
            rows.extend((f"Peer: {peer['name']}", f"State: {peer['state']}", f"Mode: {peer['mode']} ({mode})",
                         f"Stratum: {peer['stratum']}",
                         f"PeerPoll Interval: {peer['poll_interval']} ({2 ** peer['poll_interval']}s)",
                         f"HostPoll Interval: {value['poll_interval']} ({2 ** value['poll_interval']}s)", ""))
        return "\r\n".join(rows) + "\r\n"
    clock = VirtualClock(persona)
    last = value["last_sync_utc"]
    parsed = dt.datetime.strptime(last, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc) if last else None
    local = (parsed + clock.offset).strftime("%m/%d/%Y %H:%M:%S") if parsed else "unspecified"
    stratum = value["stratum"]
    description = ("unspecified" if not stratum else "primary reference - syncd by radio clock" if stratum == 1 else
                   "secondary reference - syncd by (S)NTP")
    if value["reference_ipv4"]:
        address = value["reference_ipv4"]
        reference = f"0x{int(ipaddress.IPv4Address(address)):08X} (source IP: {address})"
    else:
        reference = '0x4C4F434C (source name: "LOCL")' if stratum == 1 else "0x00000000 (unspecified)"
    resolution = 2 ** value["precision"]
    unit, scale = ("ns", 1_000_000_000) if resolution < .000001 else ("ms", 1000) if resolution < 1 else ("s", 1)
    rows = [f"Leap Indicator: {'0(no warning)' if stratum else '3(not synchronized)'}",
            f"Stratum: {stratum} ({description})",
            f"Precision: {value['precision']} ({resolution * scale:.3f}{unit} per tick)",
            f"Root Delay: {value['root_delay_ms'] / 1000:.7f}s",
            f"Root Dispersion: {value['root_dispersion_ms'] / 1000:.7f}s", f"ReferenceId: {reference}",
            f"Last Successful Sync Time: {local}", f"Source: {value['source']}",
            f"Poll Interval: {value['poll_interval']} ({2 ** value['poll_interval']}s)"]
    if argument.endswith(" /verbose"):
        elapsed = f"{max(0, int((clock.utc - parsed).total_seconds()))}s" if parsed else "unspecified"
        rows.append(f"Time since Last Good Sync Time: {elapsed}")
    return "\r\n".join(rows) + "\r\n"
