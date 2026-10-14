"""Configurable Windows 11 identity and virtual environment."""

from __future__ import annotations

import base64
import binascii
import copy
import datetime as dt
import ipaddress
import json
import ntpath
import re
from pathlib import Path

from speakeasy.config import get_default_config_dict
from .kerberos import ENCRYPTION_TYPES, ticket_datetime
from .audit_policy import validate_policy
from .dns_records import validate_records
from .time_service import validate_time_service

from .persona_content import (DISPLAY_VERSIONS, PROCESS_PATHS, desktop_files,
                              driver_package_files, registry_keys)


WINDOWS_11_DISPLAY_VERSIONS = DISPLAY_VERSIONS
DEFAULT_VOLUME_GUID = "{6f2a9e4d-81b7-4f03-a73c-2d0e6f12a5b8}"
DEFAULT_VOLUME_CAPACITY_BYTES = 512 * 1024 ** 3
DEFAULT_VOLUME_FREE_BYTES = 320 * 1024 ** 3


DEFAULT_PERSONA = {
    "hostname": "DESKTOP-7F4M2Q9",
    "domain": "WORKGROUP",
    "domain_discovery": {
        "guid": "{a63ed21e-128d-42e8-bacf-12f2fa420213}",
        "netbios_name": None, "forest_name": None,
        "site_name": "Default-First-Site-Name", "controllers": [], "trusts": [],
    },
    "user_name": "Alex",
    "user_is_admin": False,
    "user_sid": "S-1-5-21-1243773969-3482195721-2078146024-1001",
    "windows_build": 22631,
    "physical_memory_mb": 16384,
    "available_memory_mb": 7168,
    "cpu": {
        "brand": "Intel(R) Core(TM) i5-10400 CPU @ 2.90GHz",
        "signature": 0x000A0653,
        "cores": 6,
        "threads_per_core": 2,
        "base_mhz": 2900,
        "max_mhz": 4300,
    },
    "network_adapter": {
        "guid": "{7A91D3B6-46CF-4D12-9D5B-8E7C412A9360}",
        "name": "Ethernet",
        "description": "Intel(R) Ethernet Connection (7) I219-V",
        "mac": "3C-52-82-4A-6F-19",
        "ipv4": "192.168.1.107",
        "prefix_length": 24,
        "gateway": "192.168.1.1",
        "dns_servers": ["192.168.1.1"],
        "dhcp_enabled": True,
        "mtu": 1500,
        "if_index": 12,
        "pnp_instance_id": r"PCI\VEN_8086&DEV_0D4F&SUBSYS_00008086&REV_00\3&11583659&0&FE",
    },
    "current_dir": "C:\\Users\\Alex\\Downloads",
    "volume_guid": DEFAULT_VOLUME_GUID,
    "volume_capacity_bytes": DEFAULT_VOLUME_CAPACITY_BYTES,
    "volume_free_bytes": DEFAULT_VOLUME_FREE_BYTES,
    "bitlocker": {"encryption_method": "None", "protection_enabled": False,
                  "key_protectors": []},
    "shadow_copies": [],
    "backup_versions": [],
    "stored_credentials": [],
    "dns_records": [],
    "kerberos": {"logon_id": 0x10001, "tickets": []},
    "boot_config": {
        "loader_guid": "{17f03c5e-781a-429f-90d7-5f6a8e1472c3}",
        "description": "Windows 11",
        "timeout_seconds": 30,
        "hypervisor_launch_type": None,
        "debug": False,
        "safe_boot": None,
    },
    "group_policy": {
        "computer": ["Local Group Policy"],
        "user": ["Local Group Policy"],
    },
    "audit_policy": {"read_allowed": False, "subcategories": {}},
    "time_service": {"type": "NoSync", "source": "Local CMOS Clock", "reference_ipv4": None,
                     "stratum": 0, "last_sync_utc": None, "poll_interval": 6, "precision": -23,
                     "root_delay_ms": 0, "root_dispersion_ms": 10000, "peers": []},
    "device_registration": {
        "azure_ad_joined": False,
        "enterprise_joined": False,
        "domain_joined": False,
        "workplace_joined": False,
        "azure_ad_prt": False,
    },
    "locale": "en-US",
    "timezone": "Eastern Standard Time",
    "utc_offset_minutes": -240,
    "clock_utc": None,
    "uptime_ms": 523_812_000,
    "processes": [
        "System", "smss.exe", "csrss.exe", "wininit.exe", "services.exe",
        "lsass.exe", "svchost.exe", "svchost.exe", "winlogon.exe", "dwm.exe",
        "explorer.exe", "sihost.exe", "SearchHost.exe",
        "StartMenuExperienceHost.exe", "RuntimeBroker.exe", "MsMpEng.exe",
        "SecurityHealthSystray.exe", "OneDrive.exe",
    ],
    "services": [
        {"name": "WinDefend", "display_name": "Microsoft Defender Antivirus Service",
         "process": "MsMpEng.exe", "start": 2, "type": 16},
        {"name": "EventLog", "display_name": "Windows Event Log",
         "process": "svchost.exe", "start": 2, "type": 32},
        {"name": "W32Time", "display_name": "Windows Time",
         "process": "svchost.exe", "start": 3, "type": 32},
    ],
    "drivers": [
        {"name": "ACPI", "display_name": "Microsoft ACPI Driver",
         "path": r"System32\drivers\ACPI.sys", "start": 0,
         "type": 1, "running": True},
        {"name": "Wdf01000", "display_name": "Kernel Mode Driver Framework Runtime",
         "path": r"System32\drivers\Wdf01000.sys", "start": 3,
         "type": 1, "running": True},
        {"name": "WdFilter", "display_name": "Microsoft Defender Antivirus Mini-Filter Driver",
         "path": r"System32\drivers\WdFilter.sys", "start": 0,
         "type": 2, "running": True},
    ],
    "minifilters": [
        {"name": "WdFilter", "altitude": "328010", "instances": 1},
    ],
    "driver_packages": [
        {"published_name": "oem0.inf", "original_name": "e1d68x64.inf",
         "provider": "Intel", "class_name": "Net",
         "class_guid": "{4d36e972-e325-11ce-bfc1-08002be10318}",
         "version": "09/15/2022 12.19.2.45",
         "signer": "Microsoft Windows Hardware Compatibility Publisher"},
    ],
    "pnp_devices": [
        {"instance_id": r"PCI\VEN_8086&DEV_0D4F&SUBSYS_00008086&REV_00\3&11583659&0&FE",
         "description": "Intel(R) Ethernet Connection (7) I219-V",
         "class_name": "Net",
         "class_guid": "{4d36e972-e325-11ce-bfc1-08002be10318}",
         "status": "Started", "driver": "oem0.inf"},
    ],
    "event_channels": [
        {"name": "Application", "enabled": True, "max_size": 20971520,
         "retention": False},
        {"name": "Security", "enabled": True, "max_size": 20971520,
         "retention": False},
        {"name": "System", "enabled": True, "max_size": 20971520,
         "retention": False},
    ],
    "scheduled_tasks": [
        {"name": r"\Microsoft\Windows\Defender\Windows Defender Scheduled Scan",
         "status": "Ready", "next_run_minutes": 480},
    ],
    "registry_keys": [],
    "virtual_files": [],
}
DEFAULT_PERSONA["registry_keys"] = registry_keys(DEFAULT_PERSONA)
DEFAULT_PERSONA["virtual_files"] = desktop_files(
    DEFAULT_PERSONA["user_name"], DEFAULT_PERSONA["hostname"])


def virtual_file_bytes(entry: dict) -> bytes:
    if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
        raise ValueError("Each virtual_files entry needs a string path")
    if set(entry) == {"path", "text"} and isinstance(entry["text"], str):
        content = entry["text"].encode("utf-8")
    elif set(entry) == {"path", "base64"} and isinstance(entry["base64"], str):
        encoded = entry["base64"]
        if len(encoded) > 4 * ((1024 * 1024 + 2) // 3):
            raise ValueError("Persona virtual file exceeds 1 MiB")
        try:
            content = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ValueError("Persona virtual file base64 is invalid") from exc
    else:
        raise ValueError("Each virtual_files entry needs path and exactly one of text or base64")
    if len(content) > 1024 * 1024:
        raise ValueError("Persona virtual file exceeds 1 MiB")
    return content


def load_persona(path: Path | None) -> dict:
    persona = copy.deepcopy(DEFAULT_PERSONA)
    previous_adapter_description = persona["network_adapter"]["description"]
    refresh_registry = False
    custom_files = False
    if path is not None:
        supplied = json.loads(path.read_text(encoding="utf-8"))
        unknown = set(supplied) - set(persona)
        if unknown:
            raise ValueError(f"Unknown persona fields: {', '.join(sorted(unknown))}")
        if "cpu" in supplied:
            if not isinstance(supplied["cpu"], dict):
                raise ValueError("Persona cpu must be an object")
            unknown_cpu = set(supplied["cpu"]) - set(persona["cpu"])
            if unknown_cpu:
                raise ValueError(f"Unknown persona cpu fields: {', '.join(sorted(unknown_cpu))}")
            persona["cpu"].update(supplied.pop("cpu"))
        if "network_adapter" in supplied:
            adapter = supplied.pop("network_adapter")
            if not isinstance(adapter, dict):
                raise ValueError("Persona network_adapter must be an object")
            unknown_adapter = set(adapter) - set(persona["network_adapter"])
            if unknown_adapter:
                raise ValueError("Unknown persona network_adapter fields: " +
                                 ", ".join(sorted(unknown_adapter)))
            persona["network_adapter"].update(adapter)
        if "boot_config" in supplied:
            boot = supplied.pop("boot_config")
            if not isinstance(boot, dict):
                raise ValueError("Persona boot_config must be an object")
            unknown_boot = set(boot) - set(persona["boot_config"])
            if unknown_boot:
                raise ValueError("Unknown persona boot_config fields: " +
                                 ", ".join(sorted(unknown_boot)))
            persona["boot_config"].update(boot)
        if "bitlocker" in supplied:
            bitlocker = supplied.pop("bitlocker")
            if not isinstance(bitlocker, dict) or set(bitlocker) - set(persona["bitlocker"]):
                raise ValueError("Persona bitlocker fields are invalid")
            persona["bitlocker"].update(bitlocker)
        if "kerberos" in supplied:
            kerberos = supplied.pop("kerberos")
            if not isinstance(kerberos, dict) or set(kerberos) - set(persona["kerberos"]):
                raise ValueError("Persona kerberos fields are invalid")
            persona["kerberos"].update(kerberos)
        if "domain_discovery" in supplied:
            discovery = supplied.pop("domain_discovery")
            if not isinstance(discovery, dict) or set(discovery) - set(persona["domain_discovery"]):
                raise ValueError("Persona domain_discovery fields are invalid")
            persona["domain_discovery"].update(discovery)
        if "time_service" in supplied:
            time_service = supplied.pop("time_service")
            if not isinstance(time_service, dict) or set(time_service) - set(persona["time_service"]):
                raise ValueError("Persona time_service fields are invalid")
            persona["time_service"].update(time_service)
        if "audit_policy" in supplied:
            audit = supplied.pop("audit_policy")
            if not isinstance(audit, dict) or set(audit) - set(persona["audit_policy"]):
                raise ValueError("Persona audit_policy fields are invalid")
            persona["audit_policy"].update(audit)
        if "group_policy" in supplied:
            policy = supplied.pop("group_policy")
            if not isinstance(policy, dict):
                raise ValueError("Persona group_policy must be an object")
            unknown_policy = set(policy) - set(persona["group_policy"])
            if unknown_policy:
                raise ValueError("Unknown persona group_policy fields: " +
                                 ", ".join(sorted(unknown_policy)))
            persona["group_policy"].update(policy)
        custom_registration = "device_registration" in supplied
        if custom_registration:
            registration = supplied.pop("device_registration")
            if not isinstance(registration, dict):
                raise ValueError("Persona device_registration must be an object")
            unknown_registration = set(registration) - set(persona["device_registration"])
            if unknown_registration:
                raise ValueError("Unknown persona device_registration fields: " +
                                 ", ".join(sorted(unknown_registration)))
            persona["device_registration"].update(registration)
        elif "domain" in supplied:
            persona["device_registration"]["domain_joined"] = (
                supplied["domain"] != "WORKGROUP")
        custom_registry = "registry_keys" in supplied
        refresh_registry = not custom_registry
        if "drivers" in supplied and "minifilters" not in supplied:
            persona["minifilters"] = []
        custom_devices = "pnp_devices" in supplied
        custom_packages = "driver_packages" in supplied
        custom_files = "virtual_files" in supplied
        custom_current_dir = "current_dir" in supplied
        previous_name = persona["user_name"]
        persona.update(supplied)
        if not custom_devices:
            default_device = persona["pnp_devices"][0]
            if persona["network_adapter"]["description"] != previous_adapter_description:
                default_device["description"] = persona["network_adapter"]["description"]
            default_device["instance_id"] = persona["network_adapter"]["pnp_instance_id"]
            if custom_packages and isinstance(persona["driver_packages"], list) and not any(
                    str(package.get("published_name", "")).casefold() == "oem0.inf"
                    for package in persona["driver_packages"] if isinstance(package, dict)):
                default_device["driver"] = None
        offset = persona["utc_offset_minutes"]
        if (not isinstance(offset, int) or isinstance(offset, bool) or
                not -840 <= offset <= 840):
            raise ValueError("Persona utc_offset_minutes must be between -840 and 840")
        timezone_name = persona["timezone"]
        if (not isinstance(timezone_name, str) or not timezone_name or
                len(timezone_name) > 127 or any(char in timezone_name
                                                for char in "\\/\0")):
            raise ValueError("Persona timezone must be a nonempty Windows time zone name")
        try:
            if len(timezone_name.encode("utf-16le")) > 254:
                raise ValueError("Persona timezone name exceeds Windows key limit")
        except UnicodeEncodeError as exc:
            raise ValueError("Persona timezone name is not valid Unicode") from exc
        if (persona["user_name"] != previous_name and not custom_current_dir and
                persona["current_dir"].casefold() ==
                rf"C:\Users\{previous_name}\Downloads".casefold()):
            persona["current_dir"] = rf"C:\Users\{persona['user_name']}\Downloads"
        if not custom_files:
            persona["virtual_files"] = desktop_files(
                persona["user_name"], persona["hostname"])
    if not persona["user_name"] or not persona["hostname"]:
        raise ValueError("Persona user_name and hostname must not be empty")
    if not isinstance(persona["user_is_admin"], bool):
        raise ValueError("Persona user_is_admin must be a boolean")
    if (not isinstance(persona["volume_guid"], str) or
            not re.fullmatch(r"\{[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\}",
                             persona["volume_guid"])):
        raise ValueError("Persona volume_guid must be a braced GUID")
    capacity, free = persona["volume_capacity_bytes"], persona["volume_free_bytes"]
    if (any(not isinstance(value, int) or isinstance(value, bool)
            for value in (capacity, free)) or
            not 0 <= free <= capacity or not 1 <= capacity <= 16 * 1024 ** 4):
        raise ValueError("Persona volume capacity or free bytes are invalid")
    bitlocker = persona["bitlocker"]
    if (bitlocker["encryption_method"] not in ("None", "XTS-AES 128", "XTS-AES 256") or
            not isinstance(bitlocker["protection_enabled"], bool) or
            not isinstance(bitlocker["key_protectors"], list) or
            len(bitlocker["key_protectors"]) > 2 or
            any(value not in ("TPM", "Numerical Password") for value in bitlocker["key_protectors"]) or
            len(set(bitlocker["key_protectors"])) != len(bitlocker["key_protectors"]) or
            bitlocker["encryption_method"] == "None" and (
                bitlocker["protection_enabled"] or bitlocker["key_protectors"]) or
            bitlocker["protection_enabled"] and not bitlocker["key_protectors"]):
        raise ValueError("Persona bitlocker fields are inconsistent")
    shadows = persona["shadow_copies"]
    if not isinstance(shadows, list) or len(shadows) > 16:
        raise ValueError("Persona shadow_copies must have at most 16 entries")
    shadow_ids: set[str] = set()
    shadow_set_times: dict[str, str] = {}
    for shadow in shadows:
        if (not isinstance(shadow, dict) or
                set(shadow) != {"id", "set_id", "created_utc"} or
                any(not isinstance(shadow[field], str) or
                    not re.fullmatch(
                        r"\{[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\}",
                        shadow[field]) for field in ("id", "set_id")) or
                shadow["id"].casefold() in shadow_ids or
                not isinstance(shadow["created_utc"], str) or
                not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
                                 shadow["created_utc"])):
            raise ValueError("Persona shadow copy entries are invalid")
        try:
            dt.datetime.strptime(shadow["created_utc"], "%Y-%m-%dT%H:%M:%SZ")
        except ValueError as exc:
            raise ValueError("Persona shadow copy creation time is invalid") from exc
        shadow_ids.add(shadow["id"].casefold())
        set_key = shadow["set_id"].casefold()
        if (set_key in shadow_set_times and
                shadow_set_times[set_key] != shadow["created_utc"]):
            raise ValueError("Persona shadow copy set creation times differ")
        shadow_set_times[set_key] = shadow["created_utc"]
    kerberos = persona["kerberos"]
    if (not isinstance(kerberos["logon_id"], int) or isinstance(kerberos["logon_id"], bool) or
            not 1 <= kerberos["logon_id"] < 2 ** 64 or
            not isinstance(kerberos["tickets"], list) or len(kerberos["tickets"]) > 16):
        raise ValueError("Persona kerberos fields are invalid")
    for ticket in kerberos["tickets"]:
        if (not isinstance(ticket, dict) or set(ticket) != {
                "server", "realm", "encryption_type", "session_key_type", "flags",
                "start_utc", "end_utc", "renew_utc"} or
                any(not isinstance(ticket[field], str) or
                    not re.fullmatch(r"[A-Za-z0-9_./:@-]{1,256}", ticket[field])
                    for field in ("server", "realm")) or
                any(not isinstance(ticket[field], int) or isinstance(ticket[field], bool) or
                    ticket[field] not in ENCRYPTION_TYPES
                    for field in ("encryption_type", "session_key_type")) or
                not isinstance(ticket["flags"], int) or isinstance(ticket["flags"], bool) or
                not 0 <= ticket["flags"] <= 0xffffffff or
                any(not isinstance(ticket[field], str) or
                    not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
                                     ticket[field])
                    for field in ("start_utc", "end_utc", "renew_utc"))):
            raise ValueError("Persona Kerberos ticket metadata is invalid")
        try:
            start, end, renew = (ticket_datetime(ticket[field])
                                 for field in ("start_utc", "end_utc", "renew_utc"))
            if not dt.datetime(1601, 1, 1) <= start <= end <= renew <= dt.datetime(9998, 12, 31):
                raise ValueError("ticket time order")
        except ValueError as exc:
            raise ValueError("Persona Kerberos ticket times are invalid") from exc
    backups = persona["backup_versions"]
    if not isinstance(backups, list) or len(backups) > 16:
        raise ValueError("Persona backup_versions must have at most 16 entries")
    backup_ids: set[str] = set()
    for backup in backups:
        if (not isinstance(backup, dict) or
                set(backup) != {"created_utc", "target", "recovery_types"} or
                not isinstance(backup["created_utc"], str) or
                not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", backup["created_utc"]) or
                not isinstance(backup["target"], str) or not 1 <= len(backup["target"]) <= 256 or
                any(ord(char) < 32 for char in backup["target"]) or
                not isinstance(backup["recovery_types"], list) or
                not 1 <= len(backup["recovery_types"]) <= 5 or
                any(value not in ("Volumes", "Files", "Applications", "Bare Metal Recovery", "System State")
                    for value in backup["recovery_types"]) or
                len(set(backup["recovery_types"])) != len(backup["recovery_types"])):
            raise ValueError("Persona backup version metadata is invalid")
        try:
            created = dt.datetime.strptime(backup["created_utc"], "%Y-%m-%dT%H:%M:%SZ")
            if not 1601 <= created.year <= 9998:
                raise ValueError("backup year")
        except ValueError as exc:
            raise ValueError("Persona backup creation time is invalid") from exc
        version = created.strftime("%m/%d/%Y-%H:%M")
        if version in backup_ids:
            raise ValueError("Persona backup version identifiers are duplicated")
        backup_ids.add(version)
    credentials = persona["stored_credentials"]
    if not isinstance(credentials, list) or len(credentials) > 32:
        raise ValueError("Persona stored_credentials must have at most 32 entries")
    credential_targets: set[tuple[str, str]] = set()
    for credential in credentials:
        if (not isinstance(credential, dict) or
                set(credential) != {"target", "user", "type", "persistence"} or
                any(not isinstance(credential[field], str) or
                    not 1 <= len(credential[field]) <= 256 or
                    any(ord(char) < 32 for char in credential[field])
                    for field in ("target", "user")) or
                credential["type"] not in ("Generic", "Domain Password") or
                credential["persistence"] not in ("Session", "Local computer", "Enterprise")):
            raise ValueError("Persona stored credential entries are invalid")
        key = (credential["target"].casefold(), credential["type"])
        if key in credential_targets:
            raise ValueError("Persona stored credential targets are duplicated")
        credential_targets.add(key)
    boot = persona["boot_config"]
    if (not isinstance(boot["loader_guid"], str) or
            not re.fullmatch(r"\{[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\}",
                             boot["loader_guid"]) or
            not isinstance(boot["description"], str) or
            not 1 <= len(boot["description"]) <= 80 or
            any(ord(char) < 32 for char in boot["description"]) or
            not isinstance(boot["timeout_seconds"], int) or
            isinstance(boot["timeout_seconds"], bool) or
            not 0 <= boot["timeout_seconds"] <= 999 or
            boot["hypervisor_launch_type"] not in (None, "Auto", "Off") or
            not isinstance(boot["debug"], bool) or
            boot["safe_boot"] not in (None, "Minimal", "Network")):
        raise ValueError("Persona boot_config fields are invalid")
    validate_policy(persona["audit_policy"])
    policy = persona["group_policy"]
    for scope in ("computer", "user"):
        entries = policy[scope]
        if (not isinstance(entries, list) or len(entries) > 16 or
                any(not isinstance(entry, str) or
                    not 1 <= len(entry) <= 128 or
                    any(ord(char) < 32 for char in entry)
                    for entry in entries) or
                len({entry.casefold() for entry in entries}) != len(entries)):
            raise ValueError("Persona group_policy entries are invalid")
    registration = persona["device_registration"]
    if (any(not isinstance(value, bool) for value in registration.values()) or
            registration["azure_ad_joined"] and registration["enterprise_joined"] or
            registration["domain_joined"] and persona["domain"] == "WORKGROUP" or
            registration["azure_ad_prt"] and not (
                registration["azure_ad_joined"] or registration["workplace_joined"])):
        raise ValueError("Persona device_registration fields are inconsistent")
    discovery = persona["domain_discovery"]
    dns_pattern = r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?"
    if (not isinstance(persona["domain"], str) or
            not re.fullmatch(dns_pattern, persona["domain"]) or
            not isinstance(discovery["guid"], str) or
            not re.fullmatch(r"\{[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\}", discovery["guid"]) or
            discovery["netbios_name"] is not None and (
                not isinstance(discovery["netbios_name"], str) or
                not re.fullmatch(r"[A-Za-z0-9_-]{1,15}", discovery["netbios_name"])) or
            discovery["forest_name"] is not None and (
                not isinstance(discovery["forest_name"], str) or
                not re.fullmatch(dns_pattern, discovery["forest_name"])) or
            not isinstance(discovery["site_name"], str) or
            not re.fullmatch(r"[A-Za-z0-9_. -]{1,64}", discovery["site_name"]) or
            any(not isinstance(discovery[field], list) or len(discovery[field]) > 16
                for field in ("controllers", "trusts"))):
        raise ValueError("Persona domain_discovery fields are invalid")
    if (discovery["controllers"] or discovery["trusts"]) and not registration["domain_joined"]:
        raise ValueError("Persona domain discovery records require a joined domain")
    controller_names: set[str] = set()
    for controller in discovery["controllers"]:
        if (not isinstance(controller, dict) or
                set(controller) != {"name", "address", "site_name", "pdc"} or
                not isinstance(controller["name"], str) or
                not re.fullmatch(dns_pattern, controller["name"]) or
                controller["name"].casefold() in controller_names or
                not isinstance(controller["address"], str) or
                not isinstance(controller["site_name"], str) or
                not re.fullmatch(r"[A-Za-z0-9_. -]{1,64}", controller["site_name"]) or
                not isinstance(controller["pdc"], bool)):
            raise ValueError("Persona domain controller metadata is invalid")
        try:
            address = ipaddress.IPv4Address(controller["address"])
            if address.is_multicast or address.is_loopback or address.is_unspecified:
                raise ValueError("invalid controller address")
        except (ValueError, TypeError) as exc:
            raise ValueError("Persona domain controller address is invalid") from exc
        controller_names.add(controller["name"].casefold())
    if sum(controller["pdc"] for controller in discovery["controllers"]) > 1:
        raise ValueError("Persona has more than one primary domain controller")
    trust_names: set[str] = {persona["domain"].casefold()}
    for trust in discovery["trusts"]:
        if (not isinstance(trust, dict) or set(trust) != {"netbios_name", "dns_name", "direction"} or
                not isinstance(trust["netbios_name"], str) or
                not re.fullmatch(r"[A-Za-z0-9_-]{1,15}", trust["netbios_name"]) or
                not isinstance(trust["dns_name"], str) or
                not re.fullmatch(dns_pattern, trust["dns_name"]) or
                trust["dns_name"].casefold() in trust_names or
                trust["direction"] not in ("Inbound", "Outbound", "Bidirectional")):
            raise ValueError("Persona domain trust metadata is invalid")
        trust_names.add(trust["dns_name"].casefold())
    adapter = persona["network_adapter"]
    if (not isinstance(adapter["guid"], str) or
            not re.fullmatch(r"\{[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\}",
                             adapter["guid"]) or
            any(not isinstance(adapter[field], str) or not adapter[field] or
                len(adapter[field]) > 128 or "\0" in adapter[field]
                for field in ("name", "description")) or
            not isinstance(adapter["mac"], str) or
            not re.fullmatch(r"(?:[0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}", adapter["mac"]) or
            not isinstance(adapter["pnp_instance_id"], str) or
            not re.fullmatch(r"[A-Za-z0-9_&\\.:-]{1,200}", adapter["pnp_instance_id"]) or
            not isinstance(adapter["prefix_length"], int) or
            isinstance(adapter["prefix_length"], bool) or
            not 1 <= adapter["prefix_length"] <= 32 or
            not isinstance(adapter["mtu"], int) or isinstance(adapter["mtu"], bool) or
            not 576 <= adapter["mtu"] <= 9000 or
            not isinstance(adapter["if_index"], int) or
            isinstance(adapter["if_index"], bool) or
            not 1 <= adapter["if_index"] <= 65535 or
            not isinstance(adapter["dhcp_enabled"], bool) or
            not isinstance(adapter["dns_servers"], list) or
            not 1 <= len(adapter["dns_servers"]) <= 4):
        raise ValueError("Persona network_adapter fields are invalid")
    try:
        if not isinstance(adapter["ipv4"], str) or not isinstance(adapter["gateway"], str):
            raise ValueError
        address = ipaddress.IPv4Address(adapter["ipv4"])
        gateway = ipaddress.IPv4Address(adapter["gateway"])
        network = ipaddress.IPv4Network((address, adapter["prefix_length"]),
                                        strict=False)
        if (address.is_multicast or address.is_loopback or address.is_unspecified or
                gateway.is_multicast or gateway.is_loopback or
                gateway not in network or address == gateway):
            raise ValueError
        for item in adapter["dns_servers"]:
            if not isinstance(item, str):
                raise ValueError
            ipaddress.IPv4Address(item)
    except (ValueError, TypeError, ipaddress.AddressValueError) as exc:
        raise ValueError("Persona network_adapter IPv4 settings are invalid") from exc
    validate_records(persona)
    build = persona["windows_build"]
    if not isinstance(build, int) or isinstance(build, bool) or not 22000 <= build <= 65535:
        raise ValueError("Persona windows_build must be a Windows 11 build between 22000 and 65535")
    if not isinstance(persona["processes"], list) or not isinstance(persona["registry_keys"], list):
        raise ValueError("Persona processes and registry_keys must be arrays")
    if not isinstance(persona["virtual_files"], list):
        raise ValueError("Persona virtual_files must be an array")
    if len(persona["processes"]) > 128 or len(persona["registry_keys"]) > 512 or len(persona["virtual_files"]) > 512:
        raise ValueError("Persona process, registry, or file count exceeds limit")
    if any(not isinstance(name, str) or not name or len(name) > 128 or
           any(char in name for char in "\\/:\0") for name in persona["processes"]):
        raise ValueError("Persona process names must be simple filenames")
    services = persona["services"]
    if not isinstance(services, list) or len(services) > 128:
        raise ValueError("Persona services must be an array of at most 128 entries")
    service_names: set[str] = set()
    for service in services:
        if (not isinstance(service, dict) or
                set(service) != {"name", "display_name", "process", "start", "type"} or
                not isinstance(service["name"], str) or
                not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", service["name"]) or
                service["name"].casefold() in service_names or
                not isinstance(service["display_name"], str) or
                not 1 <= len(service["display_name"]) <= 128 or
                "\0" in service["display_name"] or
                not isinstance(service["process"], str) or
                not 1 <= len(service["process"]) <= 128 or
                any(char in service["process"] for char in "\\/:\0") or
                not isinstance(service["start"], int) or
                isinstance(service["start"], bool) or
                service["start"] not in (2, 3, 4) or
                not isinstance(service["type"], int) or
                service["type"] not in (16, 32)):
            raise ValueError("Persona service entries are invalid")
        service_names.add(service["name"].casefold())
    drivers = persona["drivers"]
    if not isinstance(drivers, list) or len(drivers) > 32:
        raise ValueError("Persona drivers must be an array of at most 32 entries")
    for driver in drivers:
        if (not isinstance(driver, dict) or
                set(driver) != {"name", "display_name", "path", "start", "type", "running"} or
                not isinstance(driver["name"], str) or
                not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", driver["name"]) or
                driver["name"].casefold() in service_names or
                not isinstance(driver["display_name"], str) or
                not 1 <= len(driver["display_name"]) <= 128 or
                any(ord(char) < 32 for char in driver["display_name"]) or
                not isinstance(driver["path"], str) or
                not re.fullmatch(r"System32\\drivers\\[A-Za-z0-9_.-]{1,64}\.sys",
                                 driver["path"], re.IGNORECASE) or
                not isinstance(driver["start"], int) or
                isinstance(driver["start"], bool) or
                driver["start"] not in (0, 1, 2, 3, 4) or
                not isinstance(driver["type"], int) or
                isinstance(driver["type"], bool) or
                driver["type"] not in (1, 2) or
                not isinstance(driver["running"], bool) or
                (driver["start"] == 4 and driver["running"])):
            raise ValueError("Persona driver entries are invalid")
        service_names.add(driver["name"].casefold())
    filters = persona["minifilters"]
    if not isinstance(filters, list) or len(filters) > 32:
        raise ValueError("Persona minifilters must have at most 32 entries")
    driver_by_name = {driver["name"].casefold(): driver for driver in drivers}
    filter_names: set[str] = set()
    for filter_item in filters:
        if (not isinstance(filter_item, dict) or
                set(filter_item) != {"name", "altitude", "instances"} or
                not isinstance(filter_item["name"], str) or
                filter_item["name"].casefold() in filter_names or
                filter_item["name"].casefold() not in driver_by_name or
                driver_by_name[filter_item["name"].casefold()]["type"] != 2 or
                not driver_by_name[filter_item["name"].casefold()]["running"] or
                not isinstance(filter_item["altitude"], str) or
                not re.fullmatch(r"[0-9]{1,6}(?:\.[0-9]{1,3})?", filter_item["altitude"]) or
                not isinstance(filter_item["instances"], int) or
                isinstance(filter_item["instances"], bool) or
                not 1 <= filter_item["instances"] <= 16):
            raise ValueError("Persona minifilter entries are invalid")
        filter_names.add(filter_item["name"].casefold())
    if sum(filter_item["instances"] for filter_item in filters) > 64:
        raise ValueError("Persona minifilter instance count exceeds 64")
    packages = persona["driver_packages"]
    if not isinstance(packages, list) or len(packages) > 32:
        raise ValueError("Persona driver_packages must have at most 32 entries")
    package_by_name: dict[str, dict] = {}
    for package in packages:
        if (not isinstance(package, dict) or
                set(package) != {"published_name", "original_name", "provider",
                                 "class_name", "class_guid", "version", "signer"} or
                not isinstance(package["published_name"], str) or
                not re.fullmatch(r"oem[0-9]{1,4}\.inf", package["published_name"], re.I) or
                package["published_name"].casefold() in package_by_name or
                not isinstance(package["original_name"], str) or
                not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}\.inf", package["original_name"], re.I) or
                not isinstance(package["class_name"], str) or
                not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", package["class_name"]) or
                not isinstance(package["class_guid"], str) or
                not re.fullmatch(r"\{[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\}",
                                 package["class_guid"]) or
                not isinstance(package["version"], str) or
                not re.fullmatch(r"[0-9]{2}/[0-9]{2}/[0-9]{4} [0-9]+(?:\.[0-9]+){1,3}",
                                 package["version"]) or
                any(not isinstance(package[field], str) or
                    not 1 <= len(package[field]) <= 128 or
                    any(ord(char) < 32 or char == '"' for char in package[field])
                    for field in ("provider", "signer"))):
            raise ValueError("Persona driver package entries are invalid")
        package_by_name[package["published_name"].casefold()] = package
    devices = persona["pnp_devices"]
    if not isinstance(devices, list) or len(devices) > 64:
        raise ValueError("Persona pnp_devices must have at most 64 entries")
    device_ids: set[str] = set()
    for device in devices:
        if (not isinstance(device, dict) or
                set(device) != {"instance_id", "description", "class_name",
                                "class_guid", "status", "driver"} or
                not isinstance(device["instance_id"], str) or
                not re.fullmatch(r"[A-Za-z0-9_&\\{}.:-]{1,200}", device["instance_id"]) or
                device["instance_id"].casefold() in device_ids or
                not isinstance(device["description"], str) or
                not 1 <= len(device["description"]) <= 128 or
                any(ord(char) < 32 for char in device["description"]) or
                not isinstance(device["class_name"], str) or
                not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", device["class_name"]) or
                not isinstance(device["class_guid"], str) or
                not re.fullmatch(r"\{[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\}",
                                 device["class_guid"]) or
                device["status"] not in ("Started", "Disabled", "Disconnected") or
                (device["driver"] is not None and
                 (not isinstance(device["driver"], str) or
                  device["driver"].casefold() not in package_by_name))):
            raise ValueError("Persona PnP device entries are invalid")
        if device["driver"] is not None:
            package = package_by_name[device["driver"].casefold()]
            if (package["class_name"].casefold() != device["class_name"].casefold() or
                    package["class_guid"].casefold() != device["class_guid"].casefold()):
                raise ValueError("Persona PnP device driver class does not match package")
        device_ids.add(device["instance_id"].casefold())
    if not custom_files:
        persona["virtual_files"].extend(driver_package_files(persona))
    channels = persona["event_channels"]
    if not isinstance(channels, list) or len(channels) > 32:
        raise ValueError("Persona event_channels must have at most 32 entries")
    channel_names: set[str] = set()
    for channel in channels:
        if (not isinstance(channel, dict) or
                set(channel) != {"name", "enabled", "max_size", "retention"} or
                not isinstance(channel["name"], str) or
                not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", channel["name"]) or
                channel["name"].casefold() in channel_names or
                not isinstance(channel["enabled"], bool) or
                not isinstance(channel["retention"], bool) or
                not isinstance(channel["max_size"], int) or
                isinstance(channel["max_size"], bool) or
                not 1_048_576 <= channel["max_size"] <= 268_435_456 or
                channel["max_size"] % 65536):
            raise ValueError("Persona event channel entries are invalid")
        channel_names.add(channel["name"].casefold())
    tasks = persona["scheduled_tasks"]
    if not isinstance(tasks, list) or len(tasks) > 32:
        raise ValueError("Persona scheduled_tasks must have at most 32 entries")
    task_names: set[str] = set()
    for task in tasks:
        if (not isinstance(task, dict) or
                set(task) != {"name", "status", "next_run_minutes"} or
                not isinstance(task["name"], str) or
                not 2 <= len(task["name"]) <= 128 or
                not task["name"].startswith("\\") or
                task["name"].endswith("\\") or
                any(not part or part in {".", ".."} for part in task["name"][1:].split("\\")) or
                any(ord(char) < 32 or char in '/:"' for char in task["name"]) or
                task["name"].casefold() in task_names or
                not isinstance(task["status"], str) or
                task["status"] not in {"Ready", "Disabled"} or
                (task["next_run_minutes"] is not None and
                 (not isinstance(task["next_run_minutes"], int) or
                  isinstance(task["next_run_minutes"], bool) or
                  not 0 <= task["next_run_minutes"] <= 10080)) or
                (task["status"] == "Disabled" and task["next_run_minutes"] is not None) or
                (task["status"] == "Ready" and task["next_run_minutes"] is None)):
            raise ValueError("Persona scheduled task entries are invalid")
        task_names.add(task["name"].casefold())
    file_names: set[str] = set()
    total_file_bytes = 0
    for item in persona["virtual_files"]:
        content = virtual_file_bytes(item)
        path_name = item["path"]
        if (not ntpath.isabs(path_name) or not path_name.upper().startswith("C:\\") or
                "\0" in path_name or ":" in path_name[2:] or len(path_name) > 1024 or
                ntpath.normpath(path_name).casefold() in file_names):
            raise ValueError("Persona virtual file path is unsafe or duplicated")
        file_names.add(ntpath.normpath(path_name).casefold())
        size = len(content)
        total_file_bytes += size
        if size > 1024 * 1024 or total_file_bytes > 16 * 1024 * 1024:
            raise ValueError("Persona virtual file data exceeds limit")
    for name in ("physical_memory_mb", "available_memory_mb"):
        value = persona[name]
        if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 1_048_576:
            raise ValueError(f"Persona {name} must be between 1 and 1048576")
    if persona["available_memory_mb"] > persona["physical_memory_mb"]:
        raise ValueError("Persona available_memory_mb exceeds physical_memory_mb")
    cpu = persona["cpu"]
    if not isinstance(cpu["brand"], str) or not cpu["brand"].isascii() or len(cpu["brand"]) > 48:
        raise ValueError("Persona cpu brand must be ASCII and at most 48 characters")
    for name, minimum, maximum in (("signature", 0, 0xFFFFFFFF),
                                   ("cores", 1, 32), ("threads_per_core", 1, 2),
                                   ("base_mhz", 100, 6000), ("max_mhz", 100, 7000)):
        value = cpu[name]
        if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
            raise ValueError(f"Persona cpu {name} must be between {minimum} and {maximum}")
    if cpu["max_mhz"] < cpu["base_mhz"]:
        raise ValueError("Persona cpu max_mhz must be at least base_mhz")
    validate_time_service(persona)
    if refresh_registry:
        persona["registry_keys"] = registry_keys(persona)
    return persona


MAX_NATIVE_API_CALLS = 100_000


def make_speakeasy_config(persona: dict, sample_name: str, timeout: int,
                          max_instructions: int, guest_args: list[str] | None = None,
                          guest_env: dict[str, str] | None = None,
                          quoted_arg_indices: list[int] | None = None) -> dict:
    import subprocess
    cfg = get_default_config_dict()
    cfg["os_ver"].update({"major": 10, "minor": 0, "build": int(persona["windows_build"])})
    cfg["hostname"] = persona["hostname"]
    cfg["domain"] = persona["domain"]
    cfg["user"] = {
        "name": persona["user_name"],
        "is_admin": bool(persona["user_is_admin"]),
        "sid": persona["user_sid"],
    }
    cfg["current_dir"] = persona["current_dir"]
    args = list(guest_args or [])
    quoted = set(quoted_arg_indices or [])
    if (any(not isinstance(index, int) or isinstance(index, bool) or
            index < 0 or index >= len(args) for index in quoted) or
            any('"' in args[index] for index in quoted)):
        raise ValueError('Quoted guest argument index or value is invalid')
    rendered = [subprocess.list2cmdline([f'{persona["current_dir"]}\\{sample_name}'])]
    for index, value in enumerate(args):
        part = subprocess.list2cmdline([value])
        rendered.append('"' + part + '"' if index in quoted and
                        not (part.startswith('"') and part.endswith('"')) else part)
    cfg["command_line"] = ' '.join(rendered)
    cfg["env"].update({
        "userprofile": f'C:\\Users\\{persona["user_name"]}',
        "username": persona["user_name"],
        "computername": persona["hostname"],
        "userdomain": persona["hostname"],
        "homedrive": "C:",
        "systemdrive": "C:",
        "homepath": f'\\Users\\{persona["user_name"]}',
        "public": r"C:\Users\Public",
        "programdata": r"C:\ProgramData",
        "programfiles": r"C:\Program Files",
        "programfiles(x86)": r"C:\Program Files (x86)",
        "programw6432": r"C:\Program Files",
        "commonprogramfiles": r"C:\Program Files\Common Files",
        "commonprogramfiles(x86)": r"C:\Program Files (x86)\Common Files",
        "commonprogramw6432": r"C:\Program Files\Common Files",
        "number_of_processors": str(persona["cpu"]["cores"] *
                                    persona["cpu"]["threads_per_core"]),
        "os": "Windows_NT",
        "path": r"C:\Windows\System32;C:\Windows;C:\Windows\System32\Wbem",
        "temp": f'C:\\Users\\{persona["user_name"]}\\AppData\\Local\\Temp\\',
        "tmp": f'C:\\Users\\{persona["user_name"]}\\AppData\\Local\\Temp\\',
        "appdata": f'C:\\Users\\{persona["user_name"]}\\AppData\\Roaming',
        "localappdata": f'C:\\Users\\{persona["user_name"]}\\AppData\\Local',
    })
    cfg["env"].update({key.lower(): value for key, value in (guest_env or {}).items()})
    # Speakeasy's sample config contains catch-all EXE/TXT files and demo
    # services. They make arbitrary probes succeed and are not persona data.
    cfg["filesystem"]["files"] = []
    cfg["drives"] = [drive for drive in cfg["drives"]
                     if drive["root_path"].casefold() == "c:\\"]
    cfg["processes"] = []
    cfg["registry"]["keys"] = copy.deepcopy(persona["registry_keys"])
    cfg["timeout"] = timeout
    cfg["max_instructions"] = max_instructions
    cfg["max_api_count"] = MAX_NATIVE_API_CALLS
    cfg["snapshot_memory_regions"] = True
    cfg["keep_memory_on_free"] = True
    cfg["analysis"].update({"strings": True, "memory_tracing": True, "coverage": False})
    cfg["modules"]["modules_always_exist"] = False
    cfg["modules"]["functions_always_exist"] = False
    for index, name in enumerate(persona["processes"]):
        template, session = PROCESS_PATHS.get(
            name.casefold(), ("C:\\Windows\\System32\\" + name, 1))
        cfg["processes"].append({
            "name": name,
            "base_addr": hex(0x06000000 + index * 0x00100000),
            "path": template.format(user=persona["user_name"]),
            "pid": 4 if name.casefold() == "system" else 420 + index * 168,
            "session": session,
        })
    return cfg


def materialize_virtual_files(persona: dict, root: Path) -> list[tuple[str, Path]]:
    root.mkdir(parents=True, exist_ok=True)
    result = []
    for index, entry in enumerate(persona["virtual_files"]):
        content = virtual_file_bytes(entry)
        host_path = root / f"file-{index:04d}.bin"
        host_path.write_bytes(content)
        result.append((entry["path"], host_path))
    return result
