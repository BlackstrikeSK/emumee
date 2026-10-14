"""Configurable Windows 11 identity and virtual environment."""

from __future__ import annotations

import base64
import binascii
import copy
import ipaddress
import json
import ntpath
import re
from pathlib import Path

from speakeasy.config import get_default_config_dict

from .persona_content import DISPLAY_VERSIONS, PROCESS_PATHS, desktop_files, registry_keys


WINDOWS_11_DISPLAY_VERSIONS = DISPLAY_VERSIONS


DEFAULT_PERSONA = {
    "hostname": "DESKTOP-7F4M2Q9",
    "domain": "WORKGROUP",
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
    },
    "current_dir": "C:\\Users\\Alex\\Downloads",
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
    refresh_registry = False
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
        custom_registry = "registry_keys" in supplied
        refresh_registry = not custom_registry
        custom_files = "virtual_files" in supplied
        custom_current_dir = "current_dir" in supplied
        previous_name = persona["user_name"]
        persona.update(supplied)
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
    adapter = persona["network_adapter"]
    if (not isinstance(adapter["guid"], str) or
            not re.fullmatch(r"\{[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\}",
                             adapter["guid"]) or
            any(not isinstance(adapter[field], str) or not adapter[field] or
                len(adapter[field]) > 128 or "\0" in adapter[field]
                for field in ("name", "description")) or
            not isinstance(adapter["mac"], str) or
            not re.fullmatch(r"(?:[0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}", adapter["mac"]) or
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
    if refresh_registry:
        persona["registry_keys"] = registry_keys(persona)
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
