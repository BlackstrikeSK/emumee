"""Configurable Windows 11 identity and virtual environment."""

from __future__ import annotations

import copy
import json
from pathlib import Path

from speakeasy.config import get_default_config_dict


WINDOWS_11_DISPLAY_VERSIONS = {
    22000: "21H2", 22621: "22H2", 22631: "23H2",
    26100: "24H2", 26200: "25H2", 26300: "26H2",
}


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
    "current_dir": "C:\\Users\\Alex\\Downloads",
    "locale": "en-US",
    "timezone": "Eastern Standard Time",
    "utc_offset_minutes": -240,
    "clock_utc": None,
    "uptime_ms": 523_812_000,
    "processes": ["SearchHost.exe", "RuntimeBroker.exe", "MsMpEng.exe", "OneDrive.exe"],
    "registry_keys": [
        {"path": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
         "values": [
             {"name": "ProductName", "type": "REG_SZ", "data": "Windows 11 Pro"},
             {"name": "CurrentBuild", "type": "REG_SZ", "data": "22631"},
             {"name": "DisplayVersion", "type": "REG_SZ", "data": "23H2"},
         ]},
    ],
    "virtual_files": [
        {"path": "C:\\Users\\Alex\\Documents\\readme.txt", "text": "Personal notes\n"},
    ],
}


def load_persona(path: Path | None) -> dict:
    persona = copy.deepcopy(DEFAULT_PERSONA)
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
        custom_registry = "registry_keys" in supplied
        persona.update(supplied)
        if "windows_build" in supplied and not custom_registry:
            for key in persona["registry_keys"]:
                if key["path"].lower().endswith(r"\windows nt\currentversion"):
                    values = key["values"]
                    for value in values:
                        if value["name"] == "CurrentBuild":
                            value["data"] = str(persona["windows_build"])
                        if value["name"] == "DisplayVersion":
                            value["data"] = WINDOWS_11_DISPLAY_VERSIONS.get(
                                persona["windows_build"], "")
                    if persona["windows_build"] not in WINDOWS_11_DISPLAY_VERSIONS:
                        key["values"] = [value for value in values
                                         if value["name"] != "DisplayVersion"]
    if not persona["user_name"] or not persona["hostname"]:
        raise ValueError("Persona user_name and hostname must not be empty")
    build = persona["windows_build"]
    if not isinstance(build, int) or isinstance(build, bool) or not 22000 <= build <= 65535:
        raise ValueError("Persona windows_build must be a Windows 11 build between 22000 and 65535")
    if not isinstance(persona["processes"], list) or not isinstance(persona["registry_keys"], list):
        raise ValueError("Persona processes and registry_keys must be arrays")
    if not isinstance(persona["virtual_files"], list):
        raise ValueError("Persona virtual_files must be an array")
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
                          guest_env: dict[str, str] | None = None) -> dict:
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
    cfg["command_line"] = subprocess.list2cmdline(
        [f'{persona["current_dir"]}\\{sample_name}', *(guest_args or [])])
    cfg["env"].update({
        "userprofile": f'C:\\Users\\{persona["user_name"]}',
        "username": persona["user_name"],
        "computername": persona["hostname"],
        "temp": f'C:\\Users\\{persona["user_name"]}\\AppData\\Local\\Temp\\',
        "tmp": f'C:\\Users\\{persona["user_name"]}\\AppData\\Local\\Temp\\',
        "appdata": f'C:\\Users\\{persona["user_name"]}\\AppData\\Roaming',
        "localappdata": f'C:\\Users\\{persona["user_name"]}\\AppData\\Local',
    })
    cfg["env"].update({key.lower(): value for key, value in (guest_env or {}).items()})
    cfg["timeout"] = timeout
    cfg["max_instructions"] = max_instructions
    cfg["max_api_count"] = MAX_NATIVE_API_CALLS
    cfg["snapshot_memory_regions"] = True
    cfg["keep_memory_on_free"] = True
    cfg["analysis"].update({"strings": True, "memory_tracing": True, "coverage": False})
    cfg["modules"]["modules_always_exist"] = False
    cfg["modules"]["functions_always_exist"] = False
    for index, name in enumerate(persona["processes"]):
        cfg["processes"].append({
            "name": name,
            "base_addr": hex(0x06000000 + index * 0x00100000),
            "path": "C:\\Windows\\System32\\" + name,
            "pid": 2500 + index * 100,
            "session": 1,
        })
    cfg["registry"]["keys"].extend(persona["registry_keys"])
    return cfg


def materialize_virtual_files(persona: dict, root: Path) -> list[tuple[str, Path]]:
    root.mkdir(parents=True, exist_ok=True)
    result = []
    for index, entry in enumerate(persona["virtual_files"]):
        if not isinstance(entry, dict) or set(entry) != {"path", "text"}:
            raise ValueError("Each virtual_files entry needs path and text")
        content = entry["text"].encode("utf-8")
        if len(content) > 1024 * 1024:
            raise ValueError("Persona virtual file exceeds 1 MiB")
        host_path = root / f"file-{index:04d}.bin"
        host_path.write_bytes(content)
        result.append((entry["path"], host_path))
    return result
