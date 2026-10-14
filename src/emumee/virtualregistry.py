"""Bounded guest-only registry value reads and payload capture."""

from __future__ import annotations

import base64
import binascii
import struct

from .artifacts import ArtifactCatalog
from speakeasy.windows.regman import RegKey


MAX_REG_VALUE = 1024 * 1024
MAX_REG_KEYS = 20_000
MAX_REG_HANDLES = 40_000
PREDEFINED_HANDLES = frozenset((0x80000000, 0x80000001,
                                0x80000002, 0x80000003))
REG_SZ = 1
REG_EXPAND_SZ = 2
REG_BINARY = 3
REG_DWORD = 4
REG_MULTI_SZ = 7
REG_QWORD = 11
SUPPORTED_TYPES = {REG_SZ, REG_EXPAND_SZ, REG_BINARY, REG_DWORD, REG_MULTI_SZ, REG_QWORD}
TYPE_NAMES = {"REG_SZ": REG_SZ, "REG_EXPAND_SZ": REG_EXPAND_SZ,
              "REG_BINARY": REG_BINARY, "REG_DWORD": REG_DWORD,
              "REG_MULTI_SZ": REG_MULTI_SZ, "REG_QWORD": REG_QWORD}


class VirtualRegistryBridge:
    def __init__(self, catalog: ArtifactCatalog):
        self.catalog = catalog
        self.events: list[dict] = []
        self.unsupported: list[str] = []
        self.written_values: dict[tuple[int, str], tuple[int, bytes]] = {}
        self.handle_owners: dict[int, int] = {}

    def install(self, emulator) -> None:
        for suffix in ("A", "W"):
            for module in ("advapi32", "api-ms-win-core-registry-l1-1-0"):
                emulator.add_api_hook(self._set_value, module, "RegSetValueEx" + suffix, argc=6)
                emulator.add_api_hook(self._query_value, module, "RegQueryValueEx" + suffix, argc=6)
                emulator.add_api_hook(self._create_key, module, "RegCreateKey" + suffix, argc=3)
                emulator.add_api_hook(self._create_key_ex, module, "RegCreateKeyEx" + suffix, argc=9)
                emulator.add_api_hook(self._open_key, module, "RegOpenKey" + suffix, argc=3)
                emulator.add_api_hook(self._open_key_ex, module, "RegOpenKeyEx" + suffix, argc=5)
                emulator.add_api_hook(self._delete_key, module, "RegDeleteKey" + suffix, argc=2)
        for module in ("advapi32", "api-ms-win-core-registry-l1-1-0"):
            emulator.add_api_hook(self._close_key, module, "RegCloseKey", argc=1)

    @staticmethod
    def _name(emu, api_name: str, address: int) -> str:
        return emu.read_mem_string(address, 2 if api_name.endswith("W") else 1) if address else ""

    @staticmethod
    def _type_code(value_type) -> int | None:
        if isinstance(value_type, int):
            return value_type if value_type in SUPPORTED_TYPES else None
        return TYPE_NAMES.get(value_type)

    @staticmethod
    def _exact_key(manager, path: str):
        return next((key for key in manager.keys
                     if key.get_path().casefold() == path.casefold()), None)

    @staticmethod
    def _preset_key(manager, path: str) -> bool:
        return any(item.path.casefold() == path.casefold()
                   for item in getattr(getattr(manager, "config", None), "keys", []))

    @staticmethod
    def _guest_owner(emu) -> int:
        process = (emu.get_current_process() if hasattr(emu, "get_current_process")
                   else None)
        return id(process) if process is not None else id(emu)

    @staticmethod
    def _canonical_handle(handle: int) -> int:
        """Windows x64 sign-extends predefined 32-bit HKEY constants."""
        low = handle & 0xffffffff
        return low if low in PREDEFINED_HANDLES and handle >> 32 == 0xffffffff else handle

    def _owned_key(self, emu, handle: int):
        if (handle not in PREDEFINED_HANDLES and
                self.handle_owners.get(handle) != self._guest_owner(emu)):
            return None
        return emu.reg_get_key(handle)

    def cleanup_process(self, emu, process) -> int:
        """Retire open handles issued to an exiting guest, preserving key data."""
        owner = id(process)
        handles = [handle for handle, candidate in self.handle_owners.items()
                   if candidate == owner]
        for handle in handles:
            emu.regman.reg_handles.pop(handle, None)
            del self.handle_owners[handle]
        self.events.append({"event": "virtual_registry_process_cleanup",
                            "pid": int(process.pid), "handles": len(handles),
                            "success": True})
        return len(handles)

    def _subkey_path(self, parent, subkey: str) -> str | None:
        parts = subkey.strip("\\").split("\\")
        if (not parts or any(not part or part in (".", "..") or len(part) > 255
                             or any(char in part for char in "*?[]") for part in parts)):
            return None
        path = parent.get_path().rstrip("\\") + "\\" + "\\".join(parts)
        return path if len(path) <= 32767 else None

    def _open_or_create(self, emu, api_name: str, params, *, create: bool, ex: bool = False):
        handle = self._canonical_handle(int(params[0]))
        subkey = self._name(emu, api_name, int(params[1]))
        output = int(params[4] if ex else params[2])
        manager = emu.regman
        parent = self._owned_key(emu, handle)
        event = {"event": "virtual_registry_key_create" if create else "virtual_registry_key_open",
                 "api": api_name, "parent": parent.get_path() if parent else "",
                 "subkey": subkey, "status": 0}
        self.events.append(event)
        if not parent:
            event["status"] = 6  # ERROR_INVALID_HANDLE
            return 6
        if not output:
            event["status"] = 87  # ERROR_INVALID_PARAMETER
            return 87
        if ex and int(params[2]):
            event["status"] = 50  # Unsupported open options
            self.unsupported.append(f"{api_name}: unsupported open options")
            return 50
        path = self._subkey_path(parent, subkey) if subkey else parent.get_path()
        if path is None:
            event["status"] = 50
            self.unsupported.append(f"{api_name}: unsupported registry path")
            return 50
        key = self._exact_key(manager, path)
        if key is None and self._preset_key(manager, path):
            key = manager.get_key_from_config(path)
        if key is None and not create:
            descendants = (item.get_path() for item in manager.keys)
            preset_descendants = (item.path for item in
                                  getattr(getattr(manager, "config", None), "keys", []))
            if not any(item.casefold().startswith(path.casefold() + "\\")
                       for item in (*descendants, *preset_descendants)):
                event["status"] = 2  # ERROR_FILE_NOT_FOUND
                return 2
        missing = []
        if create and subkey:
            prefix = parent.get_path().rstrip("\\")
            for part in subkey.strip("\\").split("\\")[:-1]:
                prefix += "\\" + part
                if self._exact_key(manager, prefix) is None and not self._preset_key(manager, prefix):
                    missing.append(prefix)
        if key is None:
            missing.append(path)
        if len(manager.reg_handles) >= MAX_REG_HANDLES or len(manager.keys) + len(missing) > MAX_REG_KEYS:
            event["status"] = 50
            self.unsupported.append(f"{api_name}: registry key or handle limit")
            return 50
        for missing_path in missing:
            created = RegKey(manager.allocator, missing_path)
            manager.keys.append(created)
            if missing_path == path:
                key = created
        result_handle = handle if not subkey and handle in PREDEFINED_HANDLES else key.get_handle()
        try:
            emu.mem_write(output, result_handle.to_bytes(emu.get_ptr_size(), "little"))
        except Exception:
            event["status"] = 998  # ERROR_NOACCESS
            return 998
        manager.reg_handles[result_handle] = key
        if result_handle not in PREDEFINED_HANDLES:
            self.handle_owners[result_handle] = self._guest_owner(emu)
        event.update({"path": path, "handle": result_handle})
        return 0

    def _create_key(self, emu, api_name, original, params):
        return self._open_or_create(emu, api_name, params, create=True)

    def _create_key_ex(self, emu, api_name, original, params):
        (handle, subkey_ptr, reserved, class_ptr, options, desired_access,
         security_ptr, output, disposition) = map(int, params)
        handle = self._canonical_handle(handle)
        if reserved or class_ptr or options or security_ptr:
            self.events.append({"event": "virtual_registry_key_create", "api": api_name,
                                "status": 50, "reason": "unsupported creation options"})
            self.unsupported.append(f"{api_name}: unsupported creation options")
            return 50
        parent = self._owned_key(emu, handle)
        subkey = self._name(emu, api_name, subkey_ptr)
        path = (self._subkey_path(parent, subkey) if subkey else parent.get_path()) \
            if parent else None
        existed = bool(path and (self._exact_key(emu.regman, path) or
                                 self._preset_key(emu.regman, path)))
        status = self._open_or_create(emu, api_name, [handle, subkey_ptr, output],
                                      create=True)
        if status:
            return status
        self.events[-1]["desired_access"] = desired_access
        self.events[-1]["disposition"] = 2 if existed else 1
        if disposition:
            try:
                emu.mem_write(disposition, self.events[-1]["disposition"].to_bytes(4, "little"))
            except Exception:
                self.events[-1]["status"] = 998
                return 998
        return 0

    def _open_key(self, emu, api_name, original, params):
        return self._open_or_create(emu, api_name, params, create=False)

    def _open_key_ex(self, emu, api_name, original, params):
        return self._open_or_create(emu, api_name, params, create=False, ex=True)

    def _delete_key(self, emu, api_name, original, params):
        handle, subkey_ptr = map(int, params)
        handle = self._canonical_handle(handle)
        parent = self._owned_key(emu, handle)
        subkey = self._name(emu, api_name, subkey_ptr)
        event = {"event": "virtual_registry_key_delete", "api": api_name,
                 "parent": parent.get_path() if parent else "", "subkey": subkey,
                 "status": 0}
        self.events.append(event)
        if not parent:
            event["status"] = 6
            return 6
        if not subkey_ptr or not subkey:
            event["status"] = 87
            return 87
        path = self._subkey_path(parent, subkey)
        if path is None:
            event["status"] = 50
            self.unsupported.append(f"{api_name}: unsupported registry path")
            return 50
        manager = emu.regman
        key = self._exact_key(manager, path)
        if self._preset_key(manager, path):
            event["status"] = 50
            event["reason"] = "preset key deletion unsupported"
            self.unsupported.append(f"{api_name}: preset key deletion {path}")
            return 50
        if key is None:
            event["status"] = 2
            return 2
        children = [item.get_path() for item in manager.keys]
        children.extend(item.path for item in getattr(getattr(manager, "config", None), "keys", []))
        if any(child.casefold().startswith(path.casefold() + "\\") for child in children):
            event["status"] = 5  # ERROR_ACCESS_DENIED for a nonempty key
            event["reason"] = "key has subkeys"
            return 5
        manager.keys.remove(key)
        event["path"] = path
        return 0

    def _close_key(self, emu, api_name, original, params):
        handle = self._canonical_handle(int(params[0]))
        manager = emu.regman
        key = self._owned_key(emu, handle)
        status = 0 if key else 6
        if key and handle not in PREDEFINED_HANDLES:
            manager.reg_handles.pop(handle, None)
            self.handle_owners.pop(handle, None)
        self.events.append({"event": "virtual_registry_key_close", "api": api_name,
                            "key": key.get_path() if key else "", "handle": handle,
                            "status": status})
        return status

    def _set_value(self, emu, api_name, original, params):
        handle, name_ptr, reserved, value_type, data_ptr, size = map(int, params)
        handle = self._canonical_handle(handle)
        name = self._name(emu, api_name, name_ptr)
        key = self._owned_key(emu, handle)
        event = {"event": "virtual_registry_write", "api": api_name,
                 "key": key.get_path() if key else "", "value": name,
                 "type": value_type, "size": size, "status": 0}
        self.events.append(event)
        if not key:
            event["status"] = 6  # ERROR_INVALID_HANDLE
            return 6
        if reserved or value_type not in SUPPORTED_TYPES or size > MAX_REG_VALUE:
            event["status"] = 50  # ERROR_NOT_SUPPORTED
            event["reason"] = "unsupported type, reserved value, or size"
            self.unsupported.append(f"{api_name}: unsupported registry value {key.get_path()}\\{name}")
            return 50
        if size and not data_ptr:
            event["status"] = 87  # ERROR_INVALID_PARAMETER
            return 87
        raw = emu.mem_read(data_ptr, size) if size else b""
        status = int(original(params))
        event["status"] = status
        if status == 0:
            self.written_values[(id(key), name.casefold())] = (value_type, raw)
            if value_type == REG_BINARY and raw:
                artifact = self.catalog.add(raw, "registry_value",
                                            guest_path=key.get_path() + "\\" + name)
                if artifact:
                    event["artifact_sha256"] = artifact["sha256"]
                self.catalog.carve_pe(raw, "registry_value")
        return status

    def _configured_value(self, value, wide: bool) -> tuple[int, bytes] | None:
        code = self._type_code(value.get_type())
        if code is None:
            return None
        data = value.get_data()
        if code == REG_BINARY:
            if not isinstance(data, bytes):
                return None
            try:
                raw = base64.b64decode(data, validate=True)
            except (ValueError, binascii.Error):
                return None
        elif code in (REG_SZ, REG_EXPAND_SZ, REG_MULTI_SZ):
            if not isinstance(data, str):
                return None
            ending = "\0\0" if code == REG_MULTI_SZ else "\0"
            raw = (data.rstrip("\0") + ending).encode("utf-16le" if wide else "cp1252",
                                                     errors="replace")
        elif code in (REG_DWORD, REG_QWORD):
            if not isinstance(data, int):
                return None
            width = 4 if code == REG_DWORD else 8
            if data < 0 or data >= 1 << (width * 8):
                return None
            raw = data.to_bytes(width, "little")
        else:
            return None
        return (code, raw) if len(raw) <= MAX_REG_VALUE else None

    def _query_value(self, emu, api_name, original, params):
        handle, name_ptr, reserved, type_ptr, data_ptr, size_ptr = map(int, params)
        handle = self._canonical_handle(handle)
        name = self._name(emu, api_name, name_ptr)
        key = self._owned_key(emu, handle)
        event = {"event": "virtual_registry_query", "api": api_name,
                 "key": key.get_path() if key else "", "value": name, "status": 0}
        self.events.append(event)
        if not key:
            event["status"] = 6
            return 6
        if reserved or (data_ptr and not size_ptr):
            event["status"] = 87
            return 87
        value = (next((item for item in key.get_values()
                       if item.get_name() in ("", "default")), None)
                 if not name else key.get_value(name))
        if value is None:
            event["status"] = 2  # ERROR_FILE_NOT_FOUND
            return 2
        encoded = self.written_values.get((id(key), name.casefold()))
        if encoded is None:
            encoded = self._configured_value(value, api_name.endswith("W"))
        if encoded is None:
            event["status"] = 50
            event["reason"] = "unsupported value type or size"
            self.unsupported.append(f"{api_name}: unsupported registry value {key.get_path()}\\{name}")
            return 50
        value_type, raw = encoded
        if type_ptr:
            emu.mem_write(type_ptr, struct.pack("<I", value_type))
        capacity = int.from_bytes(emu.mem_read(size_ptr, 4), "little") if data_ptr else 0
        if size_ptr:
            emu.mem_write(size_ptr, struct.pack("<I", len(raw)))
        if data_ptr and capacity < len(raw):
            event["status"] = 234  # ERROR_MORE_DATA
            event["size"] = len(raw)
            return 234
        if data_ptr and raw:
            emu.mem_write(data_ptr, raw)
        event.update({"type": value_type, "size": len(raw), "status": 0})
        return 0
