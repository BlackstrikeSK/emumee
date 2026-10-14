"""Bounded Win32 computer and user identity APIs for the guest persona."""

from __future__ import annotations

import speakeasy.common as common
from speakeasy.winenv.defs.winsock.ws2_32 import WSAData


ERROR_INVALID_PARAMETER = 87
ERROR_BUFFER_OVERFLOW = 111
ERROR_INSUFFICIENT_BUFFER = 122
ERROR_MORE_DATA = 234
ERROR_NOACCESS = 998
WSAEFAULT = 10014
WSANOTINITIALISED = 10093


class GuestIdentity:
    def __init__(self, persona: dict):
        self.persona = persona
        self._wsa_by_process: dict[int, int] = {}
        self.read_guard = None
        self.write_guard = None

    def install(self, emulator) -> None:
        for suffix in ("A", "W"):
            for module in ("kernel32", "api-ms-win-core-sysinfo-l1-1-0"):
                emulator.add_api_hook(self._computer_name, module,
                                      "GetComputerName" + suffix, argc=2)
                emulator.add_api_hook(self._computer_name_ex, module,
                                      "GetComputerNameEx" + suffix, argc=3)
            emulator.add_api_hook(self._user_name, "advapi32",
                                  "GetUserName" + suffix, argc=2)
        emulator.add_api_hook(self._wsa_startup, "ws2_32", "WSAStartup", argc=2)
        emulator.add_api_hook(self._wsa_cleanup, "ws2_32", "WSACleanup", argc=0)
        emulator.add_api_hook(self._host_name_w, "ws2_32", "GetHostNameW", argc=2)

    def _wsa_startup(self, emu, _api_name, original, params) -> int:
        if original is None:
            return WSAEFAULT
        output = int(params[1])
        size = WSAData(emu.get_ptr_size()).sizeof()
        if (self.write_guard is not None and
                not self.write_guard(emu, output, size)):
            return WSAEFAULT
        result = int(original(params))
        process = emu.get_current_process()
        if result == 0 and process is not None:
            owner = id(process)
            self._wsa_by_process[owner] = self._wsa_by_process.get(owner, 0) + 1
        return result

    def _wsa_cleanup(self, emu, _api_name, original, params) -> int:
        process = emu.get_current_process()
        owner = id(process) if process is not None else 0
        count = self._wsa_by_process.get(owner, 0)
        if not count:
            emu.set_last_error(WSANOTINITIALISED)
            return -1
        result = int(original(params)) if original is not None else 0
        if result == 0:
            if count == 1:
                self._wsa_by_process.pop(owner, None)
            else:
                self._wsa_by_process[owner] = count - 1
        return result

    def _host_name_w(self, emu, _api_name, _original, params) -> int:
        output, capacity = map(int, params)
        capacity &= 0xFFFFFFFF
        process = emu.get_current_process()
        if process is None or not self._wsa_by_process.get(id(process), 0):
            emu.set_last_error(WSANOTINITIALISED)
            return -1
        name = (self.persona['hostname'] + '\0').encode('utf-16le')
        if (not output or capacity == 0 or capacity & 0x80000000 or
                capacity * 2 < len(name)):
            emu.set_last_error(WSAEFAULT)
            return -1
        mapping = emu.get_address_map(output)
        if (mapping is None or mapping.free or
                output + len(name) > int(mapping.base) + int(mapping.size) or
                not (int(mapping.prot) & common.PERM_MEM_WRITE) or
                self.write_guard is not None and
                not self.write_guard(emu, output, len(name))):
            emu.set_last_error(WSAEFAULT)
            return -1
        try:
            emu.mem_write(output, name)
        except Exception:
            emu.set_last_error(WSAEFAULT)
            return -1
        emu.set_last_error(0)
        return 0

    def cleanup_process(self, process) -> None:
        self._wsa_by_process.pop(id(process), None)

    def _write_name(self, emu, api_name: str, buffer: int, size_ptr: int,
                    name: str, short_error: int, size_includes_null: bool,
                    allow_null_query: bool) -> int:
        if not size_ptr:
            emu.set_last_error(ERROR_INVALID_PARAMETER)
            return 0
        if (self.read_guard is not None and
                not self.read_guard(emu, size_ptr, 4)):
            emu.set_last_error(ERROR_NOACCESS)
            return 0
        try:
            capacity = int.from_bytes(emu.mem_read(size_ptr, 4), "little")
        except Exception:
            emu.set_last_error(ERROR_NOACCESS)
            return 0
        if not buffer and (not allow_null_query or capacity):
            emu.set_last_error(ERROR_INVALID_PARAMETER)
            return 0
        encoding = "utf-16-le" if api_name.endswith("W") else "cp1252"
        encoded = name.encode(encoding, errors="replace")
        char_width = 2 if api_name.endswith("W") else 1
        copied = len(encoded) // char_width
        required = copied + 1
        if (self.write_guard is not None and
                not self.write_guard(emu, size_ptr, 4)):
            emu.set_last_error(ERROR_NOACCESS)
            return 0
        if capacity < required:
            try:
                emu.mem_write(size_ptr, required.to_bytes(4, "little"))
            except Exception:
                emu.set_last_error(ERROR_NOACCESS)
                return 0
            emu.set_last_error(short_error)
            return 0
        if (self.write_guard is not None and
                not self.write_guard(emu, buffer, len(encoded) + char_width)):
            emu.set_last_error(ERROR_NOACCESS)
            return 0
        try:
            emu.mem_write(buffer, encoded + b"\0" * char_width)
            result_size = required if size_includes_null else copied
            emu.mem_write(size_ptr, result_size.to_bytes(4, "little"))
        except Exception:
            emu.set_last_error(ERROR_NOACCESS)
            return 0
        emu.set_last_error(0)
        return 1

    def _computer_name(self, emu, api_name, original, params):
        buffer, size_ptr = (int(value) for value in params)
        return self._write_name(emu, api_name, buffer, size_ptr,
                                self.persona["hostname"], ERROR_BUFFER_OVERFLOW,
                                False, False)

    def _computer_name_ex(self, emu, api_name, original, params):
        name_type, buffer, size_ptr = (int(value) for value in params)
        host = self.persona["hostname"]
        domain = self.persona["domain"]
        dns_domain = "" if domain.upper() == "WORKGROUP" else domain
        if name_type in (0, 4):
            name = host
        elif name_type in (1, 5):
            name = host
        elif name_type in (2, 6):
            name = dns_domain
        elif name_type in (3, 7):
            name = host + ("." + dns_domain if dns_domain else "")
        else:
            emu.set_last_error(ERROR_INVALID_PARAMETER)
            return 0
        return self._write_name(emu, api_name, buffer, size_ptr,
                                name, ERROR_MORE_DATA, False, True)

    def _user_name(self, emu, api_name, original, params):
        buffer, size_ptr = (int(value) for value in params)
        return self._write_name(emu, api_name, buffer, size_ptr,
                                self.persona["user_name"], ERROR_INSUFFICIENT_BUFFER,
                                True, False)
