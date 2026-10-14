"""Bounded Win32 computer and user identity APIs for the guest persona."""

from __future__ import annotations


ERROR_INVALID_PARAMETER = 87
ERROR_BUFFER_OVERFLOW = 111
ERROR_INSUFFICIENT_BUFFER = 122
ERROR_MORE_DATA = 234
ERROR_NOACCESS = 998


class GuestIdentity:
    def __init__(self, persona: dict):
        self.persona = persona

    def install(self, emulator) -> None:
        for suffix in ("A", "W"):
            emulator.add_api_hook(self._computer_name, "kernel32",
                                  "GetComputerName" + suffix, argc=2)
            emulator.add_api_hook(self._computer_name_ex, "kernel32",
                                  "GetComputerNameEx" + suffix, argc=3)
            emulator.add_api_hook(self._user_name, "advapi32",
                                  "GetUserName" + suffix, argc=2)

    @staticmethod
    def _write_name(emu, api_name: str, buffer: int, size_ptr: int,
                    name: str, short_error: int, size_includes_null: bool,
                    allow_null_query: bool) -> int:
        if not size_ptr:
            emu.set_last_error(ERROR_INVALID_PARAMETER)
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
        if capacity < required:
            try:
                emu.mem_write(size_ptr, required.to_bytes(4, "little"))
            except Exception:
                emu.set_last_error(ERROR_NOACCESS)
                return 0
            emu.set_last_error(short_error)
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
            name = host.lower()
        elif name_type in (2, 6):
            name = dns_domain
        elif name_type in (3, 7):
            name = host.lower() + ("." + dns_domain if dns_domain else "")
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
