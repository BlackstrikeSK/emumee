"""Bounded resolution of guest PE delay imports to guest API call gates."""

from __future__ import annotations

import re
import struct

from speakeasy import common


_DLL_NAME = re.compile(r"[A-Za-z0-9_.-]{1,128}\.dll\Z")
_EXPORT_NAME = re.compile(r"[A-Za-z0-9_?$@.-]{1,128}\Z")


class GuestDelayImports:
    def __init__(self):
        self.read_guard = None
        self.write_guard = None
        self.unsupported: list[str] = []

    def install(self, emulator) -> None:
        emulator.add_api_hook(self.resolve, "api-ms-win-core-delayload-l1-1-1",
                              "ResolveDelayLoadedAPI", argc=6)

    def _access(self, emu, address: int, size: int, write: bool) -> bool:
        if not address or size <= 0:
            return False
        mapping = emu.get_address_map(address)
        permission = common.PERM_MEM_WRITE if write else common.PERM_MEM_READ
        guard = self.write_guard if write else self.read_guard
        return bool(mapping is not None and not mapping.free and
                    address >= int(mapping.base) and
                    address + size <= int(mapping.base) + int(mapping.size) and
                    int(mapping.prot) & permission and
                    (guard is None or guard(emu, address, size)))

    def _read(self, emu, address: int, size: int) -> bytes:
        if not self._access(emu, address, size, False):
            raise ValueError("guest delay-import read denied")
        return emu.mem_read(address, size)

    def _name(self, emu, address: int, limit: int) -> str:
        value = bytearray()
        for offset in range(limit):
            unit = self._read(emu, address + offset, 1)
            if unit == b"\0":
                return value.decode("ascii")
            value.extend(unit)
        raise ValueError("unterminated delay-import name")

    def resolve(self, emu, api_name, _original, params) -> int:
        base, descriptor, _dll_failure, _system_failure, thunk, flags = map(int, params)
        try:
            module = next((item for item in emu.modules if int(item.base) == base), None)
            if module is None or flags or not 0 < int(module.image_size) <= 0x40000000:
                raise ValueError("invalid guest module or flags")
            end = base + int(module.image_size)
            if not base <= descriptor <= end - 32:
                raise ValueError("descriptor outside guest module")
            attrs, dll_rva, _handle_rva, iat_rva, names_rva, *_ = struct.unpack(
                "<8I", self._read(emu, descriptor, 32))
            if attrs != 1 or not all(0 < value < int(module.image_size)
                                     for value in (dll_rva, iat_rva, names_rva)):
                raise ValueError("unsupported delay-import descriptor")
            dll = self._name(emu, base + dll_rva, 129)
            if not _DLL_NAME.fullmatch(dll):
                raise ValueError("invalid delay-import DLL name")
            pointer_size = emu.get_ptr_size()
            iat = base + iat_rva
            if (not iat <= thunk < end or (thunk - iat) % pointer_size or
                    (thunk - iat) // pointer_size >= 128):
                raise ValueError("invalid delay-import thunk")
            index = (thunk - iat) // pointer_size
            name_thunk = base + names_rva + index * pointer_size
            value = int.from_bytes(self._read(emu, name_thunk, pointer_size), "little")
            if not value or value & (1 << (pointer_size * 8 - 1)):
                raise ValueError("ordinal or empty delay import unsupported")
            if value >= int(module.image_size):
                raise ValueError("delay-import name outside module")
            self._read(emu, base + value, 2)  # IMAGE_IMPORT_BY_NAME hint
            name = self._name(emu, base + value + 2, 129)
            if not _EXPORT_NAME.fullmatch(name):
                raise ValueError("invalid delay-import export name")
            if not self._access(emu, thunk, pointer_size, True):
                raise ValueError("delay-import IAT write denied")
            address = int(emu.get_proc(dll, name))
            if not address:
                raise ValueError("delay-import target unavailable")
            emu.mem_write(thunk, address.to_bytes(pointer_size, "little"))
            return address
        except Exception as exc:
            self.unsupported.append(f"{api_name}: {type(exc).__name__}: {exc}")
            return 0
