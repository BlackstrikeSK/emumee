"""Persona-owned Windows feature configuration query fallback."""

from __future__ import annotations

import struct

import speakeasy.common as common


STATUS_NOT_FOUND = 0xC0000225
STATUS_INVALID_PARAMETER = 0xC000000D


class GuestFeatureConfiguration:
    """Model an empty boot/runtime override store with a stable change stamp."""

    def __init__(self):
        self.change_stamp = 1
        self.read_guard = None
        self.write_guard = None
        self.events: list[dict] = []
        self.unsupported: list[str] = []

    def install(self, emulator) -> None:
        emulator.add_api_hook(self._query, "ntdll", "RtlQueryFeatureConfiguration",
                              argc=4)

    def _writable(self, emu, address: int, size: int) -> bool:
        mapping = emu.get_address_map(address) if address else None
        return bool(mapping and not mapping.free and
                    address + size <= int(mapping.base) + int(mapping.size) and
                    int(mapping.prot) & common.PERM_MEM_WRITE and
                    (self.write_guard is None or self.write_guard(emu, address, size)))

    def _query(self, emu, api_name, _original, params) -> int:
        feature_id, kind, stamp_ptr, config_ptr = map(int, params)
        if (kind not in (0, 1) or not self._writable(emu, stamp_ptr, 8) or
                not self._writable(emu, config_ptr, 12)):
            self.unsupported.append(f"{api_name}: feature query arguments unsupported")
            return STATUS_INVALID_PARAMETER
        emu.mem_write(stamp_ptr, struct.pack("<Q", self.change_stamp))
        self.events.append({"event": "guest_feature_query", "feature_id": feature_id & 0xffffffff,
                            "configuration_type": kind, "status": STATUS_NOT_FOUND})
        return STATUS_NOT_FOUND
