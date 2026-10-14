"""Offline DnsQuery APIs: guest records only, with no resolver or network fallback."""

import ipaddress
import struct

import speakeasy.common as common
from .dns_records import TYPES, dns_name, record_catalog


class GuestDNS:
    def __init__(self, persona):
        self.persona = persona
        self.records = record_catalog(persona)
        self.buffers = {}
        self.events = []
        self.read_guard = None
        self.write_guard = None

    def install(self, emulator):
        for suffix in ("A", "W", "UTF8"):
            emulator.add_api_hook(self._query, "dnsapi", "DnsQuery_" + suffix, argc=6)
        for name in ("DnsFree", "DnsRecordListFree"):
            emulator.add_api_hook(self._free, "dnsapi", name, argc=2)

    def _owner(self, emu):
        process = emu.get_current_process()
        return id(process) if process is not None else 0

    def _access(self, emu, pointer, size, write=False):
        if pointer <= 0 or size <= 0:
            return False
        mapping = emu.get_address_map(pointer)
        permission = common.PERM_MEM_WRITE if write else common.PERM_MEM_READ
        if (mapping is None or mapping.free or not int(mapping.prot) & permission or
                pointer + size > int(mapping.base) + int(mapping.size)):
            return False
        guard = self.write_guard if write else self.read_guard
        return guard is None or bool(guard(emu, pointer, size))

    def _text(self, emu, pointer, wide):
        data = bytearray()
        step = 2 if wide else 1
        for i in range(255):
            address = pointer + i * step
            if not self._access(emu, address, step):
                return None
            try:
                part = bytes(emu.mem_read(address, step))
            except Exception:
                return None
            if part == b"\0" * step:
                try:
                    return dns_name(data.decode("utf-16le" if wide else "ascii"))
                except (UnicodeError, ValueError):
                    return None
            data.extend(part)
        return None

    def _pack(self, records, width, base, charset):
        header = 24 if width == 4 else 32
        stride = header + 16
        data = bytearray(stride * len(records))
        encoding = "utf-16le" if charset == 1 else "ascii"
        def pointer(offset, value):
            data[offset:offset + width] = value.to_bytes(width, "little")
        def string(value):
            address = base + len(data)
            data.extend((value + "\0").encode(encoding))
            return address
        for i, record in enumerate(records):
            offset = i * stride
            pointer(offset, base + offset + stride if i + 1 < len(records) else 0)
            pointer(offset + width, string(record["name"]))
            kind = TYPES[record["type"]]
            size = 4 if kind == 1 else 16 if kind == 28 else width
            struct.pack_into("<HHIII", data, offset + width * 2,
                             kind, size, 1 | charset << 3, record["ttl"], 0)
            if kind == 12:
                pointer(offset + header, string(record["data"]))
            else:
                packed = ipaddress.ip_address(record["data"]).packed
                data[offset + header:offset + header + len(packed)] = packed
        return bytes(data)

    def _query(self, emu, api_name, _original, params):
        name_ptr, kind, options, servers, output, reserved = map(int, params)
        width = emu.get_ptr_size()
        name = self._text(emu, name_ptr, api_name.endswith("_W")) if name_ptr else None
        event = {"event": "guest_dns_query", "api": api_name, "host": name or "",
                 "record_type": kind & 0xffff, "source": "persona", "network_used": False}
        self.events.append(event)
        def fail(status, reason):
            event.update(status=status, reason=reason)
            return status
        if name is None or reserved or not self._access(emu, output, width, True) or not self._owner(emu):
            return fail(87, "invalid query parameters or guest memory")
        emu.mem_write(output, b"\0" * width)
        kind &= 0xffff
        # Only normal, bypass-cache, and no-wire queries are modeled. Explicit
        # server arrays and all other flags are rejected before any network use.
        if servers or options & ~(0x8 | 0x10):
            return fail(50, "explicit DNS servers or query options are not modeled")
        if kind not in TYPES.values():
            return fail(50, "DNS record type is not modeled")
        selected = [r for r in self.records if r["name"] == name and TYPES[r["type"]] == kind]
        if not selected:
            status = 9501 if any(r["name"] == name for r in self.records) else 9003
            return fail(status, "no guest record of this type" if status == 9501 else "name absent from guest DNS")
        if len(self.buffers) >= 64:
            return fail(8, "guest DNS response budget exhausted")
        charset = 1 if api_name.endswith("_W") else 2 if api_name.endswith("_UTF8") else 3
        size = len(self._pack(selected, width, 0, charset))
        if size > 128 * 1024:
            return fail(8, "guest DNS response exceeds size limit")
        buffer = 0
        try:
            buffer = emu.mem_map((size + 4095) & ~4095, perms=common.PERM_MEM_RW,
                                 tag="api.dns.response", process=emu.get_current_process())
            emu.mem_write(buffer, self._pack(selected, width, buffer, charset))
            emu.mem_write(output, buffer.to_bytes(width, "little"))
        except Exception:
            if buffer:
                emu.mem_free(buffer)
            return fail(8, "guest DNS allocation failed")
        self.buffers[(self._owner(emu), buffer)] = emu.get_address_map(buffer)
        event.update(status=0, answers=[r["data"] for r in selected], count=len(selected))
        return 0

    def _free(self, emu, api_name, _original, params):
        pointer, free_type = map(int, params)
        # DnsRecordListFree takes DNS_FREE_TYPE=1; DnsFree additionally accepts
        # DnsFreeFlat=0. Neither may free an unrelated guest allocation.
        if free_type not in ((0, 1) if api_name.endswith(".DnsFree") else (1,)):
            return None
        mapping = self.buffers.pop((self._owner(emu), pointer), None)
        if mapping is not None and emu.get_address_map(pointer) is mapping and not mapping.free:
            emu.mem_free(pointer)
        return None

    def cleanup_process(self, emu, process):
        for entry in tuple(self.buffers):
            if entry[0] == id(process):
                mapping = self.buffers.pop(entry)
                if emu.get_address_map(entry[1]) is mapping and not mapping.free:
                    emu.mem_free(entry[1])
