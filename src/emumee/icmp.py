"""Offline IPv4 ICMP echo replies from persona fixtures; never opens sockets."""

import hashlib
import ipaddress
import struct

import speakeasy.common as common


IP_REQ_TIMED_OUT = 11010


def _broadcast(persona, address):
    adapter = persona["network_adapter"]
    network = ipaddress.IPv4Network((adapter["ipv4"], adapter["prefix_length"]), strict=False)
    return str(address) == "255.255.255.255" or (
        network.prefixlen < 31 and address == network.broadcast_address)


def validate_icmp_responses(persona):
    records = persona["icmp_responses"]
    if not isinstance(records, list) or len(records) > 64:
        raise ValueError("Persona icmp_responses must have at most 64 entries")
    seen = set()
    for record in records:
        if (not isinstance(record, dict) or set(record) != {"address", "round_trip_ms", "ttl"} or
                not isinstance(record["address"], str) or type(record["round_trip_ms"]) is not int or
                not 0 <= record["round_trip_ms"] <= 60000 or type(record["ttl"]) is not int or
                not 1 <= record["ttl"] <= 255):
            raise ValueError("Persona icmp_responses fields are invalid")
        try:
            address = ipaddress.IPv4Address(record["address"])
        except ValueError as error:
            raise ValueError("Persona icmp_responses address is invalid") from error
        if (address.is_unspecified or address.is_multicast or address.is_loopback or
                str(address) == persona["network_adapter"]["ipv4"] or
                _broadcast(persona, address) or address in seen):
            raise ValueError("Persona icmp_responses address is duplicate, reserved, or guest-owned")
        seen.add(address)


class GuestICMP:
    def __init__(self, persona, clock=None):
        self.persona = persona
        self.clock = clock
        self.responses = {r["address"]: r for r in persona["icmp_responses"]}
        self.handles = set()
        self.next_handle = 0xE6100000
        self.events = []
        self.read_guard = None
        self.write_guard = None

    def install(self, emulator):
        for module in ("iphlpapi", "icmp"):
            for name, callback, argc in (("IcmpCreateFile", self._create, 0),
                                         ("IcmpCloseHandle", self._close, 1),
                                         ("IcmpSendEcho", self._echo, 8)):
                emulator.add_api_hook(callback, module, name, argc=argc)

    def _owner(self, emu):
        process = emu.get_current_process()
        return id(process) if process is not None else 0

    def _access(self, emu, pointer, size, write=False):
        if pointer <= 0 or size <= 0 or pointer + size > 1 << (emu.get_ptr_size() * 8):
            return False
        mapping = emu.get_address_map(pointer)
        permission = common.PERM_MEM_WRITE if write else common.PERM_MEM_READ
        if (mapping is None or mapping.free or not int(mapping.prot) & permission or
                pointer + size > int(mapping.base) + int(mapping.size)):
            return False
        guard = self.write_guard if write else self.read_guard
        return guard is None or bool(guard(emu, pointer, size))

    def _create(self, emu, _name, _original, _params):
        owner = self._owner(emu)
        if not owner or len(self.handles) >= 128:
            emu.set_last_error(8)
            return (1 << (emu.get_ptr_size() * 8)) - 1
        handle = self.next_handle
        self.next_handle += 4
        self.handles.add((owner, handle))
        emu.set_last_error(0)
        return handle

    def _close(self, emu, _name, _original, params):
        entry = self._owner(emu), int(params[0])
        if entry not in self.handles:
            emu.set_last_error(6)
            return 0
        self.handles.remove(entry)
        emu.set_last_error(0)
        return 1

    def _echo(self, emu, name, _original, params):
        handle, address, request, size, options, output, capacity, timeout = map(int, params)
        address &= 0xffffffff
        size &= 0xffff
        capacity &= 0xffffffff
        timeout &= 0xffffffff
        host = str(ipaddress.IPv4Address(address.to_bytes(4, "little")))
        event = {"event": "guest_icmp_echo", "api": name, "host": host, "request_size": size,
                 "timeout_ms": timeout, "source": "persona", "network_used": False}
        self.events.append(event)
        def fail(error, reason):
            emu.set_last_error(error)
            event.update(status=error, reason=reason)
            return 0
        width = emu.get_ptr_size()
        header = 28 if width == 4 else 40
        if ((self._owner(emu), handle) not in self.handles or size > 4096 or capacity < header or
                not self._access(emu, output, header, True) or
                size and not self._access(emu, request, size)):
            return fail(87, "invalid handle, guest memory, or request bounds")
        if capacity < header + size:
            return fail(122, "reply buffer too small")
        if not self._access(emu, output, header + size, True):
            return fail(87, "reply buffer is not writable guest memory")
        if options:
            if not self._access(emu, options, 4):
                return fail(87, "request options are unreadable")
            ttl, tos, flags, option_size = emu.mem_read(options, 4)
            if not ttl or tos or flags or option_size:
                return fail(50, "only plain IPv4 TTL options are modeled")
            event["request_ttl"] = ttl
        else:
            event["request_ttl"] = 128
        destination = ipaddress.IPv4Address(host)
        if destination.is_unspecified or destination.is_multicast or _broadcast(self.persona, destination):
            return fail(50, "broadcast, multicast, or unspecified targets are not modeled")
        data = bytes(emu.mem_read(request, size)) if size else b""
        event["data_sha256"] = hashlib.sha256(data).hexdigest()
        response = ({"round_trip_ms": 0, "ttl": 128} if destination.is_loopback or
                    host == self.persona["network_adapter"]["ipv4"] else self.responses.get(host))
        elapsed = response["round_trip_ms"] if response is not None else timeout
        success = response is not None and elapsed <= timeout
        if self.clock is not None:
            self.clock.advance(elapsed if success else timeout)
        if not success:
            return fail(IP_REQ_TIMED_OUT, "no timely simulated reply; no network packet was sent")
        result = bytearray(header + size)
        result[:4] = ipaddress.IPv4Address(host).packed
        struct.pack_into("<IIHH", result, 4, 0, elapsed, size, 0)
        result[16:16 + width] = (output + header if size else 0).to_bytes(width, "little")
        result[16 + width] = response["ttl"]
        result[header:] = data
        emu.mem_write(output, bytes(result))
        emu.set_last_error(0)
        event.update(status=0, round_trip_ms=elapsed, ttl=response["ttl"], simulated_reply=True)
        return 1

    def cleanup_process(self, _emu, process):
        self.handles = {entry for entry in self.handles if entry[0] != id(process)}
