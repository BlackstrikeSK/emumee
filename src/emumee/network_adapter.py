"""Bounded, persona-owned IP Helper adapter enumeration."""

from __future__ import annotations

import ctypes
import ipaddress
import struct
from functools import lru_cache

import speakeasy.common as common


ERROR_BUFFER_OVERFLOW = 111
ERROR_INVALID_PARAMETER = 87
ERROR_NO_DATA = 232
ERROR_NOT_SUPPORTED = 50
MAX_ADAPTER_BUFFER = 64 * 1024


@lru_cache(maxsize=2)
def _layouts(width: int):
    if width not in (4, 8):
        raise ValueError("unsupported guest pointer width")
    pointer = ctypes.c_uint32 if width == 4 else ctypes.c_uint64
    u32 = ctypes.c_uint32
    u64 = ctypes.c_uint64
    u8 = ctypes.c_uint8

    class SocketAddress(ctypes.Structure):
        _pack_ = 8
        _fields_ = [("lpSockaddr", pointer), ("iSockaddrLength", u32)]

    class Unicast(ctypes.Structure):
        _pack_ = 8
        _fields_ = [("Length", u32), ("Flags", u32), ("Next", pointer),
                    ("Address", SocketAddress), ("PrefixOrigin", u32),
                    ("SuffixOrigin", u32), ("DadState", u32),
                    ("ValidLifetime", u32), ("PreferredLifetime", u32),
                    ("LeaseLifetime", u32), ("OnLinkPrefixLength", u8)]

    class AddressNode(ctypes.Structure):
        _pack_ = 8
        _fields_ = [("Length", u32), ("Reserved", u32),
                    ("Next", pointer), ("Address", SocketAddress)]

    class Adapter(ctypes.Structure):
        _pack_ = 8
        _fields_ = [
            ("Length", u32), ("IfIndex", u32), ("Next", pointer),
            ("AdapterName", pointer), ("FirstUnicastAddress", pointer),
            ("FirstAnycastAddress", pointer), ("FirstMulticastAddress", pointer),
            ("FirstDnsServerAddress", pointer), ("DnsSuffix", pointer),
            ("Description", pointer), ("FriendlyName", pointer),
            ("PhysicalAddress", u8 * 8), ("PhysicalAddressLength", u32),
            ("Flags", u32), ("Mtu", u32), ("IfType", u32),
            ("OperStatus", u32), ("Ipv6IfIndex", u32),
            ("ZoneIndices", u32 * 16), ("FirstPrefix", pointer),
            ("TransmitLinkSpeed", u64), ("ReceiveLinkSpeed", u64),
            ("FirstWinsServerAddress", pointer), ("FirstGatewayAddress", pointer),
            ("Ipv4Metric", u32), ("Ipv6Metric", u32), ("Luid", u64),
            ("Dhcpv4Server", SocketAddress), ("CompartmentId", u32),
            ("NetworkGuid", u8 * 16), ("ConnectionType", u32),
            ("TunnelType", u32), ("Dhcpv6Server", SocketAddress),
            ("Dhcpv6ClientDuid", u8 * 130), ("Dhcpv6ClientDuidLength", u32),
            ("Dhcpv6Iaid", u32), ("FirstDnsSuffix", pointer),
        ]

    return Adapter, Unicast, AddressNode


class GuestNetworkAdapter:
    def __init__(self, persona: dict):
        self.persona = persona
        self.read_guard = None
        self.write_guard = None
        self.events: list[dict] = []
        self.unsupported: list[str] = []

    def install(self, emulator) -> None:
        emulator.add_api_hook(self._get_adapters_addresses, "iphlpapi",
                              "GetAdaptersAddresses", argc=5)

    @staticmethod
    def _sockaddr(ip: str) -> bytes:
        return struct.pack("<H", 2) + b"\0\0" + ipaddress.IPv4Address(ip).packed + b"\0" * 8

    def _buffer(self, base: int, width: int, flags: int) -> bytes:
        Adapter, Unicast, AddressNode = _layouts(width)
        adapter = self.persona["network_adapter"]
        image = bytearray()

        def reserve(size: int, alignment: int = 8) -> int:
            image.extend(b"\0" * ((-len(image)) % alignment))
            offset = len(image)
            image.extend(b"\0" * size)
            return offset

        def add(raw: bytes, alignment: int = 2) -> int:
            offset = reserve(len(raw), alignment)
            image[offset:offset + len(raw)] = raw
            return base + offset

        def put(offset: int, item) -> None:
            image[offset:offset + ctypes.sizeof(item)] = bytes(item)

        head_offset = reserve(ctypes.sizeof(Adapter))
        unicast_offset = reserve(ctypes.sizeof(Unicast)) if not flags & 1 else None
        dns_offsets = ([reserve(ctypes.sizeof(AddressNode))
                        for _ in adapter["dns_servers"]] if not flags & 8 else [])
        gateway_offset = reserve(ctypes.sizeof(AddressNode)) if flags & 0x80 else None
        name = add((adapter["guid"] + "\0").encode("ascii"), 1)
        suffix = ("" if self.persona["domain"] == "WORKGROUP"
                  else self.persona["domain"])
        suffix_ptr = add((suffix + "\0").encode("utf-16le"))
        description = add((adapter["description"] + "\0").encode("utf-16le"))
        friendly = (add((adapter["name"] + "\0").encode("utf-16le"))
                    if not flags & 0x20 else 0)
        ip_sock = add(self._sockaddr(adapter["ipv4"])) if unicast_offset is not None else 0
        dns_socks = [add(self._sockaddr(ip)) for ip in adapter["dns_servers"]] \
            if dns_offsets else []
        gateway_sock = add(self._sockaddr(adapter["gateway"])) if gateway_offset is not None else 0

        header = Adapter()
        header.Length = ctypes.sizeof(Adapter)
        header.IfIndex = adapter["if_index"]
        header.AdapterName = name
        header.FirstUnicastAddress = base + unicast_offset if unicast_offset is not None else 0
        header.FirstDnsServerAddress = base + dns_offsets[0] if dns_offsets else 0
        header.DnsSuffix = suffix_ptr
        header.Description = description
        header.FriendlyName = friendly
        header.PhysicalAddress[:6] = bytes.fromhex(adapter["mac"].replace("-", ""))
        header.PhysicalAddressLength = 6
        header.Flags = 0x80 | 0x40 | (0x4 if adapter["dhcp_enabled"] else 0)
        header.Mtu = adapter["mtu"]
        header.IfType = 6  # Ethernet
        header.OperStatus = 1  # Up
        header.TransmitLinkSpeed = 1_000_000_000
        header.ReceiveLinkSpeed = 1_000_000_000
        header.FirstGatewayAddress = base + gateway_offset if gateway_offset is not None else 0
        header.Ipv4Metric = 25
        header.ConnectionType = 1  # Dedicated
        header.Dhcpv4Server.lpSockaddr = gateway_sock
        header.Dhcpv4Server.iSockaddrLength = 16 if gateway_sock else 0
        put(head_offset, header)

        if unicast_offset is not None:
            uni = Unicast()
            uni.Length = ctypes.sizeof(Unicast)
            uni.Flags = 1  # Eligible for DNS
            uni.Address.lpSockaddr = ip_sock
            uni.Address.iSockaddrLength = 16
            uni.PrefixOrigin = 3 if adapter["dhcp_enabled"] else 1
            uni.SuffixOrigin = uni.PrefixOrigin
            uni.DadState = 4  # Preferred
            uni.ValidLifetime = 86400
            uni.PreferredLifetime = 86400
            uni.LeaseLifetime = 86400
            uni.OnLinkPrefixLength = adapter["prefix_length"]
            put(unicast_offset, uni)

        for index, offset in enumerate(dns_offsets):
            node = AddressNode()
            node.Length = ctypes.sizeof(AddressNode)
            node.Next = base + dns_offsets[index + 1] if index + 1 < len(dns_offsets) else 0
            node.Address.lpSockaddr = dns_socks[index]
            node.Address.iSockaddrLength = 16
            put(offset, node)
        if gateway_offset is not None:
            node = AddressNode()
            node.Length = ctypes.sizeof(AddressNode)
            node.Address.lpSockaddr = gateway_sock
            node.Address.iSockaddrLength = 16
            put(gateway_offset, node)
        return bytes(image)

    def _access(self, emu, address: int, size: int, write: bool) -> bool:
        mapping = emu.get_address_map(address) if address else None
        required = common.PERM_MEM_WRITE if write else common.PERM_MEM_READ
        guard = self.write_guard if write else self.read_guard
        return bool(mapping and not mapping.free and size > 0 and
                    address + size <= int(mapping.base) + int(mapping.size) and
                    int(mapping.prot) & required and
                    (guard is None or guard(emu, address, size)))

    def _get_adapters_addresses(self, emu, api_name, _original, params) -> int:
        family, flags, reserved, buffer, size_ptr = map(int, params)
        family &= 0xffffffff
        flags &= 0xffffffff
        if not size_ptr or family not in (0, 2, 23) or reserved:
            return ERROR_INVALID_PARAMETER
        if flags & ~(0x1 | 0x2 | 0x4 | 0x8 | 0x20 | 0x40 | 0x80):
            self.unsupported.append(f"{api_name}: address enumeration flags unsupported")
            return ERROR_NOT_SUPPORTED
        if not self._access(emu, size_ptr, 4, True):
            return ERROR_INVALID_PARAMETER
        if family == 23:
            return ERROR_NO_DATA
        capacity = int.from_bytes(emu.mem_read(size_ptr, 4), "little")
        # Pointer values in the returned graph refer only to the caller's
        # guest buffer; no host interface information is read.
        image = self._buffer(buffer, emu.get_ptr_size(), flags)
        required = len(image)
        if required > MAX_ADAPTER_BUFFER:
            self.unsupported.append(f"{api_name}: persona adapter exceeds limit")
            return ERROR_NOT_SUPPORTED
        if not buffer or capacity < required:
            emu.mem_write(size_ptr, struct.pack("<I", required))
            self.events.append({"event": "guest_adapter_query", "status": ERROR_BUFFER_OVERFLOW,
                                "required": required, "family": family})
            return ERROR_BUFFER_OVERFLOW
        if not self._access(emu, buffer, required, True):
            return ERROR_INVALID_PARAMETER
        emu.mem_write(buffer, image)
        emu.mem_write(size_ptr, struct.pack("<I", required))
        self.events.append({"event": "guest_adapter_query", "status": 0,
                            "required": required, "family": family,
                            "ipv4": self.persona["network_adapter"]["ipv4"]})
        return 0
