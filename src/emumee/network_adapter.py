"""Bounded, persona-owned IP Helper adapter enumeration."""

from __future__ import annotations

import ctypes
import ipaddress
import struct
from functools import lru_cache

import speakeasy.common as common


ERROR_BUFFER_OVERFLOW = 111
ERROR_INSUFFICIENT_BUFFER = 122
ERROR_INVALID_PARAMETER = 87
ERROR_NO_DATA = 232
ERROR_NOT_SUPPORTED = 50
STATUS_INVALID_PARAMETER = 0xC000000D
WSAEAFNOSUPPORT = 10047
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


@lru_cache(maxsize=2)
def _fixed_layouts(width: int):
    if width not in (4, 8):
        raise ValueError("unsupported guest pointer width")
    pointer = ctypes.c_uint32 if width == 4 else ctypes.c_uint64

    class IpAddrString(ctypes.Structure):
        _fields_ = [("Next", pointer), ("IpAddress", ctypes.c_char * 16),
                    ("IpMask", ctypes.c_char * 16), ("Context", ctypes.c_uint32)]

    class FixedInfo(ctypes.Structure):
        _fields_ = [("HostName", ctypes.c_char * 132),
                    ("DomainName", ctypes.c_char * 132),
                    ("CurrentDnsServer", pointer),
                    ("DnsServerList", IpAddrString), ("NodeType", ctypes.c_uint32),
                    ("ScopeId", ctypes.c_char * 260),
                    ("EnableRouting", ctypes.c_uint32),
                    ("EnableProxy", ctypes.c_uint32),
                    ("EnableDns", ctypes.c_uint32)]

    return FixedInfo, IpAddrString


class _MibIfRow(ctypes.Structure):
    _fields_ = [
        ("wszName", ctypes.c_uint16 * 256),
        ("dwIndex", ctypes.c_uint32), ("dwType", ctypes.c_uint32),
        ("dwMtu", ctypes.c_uint32), ("dwSpeed", ctypes.c_uint32),
        ("dwPhysAddrLen", ctypes.c_uint32), ("bPhysAddr", ctypes.c_uint8 * 8),
        ("dwAdminStatus", ctypes.c_uint32), ("dwOperStatus", ctypes.c_uint32),
        ("dwLastChange", ctypes.c_uint32), ("dwInOctets", ctypes.c_uint32),
        ("dwInUcastPkts", ctypes.c_uint32), ("dwInNUcastPkts", ctypes.c_uint32),
        ("dwInDiscards", ctypes.c_uint32), ("dwInErrors", ctypes.c_uint32),
        ("dwInUnknownProtos", ctypes.c_uint32), ("dwOutOctets", ctypes.c_uint32),
        ("dwOutUcastPkts", ctypes.c_uint32), ("dwOutNUcastPkts", ctypes.c_uint32),
        ("dwOutDiscards", ctypes.c_uint32), ("dwOutErrors", ctypes.c_uint32),
        ("dwOutQLen", ctypes.c_uint32), ("dwDescrLen", ctypes.c_uint32),
        ("bDescr", ctypes.c_uint8 * 256),
    ]


class GuestNetworkAdapter:
    def __init__(self, persona: dict):
        self.persona = persona
        self.network_bridge = None
        self.read_guard = None
        self.write_guard = None
        self.events: list[dict] = []
        self.unsupported: list[str] = []

    def install(self, emulator) -> None:
        emulator.add_api_hook(self._get_if_table, "iphlpapi", "GetIfTable", argc=3)
        emulator.add_api_hook(self._get_ip_net_table, "iphlpapi",
                              "GetIpNetTable", argc=3)
        emulator.add_api_hook(self._get_ip_addr_table, "iphlpapi",
                              "GetIpAddrTable", argc=3)
        emulator.add_api_hook(self._get_ip_forward_table, "iphlpapi",
                              "GetIpForwardTable", argc=3)
        emulator.add_api_hook(self._get_extended_tcp_table, "iphlpapi",
                              "GetExtendedTcpTable", argc=6)
        emulator.add_api_hook(self._get_adapters_addresses, "iphlpapi",
                              "GetAdaptersAddresses", argc=5)
        emulator.add_api_hook(self._convert_length_to_ipv4_mask, "iphlpapi",
                              "ConvertLengthToIpv4Mask", argc=2)
        emulator.add_api_hook(self._rtl_ipv4_address_to_string_ex_w, "ntdll",
                              "RtlIpv4AddressToStringExW", argc=4)
        emulator.add_api_hook(self._inet_ntop_w, "ws2_32", "InetNtopW", argc=4)
        emulator.add_api_hook(self._dns_free, "dnsapi", "DnsFree", argc=2)
        emulator.add_api_hook(self._get_network_params, "iphlpapi",
                              "GetNetworkParams", argc=2)

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

    def _write_mib_table(self, emu, api_name: str, params, image: bytes) -> int:
        buffer, size_ptr, _ordered = map(int, params)
        if (not self._access(emu, size_ptr, 4, False) or
                not self._access(emu, size_ptr, 4, True)):
            return ERROR_INVALID_PARAMETER
        try:
            capacity = int.from_bytes(emu.mem_read(size_ptr, 4), "little")
            required = len(image)
            if not buffer or capacity < required:
                emu.mem_write(size_ptr, struct.pack("<I", required))
                self.events.append({"event": "guest_mib_table", "api": api_name,
                                    "status": ERROR_INSUFFICIENT_BUFFER,
                                    "required": required})
                return ERROR_INSUFFICIENT_BUFFER
            if not self._access(emu, buffer, required, True):
                return ERROR_INVALID_PARAMETER
            emu.mem_write(buffer, image)
            emu.mem_write(size_ptr, struct.pack("<I", required))
        except Exception:
            return ERROR_INVALID_PARAMETER
        self.events.append({"event": "guest_mib_table", "api": api_name,
                            "status": 0, "required": required})
        return 0

    def _get_if_table(self, emu, api_name, _original, params) -> int:
        adapter = self.persona["network_adapter"]
        row = _MibIfRow()
        name = (r"\DEVICE\TCPIP_" + adapter["guid"]).encode("utf-16le")
        row.wszName[:len(name) // 2] = struct.unpack("<" + "H" * (len(name) // 2), name)
        row.dwIndex = adapter["if_index"]
        row.dwType = 6  # Ethernet
        row.dwMtu = adapter["mtu"]
        row.dwSpeed = 1_000_000_000
        mac = bytes.fromhex(adapter["mac"].replace("-", ""))
        row.dwPhysAddrLen = len(mac)
        row.bPhysAddr[:len(mac)] = mac
        row.dwAdminStatus = 1  # Up
        row.dwOperStatus = 5  # Operational
        description = adapter["description"].encode("cp1252", errors="replace")[:255]
        row.dwDescrLen = len(description)
        row.bDescr[:len(description)] = description
        image = struct.pack("<I", 1) + bytes(row)
        return self._write_mib_table(emu, api_name, params, image)

    def _get_extended_tcp_table(self, emu, api_name, _original, params) -> int:
        if len(params) != 6:
            return ERROR_INVALID_PARAMETER
        _table, _size, ordered, family, table_class, reserved = map(int, params)
        if family != 2 or table_class != 5 or reserved:
            return ERROR_NOT_SUPPORTED
        connections = list(self.network_bridge.connected_tcp.values()) if self.network_bridge else []
        if ordered:
            connections.sort(key=lambda item: (item["remote_ip"], item["remote_port"],
                                               item["local_port"]))
        connections = connections[:128]
        image = bytearray(struct.pack("<I", len(connections)))
        local_ip = ipaddress.IPv4Address(self.persona["network_adapter"]["ipv4"]).packed
        for connection in connections:
            local_port = int(connection["local_port"]).to_bytes(2, "big") + b"\0\0"
            remote_port = int(connection["remote_port"]).to_bytes(2, "big") + b"\0\0"
            remote_ip = ipaddress.IPv4Address(connection["remote_ip"]).packed
            image.extend(struct.pack("<I4s4s4s4sI", 5, local_ip, local_port,
                                     remote_ip, remote_port, connection["pid"]))
        return self._write_mib_table(emu, api_name, params[:3], bytes(image))

    def _get_ip_net_table(self, emu, api_name, _original, params) -> int:
        adapter = self.persona["network_adapter"]
        if adapter["prefix_length"] >= 31:
            size_ptr = int(params[1])
            if (not self._access(emu, size_ptr, 4, False) or
                    not self._access(emu, size_ptr, 4, True)):
                return ERROR_INVALID_PARAMETER
            return ERROR_NO_DATA
        subnet = ipaddress.IPv4Network((adapter["ipv4"],
                                        adapter["prefix_length"]), strict=False)
        # A broadcast mapping needs no invented gateway hardware address.
        broadcast = subnet.broadcast_address.packed
        row = struct.pack("<II8s4sI", adapter["if_index"], 6,
                          b"\xff" * 6 + b"\0\0", broadcast, 4)
        image = struct.pack("<I", 1) + row
        return self._write_mib_table(emu, api_name, params, image)

    def _get_ip_addr_table(self, emu, api_name, _original, params) -> int:
        adapter = self.persona["network_adapter"]
        subnet = ipaddress.IPv4Network((adapter["ipv4"],
                                        adapter["prefix_length"]), strict=False)
        address = ipaddress.IPv4Address(adapter["ipv4"]).packed
        mask = subnet.netmask.packed
        row = struct.pack("<4sI4sIIHH", address, adapter["if_index"], mask,
                          1, 65535, 0, 1)
        image = struct.pack("<I", 1) + row
        return self._write_mib_table(emu, api_name, params, image)

    def _get_ip_forward_table(self, emu, api_name, _original, params) -> int:
        buffer, size_ptr, ordered = map(int, params)
        if not self._access(emu, size_ptr, 4, True):
            return ERROR_INVALID_PARAMETER
        adapter = self.persona["network_adapter"]
        subnet = ipaddress.IPv4Network((adapter["ipv4"],
                                        adapter["prefix_length"]), strict=False)
        routes = [
            ("0.0.0.0", "0.0.0.0", adapter["gateway"], adapter["if_index"], 4, 3, 25),
            (str(subnet.network_address), str(subnet.netmask), "0.0.0.0",
             adapter["if_index"], 3, 2, 25),
            (adapter["ipv4"], "255.255.255.255", "0.0.0.0",
             adapter["if_index"], 3, 2, 25),
        ]
        if ordered:
            routes.sort(key=lambda row: (int(ipaddress.IPv4Address(row[0])),
                                         int(ipaddress.IPv4Address(row[1]))))
        def ipword(address: str) -> int:
            return int.from_bytes(ipaddress.IPv4Address(address).packed, "little")
        image = bytearray(struct.pack("<I", len(routes)))
        for destination, mask, next_hop, if_index, route_type, protocol, metric in routes:
            image.extend(struct.pack("<14I", ipword(destination), ipword(mask), 0,
                                     ipword(next_hop), if_index, route_type, protocol,
                                     0, 0, metric, *([0xffffffff] * 4)))
        required = len(image)
        try:
            capacity = int.from_bytes(emu.mem_read(size_ptr, 4), "little")
            if not buffer or capacity < required:
                emu.mem_write(size_ptr, struct.pack("<I", required))
                self.events.append({"event": "guest_ipv4_routes", "status":
                                    ERROR_INSUFFICIENT_BUFFER, "required": required})
                return ERROR_INSUFFICIENT_BUFFER
            if not self._access(emu, buffer, required, True):
                return ERROR_INVALID_PARAMETER
            emu.mem_write(buffer, bytes(image))
            emu.mem_write(size_ptr, struct.pack("<I", required))
        except Exception:
            return ERROR_INVALID_PARAMETER
        self.events.append({"event": "guest_ipv4_routes", "status": 0,
                            "required": required, "interface_index": adapter["if_index"]})
        return 0

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

    def _convert_length_to_ipv4_mask(self, emu, _api_name, _original, params) -> int:
        prefix, output = map(int, params)
        if not self._access(emu, output, 4, True):
            return ERROR_INVALID_PARAMETER
        if prefix < 0 or prefix > 32:
            emu.mem_write(output, b"\xff" * 4)
            return ERROR_INVALID_PARAMETER
        mask = (0xffffffff << (32 - prefix)) & 0xffffffff if prefix else 0
        emu.mem_write(output, mask.to_bytes(4, "big"))
        return 0

    def _rtl_ipv4_address_to_string_ex_w(self, emu, _api_name,
                                         _original, params) -> int:
        address, port, output, length_ptr = map(int, params)
        if (not self._access(emu, address, 4, False) or not output or
                not self._access(emu, length_ptr, 4, False) or
                not self._access(emu, length_ptr, 4, True)):
            return STATUS_INVALID_PARAMETER
        try:
            address_text = str(ipaddress.IPv4Address(emu.mem_read(address, 4)))
            capacity = int.from_bytes(emu.mem_read(length_ptr, 4), "little")
        except Exception:
            return STATUS_INVALID_PARAMETER
        port &= 0xffff
        if port:
            address_text += ":" + str(int.from_bytes(port.to_bytes(2, "little"), "big"))
        required = len(address_text) + 1
        if capacity < required or not self._access(emu, output, required * 2, True):
            emu.mem_write(length_ptr, struct.pack("<I", required))
            return STATUS_INVALID_PARAMETER
        emu.mem_write(output, (address_text + "\0").encode("utf-16le"))
        emu.mem_write(length_ptr, struct.pack("<I", required))
        return 0

    def _inet_ntop_w(self, emu, _api_name, _original, params) -> int:
        family, address, output, capacity = map(int, params)
        if family not in (2, 23):
            emu.set_last_error(WSAEAFNOSUPPORT)
            return 0
        if not output or capacity <= 0:
            emu.set_last_error(ERROR_INVALID_PARAMETER)
            return 0
        size = 4 if family == 2 else 16
        if not self._access(emu, address, size, False):
            emu.set_last_error(ERROR_INVALID_PARAMETER)
            return 0
        try:
            raw = emu.mem_read(address, size)
            if family == 2:
                address_text = str(ipaddress.IPv4Address(raw))
            else:
                ipv6 = ipaddress.IPv6Address(raw)
                if ipv6.ipv4_mapped is not None:
                    address_text = "::ffff:" + str(ipv6.ipv4_mapped)
                elif raw[:12] == b"\0" * 12 and raw[12:] not in (
                        b"\0" * 4, b"\0\0\0\1"):
                    address_text = "::" + str(ipaddress.IPv4Address(raw[12:]))
                else:
                    address_text = str(ipv6)
        except Exception:
            emu.set_last_error(ERROR_INVALID_PARAMETER)
            return 0
        payload = (address_text + "\0").encode("utf-16le")
        if capacity < len(address_text) + 1 or not self._access(emu, output, len(payload), True):
            emu.set_last_error(ERROR_INVALID_PARAMETER)
            return 0
        emu.mem_write(output, payload)
        return output

    def _dns_free(self, _emu, api_name, _original, params):
        address = int(params[0])
        if address:
            self.unsupported.append(f"{api_name}: non-null DNS record free unsupported")
        # The null case owns no allocation. Never pass guest pointers to the host.
        return None

    def _get_network_params(self, emu, api_name, _original, params) -> int:
        buffer, size_ptr = map(int, params)
        if not self._access(emu, size_ptr, 4, False) or not self._access(
                emu, size_ptr, 4, True):
            return ERROR_INVALID_PARAMETER
        FixedInfo, IpAddrString = _fixed_layouts(emu.get_ptr_size())
        dns_servers = self.persona["network_adapter"]["dns_servers"]
        required = ctypes.sizeof(FixedInfo) + (len(dns_servers) - 1) * ctypes.sizeof(IpAddrString)
        try:
            capacity = int.from_bytes(emu.mem_read(size_ptr, 4), "little")
        except Exception:
            return ERROR_INVALID_PARAMETER
        if not buffer or capacity < required:
            emu.mem_write(size_ptr, struct.pack("<I", required))
            self.events.append({"event": "guest_network_params", "status": ERROR_BUFFER_OVERFLOW,
                                "required": required})
            return ERROR_BUFFER_OVERFLOW
        if not self._access(emu, buffer, required, True):
            return ERROR_INVALID_PARAMETER
        domain = "" if self.persona["domain"] == "WORKGROUP" else self.persona["domain"]
        try:
            hostname = self.persona["hostname"].encode("cp1252")
            domain_name = domain.encode("cp1252")
        except (AttributeError, UnicodeError):
            self.unsupported.append(f"{api_name}: persona hostname or domain encoding unsupported")
            return ERROR_NOT_SUPPORTED
        if len(hostname) >= 132 or len(domain_name) >= 132:
            self.unsupported.append(f"{api_name}: persona hostname or domain too long")
            return ERROR_NOT_SUPPORTED
        info = FixedInfo()
        info.HostName = hostname
        info.DomainName = domain_name
        info.NodeType = 8  # Hybrid node
        info.DnsServerList.IpAddress = dns_servers[0].encode("ascii")
        if len(dns_servers) > 1:
            info.DnsServerList.Next = buffer + ctypes.sizeof(FixedInfo)
        image = bytearray(required)
        image[:ctypes.sizeof(info)] = bytes(info)
        for index, address in enumerate(dns_servers[1:]):
            node = IpAddrString()
            node.IpAddress = address.encode("ascii")
            if index + 2 < len(dns_servers):
                node.Next = buffer + ctypes.sizeof(FixedInfo) + (index + 1) * ctypes.sizeof(node)
            offset = ctypes.sizeof(FixedInfo) + index * ctypes.sizeof(node)
            image[offset:offset + ctypes.sizeof(node)] = bytes(node)
        emu.mem_write(buffer, bytes(image))
        emu.mem_write(size_ptr, struct.pack("<I", required))
        self.events.append({"event": "guest_network_params", "status": 0,
                            "required": required, "dns_server_count": len(dns_servers)})
        return 0
