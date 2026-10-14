"""Guest IP Helper adapter enumeration contracts."""

from __future__ import annotations

import ctypes
import ipaddress
import socket
import struct
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

import speakeasy.common as common

from emumee.network_adapter import (GuestNetworkAdapter, _MibIfRow,
                                    _fixed_layouts, _layouts)
from emumee.network import NetworkBridge
from emumee.artifacts import ArtifactCatalog
from emumee.feature_config import GuestFeatureConfiguration
from emumee.persona import load_persona


class MemoryEmulator:
    def __init__(self, width: int):
        self.width = width
        self.last_error = 12345
        self.base = 0x10000
        self.memory = bytearray(0x10000)
        self.mapping = SimpleNamespace(base=self.base, size=len(self.memory),
                                       prot=common.PERM_MEM_READ | common.PERM_MEM_WRITE,
                                       free=False)

    def get_ptr_size(self):
        return self.width

    def set_last_error(self, code):
        self.last_error = code

    def get_address_map(self, address):
        return self.mapping if self.base <= address < self.base + len(self.memory) else None

    def mem_read(self, address, size):
        offset = address - self.base
        if offset < 0 or offset + size > len(self.memory):
            raise ValueError("unmapped guest read")
        return bytes(self.memory[offset:offset + size])

    def mem_write(self, address, data):
        offset = address - self.base
        if offset < 0 or offset + len(data) > len(self.memory):
            raise ValueError("unmapped guest write")
        self.memory[offset:offset + len(data)] = data


class GuestNetworkAdapterTests(unittest.TestCase):
    def test_guest_tcp_connection_tracks_virtual_port_and_process_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            bridge = NetworkBridge(ArtifactCatalog(Path(directory) / "artifacts"))
            calls = []
            bridge.rpc = SimpleNamespace(call=lambda operation, **fields:
                                         calls.append((operation, fields)))
            process = SimpleNamespace(pid=9876)
            bridge.broker_sockets[10] = 42
            bridge.socket_types[10] = socket.SOCK_STREAM
            bridge.socket_owners[10] = id(process)
            sockaddr = b"\x02\x00\x01\xbb\xcb\x00\x71\x07" + b"\0" * 8
            emu = SimpleNamespace(mem_read=lambda _pointer, _size: sockaddr,
                                  get_current_process=lambda: process)
            self.assertEqual(bridge._connect(emu, "ws2_32.connect", lambda _args: 0,
                                             [10, 100]), 0)
            self.assertEqual(bridge.connected_tcp[10], {
                "local_port": 49152, "remote_ip": "203.0.113.7",
                "remote_port": 443, "pid": 9876,
            })
            bridge.cleanup_process(process)
            self.assertFalse(bridge.connected_tcp)
            self.assertFalse(bridge.broker_sockets)
            self.assertEqual(calls, [("socket_connect", {
                "socket": 42, "host": "203.0.113.7", "port": 443}),
                ("socket_close", {"socket": 42})])

    def test_mib_interface_and_arp_tables_follow_persona_and_bound_writes(self):
        for width in (4, 8):
            with self.subTest(width=width):
                emu = MemoryEmulator(width)
                persona = load_persona(None)
                persona["network_adapter"].update({
                    "ipv4": "10.10.4.22", "prefix_length": 23,
                    "gateway": "10.10.4.1", "if_index": 7,
                    "mtu": 1400, "mac": "12-34-56-78-9A-BC"})
                model = GuestNetworkAdapter(persona)
                size_ptr, buffer = 0x10100, 0x11000
                for method, expected_size in (
                        (model._get_if_table, 4 + ctypes.sizeof(_MibIfRow)),
                        (model._get_ip_net_table, 4 + 24),
                        (model._get_ip_addr_table, 4 + 24)):
                    with self.subTest(method=method.__name__):
                        emu.mem_write(buffer, b"\0" * expected_size)
                        emu.mem_write(size_ptr, struct.pack("<I", 0))
                        call = lambda address: method(emu, "iphlpapi." +
                                                      method.__name__, None,
                                                      [address, size_ptr, 1])
                        self.assertEqual(call(0), 122)
                        self.assertEqual(emu.mem_read(size_ptr, 4),
                                         struct.pack("<I", expected_size))
                        emu.mem_write(size_ptr, struct.pack("<I", expected_size - 1))
                        self.assertEqual(call(buffer), 122)
                        self.assertEqual(emu.mem_read(buffer, expected_size),
                                         b"\0" * expected_size)
                        self.assertEqual(call(buffer), 0)
                        self.assertEqual(emu.mem_read(buffer, 4), struct.pack("<I", 1))
                        if method == model._get_if_table:
                            interface_image = emu.mem_read(buffer, expected_size)
                        elif method == model._get_ip_net_table:
                            neighbor_image = emu.mem_read(buffer, expected_size)
                        else:
                            address_image = emu.mem_read(buffer, expected_size)
                        emu.mem_write(size_ptr, struct.pack("<I", expected_size))
                        self.assertEqual(call(0x30000), 87)
                        self.assertEqual(method(emu, "iphlpapi.test", None,
                                                [buffer, 0x30000, 0]), 87)
                row = _MibIfRow.from_buffer_copy(interface_image[4:])
                self.assertEqual(ctypes.sizeof(_MibIfRow), 860)
                self.assertEqual(row.dwIndex, 7)
                self.assertEqual(row.dwType, 6)
                self.assertEqual(row.dwMtu, 1400)
                self.assertEqual(row.dwSpeed, 1_000_000_000)
                self.assertEqual(row.dwPhysAddrLen, 6)
                self.assertEqual(bytes(row.bPhysAddr[:6]), bytes.fromhex("123456789abc"))
                self.assertEqual((row.dwAdminStatus, row.dwOperStatus), (1, 5))
                self.assertIn("{7A91D3B6-46CF-4D12-9D5B-8E7C412A9360}",
                              bytes(row.wszName).decode("utf-16le"))
                self.assertEqual(bytes(row.bDescr[:row.dwDescrLen]),
                                 persona["network_adapter"]["description"].encode("cp1252"))
                self.assertEqual(neighbor_image[4:],
                                 struct.pack("<II8s4sI", 7, 6,
                                             b"\xff" * 6 + b"\0\0",
                                             bytes((10, 10, 5, 255)), 4))
                self.assertEqual(address_image[4:],
                                 struct.pack("<4sI4sIIHH", bytes((10, 10, 4, 22)),
                                             7, bytes((255, 255, 254, 0)),
                                             1, 65535, 0, 1))

    def test_arp_table_has_no_invented_broadcast_on_point_to_point_subnet(self):
        emu = MemoryEmulator(8)
        persona = load_persona(None)
        persona["network_adapter"].update({
            "ipv4": "10.0.0.2", "prefix_length": 31, "gateway": "10.0.0.3"})
        model = GuestNetworkAdapter(persona)
        size_ptr, buffer = 0x10100, 0x11000
        emu.mem_write(size_ptr, struct.pack("<I", 64))
        self.assertEqual(model._get_ip_net_table(
            emu, "iphlpapi.GetIpNetTable", None,
            [buffer, size_ptr, 0]), 232)
        self.assertEqual(emu.mem_read(buffer, 28), b"\0" * 28)
        self.assertEqual(model._get_ip_net_table(
            emu, "iphlpapi.GetIpNetTable", None,
            [buffer, 0x30000, 0]), 87)

    def test_ipv4_route_table_size_and_persona_addresses(self):
        for width in (4, 8):
            with self.subTest(width=width):
                emu = MemoryEmulator(width)
                persona = load_persona(None)
                persona["network_adapter"].update({
                    "ipv4": "10.10.4.22", "prefix_length": 23,
                    "gateway": "10.10.4.1", "if_index": 7})
                model = GuestNetworkAdapter(persona)
                size_ptr, buffer = 0x10100, 0x11000
                emu.mem_write(size_ptr, struct.pack("<I", 0))
                call = lambda address: model._get_ip_forward_table(
                    emu, "iphlpapi.GetIpForwardTable", None,
                    [address, size_ptr, 0])
                self.assertEqual(call(0), 122)
                required = struct.unpack("<I", emu.mem_read(size_ptr, 4))[0]
                self.assertEqual(required, 4 + 3 * 56)
                emu.mem_write(size_ptr, struct.pack("<I", required - 1))
                self.assertEqual(call(buffer), 122)
                self.assertEqual(emu.mem_read(buffer, required), b"\0" * required)
                self.assertEqual(call(buffer), 0)
                image = emu.mem_read(buffer, required)
                self.assertEqual(struct.unpack_from("<I", image)[0], 3)
                self.assertEqual(ipaddress.IPv4Address(image[4:8]),
                                 ipaddress.IPv4Address("0.0.0.0"))
                self.assertEqual(ipaddress.IPv4Address(image[16:20]),
                                 ipaddress.IPv4Address("10.10.4.1"))
                self.assertEqual(struct.unpack_from("<I", image, 20)[0], 7)
                self.assertEqual(ipaddress.IPv4Address(image[60:64]),
                                 ipaddress.IPv4Address("10.10.4.0"))
                self.assertEqual(ipaddress.IPv4Address(image[64:68]),
                                 ipaddress.IPv4Address("255.255.254.0"))
                self.assertEqual(call(0x30000), 87)

    def test_get_network_params_returns_guest_fixed_info_and_dns_list(self):
        for width in (4, 8):
            with self.subTest(width=width):
                emu = MemoryEmulator(width)
                persona = load_persona(None)
                persona["network_adapter"]["dns_servers"] = ["192.168.1.1", "1.1.1.1"]
                model = GuestNetworkAdapter(persona)
                size_ptr, buffer = 0x10100, 0x11000
                emu.mem_write(size_ptr, struct.pack("<I", 0))
                call = lambda address: model._get_network_params(
                    emu, "iphlpapi.GetNetworkParams", None, [address, size_ptr])
                self.assertEqual(call(0), 111)
                FixedInfo, IpAddrString = _fixed_layouts(width)
                required = ctypes.sizeof(FixedInfo) + ctypes.sizeof(IpAddrString)
                self.assertEqual(emu.mem_read(size_ptr, 4), struct.pack("<I", required))
                self.assertEqual(call(buffer), 0)
                info = FixedInfo.from_buffer_copy(emu.mem_read(
                    buffer, ctypes.sizeof(FixedInfo)))
                self.assertEqual(info.HostName, b"DESKTOP-7F4M2Q9")
                self.assertEqual(info.DomainName, b"")
                self.assertEqual(info.NodeType, 8)
                self.assertEqual(info.DnsServerList.IpAddress, b"192.168.1.1")
                self.assertEqual(info.DnsServerList.Next, buffer + ctypes.sizeof(FixedInfo))
                second = IpAddrString.from_buffer_copy(emu.mem_read(
                    info.DnsServerList.Next, ctypes.sizeof(IpAddrString)))
                self.assertEqual(second.IpAddress, b"1.1.1.1")
                self.assertEqual(second.Next, 0)
                self.assertEqual(call(0x30000), 87)

    def test_ipv4_mask_bytes_and_invalid_length(self):
        emu = MemoryEmulator(8)
        model = GuestNetworkAdapter(load_persona(None))
        for prefix, expected in ((0, b"\0" * 4), (8, b"\xff\0\0\0"),
                                 (24, b"\xff\xff\xff\0"), (32, b"\xff" * 4)):
            with self.subTest(prefix=prefix):
                self.assertEqual(model._convert_length_to_ipv4_mask(
                    emu, "iphlpapi.ConvertLengthToIpv4Mask", None,
                    [prefix, 0x10100]), 0)
                self.assertEqual(emu.mem_read(0x10100, 4), expected)
        self.assertEqual(model._convert_length_to_ipv4_mask(
            emu, "iphlpapi.ConvertLengthToIpv4Mask", None,
            [33, 0x10100]), 87)
        self.assertEqual(emu.mem_read(0x10100, 4), b"\xff" * 4)

    def test_ipv4_wide_conversion_size_and_port(self):
        for width in (4, 8):
            with self.subTest(width=width):
                emu = MemoryEmulator(width)
                model = GuestNetworkAdapter(load_persona(None))
                emu.mem_write(0x10100, bytes((192, 168, 1, 107)))
                emu.mem_write(0x10200, struct.pack("<I", 2))
                params = [0x10100, 0, 0x10300, 0x10200]
                self.assertEqual(model._rtl_ipv4_address_to_string_ex_w(
                    emu, "ntdll.RtlIpv4AddressToStringExW", None, params),
                    0xC000000D)
                self.assertEqual(emu.mem_read(0x10200, 4), struct.pack("<I", 14))
                self.assertEqual(emu.mem_read(0x10300, 4), b"\0" * 4)
                self.assertEqual(model._rtl_ipv4_address_to_string_ex_w(
                    emu, "ntdll.RtlIpv4AddressToStringExW", None, params), 0)
                self.assertEqual(emu.mem_read(0x10300, 28),
                                 "192.168.1.107\0".encode("utf-16le"))
                emu.mem_write(0x10200, struct.pack("<I", 65))
                params[1] = 0x5000  # htons(80)
                self.assertEqual(model._rtl_ipv4_address_to_string_ex_w(
                    emu, "ntdll.RtlIpv4AddressToStringExW", None, params), 0)
                self.assertEqual(emu.mem_read(0x10300, 34),
                                 "192.168.1.107:80\0".encode("utf-16le"))

    def test_inet_ntop_w_ipv4_ipv6_and_small_output(self):
        emu = MemoryEmulator(8)
        model = GuestNetworkAdapter(load_persona(None))
        emu.mem_write(0x10100, bytes((192, 168, 1, 107)))
        call = lambda family, capacity: model._inet_ntop_w(
            emu, "ws2_32.InetNtopW", None,
            [family, 0x10100, 0x10300, capacity])
        self.assertEqual(call(2, 5), 0)
        self.assertEqual(emu.last_error, 87)
        self.assertEqual(emu.mem_read(0x10300, 4), b"\0" * 4)
        self.assertEqual(call(2, 65), 0x10300)
        self.assertEqual(emu.mem_read(0x10300, 28),
                         "192.168.1.107\0".encode("utf-16le"))
        self.assertEqual(call(99, 65), 0)
        self.assertEqual(emu.last_error, 10047)
        emu.mem_write(0x10100, bytes.fromhex("20010db8000000000000000000000001"))
        self.assertEqual(call(23, 65), 0x10300)
        self.assertEqual(emu.mem_read(0x10300, 22),
                         "2001:db8::1".encode("utf-16le"))
        emu.mem_write(0x10100, bytes.fromhex("00000000000000000000ffffc0000201"))
        self.assertEqual(call(23, 65), 0x10300)
        self.assertEqual(emu.mem_read(0x10300, 34),
                         "::ffff:192.0.2.1\0".encode("utf-16le"))

    def test_buffer_overflow_then_ipv4_adapter_graph(self):
        for width in (4, 8):
            with self.subTest(width=width):
                emu = MemoryEmulator(width)
                model = GuestNetworkAdapter(load_persona(None))
                size_ptr, buffer = 0x10100, 0x11000
                emu.mem_write(size_ptr, struct.pack("<I", 0))
                call = lambda address: model._get_adapters_addresses(
                    emu, "iphlpapi.GetAdaptersAddresses", None,
                    [0, 0xC6, 0, address, size_ptr])
                self.assertEqual(call(0), 111)
                required = struct.unpack("<I", emu.mem_read(size_ptr, 4))[0]
                self.assertGreater(required, 400)
                self.assertEqual(call(buffer), 0)
                self.assertEqual(struct.unpack("<I", emu.mem_read(size_ptr, 4))[0], required)

                Adapter, Unicast, AddressNode = _layouts(width)
                header = Adapter.from_buffer_copy(emu.mem_read(buffer, ctypes.sizeof(Adapter)))
                self.assertEqual(header.Length, ctypes.sizeof(Adapter))
                self.assertEqual(header.IfIndex, 12)
                self.assertEqual(header.Mtu, 1500)
                self.assertEqual(header.IfType, 6)
                self.assertEqual(header.OperStatus, 1)
                self.assertEqual(header.PhysicalAddressLength, 6)
                self.assertEqual(bytes(header.PhysicalAddress[:6]), bytes.fromhex("3c52824a6f19"))
                self.assertEqual(emu.mem_read(header.AdapterName, 39),
                                 b"{7A91D3B6-46CF-4D12-9D5B-8E7C412A9360}\0")
                self.assertEqual(emu.mem_read(header.FriendlyName, 18),
                                 "Ethernet\0".encode("utf-16le"))

                unicast = Unicast.from_buffer_copy(emu.mem_read(
                    header.FirstUnicastAddress, ctypes.sizeof(Unicast)))
                self.assertEqual(unicast.OnLinkPrefixLength, 24)
                self.assertEqual(unicast.Address.iSockaddrLength, 16)
                self.assertEqual(emu.mem_read(unicast.Address.lpSockaddr, 8),
                                 b"\x02\0\0\0\xc0\xa8\x01\x6b")
                gateway = AddressNode.from_buffer_copy(emu.mem_read(
                    header.FirstGatewayAddress, ctypes.sizeof(AddressNode)))
                self.assertEqual(emu.mem_read(gateway.Address.lpSockaddr, 8),
                                 b"\x02\0\0\0\xc0\xa8\x01\x01")
                dns = AddressNode.from_buffer_copy(emu.mem_read(
                    header.FirstDnsServerAddress, ctypes.sizeof(AddressNode)))
                self.assertEqual(dns.Next, 0)
                self.assertEqual(emu.mem_read(dns.Address.lpSockaddr, 8),
                                 b"\x02\0\0\0\xc0\xa8\x01\x01")
                for pointer in (header.AdapterName, header.FriendlyName,
                                header.FirstUnicastAddress, header.FirstDnsServerAddress,
                                header.FirstGatewayAddress):
                    self.assertGreaterEqual(pointer, buffer)
                    self.assertLess(pointer, buffer + required)

    def test_invalid_inputs_do_not_write_guest_buffer(self):
        emu = MemoryEmulator(8)
        model = GuestNetworkAdapter(load_persona(None))
        emu.mem_write(0x10100, struct.pack("<I", 0x1000))
        for params, expected in (
            ([0, 0, 0, 0x11000, 0], 87),
            ([99, 0, 0, 0x11000, 0x10100], 87),
            ([0, 0, 1, 0x11000, 0x10100], 87),
            ([23, 0, 0, 0x11000, 0x10100], 232),
            ([0, 0x10, 0, 0x11000, 0x10100], 50),
        ):
            with self.subTest(params=params):
                self.assertEqual(model._get_adapters_addresses(
                    emu, "iphlpapi.GetAdaptersAddresses", None, params), expected)
                self.assertEqual(emu.mem_read(0x11000, 16), b"\0" * 16)

    def test_extended_tcp_table_uses_guest_connection_and_persona_address(self):
        for width in (4, 8):
            with self.subTest(width=width):
                emu = MemoryEmulator(width)
                persona = load_persona(None)
                persona["network_adapter"]["ipv4"] = "10.10.4.22"
                model = GuestNetworkAdapter(persona)
                model.network_bridge = SimpleNamespace(connected_tcp={17: {
                    "local_port": 49152, "remote_ip": "203.0.113.7",
                    "remote_port": 443, "pid": 9876,
                }})
                size_ptr, buffer = 0x10100, 0x11000
                emu.mem_write(size_ptr, struct.pack("<I", 0))
                params = [0, size_ptr, 0, 2, 5, 0]
                self.assertEqual(model._get_extended_tcp_table(
                    emu, "iphlpapi.GetExtendedTcpTable", None, params), 122)
                self.assertEqual(struct.unpack("<I", emu.mem_read(size_ptr, 4))[0], 28)
                emu.mem_write(size_ptr, struct.pack("<I", 28))
                params[0] = buffer
                self.assertEqual(model._get_extended_tcp_table(
                    emu, "iphlpapi.GetExtendedTcpTable", None, params), 0)
                self.assertEqual(emu.mem_read(buffer, 28),
                                 struct.pack("<II4s4s4s4sI", 1, 5,
                                             b"\x0a\x0a\x04\x16", b"\xc0\x00\x00\x00",
                                             b"\xcb\x00\x71\x07", b"\x01\xbb\x00\x00", 9876))
                self.assertEqual(model._get_extended_tcp_table(
                    emu, "iphlpapi.GetExtendedTcpTable", None,
                    [buffer, size_ptr, 0, 23, 5, 0]), 50)


class GuestFeatureConfigurationTests(unittest.TestCase):
    def test_absent_feature_updates_stamp_without_changing_configuration(self):
        emu = MemoryEmulator(8)
        model = GuestFeatureConfiguration()
        emu.mem_write(0x10100, b"\xaa" * 8)
        emu.mem_write(0x10200, b"\xbb" * 12)
        result = model._query(emu, "ntdll.RtlQueryFeatureConfiguration", None,
                              [0x3900A15, 0, 0x10100, 0x10200])
        self.assertEqual(result, 0xC0000225)
        self.assertEqual(emu.mem_read(0x10100, 8), struct.pack("<Q", 1))
        self.assertEqual(emu.mem_read(0x10200, 12), b"\xbb" * 12)
        self.assertEqual(model.events[0]["feature_id"], 0x3900A15)
        self.assertFalse(model.unsupported)

    def test_feature_query_rejects_unmapped_output_without_write(self):
        emu = MemoryEmulator(8)
        model = GuestFeatureConfiguration()
        emu.mem_write(0x10100, b"\xaa" * 8)
        result = model._query(emu, "ntdll.RtlQueryFeatureConfiguration", None,
                              [123, 0, 0x10100, 0x30000])
        self.assertEqual(result, 0xC000000D)
        self.assertEqual(emu.mem_read(0x10100, 8), b"\xaa" * 8)
        self.assertEqual(len(model.unsupported), 1)


if __name__ == "__main__":
    unittest.main()
