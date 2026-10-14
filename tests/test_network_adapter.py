"""Guest IP Helper adapter enumeration contracts."""

from __future__ import annotations

import ctypes
import struct
import unittest
from types import SimpleNamespace

import speakeasy.common as common

from emumee.network_adapter import GuestNetworkAdapter, _fixed_layouts, _layouts
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

    def test_null_dns_free_and_non_null_is_reported(self):
        model = GuestNetworkAdapter(load_persona(None))
        self.assertIsNone(model._dns_free(None, "dnsapi.DnsFree", None,
                                           [0, 0x10144]))
        self.assertFalse(model.unsupported)
        self.assertIsNone(model._dns_free(None, "dnsapi.DnsFree", None,
                                           [0x1234, 1]))
        self.assertEqual(len(model.unsupported), 1)

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
