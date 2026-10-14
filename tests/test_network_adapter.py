"""Guest IP Helper adapter enumeration contracts."""

from __future__ import annotations

import ctypes
import struct
import unittest
from types import SimpleNamespace

import speakeasy.common as common

from emumee.network_adapter import GuestNetworkAdapter, _layouts
from emumee.persona import load_persona


class MemoryEmulator:
    def __init__(self, width: int):
        self.width = width
        self.base = 0x10000
        self.memory = bytearray(0x10000)
        self.mapping = SimpleNamespace(base=self.base, size=len(self.memory),
                                       prot=common.PERM_MEM_READ | common.PERM_MEM_WRITE,
                                       free=False)

    def get_ptr_size(self):
        return self.width

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


if __name__ == "__main__":
    unittest.main()
