"""Guest LSA handles and persona Kerberos ticket-cache responses."""

import struct
import unittest
from types import SimpleNamespace

from emumee.lsa import (GuestLSA, KERBEROS_PACKAGE, STATUS_INVALID_HANDLE,
                        STATUS_INVALID_PARAMETER, STATUS_NOT_SUPPORTED)
from emumee.kerberos import ticket_filetime


class _Emu:
    def __init__(self, width):
        self.width = width
        self.memory = bytearray(0x10000)
        self.process = object()
        self.freed = []

    def get_current_process(self):
        return self.process

    def get_ptr_size(self):
        return self.width

    def get_address_map(self, address):
        if 0 < address < len(self.memory):
            return SimpleNamespace(base=0, size=len(self.memory), prot=6, free=False)
        return None

    def mem_read(self, address, size):
        return bytes(self.memory[address:address + size])

    def mem_write(self, address, data):
        self.memory[address:address + len(data)] = data

    def mem_map(self, size, **kwargs):
        assert size == 0x1000
        assert kwargs['process'] is self.process
        return 0x8000

    def mem_free(self, address):
        self.freed.append(address)


class LSATests(unittest.TestCase):
    def test_maximum_ticket_metadata_gets_a_bounded_response_allocation(self):
        ticket = {"server": "s" * 256, "realm": "r" * 256,
                  "encryption_type": 18, "session_key_type": 17, "flags": 0,
                  "start_utc": "2026-10-14T10:00:00Z", "end_utc": "2026-10-14T20:00:00Z",
                  "renew_utc": "2026-10-21T10:00:00Z"}
        for width in (4, 8):
            with self.subTest(width=width):
                emu = _Emu(width)
                allocations = []
                emu.mem_map = lambda size, **kwargs: (allocations.append(size) or 0x8000)
                api = GuestLSA({"kerberos": {"tickets": [ticket] * 16}})
                api._connect(emu, '', None, [0x100])
                handle = int.from_bytes(emu.mem_read(0x100, width), 'little')
                emu.mem_write(0x500, struct.pack('<IQ', 1, 0))
                self.assertEqual(api._call(emu, '', None,
                                          [handle, KERBEROS_PACKAGE, 0x500, 12,
                                           0x600, 0x700, 0x800]), 0)
                length = struct.unpack('<I', emu.mem_read(0x700, 4))[0]
                self.assertGreater(length, 4096)
                self.assertLessEqual(length, allocations[0])
                self.assertLessEqual(allocations[0], 24 * 1024)
                self.assertEqual(struct.unpack('<II', emu.mem_read(0x8000, 8)), (1, 16))

    def test_persona_ticket_cache_layout_and_owned_response_buffers(self):
        ticket = {"server": "HTTP/guest.example", "realm": "GUEST.EXAMPLE",
                  "encryption_type": 18, "session_key_type": 17, "flags": 0x40a10000,
                  "start_utc": "2026-10-14T10:00:00Z", "end_utc": "2026-10-14T20:00:00Z",
                  "renew_utc": "2026-10-21T10:00:00Z"}
        for width in (4, 8):
            with self.subTest(width=width):
                emu = _Emu(width)
                api = GuestLSA({"kerberos": {"tickets": [ticket]}})
                self.assertEqual(api._connect(emu, '', None, [0x100]), 0)
                handle = int.from_bytes(emu.mem_read(0x100, width), 'little')
                emu.mem_write(0x500, struct.pack('<IQ', 1, 0))
                args = [handle, KERBEROS_PACKAGE, 0x500, 12, 0x600, 0x700, 0x800]
                self.assertEqual(api._call(emu, '', None, args), 0)
                response = int.from_bytes(emu.mem_read(0x600, width), 'little')
                self.assertEqual(struct.unpack('<II', emu.mem_read(response, 8)), (1, 1))
                string_size = 16 if width == 8 else 8
                length = struct.unpack('<I', emu.mem_read(0x700, 4))[0]
                for offset, expected in ((0, ticket['server']), (string_size, ticket['realm'])):
                    header = emu.mem_read(response + 8 + offset, string_size)
                    size, maximum = struct.unpack_from('<HH', header)
                    pointer = int.from_bytes(header[8 if width == 8 else 4:], 'little')
                    self.assertGreaterEqual(pointer, response + 8 + (64 if width == 8 else 48))
                    self.assertLessEqual(pointer + maximum, response + length)
                    self.assertEqual(emu.mem_read(pointer, size).decode('utf-16le'), expected)
                times = struct.unpack('<qqqiI', emu.mem_read(response + 8 + 2 * string_size, 32))
                self.assertEqual(times, (ticket_filetime(ticket['start_utc']),
                                         ticket_filetime(ticket['end_utc']),
                                         ticket_filetime(ticket['renew_utc']), 18, 0x40a10000))
                self.assertEqual(api._free(emu, '', None, [response]), 0)
                self.assertEqual(emu.freed, [response])

    def test_empty_kerberos_cache_and_process_ownership(self):
        for width in (4, 8):
            with self.subTest(width=width):
                emu = _Emu(width)
                api = GuestLSA()
                self.assertEqual(api._connect(emu, '', None, [0x100]), 0)
                handle = int.from_bytes(emu.mem_read(0x100, width), 'little')
                name = b'Kerberos'
                emu.mem_write(0x300, name)
                header = bytearray(8 if width == 4 else 16)
                struct.pack_into('<HH', header, 0, len(name), len(name))
                header[4 if width == 4 else 8:] = (0x300).to_bytes(width, 'little')
                emu.mem_write(0x200, header)
                self.assertEqual(api._lookup(emu, '', None,
                                             [handle, 0x200, 0x400]), 0)
                self.assertEqual(struct.unpack('<I', emu.mem_read(0x400, 4))[0],
                                 KERBEROS_PACKAGE)
                emu.mem_write(0x500, struct.pack('<IQ', 1, 0))
                args = [handle, KERBEROS_PACKAGE, 0x500, 12,
                        0x600, 0x700, 0x800]
                self.assertEqual(api._call(emu, '', None, args), 0)
                response = int.from_bytes(emu.mem_read(0x600, width), 'little')
                self.assertEqual(response, 0x8000)
                self.assertEqual(emu.mem_read(response, 8), struct.pack('<II', 1, 0))
                self.assertEqual(emu.mem_read(0x700, 4), struct.pack('<I', 8))
                self.assertEqual(emu.mem_read(0x800, 4), b'\0' * 4)
                self.assertEqual(api._free(emu, '', None, [response]), 0)
                self.assertEqual(emu.freed, [response])
                domain_request = struct.pack('<II', 32, 0) + b'\0' * (16 if width == 8 else 8)
                emu.mem_write(0x500, domain_request)
                args[3] = len(domain_request)
                self.assertEqual(api._call(emu, '', None, args), 0)
                self.assertEqual(emu.mem_read(0x8000, 16),
                                 struct.pack('<IIII', 32, 1, 0, 0))
                self.assertEqual(emu.mem_read(0x700, 4), struct.pack('<I', 16))
                self.assertEqual(api._free(emu, '', None, [response]), 0)
                emu.mem_write(0x500, struct.pack('<IQ', 99, 0))
                args[3] = 12
                self.assertEqual(api._call(emu, '', None, args), 0)
                self.assertEqual(emu.mem_read(0x800, 4),
                                 struct.pack('<I', STATUS_NOT_SUPPORTED))
                emu.mem_write(0x500, struct.pack('<IQ', 1, 0))
                self.assertEqual(api._call(emu, '', None, args), 0)
                api.cleanup_process(emu, emu.process)
                self.assertNotIn((id(emu.process), handle), api.handles)
                self.assertFalse(api.buffers)
                emu.process = object()
                self.assertEqual(api._lookup(emu, '', None,
                                             [handle, 0x200, 0x400]),
                                 STATUS_INVALID_HANDLE)
                self.assertEqual(api._free(emu, '', None, [response]),
                                 STATUS_INVALID_PARAMETER)


if __name__ == '__main__':
    unittest.main()
