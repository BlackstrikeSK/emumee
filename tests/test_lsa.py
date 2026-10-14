"""Guest LSA handles and empty Kerberos ticket-cache responses."""

import struct
import unittest
from types import SimpleNamespace

from emumee.lsa import (GuestLSA, KERBEROS_PACKAGE, STATUS_INVALID_HANDLE,
                        STATUS_INVALID_PARAMETER, STATUS_NOT_SUPPORTED)


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
