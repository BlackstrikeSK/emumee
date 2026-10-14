"""PE delay imports resolve only from bounded guest image data."""

import struct
import unittest
from types import SimpleNamespace

from speakeasy import common

from emumee.delay_imports import GuestDelayImports


class _Guest:
    def __init__(self, pointer_size):
        self.base = 0x140000000 if pointer_size == 8 else 0x400000
        self.memory = bytearray(0x2000)
        self.pointer_size = pointer_size
        self.modules = [SimpleNamespace(base=self.base, image_size=len(self.memory))]
        self.resolved = []

    def get_ptr_size(self):
        return self.pointer_size

    def get_address_map(self, address):
        if self.base <= address < self.base + len(self.memory):
            return SimpleNamespace(base=self.base, size=len(self.memory), free=False,
                                   prot=common.PERM_MEM_READ | common.PERM_MEM_WRITE)
        return None

    def mem_read(self, address, size):
        offset = address - self.base
        return bytes(self.memory[offset:offset + size])

    def mem_write(self, address, value):
        offset = address - self.base
        self.memory[offset:offset + len(value)] = value

    def get_proc(self, dll, name):
        self.resolved.append((dll, name))
        return 0xFEEDF100


class DelayImportTests(unittest.TestCase):
    def test_resolves_x86_and_x64_named_import_into_guest_iat(self):
        for pointer_size in (4, 8):
            with self.subTest(pointer_size=pointer_size):
                emu = _Guest(pointer_size)
                base = emu.base
                emu.mem_write(base + 0x500, b'ext-ms-win-test-l1-1-0.dll\0')
                emu.mem_write(base + 0x600, struct.pack(
                    '<8I', 1, 0x500, 0, 0x800, 0x700, 0, 0, 0))
                emu.mem_write(base + 0x700, (0x900).to_bytes(pointer_size, 'little'))
                emu.mem_write(base + 0x900, b'\0\0TestExport\0')
                model = GuestDelayImports()
                params = [base, base + 0x600, 0, 0, base + 0x800, 0]
                self.assertEqual(model.resolve(emu, 'ResolveDelayLoadedAPI', None,
                                               params), 0xFEEDF100)
                self.assertEqual(emu.resolved,
                                 [('ext-ms-win-test-l1-1-0.dll', 'TestExport')])
                self.assertEqual(int.from_bytes(emu.mem_read(base + 0x800,
                                                               pointer_size), 'little'),
                                 0xFEEDF100)
                emu.resolved.clear()
                model.write_guard = lambda _emu, _address, _size: False
                self.assertEqual(model.resolve(emu, 'ResolveDelayLoadedAPI', None,
                                               params), 0)
                self.assertEqual(emu.resolved, [])


if __name__ == '__main__':
    unittest.main()
