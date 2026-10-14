"""Bounded guest file-version resource and query behavior."""

import struct
import unittest
from unittest.mock import patch

import speakeasy.common as common

from emumee.version_info import GuestVersionInfo, query_version_resource


def _node(key, value=b'', children=b'', *, text=False):
    result = bytearray(b'\0' * 6)
    result.extend((key + '\0').encode('utf-16le'))
    result.extend(b'\0' * (-len(result) % 4))
    result.extend(value)
    result.extend(b'\0' * (-len(result) % 4))
    result.extend(children)
    struct.pack_into('<HHH', result, 0, len(result),
                     len(value) // 2 if text else len(value), int(text))
    return bytes(result)


RESOURCE = _node('VS_VERSION_INFO', bytes(range(52)),
                 _node('VarFileInfo', children=
                       _node('Translation', b'\x09\x04\xe4\x04')))


class _Map:
    base = 0
    size = 65536
    free = False
    prot = common.PERM_MEM_READ | common.PERM_MEM_WRITE


class _Emu:
    def __init__(self):
        self.memory = bytearray(65536)
        self.last_error = 0

    def get_address_map(self, _address):
        return _Map()

    def get_ptr_size(self):
        return 8

    def mem_read(self, address, size):
        return bytes(self.memory[address:address + size])

    def mem_write(self, address, data):
        self.memory[address:address + len(data)] = data

    def set_last_error(self, code):
        self.last_error = code


class VersionInfoTests(unittest.TestCase):
    def test_query_bounded_resource(self):
        self.assertEqual(query_version_resource(RESOURCE, '\\'), (40, 52))
        offset, length = query_version_resource(
            RESOURCE, '\\VarFileInfo\\Translation')
        self.assertEqual((RESOURCE[offset:offset + length], length),
                         (b'\x09\x04\xe4\x04', 4))
        self.assertIsNone(query_version_resource(
            RESOURCE, '\\VarFileInfo\\Unknown'))
        self.assertIsNone(query_version_resource(RESOURCE[:10], '\\'))
        malformed = bytearray(RESOURCE)
        malformed[0:2] = b'\xff\xff'
        self.assertIsNone(query_version_resource(malformed, '\\'))

    def test_size_copy_and_query_guest_pointers(self):
        emu = _Emu()
        name = r'C:\samples\sample.exe'
        emu.mem_write(0x100, (name + '\0').encode('utf-16le'))
        emu.mem_write(0x400, ('\\VarFileInfo\\Translation\0').encode('utf-16le'))
        api = GuestVersionInfo(r'C:\samples', {name: b'image'})
        with patch('emumee.version_info.version_resource', return_value=RESOURCE):
            self.assertEqual(api._size_ex(emu, 'version.GetFileVersionInfoSizeExW',
                                           None, [1, 0x100, 0x300]), len(RESOURCE))
            self.assertEqual(emu.mem_read(0x300, 4), b'\0' * 4)
            self.assertEqual(api._info_ex(emu, 'version.GetFileVersionInfoExW',
                                           None, [1, 0x100, 0, len(RESOURCE), 0x800]), 1)
        self.assertEqual(emu.mem_read(0x800, len(RESOURCE)), RESOURCE)
        self.assertEqual(api._query(emu, 'version.VerQueryValueW', None,
                                    [0x800, 0x400, 0x600, 0x700]), 1)
        pointer = int.from_bytes(emu.mem_read(0x600, 8), 'little')
        self.assertEqual(emu.mem_read(pointer, 4), b'\x09\x04\xe4\x04')
        self.assertEqual(int.from_bytes(emu.mem_read(0x700, 4), 'little'), 4)
        emu.mem_write(0x800, b'changed')
        self.assertEqual(api._query(emu, 'version.VerQueryValueW', None,
                                    [0x800, 0x400, 0x600, 0x700]), 0)


if __name__ == '__main__':
    unittest.main()
