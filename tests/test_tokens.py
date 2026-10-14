"""Persona token user SID layout and Win32 buffer contract."""

import struct
import unittest
from types import SimpleNamespace

import speakeasy.common as common

from emumee.tokens import GuestTokens, encode_sid


class _Map:
    base = 0
    size = 65536
    free = False
    prot = common.PERM_MEM_READ | common.PERM_MEM_WRITE


class _Emu:
    def __init__(self, width):
        self.width = width
        self.memory = bytearray(65536)
        self.last_error = 0
        self.token = SimpleNamespace(handles=[0x220])

    def get_ptr_size(self):
        return self.width

    def get_address_map(self, address):
        return _Map() if 0 <= address < 65536 else None

    def get_object_from_handle(self, handle):
        return self.token if handle == 0x220 else None

    def get_current_process(self):
        return SimpleNamespace(token=self.token)

    def mem_read(self, address, size):
        return bytes(self.memory[address:address + size])

    def mem_write(self, address, data):
        self.memory[address:address + len(data)] = data

    def set_last_error(self, code):
        self.last_error = code


class TokenTests(unittest.TestCase):
    def test_token_user_layout_and_sid_length(self):
        persona = {'user_sid': 'S-1-5-21-11-22-33-1001',
                   'user_is_admin': False, 'user_name': 'Alex',
                   'hostname': 'DESKTOP-Q1'}
        api = GuestTokens(persona)
        self.assertEqual(len(api.sid), 28)
        self.assertEqual(api.sid[:8], b'\x01\x05\0\0\0\0\0\x05')
        for width in (4, 8):
            with self.subTest(width=width):
                emu = _Emu(width)
                required = width + (8 if width == 8 else 4) + 28
                params = [0x220, 1, 0, 0, 0x300]
                self.assertEqual(api._token_info(emu, '', None, params), 0)
                self.assertEqual(emu.last_error, 122)
                self.assertEqual(struct.unpack('<I', emu.mem_read(0x300, 4))[0],
                                 required)
                params[2:4] = [0x500, required]
                self.assertEqual(api._token_info(emu, '', None, params), 1)
                sid_ptr = int.from_bytes(emu.mem_read(0x500, width), 'little')
                self.assertEqual(sid_ptr, 0x500 + required - len(api.sid))
                self.assertEqual(emu.mem_read(sid_ptr, 28), api.sid)
                self.assertEqual(api._valid_sid(emu, '', None, [sid_ptr]), 1)
                self.assertEqual(api._length_sid(emu, '', None, [sid_ptr]), 28)
                emu.mem_write(0x310, struct.pack('<I', 0))
                emu.mem_write(0x320, struct.pack('<I', 0))
                lookup = [0, sid_ptr, 0xC00, 0x310, 0xD00, 0x320, 0x330]
                self.assertEqual(api._lookup_sid(
                    emu, 'advapi32.LookupAccountSidW', None, lookup), 0)
                self.assertEqual(emu.last_error, 122)
                name_size = struct.unpack('<I', emu.mem_read(0x310, 4))[0]
                domain_size = struct.unpack('<I', emu.mem_read(0x320, 4))[0]
                self.assertEqual((name_size, domain_size), (5, 11))
                self.assertEqual(api._lookup_sid(
                    emu, 'advapi32.LookupAccountSidW', None, lookup), 1)
                self.assertEqual(emu.mem_read(0xC00, 10),
                                 'Alex\0'.encode('utf-16le'))
                self.assertEqual(emu.mem_read(0xD00, 22),
                                 'DESKTOP-Q1\0'.encode('utf-16le'))
                self.assertEqual(struct.unpack('<I', emu.mem_read(0x330, 4))[0], 1)
                self.assertEqual(api._copy_sid(
                    emu, '', None, [28, 0x700, sid_ptr]), 1)
                self.assertEqual(emu.mem_read(0x700, 28), api.sid)
                group_params = [0x220, 2, 0, 0, 0x300]
                self.assertEqual(api._token_info(emu, '', None, group_params), 0)
                group_size = struct.unpack('<I', emu.mem_read(0x300, 4))[0]
                group_params[2:4] = [0x900, group_size]
                self.assertEqual(api._token_info(emu, '', None, group_params), 1)
                self.assertEqual(struct.unpack('<I', emu.mem_read(0x900, 4))[0],
                                 len(api.groups))
                header = 8 if width == 8 else 4
                for index, group in enumerate(api.groups):
                    row = 0x900 + header + index * (16 if width == 8 else 8)
                    pointer = int.from_bytes(emu.mem_read(row, width), 'little')
                    self.assertEqual(emu.mem_read(pointer, len(group)), group)
                privilege_params = [0x220, 3, 0, 0, 0x300]
                self.assertEqual(api._token_info(emu, '', None, privilege_params), 0)
                privilege_size = struct.unpack('<I', emu.mem_read(0x300, 4))[0]
                self.assertEqual(privilege_size, 4 + len(api.privileges) * 12)
                privilege_params[2:4] = [0xB00, privilege_size]
                self.assertEqual(api._token_info(emu, '', None, privilege_params), 1)
                self.assertEqual(struct.unpack('<I', emu.mem_read(0xB00, 4))[0],
                                 len(api.privileges))
                self.assertEqual(struct.unpack('<III', emu.mem_read(0xB04, 12)),
                                 (22, 0, 3))
                for info_class in (33, 34):
                    claim_params = [0x220, info_class, 0, 0, 0x300]
                    self.assertEqual(api._token_info(emu, '', None, claim_params), 0)
                    self.assertEqual(emu.last_error, 122)
                    claim_size = struct.unpack('<I', emu.mem_read(0x300, 4))[0]
                    self.assertEqual(claim_size, 8 + width)
                    claim_params[2:4] = [0xA00, claim_size]
                    self.assertEqual(api._token_info(emu, '', None, claim_params), 1)
                    self.assertEqual(emu.mem_read(0xA00, claim_size),
                                     b'\x01' + b'\0' * (claim_size - 1))

    def test_invalid_sid_and_token_fail(self):
        with self.assertRaises(ValueError):
            encode_sid('S-2-5-21')
        api = GuestTokens({'user_sid': 'S-1-5-21-11-22-33-1001',
                           'user_is_admin': False, 'user_name': 'Alex',
                           'hostname': 'DESKTOP-Q1'})
        emu = _Emu(8)
        self.assertEqual(api._valid_sid(emu, '', None, [0]), 0)
        self.assertEqual(api._token_info(
            emu, '', None, [0x221, 1, 0x500, 64, 0x300]), 0)
        self.assertEqual(emu.last_error, 6)


if __name__ == '__main__':
    unittest.main()
