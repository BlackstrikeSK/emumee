"""Guest-backed string API bounds and return conventions."""

import unittest

import speakeasy.common as common

from emumee.winstrings import (FIND_FROMEND, FIND_FROMSTART,
                               FIND_STARTSWITH, GuestStrings)
from emumee.native import _api_coverage


class _Map:
    base = 0
    size = 65536
    free = False
    prot = common.PERM_MEM_READ | common.PERM_MEM_WRITE


class _Emu:
    def __init__(self):
        self.memory = bytearray(65536)
        self.last_error = 0

    def get_address_map(self, address):
        return _Map() if 0 <= address < 65536 else None

    def mem_read(self, address, size):
        return bytes(self.memory[address:address + size])

    def set_last_error(self, code):
        self.last_error = code


class WinStringTests(unittest.TestCase):
    def setUp(self):
        self.emu = _Emu()
        self.api = GuestStrings()
        self.emu.memory[0x100:0x100 + 20] = 'AlphaBeta\0'.encode('utf-16le')
        self.emu.memory[0x200:0x200 + 10] = 'beta\0'.encode('utf-16le')
        self.emu.memory[0x300:0x300 + 6] = b'ALPHA\0'
        self.emu.memory[0x400:0x400 + 6] = b'alpha\0'

    def test_ordinal_positions_and_failure(self):
        self.assertEqual(self.api._find_ordinal(
            self.emu, 'kernel32.FindStringOrdinal', None,
            [FIND_FROMSTART, 0x100, -1, 0x200, -1, 1]), 5)
        self.assertEqual(self.api._find_ordinal(
            self.emu, 'kernel32.FindStringOrdinal', None,
            [FIND_FROMEND, 0x100, -1, 0x200, -1, 0]), -1)
        self.assertEqual(self.emu.last_error, 0)
        self.assertEqual(self.api._find_ordinal(
            self.emu, 'kernel32.FindStringOrdinal', None,
            [FIND_STARTSWITH, 0x100, -1, 0x200, -1, 1]), -1)
        self.assertEqual(self.api._find_ordinal(
            self.emu, 'kernel32.FindStringOrdinal', None,
            [0, 0x100, -1, 0x200, -1, 1]), -1)
        self.assertEqual(self.emu.last_error, 1004)

    def test_compare_and_length(self):
        self.assertEqual(self.api._compare(
            self.emu, 'kernel32.CompareStringA', None,
            [0xC000, 1, 0x300, -1, 0x400, -1]), 2)
        self.assertEqual(self.api._compare(
            self.emu, 'kernel32.CompareStringA', None,
            [0xC000, 0, 0x300, -1, 0x400, -1]), 1)
        self.assertEqual(self.api._length(
            self.emu, 'kernel32.lstrlenW', None, [0x100]), 9)
        self.assertEqual(self.api._length(
            self.emu, 'kernel32.lstrlenW', None, [0]), 0)

    def test_report_does_not_treat_colon_text_as_signature(self):
        coverage = _api_coverage({'entry_points': [{'events': [
            {'event': 'api', 'api_name': 'kernel32.lstrlenW', 'args': ['ERROR: ']},
            {'event': 'api', 'api_name': 'advapi32.GetLengthSid',
             'args': ['pSid: 0x0']},
        ]}]})
        self.assertEqual(coverage['signature_only_calls'],
                         [{'api': 'advapi32.GetLengthSid', 'count': 1}])


if __name__ == '__main__':
    unittest.main()
