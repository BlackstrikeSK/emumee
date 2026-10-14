"""Guest-backed string API bounds and return conventions."""

import unittest

import speakeasy.common as common

from emumee.winstrings import (FIND_FROMEND, FIND_FROMSTART,
                               FIND_STARTSWITH, GuestStrings)
from emumee.native import _api_coverage


class _Map:
    base = 0
    size = 131072
    free = False
    prot = common.PERM_MEM_READ | common.PERM_MEM_WRITE


class _Emu:
    def __init__(self):
        self.memory = bytearray(131072)
        self.last_error = 0

    def get_address_map(self, address):
        return _Map() if 0 <= address < 131072 else None

    def mem_read(self, address, size):
        return bytes(self.memory[address:address + size])

    def mem_write(self, address, data):
        self.memory[address:address + len(data)] = data

    def set_last_error(self, code):
        self.last_error = code

    def get_ptr_size(self):
        return 8


class WinStringTests(unittest.TestCase):
    def test_default_ansi_code_page_has_no_dbcs_lead_bytes(self):
        self.assertEqual(GuestStrings._is_dbcs_lead_byte(
            None, 'kernel32.IsDBCSLeadByte', None, [0x89]), 0)

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
            self.emu, 'api-ms-win-core-libraryloader-l1-2-0.FindStringOrdinal',
            None, [FIND_FROMSTART, 0x100, 0xffffffff, 0x200, 4,
                   0x100000001]), 5)
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

    def test_strtrimw_changes_guest_buffer_only_when_needed(self):
        self.emu.mem_write(0x500, '  Alpha Beta  \0'.encode('utf-16le'))
        self.emu.mem_write(0x600, ' \0'.encode('utf-16le'))
        call = lambda: self.api._trim(self.emu, 'shlwapi.StrTrimW', None,
                                      [0x500, 0x600])
        self.assertEqual(call(), 1)
        self.assertEqual(self.api._read(self.emu, 0x500, -1, True), 'Alpha Beta')
        self.assertEqual(call(), 0)
        self.api.write_guard = lambda _emu, _address, _size: False
        self.emu.mem_write(0x500, ' Alpha \0'.encode('utf-16le'))
        self.assertEqual(call(), 0)
        self.assertEqual(self.api._read(self.emu, 0x500, -1, True), ' Alpha ')
        self.assertEqual(self.api._trim(self.emu, 'shlwapi.StrTrimW', None,
                                        [0, 0x600]), 0)

    def test_rtl_oem_to_unicode_ascii_and_bounded_truncation(self):
        self.emu.mem_write(0x500, b'A\n')
        call = lambda capacity: self.api._oem_to_unicode(
            self.emu, 'ntdll.RtlOemToUnicodeN', None,
            [0x600, capacity, 0x700, 0x500, 2])
        self.assertEqual(call(6), 0)
        self.assertEqual(self.emu.mem_read(0x600, 6), 'A\n\0'.encode('utf-16le'))
        self.assertEqual(self.emu.mem_read(0x700, 4), (4).to_bytes(4, 'little'))
        self.assertEqual(call(2), 0x80000005)
        self.assertEqual(self.emu.mem_read(0x700, 4), (2).to_bytes(4, 'little'))
        self.assertEqual(self.api._oem_to_unicode(
            self.emu, 'ntdll.RtlOemToUnicodeN', None,
            [0x600, 0x100000006, 0x700, 0x500, 0x100000002]), 0)
        self.assertEqual(self.emu.mem_read(0x600, 6), 'A\n\0'.encode('utf-16le'))
        self.emu.mem_write(0x500, b'\xff\n')
        self.assertEqual(call(6), 0xC00000BB)
        self.api.write_guard = lambda _emu, _address, _size: False
        self.assertEqual(call(6), 0xC000000D)

    def test_rtl_is_text_unicode_distinguishes_ascii_and_utf16(self):
        ascii_text = b'Milk\nCoffee\nBread\n'
        self.emu.mem_write(0x500, ascii_text)
        self.emu.mem_write(0x700, (0xffffffff).to_bytes(4, 'little'))
        call = lambda size: self.api._is_text_unicode(
            self.emu, 'ntdll.RtlIsTextUnicode', None,
            [0x500, size, 0x700])
        self.assertEqual(call(len(ascii_text)), 0)
        self.assertEqual(self.emu.mem_read(0x700, 4), b'\0' * 4)
        wide_text = 'Coffee'.encode('utf-16le')
        self.emu.mem_write(0x500, wide_text)
        self.emu.mem_write(0x700, (0xffffffff).to_bytes(4, 'little'))
        self.assertEqual(call(len(wide_text)), 1)
        self.assertEqual(int.from_bytes(self.emu.mem_read(0x700, 4), 'little'),
                         0x1003)
        self.emu.mem_write(0x500, b'\xff\xfeA\0')
        self.emu.mem_write(0x700, (0xffffffff).to_bytes(4, 'little'))
        self.assertEqual(call(4), 1)
        self.assertTrue(int.from_bytes(self.emu.mem_read(0x700, 4), 'little') & 8)
        self.emu.mem_write(0x700, (0xffffffff).to_bytes(4, 'little'))
        self.assertEqual(call(3), 0)
        self.assertEqual(self.emu.mem_read(0x700, 4), (0x200).to_bytes(4, 'little'))

    def test_wide_char_to_multi_byte_returns_real_byte_count(self):
        self.emu.mem_write(0x500, 'Coffee'.encode('utf-16le'))
        call = lambda capacity: self.api._wide_char_to_multi_byte(
            self.emu, 'api-ms-win-core-string-l1-1-0.WideCharToMultiByte',
            None, [437, 0, 0x500, 6, 0x600, capacity, 0, 0])
        self.assertEqual(call(0), 6)
        self.assertEqual(call(0x100000006), 6)
        self.assertEqual(self.emu.mem_read(0x600, 6), b'Coffee')
        self.assertEqual(call(2), 0)
        self.assertEqual(self.emu.last_error, 122)
        self.api.write_guard = lambda *_args: False
        self.assertEqual(call(6), 0)
        self.assertEqual(self.emu.last_error, 998)

    def test_api_set_presence_reads_counted_guest_namespace(self):
        name = 'ext-ms-win-fsutilext-ulib-l1-1-0'.encode('utf-16le')
        self.emu.mem_write(0x500, name)
        self.emu.mem_write(0x400, len(name).to_bytes(2, 'little') +
                           len(name).to_bytes(2, 'little') + b'\0' * 4 +
                           (0x500).to_bytes(8, 'little'))
        self.assertEqual(self.api._api_set_presence(
            self.emu, 'api-ms-win-core-apiquery-l1-1-0.ApiSetQueryApiSetPresence',
            None, [0x400, 0x600]), 0)
        self.assertEqual(self.emu.mem_read(0x600, 1), b'\x01')
        self.assertEqual(self.emu.last_error, 0)
        self.api.write_guard = lambda _emu, _address, _size: False
        self.assertEqual(self.api._api_set_presence(
            self.emu, 'api-ms-win-core-apiquery-l1-1-0.ApiSetQueryApiSetPresence',
            None, [0x400, 0x600]), 0xC000000D)
        self.assertEqual(self.emu.last_error, 87)

    def test_char_to_oem_a_copies_ascii_into_guest_buffer(self):
        self.emu.mem_write(0x500, b'Coffee\0')
        call = lambda: self.api._char_to_oem_a(
            self.emu, 'ext-ms-win-ntuser-chartranslation-l1-1-0.CharToOemA',
            None, [0x500, 0x600])
        self.assertEqual(call(), 1)
        self.assertEqual(self.emu.mem_read(0x600, 7), b'Coffee\0')
        self.api.write_guard = lambda _emu, _address, _size: False
        self.assertEqual(call(), 0)

    def test_compare_ascii_with_kana_and_width_flags(self):
        self.emu.memory[0x500:0x50a] = '/ALL\0'.encode('utf-16le')
        self.emu.memory[0x600:0x60a] = '/all\0'.encode('utf-16le')
        self.assertEqual(self.api._compare(
            self.emu, 'api-ms-win-core-string-l1-1-0.CompareStringW', None,
            [0x400, 0x30001, 0x500, -1, 0x600, -1]), 2)
        self.assertEqual(self.api._compare(
            self.emu, 'api-ms-win-core-string-l1-1-0.CompareStringW', None,
            [0x400, 0x30000, 0x500, -1, 0x600, -1]), 1)
        self.assertEqual(self.api._compare(
            self.emu, 'api-ms-win-core-string-l1-1-0.CompareStringW', None,
            [0x400, 0x40000, 0x500, -1, 0x600, -1]), 0)
        self.assertEqual(self.emu.last_error, 1004)

    def test_compare_string_api_set_is_registered(self):
        hooks = []
        class Registrar:
            def add_api_hook(self, _callback, module, name, **kwargs):
                hooks.append((module, name, kwargs['argc']))
        self.api.install(Registrar())
        self.assertIn(('api-ms-win-core-string-l1-1-0', 'CompareStringW', 6),
                      hooks)
        self.assertIn(('api-ms-win-core-libraryloader-l1-2-0',
                       'FindStringOrdinal', 6), hooks)
        self.assertIn(('msvcrt', 'wcsncmp', 3), hooks)
        self.assertIn(('api-ms-win-core-string-l2-1-0', 'CharUpperW', 1), hooks)

    def test_wcschr_returns_guest_pointer_including_terminator(self):
        self.assertEqual(self.api._wcschr(
            self.emu, 'ucrtbase.wcschr', None, [0x100, ord('B')]), 0x10a)
        self.assertEqual(self.api._wcschr(
            self.emu, 'ucrtbase.wcschr', None, [0x100, 0]), 0x112)
        self.assertEqual(self.api._wcschr(
            self.emu, 'ucrtbase.wcschr', None, [0x100, ord('Z')]), 0)

    def test_wcsncmp_stops_at_count_difference_or_terminator(self):
        self.emu.mem_write(0x500, 'ABx\0'.encode('utf-16le'))
        self.emu.mem_write(0x600, 'ABy\0'.encode('utf-16le'))
        call = lambda count: self.api._wcsncmp(
            self.emu, 'msvcrt.wcsncmp', None, [0x500, 0x600, count])
        self.assertEqual(call(0), 0)
        self.assertEqual(call(2), 0)
        self.assertLess(call(3), 0)
        self.assertGreater(self.api._wcsncmp(
            self.emu, 'msvcrt.wcsncmp', None, [0x600, 0x500, 3]), 0)
        self.emu.mem_write(0x600, 'AB\0'.encode('utf-16le'))
        self.assertGreater(call(4), 0)
        self.api.read_guard = lambda _emu, address, _size: address != 0x500
        self.assertEqual(call(1), 0)
        self.assertTrue(self.api.unsupported)

    def test_char_upper_w_changes_ascii_buffer_and_single_character(self):
        address = 0x10500
        self.emu.mem_write(address, 'Work\\notes.txt\0'.encode('utf-16le'))
        call = lambda: self.api._char_upper_w(
            self.emu, 'api-ms-win-core-string-l2-1-0.CharUpperW', None, [address])
        self.assertEqual(call(), address)
        self.assertEqual(self.api._read(self.emu, address, -1, True),
                         'WORK\\NOTES.TXT')
        self.assertEqual(self.api._char_upper_w(
            self.emu, 'user32.CharUpperW', None, [ord('z')]), ord('Z'))
        self.api.write_guard = lambda *_args: False
        self.emu.mem_write(address, 'more\0'.encode('utf-16le'))
        self.assertEqual(call(), address)
        self.assertEqual(self.api._read(self.emu, address, -1, True), 'more')
        self.assertTrue(self.api.unsupported)

    def test_report_does_not_treat_colon_text_as_signature(self):
        coverage = _api_coverage({'entry_points': [{'events': [
            {'event': 'api', 'api_name': 'kernel32.lstrlenW', 'args': ['ERROR: ']},
            {'event': 'api', 'api_name': 'msvcrt.fprintf',
             'args': ['INFO: Could not find files for the given pattern(s).']},
            {'event': 'api', 'api_name': 'advapi32.GetLengthSid',
             'args': ['pSid: 0x0']},
        ]}]})
        self.assertEqual(coverage['signature_only_calls'],
                         [{'api': 'advapi32.GetLengthSid', 'count': 1}])


if __name__ == '__main__':
    unittest.main()
