"""The old msvcrt stream array stays inside guest process memory."""

import struct
import unittest
from types import SimpleNamespace

from emumee.crt import LegacyCRTStreams, _legacy_iob_image
from emumee.virtualprocess import VirtualProcessBridge


class _Emulator:
    def __init__(self, pointer_size):
        self.pointer_size = pointer_size
        self.process = object()
        self.maps = []
        self.writes = []

    def get_current_process(self):
        return self.process

    def get_ptr_size(self):
        return self.pointer_size

    def mem_map(self, size, **kwargs):
        self.maps.append((size, kwargs))
        return 0x20000000 + len(self.maps) * 0x1000

    def mem_write(self, address, image):
        self.writes.append((address, image))


class LegacyCRTStreamsTests(unittest.TestCase):
    def test_wprintf_wide_and_narrow_strings_are_bounded(self):
        memory = {}
        def put(address, data):
            memory.update({address + index: byte for index, byte in enumerate(data)})
        put(0x1000, "Zone: %s / %S%%\n".encode("utf-16le") + b"\0\0")
        put(0x2000, "Eastern Standard Time".encode("utf-16le") + b"\0\0")
        put(0x3000, b"active\0")
        emu = SimpleNamespace(
            mem_read=lambda address, size: bytes(memory[address + index]
                                                 for index in range(size)),
            get_func_argv=lambda _conv, count: [0x1000, 0x2000, 0x3000][:count])
        crt = LegacyCRTStreams()
        output = []
        crt.console_write = lambda stream, rendered: output.append((stream, rendered))
        expected = "Zone: Eastern Standard Time / active%\n"
        self.assertEqual(crt._wprintf(emu, "msvcrt.wprintf", None, [0x1000]),
                         len(expected))
        self.assertEqual(output, [("stdout", expected)])
        put(0x1000, "%n".encode("utf-16le") + b"\0\0")
        self.assertEqual(crt._wprintf(emu, "msvcrt.wprintf", None, [0x1000]), -1)
        self.assertEqual(output, [("stdout", expected)])
        self.assertIn("unsupported wide format specifier", crt.unsupported[-1])

    def test_wcsupr_uppercases_guest_buffer_in_place_with_write_guard(self):
        emu = _Emulator(8)
        memory = {}
        emu.mem_write = lambda address, data: memory.update(
            {address + index: byte for index, byte in enumerate(data)})
        emu.mem_read = lambda address, size: bytes(
            memory[address + index] for index in range(size))
        emu.mem_write(0x1000, 'Coffeeß\0'.encode('utf-16le'))
        crt = LegacyCRTStreams()
        self.assertEqual(crt._wcsupr(emu, 'msvcrt._wcsupr', None, [0x1000]),
                         0x1000)
        self.assertEqual(emu.mem_read(0x1000, 16),
                         'COFFEEß\0'.encode('utf-16le'))
        crt.write_guard = lambda *_args: False
        self.assertEqual(crt._wcsupr(emu, 'msvcrt._wcsupr', None, [0x1000]), 0)

    def test_wcscspn_stops_at_first_rejected_guest_character(self):
        emu = _Emulator(8)
        memory = {}
        emu.mem_write = lambda address, data: memory.update(
            {address + index: byte for index, byte in enumerate(data)})
        emu.mem_read = lambda address, size: bytes(
            memory[address + index] for index in range(size))
        emu.mem_write(0x1000, 'Coffee/Tea\0'.encode('utf-16le'))
        emu.mem_write(0x2000, '/\\\0'.encode('utf-16le'))
        crt = LegacyCRTStreams()
        self.assertEqual(crt._wcscspn(emu, 'msvcrt.wcscspn', None,
                                      [0x1000, 0x2000]), 6)

    def test_strncpy_s_copies_and_terminates_bounded_guest_string(self):
        emu = _Emulator(8)
        memory = {}
        emu.mem_write = lambda address, data: memory.update(
            {address + index: byte for index, byte in enumerate(data)})
        emu.mem_read = lambda address, size: bytes(
            memory[address + index] for index in range(size))
        emu.mem_write(0x1000, b'Coffee beans\0')
        crt = LegacyCRTStreams()
        call = lambda cap, count: crt._strncpy_s(
            emu, 'msvcrt.strncpy_s', None, [0x2000, cap, 0x1000, count])
        self.assertEqual(call(32, 5), 0)
        self.assertEqual(emu.mem_read(0x2000, 6), b'Coffee'[:5] + b'\0')
        self.assertEqual(call(4, 5), 34)
        self.assertEqual(emu.mem_read(0x2000, 1), b'\0')
        self.assertEqual(call(4, (1 << 64) - 1), 80)
        self.assertEqual(emu.mem_read(0x2000, 4), b'Cof\0')
        crt.write_guard = lambda *_args: False
        self.assertEqual(call(32, 5), 22)

    def test_isatty_uses_guest_standard_handles(self):
        process = SimpleNamespace(get_std_handle=lambda value: {
            0xFFFFFFF6: 0xF001, 0xFFFFFFF5: 0xF002,
            0xFFFFFFF4: 0xBEEF}[value])
        emu = SimpleNamespace(get_current_process=lambda: process)
        crt = LegacyCRTStreams()
        call = lambda descriptor: crt._isatty(emu, 'msvcrt._isatty', None,
                                              [descriptor])
        self.assertEqual(call(0), 1)
        self.assertEqual(call(1), 1)
        self.assertEqual(call(2), 0)
        self.assertEqual(call(3), 0)

    def test_strcspn_stops_at_first_rejected_guest_byte(self):
        emu = _Emulator(8)
        memory = {}
        emu.mem_write = lambda address, data: memory.update(
            {address + index: byte for index, byte in enumerate(data)})
        emu.mem_read = lambda address, size: bytes(
            memory[address + index] for index in range(size))
        emu.mem_write(0x1000, b'Coffee\nMilk\0')
        emu.mem_write(0x1100, b'\r\n\0')
        crt = LegacyCRTStreams()
        self.assertEqual(crt._strcspn(emu, 'msvcrt.strcspn', None,
                                      [0x1000, 0x1100]), 6)

    def test_towupper_preserves_nonconvertible_code_units(self):
        crt = LegacyCRTStreams()
        call = lambda value: crt._towupper(None, 'msvcrt.towupper', None, [value])
        self.assertEqual(call(ord('a')), ord('A'))
        self.assertEqual(call(ord('Q')), ord('Q'))
        self.assertEqual(call(ord('ß')), ord('ß'))
        self.assertEqual(call(0xFFFF), 0xFFFF)

    def test_wcstok_splits_guest_buffer_and_scopes_continuation_to_thread(self):
        emu = _Emulator(8)
        memory = bytearray(0x4000)
        emu.mem_read = lambda address, size: bytes(memory[address:address + size])
        emu.mem_write = lambda address, data: memory.__setitem__(
            slice(address, address + len(data)), data)
        emu.get_address_map = lambda address: SimpleNamespace(
            base=0, size=len(memory), prot=6, free=False)
        first_thread, second_thread = object(), object()
        emu.get_current_thread = lambda: first_thread
        emu.mem_write(0x100, '  one two \0'.encode('utf-16le'))
        emu.mem_write(0x200, ' \0'.encode('utf-16le'))
        crt = LegacyCRTStreams()
        call = lambda source: crt._wcstok(emu, 'msvcrt.wcstok', None,
                                          [source, 0x200])
        self.assertEqual(call(0x100), 0x104)
        self.assertEqual(emu.mem_read(0x10a, 2), b'\0\0')
        emu.get_current_thread = lambda: second_thread
        self.assertEqual(call(0), 0)
        emu.get_current_thread = lambda: first_thread
        self.assertEqual(call(0), 0x10c)
        self.assertEqual(call(0), 0)
        self.assertEqual(crt.unsupported, [])

    def test_setlocale_uses_persona_and_process_owned_return_buffer(self):
        emu = _Emulator(8)
        memory = {}
        def put(address, data):
            for offset, byte in enumerate(data):
                memory[address + offset] = byte
        emu.mem_write = put
        emu.mem_read = lambda address, size: bytes(memory[address + index]
                                                    for index in range(size))
        put(0x1000, b'\0')
        put(0x1100, b'C\0')
        put(0x1200, b'xx-YY\0')
        crt = LegacyCRTStreams('de-DE')
        query = lambda category, pointer: crt._setlocale(
            emu, 'msvcrt.setlocale', None, [category, pointer])
        first = query(0, 0)
        self.assertEqual(emu.mem_read(first, 2), b'C\0')
        self.assertEqual(query(0, 0x1000), first)
        self.assertEqual(emu.mem_read(first, 6), b'de-DE\0')
        self.assertEqual(query(5, 0x1100), first)
        self.assertEqual(query(0, 0), first)
        prefix = b'LC_COLLATE=de-DE;LC_CTYPE=de-DE;'
        self.assertEqual(emu.mem_read(first, len(prefix)), prefix)
        self.assertEqual(query(0, 0x1200), 0)
        self.assertEqual(query(6, 0), 0)
        previous = emu.process
        emu.process = object()
        self.assertNotEqual(query(0, 0), first)
        crt.cleanup_process(previous)
        self.assertNotIn(id(previous), crt._locale_by_process)

    def test_wsetlocale_shares_categories_and_returns_wide_guest_string(self):
        emu = _Emulator(8)
        memory = {}
        emu.mem_write = lambda address, data: memory.update(
            {address + index: byte for index, byte in enumerate(data)})
        emu.mem_read = lambda address, size: bytes(
            memory[address + index] for index in range(size))
        emu.mem_write(0x1000, 'de-DE\0'.encode('utf-16le'))
        crt = LegacyCRTStreams('de-DE')
        wide = lambda category, pointer: crt._setlocale(
            emu, 'msvcrt._wsetlocale', None, [category, pointer])
        narrow = lambda category, pointer: crt._setlocale(
            emu, 'msvcrt.setlocale', None, [category, pointer])
        wide_ptr = wide(0, 0x1000)
        self.assertEqual(emu.mem_read(wide_ptr, 12), 'de-DE\0'.encode('utf-16le'))
        narrow_ptr = narrow(0, 0)
        self.assertNotEqual(wide_ptr, narrow_ptr)
        self.assertEqual(emu.mem_read(narrow_ptr, 6), b'de-DE\0')
        self.assertEqual(wide(0, 0), wide_ptr)
        emu.mem_write(0x1100, '.OCP\0'.encode('utf-16le'))
        self.assertEqual(wide(0, 0x1100), wide_ptr)
        emu.mem_write(0x1200, '.850\0'.encode('utf-16le'))
        crt.oem_code_page = 850
        self.assertEqual(wide(2, 0x1200), wide_ptr)

    def test_wcsspn_counts_only_leading_accepted_wide_units(self):
        emu = _Emulator(8)
        memory = {}
        emu.mem_write = lambda address, data: memory.update(
            {address + index: byte for index, byte in enumerate(data)})
        emu.mem_read = lambda address, size: bytes(
            memory[address + index] for index in range(size))
        emu.mem_write(0x1000, '  /name\0'.encode('utf-16le'))
        emu.mem_write(0x1100, ' /\0'.encode('utf-16le'))
        crt = LegacyCRTStreams()
        self.assertEqual(crt._wcsspn(emu, 'msvcrt.wcsspn', None,
                                     [0x1000, 0x1100]), 3)

    def test_swprintf_s_formats_bounded_wide_decimal(self):
        emu = _Emulator(8)
        memory = {}
        emu.mem_write = lambda address, data: memory.update(
            {address + index: byte for index, byte in enumerate(data)})
        emu.mem_read = lambda address, size: bytes(
            memory[address + index] for index in range(size))
        emu.get_address_map = lambda address: SimpleNamespace(
            base=0, size=0x100000000, prot=6, free=False)
        emu.get_func_argv = lambda _conv, count: [0x3000, 8, 0x2000, 25][:count]
        emu.mem_free = lambda _address: None
        emu.mem_write(0x2000, '.%d\0'.encode('utf-16le'))
        crt = LegacyCRTStreams()
        self.assertEqual(crt._swprintf_s(emu, 'msvcrt.swprintf_s', None,
                                         [0x3000, 8, 0x2000]), 3, crt.unsupported)
        self.assertEqual(emu.mem_read(0x3000, 8), '.25\0'.encode('utf-16le'))
        self.assertEqual(crt.unsupported, [])

    def test_snwprintf_s_accepts_truncate_sentinel_and_stack_argument(self):
        emu = _Emulator(8)
        memory = {}
        emu.mem_write = lambda address, data: memory.update(
            {address + index: byte for index, byte in enumerate(data)})
        emu.mem_read = lambda address, size: bytes(
            memory[address + index] for index in range(size))
        emu.get_address_map = lambda address: SimpleNamespace(
            base=0, size=0x100000000, prot=6, free=False)
        emu.get_func_argv = lambda _conv, count: [
            0x3000, 12, (1 << 64) - 1, 0x2000, 437][:count]
        emu.mem_free = lambda _address: None
        emu.mem_write(0x2000, '.%d\0'.encode('utf-16le'))
        crt = LegacyCRTStreams()
        self.assertEqual(crt._snwprintf_s(emu, 'msvcrt._snwprintf_s', None,
                                          [0x3000, 12, (1 << 64) - 1, 0x2000]), 4,
                         crt.unsupported)
        self.assertEqual(emu.mem_read(0x3000, 10), '.437\0'.encode('utf-16le'))
        self.assertEqual(crt._snwprintf_s(emu, 'msvcrt._snwprintf_s', None,
                                          [0x3000, 4, (1 << 64) - 1, 0x2000]), -1)
        self.assertEqual(emu.mem_read(0x3000, 8), '.43\0'.encode('utf-16le'))

    def test_private_crt_exit_records_guest_status_and_stops(self):
        process = SimpleNamespace(pid=1234)
        stopped = []
        emu = SimpleNamespace(get_current_process=lambda: process,
                              get_current_thread=lambda: None,
                              exit_process=lambda: stopped.append(True))
        bridge = VirtualProcessBridge(None)
        cleaned = []
        bridge._cleanup_process = lambda _emu, candidate: cleaned.append(candidate)
        bridge._crt_exit(emu, "api-ms-win-crt-private-l1-1-0._o_exit", None, [7])
        self.assertEqual(bridge.process_exit_codes[id(process)], 7)
        self.assertEqual(cleaned, [process])
        self.assertEqual(stopped, [True])

    def test_errno_storage_is_stable_per_guest_thread_and_process(self):
        emu = _Emulator(8)
        first_thread, second_thread = object(), object()
        emu.get_current_thread = lambda: first_thread
        crt = LegacyCRTStreams()
        name = 'api-ms-win-crt-private-l1-1-0._o__errno'
        first = crt._errno(emu, name, None, [])
        self.assertEqual(crt._errno(emu, name, None, []), first)
        self.assertEqual(emu.writes[-1], (first, b'\0' * 4))
        emu.get_current_thread = lambda: second_thread
        self.assertNotEqual(crt._errno(emu, name, None, []), first)
        previous = emu.process
        emu.process = object()
        self.assertNotEqual(crt._errno(emu, name, None, []), first)
        crt.cleanup_process(previous)
        self.assertTrue(all(key[0] != id(previous) for key in crt._errno_by_thread))

    def test_ultow_bounded_guest_destination_and_radix(self):
        emu = _Emulator(8)
        emu.get_address_map = lambda address: SimpleNamespace(
            base=0x1000, size=0x100, prot=6, free=False) if 0x1000 <= address < 0x1100 else None
        crt = LegacyCRTStreams()
        self.assertEqual(crt._ultow(emu, "msvcrt._ultow", None,
                                    [0xFFFFFFFF, 0x1000, 10]), 0x1000)
        self.assertEqual(emu.writes[-1], (0x1000, "4294967295\0".encode("utf-16le")))
        self.assertEqual(crt._ultow(emu, "msvcrt._ultow", None,
                                    [255, 0x1080, 16]), 0x1080)
        self.assertEqual(emu.writes[-1], (0x1080, "ff\0".encode("utf-16le")))
        count = len(emu.writes)
        self.assertEqual(crt._ultow(emu, "msvcrt._ultow", None,
                                    [0xFFFFFFFF, 0x10f0, 2]), 0)
        self.assertEqual(crt._ultow(emu, "msvcrt._ultow", None,
                                    [5, 0x1000, 1]), 0)
        self.assertEqual(len(emu.writes), count)

    def test_character_search_returns_guest_pointer_or_null(self):
        emu = _Emulator(8)
        memory = {}
        for offset, byte in enumerate('ab.ba\0'.encode('utf-16le')):
            memory[0x1000 + offset] = byte
        emu.mem_read = lambda address, size: bytes(memory[address + i]
                                                    for i in range(size))
        crt = LegacyCRTStreams()
        self.assertEqual(crt._find_character(emu, 'msvcrt.wcschr', None,
                                              [0x1000, ord('b')]), 0x1002)
        self.assertEqual(crt._find_character(emu, 'msvcrt.wcsrchr', None,
                                              [0x1000, ord('b')]), 0x1006)
        self.assertEqual(crt._find_character(emu, 'msvcrt.wcschr', None,
                                              [0x1000, ord('z')]), 0)
        self.assertEqual(crt._find_character(emu, 'msvcrt.wcschr', None,
                                              [0x1000, 0]), 0x100a)
        narrow = b'ab.ba\0'
        emu.mem_read = lambda address, size: narrow[address - 0x2000:
                                                     address - 0x2000 + size]
        self.assertEqual(crt._find_character(emu, 'msvcrt.strchr', None,
                                              [0x2000, ord('b')]), 0x2001)
        self.assertEqual(crt._find_character(emu, 'msvcrt.strrchr', None,
                                              [0x2000, ord('b')]), 0x2003)
        self.assertFalse(crt.unsupported)

    def test_setmode_tracks_each_standard_descriptor_per_process(self):
        emu = _Emulator(8)
        crt = LegacyCRTStreams()
        self.assertEqual(crt._setmode(emu, 'msvcrt._setmode', None,
                                      [1, 0x20000]), 0x4000)
        self.assertEqual(crt._setmode(emu, 'msvcrt._setmode', None,
                                      [1, 0x4000]), 0x20000)
        self.assertEqual(crt._setmode(emu, 'msvcrt._setmode', None,
                                      [2, 0x4000]), 0x4000)
        emu.process = object()
        self.assertEqual(crt._setmode(emu, 'msvcrt._setmode', None,
                                      [1, 0x8000]), 0x4000)
        self.assertEqual(crt._setmode(emu, 'msvcrt._setmode', None,
                                      [9, 0x4000]), -1)
        self.assertEqual(len(crt.unsupported), 1)
        crt.cleanup_process(emu.process)
        self.assertEqual(crt._setmode(emu, 'msvcrt._setmode', None,
                                      [1, 0x4000]), 0x4000)

    def test_write_descriptor_captures_guest_standard_stream_bytes(self):
        emu = _Emulator(8)
        memory = b'DESKTOP-Q3R8V2A\n'
        emu.mem_read = lambda address, size: memory[address - 0x1000:
                                                    address - 0x1000 + size]
        captured = []
        crt = LegacyCRTStreams()
        crt.console_write = lambda stream, content: captured.append((stream, content))
        self.assertEqual(crt._write_descriptor(emu, 'msvcrt._write', None,
                                                [1, 0x1000, len(memory)]), len(memory))
        self.assertEqual(captured, [('stdout', 'DESKTOP-Q3R8V2A\n')])
        self.assertEqual(crt._write_descriptor(emu, 'msvcrt._write', None,
                                                [9, 0x1000, len(memory)]), -1)
        self.assertEqual(len(captured), 1)
        emu.mem_read = lambda _address, _size: b'\x80'
        self.assertEqual(crt._write_descriptor(emu, 'msvcrt._write', None,
                                                [1, 0x1000, 1]), -1)
        self.assertEqual(len(captured), 1)

    def test_stream_layout_and_process_ownership(self):
        for width, stride, flag_offset, file_offset in ((4, 32, 12, 16),
                                                        (8, 48, 24, 28)):
            with self.subTest(pointer_size=width):
                emu = _Emulator(width)
                crt = LegacyCRTStreams()
                first = crt._iob_func(emu, "msvcrt.__iob_func", None, [])
                self.assertEqual(crt._iob_func(emu, "msvcrt.__iob_func", None, []),
                                 first)
                self.assertEqual(len(emu.maps), 1)
                self.assertIs(emu.maps[0][1]["process"], emu.process)
                self.assertEqual(emu.writes[0][0], first)
                image = emu.writes[0][1]
                self.assertEqual(image, _legacy_iob_image(width))
                self.assertEqual(len(image), stride * 20)
                for index, flag in enumerate((1, 2, 2)):
                    self.assertEqual(struct.unpack_from(
                        "<I", image, index * stride + flag_offset)[0], flag)
                    self.assertEqual(struct.unpack_from(
                        "<I", image, index * stride + file_offset)[0], index)
                self.assertFalse(any(image[stride * 3:]))
                for index in range(3):
                    self.assertEqual(crt._fileno(
                        emu, "msvcrt._fileno", None,
                        [first + index * stride]), index)
                self.assertEqual(crt._fileno(
                    emu, "msvcrt._fileno", None, [0]), -1)
                self.assertFalse(crt.unsupported)
                emu.process = object()
                self.assertNotEqual(crt._iob_func(
                    emu, "msvcrt.__iob_func", None, []), first)
                self.assertEqual(len(emu.maps), 2)
                self.assertEqual(crt._fileno(
                    emu, "msvcrt._fileno", None, [first]), -1)
                self.assertEqual(len(crt.unsupported), 1)

    def test_no_current_process_returns_null_without_mapping(self):
        emu = _Emulator(4)
        emu.process = None
        self.assertEqual(LegacyCRTStreams()._iob_func(
            emu, "msvcrt.__iob_func", None, []), 0)
        self.assertFalse(emu.maps)

    def test_ucrt_stream_pointers_are_guest_owned_and_stable(self):
        for width in (4, 8):
            with self.subTest(pointer_size=width):
                emu = _Emulator(width)
                crt = LegacyCRTStreams()
                pointers = [crt._acrt_iob_func(
                    emu, "ucrtbase.__acrt_iob_func", None, [index])
                    for index in range(3)]
                self.assertEqual(pointers, [pointers[0] + index * 0x80
                                            for index in range(3)])
                self.assertEqual(len(emu.maps), 1)
                self.assertIs(emu.maps[0][1]["process"], emu.process)
                self.assertEqual(emu.writes[0][0], pointers[0])
                self.assertEqual(emu.writes[0][1], b"\0" * (0x80 * 3))
                for index, pointer in enumerate(pointers):
                    self.assertEqual(crt._fileno(emu, "msvcrt._fileno", None,
                                                 [pointer]), index)
                self.assertEqual(crt._acrt_iob_func(
                    emu, "ucrtbase.__acrt_iob_func", None, [2]), pointers[2])
                self.assertEqual(crt._acrt_iob_func(
                    emu, "ucrtbase.__acrt_iob_func", None, [4]), 0)
                emu.process = object()
                self.assertEqual(crt._fileno(emu, "msvcrt._fileno", None,
                                             [pointers[1]]), -1)

    def test_memicmp_compares_exact_count_and_ascii_case(self):
        bridge = VirtualProcessBridge(None)
        bridge._owner_conflict = lambda *_args: False
        process = object()
        memory = {0x1000: b"Ab\0d", 0x2000: b"aB\0E"}
        class Reader:
            def get_current_process(self):
                return process

            def mem_read(self, address, count):
                for base, data in memory.items():
                    if base <= address <= base + len(data) - count:
                        return data[address - base:address - base + count]
                raise ValueError("unmapped guest memory")

        emu = Reader()
        self.assertEqual(bridge._bulk_memory_api(
            emu, "msvcrt._memicmp", None, [0x1000, 0x2000, 3]), 0)
        self.assertLess(bridge._bulk_memory_api(
            emu, "msvcrt._memicmp", None, [0x1000, 0x2000, 4]), 0)
        self.assertEqual(bridge._bulk_memory_api(
            emu, "msvcrt._memicmp", None, [0, 0, 0]), 0)
        self.assertEqual(bridge._bulk_memory_api(
            emu, "api-ms-win-crt-private-l1-1-0._o__memicmp", None,
            [0x1000, 0x2000, 3]), 0)

    def test_vsnwprintf_reads_guest_varargs_and_honors_count(self):
        for width in (4, 8):
            with self.subTest(pointer_size=width):
                emu = _Emulator(width)
                memory = {}
                def put(address, data):
                    for index, byte in enumerate(data):
                        memory[address + index] = byte
                def read(address, size):
                    return bytes(memory[address + index] for index in range(size))
                def write(address, data):
                    put(address, data)
                emu.mem_read = read
                emu.mem_write = write
                put(0x1000, "%s %d".encode("utf-16le") + b"\0\0")
                put(0x2000, "Test".encode("utf-16le") + b"\0\0")
                put(0x3000, (0x2000).to_bytes(width, "little") +
                    (42).to_bytes(width, "little"))
                crt = LegacyCRTStreams()
                self.assertEqual(crt._vsnwprintf(
                    emu, "msvcrt._vsnwprintf", None,
                    [0x4000, 16, 0x1000, 0x3000]), 7)
                self.assertEqual(read(0x4000, 16).decode("utf-16le"), "Test 42\0")
                self.assertEqual(crt._vsnwprintf(
                    emu, "msvcrt._vsnwprintf", None,
                    [0x5000, 4, 0x1000, 0x3000]), -1)
                self.assertEqual(read(0x5000, 8).decode("utf-16le"), "Test")
                self.assertEqual(crt._stdio_common_vswprintf(
                    emu, "api-ms-win-crt-private-l1-1-0._o___stdio_common_vswprintf",
                    None, [0, 0x6000, 16, 0x1000, 0, 0x3000]), 7)
                self.assertEqual(read(0x6000, 16).decode("utf-16le"), "Test 42\0")
                put(0x1000, "%*s".encode("utf-16le") + b"\0\0")
                put(0x3000, (6).to_bytes(width, "little") +
                    (0x2000).to_bytes(width, "little"))
                self.assertEqual(crt._vsnwprintf(
                    emu, "msvcrt._vsnwprintf", None,
                    [0x7000, 10, 0x1000, 0x3000]), 6)
                self.assertEqual(read(0x7000, 14).decode("utf-16le"), "  Test\0")
                self.assertFalse(crt.unsupported)

    def test_private_ucrt_stream_alias_is_registered(self):
        hooks = {}
        class Registrar:
            def add_api_hook(self, callback, module, name, **kwargs):
                hooks[(module, name)] = callback.__name__
        LegacyCRTStreams().install(Registrar())
        self.assertEqual(hooks[("api-ms-win-crt-private-l1-1-0",
                                "_o___acrt_iob_func")], "_acrt_iob_func")
        self.assertEqual(hooks[("api-ms-win-crt-private-l1-1-0",
                                "_o__fileno")], "_fileno")
        self.assertEqual(hooks[("api-ms-win-crt-private-l1-1-0",
                                "_o__write")], "_write_descriptor")
        self.assertEqual(hooks[("api-ms-win-crt-private-l1-1-0",
                                "_o_fflush")], "_fflush")
        self.assertEqual(hooks[("api-ms-win-crt-private-l1-1-0",
                                "_o___stdio_common_vfprintf")],
                         "_stdio_common_vfprintf")

    def test_ucrt_vfprintf_formats_bounded_guest_ascii(self):
        emu = _Emulator(8)
        memory = {}
        def put(address, data):
            for index, byte in enumerate(data):
                memory[address + index] = byte
        emu.mem_read = lambda address, size: bytes(memory[address + i]
                                                    for i in range(size))
        original_write = emu.mem_write
        def write(address, data):
            original_write(address, data)
            put(address, data)
        emu.mem_write = write
        put(0x1000, b'%s %d\n\0')
        put(0x2000, b'value\0')
        put(0x3000, (0x2000).to_bytes(8, 'little') +
            (42).to_bytes(8, 'little'))
        output = []
        crt = LegacyCRTStreams()
        crt.console_write = lambda stream, text: output.append((stream, text))
        stderr = crt._acrt_iob_func(emu, 'ucrtbase.__acrt_iob_func', None, [2])
        self.assertEqual(crt._stdio_common_vfprintf(
            emu, 'api-ms-win-crt-private-l1-1-0._o___stdio_common_vfprintf',
            None, [0, stderr, 0x1000, 0, 0x3000]), 9)
        self.assertEqual(output, [('stderr', 'value 42\n')])
        put(0x1000, b'%*s|%-*s\0')
        put(0x3000, (7).to_bytes(8, 'little') +
            (0x2000).to_bytes(8, 'little') +
            (7).to_bytes(8, 'little') +
            (0x2000).to_bytes(8, 'little'))
        self.assertEqual(crt._stdio_common_vfprintf(
            emu, 'ucrtbase.__stdio_common_vfprintf', None,
            [0, stderr, 0x1000, 0, 0x3000]), 15)
        self.assertEqual(output[-1], ('stderr', '  value|value  '))
        put(0x1000, b'%n\0')
        self.assertEqual(crt._stdio_common_vfprintf(
            emu, 'ucrtbase.__stdio_common_vfprintf', None,
            [0, stderr, 0x1000, 0, 0x3000]), -1)
        self.assertEqual(len(output), 2)

    def test_x86_ucrt_formatters_read_split_64_bit_options(self):
        emu = _Emulator(4)
        memory = {}
        def put(address, data):
            for index, byte in enumerate(data):
                memory[address + index] = byte
        emu.mem_read = lambda address, size: bytes(memory[address + i]
                                                    for i in range(size))
        emu.mem_write = put
        put(0x1000, "%s".encode("utf-16le") + b"\0\0")
        put(0x1100, b'%s\0')
        put(0x2000, "Test".encode("utf-16le") + b"\0\0")
        put(0x2100, b'Test\0')
        put(0x3000, (0x2000).to_bytes(4, 'little'))
        put(0x3100, (0x2100).to_bytes(4, 'little'))
        crt = LegacyCRTStreams()
        emu.get_func_argv = lambda _conv, count: (
            [1, 0, 0x4000, 8, 0x1000, 0, 0x3000] if count == 7
            else [0, 0, crt._acrt_iob_func(emu, 'ucrtbase.__acrt_iob_func',
                                           None, [1]), 0x1100, 0, 0x3100])
        self.assertEqual(crt._stdio_common_vswprintf(
            emu, 'api-ms-win-crt-private-l1-1-0._o___stdio_common_vswprintf',
            None, [1, 0, 0x4000, 8, 0x1000, 0]), 4)
        self.assertEqual(bytes(memory[0x4000 + i] for i in range(10)),
                         "Test\0".encode("utf-16le"))
        written = []
        crt.console_write = lambda stream, text: written.append((stream, text))
        self.assertEqual(crt._stdio_common_vfprintf(
            emu, 'api-ms-win-crt-private-l1-1-0._o___stdio_common_vfprintf',
            None, [0, 0, 0, 0x1100, 0]), 4)
        self.assertEqual(written, [('stdout', 'Test')])

    def test_vsnwprintf_rejects_unmodeled_format(self):
        emu = _Emulator(4)
        fmt = b"%\0n\0\0\0"
        emu.mem_read = lambda address, size: fmt[address - 0x1000:address - 0x1000 + size]
        crt = LegacyCRTStreams()
        self.assertEqual(crt._vsnwprintf(
            emu, "msvcrt._vsnwprintf", None,
            [0x4000, 8, 0x1000, 0x3000]), -1)
        self.assertIn("unsupported", crt.unsupported[0])

    def test_get_osfhandle_uses_guest_console_handles(self):
        emu = _Emulator(8)
        class Process:
            def get_std_handle(self, which):
                return {0xFFFFFFF6: 0xF001,
                        0xFFFFFFF5: 0xF002,
                        0xFFFFFFF4: 0xF003}[which]
        emu.process = Process()
        crt = LegacyCRTStreams()
        for descriptor in range(3):
            self.assertEqual(crt._get_osfhandle(
                emu, "msvcrt._get_osfhandle", None, [descriptor]),
                0xF001 + descriptor)
        self.assertFalse(crt.unsupported)
        self.assertEqual(crt._get_osfhandle(
            emu, "msvcrt._get_osfhandle", None, [17]), -1)
        self.assertEqual(len(crt.unsupported), 1)

    def test_fprintf_and_fflush_capture_standard_stream(self):
        emu = _Emulator(4)
        crt = LegacyCRTStreams()
        base = crt._iob_func(emu, "msvcrt.__iob_func", None, [])
        observed = []
        crt.console_write = lambda stream, value: observed.append((stream, value))
        args = []  # Speakeasy's x86 VAR_ARGS profile supplies an empty list.
        emu.get_func_argv = lambda _conv, _count: [base + 64, 0x7000]
        def formatted(params):
            params[:] = [base + 64, "example\n"]
            return 8
        self.assertEqual(crt._fprintf(emu, "msvcrt.fprintf", formatted, args), 8)
        self.assertEqual(observed, [("stderr", "example\n")])
        self.assertEqual(crt._fflush(emu, "msvcrt.fflush", None, [base + 64]), 0)
        self.assertEqual(crt._fflush(emu, "msvcrt.fflush", None, [0]), 0)
        self.assertFalse(crt.unsupported)
