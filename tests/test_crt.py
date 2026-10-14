"""The old msvcrt stream array stays inside guest process memory."""

import struct
import unittest

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
                self.assertFalse(crt.unsupported)

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
