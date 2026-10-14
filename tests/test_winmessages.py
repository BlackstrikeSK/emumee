"""Reference and boundary checks for modeled Windows message formatting."""

from __future__ import annotations

import ctypes
import struct
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import speakeasy.common as common

from emumee.winmessages import (FORMAT_MESSAGE_ALLOCATE_BUFFER,
                                FORMAT_MESSAGE_FROM_STRING,
                                FORMAT_MESSAGE_FROM_SYSTEM,
                                FORMAT_MESSAGE_IGNORE_INSERTS, WinMessages)


class _GuestMemory:
    def __init__(self, ptr_size=8):
        self.ptr_size = ptr_size
        self.blocks = {0x1000: bytearray(4096)}
        self.last_error = 12345
        self.api = self
        self.next_alloc = 0x3000
        self.modules = []

    def get_ptr_size(self):
        return self.ptr_size

    def get_current_process(self):
        return SimpleNamespace(base=0x400000)

    def get_mod_from_addr(self, address):
        return next((module for module in self.modules
                     if module.base == address), None)

    def get_address_map(self, address):
        for base, block in self.blocks.items():
            if base <= address < base + len(block):
                return SimpleNamespace(base=base, size=len(block), free=False,
                                       prot=common.PERM_MEM_RW)
        return None

    def set_last_error(self, code):
        self.last_error = code

    def access(self, _emu, address, size):
        return any(base <= address and address + size <= base + len(block)
                   for base, block in self.blocks.items())

    def _span(self, address, size):
        for base, block in self.blocks.items():
            if base <= address and address + size <= base + len(block):
                return block, address - base
        raise ValueError("guest memory outside mapped block")

    def mem_write(self, address, data):
        block, offset = self._span(address, len(data))
        block[offset:offset + len(data)] = data

    def mem_read(self, address, size):
        block, offset = self._span(address, size)
        return bytes(block[offset:offset + size])

    def load_api_handler(self, name):
        assert name == "kernel32"
        return self

    def LocalAlloc(self, _emu, params):
        assert params[0] == 0
        address = self.next_alloc
        self.next_alloc += 0x10000
        self.blocks[address] = bytearray(params[1])
        return address

    def mem_map(self, size, **_kwargs):
        return self.LocalAlloc(self, [0, size])

    def mem_free(self, address):
        self.blocks.pop(address)

    def LocalFree(self, _emu, params):
        self.mem_free(params[0])
        return 0


class WinMessageTests(unittest.TestCase):
    def setUp(self):
        self.guest = _GuestMemory()
        self.messages = WinMessages()
        self.messages.read_guard = self.guest.access
        self.messages.write_guard = self.guest.access

    def test_libraryloader_loadstring_alias_is_registered(self):
        hooks = {}
        class Registrar:
            def add_api_hook(self, callback, module, name, **kwargs):
                hooks[(module, name)] = (callback.__name__, kwargs["argc"])
        self.messages.install(Registrar())
        self.assertEqual(hooks[("api-ms-win-core-libraryloader-l1-2-0",
                                "LoadStringW")], hooks[("user32", "LoadStringW")])
        self.assertEqual(hooks[("api-ms-win-core-localization-l1-2-0",
                                "FormatMessageW")],
                         hooks[("kernel32", "FormatMessageW")])

    def format(self, flags, source=0, message_id=0, language=0,
               output=0x1000, capacity=256, arguments=0):
        return self.messages._format_w(self.guest, "kernel32.FormatMessageW", None,
                                       [flags, source, message_id, language,
                                        output, capacity, arguments])

    def test_common_system_messages_match_windows_reference(self):
        native = ctypes.WinDLL("kernel32", use_last_error=True).FormatMessageW
        native.argtypes = [ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32,
                           ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32,
                           ctypes.c_void_p]
        native.restype = ctypes.c_uint32
        for code in (0, 5, 87):
            with self.subTest(code=code):
                reference = ctypes.create_unicode_buffer(256)
                length = native(FORMAT_MESSAGE_FROM_SYSTEM |
                                FORMAT_MESSAGE_IGNORE_INSERTS, None, code,
                                0x0409, ctypes.cast(reference, ctypes.c_void_p), 256, None)
                self.assertGreater(length, 0)
                actual = self.format(FORMAT_MESSAGE_FROM_SYSTEM |
                                     FORMAT_MESSAGE_IGNORE_INSERTS, message_id=code,
                                     language=0x0409)
                self.assertEqual(actual, length)
                self.assertEqual(self.guest.mem_read(0x1000, (actual + 1) * 2)
                                 .decode("utf-16le").rstrip("\0"), reference.value)
                self.assertEqual(self.guest.last_error, 12345)

    def test_allocate_buffer_writes_guest_pointer_and_localfree_releases_it(self):
        self.guest.ptr_size = 4
        length = self.format(FORMAT_MESSAGE_ALLOCATE_BUFFER |
                             FORMAT_MESSAGE_FROM_SYSTEM |
                             FORMAT_MESSAGE_IGNORE_INSERTS,
                             message_id=5, capacity=0)
        self.assertEqual(length, len("Access is denied.\r\n"))
        address = struct.unpack("<I", self.guest.mem_read(0x1000, 4))[0]
        self.assertEqual(self.guest.mem_read(address, (length + 1) * 2)
                         .decode("utf-16le"), "Access is denied.\r\n\0")
        self.guest.LocalFree(self.guest, [address])
        self.assertNotIn(address, self.guest.blocks)

    def test_bounded_from_string_and_small_buffer(self):
        self.guest.mem_write(0x1400, "hello%nworld\0".encode("utf-16le"))
        length = self.format(FORMAT_MESSAGE_FROM_STRING |
                             FORMAT_MESSAGE_IGNORE_INSERTS, source=0x1400,
                             capacity=6)
        self.assertEqual(length, 0)
        self.assertEqual(self.guest.last_error, 122)
        self.assertEqual(self.guest.mem_read(0x1000, 12).decode("utf-16le"), "hello\0")
        self.assertEqual(self.format(FORMAT_MESSAGE_FROM_STRING |
                                     FORMAT_MESSAGE_IGNORE_INSERTS, source=0x1400), 12)
        self.assertEqual(self.guest.mem_read(0x1000, 26).decode("utf-16le"),
                         "hello\r\nworld\0")

    def test_cross_process_write_and_unknown_message_fail_without_host_access(self):
        self.messages.write_guard = lambda _emu, _address, _size: False
        self.assertEqual(self.format(FORMAT_MESSAGE_FROM_SYSTEM, message_id=5), 0)
        self.assertEqual(self.guest.last_error, 87)
        self.messages.write_guard = self.guest.access
        self.assertEqual(self.format(FORMAT_MESSAGE_FROM_SYSTEM, message_id=0xFFFF), 0)
        self.assertEqual(self.guest.last_error, 317)
        self.assertEqual(len(self.messages.unsupported), 1)

    def test_unmapped_allocated_output_pointer_is_rejected_before_allocating(self):
        self.assertEqual(self.messages._format_w(
            self.guest, "kernel32.FormatMessageW", None,
            [FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
             0, 5, 0, 0xFFFFFFFFFFFFFFFF, 0, 0]), 0)
        self.assertEqual(self.guest.last_error, 87)
        self.assertEqual(self.guest.next_alloc, 0x3000)

    def test_load_string_w_copies_character_count_and_reports_missing_mui(self):
        metadata = SimpleNamespace(string_table={7: "abc"},
                                   resources=[SimpleNamespace(type_id="MUI")])
        self.guest.modules = [SimpleNamespace(
            base=0x400000, name="fixture.exe",
            get_pe_metadata=lambda: metadata)]
        result = self.messages._load_string_w(
            self.guest, "user32.LoadStringW", None, [0, 7, 0x1000, 3])
        self.assertEqual(result, 2)
        self.assertEqual(self.guest.mem_read(0x1000, 6), "ab\0".encode("utf-16le"))
        self.assertEqual(self.messages._load_string_w(
            self.guest, "user32.LoadStringW", None, [0, 5001, 0x1000, 10]), 0)
        self.assertIn("external MUI string 0x1389", self.messages.unsupported[0])

    def test_load_string_w_reads_only_explicit_guest_mui(self):
        metadata = SimpleNamespace(string_table={},
                                   resources=[SimpleNamespace(type_id="MUI")])
        self.guest.modules = [SimpleNamespace(
            base=0x400000, name="fixture",
            get_pe_metadata=lambda: metadata)]
        self.messages.current_dir = r"C:\samples"
        self.messages.guest_images = {
            r"c:\samples\fixture.exe": b"guest exe",
            r"c:\samples\en-us\fixture.exe.mui": b"guest MUI",
        }
        with patch("emumee.winmessages.mui_string", return_value="Guest text") as read:
            result = self.messages._load_string_w(
                self.guest, "user32.LoadStringW", None,
                [0, 5001, 0x1000, 32])
        self.assertEqual(result, len("Guest text"))
        self.assertEqual(self.guest.mem_read(0x1000, 22),
                         "Guest text\0".encode("utf-16le"))
        read.assert_called_once_with(b"guest MUI", 5001)
        self.assertFalse(self.messages.unsupported)


if __name__ == "__main__":
    unittest.main()
