"""Manifest-conditioned Win32 version and bounded resource checks."""

from __future__ import annotations

import struct
import unittest
from pathlib import Path
from types import SimpleNamespace

from emumee.cpu import VirtualCPU
from emumee.persona import load_persona
from emumee.version_compat import manifest_compatibility
from emumee.version_verify import (STATUS_INVALID_PARAMETER,
                                   STATUS_REVISION_MISMATCH, actual_version,
                                   matches_version, set_condition)


FIXTURES = Path(__file__).parent / "fixtures"


class GuestMemory:
    def __init__(self, process, ptr_size=8):
        self.process = process
        self.ptr_size = ptr_size
        self.blocks = {}
        self.errors = []

    def get_current_process(self):
        return self.process

    def get_ptr_size(self):
        return self.ptr_size

    def mem_read(self, address, size):
        return self.blocks[address][:size]

    def mem_write(self, address, data):
        self.blocks[address] = data

    def set_last_error(self, value):
        self.errors.append(value)


class VersionCompatibilityTests(unittest.TestCase):
    @staticmethod
    def version_request(major=10, minor=0, build=22631, *, wide=True):
        data = bytearray(284 if wide else 156)
        struct.pack_into("<IIIII", data, 0, len(data), major, minor, build, 2)
        data[282 if wide else 154] = 1
        return bytes(data)

    def test_manifest_resources_select_supported_windows_version(self):
        for arch in ("x86", "x64"):
            for compatibility in ("none", "win81", "win10"):
                with self.subTest(arch=arch, compatibility=compatibility):
                    image = (FIXTURES / f"version_compat_{compatibility}_{arch}.exe").read_bytes()
                    self.assertEqual(manifest_compatibility(image), compatibility)

    def test_invalid_resource_bounds_cannot_claim_compatibility(self):
        image = bytearray((FIXTURES / "version_compat_win10_x64.exe").read_bytes())
        for offset, value in ((0x800 + 14, 0xFFFF), (0x848 + 4, 0xFFFFFFFF)):
            with self.subTest(offset=offset):
                mutated = bytearray(image)
                struct.pack_into("<I" if offset == 0x84C else "<H",
                                 mutated, offset, value)
                self.assertEqual(manifest_compatibility(bytes(mutated)), "none")

    def test_version_queries_follow_each_guest_process(self):
        cpu = VirtualCPU(load_persona(None))
        primary = SimpleNamespace(base=0x140000000)
        child = SimpleNamespace(base=0x150000000)
        other = SimpleNamespace(base=0x160000000)
        primary_image = (FIXTURES / "version_compat_win10_x64.exe").read_bytes()
        child_image = (FIXTURES / "version_compat_win81_x64.exe").read_bytes()
        cpu.register_primary_image(primary.base, primary_image)
        cpu.register_child_image(child, child_image)
        memory = GuestMemory(primary)
        self.assertEqual(cpu._get_version(memory, "", None, []),
                         (22631 << 16) | 10)
        memory.process = child
        self.assertEqual(cpu._get_version(memory, "", None, []),
                         (9600 << 16) | (3 << 8) | 6)
        memory.blocks[0x1000] = struct.pack("<I", 156)
        self.assertEqual(cpu._get_version_ex(memory, "kernel32.GetVersionExA",
                                              None, [0x1000]), 1)
        self.assertEqual(struct.unpack_from("<IIIII", memory.blocks[0x1000]),
                         (156, 6, 3, 9600, 2))
        self.assertEqual(memory.blocks[0x1000][154], 1)
        memory.process = other
        self.assertEqual(cpu._get_version(memory, "", None, []),
                         (9200 << 16) | (2 << 8) | 6)
        memory.blocks[0x1000] = struct.pack("<I", 1)
        self.assertEqual(cpu._get_version_ex(memory, "kernel32.GetVersionExW",
                                              None, [0x1000]), 0)
        self.assertEqual(memory.errors[-1], 87)

    def test_version_condition_mask_and_hierarchical_comparison(self):
        mask = set_condition(0, 2, 3)
        self.assertEqual(mask, 0x8000000000000018)
        mask = set_condition(mask, 1, 3)
        self.assertEqual(mask, 0x800000000000001B)
        self.assertEqual(set_condition(mask, 2, 1), mask)
        self.assertEqual(set_condition(0, 0, 3), 0)
        self.assertTrue(matches_version(actual_version(6, 3, 9600),
                                        actual_version(10, 0, 22631), 3, mask))
        self.assertFalse(matches_version(actual_version(10, 0, 22631),
                                         actual_version(6, 2, 9200), 3, mask))
        self.assertFalse(matches_version(actual_version(10, 0, 22631),
                                         actual_version(10, 0, 22631), 3,
                                         set_condition(0, 2, 2)))
        self.assertIsNone(matches_version(actual_version(10, 0, 22631),
                                          actual_version(10, 0, 22631), 2, 0))

    def test_verify_version_info_uses_manifest_and_rtl_uses_true_build(self):
        cpu = VirtualCPU(load_persona(None))
        primary = SimpleNamespace(base=0x140000000)
        cpu.register_primary_image(primary.base,
            (FIXTURES / "version_compat_none_x64.exe").read_bytes())
        memory = GuestMemory(primary)
        memory.blocks[0x1000] = self.version_request()
        mask = set_condition(0, 2, 3)
        mask = set_condition(mask, 1, 3)
        self.assertEqual(cpu._verify_version_info(
            memory, "kernel32.VerifyVersionInfoW", None,
            [0x1000, 3, mask, 0]), 0)
        self.assertEqual(memory.errors[-1], 1150)
        self.assertEqual(cpu._rtl_verify_version_info(
            memory, "ntdll.RtlVerifyVersionInfo", None,
            [0x1000, 3, mask, 0]), 0)
        memory.blocks[0x1000] = self.version_request(11)
        self.assertEqual(cpu._rtl_verify_version_info(
            memory, "ntdll.RtlVerifyVersionInfo", None,
            [0x1000, 3, mask, 0]), STATUS_REVISION_MISMATCH)
        memory.blocks[0x1000] = self.version_request(major=6, minor=2)
        self.assertEqual(cpu._verify_version_info(
            memory, "kernel32.VerifyVersionInfoW", None,
            [0x1000, 3, mask, 0]), 1)
        memory.blocks[0x1000] = b"\0" * 284
        self.assertEqual(cpu._rtl_verify_version_info(
            memory, "ntdll.RtlVerifyVersionInfo", None,
            [0x1000, 3, mask, 0]), STATUS_INVALID_PARAMETER)

    def test_x86_ansi_verify_and_condition_argument_words(self):
        cpu = VirtualCPU(load_persona(None))
        primary = SimpleNamespace(base=0x400000)
        cpu.register_primary_image(primary.base,
            (FIXTURES / "version_compat_win10_x86.exe").read_bytes())
        memory = GuestMemory(primary, 4)
        memory.blocks[0x1000] = self.version_request(wide=False)
        mask = cpu._ver_set_condition_mask(memory, "", None,
                                           [0, 0, 2, 3])
        self.assertEqual(mask, 0x18)  # EAX; guest EDX receives the high word.
        mask |= 0x80000000 << 32
        self.assertEqual(cpu._verify_version_info(
            memory, "kernel32.VerifyVersionInfoA", None,
            [0x1000, 2, mask & 0xFFFFFFFF, mask >> 32]), 1)


if __name__ == "__main__":
    unittest.main()
