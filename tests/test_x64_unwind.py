"""Harmless x64 CPU faults with explicit runtime-function metadata."""

import json
import struct
import tempfile
import unittest
from pathlib import Path

from emumee.driver import run_driver
from emumee.pe import inspect_pe
from emumee.persona import load_persona
from tests.fixtures.build_driver import build_driver


def fault_driver(handler=False):
    data = bytearray(build_driver(0x8664))
    data.extend(bytes(0xE00))
    sh = 0x98 + 0xF0 + 40
    struct.pack_into("<I", data, sh + 8, 0x1000)
    struct.pack_into("<I", data, sh + 16, 0x1000)
    struct.pack_into("<II", data, 0x98 + 112 + 3 * 8, 0x2200, 12)
    struct.pack_into("<III", data, 0x600, 0x1000, 0x1100, 0x2220)
    data[0x620:0x628] = bytes([9 if handler else 1, 4, 1, 0, 4, 0x42, 0, 0])
    if handler:
        struct.pack_into("<I", data, 0x628, 0x1080)
    code = b"\x48\x83\xec\x28\x48\xa1" + bytes(8) + b"\x48\x83\xc4\x28\xc3"
    data[0x200:0x200 + len(code)] = code
    return bytes(data)


class X64UnwindTests(unittest.TestCase):
    def test_fault_walk_finds_end_or_language_handler_without_hiding_error(self):
        for handler in (False, True):
            with self.subTest(handler=handler), tempfile.TemporaryDirectory() as directory:
                data = fault_driver(handler)
                root = Path(directory)
                result = run_driver(data, inspect_pe(data, "unwind.sys"), load_persona(None), root, 5, 1000)
                self.assertTrue(result["errors"])
                self.assertIsNone(result["guest_entry_return"])
                report = json.loads((root / "engine-report.json").read_text())
                walk = report["exception_unwind"]
                self.assertEqual(walk["stop"], "language_handler_found" if handler else "end_of_guest_stack")
                self.assertEqual(walk["frames"][0]["function_begin"], "0x140001000")
                if handler:
                    self.assertEqual(walk["frames"][0]["handler"], "0x140001080")
