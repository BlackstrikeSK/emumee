"""Permission batching must preserve order, overlaps, gaps and exact rights."""

import unittest
import tempfile
from pathlib import Path
from emumee.image_protection import ImageProtectionBatch
from emumee.driver import DriverEmulator
from emumee.persona import load_persona, make_speakeasy_config
from tests.fixtures.build_driver import build_driver


class ImageProtectionTests(unittest.TestCase):
    def test_adjacent_equal_rights_merge_without_widening(self):
        calls = []
        batch = ImageProtectionBatch(lambda *args: calls.append(args))
        original = [(0x1000, 0x1000, 1), (0x2000, 0x1000, 1),
                    (0x3000, 0x1000, 5), (0x4000, 0x1000, 5),
                    (0x6000, 0x1000, 3), (0x3000, 0x1000, 1)]
        for request in original:
            batch.add(*request)
        batch.flush()
        self.assertEqual(calls, [(0x1000, 0x2000, 1), (0x3000, 0x2000, 5),
                                 (0x6000, 0x1000, 3), (0x3000, 0x1000, 1)])
        def pages(requests):
            result = {}
            for start, size, rights in requests:
                for address in range(start, start + size, 0x1000):
                    result[address] = rights
            return result
        self.assertEqual(pages(calls), pages(original))

    def test_large_image_has_constant_number_of_native_calls(self):
        calls = []
        batch = ImageProtectionBatch(lambda *args: calls.append(args))
        for index in range(26610):
            batch.add(0x140000000 + index * 0x1000, 0x1000, 5)
        batch.flush()
        self.assertEqual(calls, [(0x140000000, 26610 * 0x1000, 5)])
        self.assertEqual((batch.requests, batch.applied), (26610, 1))

    def test_native_failure_is_not_hidden(self):
        def protect(*_args):
            raise ValueError("unmapped page")
        batch = ImageProtectionBatch(protect)
        batch.add(0x1000, 0x1000, 1)
        with self.assertRaisesRegex(ValueError, "unmapped"):
            batch.flush()
        with self.assertRaisesRegex(ValueError, "unmapped"):
            batch.flush()

    def test_kernel_loader_preserves_actual_unicorn_permissions(self):
        for machine in (0x14C, 0x8664):
            with self.subTest(machine=machine), tempfile.TemporaryDirectory() as directory:
                cfg = make_speakeasy_config(load_persona(None), "rights.sys", 5, 1000)
                cfg["modules"]["module_directory_x86"] = directory
                cfg["modules"]["module_directory_x64"] = directory
                with DriverEmulator(cfg) as emulator:
                    module = emulator.load_module(data=build_driver(machine), filename="rights.sys")
                    regions = list(emulator.emu.emu_eng.emu.mem_regions())
                    def rights(address):
                        return next(value for start, end, value in regions if start <= address <= end)
                    self.assertEqual(rights(module.base), 1)  # headers: read only
                    self.assertEqual(rights(module.base + 0x1000), 5)  # text: read/execute
                    self.assertEqual(rights(module.base + 0x2000), 3)  # data: read/write
                    self.assertIsNone(emulator.emu.image_protections.pending)
