"""Real CPU checks for relocation, canonical addresses and write evidence."""

import json
import struct
import tempfile
import unittest
from pathlib import Path

from emumee.driver import run_driver
from emumee.pe import inspect_pe, InvalidSample
from emumee.persona import load_persona
from tests.fixtures.build_driver import build_driver


def relocated_probe(machine):
    data = bytearray(build_driver(machine))
    x64 = machine == 0x8664
    base, width = (0x140000000, 8) if x64 else (0x400000, 4)
    optional = 0x98
    characteristics = struct.unpack_from("<H", data, 0x96)[0]
    struct.pack_into("<H", data, 0x96, characteristics & ~1)
    struct.pack_into("<II", data, optional + (112 if x64 else 96) + 5 * 8, 0x2180, 12)
    struct.pack_into("<IIHH", data, 0x580, 0x1000, 12, ((10 if x64 else 3) << 12) | (2 if x64 else 1), 0)
    code = (b"\x48\xb8" if x64 else b"\xb8") + (base + 0x21A0).to_bytes(width, "little")
    code += b"\xc6\x00\x2a\x0f\xb6\x00" + (b"\xc3" if x64 else b"\xc2\x08\x00")
    data[0x200:0x200 + len(code)] = code
    return data


class DriverImageTests(unittest.TestCase):
    def test_relocation_preserves_preferred_base_in_guest_header(self):
        for machine in (0x14C, 0x8664):
            with self.subTest(machine=machine), tempfile.TemporaryDirectory() as directory:
                data = relocated_probe(machine)
                x64 = machine == 0x8664
                preferred = 0x140000000 if x64 else 0x400000
                struct.pack_into("<IIHH", data, 0x580, 0x2000, 12, (0xA000 if x64 else 0x3000) | 0x1A0, 0)
                struct.pack_into("<Q" if x64 else "<I", data, 0x5A0, preferred + 0x2100)
                if x64:
                    code = b"\x48\x8d\x05" + struct.pack("<i", 0xB0 - 0x1007)
                    code += b"\x48\xb9" + struct.pack("<Q", preferred) + bytes.fromhex("4839080f94c00fb6c0c3")
                else:
                    code = bytes.fromhex("e800000000582d0510000081b8b4000000") + struct.pack("<I", preferred)
                    code += bytes.fromhex("0f94c00fb6c0c20800")
                data[0x200:0x200 + len(code)] = code
                data = bytes(data)
                root = Path(directory)
                result = run_driver(data, inspect_pe(data, "preferred.sys"), load_persona(None), root, 5, 1000)
                self.assertEqual(result["errors"], [])
                self.assertEqual(result["guest_entry_return"], 1)
                report = json.loads((root / "engine-report.json").read_text())
                reads = report["driver_header_reads"]["observations"]
                actual = 0xFFFFF80100000000 if x64 else 0x90000000
                location = actual + (0xB0 if x64 else 0xB4)
                self.assertTrue(any(int(item["address"], 0) == location and
                    int.from_bytes(bytes.fromhex(item["prefix_at_read"]), "little") == preferred for item in reads))

    def test_relocated_imports_and_registered_unload_execute(self):
        data = bytearray(build_driver(0x8664))
        offsets = [data.index(struct.pack("<Q", address), 0x200, 0x380)
                   for address in (0x140001180, 0x1400021C0)]
        struct.pack_into("<H", data, 0x96, struct.unpack_from("<H", data, 0x96)[0] & ~1)
        struct.pack_into("<II", data, 0x98 + 112 + 5 * 8, 0x2180, 12)
        struct.pack_into("<IIHH", data, 0x580, 0x1000, 12,
                         *(0xA000 | (offset - 0x200) for offset in offsets))
        data = bytes(data)
        with tempfile.TemporaryDirectory() as directory:
            result = run_driver(data, inspect_pe(data, "imports.sys"), load_persona(None), Path(directory), 5, 1000, unload=True)
            self.assertEqual(result["errors"], [])
            self.assertEqual(result["guest_entry_return"], 0)
            self.assertTrue(result["driver"]["unload_completed"])
            self.assertEqual(result["api_coverage"]["api_calls"], 3)

    def test_relocated_absolute_data_pointer_and_cpu_write_use_kernel_address(self):
        for machine in (0x14C, 0x8664):
            with self.subTest(machine=machine), tempfile.TemporaryDirectory() as directory:
                data = bytes(relocated_probe(machine))
                root = Path(directory)
                result = run_driver(data, inspect_pe(data, "relocated.sys"), load_persona(None), root, 5, 1000)
                self.assertEqual(result["errors"], [])
                self.assertEqual(result["guest_entry_return"], 42)
                report = json.loads((root / "engine-report.json").read_text())
                base = 0xFFFFF80100000000 if machine == 0x8664 else 0x90000000
                self.assertEqual(report["image_placement"]["mapped_base"], hex(base))
                self.assertEqual(report["image_placement"]["relocations_applied"], 1)
                self.assertEqual(report["entry_points"][0]["start_addr"], hex(base + 0x1000))
                self.assertEqual(report["driver_image_changes"]["changed_pages"], 1)
                item = next(item for item in result["artifacts"] if item["source"] == "modified_driver_image:0x2000")
                self.assertEqual((root / "artifacts" / item["file"]).read_bytes()[0x1A0], 42)

    def test_invalid_relocation_fails_before_guest_execution(self):
        for entry in (0x7002, 0xAFFC):
            with self.subTest(entry=entry), tempfile.TemporaryDirectory() as directory:
                data = relocated_probe(0x8664)
                if entry == 0xAFFC:
                    struct.pack_into("<I", data, 0x580, 0x2000)
                struct.pack_into("<H", data, 0x588, entry)
                data = bytes(data)
                with self.assertRaises(InvalidSample):
                    run_driver(data, inspect_pe(data, "invalid.sys"), load_persona(None), Path(directory), 5, 1000)
