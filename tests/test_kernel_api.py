"""Harmless real-CPU calls through modeled kernel exports."""

import json
import struct
import tempfile
import unittest
from pathlib import Path

from emumee.driver import run_driver
from emumee.pe import inspect_pe
from emumee.persona import load_persona
from tests.fixtures.build_driver import build_driver


def pc_lookup_probe(machine, found=True, bad_output=False):
    data = bytearray(build_driver(machine))
    name = b"RtlPcToFileHeader\0"
    data[0x4D2:0x4D2 + len(name)] = name
    x64 = machine == 0x8664
    base, width = (0x140000000, 8) if x64 else (0x400000, 4)
    pc, output = base + (0x1000 if found else 0x3000), base + (0x1000 if bad_output else 0x21C0)
    if x64:
        code = b"\x48\x83\xec\x28\x48\xb9" + struct.pack("<Q", pc)
        code += b"\x48\xba" + struct.pack("<Q", output)
        code += b"\xff\x15" + struct.pack("<i", 0x20A0 - (0x1000 + len(code) + 6))
        code += b"\x48\xb9" + struct.pack("<Q", output)
        code += b"\x48\x3b\x01\x0f\x94\xc0\x0f\xb6\xc0\x48\x83\xc4\x28\xc3"
    else:
        code = b"\x68" + struct.pack("<I", output) + b"\x68" + struct.pack("<I", pc)
        code += b"\xff\x15" + struct.pack("<I", base + 0x20A0)
        code += b"\x3b\x05" + struct.pack("<I", output) + b"\x0f\x94\xc0\x0f\xb6\xc0\xc2\x08\x00"
    data[0x200:0x200 + len(code)] = code
    data[0x5C0:0x5C0 + width] = bytes([0xFF]) * width
    return bytes(data)


class KernelApiTests(unittest.TestCase):
    def test_modeled_api_code_write_invalidates_instruction_cache_and_is_captured(self):
        for machine in (0x14C, 0x8664):
            with self.subTest(machine=machine), tempfile.TemporaryDirectory() as directory:
                data = bytearray(pc_lookup_probe(machine))
                x64 = machine == 0x8664
                base, width = (0x140000000, 8) if x64 else (0x400000, 4)
                sh = 0x98 + (0xF0 if x64 else 0xE0)
                struct.pack_into("<I", data, sh + 36, 0xE0000020)
                # Change the modeled API's output from ordinary data to the
                # immediate of a later function on this already-cached page.
                old = struct.pack("<Q" if x64 else "<I", base + 0x21C0)
                new = struct.pack("<Q" if x64 else "<I", base + 0x1100 + (2 if x64 else 1))
                code = bytes(data[0x200:0x300]).replace(old, new)
                # Locate the first comparison following the API call and jump
                # directly to the patched function, keeping the calling frame.
                compare = code.index(b"\x48\x3b\x01" if x64 else b"\x3b\x05")
                if x64:
                    ending = b"\x48\x83\xc4\x28\xe9"
                else:
                    ending = b"\xe9"
                ending += struct.pack("<i", 0x1100 - (0x1000 + compare + len(ending) + 4))
                code = code[:compare] + ending
                data[0x200:0x200 + len(code)] = code
                target = (b"\x48\xb8" + struct.pack("<Q", 1) + bytes.fromhex("48c1e820c3") if x64 else
                          b"\xb8" + struct.pack("<I", 1) + bytes.fromhex("c1e816c20800"))
                data[0x300:0x300 + len(target)] = target
                data = bytes(data)
                root = Path(directory)
                result = run_driver(data, inspect_pe(data, "api-code-write.sys"), load_persona(None), root, 5, 1000)
                self.assertEqual(result["errors"], [])
                self.assertEqual(result["guest_entry_return"], 1)
                self.assertEqual(result["driver_image_changes"]["executed_after_write_pages"], 1)
                item = next(item for item in result["artifacts"] if item["source"] == "modified_driver_image:0x1000")
                payload = (root / "artifacts" / item["file"]).read_bytes()
                offset = 0x102 if x64 else 0x101
                self.assertEqual(int.from_bytes(payload[offset:offset + width], "little"), base)

    def test_pc_lookup_returns_and_writes_image_base_or_null(self):
        for machine in (0x14C, 0x8664):
            for found in (False, True):
                with self.subTest(machine=machine, found=found), tempfile.TemporaryDirectory() as directory:
                    data = pc_lookup_probe(machine, found)
                    root = Path(directory)
                    result = run_driver(data, inspect_pe(data, "lookup.sys"), load_persona(None), root, 5, 1000)
                    self.assertEqual(result["errors"], [])
                    self.assertEqual(result["guest_entry_return"], 1)
                    self.assertEqual(result["api_coverage"]["signature_only_calls"], [])
                    report = json.loads((root / "engine-report.json").read_text())
                    events = report["entry_points"][0]["events"]
                    call = next(event for event in events if event.get("api_name") == "ntoskrnl.RtlPcToFileHeader")
                    self.assertEqual(int(call["ret_val"], 0), (0x140000000 if machine == 0x8664 else 0x400000) if found else 0)

    def test_pc_lookup_does_not_bypass_guest_output_permissions(self):
        for machine in (0x14C, 0x8664):
            with self.subTest(machine=machine), tempfile.TemporaryDirectory() as directory:
                data = pc_lookup_probe(machine, bad_output=True)
                result = run_driver(data, inspect_pe(data, "readonly.sys"), load_persona(None), Path(directory), 5, 1000)
                self.assertIsNone(result["guest_entry_return"])
                self.assertTrue(any("writable guest pointer" in error for error in result["errors"]))
