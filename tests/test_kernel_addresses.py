"""Guest CPU observations of kernel pointers and native NX permissions."""

import json
import struct
import tempfile
import unittest
from pathlib import Path

from emumee.driver import run_driver
from emumee.pe import inspect_pe
from emumee.persona import load_persona
from tests.test_kernel_objects import call_driver


def address_probe(machine, mode="pointers"):
    wide = machine == 0x8664
    base, width = (0x140000000, 8) if wide else (0x400000, 4)
    pointer = lambda value: (base + value).to_bytes(width, "little")
    store = lambda offset: (b"\x48\xa3" if wide else b"\xa3") + pointer(offset)
    code = (b"\x48\xa1" if wide else b"\xa1") + pointer(0x2900) + store(0x2380)
    code += (bytes.fromhex("4889c8") if wide else bytes.fromhex("8b442404")) + store(0x2388)
    code += (bytes.fromhex("4889e0") if wide else bytes.fromhex("89e0")) + store(0x2390)
    code += (bytes.fromhex("65488b042588010000") if wide else bytes.fromhex("64a124010000")) + store(0x2398)
    if mode == "unresolved-read":
        code += (b"\x48\xa1" if wide else b"\xa1") + pointer(0x2900 + 3 * width)
        code += store(0x23C0) + (b"\x48\x8b\x00" if wide else b"\x8b\x00")
        code += b"\xb8" + struct.pack("<I", 0xDEADBEEF) + store(0x23F8)
    elif mode.startswith("unmapped-"):
        code += b"\xb8" + struct.pack("<I", 0x7FFF7000)
        code += (b"\x8b\x00" if mode == "unmapped-read" else
                 b"\xff\xd0" if mode == "unmapped-fetch" else b"\xc7\x00EMU!")
        code += b"\xb8" + struct.pack("<I", 0xDEADBEEF) + store(0x23F8)
    elif mode != "pointers":
        code += (b"\x48\xa1" if wide else b"\xa1") + pointer(0x2390 if mode == "stack-nx" else 0x2388)
        if mode == "stack-nx":
            code += bytes.fromhex("482d00010000" if wide else "2d00010000")
        code += bytes.fromhex("c600c3ffd0")  # write RET, then attempt native execution
    routine = "KeGetCurrentIrql".encode("utf-16le")
    unicode = struct.pack("<HH", len(routine), len(routine) + 2)
    unicode += bytes(4) if wide else b""
    unicode += pointer(0x2620)
    read_code = (b"\x48\xa1" if wide else b"\xa1") + pointer(0x2900)
    read_code += bytes.fromhex("0fb600") + store(0x23F0)
    names = ["KeGetCurrentIrql", "RtlPcToFileHeader", "MmGetSystemRoutineAddress"]
    if mode == "unresolved-read":
        names.append("MissingEmumeeKernelData")
    return call_driver(machine, names,
        [("raw", code), (1, [("load", 0x2380), base + 0x23D0], 0x23D8),
         (2, [base + 0x2600], 0x23E0), (0, [], 0x23E8), ("raw", read_code)], b"\x31\xc0",
        [(0x2600, unicode), (0x2620, routine + bytes(2))])


class KernelAddressTests(unittest.TestCase):
    def test_import_lookup_objects_and_stack_use_kernel_addresses(self):
        for machine in (0x14C, 0x8664):
            with self.subTest(machine=machine), tempfile.TemporaryDirectory() as directory:
                payload = address_probe(machine)
                root = Path(directory)
                result = run_driver(payload, inspect_pe(payload, "addresses.sys"), load_persona(None), root, 5, 1000)
                self.assertEqual(result["errors"], [])
                self.assertEqual(result["guest_entry_return"], 0)
                item = next(item for item in result["artifacts"] if item["source"] == "modified_driver_image:0x2000")
                data = (root / "artifacts" / item["file"]).read_bytes()
                width = 8 if machine == 0x8664 else 4
                value = lambda offset: int.from_bytes(data[offset:offset + width], "little")
                minimum = 0xFFFF800000000000 if width == 8 else 0x80000000
                for offset in (0x380, 0x388, 0x390, 0x398):
                    self.assertGreaterEqual(value(offset), minimum)
                self.assertEqual(value(0x3E0), value(0x380))  # dynamic lookup and IAT agree
                self.assertEqual(value(0x3D0), value(0x3D8))  # PC lookup writes and returns base
                self.assertLessEqual(value(0x3D0), value(0x380))
                self.assertLess(value(0x380), value(0x3D0) + 0x10000)
                self.assertEqual(value(0x3E8), 0)  # canonical API address actually dispatched
                self.assertLess(value(0x3F0), 256)  # native read of provider code also succeeds

    def test_native_stack_and_object_execution_faults_preserve_partial_result(self):
        for machine in (0x14C, 0x8664):
            for mode in ("stack-nx", "object-nx"):
                with self.subTest(machine=machine, mode=mode), tempfile.TemporaryDirectory() as directory:
                    payload = address_probe(machine, mode)
                    root = Path(directory)
                    result = run_driver(payload, inspect_pe(payload, "address-nx.sys"), load_persona(None), root, 5, 1000)
                    self.assertIsNone(result["guest_entry_return"])
                    report = json.loads((root / "engine-report.json").read_text())
                    self.assertEqual(report["entry_points"][0]["error"]["type"], "invalid_execute")
                    self.assertTrue(result["errors"])

    def test_unmapped_access_stops_without_user_seh_or_following_instructions(self):
        for machine in (0x14C, 0x8664):
            for mode in ("unmapped-read", "unmapped-write", "unmapped-fetch"):
                with self.subTest(machine=machine, mode=mode), tempfile.TemporaryDirectory() as directory:
                    payload = address_probe(machine, mode)
                    root = Path(directory)
                    result = run_driver(payload, inspect_pe(payload, "address-fault.sys"), load_persona(None), root, 5, 1000)
                    self.assertIsNone(result["guest_entry_return"])
                    report = json.loads((root / "engine-report.json").read_text())
                    error = report["entry_points"][0]["error"]
                    self.assertEqual(error["type"], {"unmapped-read": "invalid_read", "unmapped-write": "invalid_write", "unmapped-fetch": "invalid_fetch"}[mode])
                    self.assertEqual(int(error["address"], 0), 0x7FFF7000)
                    self.assertIsNone(error["address_region"])
                    self.assertEqual(error["access_type"], {"unmapped-read": "read", "unmapped-write": "write", "unmapped-fetch": "execute"}[mode])
                    self.assertNotIn("AttributeError", str(result["errors"]))
                    item = next(item for item in result["artifacts"] if item["source"] == "modified_driver_image:0x2000")
                    data = (root / "artifacts" / item["file"]).read_bytes()
                    self.assertNotEqual(data[0x3F8:0x3FC], struct.pack("<I", 0xDEADBEEF))
