"""Kernel APIs, imported data and direct shared-page observations must agree."""

import datetime as dt
import json
import struct
import tempfile
import unittest
from pathlib import Path

from emumee.driver import run_driver
from emumee.pe import inspect_pe
from emumee.persona import load_persona
from tests.test_kernel_runtime import runtime_driver


def environment_probe(machine, kind):
    x64 = machine == 0x8664
    base, width = (0x140000000, 8) if x64 else (0x400000, 4)
    writes = []
    if kind == "time":
        names = ["KeQuerySystemTime", "KeQuerySystemTimePrecise"]
        calls = [(0, [base + 0x2300], False), (1, [base + 0x2310], False)]
        tail = (b"\x48\xb9" + struct.pack("<Q", 0xFFFFF78000000014) + bytes.fromhex("8b018b510448c1e2204809d048b9")
                + struct.pack("<Q", base + 0x2310) + bytes.fromhex("482b01") if x64 else
                bytes.fromhex("8b15") + struct.pack("<I", 0xFFDF0014) + b"\x33\x15" + struct.pack("<I", base + 0x2310)
                + b"\xa1" + struct.pack("<I", 0xFFDF0018) + b"\x33\x05" + struct.pack("<I", base + 0x2314) + b"\x09\xd0")
    elif kind == "counter":
        names = ["KeQueryPerformanceCounter"]
        calls = [(0, [base + 0x2300], False)]
        tail = (b"\x48\xb9" + struct.pack("<Q", base + 0x2310) + b"\x48\x89\x01" if x64 else
                b"\xa3" + struct.pack("<I", base + 0x2310) + b"\x89\x15" + struct.pack("<I", base + 0x2314)) + b"\x31\xc0"
    elif kind == "processors":
        names = ["KeQueryActiveProcessorCountEx", "KeNumberProcessors"]
        calls = [(0, [0], False)]
        tail = (b"\x48\xb9" + struct.pack("<Q", base + 0x2900 + width) + b"\x48\x8b\x09" if x64 else
                b"\x8b\x0d" + struct.pack("<I", base + 0x2900 + width)) + bytes.fromhex("0fb60939c80f94c00fb6c0")
    else:
        names = ["KeGetCurrentProcessorNumberEx"]
        calls = [(0, [base + 0x2300], False)]
        writes = [(0x2300, b"\xcd" * 4)]
        tail = b""
    return runtime_driver(machine, names, calls, writes, tail=tail)


class KernelEnvironmentTests(unittest.TestCase):
    def run_probe(self, machine, data):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        persona = load_persona(None)
        persona["clock_utc"] = "2024-02-29T12:00:00+00:00"
        persona["cpu"]["cores"] = 3
        persona["cpu"]["threads_per_core"] = 2
        result = run_driver(data, inspect_pe(data, "environment.sys"), persona, root, 5, 2000)
        self.assertEqual(result["errors"], [])
        report = json.loads((root / "engine-report.json").read_text())
        item = next((item for item in result["artifacts"] if item["source"] == "modified_driver_image:0x2000"), None)
        image = (root / "artifacts" / item["file"]).read_bytes() if item else None
        return result, report, image, persona

    def test_system_time_precise_and_standard_share_the_direct_cpu_timeline(self):
        for machine in (0x14C, 0x8664):
            with self.subTest(machine=machine):
                result, _, image, _ = self.run_probe(machine, environment_probe(machine, "time"))
                self.assertEqual(result["guest_entry_return"], 0)
                first, second = struct.unpack_from("<Q", image, 0x300)[0], struct.unpack_from("<Q", image, 0x310)[0]
                epoch = dt.datetime(1601, 1, 1)
                expected = int((dt.datetime(2024, 2, 29, 12) - epoch).total_seconds()) * 10_000_000
                self.assertTrue(expected <= first < second < expected + 1_000_000)

    def test_counter_frequency_and_64_bit_return_work_through_ntos_and_hal(self):
        for machine in (0x14C, 0x8664):
            for module in ("ntoskrnl.exe", "HAL.dll"):
                with self.subTest(machine=machine, module=module):
                    data = bytearray(environment_probe(machine, "counter"))
                    data[0x460:0x46D] = (module.encode() + b"\0").ljust(13, b"\0")
                    result, _, image, persona = self.run_probe(machine, bytes(data))
                    self.assertEqual(result["guest_entry_return"], 0)
                    self.assertEqual(struct.unpack_from("<Q", image, 0x300)[0], 10_000_000)
                    value = struct.unpack_from("<Q", image, 0x310)[0]
                    self.assertTrue(persona["uptime_ms"] * 10_000 <= value < persona["uptime_ms"] * 10_000 + 1_000_000)
                    self.assertGreater(value >> 32, 0)

    def test_processor_global_and_queries_use_the_persona(self):
        for machine in (0x14C, 0x8664):
            with self.subTest(machine=machine):
                result, report, _, _ = self.run_probe(machine, environment_probe(machine, "processors"))
                self.assertEqual(result["guest_entry_return"], 1)
                call = next(event for event in report["entry_points"][0]["events"] if event.get("api_name") == "ntoskrnl.KeQueryActiveProcessorCountEx")
                self.assertEqual(int(call["ret_val"], 0), 6)
                result, _, image, _ = self.run_probe(machine, environment_probe(machine, "number"))
                self.assertEqual(result["guest_entry_return"], 0)
                self.assertEqual(image[0x300:0x304], bytes(4))

    def test_unresolved_import_dereference_stops_instead_of_silently_reading_zero(self):
        for machine in (0x14C, 0x8664):
            with self.subTest(machine=machine), tempfile.TemporaryDirectory() as directory:
                base = 0x140000000 if machine == 0x8664 else 0x400000
                tail = (b"\x48\xb8" + struct.pack("<Q", base + 0x2900) + bytes.fromhex("488b00488b00") if machine == 0x8664 else
                        b"\xa1" + struct.pack("<I", base + 0x2900) + b"\x8b\x00")
                data = runtime_driver(machine, ["MissingEmumeeKernelData"], [], tail=tail)
                root = Path(directory)
                result = run_driver(data, inspect_pe(data, "unknown-data.sys"), load_persona(None), root, 5, 2000)
                self.assertIsNone(result["guest_entry_return"])
                self.assertTrue(any("unresolved_kernel_import_read" in error and "MissingEmumeeKernelData" in error for error in result["errors"]))
