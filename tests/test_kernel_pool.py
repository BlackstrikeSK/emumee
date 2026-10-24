"""CPU execution must distinguish executable and NX kernel pool allocations."""

import json
import struct
import tempfile
import unittest
from pathlib import Path

from emumee.driver import run_driver
from emumee.pe import inspect_pe
from emumee.persona import load_persona
from tests.fixtures.build_driver import build_driver
from tests.test_kernel_runtime import runtime_driver


def pool_probe(machine, pool_type):
    data = bytearray(build_driver(machine))
    if machine == 0x8664:
        code = bytearray(b"\x48\x83\xec\x28\xb9" + struct.pack("<I", pool_type) + b"\xba\x10\0\0\0\x41\xb8NX!!")
        code += b"\xff\x15" + struct.pack("<i", 0x20B0 - (0x1000 + len(code) + 6))
        code += bytes.fromhex("c700b82a000066c7400400c3ffd04883c428c3")
    else:
        code = bytearray(b"\x68NX!!\x6a\x10\x68" + struct.pack("<I", pool_type) + b"\xff\x15" + struct.pack("<I", 0x4020A8))
        code += bytes.fromhex("c700b82a000066c7400400c3ffd0c20800")
    data[0x200:0x200 + len(code)] = code
    return bytes(data)


def zero_pool_probe(machine, pool_type=0x600):
    return runtime_driver(machine, ["ExAllocatePoolWithTag"],
        [(0, [pool_type, 0x238, 0x72546756], False)],
        tail=bytes.fromhex("8b080b883402000025ff0f000009c8"))


class KernelPoolTests(unittest.TestCase):
    def test_execute_pool_runs_and_nx_pool_faults_before_payload_execution(self):
        for machine in (0x14C, 0x8664):
            for pool_type in (0, 4, 0x200, 0x204, 0x600, 0x604, 0x700):
                with self.subTest(machine=machine, pool_type=pool_type), tempfile.TemporaryDirectory() as directory:
                    data = pool_probe(machine, pool_type)
                    root = Path(directory)
                    result = run_driver(data, inspect_pe(data, "pool.sys"), load_persona(None), root, 5, 1000)
                    nx = bool(pool_type & 0x200)
                    self.assertEqual(result["guest_entry_return"], None if nx else 42)
                    if nx:
                        self.assertTrue(any("non-executable" in error for error in result["errors"]))
                    else:
                        self.assertEqual(result["errors"], [])
                    report = json.loads((root / "engine-report.json").read_text())
                    allocation = next(event for event in report["entry_points"][0]["events"]
                                      if event.get("api_name") == "ntoskrnl.ExAllocatePoolWithTag")
                    address = int(allocation["ret_val"], 0)
                    self.assertGreaterEqual(address, 0xFFFF800000000000 if machine == 0x8664 else 0x80000000)
                    pool = next(item for item in result["artifacts"] if item["source"].startswith("memory:api.pool."))
                    self.assertEqual((root / "artifacts" / pool["file"]).read_bytes()[:6], bytes.fromhex("b82a000000c3"))

    def test_zero_pool_modifiers_preserve_zero_bytes_and_alignment(self):
        for machine in (0x14C, 0x8664):
            for pool_type in (0x400, 0x401, 0x405, 0x600, 0x604, 0x700):
                with self.subTest(machine=machine, pool_type=pool_type), tempfile.TemporaryDirectory() as directory:
                    # Check the first and last requested DWORD and page alignment
                    # with actual CPU reads before writing anything to the pool.
                    data = zero_pool_probe(machine, pool_type)
                    root = Path(directory)
                    result = run_driver(data, inspect_pe(data, "zero-pool.sys"), load_persona(None), root, 5, 1000)
                    self.assertEqual(result["errors"], [])
                    self.assertEqual(result["guest_entry_return"], 0)
                    pool = next(item for item in result["artifacts"] if item["source"].startswith("memory:api.pool."))
                    self.assertEqual((root / "artifacts" / pool["file"]).read_bytes(), bytes(4096))
