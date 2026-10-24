"""Report actual allocated-code execution without changing guest behavior."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from emumee.driver import run_driver
from emumee.kernel_memory_report import capture
from emumee.pe import inspect_pe
from emumee.persona import load_persona
from tests.test_kernel_objects import call_driver


def allocated_code_probe(machine, executable=True):
    wide = machine == 0x8664
    base, width = (0x140000000, 8) if wide else (0x400000, 4)
    load = (b"\x48\xa1" if wide else b"\xa1") + (base + 0x2300).to_bytes(width, "little")
    code = load + bytes.fromhex("c700b842420066c7400400c3ffd0")
    code += (b"\x48\xa3" if wide else b"\xa3") + (base + 0x2380).to_bytes(width, "little")
    return call_driver(machine, ["ExAllocatePoolWithTag"],
        [(0, [0 if executable else 0x200, 4096, 0x41424C45], 0x2300), ("raw", code)], b"\x31\xc0")


def verify_memory_result(report, executable):
    entries = report["entry_points"]
    pools = [row for entry in entries for row in (entry.get("memory") or {}).get("layout", [])
             if row["tag"].startswith("api.pool.")]
    dynamic = [row for entry in entries for row in entry.get("dynamic_code_segments") or []]
    assert len(pools) == 1 and pools[0]["accesses"]["writes"] == 2
    assert pools[0]["prot"] == ("rwx" if executable else "rw-")
    if executable:
        assert pools[0]["accesses"]["execs"] == 2 and len(dynamic) == 1
        assert dynamic[0]["base"] == pools[0]["address"]
    else:
        assert pools[0]["accesses"]["execs"] == 0 and not dynamic
        assert entries[0]["error"]["type"] == "invalid_execute"
    assert entries[0]["memory"]["modules"]
    assert all(not (entry.get("memory") or {}).get("modules") for entry in entries[1:])
    assert report["kernel_memory_capture"]["limited"] is False


class KernelMemoryReportTests(unittest.TestCase):
    def run_probe(self, machine, executable):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = allocated_code_probe(machine, executable)
            result = run_driver(payload, inspect_pe(payload, "memory-report.sys"), load_persona(None), root, 5, 1000)
            report = json.loads((root / "engine-report.json").read_text())
            observation = {"instructions": result["instruction_count"], "return": result["guest_entry_return"],
                "virtual_tsc": report["virtual_tsc"],
                "artifacts": [(item["source"], item["sha256"]) for item in result["artifacts"]]}
            return result, report, observation

    def test_allocated_execution_and_nx_fault_are_reported_without_guest_changes(self):
        for machine in (0x14C, 0x8664):
            for executable in (True, False):
                with self.subTest(machine=machine, executable=executable):
                    with patch("emumee.kernel_memory_report.capture", return_value={"scope": "test baseline"}):
                        _baseline, baseline_report, baseline_observation = self.run_probe(machine, executable)
                    result, report, observation = self.run_probe(machine, executable)
                    self.assertEqual(observation, baseline_observation)
                    self.assertIsNone(baseline_report["entry_points"][0]["memory"])
                    self.assertEqual(result["guest_entry_return"], 0 if executable else None)
                    verify_memory_result(report, executable)

    def test_capture_limits_are_explicit_and_do_not_change_native_counters(self):
        def bounded(kernel):
            before = [(id(run), [(id(mapping), access.reads, access.writes, access.execs)
                       for mapping, access in run.mem_access.items()]) for run in kernel.runs]
            limited = capture(kernel, max_records=0, max_modules=0, max_segments=0, max_dynamic=0)
            self.assertTrue(limited["limited"])
            self.assertEqual(limited["region_records"], 0)
            self.assertEqual(limited["dynamic_regions"], 0)
            self.assertGreater(limited["omitted_region_records"], 0)
            self.assertGreater(limited["omitted_modules"], 0)
            self.assertGreater(limited["omitted_dynamic_regions"], 0)
            separate = capture(kernel, max_records=0, max_modules=0, max_segments=0, max_dynamic=1)
            self.assertEqual(separate["region_records"], 0)
            self.assertEqual(separate["dynamic_regions"], 1)
            final = capture(kernel)
            after = [(id(run), [(id(mapping), access.reads, access.writes, access.execs)
                      for mapping, access in run.mem_access.items()]) for run in kernel.runs]
            self.assertEqual(before, after)
            return final
        for machine in (0x14C, 0x8664):
            with self.subTest(machine=machine), patch("emumee.kernel_memory_report.capture", side_effect=bounded):
                _result, report, _observation = self.run_probe(machine, True)
                verify_memory_result(report, True)
