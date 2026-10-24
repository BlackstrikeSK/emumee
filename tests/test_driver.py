"""Harmless CPU fixtures for the driver target and truthful stop reporting."""

import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from emumee.driver import run_driver
from emumee.pe import InvalidSample, inspect_pe, inspect_pe_header
from emumee.persona import load_persona
from emumee.worker import _result_status, execute
from emumee.reports import verify_artifact_manifest, valid_summary
from emumee.dashboard import create_app, _compare_runs
from emumee.cli import main
import contextlib
import io
from tests.fixtures.build_driver import build_driver, build_driver_file_probe
from tests.fixtures.build_native import build


class DriverTests(unittest.TestCase):
    def run_case(self, machine, mode, *, unload=False, budget=1000, timeout=5):
        data = build_driver(machine, mode)
        name = "probe.sys"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = run_driver(data, inspect_pe(data, name), load_persona(None),
                                root, timeout, budget, unload=unload)
            report = json.loads((root / "engine-report.json").read_text())
            self.assertTrue(verify_artifact_manifest(root, result["artifacts"], result["artifact_groups"]))
            pool = [item for item in result["artifacts"] if item["source"].startswith("memory:api.pool.")]
            if pool:
                self.assertTrue(any((root / "artifacts" / item["file"]).read_bytes().startswith(b"EMU!")
                                    for item in pool))
            return result, report

    def test_classification_and_malformed_inputs(self):
        for machine in (0x14C, 0x8664):
            data = build_driver(machine)
            for name in ("probe.sys", "renamed.bin"):
                self.assertEqual(inspect_pe_header(data, name).kind, "driver")
                self.assertEqual(inspect_pe(data, name).kind, "driver")
            with self.assertRaises(InvalidSample):
                inspect_pe_header(build(machine), "wrong.sys")
            empty = bytearray(data)
            struct.pack_into("<I", empty, 0x98 + 16, 0)
            with self.assertRaisesRegex(InvalidSample, "DriverEntry"):
                inspect_pe(bytes(empty), "empty.sys")
            # The CLR directory is not a supported kernel execution mode.
            clr = bytearray(data)
            directory = 112 if machine == 0x8664 else 96
            struct.pack_into("<II", clr, 0x98 + directory + 14 * 8, 0x2000, 72)
            with self.assertRaisesRegex(InvalidSample, "Managed kernel"):
                inspect_pe_header(bytes(clr), "managed.sys")

    def test_entry_and_explicit_unload(self):
        for machine in (0x14C, 0x8664):
            for unload in (False, True):
                with self.subTest(machine=machine, unload=unload):
                    result, report = self.run_case(machine, "success", unload=unload)
                    self.assertEqual(result["errors"], [])
                    self.assertEqual(_result_status(result), ("completed", None))
                    self.assertEqual(result["guest_entry_return"], 0)
                    self.assertIsNone(result["guest_exit_code"])
                    driver = result["driver"]
                    self.assertTrue(driver["initialization_succeeded"])
                    self.assertTrue(driver["unload_registered"])
                    self.assertEqual(driver["unload_completed"], unload)
                    self.assertEqual(len(driver["devices_created"]), 1)
                    self.assertTrue(driver["dispatch_routines"])
                    self.assertTrue(driver["registry_path"].endswith("\\probe"))
                    self.assertEqual([ep["ep_type"] for ep in report["entry_points"]],
                                     ["entry_point", "driver_unload"] if unload else ["entry_point"])
                    self.assertTrue(any(item["source"].startswith("memory:api.pool.")
                                        for item in result["artifacts"]))

    def test_failed_initialization_never_unloads(self):
        for machine in (0x14C, 0x8664):
            result, report = self.run_case(machine, "failure", unload=True)
            self.assertEqual(result["errors"], [])
            self.assertEqual(result["guest_entry_return"], 0xC0000001)
            self.assertFalse(result["driver"]["initialization_succeeded"])
            self.assertFalse(result["driver"]["unload_completed"])
            self.assertEqual(len(report["entry_points"]), 1)

    def test_worker_routes_drivers_and_validates_options(self):
        for overrides, expected in (({}, "completed"), ({"driver_unload": True}, "completed"),
                                    ({"all_exports": True}, "failed"),
                                    ({"guest_args": ["bad"]}, "failed"),
                                    ({"driver_unload": "yes"}, "failed")):
            with self.subTest(overrides=overrides), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "input.pe").write_bytes(build_driver(0x8664))
                request = {"sample_name": "probe.sys", "persona": load_persona(None),
                           "dlls": [], "timeout": 5, "max_instructions": 1000, **overrides}
                (root / "request.json").write_text(json.dumps(request))
                with patch("emumee.worker.verify_worker_containment", return_value={}), \
                        patch("emumee.worker.run_native", side_effect=AssertionError("User-mode runner called")):
                    summary = execute(root)
                self.assertEqual(summary["status"], expected)
                summary["id"] = "20261015T120000Z-12345678"
                self.assertTrue(valid_summary(summary))
                if expected == "completed":
                    self.assertEqual(summary["execution_mode"], "kernel")
                    summary["driver"]["entry_status"] = "untrusted text"
                    self.assertFalse(valid_summary(summary))

    def test_limits_faults_and_unknown_imports_are_partial(self):
        for machine in (0x14C, 0x8664):
            for mode in ("loop", "fault", "unknown", "unload_loop", "unload_fault"):
                with self.subTest(machine=machine, mode=mode):
                    result, _report = self.run_case(machine, mode, unload=True, budget=100)
                    self.assertTrue(result["errors"])
                    self.assertEqual(_result_status(result)[0], "partial")
                    self.assertFalse(result["driver"]["unload_completed"])
                    if mode == "unknown":
                        self.assertTrue(any("ntoskrnl.MissingEmumeeKernelApi" in error for error in result["errors"]))
                    if mode.endswith("loop"):
                        self.assertTrue(result["instruction_limit_reached"])
                        self.assertLessEqual(result["instruction_count"], 100)
                    if not mode.startswith("unload_"):
                        self.assertIsNone(result["guest_entry_return"])

    def test_api_calls_do_not_cause_an_unreported_native_budget_stop(self):
        for machine in (0x14C, 0x8664):
            with self.subTest(machine=machine), tempfile.TemporaryDirectory() as directory:
                data = bytearray(build_driver(machine))
                location = data.index(b"\xc7\x00EMU!\x31\xc0") + 6
                data[location:location + 2] = b"\xeb\xfe"
                data = bytes(data)
                result = run_driver(data, inspect_pe(data, "api-loop.sys"), load_persona(None), Path(directory), 5, 100)
                self.assertTrue(result["instruction_limit_reached"])
                self.assertEqual(result["instruction_count"], 100)
                self.assertIsNone(result["guest_entry_return"])
                self.assertEqual(result["api_coverage"]["api_calls"], 2)
                progress = json.loads((Path(directory) / "driver-progress.json").read_text())
                self.assertEqual(progress["status"], "stopped")
                self.assertEqual(progress["completion_reason"], "instruction_limit")
                self.assertEqual(progress["instruction_count"], 100)

    def test_wall_clock_stop_is_not_an_entry_return(self):
        result, _ = self.run_case(0x8664, "loop", budget=5_000_000, timeout=1)
        self.assertTrue(result["timeout_reached"])
        self.assertIsNone(result["guest_entry_return"])
        self.assertEqual(_result_status(result)[0], "timeout")

    def test_analyst_stop_preserves_partial_report_without_fabricating_return(self):
        data = build_driver(0x8664, "loop")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "driver-control.json").write_text('{"stop": true}')
            result = run_driver(data, inspect_pe(data, "stop.sys"), load_persona(None), root, 5, 1000)
            self.assertEqual(result["completion_reason"], "cancelled")
            self.assertIsNone(result["guest_entry_return"])
            self.assertEqual(result["instruction_count"], 0)
            self.assertEqual(_result_status(result), ("partial", None))
            progress = json.loads((root / "driver-progress.json").read_text())
            self.assertEqual(progress["status"], "stopped")
            report = json.loads((root / "engine-report.json").read_text())
            self.assertIn("rsp", report["stopped_registers"])

    def test_kernel_file_creation_stays_in_guest_state(self):
        for machine in (0x14C, 0x8664):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                marker = root / "outside-worker.txt"
                run = root / "run"
                run.mkdir()
                data = build_driver_file_probe(machine, str(marker))
                result = run_driver(data, inspect_pe(data, "file.sys"), load_persona(None), run, 5, 1000)
                self.assertEqual(result["errors"], [])
                self.assertEqual(result["guest_entry_return"], 0)
                self.assertFalse(marker.exists())
                report = json.loads((run / "engine-report.json").read_text())
                events = report["entry_points"][0]["events"]
                self.assertTrue(any(event.get("event") == "file_open" and
                                    event.get("path") == str(marker) for event in events))

    def test_importless_driver_receives_kernel_arguments(self):
        for machine in (0x14C, 0x8664):
            data = bytearray(build_driver(machine))
            dd = 112 if machine == 0x8664 else 96
            struct.pack_into("<II", data, 0x98 + dd + 8, 0, 0)
            data[0x200:0x208] = (b"\x31\xc0\xc3\x90\x90\x90\x90\x90" if machine == 0x8664 else
                                 b"\x31\xc0\xc2\x08\x00\x90\x90\x90")
            with tempfile.TemporaryDirectory() as directory:
                result = run_driver(bytes(data), inspect_pe(bytes(data), "empty.sys"), load_persona(None),
                                    Path(directory), 5, 100, unload=True)
                self.assertEqual(result["errors"], [])
                self.assertEqual(result["guest_entry_return"], 0)
                self.assertFalse(result["driver"]["unload_registered"])

    def test_kernel_cpu_reads_shared_time_from_canonical_high_alias(self):
        for machine in (0x14C, 0x8664):
            with self.subTest(machine=machine), tempfile.TemporaryDirectory() as directory:
                data = bytearray(build_driver(machine))
                if machine == 0x8664:
                    # The CPU translates this high alias; reading it must not
                    # fault or expose a separate host-derived clock value.
                    code = b"\x48\xb8" + struct.pack("<Q", 0xFFFFF78000000320) + b"\x8b\x00\xc3"
                else:
                    code = b"\xa1" + struct.pack("<I", 0xFFDF0320) + b"\xc2\x08\x00"
                data[0x200:0x200 + len(code)] = code
                persona = load_persona(None)
                result = run_driver(bytes(data), inspect_pe(bytes(data), "clock.sys"),
                                    persona, Path(directory), 5, 1000)
                self.assertEqual(result["errors"], [])
                self.assertEqual(result["guest_entry_return"], persona["uptime_ms"] // 16 * 16)

    def test_driver_cpu_runs_at_kernel_privilege_with_a_current_thread(self):
        for machine in (0x14C, 0x8664):
            with self.subTest(machine=machine), tempfile.TemporaryDirectory() as directory:
                data = bytearray(build_driver(machine))
                # Verify the Windows selector, including its privilege bits.
                code = b"\x31\xc0\x8c\xc8" + (b"\xc3" if machine == 0x8664 else b"\xc2\x08\x00")
                data[0x200:0x200 + len(code)] = code
                root = Path(directory)
                result = run_driver(bytes(data), inspect_pe(bytes(data), "privilege.sys"),
                                    load_persona(None), root, 5, 1000)
                self.assertEqual(result["errors"], [])
                self.assertEqual(result["guest_entry_return"], 0x10 if machine == 0x8664 else 0x08)
                report = json.loads((root / "engine-report.json").read_text())
                self.assertEqual(report["kernel_context"]["cpl"], 0)
                self.assertEqual(report["kernel_context"]["system_pid"], 4)
                self.assertIsNotNone(report["entry_points"][0]["tid"])

    def test_x64_pcr_self_pointer_is_in_kernel_address_range(self):
        data = bytearray(build_driver(0x8664))
        code = bytes.fromhex("65488b04251800000048c1e83fc3")
        data[0x200:0x200 + len(code)] = code
        data = bytes(data)
        with tempfile.TemporaryDirectory() as directory:
            result = run_driver(data, inspect_pe(data, "pcr.sys"), load_persona(None), Path(directory), 5, 1000)
            self.assertEqual(result["errors"], [])
            self.assertEqual(result["guest_entry_return"], 1)

    def test_x64_queue_lock_pointer_can_find_modeled_kernel_image(self):
        data = bytearray(build_driver(0x8664))
        # Follow LockArray[LockQueueNonPagedPoolLock].Lock and walk its
        # containing module's pages to the DOS signature, entirely in CPU.
        code = bytes.fromhex("65488b042528000000488b4068482500f0ffff6681384d5a7408482d00100000ebf10fb700c3")
        data[0x200:0x200 + len(code)] = code
        data = bytes(data)
        with tempfile.TemporaryDirectory() as directory:
            result = run_driver(data, inspect_pe(data, "queues.sys"), load_persona(None), Path(directory), 5, 1000)
            self.assertEqual(result["errors"], [])
            self.assertEqual(result["guest_entry_return"], 0x5A4D)

    def test_x64_queued_lock_storage_is_not_executable(self):
        data = bytearray(build_driver(0x8664))
        code = bytes.fromhex("65488b042528000000488b4068ffd0c3")
        data[0x200:0x200 + len(code)] = code
        data = bytes(data)
        with tempfile.TemporaryDirectory() as directory:
            result = run_driver(data, inspect_pe(data, "queue-nx.sys"), load_persona(None), Path(directory), 5, 1000)
            self.assertIsNone(result["guest_entry_return"])
            self.assertTrue(any("non-executable" in error for error in result["errors"]))

    def test_modified_executed_image_bytes_are_captured(self):
        for machine in (0x14C, 0x8664):
            with self.subTest(machine=machine), tempfile.TemporaryDirectory() as directory:
                data = bytearray(build_driver(machine))
                base = 0x140000000 if machine == 0x8664 else 0x400000
                sh = 0x98 + (0xF0 if machine == 0x8664 else 0xE0)
                struct.pack_into("<I", data, sh + 36, 0xE0000020)  # explicit RWX test code
                if machine == 0x8664:
                    code = b"\xc6\x05" + struct.pack("<i", 0x1101 - 0x1007) + b"\x2a"
                else:
                    code = b"\xc6\x05" + struct.pack("<I", base + 0x1101) + b"\x2a"
                code += b"\xe9" + struct.pack("<i", 0x1100 - (0x1000 + len(code) + 5))
                data[0x200:0x200 + len(code)] = code
                target = b"\xb8\x01\x00\x00\x00" + (b"\xc3" if machine == 0x8664 else b"\xc2\x08\x00")
                data[0x300:0x300 + len(target)] = target
                root = Path(directory)
                result = run_driver(bytes(data), inspect_pe(bytes(data), "modify.sys"),
                                    load_persona(None), root, 5, 1000)
                self.assertEqual(result["errors"], [])
                self.assertEqual(result["guest_entry_return"], 42)
                self.assertEqual(result["driver_image_changes"]["executed_after_write_pages"], 1)
                artifact = next(item for item in result["artifacts"]
                                if item["source"] == "modified_driver_image:0x1000")
                self.assertEqual((root / "artifacts" / artifact["file"]).read_bytes()[0x100:0x105],
                                 b"\xb8\x2a\x00\x00\x00")

    def test_cli_driver_option_validation_and_batch_selection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            driver = root / "probe.sys"
            driver.write_bytes(build_driver(0x8664))
            exe = root / "probe.exe"
            exe.write_bytes(build(0x8664))
            for sample, options in ((driver, ["--all-exports"]), (driver, ["--guest-arg", "bad"]),
                                    (driver, ["--guest-env", "TEST=bad"]), (exe, ["--driver-unload"])):
                with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(main(["run", str(sample), *options]), 2)
            with patch("emumee.cli.run", return_value=0) as run, \
                    contextlib.redirect_stdout(io.StringIO()):
                main(["batch", str(root), "--include-driver"])
                self.assertEqual({Path(call.args[0].sample).suffix for call in run.call_args_list},
                                 {".exe", ".sys"})

    def test_driver_dashboard_and_comparison(self):
        result, _report = self.run_case(0x8664, "success", unload=True)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_id = "20261015T120000Z-12345678"
            path = root / run_id
            path.mkdir()
            value = {**result, "id": run_id, "status": "completed", "sample": {
                "name": "probe.sys", "kind": "driver", "managed": False, "architecture": "x64"},
                "artifacts": [], "artifact_groups": []}
            (path / "summary.json").write_text(json.dumps(value))
            response = create_app(root).test_client().get(f"/runs/{run_id}")
            self.assertEqual(response.status_code, 200)
            html = response.get_data(as_text=True)
            self.assertIn("DriverEntry NTSTATUS", html)
            self.assertIn("0x00000000", html)
            self.assertIn("Kernel driver", html)
            self.assertIn("Registered dispatch routines", html)
            left = {**value, "run_manifest": {"driver_unload": False}}
            right = {**value, "run_manifest": {"driver_unload": True}}
            self.assertFalse(_compare_runs(left, right)["comparable_context"]["same_invocation"])


if __name__ == "__main__":
    unittest.main()
