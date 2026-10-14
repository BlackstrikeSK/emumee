"""Check the guarded malware-behavior fixture under managed emulation."""

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from emumee.managed import run_managed
from emumee.pe import inspect_pe
from emumee.persona import load_persona


FIXTURE = Path(__file__).parent / "fixtures" / "ManagedThreatSimulation"
STAGED = Path(__file__).parent / "fixtures" / "ManagedStagedDeployer"


@unittest.skipUnless(shutil.which("dotnet"), ".NET SDK is unavailable")
class ThreatSimulationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        subprocess.run(["dotnet", "build", str(FIXTURE / "ManagedThreatSimulation.csproj"),
                        "-c", "Release"], check=True, stdout=subprocess.DEVNULL)
        cls.assembly = FIXTURE / "bin" / "Release" / "net8.0" / "ManagedThreatSimulation.dll"
        cls.data = cls.assembly.read_bytes()
        cls.info = inspect_pe(cls.data, cls.assembly.name)

    def test_guard_exits_without_guest_opt_in(self):
        with tempfile.TemporaryDirectory() as directory:
            result = run_managed(self.data, self.info, load_persona(None),
                                 Path(directory), 500_000)
            self.assertFalse(result["errors"])
            self.assertEqual(result["guest_entry_return"], 2)
            self.assertFalse(result["artifacts"])
            self.assertEqual(result["denied_operations"], 0)

    def test_emulated_payload_drop_and_offline_network_denial(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = run_managed(self.data, self.info, load_persona(None), root,
                                 500_000, guest_env={"EMUMEE_TEST": "virtual"})
            self.assertFalse(result["errors"])
            self.assertEqual(result["guest_entry_return"], 0)
            expected = b'{"stage":"memory-only","url":"https://example.invalid/collect"}'
            self.assertTrue(any(item.get("source") == "managed_aes_plaintext" and
                                (root / "artifacts" / item["file"]).read_bytes() == expected
                                for item in result["artifacts"]))
            self.assertTrue(any(item.get("guest_path") ==
                                r"C:\Users\Alex\Downloads\emumee-threat-canary.json" and
                                (root / "artifacts" / item["file"]).read_bytes() == expected
                                for item in result["artifacts"]))
            report = json.loads((root / result["engine_report"]).read_text())
            self.assertTrue(any(event.get("event") == "network_denied"
                                for event in report["network_events"]))


@unittest.skipUnless(shutil.which("dotnet"), ".NET SDK is unavailable")
class StagedDeployerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        subprocess.run([sys.executable,
                        str(STAGED / "build_fixture.py")], check=True,
                       stdout=subprocess.DEVNULL)
        assembly = STAGED / "bin" / "Release" / "net8.0" / "ManagedStagedDeployer.dll"
        cls.data = assembly.read_bytes()
        cls.info = inspect_pe(cls.data, assembly.name)

    def test_guard_blocks_staged_actions(self):
        with tempfile.TemporaryDirectory() as directory:
            result = run_managed(self.data, self.info, load_persona(None),
                                 Path(directory), 1_000_000)
            self.assertFalse(result["errors"])
            self.assertEqual(result["guest_entry_return"], 2)
            self.assertFalse(result["artifacts"])

    def test_guest_decrypts_unpacks_invokes_and_logs_denial(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = run_managed(self.data, self.info, load_persona(None), root,
                                 1_000_000, guest_env={"EMUMEE_TEST": "virtual"})
            self.assertFalse(result["errors"])
            self.assertEqual(result["guest_entry_return"], 0)
            self.assertTrue(any(item.get("guest_path") ==
                                r"C:\Users\Alex\Downloads\emumee-stage-two.txt" and
                                (root / "artifacts" / item["file"]).read_bytes() ==
                                b"benign embedded stage reached"
                                for item in result["artifacts"]))
            report = json.loads((root / result["engine_report"]).read_text())
            events = [event.get("event") for event in report["events"]]
            self.assertIn("managed_aes_transform", events)
            self.assertIn("managed_zip_entry_open", events)
            self.assertIn("managed_assembly_load", events)
            self.assertIn("managed_reflect_invoke", events)
            self.assertTrue(any(event.get("event") == "network_denied"
                                for event in report["network_events"]))
