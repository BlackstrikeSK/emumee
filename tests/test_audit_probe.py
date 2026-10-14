"""Verify all requested audit behaviors using the contained native fixture."""
import json
import tempfile
import unittest
from pathlib import Path

from emumee.native import run_native
from emumee.pe import inspect_pe
from emumee.persona import load_persona
from tests.fixtures.NativeAuditProbe.build_fixture import build_probe, REGISTRY_KEY, TELEGRAM_URL


class AuditProbeTests(unittest.TestCase):
    def execute_probe(self, root, env=None):
        data = build_probe()
        result = run_native(data, inspect_pe(data, "audit_probe_x64.exe"),
                            load_persona(None), root, [], 5, 100_000, guest_env=env)
        return result, json.loads((root / result["engine_report"]).read_text())

    def test_guard_prevents_audit_actions(self):
        with tempfile.TemporaryDirectory() as directory:
            result, report = self.execute_probe(Path(directory))
            self.assertFalse(result["errors"])
            self.assertEqual(result["guest_exit_code"], 2)
            self.assertFalse(report["network_events"])
            self.assertFalse([event for event in report["virtual_registry_events"]
                              if event["event"] != "virtual_registry_process_cleanup"])
            self.assertFalse([event for event in report["virtual_process_events"]
                              if event["event"] == "virtual_process_create"])

    def test_all_three_attempts_are_logged(self):
        with tempfile.TemporaryDirectory() as directory:
            result, report = self.execute_probe(Path(directory), {"EMUMEE_TEST": "virtual"})
            writes = [e for e in report["virtual_registry_events"]
                      if e["event"] == "virtual_registry_write"]
            self.assertEqual([e["value"] for e in writes], ["ProbeState", "Canary"])
            self.assertTrue(all(e["status"] == 0 and e["key"].endswith(REGISTRY_KEY)
                                for e in writes))
            tasks = [e for e in report["virtual_process_events"]
                     if e["event"] == "virtual_process_create"]
            self.assertEqual(len(tasks), 1)
            self.assertIn("schtasks.exe /Create", tasks[0]["command_line"])
            self.assertTrue(tasks[0]["success"])
            self.assertEqual(tasks[0]["path"].casefold(),
                             r"C:\Windows\System32\schtasks.exe".casefold())
            self.assertTrue(any(event["event"] == "virtual_process_exit" and
                                event["pid"] == tasks[0]["pid"] and
                                event["exit_code"] == 87
                                for event in report["virtual_process_events"]))
            self.assertTrue(any(e.get("url") == TELEGRAM_URL for e in report["network_events"]))
            self.assertEqual(result["guest_exit_code"], 0)
