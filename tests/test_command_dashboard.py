"""Command observations retain evaluated data and report integrity in the UI."""

import hashlib
import html
import json
import tempfile
import unittest
from pathlib import Path

from emumee.dashboard import create_app
from emumee.powershell_probe_report import save_probe_run


def probe_report(events):
    return {"passed": True, "image": "fixed-test-image", "limitations": ["Fixed probe; capture is incomplete"],
            "probe": {"command_events": events, "dropped_command_events": 0,
                      "values": ["runtime-value"]}}


class CommandDashboardTests(unittest.TestCase):
    def test_display_json_preserves_unicode_and_safely_renders_punctuation(self):
        value = "Café 日本語 😀 'quoted' <script>alert(1)</script> & " + r"\u0041"
        event = {"event": "powershell_command_invocation", "command": "Write-Output",
                 "bound_parameters": {"InputObject": value}}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = save_probe_run(probe_report([event]), root, "fixed benign source")
            page = create_app(root).test_client().get(f"/runs/{run.name}")
            self.assertEqual(page.status_code, 200)
            markup = page.get_data(as_text=True)
            self.assertNotIn("<script>alert(1)</script>", markup)
            self.assertIn("&lt;script&gt;", markup)
            display = html.unescape(markup)
            self.assertIn("Café 日本語 😀 'quoted' <script>alert(1)</script> &", display)
            self.assertIn(r"\\u0041", display)
            for escaped in (r"\u00e9", r"\u003c", r"\u0027", r"\ud83d"):
                self.assertNotIn(escaped, display)

    def test_breakpoint_interruption_is_explicit_in_the_verified_report_and_page(self):
        report = probe_report([])
        report["probe"]["capture_integrity_events"] = [
            {"event": "powershell_capture_breakpoint_update", "update": "Disabled",
             "scope": "breakpoint-tamper", "breakpoint_id": 2,
             "timestamp_utc": "2026-10-14T20:32:43Z"},
            {"event": "powershell_capture_breakpoint_update", "update": "Removed",
             "scope": "breakpoint-tamper", "breakpoint_id": 2,
             "timestamp_utc": "2026-10-14T20:32:44Z"}]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = save_probe_run(report, root, "fixed benign source")
            engine = json.loads((run / "engine-report.json").read_text())
            self.assertEqual(engine["command_capture"]["observer_state"], "interrupted")
            page = create_app(root).test_client().get(f"/runs/{run.name}")
            self.assertEqual(page.status_code, 200)
            html = page.get_data(as_text=True)
            self.assertIn("Command observer interrupted", html)
            self.assertIn("Subsequent invocations may be absent", html)
            self.assertIn("Disabled", html)
            self.assertIn("Removed", html)
            self.assertIn("breakpoint-tamper", html)

    def test_structured_parameters_are_escaped_and_capture_limits_are_visible(self):
        event = {"event": "powershell_command_invocation", "command": "Write-Output",
                 "phase": "before_execution", "capture": "engine_debugger_command_processor",
                 "bound_parameters": {"InputObject": ["runtime-value", "<script>alert(1)</script>"]},
                 "native_arguments": None, "source_line": "& $name $value"}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = save_probe_run(probe_report([event]), root, "fixed benign source")
            page = create_app(root).test_client().get(f"/runs/{run.name}")
            self.assertEqual(page.status_code, 200)
            html = page.get_data(as_text=True)
            self.assertIn('id="commands"', html)
            self.assertIn("Evaluated parameters", html)
            self.assertIn("runtime-value", html)
            self.assertNotIn("<script>alert(1)</script>", html)
            self.assertIn("Command capture is incomplete", html)
            self.assertIn("PowerShell capture scope", html)
            self.assertNotIn("Observed WinAPI calls", html)

    def test_command_pages_preserve_native_argument_arrays(self):
        events = [{"event": "powershell_command_invocation", "command": f"command-{i}",
                   "native_arguments": ["space value", 'quote"value', ""]} for i in range(101)]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = save_probe_run(probe_report(events), root, "fixed benign source")
            client = create_app(root).test_client()
            page = client.get(f"/runs/{run.name}?commands_page=2")
            self.assertEqual(page.status_code, 200)
            commands = page.get_data(as_text=True).split('id="commands"', 1)[1].split('id="coverage"', 1)[0]
            self.assertIn("command-100", commands)
            self.assertNotIn("command-99", commands)
            self.assertIn("Native argument array", commands)
            self.assertIn("space value", commands)
            self.assertEqual(client.get(f"/runs/{run.name}?commands_page=3").status_code, 404)
            self.assertEqual(client.get(f"/runs/{run.name}?commands_page=-1").status_code, 400)

    def test_guest_process_command_lines_show_success_and_denial(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = save_probe_run(probe_report([]), root, "fixed benign source")
            path = run / "engine-report.json"
            engine = json.loads(path.read_text())
            engine["virtual_process_events"] = [
                {"event": "virtual_process_create", "path": r"C:\Windows\System32\ipconfig.exe",
                 "command_line": "ipconfig /all", "success": True},
                {"event": "virtual_process_create", "path": "missing.exe",
                 "command_line": "missing.exe <tag>", "success": False,
                 "reason": "executable absent from guest filesystem"}]
            data = json.dumps(engine).encode()
            path.write_bytes(data)
            summary_path = run / "summary.json"
            summary = json.loads(summary_path.read_text())
            summary.update(engine_report_sha256=hashlib.sha256(data).hexdigest(), engine_report_size=len(data))
            summary_path.write_text(json.dumps(summary))
            page = create_app(root).test_client().get(f"/runs/{run.name}")
            self.assertEqual(page.status_code, 200)
            html = page.get_data(as_text=True)
            self.assertIn("ipconfig /all", html)
            self.assertIn("guest_process_api", html)
            self.assertIn("rejected", html)
            self.assertIn("missing.exe &lt;tag&gt;", html)

    def test_modified_command_report_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = save_probe_run(probe_report([]), root, "fixed benign source")
            with (run / "engine-report.json").open("ab") as output:
                output.write(b" ")
            self.assertEqual(create_app(root).test_client().get(f"/runs/{run.name}").status_code, 404)


if __name__ == "__main__":
    unittest.main()
