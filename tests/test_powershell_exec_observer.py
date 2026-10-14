"""The native observer channel rejects tampering and preserves syscall argv."""

import hashlib
import hmac
import json
import tempfile
import unittest
from pathlib import Path

from emumee.dashboard import create_app
from emumee.powershell_probe_report import save_probe_run
from tools.probe_powershell_exec_observer import command_events, verified_events


class ExecObserverTests(unittest.TestCase):
    def signed(self, events, key=b"k" * 32):
        lines = []
        for event in events:
            body = json.dumps(event, separators=(",", ":")).encode("ascii")
            lines.append(hmac.new(key, body, hashlib.sha256).hexdigest().encode("ascii") + b" " + body)
        return b"\n".join(lines) + b"\n"

    def test_authenticated_ordered_lifecycle_and_forged_or_missing_records(self):
        events = [{"event": "observer_ready", "sequence": 1},
                  {"event": "native_exec_attempt", "sequence": 2},
                  {"event": "observer_finished", "sequence": 3}]
        raw = self.signed(events)
        self.assertEqual(verified_events(raw, b"k" * 32), events)
        for altered in (raw.replace(b"attempt", b"changed"), raw.splitlines()[0] + b"\n",
                        self.signed([events[0], events[2]]),
                        self.signed([events[1], events[0], events[2]]),
                        raw + b"script-forged-output\n", b""):
            with self.subTest(altered=altered[:80]), self.assertRaises(ValueError):
                verified_events(altered, b"k" * 32)
        with self.assertRaises(ValueError):
            verified_events(raw, b"wrong-key")

    def test_only_committed_execs_project_commands_with_exact_bytes(self):
        argv = [b"/bin/echo", b"space value", b'quote"value', b"", "café-✓".encode("utf-8"), b"\xff"]
        events = [{"event": "native_exec_attempt", "pid": 5, "sequence": 1,
                   "path_hex": b"/absent".hex(), "argv_hex": []},
                  {"event": "native_exec_attempt", "pid": 5, "sequence": 2,
                   "path_hex": b"/bin/echo".hex(), "argv_hex": [arg.hex() for arg in argv]},
                  {"event": "native_exec_committed", "pid": 5, "sequence": 3}]
        commands = command_events(events)
        self.assertEqual(len(commands), 1)
        self.assertEqual(commands[0]["native_arguments"],
                         ["space value", 'quote"value', "", "café-✓", r"\xff"])
        self.assertEqual([bytes.fromhex(value) for value in commands[0]["argv_hex"]], argv)
        self.assertEqual(commands[0]["phase"], "kernel_exec_committed")
        with self.assertRaises(ValueError):
            command_events([events[-1]])

    def test_dashboard_marks_external_source_denied_socket_and_missing_console(self):
        report = {"passed": True, "image": "fixed-probe-image", "capture_source": "external_linux_ptrace",
            "limitations": ["Native execs only; PowerShell cmdlets are not covered"],
            "probe": {"command_events": [{"command": "echo", "path": "/bin/echo",
                "capture": "external_linux_ptrace", "phase": "kernel_exec_committed",
                "native_arguments": ["after-breakpoint-removal", "café-✓", ""]}],
                "dropped_command_events": 0,
                "network_events": [{"event": "network_denied", "api": "linux.socket", "network_used": False}]}}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = save_probe_run(report, root, "fixed benign fixture")
            engine = json.loads((run / "engine-report.json").read_text())
            self.assertEqual(engine["command_capture"]["source"], "external_linux_ptrace")
            page = create_app(root).test_client().get(f"/runs/{run.name}")
            self.assertEqual(page.status_code, 200)
            html = page.get_data(as_text=True)
            for text in ("external_linux_ptrace", "after-breakpoint-removal", "café-✓", "linux.socket",
                         "No console capture in this report", "Command capture is incomplete"):
                self.assertIn(text, html)
