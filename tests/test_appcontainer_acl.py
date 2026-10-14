"""Regression checks for temporary AppContainer ACL bookkeeping."""

from __future__ import annotations

import tempfile
import unittest
import ctypes
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from emumee.appcontainer import AppContainer


class AppContainerAclTests(unittest.TestCase):
    def test_nonrecursive_directory_grant_does_not_inherit_into_files(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "run"
            target.mkdir()
            (target / "input.pe").write_bytes(b"harmless")
            box = AppContainer.__new__(AppContainer)
            box.sid_string = "S-1-15-2-123"
            box.granted_roots = {}
            outcome = SimpleNamespace(returncode=0, stderr="", stdout="")
            with patch("emumee.appcontainer.subprocess.run", return_value=outcome) as command:
                box.grant(target, "RX", recursive=False)
                box.revoke(target)
            grant, revoke = (call.args[0] for call in command.call_args_list)
            self.assertNotIn("/T", grant)
            self.assertNotIn("/T", revoke)
            self.assertIn("*S-1-15-2-123:RX", grant)
            self.assertFalse(any("(OI)(CI)" in item for item in grant))
            self.assertEqual(box.granted_roots, {})

    def test_recursive_grant_accepts_single_linked_nested_file(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "run"
            (target / "nested").mkdir(parents=True)
            (target / "nested" / "ordinary.bin").write_bytes(b"harmless")
            box = AppContainer.__new__(AppContainer)
            box.sid_string = "S-1-15-2-123"
            box.granted_roots = {}
            outcome = SimpleNamespace(returncode=0, stderr="", stdout="")
            with patch("emumee.appcontainer.subprocess.run", return_value=outcome) as command:
                box.grant(target, "M")
                box.revoke(target)
            self.assertEqual(command.call_count, 2)
            self.assertEqual(box.granted_roots, {})

    def test_recursive_grant_and_revoke_refuse_nested_hardlink(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            target = root / "run"
            target.mkdir()
            outside = root / "outside.txt"
            outside.write_text("harmless marker", encoding="utf-8")
            link = target / "linked.txt"
            try:
                link.hardlink_to(outside)
            except OSError:
                self.skipTest("Host does not permit disposable hardlink creation")
            box = AppContainer.__new__(AppContainer)
            box.sid_string = "S-1-15-2-123"
            box.granted_roots = {}
            with patch("emumee.appcontainer.subprocess.run") as command:
                with self.assertRaisesRegex(OSError, "linked or unsafe file"):
                    box.grant(target, "M")
                command.assert_not_called()
                box.granted_roots[str(target.absolute()).casefold()] = (target.resolve(), True)
                with self.assertRaisesRegex(OSError, "linked or unsafe file"):
                    box.revoke(target)
                command.assert_not_called()

    def test_launch_terminates_suspended_worker_after_assignment_failure(self) -> None:
        class Kernel:
            def __init__(self):
                self.calls = []

            def InitializeProcThreadAttributeList(self, buffer, count, flags, size):
                if buffer is None:
                    size._obj.value = 64
                return True

            def UpdateProcThreadAttribute(self, *args):
                return True

            def CreateProcessW(self, *args):
                info = args[-1]._obj
                info.hProcess = 123
                info.hThread = 456
                return True

            def TerminateProcess(self, process, code):
                self.calls.append(("terminate", process, code))
                return True

            def WaitForSingleObject(self, process, timeout):
                self.calls.append(("wait", process, timeout))
                return 0

            def CloseHandle(self, handle):
                self.calls.append(("close", handle))
                return True

            def DeleteProcThreadAttributeList(self, value):
                pass

        box = AppContainer.__new__(AppContainer)
        box.kernel = Kernel()
        box.sid = ctypes.c_void_p(1)
        box.capability_sid = ctypes.c_void_p()
        box.lpac = False
        job = SimpleNamespace(assign_handle=lambda _: (_ for _ in ()).throw(OSError("assign failed")))
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaisesRegex(OSError, "assign failed"):
                box.launch(["harmless.exe"], Path(folder), 1, job=job)
        self.assertEqual(box.kernel.calls[:2], [("terminate", 123, 1), ("wait", 123, 5000)])
        self.assertIn(("close", 456), box.kernel.calls)
        self.assertIn(("close", 123), box.kernel.calls)

    def test_failed_recursive_grant_is_still_cleaned_up(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder)
            box = AppContainer.__new__(AppContainer)
            box.sid_string = "S-1-15-2-123"
            box.granted_roots = {}
            outcomes = [SimpleNamespace(returncode=1, stderr="partial failure", stdout=""),
                        SimpleNamespace(returncode=0, stderr="", stdout="")]
            with patch("emumee.appcontainer.subprocess.run", side_effect=outcomes) as command:
                with self.assertRaisesRegex(OSError, "partial failure"):
                    box.grant(target, "M")
                box.revoke(target)
                box.revoke(target)
            self.assertEqual(command.call_count, 2)
            for call in command.call_args_list:
                self.assertIn("/L", call.args[0])
            self.assertEqual(box.granted_roots, {})


if __name__ == "__main__":
    unittest.main()
