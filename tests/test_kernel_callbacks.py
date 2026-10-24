"""Registration must retain callback state without firing a crash callback."""

import json
import tempfile
import unittest
from pathlib import Path

from emumee.driver import run_driver
from emumee.pe import inspect_pe
from emumee.persona import load_persona
from tests.test_kernel_runtime import runtime_driver


def callback_probe(machine, mode="register", reason=2):
    base = 0x140000000 if machine == 0x8664 else 0x400000
    register = [base + 0x2300, base + 0x1100, reason, base + 0x2400]
    calls = [(0, register, False)]
    if mode == "duplicate":
        calls += [(0, register, False)]
    elif mode in ("deregister", "twice"):
        calls += [(1, [base + 0x2300], False)]
        if mode == "twice":
            calls += [(1, [base + 0x2300], False)]
    elif mode == "two-records":
        calls += [(0, [base + 0x2340, *register[1:]], False), (1, [base + 0x2300], False)]
    elif mode == "missing":
        calls = [(1, [base + 0x2300], False)]
    elif mode == "readonly":
        calls = [(0, [base + 0x1100, *register[1:]], False)]
    data = bytearray(runtime_driver(machine,
        ["KeRegisterBugCheckReasonCallback", "KeDeregisterBugCheckReasonCallback"], calls,
        [(0x2400, b"EMU\0")]))
    data[0x300:0x302] = b"\x0f\x0b"  # Any invented callback execution must fault.
    return bytes(data)


class KernelCallbackTests(unittest.TestCase):
    def run_probe(self, machine, mode, reason=2):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        data = callback_probe(machine, mode, reason)
        result = run_driver(data, inspect_pe(data, "callback.sys"), load_persona(None), root, 5, 2000)
        report = json.loads((root / "engine-report.json").read_text())
        item = next((item for item in result["artifacts"] if item["source"] == "modified_driver_image:0x2000"), None)
        image = (root / "artifacts" / item["file"]).read_bytes() if item else None
        return result, report, image

    def test_register_duplicate_and_deregister_preserve_boolean_and_record_state(self):
        for machine in (0x14C, 0x8664):
            for mode, expected, active in (("register", 1, 1), ("duplicate", 0, 1),
                    ("deregister", 1, 0), ("twice", 0, 0), ("missing", 0, 0)):
                with self.subTest(machine=machine, mode=mode):
                    result, report, image = self.run_probe(machine, mode)
                    self.assertEqual(result["errors"], [])
                    self.assertEqual(result["guest_entry_return"], expected)
                    callbacks = report["kernel_bugcheck_callbacks"]
                    self.assertEqual(len(callbacks["registered"]), active)
                    self.assertEqual(callbacks["callbacks_executed"], 0)
                    if image:
                        width = 8 if machine == 0x8664 else 4
                        self.assertEqual(image[0x300 + width * 5 + 4], active)
                        base = 0x140000000 if width == 8 else 0x400000
                        self.assertEqual(int.from_bytes(image[0x300 + width * 2:0x300 + width * 3], "little"), base + 0x1100)

    def test_removing_one_record_keeps_the_other_linked_to_the_kernel_list(self):
        for machine in (0x14C, 0x8664):
            with self.subTest(machine=machine):
                result, report, image = self.run_probe(machine, "two-records")
                self.assertEqual(result["errors"], [])
                active = report["kernel_bugcheck_callbacks"]["registered"]
                self.assertEqual(len(active), 1)
                width = 8 if machine == 0x8664 else 4
                base = 0x140000000 if width == 8 else 0x400000
                self.assertEqual(active[0]["record"], hex(base + 0x2340))
                self.assertEqual(image[0x340 + width * 5 + 4], 1)
                self.assertEqual(image[0x340:0x340 + width], image[0x340 + width:0x340 + width * 2])
                head = int.from_bytes(image[0x340:0x340 + width], "little")
                self.assertGreater(head, 0xFFFF800000000000 if width == 8 else 0x80000000)

    def test_reserved_reason_and_readonly_record_cannot_register(self):
        for machine in (0x14C, 0x8664):
            for mode, reason in (("register", 0), ("register", 8), ("readonly", 2)):
                with self.subTest(machine=machine, mode=mode, reason=reason):
                    result, report, _image = self.run_probe(machine, mode, reason)
                    self.assertEqual(report["kernel_bugcheck_callbacks"]["registered"], [])
                    if mode == "readonly":
                        self.assertIsNone(result["guest_entry_return"])
                        self.assertTrue(any("writable" in error for error in result["errors"]))
                    else:
                        self.assertEqual(result["guest_entry_return"], 0)
                        self.assertEqual(result["errors"], [])
