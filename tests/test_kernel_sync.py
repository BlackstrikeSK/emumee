"""Actual guest calls check synchronization state, IRQL and blocked operations."""

import json
import struct
import tempfile
import unittest
from pathlib import Path

from emumee.driver import run_driver
from emumee.pe import inspect_pe
from emumee.persona import load_persona
from tests.test_kernel_runtime import runtime_driver


def sync_probe(machine, kind, mode):
    x64 = machine == 0x8664
    base, width = (0x140000000, 8) if x64 else (0x400000, 4)
    pointer = base + 0x2300
    read_irql = bytes.fromhex("440f20c0") if x64 else bytes.fromhex("640fb60524000000")
    read_value = (b"\x48\xb8" + struct.pack("<Q", pointer) + b"\x48\x8b\x00" if x64 else b"\xa1" + struct.pack("<I", pointer))
    tail = read_value
    if kind == "guarded":
        names = ["KeInitializeGuardedMutex", "KeAcquireGuardedMutex", "KeReleaseGuardedMutex"]
        calls = [(0, [pointer], False), (1, [pointer], False)]
        if mode == "released":
            calls += [(2, [pointer], False)]
        elif mode == "blocked":
            calls += [(1, [pointer], False)]
        tail = read_irql
    elif kind == "rundown":
        names = ["ExInitializeRundownProtection", "ExAcquireRundownProtection", "ExReleaseRundownProtection", "ExWaitForRundownProtectionRelease"]
        calls = [(0, [pointer], "fastcall")]
        if mode == "count":
            calls += [(1, [pointer], "fastcall"), (1, [pointer], "fastcall"), (2, [pointer], "fastcall")]
        elif mode == "complete":
            calls += [(3, [pointer], "fastcall"), (1, [pointer], "fastcall")]
            tail = b""  # BOOLEAN refusal after rundown is the result.
        else:
            calls += [(1, [pointer], "fastcall"), (3, [pointer], "fastcall")]
    elif kind == "push":
        names = ["ExInitializePushLock", "KeEnterCriticalRegion", "ExAcquirePushLockExclusiveEx", "ExReleasePushLockExclusiveEx", "KeLeaveCriticalRegion"]
        calls = [(0, [pointer], False), (1, [], False), (2, [pointer, 0], "fastcall")]
        if mode == "released":
            calls += [(3, [pointer, 0], "fastcall"), (4, [], False)]
        elif mode == "blocked":
            calls += [(2, [pointer, 0], "fastcall")]
    elif kind == "irql":
        names = ["KfRaiseIrql", "KeGetCurrentIrql", "KeLowerIrql"]
        calls = [(0, [2], "fastcall")]
        tail = read_irql
        if mode == "lowered":
            calls += [(2, [0], "fastcall")]
        elif mode == "previous":
            calls += [(0, [3], "fastcall")]
            tail = b""
        elif mode == "direct":
            calls = []
            tail = (bytes.fromhex("b902000000440f22c1") + b"\x48\xb8" + struct.pack("<Q", base + 0x2900 + width) + b"\xff\x10" if x64 else
                    bytes.fromhex("64c6052400000002ff15") + struct.pack("<I", base + 0x2900 + width))
    else:
        names = ["KeEnterCriticalRegion", "KeAreAllApcsDisabled" if mode == "all" else "KeAreApcsDisabled", "KeLeaveCriticalRegion"]
        calls = [(0, [], False)]
        if mode == "released":
            calls += [(2, [], False)]
        calls += [(1, [], False)]
        tail = b""
    return runtime_driver(machine, names, calls, tail=tail)


class KernelSynchronizationTests(unittest.TestCase):
    def run_probe(self, machine, kind, mode):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        data = sync_probe(machine, kind, mode)
        result = run_driver(data, inspect_pe(data, "sync.sys"), load_persona(None), root, 5, 2000)
        report = json.loads((root / "engine-report.json").read_text())
        item = next((item for item in result["artifacts"] if item["source"] == "modified_driver_image:0x2000"), None)
        image = (root / "artifacts" / item["file"]).read_bytes() if item else None
        return result, report, image

    def test_guarded_mutex_changes_native_irql_owner_and_restores_on_release(self):
        for machine in (0x14C, 0x8664):
            for mode in ("held", "released", "blocked"):
                with self.subTest(machine=machine, mode=mode):
                    result, report, image = self.run_probe(machine, "guarded", mode)
                    width = 8 if machine == 0x8664 else 4
                    self.assertEqual(struct.unpack_from("<I", image, 0x300)[0], 1 if mode == "released" else 0)
                    owner = int.from_bytes(image[0x300 + width:0x300 + width * 2], "little")
                    self.assertEqual(owner, 0 if mode == "released" else int(report["kernel_context"]["thread"], 0))
                    self.assertEqual(report["kernel_synchronization"]["irql"], 0 if mode == "released" else 1)
                    if mode == "blocked":
                        self.assertIsNone(result["guest_entry_return"])
                        self.assertTrue(any("requires kernel thread scheduling" in error for error in result["errors"]))
                    else:
                        self.assertEqual(result["errors"], [])
                        self.assertEqual(result["guest_entry_return"], 0 if mode == "released" else 1)

    def test_rundown_reference_count_refusal_and_blocking_wait_are_distinct(self):
        for machine in (0x14C, 0x8664):
            for mode, expected, count in (("count", 2, 2), ("complete", 0, 1), ("blocked", None, 3)):
                with self.subTest(machine=machine, mode=mode):
                    result, _, image = self.run_probe(machine, "rundown", mode)
                    width = 8 if machine == 0x8664 else 4
                    self.assertEqual(int.from_bytes(image[0x300:0x300 + width], "little"), count)
                    self.assertEqual(result["guest_entry_return"], expected)
                    self.assertEqual(bool(result["errors"]), mode == "blocked")

    def test_push_lock_release_and_contended_acquisition_preserve_state(self):
        for machine in (0x14C, 0x8664):
            for mode in ("held", "released", "blocked"):
                with self.subTest(machine=machine, mode=mode):
                    result, report, _image = self.run_probe(machine, "push", mode)
                    self.assertEqual(report["kernel_synchronization"]["critical_region_depth"], 0 if mode == "released" else 1)
                    self.assertEqual(result["guest_entry_return"], None if mode == "blocked" else 0 if mode == "released" else 1)
                    self.assertEqual(bool(result["errors"]), mode == "blocked")

    def test_irql_api_and_direct_cpu_state_agree_on_both_architectures(self):
        for machine in (0x14C, 0x8664):
            for mode, expected, irql in (("raised", 2, 2), ("lowered", 0, 0), ("previous", 2, 3), ("direct", 2, 2)):
                with self.subTest(machine=machine, mode=mode):
                    result, report, _image = self.run_probe(machine, "irql", mode)
                    self.assertEqual(result["errors"], [])
                    self.assertEqual(result["guest_entry_return"], expected)
                    self.assertEqual(report["kernel_synchronization"]["irql"], irql)

    def test_critical_region_distinguishes_normal_from_all_apc_disabling(self):
        for machine in (0x14C, 0x8664):
            for mode, expected, depth in (("held", 1, 1), ("released", 0, 0), ("all", 0, 1)):
                with self.subTest(machine=machine, mode=mode):
                    result, report, _image = self.run_probe(machine, "critical", mode)
                    self.assertEqual(result["errors"], [])
                    self.assertEqual(result["guest_entry_return"], expected)
                    self.assertEqual(report["kernel_synchronization"]["critical_region_depth"], depth)

    def test_cr8_extended_registers_and_invalid_value_do_not_silently_use_cr0(self):
        for valid in (True, False):
            with self.subTest(valid=valid), tempfile.TemporaryDirectory() as directory:
                tail = (bytes.fromhex("49b80200000000000000450f22c0450f20c14c89c8") if valid else
                        bytes.fromhex("b910000000440f22c1"))
                data = runtime_driver(0x8664, ["KeGetCurrentIrql"], [], tail=tail)
                root = Path(directory)
                result = run_driver(data, inspect_pe(data, "cr8.sys"), load_persona(None), root, 5, 2000)
                self.assertEqual(result["guest_entry_return"], 2 if valid else None)
                if valid:
                    self.assertEqual(result["errors"], [])
                else:
                    self.assertTrue(any("invalid_cr8_write" in error for error in result["errors"]))
