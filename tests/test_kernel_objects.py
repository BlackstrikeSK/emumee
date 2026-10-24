"""Harmless real CPU probes for kernel dispatcher, rundown and MDL state."""

import json
import struct
import tempfile
import unittest
from pathlib import Path

import emumee.driver as driver
from emumee.pe import inspect_pe
from emumee.persona import load_persona
from tests.test_kernel_runtime import runtime_driver


def cache_probe(machine, mode):
    x64 = machine == 0x8664
    base = 0x140000000 if x64 else 0x400000
    names = ["ExAllocateCacheAwareRundownProtection", "ExAcquireRundownProtectionCacheAwareEx",
             "ExReleaseRundownProtectionCacheAwareEx", "ExWaitForRundownProtectionReleaseCacheAware",
             "ExFreeCacheAwareRundownProtection"]
    code = bytearray()
    def call(index, values, fast=False):
        if x64:
            for position, value in enumerate(values):
                if value == "saved":
                    code.extend((b"\x48\x8b\x0d", b"\x48\x8b\x15")[position])
                    code.extend(struct.pack("<i", 0x2300 - (0x1004 + len(code) + 4)))
                else:
                    code.extend((b"\x48\xb9", b"\x48\xba")[position] + struct.pack("<Q", value))
            code.extend(b"\xff\x15" + struct.pack("<i", 0x2900 + index * 8 - (0x1004 + len(code) + 6)))
        else:
            for value in reversed(values[2:] if fast else values):
                code.extend(b"\xff\x35" + struct.pack("<I", base + 0x2300) if value == "saved" else b"\x68" + struct.pack("<I", value))
            if fast:
                for position, value in enumerate(values[:2]):
                    if value == "saved":
                        code.extend((b"\x8b\x0d", b"\x8b\x15")[position] + struct.pack("<I", base + 0x2300))
                    else:
                        code.extend((b"\xb9", b"\xba")[position] + struct.pack("<I", value))
            code.extend(b"\xff\x15" + struct.pack("<I", base + 0x2900 + index * 4))
    call(0, [0x600, 0x72546756])
    code.extend((b"\x48\xa3" + struct.pack("<Q", base + 0x2300)) if x64 else b"\xa3" + struct.pack("<I", base + 0x2300))
    call(1, ["saved", 1 if mode == "underflow" else 3], True)
    if mode == "underflow":
        call(2, ["saved", 2], True)
    elif mode == "blocked":
        call(3, ["saved"], True)
    else:
        call(2, ["saved", 3], True)
        call(3, ["saved"], True)
        call(1, ["saved", 1], True)
        if mode == "free":
            call(4, ["saved"])
            code.extend(b"\x31\xc0")
    return runtime_driver(machine, names, [], tail=bytes(code))


def call_driver(machine, names, operations, tail=b"", writes=()):
    x64 = machine == 0x8664
    base, width, start = (0x140000000, 8, 0x1004) if x64 else (0x400000, 4, 0x1000)
    code = bytearray()
    for operation in operations:
        if operation[0] == "raw":
            code.extend(operation[1])
            continue
        index, values, save = operation
        if x64:
            for position, value in enumerate(values):
                if position < 4:
                    if isinstance(value, tuple):
                        code.extend((b"\x48\x8b\x0d", b"\x48\x8b\x15", b"\x4c\x8b\x05", b"\x4c\x8b\x0d")[position])
                        code.extend(struct.pack("<i", value[1] - (start + len(code) + 4)))
                    else:
                        code.extend((b"\x48\xb9", b"\x48\xba", b"\x49\xb8", b"\x49\xb9")[position] + struct.pack("<Q", value))
                else:
                    code.extend(b"\x48\xb8" + struct.pack("<Q", value) + b"\x48\x89\x44\x24" + bytes([0x20 + (position - 4) * 8]))
            code.extend(b"\xff\x15" + struct.pack("<i", 0x2900 + index * width - (start + len(code) + 6)))
        else:
            for value in reversed(values):
                code.extend(b"\xff\x35" + struct.pack("<I", base + value[1]) if isinstance(value, tuple) else
                            b"\x68" + struct.pack("<I", value))
            code.extend(b"\xff\x15" + struct.pack("<I", base + 0x2900 + index * width))
        if save is not None:
            code.extend(b"\x48\xa3" + struct.pack("<Q", base + save) if x64 else b"\xa3" + struct.pack("<I", base + save))
    return runtime_driver(machine, names, [], writes, tail=bytes(code) + tail)


def mdl_probe(machine, mode):
    x64 = machine == 0x8664
    base = 0x140000000 if x64 else 0x400000
    width = 8 if x64 else 4
    pointer = lambda value: struct.pack("<Q" if x64 else "<I", base + value)
    load_rax = lambda rva: (b"\x48\xa1" if x64 else b"\xa1") + pointer(rva)
    store_rax = lambda rva: (b"\x48\xa3" if x64 else b"\xa3") + pointer(rva)
    prepare = load_rax(0x2300) + (b"\x48\x05" if x64 else b"\x05") + struct.pack("<I", 0x123)
    prepare += b"\xc7\x00EMU!" + store_rax(0x2320)
    size = (48 if x64 else 28) + 3 * width
    copy = load_rax(0x2310) + (b"\x48\x89\xc6\x48\xbf" if x64 else b"\x89\xc6\xbf") + pointer(0x2400)
    copy += b"\xb9" + struct.pack("<I", size) + bytes.fromhex("fcf3a4")
    names = ["ExAllocatePoolWithTag", "IoAllocateMdl", "MmBuildMdlForNonPagedPool", "IoFreeMdl", "MmGetPhysicalAddress", "MmMapLockedPagesSpecifyCache", "MmUnmapLockedPages", "RtlMoveMemory"]
    operations = [(0, [0x600, 0x4000, 0x72546756], 0x2300), ("raw", prepare),
                  (1, [("load", 0x2320), 0x2000, 0, 0, 0], 0x2310),
                  (2, [("load", 0x2310)], None), ("raw", copy),
                  (4, [("load", 0x2320)], 0x2330)]
    if mode == "free": operations.append((3, [("load", 0x2310)], None))
    if mode in ("alias", "readonly", "nx", "unmapped", "free-active"):
        operations.append((5, [("load", 0x2310), 1, 1, 0, 0, 0x80000000 if mode == "readonly" else 0], 0x2340))
        if mode == "nx": operations.append(("raw", load_rax(0x2340) + b"\xff\xd0"))
        elif mode == "free-active": operations.append((3, [("load", 0x2310)], None))
        else:
            operations.append(("raw", load_rax(0x2340) + b"\xc7\x00CPU!" + load_rax(0x2320) + b"\x8b\x00" + store_rax(0x2350)))
            operations.append((7, [("load", 0x2320), base + 0x2480, 4], None))
            operations.append(("raw", load_rax(0x2340) + b"\x8b\x00" + store_rax(0x2358)))
            operations.append((6, [("load", 0x2340), ("load", 0x2310)], None))
            operations.append((3, [("load", 0x2310)], None))
    tail = load_rax(0x2340 if mode == "unmapped" else 0x2320) + b"\x8b\x00"
    return call_driver(machine, names, operations, tail, [(0x2480, b"API!")])


def pending_dpc_probe(machine):
    x64 = machine == 0x8664
    base = 0x140000000 if x64 else 0x400000
    due = (1 << 64) - 10000000
    args = [base + 0x2300] + ([due] if x64 else [due & 0xFFFFFFFF, due >> 32]) + [0, base + 0x2380]
    data = bytearray(runtime_driver(machine, ["KeInitializeTimerEx", "KeInitializeDpc", "KeSetTimerEx"],
        [(0, [base + 0x2300, 0], False), (1, [base + 0x2380, base + 0x1100, 0], False), (2, args, False)]))
    data[0x300:0x302] = b"\x0f\x0b"  # Any invented callback execution faults.
    return bytes(data)


def simple_timer_probe(machine):
    x64 = machine == 0x8664
    base = 0x140000000 if x64 else 0x400000
    due = (1 << 64) - 10000000
    args = [base + 0x2300] + ([due] if x64 else [due & 0xFFFFFFFF, due >> 32]) + [0]
    return runtime_driver(machine, ["KeInitializeTimer", "KeSetTimer", "KeCancelTimer"],
        [(0, [base + 0x2300], False), (1, args, False), (2, [base + 0x2300], False)])


def readonly_api_probe(machine, size=4):
    base = 0x140000000 if machine == 0x8664 else 0x400000
    return call_driver(machine, ["ExAllocatePoolWithTag", "IoAllocateMdl", "MmBuildMdlForNonPagedPool",
            "MmMapLockedPagesSpecifyCache", "RtlMoveMemory"],
        [(0, [0x600, 4096, 0x72546756], 0x2300),
         (1, [("load", 0x2300), 16, 0, 0, 0], 0x2310), (2, [("load", 0x2310)], None),
         (3, [("load", 0x2310), 1, 1, 0, 0, 0x80000000], 0x2320),
         (4, [("load", 0x2320), base + 0x2480, size], None)],
        b"\x31\xc0", [(0x2480, b"API!")])


class KernelObjectTests(unittest.TestCase):
    def probe(self, machine, data):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = driver.run_driver(data, inspect_pe(data, "objects.sys"), load_persona(None), root, 5, 4000)
            report = json.loads((root / "engine-report.json").read_text())
            changes = [item for item in result["artifacts"] if item["source"] == "modified_driver_image:0x2000"]
            image = (root / "artifacts" / changes[0]["file"]).read_bytes() if changes else None
            pool = next((root / "artifacts" / item["file"] for item in result["artifacts"]
                         if item["source"].startswith("memory:api.pool.NonPagedPoolNx.VgTr")), None)
            state = {"rundown": report["kernel_cache_aware_rundown"], "mdls": report["kernel_mdls"],
                     "pool_bytes": pool.read_bytes() if pool else None}
            return result, report, image, state

    def test_cache_aware_acquire_release_rundown_free_and_blocking(self):
        for machine in (0x14C, 0x8664):
            for mode in ("complete", "free", "blocked", "underflow"):
                with self.subTest(machine=machine, mode=mode):
                    result, _, _, state = self.probe(machine, cache_probe(machine, mode))
                    if mode in ("blocked", "underflow"):
                        self.assertIsNone(result["guest_entry_return"])
                        self.assertTrue(any(("requires kernel thread scheduling" if mode == "blocked" else
                                             "exceeds acquired references") in error for error in result["errors"]), result)
                    else:
                        self.assertEqual(result["errors"], [])
                        self.assertEqual(result["guest_entry_return"], 0)
                    records = state["rundown"]["references"]
                    if mode == "free":
                        self.assertEqual(records, [])
                    elif mode == "complete":
                        self.assertEqual(records[0]["references"], 0)
                        self.assertTrue(records[0]["running_down"])

    def test_event_signal_consumption_and_zero_timeout(self):
        for machine in (0x14C, 0x8664):
            base = 0x140000000 if machine == 0x8664 else 0x400000
            for kind in (0, 1):
                with self.subTest(machine=machine, kind=kind):
                    data = runtime_driver(machine, ["KeInitializeEvent", "KeSetEvent", "KeWaitForSingleObject"],
                        [(0, [base + 0x2300, kind, 0], False), (1, [base + 0x2300, 0, 0], False),
                         (2, [base + 0x2300, 0, 0, 0, base + 0x23F0], False),
                         (2, [base + 0x2300, 0, 0, 0, base + 0x23F0], False)])
                    result, _, image, _ = self.probe(machine, data)
                    self.assertEqual(result["errors"], [])
                    self.assertEqual(result["guest_entry_return"], 0 if kind == 0 else 0x102)
                    self.assertEqual(int.from_bytes(image[0x304:0x308], "little"), 1 - kind)

    def test_timer_replacement_cancel_immediate_and_wait(self):
        for machine in (0x14C, 0x8664):
            x64 = machine == 0x8664
            base = 0x140000000 if x64 else 0x400000
            for mode in ("replace", "cancel", "notification", "synchronization"):
                with self.subTest(machine=machine, mode=mode):
                    due = ((1 << 64) - 10000000) if mode in ("replace", "cancel") else 0
                    arguments = [base + 0x2300] + ([due] if x64 else [due & 0xFFFFFFFF, due >> 32]) + [0, 0]
                    calls = [(0, [base + 0x2300, int(mode == "synchronization")], False), (1, arguments, False)]
                    if mode == "replace": calls.append((1, arguments, False))
                    elif mode == "cancel": calls.append((2, [base + 0x2300], False))
                    else:
                        calls.extend([(3, [base + 0x2300, 0, 0, 0, base + 0x23F0], False)] * 2)
                    data = runtime_driver(machine, ["KeInitializeTimerEx", "KeSetTimerEx", "KeCancelTimer", "KeWaitForSingleObject"], calls)
                    result, _, image, _ = self.probe(machine, data)
                    self.assertEqual(result["errors"], [])
                    self.assertEqual(result["guest_entry_return"], 1 if mode in ("replace", "cancel") else
                                     0x102 if mode == "synchronization" else 0)
                    self.assertEqual(image[0x300], 9 if mode == "synchronization" else 8)

    def test_due_dpc_stops_instead_of_skipping_the_callback(self):
        for machine in (0x14C, 0x8664):
            x64 = machine == 0x8664
            base = 0x140000000 if x64 else 0x400000
            arguments = [base + 0x2300] + ([0] if x64 else [0, 0]) + [0, base + 0x2380]
            data = runtime_driver(machine, ["KeInitializeTimerEx", "KeInitializeDpc", "KeSetTimerEx"],
                [(0, [base + 0x2300, 0], False), (1, [base + 0x2380, base + 0x1100, 0], False), (2, arguments, False)])
            result, _, _, _ = self.probe(machine, data)
            self.assertIsNone(result["guest_entry_return"])
            self.assertTrue(any("requires kernel callback scheduling" in error for error in result["errors"]), result)

    def test_finite_event_wait_and_delay_advance_guest_time(self):
        for machine in (0x14C, 0x8664):
            base = 0x140000000 if machine == 0x8664 else 0x400000
            data = runtime_driver(machine, ["KeInitializeEvent", "KeWaitForSingleObject", "KeDelayExecutionThread"],
                [(0, [base + 0x2300, 0, 0], False),
                 (1, [base + 0x2300, 0, 0, 0, base + 0x23E0], False),
                 (2, [0, 0, base + 0x23E8], False)],
                [(0x23E0, struct.pack("<qq", -200000, -300000))])
            result, report, _, _ = self.probe(machine, data)
            self.assertEqual(result["errors"], [])
            self.assertEqual(result["guest_entry_return"], 0)
            calls = report["entry_points"][0]["events"]
            wait = next(event for event in calls if event.get("api_name") == "ntoskrnl.KeWaitForSingleObject")
            self.assertEqual(int(wait["ret_val"], 0), 0x102)
            initial = load_persona(None)["uptime_ms"]
            self.assertGreaterEqual(report["virtual_uptime_ms"], initial + 50)
            self.assertLess(report["virtual_uptime_ms"], initial + 51)

    def test_timer_wait_advances_to_signal_before_timeout(self):
        for machine in (0x14C, 0x8664):
            x64 = machine == 0x8664
            base = 0x140000000 if x64 else 0x400000
            due = (1 << 64) - 100000
            args = [base + 0x2300] + ([due] if x64 else [due & 0xFFFFFFFF, due >> 32]) + [0, 0]
            data = runtime_driver(machine, ["KeInitializeTimerEx", "KeSetTimerEx", "KeWaitForSingleObject"],
                [(0, [base + 0x2300, 1], False), (1, args, False),
                 (2, [base + 0x2300, 0, 0, 0, base + 0x23F0], False)],
                [(0x23F0, struct.pack("<q", -200000))])
            result, report, image, _ = self.probe(machine, data)
            self.assertEqual(result["errors"], [])
            self.assertEqual(result["guest_entry_return"], 0)
            self.assertEqual(image[0x304:0x308], bytes(4))
            initial = load_persona(None)["uptime_ms"]
            self.assertGreaterEqual(report["virtual_uptime_ms"], initial + 10)
            self.assertLess(report["virtual_uptime_ms"], initial + 11)

    def test_direct_timer_reads_observe_cpu_time_and_pending_dpc(self):
        for machine in (0x14C, 0x8664):
            x64 = machine == 0x8664
            base = 0x140000000 if x64 else 0x400000
            for with_dpc in (False, True):
                with self.subTest(machine=machine, dpc=with_dpc):
                    due = (1 << 64) - 10
                    args = [base + 0x2300] + ([due] if x64 else [due & 0xFFFFFFFF, due >> 32]) + [0, base + 0x2380 if with_dpc else 0]
                    calls = [(0, [base + 0x2300, 0], False)]
                    if with_dpc: calls.append((1, [base + 0x2380, base + 0x1100, 0], False))
                    calls.append((2, args, False))
                    tail = bytes.fromhex("b964000000ffc975fca1") + (struct.pack("<Q", base + 0x2304) if x64 else struct.pack("<I", base + 0x2304))
                    data = runtime_driver(machine, ["KeInitializeTimerEx", "KeInitializeDpc", "KeSetTimerEx"], calls, tail=tail)
                    result, _, _, _ = self.probe(machine, data)
                    if with_dpc:
                        self.assertIsNone(result["guest_entry_return"])
                        self.assertTrue(any("kernel_timer_scheduling" in error and "requires kernel callback scheduling" in error
                                            for error in result["errors"]), result)
                    else:
                        self.assertEqual(result["errors"], [])
                        self.assertEqual(result["guest_entry_return"], 1)

    def test_nonpaged_mdl_preserves_kernel_address_and_buffer_lifetime(self):
        for machine in (0x14C, 0x8664):
            for mode in ("keep", "free", "alias"):
                with self.subTest(machine=machine, mode=mode):
                    result, _, image, state = self.probe(machine, mdl_probe(machine, mode))
                    self.assertEqual(result["errors"], [])
                    self.assertEqual(result["guest_entry_return"], int.from_bytes(b"API!" if mode == "alias" else b"EMU!", "little"))
                    x64 = machine == 0x8664
                    width, header, start = (8, 48, 32) if x64 else (4, 28, 16)
                    buffer = int.from_bytes(image[0x320:0x320 + width], "little")
                    descriptor = image[0x400:]
                    self.assertGreaterEqual(buffer, 0xFFFF800000000000 if x64 else 0x80000000)
                    self.assertEqual(struct.unpack_from("<HH", descriptor, width), (header + 3 * width, 4))
                    self.assertEqual(int.from_bytes(descriptor[start:start + width], "little"), buffer & ~4095)
                    mapped = 24 if x64 else 12
                    self.assertEqual(int.from_bytes(descriptor[mapped:mapped + width], "little"), buffer)
                    self.assertEqual(struct.unpack_from("<II", descriptor, start + width), (0x2000, 0x123))
                    frames = [int.from_bytes(descriptor[header + i * width:header + (i + 1) * width], "little") for i in range(3)]
                    self.assertEqual(len(set(frames)), 3)
                    self.assertEqual(int.from_bytes(image[0x330:0x330 + width], "little"), frames[0] * 4096 + 0x123)
                    self.assertEqual(state["mdls"]["descriptors"], 0 if mode in ("free", "alias") else 1)
                    if mode == "alias":
                        self.assertEqual(image[0x350:0x354], b"CPU!")
                        self.assertEqual(image[0x358:0x35C], b"API!")
                        self.assertEqual(state["mdls"]["user_aliases"], 0)

    def test_mdl_alias_protections_unmapping_and_active_descriptor_lifetime(self):
        for machine in (0x14C, 0x8664):
            for mode in ("readonly", "nx", "unmapped", "free-active"):
                with self.subTest(machine=machine, mode=mode):
                    result, _, image, state = self.probe(machine, mdl_probe(machine, mode))
                    self.assertIsNone(result["guest_entry_return"])
                    self.assertTrue(result["errors"])
                    if mode == "readonly":
                        self.assertEqual(state["pool_bytes"][0x123:0x127], b"EMU!")
                    if mode == "free-active":
                        self.assertTrue(any("MDL with active mappings" in error for error in result["errors"]))

    def test_pending_timer_dpc_does_not_turn_entry_return_into_complete_emulation(self):
        for machine in (0x14C, 0x8664):
            with self.subTest(machine=machine):
                result, report, _, _ = self.probe(machine, pending_dpc_probe(machine))
                self.assertEqual(result["guest_entry_return"], 0)
                self.assertEqual(result["completion_reason"], "error")
                self.assertEqual(result["errors"], ["Pending kernel timer DPCs require kernel callback scheduling"])
                self.assertTrue(report["kernel_dispatcher"]["timers"][0]["inserted"])

    def test_timer_aliases_use_the_full_x86_due_time_argument(self):
        for machine in (0x14C, 0x8664):
            with self.subTest(machine=machine):
                result, _, _, _ = self.probe(machine, simple_timer_probe(machine))
                self.assertEqual(result["errors"], [])
                self.assertEqual(result["guest_entry_return"], 1)

    def test_api_copy_cannot_write_a_readonly_mdl_alias(self):
        for machine in (0x14C, 0x8664):
            for size in (0, 4):
                with self.subTest(machine=machine, size=size):
                    result, _, _, state = self.probe(machine, readonly_api_probe(machine, size))
                    self.assertEqual(state["pool_bytes"][:4], bytes(4))
                    if size:
                        self.assertIsNone(result["guest_entry_return"])
                        self.assertTrue(any("read-only MDL alias" in error for error in result["errors"]))
                    else:
                        self.assertEqual(result["errors"], [])
                        self.assertEqual(result["guest_entry_return"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
