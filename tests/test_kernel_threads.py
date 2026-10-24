"""Real CPU probes for natural system-thread startup, blocking and resumption."""

import json
import struct
import tempfile
import unittest
from pathlib import Path
from emumee.driver import run_driver
from emumee.pe import inspect_pe
from emumee.persona import load_persona
from tests.test_kernel_objects import call_driver, simple_timer_probe, pending_dpc_probe, mdl_probe


def thread_probe(machine, mode="wait"):
    x64 = machine == 0x8664
    base = 0x140000000 if x64 else 0x400000
    names = ["KeInitializeEvent", "PsCreateSystemThread", "KeWaitForSingleObject",
             "KeSetEvent", "PsTerminateSystemThread", "KeAreApcsDisabled" if mode == "critical" else "PsGetCurrentThreadId",
             "ZwClose", "KeDelayExecutionThread"]
    many = mode in ("many-any", "many-all")
    thread_rva = 0x1180 if many or mode == "flags" else 0x1100
    if many: names[2] = "KeWaitForMultipleObjects"
    if mode == "priority": names[6] = "KeSetActualBasePriorityThread"
    if mode == "priority-lookup":
        names[5], names[6] = "MmGetSystemRoutineAddress", "PsGetCurrentThreadId"
    saved = (b"\x48\xbb" + struct.pack("<Q", 0x1234)) if x64 else b"\xbb" + struct.pack("<I", 0x1234)
    oa = (struct.pack("<I", 48) + bytes(20) + struct.pack("<I", 0x200) + bytes(20)) if x64 else struct.pack("<6I", 24, 0, 0, 0x200, 0, 0)
    operations = [(0, [base + 0x2300, 0, 0], None), (6 if mode == "priority-lookup" else 5, [], 0x2340),
                  (1, [base + 0x2320, 0x1FFFFF, base + 0x2380 if mode == "attributes" else 0, 0,
                       base + 0x23B8 if mode == "attributes" else 0, base + thread_rva, base + 0x2300], None)]
    if mode == "unload":
        register = b"\x48\xb8" + struct.pack("<Q", base + 0x1180) + bytes.fromhex("48894168") if x64 else bytes.fromhex("8b442404c74034") + struct.pack("<I", base + 0x1180)
        operations.insert(0, ("raw", register))
    if mode == "close": operations.append((6, [("load", 0x2320)], None))
    operations.append(("raw", saved))
    if many:
        operations.insert(1, (0, [base + 0x2328, 1, int(mode == "many-all")], None))
        operations.append((2, [2, base + 0x23C0, 0 if mode == "many-all" else 1, 0, 0, 0, 0, 0], None))
    elif mode == "poll":
        poll = b"\xa1" + (struct.pack("<Q", base + 0x2304) if x64 else struct.pack("<I", base + 0x2304)) + b"\x85\xc0"
        poll += b"\x74" + bytes([(-len(poll) - 2) & 255])
        operations.append(("raw", poll))
    elif mode != "return-first":
        operations.append((2, [base + 0x2300, 0, 0, 0, base + 0x23E8 if mode == "timeout" else 0], None))
    if mode == "flags":
        flags = bytes.fromhex("9c582500020000")
        flags += (b"\x48\xa3" + struct.pack("<Q", base + 0x2378)) if x64 else b"\xa3" + struct.pack("<I", base + 0x2378)
        operations.append(("raw", flags))
    tail = b"" if mode == "timeout" or many else b"\x89\xd8"
    array = b"".join((base + offset).to_bytes(8 if x64 else 4, "little") for offset in (0x2328, 0x2300))
    data = bytearray(call_driver(machine, names, operations, tail,
        [(0x2380, oa), (0x23C0, array), (0x23E0, struct.pack("<qq", -200000 if mode == "timeout" else -50000, -50000))]))
    if mode == "priority-lookup":
        text = "KeSetActualBasePriorityThread".encode("utf-16le")
        header = struct.pack("<HH", len(text), len(text) + 2) + (bytes(4) if x64 else b"") + (base + 0x2400).to_bytes(8 if x64 else 4, "little")
        data[0x7C0:0x7C0 + len(header)] = header
        data[0x800:0x802 + len(text)] = text + b"\0\0"
    code = bytearray(bytes.fromhex("4883ec284889cb") if x64 else bytes.fromhex("8b5c2404"))
    if mode == "flags":
        code.extend(bytes.fromhex("9c582500020000"))
        code.extend(b"\x48\xa3" + struct.pack("<Q", base + 0x2360) if x64 else b"\xa3" + struct.pack("<I", base + 0x2360))
    if mode == "fault": code.extend(b"\x0f\x0b")
    def invoke(index):
        if x64:
            code.extend(b"\xff\x15" + struct.pack("<i", 0x2900 + index * 8 - (thread_rva + len(code) + 6)))
        else:
            code.extend(b"\xff\x15" + struct.pack("<I", base + 0x2900 + index * 4))
    if mode == "priority-lookup":
        code.extend((b"\x48\xb9" + struct.pack("<Q", base + 0x23C0)) if x64 else b"\x68" + struct.pack("<I", base + 0x23C0))
    invoke(5)
    code.extend(b"\x48\xa3" + struct.pack("<Q", base + 0x2348) if x64 else b"\xa3" + struct.pack("<I", base + 0x2348))
    if mode in ("delay", "timeout"):
        if x64:
            code.extend(bytes.fromhex("31c931d249b8") + struct.pack("<Q", base + 0x23E0))
        else:
            code.extend(b"\x68" + struct.pack("<I", base + 0x23E0) + b"\x6a\x00\x6a\x00")
        invoke(7)
    if x64:
        code.extend(bytes.fromhex("65488b04258801000048a3") + struct.pack("<Q", base + 0x2350))
        if mode in ("priority", "priority-lookup"):
            code.extend(bytes.fromhex("4889c1ba0f000000"))
            if mode == "priority": invoke(6)
            else: code.extend(b"\x48\xa1" + struct.pack("<Q", base + 0x2348) + b"\xff\xd0")
        code.extend(bytes.fromhex("4889d931d24531c0"))
    else:
        code.extend(bytes.fromhex("64a124010000a3") + struct.pack("<I", base + 0x2350))
        if mode in ("priority", "priority-lookup"):
            code.extend(bytes.fromhex("6a0f50"))
            if mode == "priority": invoke(6)
            else: code.extend(b"\xa1" + struct.pack("<I", base + 0x2348) + b"\xff\xd0")
        code.extend(bytes.fromhex("6a006a0053"))
    if mode == "budget": code.extend(b"\xeb\xfe")
    if mode != "deadlock": invoke(3)
    code.extend(b"\x31\xc9" if x64 else b"\x6a\x00")
    invoke(4)
    code.extend(b"\x0f\x0b")
    raw = 0x200 + thread_rva - 0x1000
    data[raw:raw + len(code)] = code
    if mode == "unload":
        unload = (b"\x48\xb8" + struct.pack("<Q", base + 0x2370) if x64 else b"\xb8" + struct.pack("<I", base + 0x2370)) + b"\xc7\x00UL!!\x31\xc0" + (b"\xc3" if x64 else b"\xc2\x04\x00")
        data[0x380:0x380 + len(unload)] = unload
    return bytes(data)


def thread_chain_probe(machine):
    """The first child must wait for the second before it can wake DriverEntry."""
    x64 = machine == 0x8664
    base, width = (0x140000000, 8) if x64 else (0x400000, 4)
    names = ["KeInitializeEvent", "PsCreateSystemThread", "KeWaitForSingleObject",
             "KeSetEvent", "PsTerminateSystemThread"]
    operations = [(0, [base + offset, 1, int(offset == 0x2300)], None)
                  for offset in (0x2300, 0x2320, 0x2340)]
    for index, context in enumerate((0x2390, 0x2380)):
        operations.append((1, [base + 0x2360 + index * width, 0x1FFFFF, 0, 0, 0,
                               base + 0x1180, base + context], None))
    operations.extend([("raw", (b"\x48\xbb" + struct.pack("<Q", 0x1234)) if x64 else b"\xbb\x34\x12\x00\x00"),
                       (2, [base + 0x2340, 0, 0, 0, 0], None)])
    pointer = lambda value: (base + value).to_bytes(width, "little")
    contexts = pointer(0x2300) + pointer(0x2320) + bytes(16 - width * 2) + pointer(0x2320) + pointer(0x2340)
    data = bytearray(call_driver(machine, names, operations, b"\x89\xd8", [(0x2380, contexts)]))
    code = bytearray(bytes.fromhex("4883ec384889cb488b0b31d24531c04531c948c744242000000000") if x64
                     else bytes.fromhex("8b5c24046a006a006a006a00ff33"))
    def invoke(index):
        code.extend(b"\xff\x15" + struct.pack("<i" if x64 else "<I",
            0x2900 + index * width - (0x1180 + len(code) + 6) if x64 else base + 0x2900 + index * width))
    invoke(2)
    code.extend(bytes.fromhex("488b4b0831d24531c0") if x64 else bytes.fromhex("6a006a00ff7304"))
    invoke(3)
    code.extend(bytes.fromhex("31c9") if x64 else bytes.fromhex("6a00"))
    invoke(4)
    code.extend(b"\x0f\x0b")
    if len(code) > 128:
        raise ValueError("Thread-chain body exceeds its code slot")
    data[0x380:0x380 + len(code)] = code
    return bytes(data)


def thread_unload_probe(machine):
    """Unload wakes an idle worker and waits for its exit notification."""
    x64 = machine == 0x8664
    base, width = (0x140000000, 8) if x64 else (0x400000, 4)
    names = ["KeInitializeEvent", "PsCreateSystemThread", "KeWaitForSingleObject",
             "KeSetEvent", "PsTerminateSystemThread"]
    register = (b"\x48\xb8" + struct.pack("<Q", base + 0x1100) + bytes.fromhex("48894168")) if x64 else bytes.fromhex("8b442404c74034") + struct.pack("<I", base + 0x1100)
    operations = [("raw", register), (0, [base + 0x2300, 1, 0], None), (0, [base + 0x2320, 1, 0], None),
                  (1, [base + 0x2360, 0x1FFFFF, 0, 0, 0, base + 0x1180, base + 0x2380], None)]
    contexts = b"".join((base + offset).to_bytes(width, "little") for offset in (0x2300, 0x2320))
    data = bytearray(call_driver(machine, names, operations, b"\x31\xc0", [(0x2380, contexts)]))
    data[0x380:0x400] = thread_chain_probe(machine)[0x380:0x400]
    code = bytearray(bytes.fromhex("4883ec78") if x64 else b"")
    for index, values in ((3, [base + 0x2300, 0, 0]), (2, [base + 0x2320, 0, 0, 0, 0])):
        if x64:
            for position, value in enumerate(values):
                if position < 4:
                    code.extend((b"\x48\xb9", b"\x48\xba", b"\x49\xb8", b"\x49\xb9")[position] + struct.pack("<Q", value))
                else:
                    code.extend(bytes.fromhex("48c744242000000000"))
            code.extend(b"\xff\x15" + struct.pack("<i", 0x2900 + index * width - (0x1100 + len(code) + 6)))
        else:
            for value in reversed(values):
                code.extend(b"\x68" + struct.pack("<I", value))
            code.extend(b"\xff\x15" + struct.pack("<I", base + 0x2900 + index * width))
    code.extend(b"\x31\xc0" + (bytes.fromhex("4883c478c3") if x64 else bytes.fromhex("c20400")))
    if len(code) > 128:
        raise ValueError("Unload body exceeds its code slot")
    data[0x300:0x300 + len(code)] = code
    return bytes(data)


class KernelThreadTests(unittest.TestCase):
    def test_unload_releases_and_waits_for_a_quiescent_background_thread(self):
        for machine in (0x14C, 0x8664):
            with self.subTest(machine=machine), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                data = thread_unload_probe(machine)
                result = run_driver(data, inspect_pe(data, "unload.sys"), load_persona(None), root, 5, 4000, unload=True)
                report = json.loads((root / "engine-report.json").read_text())
                self.assertEqual(result["errors"], [], result)
                self.assertEqual(result["guest_entry_return"], 0)
                self.assertTrue(result["driver"]["unload_completed"])
                threads = report["kernel_scheduling"]["threads"]
                self.assertEqual(len(threads), 1)
                self.assertEqual(threads[0]["state"], "done")
                waits = [event for entry in report["entry_points"] for event in entry["events"]
                         if event.get("api_name") == "ntoskrnl.KeWaitForSingleObject"]
                self.assertEqual(len(waits), 2)
                self.assertTrue(all(event["ret_val"] == "0x0" for event in waits))

    def test_thread_priority_routine_is_resolved_through_guest_unicode_name(self):
        for machine in (0x14C, 0x8664):
            with self.subTest(machine=machine), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                data = thread_probe(machine, "priority-lookup")
                result = run_driver(data, inspect_pe(data, "priority.sys"), load_persona(None), root, 5, 4000)
                report = json.loads((root / "engine-report.json").read_text())
                self.assertEqual(result["errors"], [], result)
                self.assertEqual(result["guest_entry_return"], 0x1234)
                self.assertEqual(report["kernel_scheduling"]["threads"][0]["recorded_priority"], 15)
                lookups = [event for entry in report["entry_points"] for event in entry["events"]
                           if event.get("api_name") == "ntoskrnl.MmGetSystemRoutineAddress"]
                self.assertEqual(len(lookups), 1)
                self.assertEqual(lookups[0]["args"], ["KeSetActualBasePriorityThread"])
                self.assertGreater(int(lookups[0]["ret_val"], 0), 0)

    def test_two_children_chain_waits_with_distinct_contexts(self):
        for machine in (0x14C, 0x8664):
            with self.subTest(machine=machine), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                data = thread_chain_probe(machine)
                result = run_driver(data, inspect_pe(data, "chain.sys"), load_persona(None), root, 5, 4000)
                report = json.loads((root / "engine-report.json").read_text())
                self.assertEqual(result["errors"], [], result)
                self.assertEqual(result["guest_entry_return"], 0x1234)
                threads = report["kernel_scheduling"]["threads"]
                self.assertEqual(len(threads), 2)
                self.assertEqual(len({thread["tid"] for thread in threads}), 2)
                self.assertTrue(all(thread["state"] == "done" and thread["instruction_count"] > 0 for thread in threads))
                waits = [event for entry in report["entry_points"] for event in entry["events"]
                         if event.get("api_name") == "ntoskrnl.KeWaitForSingleObject"]
                self.assertEqual(len(waits), 3)
                self.assertTrue(all(event["ret_val"] == "0x0" for event in waits))

    def test_nonthread_lifecycle_and_mdl_probes_keep_their_behavior(self):
        for machine in (0x14C, 0x8664):
            for name, data, expected in (("timer", simple_timer_probe(machine), 1),
                    ("pending", pending_dpc_probe(machine), 0), ("mdl", mdl_probe(machine, "alias"), int.from_bytes(b"API!", "little"))):
                with self.subTest(machine=machine, case=name), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    result = run_driver(data, inspect_pe(data, "unchanged.sys"), load_persona(None), root, 5, 4000)
                    self.assertEqual(result["guest_entry_return"], expected)
                    if name == "pending":
                        self.assertEqual(result["errors"], ["Pending kernel timer DPCs require kernel callback scheduling"])
                    else:
                        self.assertEqual(result["errors"], [])

    def test_entry_waits_for_actual_thread_and_resumes_its_own_register_context(self):
        for machine in (0x14C, 0x8664):
            with self.subTest(machine=machine), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                data = thread_probe(machine)
                result = run_driver(data, inspect_pe(data, "thread.sys"), load_persona(None), root, 5, 4000)
                report = json.loads((root / "engine-report.json").read_text())
                self.assertEqual(result["errors"], [], result)
                self.assertEqual(result["guest_entry_return"], 0x1234)
                self.assertEqual(len(report["entry_points"]), 2)
                self.assertGreater(report["entry_points"][1]["instr_count"], 0)
                artifact = next(item for item in result["artifacts"] if item["source"] == "modified_driver_image:0x2000")
                image = (root / "artifacts" / artifact["file"]).read_bytes()
                width = 8 if machine == 0x8664 else 4
                parent = int.from_bytes(image[0x340:0x340 + width], "little")
                child = int.from_bytes(image[0x348:0x348 + width], "little")
                self.assertNotEqual(parent, child)
                self.assertEqual(int.from_bytes(image[0x350:0x350 + width], "little"),
                                 int(report["kernel_scheduling"]["threads"][0]["object"], 0))

    def test_waits_handles_object_attributes_critical_region_preemption_and_quiescence(self):
        for machine in (0x14C, 0x8664):
            for mode in ("close", "attributes", "critical", "delay", "timeout", "poll", "return-first", "deadlock", "budget", "fault", "unload", "many-any", "many-all", "priority"):
                with self.subTest(machine=machine, mode=mode), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    data = thread_probe(machine, mode)
                    result = run_driver(data, inspect_pe(data, "thread.sys"), load_persona(None), root, 5,
                                        300 if mode == "budget" else 4000, unload=mode == "unload")
                    report = json.loads((root / "engine-report.json").read_text())
                    if mode in ("deadlock", "budget", "fault"):
                        self.assertIsNone(result["guest_entry_return"])
                        self.assertTrue(result["errors"])
                        if mode == "budget":
                            self.assertEqual(result["instruction_count"], 300)
                            self.assertTrue(result["instruction_limit_reached"])
                    else:
                        self.assertEqual(result["errors"], [], result)
                        expected = 0x102 if mode == "timeout" else 1 if mode == "many-any" else 0 if mode == "many-all" else 0x1234
                        self.assertEqual(result["guest_entry_return"], expected)
                    if mode == "close": self.assertEqual(report["kernel_scheduling"]["open_thread_handles"], 0)
                    if mode == "priority": self.assertEqual(report["kernel_scheduling"]["threads"][0]["recorded_priority"], 15)
                    if mode == "unload":
                        self.assertTrue(result["driver"]["unload_completed"])
                        artifact = next(item for item in result["artifacts"] if item["source"] == "modified_driver_image:0x2000")
                        self.assertEqual((root / "artifacts" / artifact["file"]).read_bytes()[0x370:0x374], b"UL!!")
                    if mode == "critical":
                        artifact = next(item for item in result["artifacts"] if item["source"] == "modified_driver_image:0x2000")
                        image = (root / "artifacts" / artifact["file"]).read_bytes()
                        self.assertEqual(image[0x340], 0)
                        self.assertEqual(image[0x348], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
