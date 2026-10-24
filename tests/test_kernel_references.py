"""Native object-type references and joins of real guest-created threads."""

import json
import struct
import tempfile
import unittest
from pathlib import Path

from emumee.driver import run_driver
from emumee.pe import inspect_pe
from emumee.persona import load_persona
from tests.fixtures.build_driver import build_driver


def reference_probe(machine, mode="join", mismatch_type="PsProcessType"):
    wide = machine == 0x8664
    base, width = (0x140000000, 8) if wide else (0x400000, 4)
    many = mode in ("many-any", "many-all")
    names = ["PsThreadType", mismatch_type, "KeInitializeEvent", "PsCreateSystemThread",
             "ObReferenceObjectByHandle", "ZwClose", "ObReferenceObjectByPointer", "KeSetEvent",
             "KeWaitForSingleObject", "PsTerminateSystemThread", "ObfDereferenceObject",
             "KeWaitForMultipleObjects" if many else "ObfReferenceObject"]

    class Code:
        def __init__(self, rva):
            self.rva = rva
            self.data = bytearray(bytes.fromhex("4883ec78") if wide else b"")

        def raw(self, data):
            self.data.extend(data)

        def load(self, slot):
            self.raw((b"\x48\xa1" if wide else b"\xa1") + (base + slot).to_bytes(width, "little"))

        def store(self, slot):
            self.raw((b"\x48\xa3" if wide else b"\xa3") + (base + slot).to_bytes(width, "little"))

        def invoke(self, index):
            operand = 0x2900 + index * width
            self.raw(b"\xff\x15" + (struct.pack("<i", operand - (self.rva + len(self.data) + 6)) if wide
                                    else struct.pack("<I", base + operand)))

        def call(self, index, values, save=None):
            if wide:
                for position, value in enumerate(values):
                    if isinstance(value, tuple):
                        assert position < 4
                        self.raw((b"\x48\x8b\x0d", b"\x48\x8b\x15", b"\x4c\x8b\x05", b"\x4c\x8b\x0d")[position])
                        self.raw(struct.pack("<i", value[1] - (self.rva + len(self.data) + 4)))
                    elif position < 4:
                        self.raw((b"\x48\xb9", b"\x48\xba", b"\x49\xb8", b"\x49\xb9")[position] + struct.pack("<Q", value))
                    else:
                        self.raw(b"\x48\xb8" + struct.pack("<Q", value) + b"\x48\x89\x44\x24" + bytes([0x20 + (position - 4) * 8]))
            else:
                for value in reversed(values):
                    self.raw(b"\xff\x35" + struct.pack("<I", base + value[1]) if isinstance(value, tuple)
                             else b"\x68" + struct.pack("<I", value))
            self.invoke(index)
            if save is not None:
                self.store(save)

        def fast(self, index):
            self.raw((b"\x48\x8b\x0d" if wide else b"\x8b\x0d") +
                     (struct.pack("<i", 0x2318 - (self.rva + len(self.data) + 7)) if wide
                      else struct.pack("<I", base + 0x2318)))
            self.invoke(index)

        def marker(self, slot, value):
            self.raw(b"\xb8" + value)
            self.store(slot)

        def returned(self, argument_bytes):
            self.raw(b"\x31\xc0" + (bytes.fromhex("4883c478c3") if wide else b"\xc2" + struct.pack("<H", argument_bytes)))

    root = Code(0x1000)
    for index, slot in ((0, 0x2300), (1, 0x2308)):
        root.load(0x2900 + index * width)
        root.raw(bytes.fromhex("488b00") if wide else bytes.fromhex("8b00"))
        root.store(slot)
    if mode.startswith("opaque-"):
        root.load(0x2300)
        root.raw(b"\xff\xd0" if mode == "opaque-exec" else bytes.fromhex("488b00") if wide else bytes.fromhex("8b00"))
    else:
        for event in (0x2400, 0x2440, 0x2480):
            root.call(2, [base + event, 0, 0])
        root.call(3, [base + 0x2310, 0x1FFFFF, 0, 0, 0, base + 0x1C00, 0])
        root.call(8, [base + 0x2440, 0, 0, 0, 0])
        expected_type = ("load", 0x2308 if mode == "handle-mismatch" else 0x2300)
        root.call(4, [0xBADC0DE if mode == "invalid-handle" else ("load", 0x2310),
                      0x100000, expected_type, 0, base + 0x1000 if mode == "readonly-output" else base + 0x2318, 0], 0x2320)
        if mode in ("handle-mismatch", "invalid-handle"):
            root.call(4, [("load", 0x2310), 0, ("load", 0x2300), 0, base + 0x2318, 0])
        root.call(5, [("load", 0x2310)])
        root.call(8, [("load", 0x2318), 0, 0, 0, base + 0x2390], 0x2328)
        selected_type = 0 if mode == "null-type" else ("load", 0x2308 if mode in ("kernel-mismatch", "user-mismatch") else 0x2300)
        root.call(6, [("load", 0x2318), 0x100000, selected_type,
                      1 if mode in ("user-mismatch", "user-access") else 0], 0x2330)
        if mode == "user-mismatch":
            root.call(6, [("load", 0x2318), 0, ("load", 0x2300), 0])
        root.call(7, [base + 0x2400, 0, 0])
        if many:
            root.load(0x2318)
            root.store(0x23A0)
            root.call(11, [2, base + 0x23A0, int(mode == "many-any"), 0, 0, 0, 0, 0], 0x2338)
        else:
            root.call(8, [("load", 0x2318), 0, 0, 0, 0], 0x2338)
        root.call(8, [("load", 0x2318), 0, 0, 0, base + 0x2390], 0x2340)
        root.load(0x2318)
        root.raw(b"\x8b\x40\x04")
        root.store(0x2350)
        if not many:
            root.fast(11)
        for _ in range(2 if many else 3):
            root.fast(10)
        if mode == "released-wait":
            root.call(8, [("load", 0x2318), 0, 0, 0, base + 0x2390])
        if mode == "released-reference":
            root.call(6, [("load", 0x2318), 0, 0, 0])
    root.marker(0x23F8, b"DONE")
    root.returned(8)

    child = Code(0x1C00)
    child.call(7, [base + 0x2440, 0, 0])
    child.call(8, [base + 0x2400, 0, 0, 0, 0])
    child.marker(0x2370, b"EXIT")
    if mode == "return":
        child.returned(4)
    else:
        child.call(9, [0x11223344])
        child.raw(b"\x0f\x0b")
    assert len(root.data) <= 0xC00 and len(child.data) <= 0x400

    original = build_driver(machine)
    data = bytearray(0x3200)
    data[:0x200] = original[:0x200]
    data[0x1200:0x1400] = original[0x400:0x600]
    section = 0x98 + (0xF0 if wide else 0xE0)
    struct.pack_into("<I", data, section + 8, 0x1000)
    struct.pack_into("<I", data, section + 16, 0x1000)
    struct.pack_into("<I", data, section + 48, 0x2000)
    struct.pack_into("<II", data, section + 56, 0x2000, 0x1200)
    struct.pack_into("<I", data, 0x98 + 56, 0x4000)
    struct.pack_into("<IIIII", data, 0x1200, 0x2800, 0, 0, 0x2060, 0x2900)
    for index, name in enumerate(names):
        rva = 0x2500 + index * 64
        encoded = b"\0\0" + name.encode() + b"\0"
        assert len(encoded) <= 64
        data[0x1200 + rva - 0x2000:0x1200 + rva - 0x2000 + len(encoded)] = encoded
        for table in (0x2800, 0x2900):
            struct.pack_into("<Q" if wide else "<I", data, 0x1200 + table - 0x2000 + index * width, rva)
    # Clear old fixture import entries after the new lookup/IAT terminators.
    for table in (0x2800, 0x2900):
        struct.pack_into("<Q" if wide else "<I", data, 0x1200 + table - 0x2000 + len(names) * width, 0)
    struct.pack_into("<Q" if wide else "<I", data, 0x1200 + 0x23A0 - 0x2000 + width,
                     base + (0x2400 if mode == "many-all" else 0x2480))
    data[0x200:0x200 + len(root.data)] = root.data
    data[0xE00:0xE00 + len(child.data)] = child.data
    return bytes(data)


def reference_bytes(result, root):
    item = next(item for item in result["artifacts"] if item["source"] == "modified_driver_image:0x2000")
    return (root / "artifacts" / item["file"]).read_bytes()


class KernelReferenceTests(unittest.TestCase):
    def probe(self, machine, mode):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        data = reference_probe(machine, mode)
        result = run_driver(data, inspect_pe(data, "references.sys"), load_persona(None), root, 5, 5000)
        report = json.loads((root / "engine-report.json").read_text())
        return result, report, reference_bytes(result, root)

    def test_native_type_references_join_termination_and_persistent_signal(self):
        for machine in (0x14C, 0x8664):
            for mode in ("join", "return", "many-any", "many-all", "null-type", "kernel-mismatch"):
                with self.subTest(machine=machine, mode=mode):
                    result, report, data = self.probe(machine, mode)
                    self.assertEqual(result["errors"], [])
                    self.assertEqual(result["guest_entry_return"], 0)
                    value = lambda offset: int.from_bytes(data[offset:offset + 4], "little")
                    self.assertEqual(value(0x320), 0)
                    self.assertEqual(value(0x328), 0x102)
                    self.assertEqual(value(0x330), 0)
                    self.assertEqual(value(0x338), 0)
                    self.assertEqual(value(0x340), 0)
                    self.assertEqual(value(0x350), 1)
                    self.assertEqual(data[0x370:0x374], b"EXIT")
                    self.assertEqual(data[0x3F8:0x3FC], b"DONE")
                    references = report["kernel_object_references"]
                    width = 8 if machine == 0x8664 else 4
                    thread_type = int.from_bytes(data[0x300:0x300 + width], "little")
                    process_type = int.from_bytes(data[0x308:0x308 + width], "little")
                    self.assertNotEqual(thread_type, process_type)
                    self.assertGreaterEqual(thread_type, 0xFFFF800000000000 if width == 8 else 0x80000000)
                    self.assertEqual(hex(thread_type), references["types"]["Thread"]["identity"])
                    self.assertEqual(hex(process_type), references["types"]["Process"]["identity"])
                    self.assertEqual(references["events"][-1]["references_after"], 0)
                    self.assertEqual(report["kernel_scheduling"]["open_thread_handles"], 0)
                    child = report["kernel_scheduling"]["threads"][0]
                    self.assertEqual(child["state"], "done")
                    self.assertEqual(hex(int.from_bytes(data[0x318:0x318 + width], "little")), child["object"])
                    self.assertEqual(child["exit_status"], None if mode == "return" else 0x11223344)

    def test_reference_statuses_do_not_fabricate_success_or_lose_the_real_handle(self):
        for machine in (0x14C, 0x8664):
            for mode, offset, expected in (("invalid-handle", 0x320, 0xC0000008),
                                           ("handle-mismatch", 0x320, 0xC0000024),
                                           ("user-mismatch", 0x330, 0xC0000024)):
                with self.subTest(machine=machine, mode=mode):
                    result, report, data = self.probe(machine, mode)
                    self.assertEqual(result["errors"], [])
                    self.assertEqual(result["guest_entry_return"], 0)
                    self.assertEqual(int.from_bytes(data[offset:offset + 4], "little"), expected)
                    self.assertEqual(report["kernel_object_references"]["events"][-1]["references_after"], 0)

    def test_unmodeled_access_and_released_objects_stop_before_following_code(self):
        for machine in (0x14C, 0x8664):
            for mode in ("user-access", "readonly-output", "released-wait", "released-reference", "opaque-read", "opaque-exec"):
                with self.subTest(machine=machine, mode=mode):
                    result, report, data = self.probe(machine, mode)
                    self.assertTrue(result["errors"])
                    self.assertIsNone(result["guest_entry_return"])
                    self.assertNotEqual(data[0x3F8:0x3FC], b"DONE")
                    if mode.startswith("opaque-"):
                        self.assertEqual(report["entry_points"][0]["error"]["type"],
                                         "invalid_execute" if mode == "opaque-exec" else "invalid_protect_read")
                        self.assertEqual(report["entry_points"][0]["error"]["address"],
                                         report["kernel_object_references"]["types"]["Thread"]["identity"])
