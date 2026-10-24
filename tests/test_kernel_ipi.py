"""Native guest callbacks test processor broadcasts and caller restoration."""

import json
import struct
import tempfile
import unittest
from pathlib import Path

from emumee.driver import run_driver
from emumee.pe import inspect_pe
from emumee.persona import load_persona
from tests.test_kernel_objects import call_driver


def ipi_probe(machine, mode="basic", logical=4):
    x64 = machine == 0x8664
    base, width = (0x140000000, 8) if x64 else (0x400000, 4)
    names = ["KeIpiGenericCall", "KeGetCurrentProcessorNumberEx", "KeGetCurrentIrql", "KeInitializeEvent",
             "PsCreateSystemThread", "KeWaitForSingleObject", "KeSetEvent", "PsTerminateSystemThread"]
    operations = []
    if mode == "background":
        operations.extend((3, [base + offset, 1, 0], None) for offset in (0x2300, 0x2320, 0x2340))
        operations.extend([(4, [base + 0x2360, 0x1FFFFF, 0, 0, 0, base + 0x1800, base + 0x2300], None),
                           (5, [base + 0x2300, 0, 0, 0, 0], None)])
    marker = 0x1122334455667788 if x64 else 0xAABBCCDD
    operations.append(("raw", (b"\x48\xbb" if x64 else b"\xbb") + marker.to_bytes(width, "little")))
    operations.append((0, [base + (0x2A00 if mode == "invalid" else 0x1400), base + 0x2A00], 0x2F00))
    if mode == "repeat": operations.append((0, [base + 0x1400, base + 0x2C00], 0x2F20))
    save = (b"\x48\xb8" if x64 else b"\xb8") + (base + 0x2F18).to_bytes(width, "little")
    operations.extend([("raw", save + (bytes.fromhex("488918") if x64 else bytes.fromhex("8918"))),
                       (1, [0], 0x2F08), (2, [], 0x2F10)])
    if mode == "background":
        operations.extend([(6, [base + 0x2320, 0, 0], None), (5, [base + 0x2340, 0, 0, 0, 0], None)])
    tail = b"\xa1" + (base + 0x2F00).to_bytes(width, "little")
    original = bytearray(call_driver(machine, names, operations, tail, [(0x2F00, b"\xcc" * 32)]))
    section = 0x98 + (0xF0 if x64 else 0xE0)
    struct.pack_into("<I", original, section + 8, 0x1000)
    struct.pack_into("<I", original, section + 16, 0x1000)
    struct.pack_into("<I", original, section + 40 + 20, 0x1200)
    data = original[:0x400] + bytes(0xE00) + original[0x400:]

    def emit(rva, instructions):
        code = bytearray()
        for instruction in instructions:
            if isinstance(instruction, bytes):
                code.extend(instruction)
            else:
                index = instruction
                code.extend(b"\xff\x15" + struct.pack("<i" if x64 else "<I",
                    0x2900 + index * width - (rva + len(code) + 6) if x64 else base + 0x2900 + index * width))
        offset = 0x200 + rva - 0x1000
        data[offset:offset + len(code)] = code

    instructions = [bytes.fromhex("4883ec384889cb31c9") if x64 else bytes.fromhex("8b5c24046a00"), 1,
        bytes.fromhex("4889c748c1e7064801df890748896720") if x64 else bytes.fromhex("89c7c1e70601df8907896720"), 2,
        bytes.fromhex("894704b80b000000b9010000000fa28957080f01f9894f0cb80100000031c90fa2c1eb18895f14"),
        bytes.fromhex("658b0425a401000089471065488b04258801000048894718") if x64 else
            bytes.fromhex("640fb6055100000089471064a124010000894718"),
        bytes.fromhex("488d4f28") if x64 else bytes.fromhex("8d472850"), 1]
    instructions.append(bytes.fromhex("b9030100c00f3289472c"))
    if not x64: instructions.append(bytes.fromhex("64a148000000894730"))
    instructions.append(bytes.fromhex("0f20c0894734480f01e08947380f20e089473c" if x64 else
                                      "0f20c08947340f01e08947380f20e089473c"))
    instructions.append(bytes.fromhex("9c582500020000894730" if x64 else "9c58250002000089471c"))
    if mode in ("barrier", "budget"):
        instructions.append((b"\x48\xb8" if x64 else b"\xb8") + (base + 0x2E80).to_bytes(width, "little") +
            bytes.fromhex("f0ff008338") + bytes([logical]) + bytes.fromhex("75fb"))
    if mode == "fault": instructions.append(bytes.fromhex("833f0175020f0b"))
    if mode == "nested":
        instructions.extend([(b"\x48\xb9" + struct.pack("<Q", base + 0x1400) + b"\x48\xba" + struct.pack("<Q", base + 0x2A00)) if x64
                             else b"\x68" + struct.pack("<I", base + 0x2A00) + b"\x68" + struct.pack("<I", base + 0x1400), 0])
    if mode == "terminate":
        instructions.extend([bytes.fromhex("31c9") if x64 else bytes.fromhex("6a00"), 7])
    if mode == "irql":
        instructions.append(bytes.fromhex("31c0440f22c0") if x64 else bytes.fromhex("64c6052400000000"))
    if mode == "wide" and x64:
        instructions.append(b"\x8b\x0f\x48\xb8" + struct.pack("<Q", 0x1234567800001234) + bytes.fromhex("4801c8"))
    else:
        instructions.append(bytes.fromhex("8b070534120000"))
    instructions.append(bytes.fromhex("4883c438c3") if x64 else bytes.fromhex("c20400"))
    emit(0x1400, instructions)
    if mode == "background":
        emit(0x1800, [bytes.fromhex("4883ec384889cb4889d931d24531c0") if x64 else bytes.fromhex("8b5c24046a006a0053"), 6,
            bytes.fromhex("488d4b2031d24531c04531c948c744242000000000") if x64 else bytes.fromhex("6a006a006a006a008d432050"), 5,
            bytes.fromhex("488d4b4031d24531c0") if x64 else bytes.fromhex("6a006a008d434050"), 6,
            bytes.fromhex("31c9") if x64 else bytes.fromhex("6a00"), 7, bytes.fromhex("0f0b")])
    return bytes(data)


class KernelIpiTests(unittest.TestCase):
    def run_probe(self, machine, mode, logical=4):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        persona = load_persona(None)
        persona["cpu"]["cores"], persona["cpu"]["threads_per_core"] = logical, 1
        data = ipi_probe(machine, mode, logical)
        result = run_driver(data, inspect_pe(data, "ipi.sys"), persona, root, 5, 50 if mode == "budget" else 20000)
        report = json.loads((root / "engine-report.json").read_text())
        return result, report, root

    def test_callbacks_agree_on_cpu_identity_irql_and_preserve_the_caller(self):
        for machine in (0x14C, 0x8664):
            for mode, logical in (("basic", 1), ("basic", 4), ("basic", 12), ("wide", 4), ("background", 4)):
                with self.subTest(machine=machine, mode=mode, logical=logical):
                    result, report, root = self.run_probe(machine, mode, logical)
                    self.assertEqual(result["errors"], [], result)
                    self.assertEqual(result["guest_entry_return"], 0x1234)
                    group = report["kernel_ipi"]["broadcasts"][0]
                    self.assertTrue(group["completed"])
                    self.assertEqual(len(group["callbacks"]), logical)
                    self.assertTrue(all(row["started"] and row["instruction_count"] > 0 for row in group["callbacks"]))
                    item = next(item for item in result["artifacts"] if item["source"] == "modified_driver_image:0x2000")
                    image = (root / "artifacts" / item["file"]).read_bytes()
                    width = 8 if machine == 0x8664 else 4
                    stacks, threads = set(), set()
                    for number in range(logical):
                        values = struct.unpack_from("<6I", image, 0xA00 + number * 64)
                        self.assertEqual(values, (number, 14 if width == 8 else 29, number, number, number, number))
                        self.assertEqual(image[0xA28 + number * 64:0xA2C + number * 64], bytes([0, 0, number, 0]))
                        self.assertEqual(struct.unpack_from("<I", image, 0xA2C + number * 64)[0], number)
                        if width == 4:
                            self.assertEqual(struct.unpack_from("<I", image, 0xA30 + number * 64)[0], 1 << number)
                        cr0, msw, cr4 = struct.unpack_from("<3I", image, 0xA34 + number * 64)
                        self.assertEqual(cr0, 0x80050033)
                        self.assertEqual(msw, cr0)
                        self.assertTrue(cr4 & 0x20)
                        self.assertEqual(struct.unpack_from("<I", image, 0xA00 + number * 64 + (48 if width == 8 else 28))[0], 0)
                        threads.add(int.from_bytes(image[0xA18 + number * 64:0xA18 + number * 64 + width], "little"))
                        stacks.add(int.from_bytes(image[0xA20 + number * 64:0xA20 + number * 64 + width], "little"))
                    self.assertEqual(len(threads), logical)
                    self.assertEqual(len(stacks), logical)
                    minimum = 0xFFFF800000000000 if width == 8 else 0x80000000
                    self.assertTrue(all(address >= minimum for address in threads | stacks))
                    self.assertEqual(image[0xF08:0xF18], (bytes(width) + b"\xcc" * (8 - width)) * 2)
                    self.assertEqual(int.from_bytes(image[0xF18:0xF18 + width], "little"), 0x1122334455667788 if width == 8 else 0xAABBCCDD)
                    expected = 0x1234567800001234 if mode == "wide" and width == 8 else 0x1234
                    self.assertEqual(int.from_bytes(image[0xF00:0xF00 + width], "little"), expected)
                    self.assertEqual(int(group["results"]["0"], 0), expected)
                    if mode == "background":
                        self.assertEqual(report["kernel_scheduling"]["threads"][0]["state"], "done")

    def test_high_irql_processors_interleave_to_complete_a_shared_barrier(self):
        for machine in (0x14C, 0x8664):
            with self.subTest(machine=machine):
                result, report, root = self.run_probe(machine, "barrier")
                self.assertEqual(result["errors"], [], result)
                self.assertEqual(result["guest_entry_return"], 0x1234)
                self.assertTrue(report["kernel_ipi"]["broadcasts"][0]["completed"])
                self.assertGreater(report["kernel_scheduling"]["switches_observed"], 4)

    def test_repeated_broadcasts_reuse_parked_contexts_and_restore_the_caller(self):
        for machine in (0x14C, 0x8664):
            with self.subTest(machine=machine):
                result, report, root = self.run_probe(machine, "repeat")
                self.assertEqual(result["errors"], [], result)
                self.assertEqual(result["guest_entry_return"], 0x1234)
                groups = report["kernel_ipi"]["broadcasts"]
                self.assertEqual(len(groups), 2)
                self.assertTrue(all(group["completed"] and len(group["callbacks"]) == 4 for group in groups))
                item = next(item for item in result["artifacts"] if item["source"] == "modified_driver_image:0x2000")
                image = (root / "artifacts" / item["file"]).read_bytes()
                width = 8 if machine == 0x8664 else 4
                for number in range(4):
                    first, second = 0xA00 + number * 64, 0xC00 + number * 64
                    self.assertEqual(image[first:first + 44], image[second:second + 44])
                self.assertEqual(int.from_bytes(image[0xF20:0xF20 + width], "little"), 0x1234)

    def test_more_than_one_processor_group_stops_before_any_callback(self):
        for machine in (0x14C, 0x8664):
            with self.subTest(machine=machine), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                persona = load_persona(None)
                persona["cpu"]["cores"], persona["cpu"]["threads_per_core"] = 33, 2
                data = ipi_probe(machine)
                result = run_driver(data, inspect_pe(data, "groups.sys"), persona, root, 5, 20000)
                report = json.loads((root / "engine-report.json").read_text())
                self.assertIsNone(result["guest_entry_return"])
                self.assertTrue(any("one processor group" in error for error in result["errors"]))
                self.assertEqual(report["kernel_ipi"]["broadcasts"], [])

    def test_faults_budgets_invalid_callbacks_and_nested_ipis_do_not_complete(self):
        for machine in (0x14C, 0x8664):
            for mode in ("fault", "budget", "invalid", "nested", "terminate", "irql"):
                with self.subTest(machine=machine, mode=mode):
                    result, report, root = self.run_probe(machine, mode)
                    self.assertTrue(result["errors"])
                    self.assertIsNone(result["guest_entry_return"])
                    self.assertTrue(all(not group["completed"] for group in report["kernel_ipi"]["broadcasts"]))
                    if mode == "budget":
                        self.assertTrue(result["instruction_limit_reached"])
                        self.assertEqual(result["instruction_count"], 50)
                    if machine == 0x8664 and mode == "fault":
                        self.assertTrue(report["exception_unwind"]["frames"])
                        self.assertNotEqual(report["exception_unwind"]["stop"], "Guest RSP is outside the modeled stack")


if __name__ == "__main__": unittest.main(verbosity=2)
