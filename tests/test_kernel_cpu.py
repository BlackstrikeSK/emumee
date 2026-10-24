"""Harmless guest instructions for kernel CPU state and entry transitions."""
import json
import struct
import tempfile
import unittest
from pathlib import Path
from emumee.driver import run_driver
from emumee.pe import inspect_pe
from emumee.persona import load_persona
from tests.test_kernel_objects import call_driver


def cpu_probe(machine, mode):
    if mode == "thread-flags":
        from tests.test_kernel_threads import thread_probe
        return thread_probe(machine, "flags")
    wide = machine == 0x8664
    base, width = (0x140000000, 8) if wide else (0x400000, 4)
    store = lambda offset: (b"\x48\xa3" if wide else b"\xa3") + (base + offset).to_bytes(width, "little")
    if mode == "boot":
        code = bytes.fromhex("9c58") + store(0x23B0)
        code += bytes.fromhex("0f20c0") + store(0x2380)
        code += bytes.fromhex("480f01e0" if wide else "0f01e0") + store(0x2388)
        code += bytes.fromhex("0f20e0") + store(0x2390)
        code += bytes.fromhex("b9800000c00f32") + store(0x2398)
        code += bytes.fromhex("0f20c04835000001000f22c0" if wide else "0f20c035000001000f22c0")
        code += bytes.fromhex("0f20c0") + store(0x23A0)
    elif mode == "suffix-immediate":
        code = bytes.fromhex("b800000f05") + store(0x23A0)
    elif mode == "cpuid":
        code = b""
        for index, opcode in enumerate((b"\x48\xb8", b"\x48\xbb", b"\x48\xb9", b"\x48\xba") if wide else
                                       (b"\xb8", b"\xbb", b"\xb9", b"\xba")):
            value = (((0xFFFF9000 + index) << 32) if wide else 0) | int(index == 0)
            code += opcode + value.to_bytes(width, "little")
        code += bytes.fromhex("0fa2") + store(0x2380)
        for offset, move in ((0x2388, "4889d8" if wide else "89d8"),
                             (0x2390, "4889c8" if wide else "89c8"), (0x2398, "4889d0" if wide else "89d0")):
            code += bytes.fromhex(move) + store(offset)
        # RBX is nonvolatile under the driver calling convention.
        code += bytes.fromhex("31db")
    elif mode.startswith("iret"):
        code = bytes.fromhex("4889e0" if wide else "89e0") + store(0x2380)
        if wide:
            code += bytes.fromhex("4889e76a00" if mode == "iret-null-ss" else "4889e76a18")
            code += bytes.fromhex("579c6a1048b8")
            target = 0x1004 + len(code) + 8 + 3
            code += (base + target).to_bytes(8, "little") + bytes.fromhex("5048cf")
        else:
            code += bytes.fromhex("9c6a0868")
            target = 0x1000 + len(code) + 4 + 1
            code += (base + target).to_bytes(4, "little") + bytes.fromhex("cf")
        code += bytes.fromhex("4889e0" if wide else "89e0") + store(0x23C0)
        code += bytes.fromhex("31c08cd0") + store(0x23B8)
        code += b"\xb8" + struct.pack("<I", 0x5A) + store(0x23D0)
    else:
        code = b""
        if wide and mode in ("syscall", "syscall-rex", "syscall-segment", "syscall-bad-target", "syscall-bad-selector"):
            target = 0x800000000000 if mode == "syscall-bad-target" else base + 0x1100
            code += b"\xb9" + struct.pack("<I", 0xC0000082)
            code += b"\xb8" + struct.pack("<I", target & 0xFFFFFFFF)
            code += b"\xba" + struct.pack("<I", target >> 32) + bytes.fromhex("0f30")
            if mode == "syscall-bad-selector":
                code += bytes.fromhex("b9810000c031c0ba180000000f30")
        if wide and mode == "syscall-disabled":
            code += bytes.fromhex("b9800000c00f3283e0fe0f30")
        code += bytes.fromhex("4889e0" if wide else "89e0") + store(0x2380)
        code += b"\xb8" + struct.pack("<I", 0x1234)
        code += bytes.fromhex("fbfd")  # IF/DF are cleared by the configured SFMASK.
        opcode = {"sysenter": bytes.fromhex("0f34"), "sysret": bytes.fromhex("480f07" if wide else "0f07"),
                  "sysexit": bytes.fromhex("480f35" if wide else "0f35"),
                  "syscall-rex": bytes.fromhex("480f05"), "syscall-segment": bytes.fromhex("650f05")}.get(mode, bytes.fromhex("0f05"))
        code += opcode
        code += b"\xb8" + struct.pack("<I", 0x5A) + store(0x23D0)
    data = bytearray(call_driver(machine, ["KeGetCurrentIrql"], [("raw", code)], bytes.fromhex("31c0")))
    if mode in ("syscall", "syscall-rex", "syscall-segment", "syscall-bad-target", "syscall-bad-selector") and wide:
        # A real guest entry handler captures state, then jumps to saved RCX.
        handler = store(0x23A0) + bytes.fromhex("4889c8") + store(0x23A8)
        handler += bytes.fromhex("4c89d8") + store(0x23B0)
        handler += bytes.fromhex("9c58") + store(0x23B8)
        handler += bytes.fromhex("4889e0") + store(0x23C0) + bytes.fromhex("ffe1")
        data[0x300:0x300 + len(handler)] = handler
    return bytes(data)


class KernelCpuTests(unittest.TestCase):
    def run_probe(self, machine, mode):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        payload = cpu_probe(machine, mode)
        result = run_driver(payload, inspect_pe(payload, "cpu-state.sys"), load_persona(None), root, 5, 1000)
        report = json.loads((root / "engine-report.json").read_text())
        item = next((item for item in result["artifacts"] if item["source"] == "modified_driver_image:0x2000"), None)
        data = (root / "artifacts" / item["file"]).read_bytes() if item else b""
        return result, report, data

    def test_native_boot_registers_and_guest_cr0_changes_are_consistent(self):
        for machine in (0x14C, 0x8664):
            with self.subTest(machine=machine):
                result, report, data = self.run_probe(machine, "boot")
                self.assertEqual(result["errors"], [])
                width = 8 if machine == 0x8664 else 4
                value = lambda offset: int.from_bytes(data[offset:offset + width], "little")
                self.assertEqual(value(0x380), 0x80050033)
                self.assertEqual(value(0x388), value(0x380))
                self.assertTrue(value(0x390) & 0x20)
                self.assertTrue(value(0x398) & 0x800)
                self.assertEqual(value(0x3A0), 0x80040033)
                self.assertTrue(value(0x3B0) & 0x200)
                self.assertEqual(int(report["kernel_cpu"]["current_state"]["cr0"], 0), value(0x3A0))

    def test_cpuid_clears_all_upper_halves_on_x64(self):
        from emumee.cpu import VirtualCPU
        expected = VirtualCPU(load_persona(None)).leaf(1, 0)
        for machine in (0x14C, 0x8664):
            with self.subTest(machine=machine):
                result, report, data = self.run_probe(machine, "cpuid")
                self.assertEqual(result["errors"], [])
                width = 8 if machine == 0x8664 else 4
                values = tuple(int.from_bytes(data[offset:offset + width], "little") for offset in (0x380, 0x388, 0x390, 0x398))
                self.assertEqual(values, expected)

    def test_syscall_reaches_guest_entry_with_architectural_registers(self):
        for mode in ("syscall", "syscall-rex", "syscall-segment"):
            with self.subTest(mode=mode):
                result, report, data = self.run_probe(0x8664, mode)
                self.assertEqual(result["errors"], [])
                self.assertEqual(result["guest_entry_return"], 0)
                value = lambda offset: int.from_bytes(data[offset:offset + 8], "little")
                self.assertEqual(value(0x3A0), 0x1234)
                self.assertTrue(0x140001000 <= value(0x3A8) < 0x140001100)
                self.assertEqual(value(0x3B0) & 0x600, 0x600)
                self.assertEqual(value(0x3B8) & 0x600, 0)
                self.assertEqual(value(0x380), value(0x3C0))
                self.assertEqual(value(0x3D0), 0x5A)
                self.assertEqual(report["kernel_cpu"]["system_entry_attempts"], 1)
                self.assertTrue(report["kernel_cpu"]["entry_tail"][0]["accepted"])

    def test_unmodeled_or_disabled_entries_stop_before_fallthrough(self):
        for machine, mode in ((0x8664, "syscall-default"), (0x8664, "syscall-disabled"),
                              (0x14C, "syscall-disabled"), (0x14C, "sysenter"), (0x8664, "sysenter"),
                              (0x14C, "sysret"), (0x8664, "sysret"), (0x14C, "sysexit"), (0x8664, "sysexit"),
                              (0x8664, "syscall-bad-target"), (0x8664, "syscall-bad-selector")):
            with self.subTest(machine=machine, mode=mode):
                result, report, data = self.run_probe(machine, mode)
                self.assertTrue(result["errors"])
                self.assertIsNone(result["guest_entry_return"])
                self.assertNotEqual(data[0x3D0:0x3D4], struct.pack("<I", 0x5A))
                error = report["entry_points"][0]["error"]
                expected = ("unsupported_kernel_syscall_dispatch" if mode == "syscall-default" else
                            "unsupported_kernel_syscall_state" if mode in ("syscall-bad-target", "syscall-bad-selector") else
                            "unsupported_kernel_instruction")
                self.assertEqual(error["type"], expected)
                if mode == "syscall-default":
                    self.assertEqual(error["api_name"], "ntoskrnl.KiSystemCall64")
                self.assertFalse(report["kernel_cpu"]["entry_tail"][0]["accepted"])

    def test_native_iret_restores_same_privilege_stack_and_kernel_selectors(self):
        for machine, mode in ((0x14C, "iret"), (0x8664, "iret"), (0x8664, "iret-null-ss")):
            with self.subTest(machine=machine, mode=mode):
                result, report, data = self.run_probe(machine, mode)
                self.assertEqual(result["errors"], [])
                self.assertEqual(result["guest_entry_return"], 0)
                width = 8 if machine == 0x8664 else 4
                value = lambda offset: int.from_bytes(data[offset:offset + width], "little")
                self.assertEqual(value(0x380), value(0x3C0))
                self.assertEqual(value(0x3D0), 0x5A)
                self.assertEqual(value(0x3B8), 0 if mode == "iret-null-ss" else 0x18 if width == 8 else 0x10)

    def test_immediate_bytes_do_not_become_system_entry_instructions(self):
        for machine in (0x14C, 0x8664):
            with self.subTest(machine=machine):
                result, report, data = self.run_probe(machine, "suffix-immediate")
                self.assertEqual(result["errors"], [])
                self.assertEqual(result["guest_entry_return"], 0)
                self.assertEqual(int.from_bytes(data[0x3A0:0x3A4], "little"), 0x050F0000)

    def test_fresh_system_thread_and_resumed_caller_keep_normal_interrupt_state(self):
        for machine in (0x14C, 0x8664):
            with self.subTest(machine=machine):
                result, report, data = self.run_probe(machine, "thread-flags")
                self.assertEqual(result["errors"], [])
                self.assertEqual(result["guest_entry_return"], 0x1234)
                self.assertEqual(int.from_bytes(data[0x360:0x364], "little"), 0x200)
                self.assertEqual(int.from_bytes(data[0x378:0x37C], "little"), 0x200)
