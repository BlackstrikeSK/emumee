"""Kernel file APIs must preserve exact bytes and native status/handle state."""

import json
import struct
import tempfile
import unittest
from pathlib import Path

from emumee.driver import run_driver
from emumee.pe import inspect_pe
from emumee.persona import load_persona
from tests.test_kernel_runtime import runtime_driver


def file_probe(machine, path, mode="write", *, options=0x60, disposition=2, share=3, access=0xC0100000):
    x64 = machine == 0x8664
    base, width = (0x140000000, 8) if x64 else (0x400000, 4)
    name = ("\\??\\" + path).encode("utf-16le")
    source = struct.pack("<HH", len(name), len(name) + 2) + (bytes(4) if x64 else b"")
    source += (base + 0x2400).to_bytes(width, "little")
    oa = (struct.pack("<IIQQIIQQ", 48, 0, 0, base + 0x2240, 0x240, 0, 0, 0) if x64 else
          struct.pack("<6I", 24, 0, base + 0x2240, 0x240, 0, 0))
    create = [base + 0x2200, access, base + 0x2260, base + 0x2210,
              0, 0x80, share, disposition, options, 0, 0, 0, 0, 8, 0]
    if x64:
        # ULONG stack arguments may have unspecified upper DWORDs.
        for index in (5, 6, 7, 8, 10, 11, 13):
            create[index] |= 0xCDCDCDCD00000000
    calls = [(0, create, False)]
    names = ["IoCreateFileEx", "ZwWriteFile", "ZwFlushBuffersFile"]
    write = [("load", 0x2200), 0, 0, 0, base + 0x2220, base + 0x2300, 4, 0, 0]
    if mode == "write":
        calls += [(1, write, False), (2, [("load", 0x2200), base + 0x2230], False)]
    elif mode in ("read", "eof", "reread"):
        names[1] = "ZwReadFile"
        calls += [(1, write, False)]
        if mode != "read":
            again = list(write)
            again[4] = base + 0x2230
            if mode == "reread":
                again[7] = base + 0x2380
            calls += [(1, again, False)]
    elif mode == "close":
        names[2] = "ZwClose"
        calls += [(2, [("load", 0x2200)], False), (1, write, False)]
    elif mode in ("duplicate", "mismatch"):
        again = list(create)
        again[0] = base + 0x2208
        again[3] = base + 0x2220
        if mode == "mismatch":
            again[7:9] = [1, 0x60]
        calls += [(0, again, False)]
    return runtime_driver(machine, names, calls, [(0x2240, source), (0x2260, oa),
        (0x2300, b"EMU!"), (0x2400, name + b"\0\0")])


class KernelFileTests(unittest.TestCase):
    def run_probe(self, machine, path, mode, *, persona=None, **kwargs):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        data = file_probe(machine, path, mode, **kwargs)
        result = run_driver(data, inspect_pe(data, "files.sys"), persona or load_persona(None), root, 5, 2000)
        report = json.loads((root / "engine-report.json").read_text())
        item = next(item for item in result["artifacts"] if item["source"] == "modified_driver_image:0x2000")
        image = (root / "artifacts" / item["file"]).read_bytes()
        return result, report, image, root

    def test_synchronous_create_write_flush_retains_exact_guest_bytes(self):
        for machine in (0x14C, 0x8664):
            with self.subTest(machine=machine):
                result, report, image, root = self.run_probe(machine, r"C:\Windows\Temp\kernel-probe.txt", "write")
                self.assertEqual(result["errors"], [])
                self.assertEqual(result["guest_entry_return"], 0)
                width = 8 if machine == 0x8664 else 4
                self.assertEqual(int.from_bytes(image[0x210 + width:0x210 + width * 2], "little"), 2)
                self.assertEqual(int.from_bytes(image[0x220 + width:0x220 + width * 2], "little"), 4)
                files = [item for item in result["artifacts"] if item["source"] == "virtual_file_final"]
                self.assertEqual(len(files), 1)
                self.assertEqual((root / "artifacts" / files[0]["file"]).read_bytes(), b"EMU!")
                self.assertTrue(any(event.get("event") == "file_write" for event in report["entry_points"][0]["events"]))

    def test_closed_handle_write_fails_and_does_not_create_file_contents(self):
        for machine in (0x14C, 0x8664):
            with self.subTest(machine=machine):
                result, _, image, _ = self.run_probe(machine, r"C:\Windows\Temp\closed.txt", "close")
                self.assertEqual(result["errors"], [])
                self.assertEqual(result["guest_entry_return"], 0xC0000008)
                self.assertEqual(struct.unpack_from("<I", image, 0x220)[0], 0xC0000008)
                self.assertFalse(any(item["source"] == "virtual_file_final" for item in result["artifacts"]))

    def test_configured_file_reads_only_submitted_guest_bytes(self):
        for machine in (0x14C, 0x8664):
            with self.subTest(machine=machine):
                persona = load_persona(None)
                path = r"C:\Windows\Temp\submitted.txt"
                persona["virtual_files"].append({"path": path, "text": "read contents"})
                result, _, image, _ = self.run_probe(machine, path, "read", persona=persona,
                    access=0x80100000, disposition=1)
                self.assertEqual(result["errors"], [])
                self.assertEqual(result["guest_entry_return"], 0)
                self.assertEqual(image[0x300:0x304], b"read")

    def test_read_position_and_explicit_offset_match_native_file_behavior(self):
        for machine in (0x14C, 0x8664):
            for mode, expected, count in (("eof", 0xC0000011, 0), ("reread", 0, 4)):
                with self.subTest(machine=machine, mode=mode):
                    persona = load_persona(None)
                    path = r"C:\Windows\Temp\cursor.txt"
                    persona["virtual_files"].append({"path": path, "text": "EMU!"})
                    result, _, image, _ = self.run_probe(machine, path, mode, persona=persona,
                        access=0x80100000, disposition=1)
                    self.assertEqual(result["errors"], [])
                    self.assertEqual(result["guest_entry_return"], expected)
                    width = 8 if machine == 0x8664 else 4
                    self.assertEqual(int.from_bytes(image[0x230 + width:0x230 + width * 2], "little"), count)
                    self.assertEqual(image[0x300:0x304], b"EMU!")

    def test_create_output_cannot_bypass_readonly_guest_page(self):
        for machine in (0x14C, 0x8664):
            with self.subTest(machine=machine), tempfile.TemporaryDirectory() as directory:
                data = bytearray(file_probe(machine, r"C:\Windows\Temp\readonly.txt", "create"))
                base, width = (0x140000000, 8) if machine == 0x8664 else (0x400000, 4)
                old = (base + 0x2200).to_bytes(width, "little")
                offset = data.index(old, 0x200, 0x400)
                data[offset:offset + width] = (base + 0x1000).to_bytes(width, "little")
                data = bytes(data)
                root = Path(directory)
                result = run_driver(data, inspect_pe(data, "readonly.sys"), load_persona(None), root, 5, 2000)
                self.assertIsNone(result["guest_entry_return"])
                self.assertTrue(any("writable" in error for error in result["errors"]))
                report = json.loads((root / "engine-report.json").read_text())
                self.assertFalse(any(event.get("event") == "file_open"
                    for event in report["entry_points"][0].get("events") or []))

    def test_directory_creation_collision_and_file_type_are_distinct(self):
        for machine in (0x14C, 0x8664):
            for mode, expected in (("duplicate", 0xC0000035), ("mismatch", 0xC00000BA)):
                with self.subTest(machine=machine, mode=mode):
                    result, _, image, _ = self.run_probe(machine, r"C:\Windows\Temp\kernel-dir", mode, options=0x21)
                    self.assertEqual(result["errors"], [])
                    self.assertEqual(result["guest_entry_return"], expected)
                    self.assertEqual(struct.unpack_from("<I", image, 0x210)[0], 0)
                    self.assertEqual(struct.unpack_from("<I", image, 0x220)[0], expected)

    def test_sharing_and_missing_parent_fail_without_fake_success(self):
        for machine in (0x14C, 0x8664):
            for path, mode, share, expected in ((r"C:\Windows\Temp\exclusive.txt", "duplicate", 0, 0xC0000043),
                    (r"C:\NoSuchParent\kernel.txt", "create", 3, 0xC000003A)):
                with self.subTest(machine=machine, path=path):
                    result, _, _, _ = self.run_probe(machine, path, mode, share=share,
                        disposition=3 if mode == "duplicate" else 2)
                    self.assertEqual(result["errors"], [])
                    self.assertEqual(result["guest_entry_return"], expected)
