"""Native driver queries of the modeled kernel's loaded-module inventory."""

import json
import struct
import tempfile
import unittest
from pathlib import Path

from emumee.driver import run_driver
from emumee.pe import inspect_pe
from emumee.persona import load_persona
from tests.test_kernel_objects import call_driver


def system_information_probe(machine, mode="extended", alias=False, relocated=False):
    wide = machine == 0x8664
    base, width = (0x140000000, 8) if wide else (0x400000, 4)
    store = lambda rva: (b"\x48\xa3" if wide else b"\xa3") + (base + rva).to_bytes(width, "little")
    load = lambda rva: (b"\x48\xa1" if wide else b"\xa1") + (base + rva).to_bytes(width, "little")
    marker = b"\xb8MARK" + store(0x23F0)
    name = "NtQuerySystemInformation" if alias else "ZwQuerySystemInformation"
    names = [name, "ExAllocatePoolWithTag", "RtlMoveMemory"]
    information_class = 11 if mode == "standard" else 77
    if mode in ("extended", "standard", "optional"):
        operations = [("raw", marker), (0, [information_class, 0, 0, base + 0x2300], 0x2380),
            (1, [0, ("load", 0x2300), 0x51494D45], 0x2310),
            (0, [information_class, ("load", 0x2310), ("load", 0x2300),
                 0 if mode == "optional" else base + 0x2308], 0x2388),
            (2, [base + 0x3000, ("load", 0x2310), ("load", 0x2300)], None),
            ("raw", load(0x2310) + (b"\x48\x8b\x40" if wide else b"\x8b\x40") + bytes([3 * width]) +
             b"\x0f\xb7\x00" + store(0x2330))]
    else:
        output = {"null": 0, "unmapped": 0x7FFF7000, "readonly": base + 0x1000}.get(mode, base + 0x3000)
        returned = {"return-readonly": base + 0x1000, "return-unmapped": 0x7FFF7000}.get(mode, base + 0x2300)
        capacity = 1 if mode == "short" else 0x8000
        if mode == "unknown":
            information_class = 0xDEAD
        operations = [("raw", marker), (0, [information_class, output, capacity, returned], 0x2380)]
    operations.append(("raw", b"\xb8DONE" + store(0x23F8)))
    data = bytearray(call_driver(machine, names, operations, b"\x31\xc0",
        [(0x2308, b"\xaa" * 8)]))
    # A larger writable image section holds the complete query result, away
    # from its own IAT. The driver still allocates the queried size dynamically.
    section = 0x98 + (0xF0 if wide else 0xE0) + 40
    struct.pack_into("<I", data, section + 8, 0x9000)
    struct.pack_into("<I", data, section + 16, 0x9000)
    struct.pack_into("<I", data, 0x98 + 56, 0xB000)
    data.extend(bytes(0x9400 - len(data)))
    struct.pack_into("<I", data, 0x88, 0x12345678)
    struct.pack_into("<I", data, 0x98 + 64, 0x98765432)
    if relocated:
        locations = []
        offset = 0x200
        while offset + width <= 0x400:
            value = int.from_bytes(data[offset:offset + width], "little")
            if base <= value < base + 0xB000:
                locations.append((0xA000 if wide else 0x3000) | (offset - 0x200))
                offset += width
            else:
                offset += 1
        assert locations
        if len(locations) % 2:
            locations.append(0)
        block = struct.pack("<II", 0x1000, 8 + 2 * len(locations)) + struct.pack("<" + "H" * len(locations), *locations)
        struct.pack_into("<H", data, 0x96, struct.unpack_from("<H", data, 0x96)[0] & ~1)
        struct.pack_into("<II", data, 0x98 + (112 if wide else 96) + 5 * 8, 0xA000, len(block))
        data[0x8400:0x8400 + len(block)] = block
    return bytes(data)


def image_range(result, root, rva, size):
    output = bytearray(size)
    covered = bytearray(size)
    for item in result["artifacts"]:
        if not item["source"].startswith("modified_driver_image:"):
            continue
        start = int(item["source"].split(":")[1], 0)
        data = (root / "artifacts" / item["file"]).read_bytes()
        first, stop = max(start, rva), min(start + len(data), rva + size)
        if first < stop:
            output[first - rva:stop - rva] = data[first - start:stop - start]
            covered[first - rva:stop - rva] = b"\1" * (stop - first)
    assert all(covered), (hex(rva), size)
    return bytes(output)


def verify_module_result(result, root, machine, mode):
    width = 8 if machine == 0x8664 else 4
    metadata = image_range(result, root, 0x2300, 0x100)
    value = lambda offset: int.from_bytes(metadata[offset:offset + 4], "little")
    assert value(0x80) == 0xC0000004
    assert value(0x88) == 0 and value(0x30) == 0x5A4D
    assert metadata[0xF0:0xF4] == b"MARK" and metadata[0xF8:0xFC] == b"DONE"
    if mode != "optional":
        assert value(8) == value(0)
    else:
        assert value(8) == 0xAAAAAAAA
    assert metadata[12:16] == b"\xaa" * 4  # ReturnLength is always ULONG.
    report = json.loads((root / "engine-report.json").read_text())
    modules = report["entry_points"][0]["memory"]["modules"]
    by_base = {int(item["base"], 0): item for item in modules}
    data = image_range(result, root, 0x3000, value(0))
    extended = mode != "standard"
    stride = (320 if width == 8 else 300) if extended else (296 if width == 8 else 284)
    cursor, parsed = (0 if extended else width), []
    if not extended:
        assert int.from_bytes(data[:4], "little") == len(modules)
    while cursor + stride <= len(data):
        if extended:
            assert int.from_bytes(data[cursor:cursor + 2], "little") == stride
        start = cursor + (width if extended else 0)
        base = int.from_bytes(data[start + 2 * width:start + 3 * width], "little")
        image_size, flags, index, init, count, name_offset = struct.unpack_from("<II4H", data, start + 3 * width)
        path = data[start + 3 * width + 16:start + 3 * width + 272].split(b"\0", 1)[0].decode("cp1252")
        assert base in by_base and image_size == int(by_base[base]["size"], 0)
        assert path == by_base[base]["path"] and path[name_offset:] == by_base[base]["name"]
        assert index == init == len(parsed) and count == 1 and flags == 0
        if path.endswith("system-info.sys") and extended:
            base_size = 296 if width == 8 else 284
            assert struct.unpack_from("<II", data, start + base_size) == (0x98765432, 0x12345678)
            assert int.from_bytes(data[cursor + stride - width:cursor + stride], "little") == (0x140000000 if width == 8 else 0x400000)
        parsed.append(base)
        cursor += stride
    assert len(parsed) == len(modules) and len(set(parsed)) == len(parsed)
    assert by_base[parsed[0]]["name"] == "ntoskrnl.exe"
    assert data[cursor:] == (b"\0\0" if extended else b"")
    queries = report["kernel_system_information"]["queries"]
    assert [item["status"] for item in queries] == ["0xc0000004", "0x0"]
    return report


class KernelSystemInformationTests(unittest.TestCase):
    def run_probe(self, machine, mode, alias=False, relocated=False):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        data = system_information_probe(machine, mode, alias, relocated)
        result = run_driver(data, inspect_pe(data, "system-info.sys"), load_persona(None), root, 5, 3000)
        return result, root

    def test_relocated_module_default_base_preserves_preferred_header(self):
        for machine in (0x14C, 0x8664):
            with self.subTest(machine=machine):
                result, root = self.run_probe(machine, "extended", relocated=True)
                self.assertEqual(result["errors"], [])
                report = verify_module_result(result, root, machine, "extended")
                self.assertEqual(report["image_base"], 0xFFFFF80100000000 if machine == 0x8664 else 0x90000000)

    def test_native_module_queries_match_mapped_inventory_and_headers(self):
        for machine in (0x14C, 0x8664):
            for mode in ("standard", "extended", "optional"):
                for alias in (False, True):
                    with self.subTest(machine=machine, mode=mode, alias=alias):
                        result, root = self.run_probe(machine, mode, alias)
                        self.assertEqual(result["errors"], [])
                        self.assertEqual(result["guest_entry_return"], 0)
                        verify_module_result(result, root, machine, mode)

    def test_short_buffer_returns_required_length_without_writing_output(self):
        for machine in (0x14C, 0x8664):
            with self.subTest(machine=machine):
                result, root = self.run_probe(machine, "short")
                self.assertEqual(result["errors"], [])
                metadata = image_range(result, root, 0x2300, 0x100)
                self.assertGreater(int.from_bytes(metadata[:4], "little"), 300)
                self.assertEqual(int.from_bytes(metadata[0x80:0x84], "little"), 0xC0000004)
                self.assertEqual(metadata[0xF8:0xFC], b"DONE")
                report = json.loads((root / "engine-report.json").read_text())
                self.assertEqual(report["driver_image_changes"]["changed_pages"], 1)

    def test_invalid_kernel_outputs_stop_before_following_guest_code(self):
        for machine in (0x14C, 0x8664):
            for mode in ("null", "unmapped", "readonly", "return-readonly", "return-unmapped", "unknown"):
                with self.subTest(machine=machine, mode=mode):
                    result, root = self.run_probe(machine, mode)
                    self.assertTrue(result["errors"])
                    self.assertIsNone(result["guest_entry_return"])
                    metadata = image_range(result, root, 0x2300, 0x100)
                    self.assertEqual(metadata[0xF0:0xF4], b"MARK")
                    self.assertNotEqual(metadata[0xF8:0xFC], b"DONE")
                    report = json.loads((root / "engine-report.json").read_text())
                    self.assertEqual(report["driver_image_changes"]["changed_pages"], 1)
