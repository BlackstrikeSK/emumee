"""Real CPU fixtures for kernel Unicode, clock conversion and secure formatting."""

import datetime as dt
import json
import struct
import tempfile
import unittest
from contextlib import nullcontext
from unittest.mock import patch
from pathlib import Path

from emumee.driver import run_driver
from emumee.pe import inspect_pe
from emumee.persona import load_persona
from tests.fixtures.build_driver import build_driver


def runtime_driver(machine, names, calls, writes=(), *, zero_return=False, tail=b""):
    data = bytearray(build_driver(machine))
    data.extend(bytes(0xE00))
    x64 = machine == 0x8664
    base, width = (0x140000000, 8) if x64 else (0x400000, 4)
    if not 1 <= len(names) <= 8:
        raise ValueError("Runtime fixture import limit exceeded")
    struct.pack_into("<I", data, 0x400, 0x2800)
    struct.pack_into("<I", data, 0x410, 0x2900)
    section = 0x98 + (0xF0 if x64 else 0xE0) + 40
    struct.pack_into("<I", data, section + 8, 0x1000)
    struct.pack_into("<I", data, section + 16, 0x1000)
    for index, name in enumerate(names):
        encoded = name.encode() + b"\0"
        rva = 0x2500 + index * 64
        if len(encoded) > 62:
            raise ValueError("Fixture import name exceeds its slot")
        struct.pack_into("<Q" if x64 else "<I", data, 0xC00 + index * width, rva)
        struct.pack_into("<Q" if x64 else "<I", data, 0xD00 + index * width, rva)
        data[0x400 + rva - 0x2000:0x402 + rva - 0x2000 + len(encoded)] = b"\0\0" + encoded
    for offset in (0xC00, 0xD00):
        struct.pack_into("<Q" if x64 else "<I", data, offset + len(names) * width, 0)
    for rva, value in writes:
        data[0x400 + rva - 0x2000:0x400 + rva - 0x2000 + len(value)] = value
    code = bytearray(b"\x48\x83\xec\x78" if x64 else b"")
    for index, arguments, cdecl in calls:
        if x64:
            for position, value in enumerate(arguments):
                if isinstance(value, tuple):
                    if position >= 4:
                        raise ValueError("Indirect fixture argument must use a register")
                    code += (b"\x48\x8b\x0d", b"\x48\x8b\x15", b"\x4c\x8b\x05", b"\x4c\x8b\x0d")[position]
                    code += struct.pack("<i", value[1] - (0x1000 + len(code) + 4))
                    continue
                if position < 4:
                    code += (b"\x48\xb9", b"\x48\xba", b"\x49\xb8", b"\x49\xb9")[position] + struct.pack("<Q", value)
                else:
                    code += b"\x48\xb8" + struct.pack("<Q", value) + b"\x48\x89\x44\x24" + bytes([0x20 + (position - 4) * 8])
            code += b"\xff\x15" + struct.pack("<i", 0x2900 + index * width - (0x1000 + len(code) + 6))
        else:
            if cdecl == "fastcall":
                for position, value in enumerate(arguments[:2]):
                    code += ((b"\x8b\x0d", b"\x8b\x15")[position] + struct.pack("<I", base + value[1]) if isinstance(value, tuple)
                             else (b"\xb9", b"\xba")[position] + struct.pack("<I", value))
                stack_arguments = arguments[2:]
            else:
                stack_arguments = arguments
            for value in reversed(stack_arguments):
                code += (b"\xff\x35" + struct.pack("<I", base + value[1]) if isinstance(value, tuple)
                         else b"\x68" + struct.pack("<I", value))
            code += b"\xff\x15" + struct.pack("<I", base + 0x2900 + index * width)
            if cdecl is True:
                code += b"\x83\xc4" + bytes([len(arguments) * 4])
    code += tail
    if zero_return:
        code += b"\x31\xc0"
    code += b"\x48\x83\xc4\x78\xc3" if x64 else b"\xc2\x08\x00"
    if len(code) > 512:
        raise ValueError("Runtime fixture code exceeds its section")
    data[0x200:0x200 + len(code)] = code
    return bytes(data)


def legacy_format_probe(machine, capacity):
    x64 = machine == 0x8664
    base = 0x140000000 if x64 else 0x400000
    arguments = (0xFFFFFE30, 0x10000002A, base + 0x2380) if x64 else (0xFFFFFE30, 42, 1, base + 0x2380)
    packed = b"".join(value.to_bytes(8 if x64 else 4, "little") for value in arguments)
    return runtime_driver(machine, ["_vsnwprintf"],
        [(0, [base + 0x2400, capacity, base + 0x2300, base + 0x23A0], True)],
        [(0x2300, "%d %I64u %s\0".encode("utf-16le")), (0x2380, "emu\0".encode("utf-16le")),
         (0x23A0, packed), (0x2400, b"\xcd" * 128)])


class KernelRuntimeTests(unittest.TestCase):
    def test_format_capture_preserves_guest_output_and_clock(self):
        from tools.benchmark_driver_hooks import observations
        for machine in (0x14C, 0x8664):
            for capacity in (64, 18, 3):
                observed = []
                for enabled in (False, True):
                    with self.subTest(machine=machine, capacity=capacity, enabled=enabled):
                        with patch('emumee.kernel_api.record_format') if not enabled else nullcontext():
                            result, root = self.run_fixture(machine, legacy_format_probe(machine, capacity))
                        report = json.loads((root/'engine-report.json').read_text())
                        observed.append(observations(result, report))
                        state = report['kernel_formatting']
                        self.assertEqual(state['capture_errors'], 0)
                        if enabled:
                            record = state['observations'][0]
                            self.assertEqual(record['text'], '-464 4294967338 emu'[:capacity])
                            self.assertEqual(record['truncated'], capacity < len('-464 4294967338 emu'))
                        else:
                            self.assertEqual(state['observations'], [])
                self.assertEqual(observed[0], observed[1])

    def run_fixture(self, machine, data, persona=None):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        result = run_driver(data, inspect_pe(data, "runtime.sys"), persona or load_persona(None), root, 5, 2000)
        self.assertEqual(result["errors"], [])
        self.assertEqual(result["api_coverage"]["signature_only_calls"], [])
        return result, root

    def image_data(self, result, root):
        item = next(item for item in result["artifacts"] if item["source"] == "modified_driver_image:0x2000")
        return (root / "artifacts" / item["file"]).read_bytes()

    def test_secure_kernel_wide_format_consumes_x86_64_bit_varargs(self):
        for machine in (0x14C, 0x8664):
            for capacity in (64, 3, 19):
                with self.subTest(machine=machine, capacity=capacity):
                    base = 0x140000000 if machine == 0x8664 else 0x400000
                    arguments = [base + 0x2400, capacity, base + 0x2300, 0xFFFFFE30]
                    arguments += [0x10000002A] if machine == 0x8664 else [42, 1]
                    arguments += [base + 0x2380]
                    data = runtime_driver(machine, ["swprintf_s"], [(0, arguments, True)],
                        [(0x2300, "%d %I64u %s\0".encode("utf-16le")),
                         (0x2380, "emu\0".encode("utf-16le")), (0x2400, bytes([0xCD]) * 128)])
                    result, root = self.run_fixture(machine, data)
                    expected = "-464 4294967338 emu"
                    self.assertEqual(result["guest_entry_return"], len(expected) if capacity == 64 else 0xFFFFFFFF)
                    output = self.image_data(result, root)[0x400:]
                    self.assertEqual(output[:(len(expected) + 1) * 2] if capacity == 64 else output[:2],
                                     (expected + "\0").encode("utf-16le") if capacity == 64 else b"\0\0")

    def test_legacy_kernel_wide_format_exact_fit_and_truncation(self):
        expected = "-464 4294967338 emu"
        for machine in (0x14C, 0x8664):
            for capacity in (64, len(expected), 3):
                with self.subTest(machine=machine, capacity=capacity):
                    result, root = self.run_fixture(machine, legacy_format_probe(machine, capacity))
                    self.assertEqual(result["guest_entry_return"], len(expected) if capacity >= len(expected) else 0xFFFFFFFF)
                    output = self.image_data(result, root)[0x400:0x480]
                    wanted = ((expected + "\0").encode("utf-16le") if capacity > len(expected)
                              else expected[:capacity].encode("utf-16le"))
                    self.assertEqual(output, wanted + b"\xcd" * (128 - len(wanted)))

    def test_duplicate_unicode_matches_native_empty_and_termination_flags(self):
        for machine in (0x14C, 0x8664):
            for text in ("", "emu"):
                for flags in (0, 1, 2, 3):
                    with self.subTest(machine=machine, text=text, flags=flags):
                        x64 = machine == 0x8664
                        base = 0x140000000 if x64 else 0x400000
                        payload = text.encode("utf-16le")
                        source = struct.pack("<HH", len(payload), len(payload) + 2) + (bytes(4) if x64 else b"")
                        source += (base + 0x2400).to_bytes(8 if x64 else 4, "little")
                        data = runtime_driver(machine, ["RtlDuplicateUnicodeString"], [(0, [flags, base + 0x2300, base + 0x2320], False)],
                            [(0x2300, source), (0x2320, bytes([0xCD]) * len(source)), (0x2400, payload + b"\0\0")])
                        result, root = self.run_fixture(machine, data)
                        self.assertEqual(result["guest_entry_return"], 0xC000000D if flags == 2 else 0)
                        if flags == 2:
                            self.assertEqual(result["driver_image_changes"]["changed_pages"], 0)
                            continue
                        output = self.image_data(result, root)[0x320:0x320 + len(source)]
                        length, maximum = struct.unpack_from("<HH", output)
                        pointer = int.from_bytes(output[-(8 if x64 else 4):], "little")
                        allocated = bool(payload) or flags == 3
                        self.assertEqual((length, maximum), (len(payload), len(payload) + (2 if flags & 1 else 0)) if allocated else (0, 0))
                        self.assertEqual(bool(pointer), allocated)
                        if allocated:
                            item = next(item for item in result["artifacts"] if "api.pool.PagedPool.Ustr" in item["source"])
                            self.assertEqual((root / "artifacts" / item["file"]).read_bytes()[:maximum], payload + (b"\0\0" if flags & 1 else b""))

    def test_kernel_time_conversion_uses_persona_offset_and_writes_fields(self):
        moment = dt.datetime(2024, 2, 29, 23, 59, 58, 123456)
        delta = moment - dt.datetime(1601, 1, 1)
        ticks = (delta.days * 86400 + delta.seconds) * 10_000_000 + delta.microseconds * 10 + 7
        for machine in (0x14C, 0x8664):
            with self.subTest(machine=machine):
                base = 0x140000000 if machine == 0x8664 else 0x400000
                persona = load_persona(None)
                persona["utc_offset_minutes"] = 120
                data = runtime_driver(machine, ["ExSystemTimeToLocalTime", "RtlTimeToTimeFields"],
                    [(0, [base + 0x2300, base + 0x2320], False), (1, [base + 0x2320, base + 0x2340], False)],
                    [(0x2300, struct.pack("<q", ticks))], zero_return=True)
                result, root = self.run_fixture(machine, data, persona)
                output = self.image_data(result, root)
                self.assertEqual(struct.unpack_from("<q", output, 0x320)[0], ticks + 7200 * 10_000_000)
                self.assertEqual(struct.unpack_from("<8h", output, 0x340), (2024, 3, 1, 1, 59, 58, 123, 5))
