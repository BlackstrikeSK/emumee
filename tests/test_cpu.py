"""Harmless consistency checks for the guest CPU persona."""

from __future__ import annotations

import json
import struct
import tempfile
import unittest
from pathlib import Path

from emumee.cpu import VirtualCPU
from emumee.clock import VirtualClock
from emumee.persona import load_persona, make_speakeasy_config


class Memory:
    def __init__(self, width: int):
        self.width = width
        self.writes = {}
        self.errors = []

    def get_ptr_size(self):
        return self.width

    def mem_write(self, address, data):
        self.writes[address] = data

    def mem_read(self, address, size):
        return self.writes[address][:size]

    def set_last_error(self, error):
        self.errors.append(error)


class VirtualCPUTests(unittest.TestCase):
    def test_guest_instruction_progress_advances_virtual_qpc_and_tsc(self):
        persona = load_persona(None)
        persona["clock_utc"] = "2026-10-11T12:00:00Z"
        clock = VirtualClock(persona)
        cpu = VirtualCPU(persona, clock)
        memory = Memory(8)
        before_tsc = cpu.tsc()
        before_filetime = clock.filetime_ticks()
        for _ in range(5000):
            cpu.observe_instruction(memory, 0x1000, 1)
        cpu.flush_cycles()
        self.assertEqual(cpu.tsc() - before_tsc, 500_000)
        self.assertEqual(clock.filetime_ticks() - before_filetime,
                         (500_000 // 2900) * 10)
        clock.performance_counter(memory, "", None, [0x2000])
        qpc = struct.unpack("<Q", memory.writes[0x2000])[0]
        self.assertEqual(qpc, clock.uptime_ms * 10_000 +
                         clock._submillisecond_100ns)

    def test_cpuid_and_system_info_share_processor_count(self):
        cpu = VirtualCPU(load_persona(None))
        _, ebx, ecx, edx = cpu.leaf(0)
        self.assertEqual(struct.pack("<III", ebx, edx, ecx), b"GenuineIntel")
        leaf1 = cpu.leaf(1)
        self.assertEqual((leaf1[1] >> 16) & 0xFF, 12)
        self.assertFalse(leaf1[2] & (1 << 31))
        self.assertTrue(leaf1[2] & (1 << 5))
        self.assertTrue(leaf1[2] & (1 << 28))
        self.assertTrue(cpu.leaf(7)[1] & (1 << 5))
        self.assertEqual(cpu.leaf(0xB, 1)[1], 12)
        self.assertEqual(cpu.leaf(0x40000000), (0, 0, 0, 0))
        brand = b"".join(struct.pack("<IIII", *cpu.leaf(leaf))
                         for leaf in range(0x80000002, 0x80000005))
        self.assertIn(b"i5-10400", brand)
        shared = Memory(8)
        cpu._populate_shared_data(shared)
        self.assertEqual(struct.unpack("<I", shared.writes[0x7FFE0260])[0], 22631)
        self.assertEqual(struct.unpack("<I", shared.writes[0x7FFE026C])[0], 10)
        self.assertEqual(shared.writes[0x7FFE0274][39], 1)  # PF_AVX
        for index in (20, 21, 39, 40, 42, 41, 0, 63, 0xFFFFFFFF):
            with self.subTest(index=index):
                expected = 1 if index in (20, 21, 39, 40, 42) else 0
                self.assertEqual(cpu._is_processor_feature_present(
                    None, "", None, [index]), expected)
                if index < 64:
                    self.assertEqual(shared.writes[0x7FFE0274][index], expected)
        self.assertEqual(struct.unpack("<I", shared.writes[0x7FFE02E8])[0],
                         16_384 * 256)
        self.assertEqual(struct.unpack("<I", shared.writes[0x7FFE03C0])[0], 12)
        for width in (4, 8):
            with self.subTest(width=width):
                memory = Memory(width)
                cpu._get_system_info(memory, "kernel32.GetSystemInfo", None,
                                     [0x1000])
                data = memory.writes[0x1000]
                count = struct.unpack_from("<I", data, 20 if width == 4 else 32)[0]
                self.assertEqual(count, 12)
                self.assertEqual(len(data), 36 if width == 4 else 48)
                self.assertEqual(struct.unpack_from("<H", data,
                                                     34 if width == 4 else 46)[0],
                                 0xA503)
                memory.writes[0x2000] = struct.pack("<I", 64)
                self.assertEqual(cpu._global_memory_status_ex(memory, "", None,
                                                                [0x2000]), 1)
                length, load, total, available = struct.unpack_from(
                    "<IIQQ", memory.writes[0x2000])
                self.assertEqual((length, load, total, available),
                                 (64, 56, 16_384 * 1024**2, 7_168 * 1024**2))
                cpu._global_memory_status(memory, "", None, [0x2100])
                self.assertEqual(struct.unpack_from("<I", memory.writes[0x2100])[0],
                                 32 if width == 4 else 56)

    def test_system_info_affinity_fits_32_bit_processor_group(self):
        persona = load_persona(None)
        persona["cpu"]["cores"] = 32
        persona["cpu"]["threads_per_core"] = 2
        cpu = VirtualCPU(persona)
        self.assertEqual(cpu.leaf(0xB, 1)[1], 64)
        for width, expected_count in ((4, 32), (8, 64)):
            with self.subTest(width=width):
                memory = Memory(width)
                cpu._get_system_info(memory, "kernel32.GetSystemInfo", None,
                                     [0x1000])
                data = memory.writes[0x1000]
                mask = struct.unpack_from("<I" if width == 4 else "<Q", data,
                                          16 if width == 4 else 24)[0]
                count = struct.unpack_from("<I", data, 20 if width == 4 else 32)[0]
                self.assertEqual((mask, count),
                                 ((1 << expected_count) - 1, expected_count))

    def test_cpu_persona_fields_are_bounded_and_partially_configurable(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "persona.json"
            path.write_text(json.dumps({"cpu": {"brand": "Lab CPU", "cores": 4}}),
                            encoding="utf-8")
            persona = load_persona(path)
            self.assertEqual(persona["cpu"]["cores"], 4)
            self.assertEqual(persona["cpu"]["threads_per_core"], 2)
            cpu = VirtualCPU(persona)
            self.assertEqual(cpu.leaf(0xB, 1)[1], 8)
            path.write_text(json.dumps({"cpu": {"cores": 0}}), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_persona(path)
            path.write_text(json.dumps({"available_memory_mb": 20_000}),
                            encoding="utf-8")
            with self.assertRaises(ValueError):
                load_persona(path)

    def test_nt_version_queries_and_default_registry_follow_custom_build(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "persona.json"
            path.write_text(json.dumps({"windows_build": 26100}), encoding="utf-8")
            persona = load_persona(path)
            config = make_speakeasy_config(persona, "sample.exe", 10, 1000)
            self.assertEqual(config["os_ver"]["build"], 26100)
            values = persona["registry_keys"][0]["values"]
            self.assertEqual(next(value["data"] for value in values
                                  if value["name"] == "CurrentBuild"), "26100")
            self.assertEqual(next(value["data"] for value in values
                                  if value["name"] == "DisplayVersion"), "24H2")
            cpu = VirtualCPU(persona)
            memory = Memory(8)
            for size in (276, 284):
                with self.subTest(size=size):
                    memory.writes[0x3000] = struct.pack("<I", size)
                    self.assertEqual(cpu._rtl_get_version(memory, "", None,
                                                           [0x3000]), 0)
                    info = memory.writes[0x3000]
                    self.assertEqual(len(info), size)
                    self.assertEqual(struct.unpack_from("<IIIII", info),
                                     (size, 10, 0, 26100, 2))
                    if size == 284:
                        self.assertEqual(info[282], 1)
            cpu._rtl_get_nt_version_numbers(memory, "", None,
                                            [0x3100, 0x3104, 0x3108])
            self.assertEqual(tuple(struct.unpack("<I", memory.writes[p])[0]
                                   for p in (0x3100, 0x3104, 0x3108)),
                             (10, 0, 0xF0000000 | 26100))
            memory.writes[0x3000] = struct.pack("<I", 4)
            self.assertEqual(cpu._rtl_get_version(memory, "", None,
                                                   [0x3000]), 0xC000000D)
            self.assertEqual(cpu._rtl_get_version(memory, "", None,
                                                   [0]), 0xC000000D)
            path.write_text(json.dumps({"windows_build": 19041}), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_persona(path)
            path.write_text(json.dumps({"windows_build": 25000}), encoding="utf-8")
            unknown = load_persona(path)
            self.assertFalse(any(value["name"] == "DisplayVersion"
                                 for value in unknown["registry_keys"][0]["values"]))


if __name__ == "__main__":
    unittest.main()
