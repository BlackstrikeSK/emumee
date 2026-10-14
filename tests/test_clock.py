"""Harmless checks for the virtual time API timeline."""

import datetime as dt
import struct
import unittest

from emumee.clock import VirtualClock


class Memory:
    def __init__(self):
        self.values = {}
        self.page_size = 0x1000
        self.maps = []
        self.last_error = None

    def mem_write(self, address, value):
        self.values[address] = value

    def get_ptr_size(self):
        return 8

    def set_last_error(self, error):
        self.last_error = error

    def mem_map(self, size, base, tag):
        self.maps.append((size, base, tag))
        return base


class VirtualClockTests(unittest.TestCase):
    def test_dynamic_timezone_uses_fixed_persona_offset_and_full_layout(self):
        clock = VirtualClock({"clock_utc": "2026-10-11T12:00:00Z",
                              "utc_offset_minutes": -240,
                              "timezone": "Eastern Standard Time",
                              "uptime_ms": 523_812_000})
        mem = Memory()
        self.assertEqual(clock.dynamic_time_zone(mem, "", None, [0x1000]), 0)
        data = mem.values[0x1000]
        self.assertEqual(len(data), 432)
        self.assertEqual(struct.unpack_from("<i", data)[0], 240)
        self.assertEqual(data[4:68].decode("utf-16le").rstrip("\0"),
                         "Eastern Standard Time")
        self.assertEqual(data[172:428].decode("utf-16le").rstrip("\0"),
                         "Eastern Standard Time")
        self.assertEqual(data[68:84], b"\0" * 16)  # No DST transition.
        self.assertEqual(data[152:168], b"\0" * 16)
        self.assertEqual(data[428], 1)
        self.assertEqual(mem.last_error, 0)
        self.assertEqual(clock.time_zone(mem, "", None, [0x2000]), 0)
        self.assertEqual(mem.values[0x2000], data[:172])
        self.assertEqual(clock.dynamic_time_zone(mem, "", None, [0]), 0xFFFFFFFF)
        self.assertEqual(mem.last_error, 87)

    def test_shared_user_data_tracks_virtual_time_on_both_aliases(self):
        clock = VirtualClock({"clock_utc": "2026-10-11T12:00:00Z",
                              "utc_offset_minutes": -240,
                              "uptime_ms": 523_812_000})
        mem = Memory()
        clock.attach_shared_data(mem)
        low, high = 0x7FFE0000, 0xFFFFF78000000000
        translated = high & ((1 << 52) - 1)
        self.assertEqual(mem.maps[0][1], translated)

        def value(base, offset):
            raw = mem.values[base + offset]
            if len(raw) == 12:
                lo, hi1, hi2 = struct.unpack("<III", raw)
                self.assertEqual(hi1, hi2)
                return lo | (hi1 << 32)
            return struct.unpack("<Q", raw)[0]

        for base in (low, high, translated):
            self.assertEqual(value(base, 0x014), clock.filetime_ticks())
            self.assertEqual(value(base, 0x008), 523_812_000 * 10_000)
            self.assertEqual(value(base, 0x320), 523_812_000)
            self.assertEqual(value(base, 0x300), 10_000_000)
            self.assertEqual(value(base, 0x3B8), 0)
        clock.performance_counter(mem, "", None, [0x1000])
        self.assertEqual(value(low, 0x008), 523_812_000 * 10_000 + 10)
        self.assertEqual(value(high, 0x014), clock.filetime_ticks())
        clock.sleep(mem, "", None, [2000])
        for base in (low, high, translated):
            self.assertEqual(value(base, 0x008), 523_814_000 * 10_000 + 10)
            self.assertEqual(value(base, 0x320), 523_814_000)

    def test_precise_file_time_uses_the_virtual_clock(self):
        clock = VirtualClock({"clock_utc": "2026-10-11T12:00:00Z",
                              "utc_offset_minutes": 0,
                              "uptime_ms": 523_812_000})
        hooks = {}
        clock.install(type("Hooks", (), {"add_api_hook":
                      lambda _self, method, module, name, **_kwargs:
                      hooks.setdefault(name, method)})())
        mem = Memory()
        hooks["GetSystemTimeAsFileTime"](mem, "", None, [0x1000])
        hooks["GetSystemTimePreciseAsFileTime"](mem, "", None, [0x1008])
        coarse = struct.unpack("<Q", mem.values[0x1000])[0]
        precise = struct.unpack("<Q", mem.values[0x1008])[0]
        self.assertEqual(precise - coarse, 10)

    def test_high_resolution_counter_and_wall_time_share_one_timeline(self):
        clock = VirtualClock({"clock_utc": "2026-10-11T12:00:00Z",
                              "utc_offset_minutes": -240,
                              "uptime_ms": 523_812_000})
        mem = Memory()
        before = clock.filetime_ticks()
        self.assertEqual(clock.performance_frequency(mem, "", None, [0x1000]), 1)
        self.assertEqual(struct.unpack("<Q", mem.values[0x1000])[0], 10_000_000)

        clock.performance_counter(mem, "", None, [0x1008])
        first = struct.unpack("<Q", mem.values[0x1008])[0]
        clock.performance_counter(mem, "", None, [0x1010])
        second = struct.unpack("<Q", mem.values[0x1010])[0]
        self.assertEqual(second - first, 10)
        self.assertEqual(clock.tick64(mem, "", None, []), 523_812_000)
        self.assertEqual(clock.filetime_ticks() - before, 30)

        clock.sleep(mem, "", None, [2 * 86_400_000])
        clock.file_time(mem, "", None, [0x1018])
        after = struct.unpack("<Q", mem.values[0x1018])[0]
        self.assertEqual(after - before, 2 * 86_400_000 * 10_000 + 40)
        self.assertEqual(clock.utc, dt.datetime(2026, 10, 13, 12, 0, 0, 4,
                                                 tzinfo=dt.timezone.utc))

    def test_tick_wraps_but_tick64_continues(self):
        clock = VirtualClock({"clock_utc": "2026-10-11T12:00:00Z",
                              "utc_offset_minutes": 0,
                              "uptime_ms": 0xFFFFFFFF})
        clock.advance(1)
        self.assertEqual(clock.tick(None, "", None, []), 0)
        self.assertEqual(clock.tick64(None, "", None, []), 0x100000000)

    def test_tick_resolution_is_coarser_than_qpc(self):
        clock = VirtualClock({"clock_utc": "2026-10-11T12:00:00Z",
                              "utc_offset_minutes": 0,
                              "uptime_ms": 523_812_000})
        start = clock.tick(None, "", None, [])
        clock.advance(1)
        self.assertEqual(clock.tick(None, "", None, []), start)
        clock.advance(15)
        self.assertEqual(clock.tick(None, "", None, []), start + 16)


if __name__ == "__main__":
    unittest.main()
