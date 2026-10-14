"""Per-run virtual clock for WinAPI time and sleep behavior."""

from __future__ import annotations

import datetime as dt
import struct


class VirtualClock:
    def __init__(self, persona: dict):
        configured = persona.get("clock_utc")
        if configured:
            self.utc = dt.datetime.fromisoformat(configured.replace("Z", "+00:00"))
            if self.utc.tzinfo is None:
                raise ValueError("clock_utc must include a timezone")
            self.utc = self.utc.astimezone(dt.timezone.utc)
        else:
            self.utc = dt.datetime.now(dt.timezone.utc)
        self.offset = dt.timedelta(minutes=int(persona["utc_offset_minutes"]))
        self.timezone_name = str(persona.get("timezone", "UTC"))
        self.uptime_ms = int(persona["uptime_ms"])
        # Keep sub-millisecond observations in the same timeline as wall time.
        # A frozen QPC across successive API calls is a common sandbox tell.
        self._submillisecond_100ns = 0
        self._shared_data_emu = None
        self._shared_data_addresses: tuple[int, ...] = ()
        self.before_observe = None

    def attach_shared_data(self, emu) -> None:
        """Replace Speakeasy's host-derived KUSER_SHARED_DATA time fields."""
        self._shared_data_emu = emu
        if emu.get_ptr_size() == 8:
            high_alias = 0xFFFFF78000000000
            # This Unicorn build reports x64 CPU accesses to the canonical
            # high alias with its upper twelve bits cleared. Speakeasy maps
            # only the canonical address, so map the translated engine view.
            engine_alias = high_alias & ((1 << 52) - 1)
            emu.mem_map(emu.page_size, base=engine_alias,
                        tag="emu.struct.KUSER_SHARED_DATA.cpu_alias")
            self._shared_data_addresses = (0x7FFE0000, high_alias, engine_alias)
        else:
            self._shared_data_addresses = (0x7FFE0000, 0xFFDF0000)
        self._sync_shared_data()

    def _sync_shared_data(self) -> None:
        if self._shared_data_emu is None:
            return

        def ksystem_time(value: int) -> bytes:
            value &= 0xFFFFFFFFFFFFFFFF
            high = (value >> 32) & 0xFFFFFFFF
            return struct.pack("<III", value & 0xFFFFFFFF, high, high)

        interrupt = self.uptime_ms * 10_000 + self._submillisecond_100ns
        tick = self.uptime_ms // 16 * 16
        # These offsets are the fields populated by the installed Speakeasy
        # KUSER_SHARED_DATA layout. Keep both guest aliases on one timeline.
        fields = ((0x000, struct.pack("<I", tick & 0xFFFFFFFF)),
                  (0x004, struct.pack("<I", 1 << 24)),
                  (0x008, ksystem_time(interrupt)),
                  (0x014, ksystem_time(self.filetime_ticks())),
                  (0x020, ksystem_time(-int(self.offset.total_seconds()) * 10_000_000)),
                  (0x300, struct.pack("<q", 10_000_000)),
                  (0x320, ksystem_time(tick)),
                  (0x3B8, struct.pack("<q", 0)))
        for base in self._shared_data_addresses:
            for offset, data in fields:
                self._shared_data_emu.mem_write(base + offset, data)

    def install(self, emulator) -> None:
        for name, method in {
            "Sleep": self.sleep,
            "SleepEx": self.sleep,
            "GetTickCount": self.tick,
            "GetTickCount64": self.tick64,
            "GetSystemTime": self.system_time,
            "GetLocalTime": self.local_time,
            "GetSystemTimeAsFileTime": self.file_time,
            "GetSystemTimePreciseAsFileTime": self.file_time,
            "QueryPerformanceCounter": self.performance_counter,
            "QueryPerformanceFrequency": self.performance_frequency,
        }.items():
            emulator.add_api_hook(method, "kernel32", name)
        for module in ("kernel32", "api-ms-win-core-timezone-l1-1-0"):
            emulator.add_api_hook(self.dynamic_time_zone, module,
                                  "GetDynamicTimeZoneInformation", argc=1)
            emulator.add_api_hook(self.time_zone, module,
                                  "GetTimeZoneInformation", argc=1)

    def _time_zone_result(self, emu, params, size: int):
        """Write the shared 172-byte prefix, with optional dynamic fields."""
        address = int(params[0])
        if not address:
            emu.set_last_error(87)  # ERROR_INVALID_PARAMETER
            return 0xFFFFFFFF  # TIME_ZONE_ID_INVALID
        label = self.timezone_name.encode("utf-16le")
        if len(label) > 254:
            emu.set_last_error(87)
            return 0xFFFFFFFF
        standard_name = self.timezone_name
        while len(standard_name.encode("utf-16le")) > 62:
            standard_name = standard_name[:-1]
        data = bytearray(432)
        struct.pack_into("<i", data, 0, -int(self.offset.total_seconds() // 60))
        standard_label = standard_name.encode("utf-16le")
        data[4:4 + len(standard_label)] = standard_label  # StandardName[32]
        data[172:172 + len(label)] = label  # TimeZoneKeyName[128]
        data[428] = 1  # No transition dates in the fixed-offset model.
        try:
            emu.mem_write(address, bytes(data[:size]))
        except Exception:
            emu.set_last_error(998)  # ERROR_NOACCESS
            return 0xFFFFFFFF
        emu.set_last_error(0)
        return 0  # TIME_ZONE_ID_UNKNOWN: no daylight transitions

    def dynamic_time_zone(self, emu, api_name, original, params):
        """Report the persona's fixed offset in the documented 432-byte layout."""
        return self._time_zone_result(emu, params, 432)

    def time_zone(self, emu, api_name, original, params):
        """Report the same offset in TIME_ZONE_INFORMATION's 172-byte layout."""
        return self._time_zone_result(emu, params, 172)

    def advance(self, milliseconds: int) -> None:
        # Sleep takes a DWORD; a multi-day delay must not silently stop at 24h.
        if self.before_observe is not None:
            self.before_observe()
        amount = max(0, min(int(milliseconds), 0xFFFFFFFF))
        self.uptime_ms += amount
        self.utc += dt.timedelta(milliseconds=amount)
        self._sync_shared_data()

    def advance_microseconds(self, amount: int) -> None:
        """Advance by modeled guest CPU time without observing a host clock."""
        amount = max(0, int(amount))
        if not amount:
            return
        self.utc += dt.timedelta(microseconds=amount)
        self._submillisecond_100ns += amount * 10
        self.uptime_ms += self._submillisecond_100ns // 10_000
        self._submillisecond_100ns %= 10_000
        self._sync_shared_data()

    def _observe(self) -> None:
        # Model modest progress between guest API calls without reading a host
        # clock. This cannot represent guest CPU-loop timing, but prevents a
        # perfectly frozen high-resolution counter and keeps clocks coherent.
        if self.before_observe is not None:
            self.before_observe()
        self.advance_microseconds(1)

    def sleep(self, emu, api_name, original, params):
        self.advance(int(params[0]))
        return 0

    def tick(self, emu, api_name, original, params):
        self._observe()
        return (self.uptime_ms // 16 * 16) & 0xFFFFFFFF

    def tick64(self, emu, api_name, original, params):
        self._observe()
        return self.uptime_ms // 16 * 16

    def _write_systemtime(self, emu, ptr: int, when: dt.datetime) -> None:
        day_of_week = (when.weekday() + 1) % 7
        emu.mem_write(ptr, struct.pack("<8H", when.year, when.month, day_of_week,
                                       when.day, when.hour, when.minute, when.second,
                                       when.microsecond // 1000))

    def system_time(self, emu, api_name, original, params):
        self._observe()
        if params[0]:
            self._write_systemtime(emu, int(params[0]), self.utc)
        return 0

    def local_time(self, emu, api_name, original, params):
        self._observe()
        if params[0]:
            self._write_systemtime(emu, int(params[0]), self.utc + self.offset)
        return 0

    def file_time(self, emu, api_name, original, params):
        self._observe()
        if params[0]:
            emu.mem_write(int(params[0]), struct.pack("<Q", self.filetime_ticks()))
        return 0

    def filetime_ticks(self) -> int:
        epoch = dt.datetime(1601, 1, 1, tzinfo=dt.timezone.utc)
        elapsed = self.utc - epoch
        return ((elapsed.days * 86_400 + elapsed.seconds) * 10_000_000
                + elapsed.microseconds * 10)

    def performance_counter(self, emu, api_name, original, params):
        self._observe()
        if params[0]:
            count = self.uptime_ms * 10_000 + self._submillisecond_100ns
            emu.mem_write(int(params[0]), struct.pack("<Q", count))
        return 1

    def performance_frequency(self, emu, api_name, original, params):
        if params[0]:
            emu.mem_write(int(params[0]), struct.pack("<Q", 10_000_000))
        return 1
