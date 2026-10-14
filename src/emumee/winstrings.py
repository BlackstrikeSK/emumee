"""Bounded, guest-only Windows string lookup and comparison APIs."""

from __future__ import annotations

import speakeasy.common as common
from speakeasy.winenv import arch as e_arch


MAX_CHARS = 32767
ERROR_INVALID_PARAMETER = 87
ERROR_INVALID_FLAGS = 1004
FIND_STARTSWITH = 0x00100000
FIND_ENDSWITH = 0x00200000
FIND_FROMSTART = 0x00400000
FIND_FROMEND = 0x00800000


class GuestStrings:
    def __init__(self):
        self.read_guard = None
        self.unsupported: list[str] = []

    def install(self, emulator) -> None:
        emulator.add_api_hook(self._find_ordinal, 'kernel32',
                              'FindStringOrdinal', argc=6)
        emulator.add_api_hook(self._find_ordinal,
                              'api-ms-win-core-libraryloader-l1-2-0',
                              'FindStringOrdinal', argc=6)
        for suffix in ('A', 'W'):
            for module in ('kernel32', 'api-ms-win-core-string-l1-1-0'):
                emulator.add_api_hook(self._compare, module,
                                      'CompareString' + suffix, argc=6)
            emulator.add_api_hook(self._length, 'kernel32',
                                  'lstrlen' + suffix, argc=1)
        for module in ('ucrtbase', 'api-ms-win-crt-private-l1-1-0'):
            emulator.add_api_hook(self._wcschr, module, 'wcschr', argc=2,
                                  call_conv=e_arch.CALL_CONV_CDECL)

    def _wcschr(self, emu, api_name, _original, params) -> int:
        address, wanted = map(int, params)
        wanted &= 0xffff
        for index in range(MAX_CHARS + 1):
            char_address = address + index * 2
            if not self._access(emu, char_address, 2):
                self.unsupported.append(f'{api_name}: inaccessible or unterminated string')
                return 0
            char = int.from_bytes(emu.mem_read(char_address, 2), 'little')
            if char == wanted:
                return char_address
            if char == 0:
                return 0
        self.unsupported.append(f'{api_name}: string exceeds limit')
        return 0

    def _access(self, emu, address: int, size: int) -> bool:
        if not address or size <= 0:
            return False
        mapping = emu.get_address_map(address)
        if (mapping is None or mapping.free or
                address + size > int(mapping.base) + int(mapping.size) or
                not (int(mapping.prot) & common.PERM_MEM_READ)):
            return False
        return self.read_guard is None or bool(self.read_guard(emu, address, size))

    def _read(self, emu, address: int, count: int, wide: bool) -> str | None:
        if not address or count < -1 or count > MAX_CHARS:
            return None
        width = 2 if wide else 1
        size = (count if count >= 0 else MAX_CHARS + 1) * width
        if count >= 0:
            if count == 0:
                return ''
            if not self._access(emu, address, size):
                return None
            try:
                data = emu.mem_read(address, size)
                return data.decode('utf-16le' if wide else 'cp1252')
            except Exception:
                return None
        parts = bytearray()
        for index in range(MAX_CHARS + 1):
            ptr = address + index * width
            if not self._access(emu, ptr, width):
                return None
            try:
                unit = emu.mem_read(ptr, width)
            except Exception:
                return None
            if unit == b'\0' * width:
                try:
                    return parts.decode('utf-16le' if wide else 'cp1252')
                except UnicodeError:
                    return None
            parts.extend(unit)
        return None

    def _length(self, emu, api_name, _original, params) -> int:
        address = int(params[0])
        if not address:
            return 0
        value = self._read(emu, address, -1, api_name.endswith('W'))
        return (len(value.encode('utf-16le')) // 2 if api_name.endswith('W')
                else len(value)) if value is not None else 0

    def _compare(self, emu, api_name, _original, params) -> int:
        _locale, flags, first, first_count, second, second_count = map(int, params)
        if flags not in (0, 1):
            emu.set_last_error(ERROR_INVALID_FLAGS)
            return 0
        width = api_name.endswith('W')
        left = self._read(emu, first, self._signed(first_count), width)
        right = self._read(emu, second, self._signed(second_count), width)
        if left is None or right is None:
            emu.set_last_error(ERROR_INVALID_PARAMETER)
            return 0
        # This implementation covers invariant ASCII comparisons. Returning a
        # collation result for other characters would pretend to model NLS.
        if not left.isascii() or not right.isascii():
            self.unsupported.append(f'{api_name}: non-ASCII collation unavailable')
            emu.set_last_error(ERROR_INVALID_PARAMETER)
            return 0
        if flags == 1:
            left, right = left.casefold(), right.casefold()
        return 1 if left < right else (3 if left > right else 2)

    @staticmethod
    def _signed(value: int) -> int:
        value &= 0xFFFFFFFF
        return value - 0x100000000 if value & 0x80000000 else value

    def _find_ordinal(self, emu, api_name, _original, params) -> int:
        flags, source, source_count, value, value_count, ignore_case = map(int, params)
        flags &= 0xffffffff
        ignore_case &= 0xffffffff
        if flags not in (FIND_STARTSWITH, FIND_ENDSWITH,
                         FIND_FROMSTART, FIND_FROMEND):
            emu.set_last_error(ERROR_INVALID_FLAGS)
            return -1
        haystack = self._read(emu, source, self._signed(source_count), True)
        needle = self._read(emu, value, self._signed(value_count), True)
        if haystack is None or needle is None or ignore_case not in (0, 1):
            emu.set_last_error(ERROR_INVALID_PARAMETER)
            return -1
        if ignore_case:
            if not haystack.isascii() or not needle.isascii():
                self.unsupported.append(f'{api_name}: non-ASCII case fold unavailable')
                emu.set_last_error(ERROR_INVALID_PARAMETER)
                return -1
            haystack, needle = haystack.casefold(), needle.casefold()
        if flags == FIND_STARTSWITH:
            index = 0 if haystack.startswith(needle) else -1
        elif flags == FIND_ENDSWITH:
            index = len(haystack) - len(needle) if haystack.endswith(needle) else -1
        elif flags == FIND_FROMEND:
            index = haystack.rfind(needle)
        else:
            index = haystack.find(needle)
        emu.set_last_error(0)
        return len(haystack[:index].encode('utf-16le')) // 2 if index >= 0 else -1
