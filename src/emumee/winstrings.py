"""Bounded, guest-only Windows string lookup and comparison APIs."""

from __future__ import annotations

import speakeasy.common as common
from speakeasy.winenv import arch as e_arch


MAX_CHARS = 32767
ERROR_INVALID_PARAMETER = 87
ERROR_INVALID_FLAGS = 1004
NORM_IGNORECASE = 0x00000001
NORM_IGNOREKANATYPE = 0x00010000
NORM_IGNOREWIDTH = 0x00020000
FIND_STARTSWITH = 0x00100000
FIND_ENDSWITH = 0x00200000
FIND_FROMSTART = 0x00400000
FIND_FROMEND = 0x00800000
PRESENT_API_SETS = frozenset({
    'ext-ms-win-fsutilext-ulib-l1-1-0',
    'ext-ms-win-ntuser-chartranslation-l1-1-0',
})


class GuestStrings:
    def __init__(self, oem_code_page: int = 437):
        self.oem_code_page = oem_code_page
        self.read_guard = None
        self.write_guard = None
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
        for module in ('msvcrt', 'ucrtbase', 'api-ms-win-crt-private-l1-1-0',
                       'api-ms-win-crt-string-l1-1-0'):
            emulator.add_api_hook(self._wcsncmp, module, 'wcsncmp', argc=3,
                                  call_conv=e_arch.CALL_CONV_CDECL)
        for module in ('user32', 'kernel32', 'api-ms-win-core-string-l2-1-0'):
            emulator.add_api_hook(self._char_upper_w, module, 'CharUpperW', argc=1)
        emulator.add_api_hook(self._trim, 'shlwapi', 'StrTrimW', argc=2)
        emulator.add_api_hook(self._oem_to_unicode, 'ntdll',
                              'RtlOemToUnicodeN', argc=5)
        emulator.add_api_hook(self._is_text_unicode, 'ntdll',
                              'RtlIsTextUnicode', argc=3)
        for module in ('kernel32', 'api-ms-win-core-string-l1-1-0'):
            emulator.add_api_hook(self._wide_char_to_multi_byte, module,
                                  'WideCharToMultiByte', argc=8)
        emulator.add_api_hook(self._api_set_presence,
                              'api-ms-win-core-apiquery-l1-1-0',
                              'ApiSetQueryApiSetPresence', argc=2)
        for module in ('user32', 'ext-ms-win-ntuser-chartranslation-l1-1-0'):
            emulator.add_api_hook(self._char_to_oem_a, module, 'CharToOemA', argc=2)
        for module in ('kernel32', 'api-ms-win-core-localization-l1-2-0'):
            emulator.add_api_hook(self._is_dbcs_lead_byte, module,
                                  'IsDBCSLeadByte', argc=1)

    @staticmethod
    def _is_dbcs_lead_byte(_emu, _api_name, _original, params) -> int:
        # The default persona uses a single-byte ANSI code page.
        return 0

    def _char_to_oem_a(self, emu, api_name, _original, params) -> int:
        source, output = map(int, params)
        value = self._read(emu, source, -1, False)
        if value is None or not value.isascii():
            self.unsupported.append(f'{api_name}: non-ASCII or inaccessible source')
            return 0
        encoded = value.encode('ascii') + b'\0'
        if not self._writable(emu, output, len(encoded)):
            self.unsupported.append(f'{api_name}: guest destination is not writable')
            return 0
        try:
            emu.mem_write(output, encoded)
        except Exception:
            self.unsupported.append(f'{api_name}: guest destination is not writable')
            return 0
        return 1

    def _api_set_presence(self, emu, api_name, _original, params) -> int:
        namespace, output = map(int, params)
        pointer_size = emu.get_ptr_size()
        header_size = 16 if pointer_size == 8 else 8
        if (not self._access(emu, namespace, header_size) or
                not self._writable(emu, output, 1)):
            emu.set_last_error(ERROR_INVALID_PARAMETER)
            return 0xC000000D
        try:
            header = emu.mem_read(namespace, header_size)
            length = int.from_bytes(header[:2], 'little')
            maximum = int.from_bytes(header[2:4], 'little')
            pointer = int.from_bytes(header[8:16] if pointer_size == 8
                                     else header[4:8], 'little')
            if (length == 0 or length & 1 or length > maximum or
                    length > MAX_CHARS * 2 or not self._access(emu, pointer, length)):
                raise ValueError('invalid Unicode namespace')
            name = emu.mem_read(pointer, length).decode('utf-16le').casefold()
            if not name.startswith(('api-ms-win-', 'ext-ms-win-')):
                raise ValueError('invalid API-set namespace')
            present = name in PRESENT_API_SETS
            if not present:
                self.unsupported.append(f'{api_name}: namespace {name} unavailable')
            emu.mem_write(output, b'\x01' if present else b'\x00')
        except (ValueError, UnicodeError, OverflowError):
            emu.set_last_error(ERROR_INVALID_PARAMETER)
            return 0xC000000D
        except Exception:
            emu.set_last_error(ERROR_INVALID_PARAMETER)
            return 0xC000000D
        emu.set_last_error(0)
        return 0

    def _oem_to_unicode(self, emu, api_name, _original, params) -> int:
        output, capacity, written, source, count = map(int, params)
        # These length arguments are ULONG, even when the caller is 64-bit.
        capacity &= 0xffffffff
        count &= 0xffffffff
        invalid = 0xC000000D  # STATUS_INVALID_PARAMETER
        if (count < 0 or count > MAX_CHARS or capacity < 0 or capacity > MAX_CHARS * 2 or
                count and not self._access(emu, source, count) or
                written and not self._writable(emu, written, 4)):
            return invalid
        try:
            raw = emu.mem_read(source, count) if count else b''
        except Exception:
            return invalid
        if not raw.isascii():
            self.unsupported.append(f'{api_name}: non-ASCII OEM code page unavailable')
            return 0xC00000BB  # STATUS_NOT_SUPPORTED
        units = min(count, capacity // 2)
        truncated = units < count
        encoded = raw[:units].decode('ascii').encode('utf-16le')
        image = encoded + (b'\0\0' if not truncated and capacity >= len(encoded) + 2
                           else b'')
        if image and not self._writable(emu, output, len(image)):
            return invalid
        try:
            if image:
                emu.mem_write(output, image)
            if written:
                emu.mem_write(written, len(encoded).to_bytes(4, 'little'))
        except Exception:
            return invalid
        return 0x80000005 if truncated else 0  # STATUS_BUFFER_OVERFLOW or SUCCESS

    def _is_text_unicode(self, emu, api_name, _original, params) -> int:
        pointer, size, result_pointer = map(int, params)
        size &= 0xffffffff
        if size & 0x80000000 or size > 1024 * 1024 or (size and not self._access(
                emu, pointer, size)):
            self.unsupported.append(f'{api_name}: invalid or oversized text buffer')
            return 0
        if result_pointer and (not self._access(emu, result_pointer, 4) or
                               not self._writable(emu, result_pointer, 4)):
            self.unsupported.append(f'{api_name}: inaccessible result flags')
            return 0
        try:
            raw = emu.mem_read(pointer, size) if size else b''
            requested = (int.from_bytes(emu.mem_read(result_pointer, 4), 'little')
                         if result_pointer else 0xffffffff)
            flags = 0
            if size & 1:
                flags |= 0x200  # IS_TEXT_UNICODE_ODD_LENGTH
            elif raw.startswith(b'\xff\xfe'):
                flags |= 0x8  # IS_TEXT_UNICODE_SIGNATURE
            elif raw.startswith(b'\xfe\xff'):
                flags |= 0x80  # IS_TEXT_UNICODE_REVERSE_SIGNATURE
            elif size >= 4:
                high = raw[1::2]
                low = raw[::2]
                zero_high = sum(value == 0 for value in high)
                printable_low = sum(value in (9, 10, 13) or 32 <= value < 127
                                    or 160 <= value <= 255
                                    for value in low)
                if zero_high * 4 >= len(high) * 3 and (
                        printable_low * 4 >= len(low) * 3):
                    flags |= 0x2  # IS_TEXT_UNICODE_STATISTICS
                    if zero_high == len(high):
                        flags |= 0x1000  # IS_TEXT_UNICODE_NULL_BYTES
                        flags |= (0x4 if any(value in (9, 10, 13, 32)
                                             for value in low) else 0x1)
            selected = flags & requested
            if result_pointer:
                emu.mem_write(result_pointer, selected.to_bytes(4, 'little'))
            return int(bool(selected & (0x1 | 0x2 | 0x4 | 0x8 | 0x10 | 0x20 |
                                        0x40 | 0x80 | 0x1000)))
        except Exception:
            self.unsupported.append(f'{api_name}: inaccessible text buffer')
            return 0

    def _wide_char_to_multi_byte(self, emu, api_name, _original, params) -> int:
        page, flags, source, count, output, capacity, default, used = map(int, params)
        page &= 0xffffffff
        flags &= 0xffffffff
        count &= 0xffffffff
        capacity &= 0xffffffff
        if count == 0xffffffff:
            count = -1
        elif count & 0x80000000:
            emu.set_last_error(87)
            return 0
        if capacity & 0x80000000 or not source or count == 0 or capacity > MAX_CHARS * 4:
            emu.set_last_error(87)
            return 0
        if flags:
            self.unsupported.append(f'{api_name}: unsupported conversion flags 0x{flags:x}')
            emu.set_last_error(ERROR_INVALID_FLAGS)
            return 0
        if page == 0:
            page = 1252
        elif page == 1:
            page = self.oem_code_page
        if page not in (437, 850, 1252, 65001):
            self.unsupported.append(f'{api_name}: unsupported code page {page}')
            emu.set_last_error(87)
            return 0
        if page == 65001 and (default or used):
            emu.set_last_error(87)
            return 0
        if (default and not self._access(emu, default, 1) or
                used and not self._writable(emu, used, 4)):
            emu.set_last_error(87)
            return 0
        try:
            if count == -1:
                raw = bytearray()
                for index in range(MAX_CHARS):
                    if not self._access(emu, source + index * 2, 2):
                        raise ValueError('wide input unavailable')
                    unit = emu.mem_read(source + index * 2, 2)
                    raw.extend(unit)
                    if unit == b'\0\0':
                        break
                else:
                    raise ValueError('unterminated wide input')
            else:
                if count > MAX_CHARS or not self._access(emu, source, count * 2):
                    raise ValueError('wide input unavailable')
                raw = emu.mem_read(source, count * 2)
            value = bytes(raw).decode('utf-16le')
            replacement = (emu.mem_read(default, 1).decode(f'cp{page}')
                           if default else '?')
            encoded = value.encode(f'cp{page}', errors='replace')
            used_default = any(char.encode(f'cp{page}', errors='replace') == b'?'
                               and char != '?' for char in value)
            if replacement != '?' and used_default:
                encoded = b''.join(char.encode(f'cp{page}', errors='replace')
                                   if char.encode(f'cp{page}', errors='replace') != b'?'
                                   or char == '?' else replacement.encode(f'cp{page}')
                                   for char in value)
            if capacity:
                if output and output < source + len(raw) and source < output + len(encoded):
                    emu.set_last_error(87)
                    return 0
                if not output or len(encoded) > capacity:
                    emu.set_last_error(122)
                    return 0
                if not self._writable(emu, output, len(encoded)):
                    emu.set_last_error(998)
                    return 0
                emu.mem_write(output, encoded)
            if used:
                emu.mem_write(used, int(used_default).to_bytes(4, 'little'))
            emu.set_last_error(0)
            return len(encoded)
        except (ValueError, UnicodeError, LookupError):
            emu.set_last_error(87)
            return 0
        except Exception:
            emu.set_last_error(998)
            return 0

    def _trim(self, emu, api_name, _original, params) -> int:
        target, trim_chars = map(int, params)
        if not target:
            return 0
        value = self._read(emu, target, -1, True)
        chars = self._read(emu, trim_chars, -1, True)
        if value is None or chars is None:
            self.unsupported.append(f'{api_name}: inaccessible or unterminated guest string')
            return 0
        trimmed = value.strip(chars)
        if trimmed == value:
            return 0
        encoded = trimmed.encode('utf-16le') + b'\0\0'
        mapping = emu.get_address_map(target)
        if (mapping is None or mapping.free or
                target + len(encoded) > int(mapping.base) + int(mapping.size) or
                not (int(mapping.prot) & common.PERM_MEM_WRITE) or
                self.write_guard is not None and
                not self.write_guard(emu, target, len(encoded))):
            self.unsupported.append(f'{api_name}: guest destination is not writable')
            return 0
        try:
            emu.mem_write(target, encoded)
        except Exception:
            self.unsupported.append(f'{api_name}: guest destination is not writable')
            return 0
        return 1

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

    def _wcsncmp(self, emu, api_name, _original, params) -> int:
        first, second, count = map(int, params)
        if count == 0:
            return 0
        for index in range(min(count, MAX_CHARS + 1)):
            left_at = first + index * 2
            right_at = second + index * 2
            if not self._access(emu, left_at, 2) or not self._access(emu, right_at, 2):
                self.unsupported.append(f'{api_name}: inaccessible string')
                return 0
            try:
                left = int.from_bytes(emu.mem_read(left_at, 2), 'little')
                right = int.from_bytes(emu.mem_read(right_at, 2), 'little')
            except Exception:
                self.unsupported.append(f'{api_name}: inaccessible string')
                return 0
            if left != right:
                return -1 if left < right else 1
            if left == 0:
                return 0
        if count > MAX_CHARS:
            self.unsupported.append(f'{api_name}: comparison exceeds limit')
        return 0

    def _char_upper_w(self, emu, api_name, _original, params) -> int:
        address = int(params[0])
        if address <= 0xffff:
            char = chr(address & 0xffff)
            if char.isascii():
                return ord(char.upper())
            self.unsupported.append(f'{api_name}: non-ASCII character mapping unavailable')
            return address
        value = self._read(emu, address, -1, True)
        if value is None or not value.isascii():
            self.unsupported.append(f'{api_name}: inaccessible or non-ASCII string')
            return address
        image = (value.upper() + '\0').encode('utf-16le')
        if not self._writable(emu, address, len(image)):
            self.unsupported.append(f'{api_name}: guest string is not writable')
            return address
        try:
            emu.mem_write(address, image)
        except Exception:
            self.unsupported.append(f'{api_name}: guest string is not writable')
        return address

    def _access(self, emu, address: int, size: int) -> bool:
        if not address or size <= 0:
            return False
        mapping = emu.get_address_map(address)
        if (mapping is None or mapping.free or
                address + size > int(mapping.base) + int(mapping.size) or
                not (int(mapping.prot) & common.PERM_MEM_READ)):
            return False
        return self.read_guard is None or bool(self.read_guard(emu, address, size))

    def _writable(self, emu, address: int, size: int) -> bool:
        if not address or size <= 0:
            return False
        mapping = emu.get_address_map(address)
        if (mapping is None or mapping.free or
                address < int(mapping.base) or
                address + size > int(mapping.base) + int(mapping.size) or
                not (int(mapping.prot) & common.PERM_MEM_WRITE)):
            return False
        return self.write_guard is None or bool(self.write_guard(emu, address, size))

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
        flags &= 0xffffffff
        if flags & ~(NORM_IGNORECASE | NORM_IGNOREKANATYPE | NORM_IGNOREWIDTH):
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
        # Kana and width options do not change ASCII strings. Non-ASCII
        # collation remains explicitly unsupported above.
        if flags & NORM_IGNORECASE:
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
