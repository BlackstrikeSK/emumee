"""Small, process-owned models for legacy Microsoft C runtime state."""

from __future__ import annotations

import struct
import re

from speakeasy import common
from speakeasy.winenv import arch as e_arch


_IOB_ENTRIES = 20
_IOREAD = 0x0001
_IOWRT = 0x0002
_O_TEXT = 0x4000
_STREAM_MODES = frozenset((0x4000, 0x8000, 0x10000, 0x20000, 0x40000))
_MAX_FORMAT_CHARS = 8192
_MAX_OUTPUT_CHARS = 65536
_FORMAT_SPEC = re.compile(
    r"%([-+ #0]*)(\d{0,5}|\*)(?:\.(\d{0,5}|\*))?(hh|h|ll|l|I64|I32|z|t|w)?([diuoxXpcCsS%])")


def _legacy_iob_image(pointer_size: int) -> bytes:
    """Build the old msvcrt _iobuf array, with the first three streams open.

    The public MinGW msvcrt FILE layout has _ptr, _cnt, _base, _flag,
    _file, _charbuf, _bufsiz and _tmpfname in that order. Pointer alignment
    makes each entry 32 bytes on x86 and 48 bytes on x64.
    """
    if pointer_size == 4:
        stride, flag_offset, file_offset = 32, 12, 16
    elif pointer_size == 8:
        stride, flag_offset, file_offset = 48, 24, 28
    else:
        raise ValueError("unsupported guest pointer size")
    image = bytearray(stride * _IOB_ENTRIES)
    for index in range(3):
        struct.pack_into("<I", image, index * stride + flag_offset,
                         _IOREAD if index == 0 else _IOWRT)
        struct.pack_into("<I", image, index * stride + file_offset, index)
    return bytes(image)


class LegacyCRTStreams:
    """Return stable guest FILE pointers without borrowing host CRT state."""

    def __init__(self):
        self._iob_by_process: dict[int, int] = {}
        self._ucrt_iob_by_process: dict[int, tuple[int, int]] = {}
        self._mode_by_process: dict[tuple[int, int], int] = {}
        self._errno_by_thread: dict[tuple[int, int], int] = {}
        self.read_guard = None
        self.write_guard = None
        self.console_write = None
        self.unsupported: list[str] = []

    def install(self, emulator) -> None:
        emulator.add_api_hook(self._iob_func, "msvcrt", "__iob_func", argc=0,
                              call_conv=e_arch.CALL_CONV_CDECL)
        for module in ("msvcrt", "ucrtbase"):
            emulator.add_api_hook(self._acrt_iob_func, module, "__acrt_iob_func", argc=1,
                                  call_conv=e_arch.CALL_CONV_CDECL)
        emulator.add_api_hook(self._acrt_iob_func, "api-ms-win-crt-private-l1-1-0",
                              "_o___acrt_iob_func", argc=1,
                              call_conv=e_arch.CALL_CONV_CDECL)
        emulator.add_api_hook(self._vsnwprintf, "msvcrt", "_vsnwprintf", argc=4,
                              call_conv=e_arch.CALL_CONV_CDECL)
        for module in ("ucrtbase", "api-ms-win-crt-private-l1-1-0"):
            for name in ("__stdio_common_vswprintf", "_o___stdio_common_vswprintf"):
                emulator.add_api_hook(self._stdio_common_vswprintf, module, name,
                                      argc=6, call_conv=e_arch.CALL_CONV_CDECL)
            for name in ("__stdio_common_vfprintf", "_o___stdio_common_vfprintf"):
                emulator.add_api_hook(self._stdio_common_vfprintf, module, name,
                                      argc=5, call_conv=e_arch.CALL_CONV_CDECL)
        emulator.add_api_hook(self._fileno, "msvcrt", "_fileno", argc=1,
                              call_conv=e_arch.CALL_CONV_CDECL)
        emulator.add_api_hook(self._get_osfhandle, "msvcrt", "_get_osfhandle",
                              argc=1, call_conv=e_arch.CALL_CONV_CDECL)
        emulator.add_api_hook(self._fprintf, "msvcrt", "fprintf", argc=2,
                              call_conv=e_arch.CALL_CONV_CDECL)
        emulator.add_api_hook(self._fflush, "msvcrt", "fflush", argc=1,
                              call_conv=e_arch.CALL_CONV_CDECL)
        emulator.add_api_hook(self._fflush, "api-ms-win-crt-private-l1-1-0",
                              "_o_fflush", argc=1, call_conv=e_arch.CALL_CONV_CDECL)
        emulator.add_api_hook(self._ultow, "msvcrt", "_ultow", argc=3,
                              call_conv=e_arch.CALL_CONV_CDECL)
        emulator.add_api_hook(self._setmode, "msvcrt", "_setmode", argc=2,
                              call_conv=e_arch.CALL_CONV_CDECL)
        emulator.add_api_hook(self._write_descriptor, "msvcrt", "_write", argc=3,
                              call_conv=e_arch.CALL_CONV_CDECL)
        for name, callback, argc in (("_o__fileno", self._fileno, 1),
                                     ("_o__get_osfhandle", self._get_osfhandle, 1),
                                     ("_o__setmode", self._setmode, 2),
                                     ("_o__write", self._write_descriptor, 3)):
            emulator.add_api_hook(callback, "api-ms-win-crt-private-l1-1-0",
                                  name, argc=argc, call_conv=e_arch.CALL_CONV_CDECL)
        for module, name in (("msvcrt", "_errno"), ("ucrtbase", "_errno"),
                             ("api-ms-win-crt-private-l1-1-0", "_o__errno")):
            emulator.add_api_hook(self._errno, module, name, argc=0,
                                  call_conv=e_arch.CALL_CONV_CDECL)
        for name in ("strchr", "strrchr", "wcschr", "wcsrchr"):
            emulator.add_api_hook(self._find_character, "msvcrt", name, argc=2,
                                  call_conv=e_arch.CALL_CONV_CDECL)

    def _find_character(self, emu, api_name, _original, params) -> int:
        address, value = map(int, params)
        function = api_name.rsplit('.', 1)[-1]
        width = 2 if function.startswith('wcs') else 1
        target = (value & (0xFFFF if width == 2 else 0xFF)).to_bytes(width, 'little')
        last = 0
        try:
            for index in range(_MAX_FORMAT_CHARS):
                pointer = address + index * width
                unit = self._read(emu, pointer, width)
                if unit == target:
                    if function not in ('strrchr', 'wcsrchr'):
                        return pointer
                    last = pointer
                if unit == b'\0' * width:
                    return last
        except Exception:
            self.unsupported.append(f"{api_name}: unreadable guest string")
            return 0
        self.unsupported.append(f"{api_name}: unterminated guest string")
        return 0

    def _ultow(self, emu, api_name, _original, params) -> int:
        """Format one unsigned 32-bit long in a guest wide-character buffer."""
        value, output, radix = map(int, params)
        if not 2 <= radix <= 36 or not output:
            self.unsupported.append(f"{api_name}: invalid destination or radix")
            return 0
        alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
        number = value & 0xFFFFFFFF
        digits = []
        while number:
            number, remainder = divmod(number, radix)
            digits.append(alphabet[remainder])
        encoded = ("".join(reversed(digits)) if digits else "0").encode("utf-16le") + b"\0\0"
        try:
            mapping = emu.get_address_map(output)
            if (mapping is None or mapping.free or
                    output + len(encoded) > int(mapping.base) + int(mapping.size) or
                    not (int(mapping.prot) & common.PERM_MEM_WRITE) or
                    self.write_guard is not None and
                    not self.write_guard(emu, output, len(encoded))):
                raise ValueError("guest destination is not writable")
            emu.mem_write(output, encoded)
        except Exception:
            self.unsupported.append(f"{api_name}: guest destination is not writable")
            return 0
        return output

    def _setmode(self, emu, api_name, _original, params) -> int:
        descriptor, mode = map(int, params)
        process = emu.get_current_process()
        if process is None or descriptor not in (0, 1, 2) or mode not in _STREAM_MODES:
            self.unsupported.append(f"{api_name}: descriptor or text mode is not modeled")
            return -1
        key = (id(process), descriptor)
        previous = self._mode_by_process.get(key, _O_TEXT)
        self._mode_by_process[key] = mode
        return previous

    def cleanup_process(self, process) -> None:
        owner = id(process)
        self._iob_by_process.pop(owner, None)
        self._ucrt_iob_by_process.pop(owner, None)
        for key in tuple(self._mode_by_process):
            if key[0] == owner:
                self._mode_by_process.pop(key, None)
        for key in tuple(self._errno_by_thread):
            if key[0] == owner:
                self._errno_by_thread.pop(key, None)

    def _errno(self, emu, api_name, _original, _params) -> int:
        """Return stable, guest-writable CRT errno storage for this guest thread."""
        process = emu.get_current_process()
        if process is None:
            return 0
        thread = emu.get_current_thread() if hasattr(emu, "get_current_thread") else None
        key = (id(process), id(thread) if thread is not None else id(process))
        address = self._errno_by_thread.get(key)
        if address is not None:
            return address
        address = 0
        try:
            address = emu.mem_map(4, perms=common.PERM_MEM_RW,
                                  tag="api.ucrt.errno", process=process)
            emu.mem_write(address, b"\0" * 4)
        except Exception:
            if address:
                emu.mem_free(address)
            self.unsupported.append(f"{api_name}: guest errno allocation failed")
            return 0
        self._errno_by_thread[key] = address
        return address

    def _write_descriptor(self, emu, api_name, _original, params) -> int:
        descriptor, address, count = map(int, params)
        if (descriptor not in (1, 2) or count < 0 or count > _MAX_OUTPUT_CHARS * 2 or
                emu.get_current_process() is None or self.console_write is None):
            self.unsupported.append(f"{api_name}: descriptor or count is not modeled")
            return -1
        if count == 0:
            return 0
        try:
            data = self._read(emu, address, count)
        except Exception:
            self.unsupported.append(f"{api_name}: guest buffer is unreadable")
            return -1
        mode = self._mode_by_process.get((id(emu.get_current_process()), descriptor),
                                         _O_TEXT)
        try:
            if mode == 0x20000:
                rendered = data.decode('utf-16le')
            elif mode == 0x40000:
                rendered = data.decode('utf-8')
            else:
                # An ANSI/OEM code page is not yet selected for arbitrary
                # guest bytes. ASCII is identical in the common code pages.
                rendered = data.decode('ascii')
        except UnicodeError:
            self.unsupported.append(f"{api_name}: stream encoding could not be decoded")
            return -1
        self.console_write('stdout' if descriptor == 1 else 'stderr', rendered)
        return count

    def _iob_func(self, emu, _api_name, _original, _params) -> int:
        process = emu.get_current_process()
        if process is None:
            return 0
        owner = id(process)
        address = self._iob_by_process.get(owner)
        if address is None:
            image = _legacy_iob_image(emu.get_ptr_size())
            address = emu.mem_map(0x1000, perms=common.PERM_MEM_RW,
                                  tag="api.msvcrt.iob", process=process)
            emu.mem_write(address, image)
            self._iob_by_process[owner] = address
        return address

    def _acrt_iob_func(self, emu, api_name, _original, params) -> int:
        descriptor = int(params[0])
        process = emu.get_current_process()
        if process is None or descriptor not in (0, 1, 2):
            self.unsupported.append(f"{api_name}: nonstandard CRT descriptor is not modeled")
            return 0
        owner = id(process)
        pair = self._ucrt_iob_by_process.get(owner)
        if pair is None:
            # UCRT FILE is opaque to callers. Return stable, process-owned
            # guest addresses, leaving stream operations to the API model.
            stride = 0x80
            base = emu.mem_map(0x1000, perms=common.PERM_MEM_RW,
                               tag="api.ucrt.iob", process=process)
            emu.mem_write(base, b"\0" * (stride * 3))
            pair = (base, stride)
            self._ucrt_iob_by_process[owner] = pair
        return pair[0] + descriptor * pair[1]

    def _read(self, emu, address: int, size: int) -> bytes:
        if not address or size < 0 or size > _MAX_OUTPUT_CHARS * 2:
            raise ValueError("invalid guest CRT pointer or size")
        if self.read_guard is not None and not self.read_guard(emu, address, size):
            raise ValueError("guest CRT read denied")
        return emu.mem_read(address, size)

    def _fileno(self, emu, api_name, _original, params) -> int:
        stream = int(params[0])
        process = emu.get_current_process()
        if stream == 0 or process is None:
            return -1
        index = self._standard_index(emu, stream)
        if index is not None:
            return index
        self.unsupported.append(f"{api_name}: nonstandard FILE pointer is not modeled")
        return -1

    def _standard_index(self, emu, stream: int) -> int | None:
        process = emu.get_current_process()
        if process is None:
            return None
        base = self._iob_by_process.get(id(process))
        stride = 32 if emu.get_ptr_size() == 4 else 48
        if base is not None:
            for index in range(3):
                if stream == base + index * stride:
                    return index
        modern = self._ucrt_iob_by_process.get(id(process))
        if modern is not None:
            for index in range(3):
                if stream == modern[0] + index * modern[1]:
                    return index
        return None

    def _fprintf(self, emu, api_name, original, params) -> int:
        if original is None:
            self.unsupported.append(f"{api_name}: format handler unavailable")
            return -1
        # Speakeasy reports VAR_ARGS as argc=-1, leaving `params` empty on
        # x86 even though the two fixed arguments are present on the stack.
        try:
            stream = int(emu.get_func_argv(e_arch.CALL_CONV_CDECL, 2)[0])
            result = original(params)
        except Exception as exc:
            self.unsupported.append(f"{api_name}: formatter failed ({type(exc).__name__})")
            return -1
        index = self._standard_index(emu, stream)
        if index in (1, 2) and self.console_write is not None:
            # Speakeasy's formatter replaces the format argument with its
            # rendered text before returning; it does not write to a handle.
            if len(params) > 1 and isinstance(params[1], str):
                self.console_write("stdout" if index == 1 else "stderr", params[1])
            else:
                self.unsupported.append(f"{api_name}: rendered console text unavailable")
        elif index is None:
            self.unsupported.append(f"{api_name}: nonstandard FILE pointer is not modeled")
        return int(result)

    def _fflush(self, emu, api_name, _original, params) -> int:
        stream = int(params[0])
        if stream == 0 or self._standard_index(emu, stream) is not None:
            return 0  # Standard streams are unbuffered in this model.
        self.unsupported.append(f"{api_name}: nonstandard FILE pointer is not modeled")
        return -1

    def _get_osfhandle(self, emu, api_name, _original, params) -> int:
        descriptor = int(params[0])
        process = emu.get_current_process()
        if process is None:
            return -1
        standard = (0xFFFFFFF6, 0xFFFFFFF5, 0xFFFFFFF4)
        if 0 <= descriptor < len(standard):
            return int(process.get_std_handle(standard[descriptor]))
        self.unsupported.append(f"{api_name}: nonstandard CRT descriptor is not modeled")
        return -1

    def _string(self, emu, address: int, width: int) -> str:
        if not address:
            return "(null)"
        data = bytearray()
        for index in range(_MAX_FORMAT_CHARS):
            char = self._read(emu, address + index * width, width)
            if char == b"\0" * width:
                return data.decode("utf-16le" if width == 2 else "latin-1",
                                   errors="replace")
            data.extend(char)
        raise ValueError("guest CRT string exceeds format limit")

    def _vsnwprintf(self, emu, api_name, _original, params) -> int:
        """Bounded legacy wide formatting; unsupported specifiers stay visible."""
        try:
            buffer, count, format_ptr, arg_ptr = (int(value) for value in params)
            if not 0 < count <= _MAX_OUTPUT_CHARS or not buffer or not arg_ptr:
                raise ValueError("invalid _vsnwprintf buffer or count")
            fmt = self._string(emu, format_ptr, 2)
            pointer_size = emu.get_ptr_size()
            arg_index = 0
            def next_arg():
                nonlocal arg_index
                if arg_index >= 64:
                    raise ValueError("_vsnwprintf argument limit exceeded")
                value = int.from_bytes(self._read(
                    emu, arg_ptr + arg_index * pointer_size, pointer_size), "little")
                arg_index += 1
                return value
            parts = []
            cursor = 0
            while cursor < len(fmt):
                if fmt[cursor] != "%":
                    end = fmt.find("%", cursor)
                    if end < 0:
                        end = len(fmt)
                    parts.append(fmt[cursor:end])
                    cursor = end
                    continue
                match = _FORMAT_SPEC.match(fmt, cursor)
                if match is None:
                    raise ValueError("unsupported _vsnwprintf format specifier")
                flags, width_text, precision_text, length, kind = match.groups()
                cursor = match.end()
                if kind == "%":
                    parts.append("%")
                    continue
                width = self._signed32(next_arg()) if width_text == "*" else int(width_text or 0)
                precision = (self._signed32(next_arg()) if precision_text == "*"
                             else int(precision_text) if precision_text is not None else None)
                if width < 0:
                    flags += "-"
                    width = -width
                if precision is not None and precision < 0:
                    precision = None
                if width > _MAX_FORMAT_CHARS or (precision is not None and
                                                 precision > _MAX_FORMAT_CHARS):
                    raise ValueError("_vsnwprintf field exceeds format limit")
                value = next_arg()
                if kind in "sS":
                    string_width = (2 if kind == "s" and length not in ("h", "hh")
                                    or kind == "S" and length in ("l", "w") else 1)
                    rendered = self._string(emu, value, string_width)
                    if precision is not None:
                        rendered = rendered[:precision]
                elif kind in "cC":
                    rendered = chr(value & (0xFFFF if kind == "c" else 0xFF))
                else:
                    bits = 64 if length in ("ll", "I64") or kind == "p" else 32
                    number = value & ((1 << bits) - 1)
                    if kind in "di" and number & (1 << (bits - 1)):
                        number -= 1 << bits
                    if kind in "diu":
                        rendered = str(number)
                    elif kind in "xXp":
                        rendered = format(number, "X" if kind == "X" else "x")
                        if kind == "p":
                            rendered = rendered.rjust(pointer_size * 2, "0")
                        elif "#" in flags and number:
                            rendered = ("0X" if kind == "X" else "0x") + rendered
                    else:
                        rendered = format(number, "o")
                        if "#" in flags and number:
                            rendered = "0" + rendered
                    if precision is not None and kind != "p":
                        prefix = "-" if rendered.startswith("-") else ""
                        rendered = prefix + rendered[len(prefix):].rjust(precision, "0")
                    if number >= 0 and kind in "di" and "+" in flags:
                        rendered = "+" + rendered
                if width:
                    pad = "0" if "0" in flags and "-" not in flags and kind not in "sScC" else " "
                    rendered = (rendered.ljust(width, " ") if "-" in flags
                                else rendered.rjust(width, pad))
                parts.append(rendered)
                if sum(len(part) for part in parts) > _MAX_OUTPUT_CHARS:
                    raise ValueError("_vsnwprintf result exceeds output limit")
            encoded = "".join(parts).encode("utf-16le", errors="surrogatepass")
            length = len(encoded) // 2
            output = (encoded + b"\0\0") if length < count else encoded[:count * 2]
            if self.write_guard is not None and not self.write_guard(
                    emu, buffer, len(output)):
                raise ValueError("guest CRT write denied")
            emu.mem_write(buffer, output)
            return length if length < count else -1
        except Exception as exc:
            self.unsupported.append(f"{api_name}: {type(exc).__name__}: {exc}")
            return -1

    def _stdio_common_vswprintf(self, emu, api_name, _original, params) -> int:
        """UCRT wide formatting wrapper over the bounded guest vararg reader."""
        if emu.get_ptr_size() == 4 and hasattr(emu, "get_func_argv"):
            raw = list(emu.get_func_argv(e_arch.CALL_CONV_CDECL, 7))
            params = [raw[0] | (raw[1] << 32), *raw[2:]]
        options, buffer, count, format_ptr, locale, arg_ptr = map(int, params)
        if locale or options & ~0x3:
            self.unsupported.append(f"{api_name}: unsupported locale or formatting options")
            return -1
        return self._vsnwprintf(emu, api_name, _original,
                               [buffer, count, format_ptr, arg_ptr])

    @staticmethod
    def _signed32(value: int) -> int:
        value &= 0xffffffff
        return value - 0x100000000 if value & 0x80000000 else value

    def _stdio_common_vfprintf(self, emu, api_name, _original, params) -> int:
        """Format bounded UCRT narrow output into a modeled standard stream."""
        try:
            if emu.get_ptr_size() == 4 and hasattr(emu, "get_func_argv"):
                raw = list(emu.get_func_argv(e_arch.CALL_CONV_CDECL, 6))
                params = [raw[0] | (raw[1] << 32), *raw[2:]]
            options, stream, format_ptr, locale, arg_ptr = map(int, params)
            if locale or options & ~0x3 or not format_ptr or not arg_ptr:
                raise ValueError("unsupported locale, options, or null format arguments")
            index = self._standard_index(emu, stream)
            if index not in (1, 2) or self.console_write is None:
                raise ValueError("nonstandard output stream is not modeled")
            fmt = self._string(emu, format_ptr, 1)
            width = emu.get_ptr_size()
            parts = []
            arg_index = 0
            def next_arg():
                nonlocal arg_index
                if arg_index >= 64:
                    raise ValueError("argument count exceeds limit")
                value = int.from_bytes(self._read(
                    emu, arg_ptr + arg_index * width, width), "little")
                arg_index += 1
                return value
            cursor = 0
            while cursor < len(fmt):
                if fmt[cursor] != "%":
                    end = fmt.find("%", cursor)
                    if end < 0:
                        end = len(fmt)
                    parts.append(fmt[cursor:end])
                    cursor = end
                    continue
                match = _FORMAT_SPEC.match(fmt, cursor)
                if match is None:
                    raise ValueError("unsupported format specifier")
                flags, field_text, precision_text, length, kind = match.groups()
                cursor = match.end()
                if kind == "%":
                    parts.append("%")
                    continue
                field = self._signed32(next_arg()) if field_text == "*" else int(field_text or 0)
                precision = (self._signed32(next_arg()) if precision_text == "*"
                             else int(precision_text) if precision_text is not None else None)
                if field < 0:
                    flags += "-"
                    field = -field
                if precision is not None and precision < 0:
                    precision = None
                if field > _MAX_FORMAT_CHARS or (precision is not None and
                                                precision > _MAX_FORMAT_CHARS):
                    raise ValueError("format field exceeds limit")
                value = next_arg()
                if kind in "sS":
                    string_width = (2 if kind == "S" or length in ("l", "w") else 1)
                    rendered = self._string(emu, value, string_width)
                    if precision is not None:
                        rendered = rendered[:precision]
                elif kind in "cC":
                    rendered = chr(value & (0xffff if kind == "C" else 0xff))
                else:
                    bits = 64 if length in ("ll", "I64") or kind == "p" else 32
                    number = value & ((1 << bits) - 1)
                    if kind in "di" and number & (1 << (bits - 1)):
                        number -= 1 << bits
                    if kind in "diu":
                        rendered = str(number)
                    elif kind in "xXp":
                        rendered = format(number, "X" if kind == "X" else "x")
                        if kind == "p":
                            rendered = rendered.rjust(width * 2, "0")
                        elif "#" in flags and number:
                            rendered = ("0X" if kind == "X" else "0x") + rendered
                    else:
                        rendered = format(number, "o")
                    if precision is not None and kind != "p":
                        sign = "-" if rendered.startswith("-") else ""
                        rendered = sign + rendered[len(sign):].rjust(precision, "0")
                    if number >= 0 and kind in "di" and "+" in flags:
                        rendered = "+" + rendered
                if field:
                    pad = "0" if "0" in flags and "-" not in flags and kind not in "sScC" else " "
                    rendered = (rendered.ljust(field) if "-" in flags
                                else rendered.rjust(field, pad))
                parts.append(rendered)
                if sum(len(part) for part in parts) > _MAX_OUTPUT_CHARS:
                    raise ValueError("formatted output exceeds limit")
            output = "".join(parts)
            # Invariant ASCII is shared by Windows console code pages. Other
            # code pages require a modeled locale before output can be exact.
            output.encode("ascii")
            self.console_write("stdout" if index == 1 else "stderr", output)
            return len(output)
        except Exception as exc:
            self.unsupported.append(f"{api_name}: {type(exc).__name__}: {exc}")
            return -1
