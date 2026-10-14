"""Small, process-owned models for legacy Microsoft C runtime state."""

from __future__ import annotations

import struct
import re

from speakeasy import common
from speakeasy.winenv import arch as e_arch


_IOB_ENTRIES = 20
_IOREAD = 0x0001
_IOWRT = 0x0002
_MAX_FORMAT_CHARS = 8192
_MAX_OUTPUT_CHARS = 65536
_FORMAT_SPEC = re.compile(
    r"%([-+ #0]*)(\d{0,5})(?:\.(\d{0,5}))?(hh|h|ll|l|I64|I32|z|t|w)?([diuoxXpcCsS%])")


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
        emulator.add_api_hook(self._vsnwprintf, "msvcrt", "_vsnwprintf", argc=4,
                              call_conv=e_arch.CALL_CONV_CDECL)
        emulator.add_api_hook(self._fileno, "msvcrt", "_fileno", argc=1,
                              call_conv=e_arch.CALL_CONV_CDECL)
        emulator.add_api_hook(self._get_osfhandle, "msvcrt", "_get_osfhandle",
                              argc=1, call_conv=e_arch.CALL_CONV_CDECL)
        emulator.add_api_hook(self._fprintf, "msvcrt", "fprintf", argc=2,
                              call_conv=e_arch.CALL_CONV_CDECL)
        emulator.add_api_hook(self._fflush, "msvcrt", "fflush", argc=1,
                              call_conv=e_arch.CALL_CONV_CDECL)

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
                width = int(width_text or 0)
                precision = int(precision_text) if precision_text is not None else None
                if width > _MAX_FORMAT_CHARS or (precision is not None and
                                                 precision > _MAX_FORMAT_CHARS):
                    raise ValueError("_vsnwprintf field exceeds format limit")
                if arg_index >= 64:
                    raise ValueError("_vsnwprintf argument limit exceeded")
                value = int.from_bytes(self._read(
                    emu, arg_ptr + arg_index * pointer_size, pointer_size), "little")
                arg_index += 1
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
