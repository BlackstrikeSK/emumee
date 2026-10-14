"""Bounded guest console output; never writes guest text to host stdio."""

from __future__ import annotations

import struct


MAX_CONSOLE_CHARS = 128 * 1024
MAX_CONSOLE_WRITE_BYTES = 1024 * 1024


class ConsoleOutput:
    def __init__(self, code_page: int = 437):
        self.code_page = code_page
        self._parts = {"stdout": [], "stderr": []}
        self._lengths = {"stdout": 0, "stderr": 0}
        self._truncated = {"stdout": False, "stderr": False}
        self.read_guard = None
        self.write_guard = None

    def append_text(self, stream: str, value: str) -> None:
        remaining = MAX_CONSOLE_CHARS - self._lengths[stream]
        if len(value) > remaining:
            self._truncated[stream] = True
        if remaining > 0:
            part = value[:remaining]
            self._parts[stream].append(part)
            self._lengths[stream] += len(part)

    def report(self) -> dict:
        return {
            "stdout": "".join(self._parts["stdout"]),
            "stderr": "".join(self._parts["stderr"]),
            "stdout_truncated": self._truncated["stdout"],
            "stderr_truncated": self._truncated["stderr"],
        }

    @staticmethod
    def _stream(emu, handle: int) -> str | None:
        process = emu.get_current_process()
        if process is None:
            return None
        # These are Speakeasy's default console handles. A redirected file or
        # pipe is handled by the ordinary virtual-file model instead.
        if handle == 0xF002 and handle == int(process.get_std_handle(0xFFFFFFF5)):
            return "stdout"
        if handle == 0xF003 and handle == int(process.get_std_handle(0xFFFFFFF4)):
            return "stderr"
        return None

    def observe_write_file(self, emu, handle: int, pointer: int, count: int,
                           written_pointer: int = 0) -> None:
        stream = self._stream(emu, handle)
        if stream is None or not pointer or count <= 0:
            return
        if written_pointer:
            if self.read_guard is not None and not self.read_guard(
                    emu, written_pointer, 4):
                return
            try:
                count = min(count, int.from_bytes(
                    emu.mem_read(written_pointer, 4), "little"))
            except Exception:
                return
            if count <= 0:
                return
        length = min(count, MAX_CONSOLE_CHARS + 4)
        if self.read_guard is not None and not self.read_guard(emu, pointer, length):
            return
        try:
            value = emu.mem_read(pointer, length).decode(
                f"cp{self.code_page}", errors="replace")
        except Exception:
            return
        self.append_text(stream, value)
        if count > length:
            self._truncated[stream] = True

    def _write_console(self, emu, api_name, original, params):
        handle, pointer, count, written, reserved = (int(value) for value in params)
        stream = self._stream(emu, handle)
        if stream is None:
            emu.set_last_error(6)  # ERROR_INVALID_HANDLE
            return 0
        if reserved or (count and not pointer):
            emu.set_last_error(87)  # ERROR_INVALID_PARAMETER
            return 0
        width = 2 if api_name.endswith("W") else 1
        byte_count = count * width
        if byte_count > MAX_CONSOLE_WRITE_BYTES:
            emu.set_last_error(8)  # ERROR_NOT_ENOUGH_MEMORY
            return 0
        if byte_count and self.read_guard is not None and not self.read_guard(
                emu, pointer, byte_count):
            return 0
        if written and self.write_guard is not None and not self.write_guard(
                emu, written, 4):
            return 0
        try:
            payload = emu.mem_read(pointer, byte_count) if byte_count else b""
            text = payload.decode("utf-16le" if width == 2 else f"cp{self.code_page}",
                                  errors="replace")
            if written:
                emu.mem_write(written, count.to_bytes(4, "little"))
        except Exception:
            emu.set_last_error(87)
            return 0
        self.append_text(stream, text)
        emu.set_last_error(0)
        return 1

    def install(self, emulator) -> None:
        for module in ("kernel32", "kernelbase"):
            for name in ("WriteConsoleA", "WriteConsoleW"):
                emulator.add_api_hook(self._write_console, module, name, argc=5)
        for module in ("kernel32", "api-ms-win-core-console-l1-1-0",
                       "api-ms-win-core-console-l2-1-0"):
            for name in ("GetConsoleCP", "GetConsoleOutputCP"):
                emulator.add_api_hook(self._get_code_page, module, name, argc=0)
            emulator.add_api_hook(self._screen_buffer_info, module,
                                  "GetConsoleScreenBufferInfo", argc=2)

    def _get_code_page(self, emu, api_name, _original, _params) -> int:
        return self.code_page

    def _screen_buffer_info(self, emu, _api_name, _original, params) -> int:
        handle, output = map(int, params)
        if self._stream(emu, handle) is None:
            emu.set_last_error(6)
            return 0
        if not output or (self.write_guard is not None and not self.write_guard(
                emu, output, 22)):
            emu.set_last_error(87)
            return 0
        try:
            emu.mem_write(output, struct.pack('<hhhhHhhhhhh',
                                              80, 25, 0, 0, 7,
                                              0, 0, 79, 24, 80, 25))
        except Exception:
            emu.set_last_error(87)
            return 0
        emu.set_last_error(0)
        return 1
