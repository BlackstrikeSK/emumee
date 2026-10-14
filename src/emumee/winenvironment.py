"""Bounded, guest-owned Windows environment string blocks."""

from __future__ import annotations

import speakeasy.common as common


MAX_ENVIRONMENT_ENTRIES = 256
MAX_ENVIRONMENT_BYTES = 1 << 20


class GuestEnvironmentBlocks:
    def __init__(self):
        self._blocks: dict[int, tuple[int, bool]] = {}
        self.events: list[dict] = []
        self.unsupported: list[str] = []

    def install(self, emulator) -> None:
        emulator.add_api_hook(self._get, "kernel32", "GetEnvironmentStrings*", argc=0)
        emulator.add_api_hook(self._free, "kernel32", "FreeEnvironmentStrings*", argc=1)
        for suffix in ("A", "W"):
            emulator.add_api_hook(self._get_variable, "kernel32",
                                  "GetEnvironmentVariable" + suffix, argc=3)

    @staticmethod
    def _wide(api_name: str) -> bool:
        return api_name.lower().endswith("w")

    def _encode(self, environment: dict, *, wide: bool) -> bytes:
        if len(environment) > MAX_ENVIRONMENT_ENTRIES:
            raise ValueError("environment entry count exceeds limit")
        encoding = "utf-16le" if wide else "cp437"
        terminator = b"\0\0" if wide else b"\0"
        chunks = []
        size = len(terminator)
        for key, value in environment.items():
            name, text = str(key), str(value)
            if not name or "\0" in name or "\0" in text or "=" in name:
                raise ValueError("invalid environment entry")
            chunk = f"{name}={text}".encode(encoding, errors="replace") + terminator
            size += len(chunk)
            if size > MAX_ENVIRONMENT_BYTES:
                raise ValueError("environment block exceeds limit")
            chunks.append(chunk)
        # Every entry ends with NUL; a final NUL terminates the block. An
        # empty block still consists of two NUL characters.
        return b"".join(chunks) + terminator * (2 if not chunks else 1)

    def _get(self, emu, api_name, _original, _params) -> int:
        process = emu.get_current_process()
        if process is None:
            return 0
        address = 0
        try:
            wide = self._wide(api_name)
            payload = self._encode(emu.get_env(), wide=wide)
            address = emu.mem_map(len(payload), tag="api.environment.block",
                                  perms=common.PERM_MEM_RW, process=process)
            emu.mem_write(address, payload)
            self._blocks[address] = (id(process), wide)
            self.events.append({"event": "environment_block_allocated", "api": api_name,
                                "address": hex(address), "size": len(payload),
                                "encoding": "utf-16le" if wide else "cp437"})
            return address
        except Exception as exc:
            if address:
                try:
                    emu.mem_free(address)
                except Exception:
                    pass
            self.unsupported.append(f"{api_name}: {type(exc).__name__}: {exc}")
            emu.set_last_error(8)
            return 0

    def _free(self, emu, api_name, _original, params) -> int:
        address = int(params[0])
        process = emu.get_current_process()
        owner = self._blocks.get(address)
        if (process is None or owner is None or
                owner != (id(process), self._wide(api_name))):
            emu.set_last_error(87)
            return 0
        try:
            emu.mem_free(address)
        except Exception:
            emu.set_last_error(87)
            return 0
        del self._blocks[address]
        self.events.append({"event": "environment_block_freed", "api": api_name,
                            "address": hex(address)})
        return 1

    def _get_variable(self, emu, api_name, _original, params) -> int:
        name_ptr, buffer, capacity = (int(value) for value in params)
        if not name_ptr:
            emu.set_last_error(87)
            return 0
        wide = self._wide(api_name)
        try:
            name = emu.read_mem_string(name_ptr, 2 if wide else 1)
        except Exception:
            emu.set_last_error(998)
            return 0
        if not name or len(name) > 32767 or "=" in name:
            emu.set_last_error(87)
            return 0
        env = {str(key).casefold(): str(value) for key, value in emu.get_env().items()}
        value = env.get(name.casefold())
        if value is None:
            emu.set_last_error(203)  # ERROR_ENVVAR_NOT_FOUND
            return 0
        if "\0" in value or len(value) > 32767:
            emu.set_last_error(87)
            return 0
        encoding = "utf-16-le" if wide else "cp437"
        encoded = value.encode(encoding, errors="replace")
        width = 2 if wide else 1
        copied = len(encoded) // width
        needed = copied + 1
        if capacity < needed:
            emu.set_last_error(122)  # ERROR_INSUFFICIENT_BUFFER
            return needed
        if not buffer:
            emu.set_last_error(87)
            return 0
        try:
            emu.mem_write(buffer, encoded + b"\0" * width)
        except Exception:
            emu.set_last_error(998)
            return 0
        emu.set_last_error(0)
        return copied
