"""Execute bounded CRT initializer arrays and model startup arguments."""

from __future__ import annotations

import struct

import speakeasy.common as common
from speakeasy.winenv import arch as e_arch


MAX_INITIALIZERS = 128
MAX_ARGUMENTS = 256
MAX_STARTUP_BYTES = 1 << 20


class CRTStartup:
    def __init__(self):
        self.unsupported: list[str] = []
        self.events: list[dict] = []
        self.read_guard = None
        self.write_guard = None
        self.execute_guard = None
        self._initial_env_by_process: dict[tuple[int, bool], int] = {}
        self._argument_globals_by_process: dict[int, tuple[int, int, int]] = {}

    def install(self, emulator) -> None:
        for name, method in (("_initterm", self._initterm),
                             ("_initterm_e", self._initterm_e)):
            emulator.add_api_hook(method, "msvcrt", name, argc=2,
                                  call_conv=e_arch.CALL_CONV_CDECL)
        emulator.add_api_hook(self._wgetmainargs, "msvcrt", "__wgetmainargs",
                              argc=5, call_conv=e_arch.CALL_CONV_CDECL)
        emulator.add_api_hook(self._getmainargs, "msvcrt", "__getmainargs",
                              argc=5, call_conv=e_arch.CALL_CONV_CDECL)
        for module in ("api-ms-win-crt-private-l1-1-0", "ucrtbase"):
            for name, wide in (("_o__get_initial_wide_environment", True),
                               ("_o__get_initial_narrow_environment", False),
                               ("_get_initial_wide_environment", True),
                               ("_get_initial_narrow_environment", False)):
                emulator.add_api_hook(self._initial_environment, module, name,
                                      argc=0, call_conv=e_arch.CALL_CONV_CDECL)
            for name in ("_o___p___argc", "_o___p___argv", "_o___p___wargv",
                         "__p___argc", "__p___argv", "__p___wargv"):
                emulator.add_api_hook(self._argument_global, module, name,
                                      argc=0, call_conv=e_arch.CALL_CONV_CDECL)

    def _argument_global(self, emu, api_name, _original, _params) -> int:
        process = emu.get_current_process()
        if process is None:
            return 0
        owner = id(process)
        addresses = self._argument_globals_by_process.get(owner)
        if addresses is None:
            arguments = list(emu.get_argv())
            if len(arguments) > MAX_ARGUMENTS:
                self.unsupported.append(f"{api_name}: argument count exceeds limit")
                return 0
            width = emu.get_ptr_size()
            encoded = (
                [(str(arg) + "\0").encode("cp1252", errors="replace")
                 for arg in arguments],
                [(str(arg) + "\0").encode("utf-16le", errors="replace")
                 for arg in arguments],
            )
            array_size = width * (len(arguments) + 1)
            total = 3 * width + 2 * array_size + sum(
                len(item) for group in encoded for item in group)
            if total > MAX_STARTUP_BYTES:
                self.unsupported.append(f"{api_name}: argument bytes exceed limit")
                return 0
            base = 0
            try:
                base = emu.mem_map(total, tag="api.ucrt.argument_globals",
                                   perms=common.PERM_MEM_RW, process=process)
                narrow_array = base + 3 * width
                wide_array = narrow_array + array_size
                cursor = wide_array + array_size
                emu.mem_write(base, struct.pack('<I', len(arguments)))
                emu.mem_write(base + width, narrow_array.to_bytes(width, 'little'))
                emu.mem_write(base + 2 * width, wide_array.to_bytes(width, 'little'))
                for array, strings in ((narrow_array, encoded[0]),
                                       (wide_array, encoded[1])):
                    for index, item in enumerate(strings):
                        emu.mem_write(array + index * width,
                                      cursor.to_bytes(width, 'little'))
                        emu.mem_write(cursor, item)
                        cursor += len(item)
                    emu.mem_write(array + len(strings) * width, b'\0' * width)
            except Exception:
                if base:
                    emu.mem_free(base)
                self.unsupported.append(f"{api_name}: guest argument allocation failed")
                return 0
            addresses = (base, base + width, base + 2 * width)
            self._argument_globals_by_process[owner] = addresses
        if api_name.endswith('wargv'):
            return addresses[2]
        if api_name.endswith('argv'):
            return addresses[1]
        return addresses[0]

    def _initial_environment(self, emu, api_name, _original, _params) -> int:
        process = emu.get_current_process()
        if process is None:
            return 0
        wide = "wide" in api_name
        key = (id(process), wide)
        if key in self._initial_env_by_process:
            return self._initial_env_by_process[key]
        environment = emu.get_env()
        if len(environment) > MAX_ARGUMENTS:
            self.unsupported.append(f"{api_name}: environment entry limit exceeded")
            return 0
        encoding = "utf-16le" if wide else "cp1252"
        strings = [(f"{name}={value}\0").encode(encoding, errors="replace")
                   for name, value in environment.items()]
        width = emu.get_ptr_size()
        array_size = width * (len(strings) + 1)
        total = array_size + sum(map(len, strings))
        if total > MAX_STARTUP_BYTES:
            self.unsupported.append(f"{api_name}: environment byte limit exceeded")
            return 0
        address = 0
        try:
            address = emu.mem_map(max(total, width), tag="api.ucrt.initial_env",
                                  perms=common.PERM_MEM_RW, process=process)
            cursor = address + array_size
            for index, value in enumerate(strings):
                emu.mem_write(address + index * width,
                              cursor.to_bytes(width, "little"))
                emu.mem_write(cursor, value)
                cursor += len(value)
            emu.mem_write(address + len(strings) * width, b"\0" * width)
        except Exception:
            if address:
                emu.mem_free(address)
            self.unsupported.append(f"{api_name}: guest environment allocation failed")
            return 0
        self._initial_env_by_process[key] = address
        self.events.append({"event": "crt_initial_environment",
                            "encoding": encoding, "environment_count": len(strings)})
        return address

    def cleanup_process(self, process) -> None:
        owner = id(process)
        self._argument_globals_by_process.pop(owner, None)
        for key in tuple(self._initial_env_by_process):
            if key[0] == owner:
                self._initial_env_by_process.pop(key, None)

    def attach(self, emu) -> None:
        if emu.get_ptr_size() != 4:
            return
        # Speakeasy's stock __getmainargs declarations use stdcall on x86.
        # The CRT caller removes its five arguments, so the underlying
        # handler's convention must also be corrected for our hook to work.
        msvcrt = emu.api.load_api_handler("msvcrt")
        for name in ("__getmainargs", "__wgetmainargs"):
            handler_name, func, _argc, _conv, ordinal = msvcrt.funcs[name]
            msvcrt.funcs[name] = (
                handler_name, func, 5, e_arch.CALL_CONV_CDECL, ordinal)

    def _allowed(self, emu, address: int, size: int, mode: str) -> bool:
        guard = {"read": self.read_guard, "write": self.write_guard,
                 "execute": self.execute_guard}[mode]
        if not address or size <= 0:
            return False
        mapped = emu.get_address_map(address)
        required = {"read": common.PERM_MEM_READ,
                    "write": common.PERM_MEM_WRITE,
                    "execute": common.PERM_MEM_EXEC}[mode]
        if (mapped is None or mapped.free or
                address + size > int(mapped.base) + int(mapped.size) or
                not (int(mapped.prot) & required)):
            return False
        return bool(guard is None or guard(emu, address, size))

    def _initializers(self, emu, api_name: str, begin: int, end: int) -> list[int] | None:
        width = emu.get_ptr_size()
        count = (end - begin) // width if end >= begin else -1
        if ((begin % width) or (end % width) or count < 0 or
                count > MAX_INITIALIZERS or (end - begin) != count * width):
            self.unsupported.append(f"{api_name}: invalid or oversized initializer range")
            return None
        if count == 0:
            return []
        if not self._allowed(emu, begin, end - begin, "read"):
            self.unsupported.append(f"{api_name}: initializer array read denied")
            return None
        try:
            raw = emu.mem_read(begin, end - begin)
        except Exception:
            self.unsupported.append(f"{api_name}: initializer array unreadable")
            return None
        fmt = "<" + ("Q" if width == 8 else "I") * count
        callbacks = [int(address) for address in struct.unpack(fmt, raw) if address]
        for address in callbacks:
            mapped = emu.get_address_map(address)
            if (mapped is None or mapped.free or
                    not (int(mapped.prot) & common.PERM_MEM_EXEC) or
                    not self._allowed(emu, address, 1, "execute")):
                self.unsupported.append(
                    f"{api_name}: initializer target {address:#x} not executable by guest")
                return None
        return callbacks

    def _dispatch(self, emu, api_name: str, params, *, error_returning: bool) -> int:
        begin, end = map(int, params)
        callbacks = self._initializers(emu, api_name, begin, end)
        if not callbacks:
            return 0
        width = emu.get_ptr_size()
        original_return = emu.get_ret_address()
        code = bytearray(b"\x48\x83\xec\x20" if width == 8 else b"")
        call_offsets: list[tuple[int, int]] = []
        failure_patches: list[int] = []
        for address in callbacks:
            call_offsets.append((len(code), address))
            if width == 8:
                code.extend(b"\x48\xb8" + struct.pack("<Q", address) + b"\xff\xd0")
            else:
                code.extend(b"\xb8" + struct.pack("<I", address) + b"\xff\xd0")
            if error_returning:
                code.extend(b"\x85\xc0\x0f\x85\0\0\0\0")
                failure_patches.append(len(code) - 4)

        def emit_return():
            if width == 8:
                code.extend(b"\x48\x83\xc4\x20\x49\xbb" +
                            struct.pack("<Q", original_return) + b"\x41\xff\xe3")
            else:
                code.extend(b"\x68" + struct.pack("<I", original_return) + b"\xc3")

        success_offset = len(code)
        code.extend(b"\x31\xc0")  # successful _initterm_e return, void _initterm
        emit_return()
        failure_offset = len(code)
        if failure_patches:
            emit_return()  # preserve nonzero EAX from the failed callback
            for patch in failure_patches:
                struct.pack_into("<i", code, patch, failure_offset - patch - 4)
        if len(code) > 0x1000:
            self.unsupported.append(f"{api_name}: initializer bootstrap too large")
            return 0
        bootstrap = emu.mem_map(0x1000, tag="emu.crt_initializers",
                                process=emu.get_current_process())
        emu.mem_write(bootstrap, bytes(code))
        hooks = []
        for index, (offset, address) in enumerate(call_offsets):
            def started(_active_emu, _address, _size, index=index, address=address):
                self.events.append({"event": "crt_initializer", "api": api_name,
                                    "index": index, "address": hex(address)})
                return True
            hooks.append(emu.add_code_hook(started, begin=bootstrap + offset,
                                           end=bootstrap + offset + 1))
        def completed(active_emu, _address, _size, *, failure=False):
            self.events.append({"event": "crt_initializer_result", "api": api_name,
                                "result": int(active_emu.reg_read("eax")) if failure else 0})
            return True
        hooks.append(emu.add_code_hook(completed, begin=bootstrap + success_offset,
                                       end=bootstrap + success_offset + 1))
        if failure_patches:
            hooks.append(emu.add_code_hook(
                lambda active_emu, address, size: completed(
                    active_emu, address, size, failure=True),
                begin=bootstrap + failure_offset, end=bootstrap + failure_offset + 1))
        emu._emumee_crt_hooks = getattr(emu, "_emumee_crt_hooks", []) + hooks
        # The imported CRT call has one return address. The x86 arguments
        # remain on the caller's stack because these functions are cdecl.
        emu.set_stack_ptr(emu.get_stack_ptr() + width)
        emu.set_pc(bootstrap)
        return 0

    def _initterm(self, emu, api_name, _original, params) -> int:
        return self._dispatch(emu, api_name, params, error_returning=False)

    def _initterm_e(self, emu, api_name, _original, params) -> int:
        return self._dispatch(emu, api_name, params, error_returning=True)

    def _mainargs(self, emu, api_name, params, *, wide: bool) -> int:
        argc_ptr, argv_ptr, env_ptr, wildcard, _startup = map(int, params)
        width = emu.get_ptr_size()
        if wildcard:
            self.unsupported.append(f"{api_name}: wildcard expansion not modeled")
        for address, size in ((argc_ptr, 4), (argv_ptr, width), (env_ptr, width)):
            if not self._allowed(emu, address, size, "write"):
                self.unsupported.append(f"{api_name}: output pointer denied")
                return 22
        argv = list(emu.get_argv())
        environment = emu.get_env()
        if len(argv) > MAX_ARGUMENTS or len(environment) > MAX_ARGUMENTS:
            self.unsupported.append(f"{api_name}: argument or environment count exceeds limit")
            return 12
        encoding = "utf-16le" if wide else "cp1252"
        args = [(str(item) + "\0").encode(encoding, errors="replace") for item in argv]
        envs = [(f"{key}={value}\0").encode(encoding, errors="replace")
                for key, value in environment.items()]
        total = sum(map(len, args + envs)) + width * (len(args) + len(envs) + 2)
        if total > MAX_STARTUP_BYTES:
            self.unsupported.append(f"{api_name}: argument or environment bytes exceed limit")
            return 12
        process = emu.get_current_process()

        def allocate(strings: list[bytes], tag: str) -> int:
            array_bytes = width * (len(strings) + 1)
            address = emu.mem_map(array_bytes + sum(map(len, strings)),
                                  tag=tag, perms=common.PERM_MEM_RW, process=process)
            cursor = address + array_bytes
            for index, value in enumerate(strings):
                emu.mem_write(address + index * width, cursor.to_bytes(width, "little"))
                emu.mem_write(cursor, value)
                cursor += len(value)
            emu.mem_write(address + len(strings) * width, b"\0" * width)
            return address

        try:
            arguments = allocate(args, "api.msvcrt.wargv" if wide else "api.msvcrt.argv")
            variables = allocate(envs, "api.msvcrt.wenv" if wide else "api.msvcrt.env")
            emu.mem_write(argc_ptr, struct.pack("<I", len(args)))
            emu.mem_write(argv_ptr, arguments.to_bytes(width, "little"))
            emu.mem_write(env_ptr, variables.to_bytes(width, "little"))
        except Exception:
            self.unsupported.append(f"{api_name}: guest startup memory allocation failed")
            return 12
        self.events.append({"event": "crt_wide_arguments" if wide else "crt_arguments",
                            "argc": len(args),
                            "environment_count": len(envs)})
        return 0

    def _wgetmainargs(self, emu, api_name, _original, params) -> int:
        return self._mainargs(emu, api_name, params, wide=True)

    def _getmainargs(self, emu, api_name, _original, params) -> int:
        return self._mainargs(emu, api_name, params, wide=False)
