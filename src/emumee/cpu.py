"""Guest-only CPU identity for native user-mode emulation."""

from __future__ import annotations

import struct

from unicorn import UC_HOOK_INSN, UC_QUERY_MODE, UC_MODE_64
from unicorn.x86_const import (UC_X86_INS_CPUID, UC_X86_REG_EAX,
                               UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX,
                               UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX)
from speakeasy.winenv import arch as e_arch

from .avx_fallback import AVXFallback
from .version_compat import manifest_compatibility
from .version_verify import (ERROR_OLD_WIN_VERSION, STATUS_INVALID_PARAMETER,
                             STATUS_REVISION_MISMATCH, actual_version,
                             matches_version, read_request, set_condition)


PRESENT_PROCESSOR_FEATURES = frozenset((
    2, 3, 6, 8, 9, 10, 12, 13, 14, 17, 20, 21, 22, 23, 28,
    32, 36, 37, 38, 39, 40, 42,
))


class VirtualCPU:
    def __init__(self, persona: dict, clock=None):
        self.persona = persona
        self.profile = persona["cpu"]
        self.logical = (int(self.profile["cores"]) *
                        int(self.profile["threads_per_core"]))
        self.processor_id = 0
        self._hook = None
        self.clock = clock
        self._pending_cycles = 0
        self._instructions = 0
        self._primary_image_base = None
        self._primary_compatibility = "none"
        self._child_compatibility = {}
        self.avx_read_guard = None
        self.avx_write_guard = None
        self.avx_fallback = None
        if clock is not None:
            clock.before_observe = self.flush_cycles

    def flush_cycles(self) -> None:
        if self.clock is None:
            return
        cycles_per_microsecond = int(self.profile["base_mhz"])
        microseconds, self._pending_cycles = divmod(
            self._pending_cycles, cycles_per_microsecond)
        if microseconds:
            self.clock.advance_microseconds(microseconds)

    def tsc(self) -> int:
        if self.clock is None:
            return self._pending_cycles
        microseconds = (self.clock.uptime_ms * 1000 +
                        self.clock._submillisecond_100ns // 10)
        return microseconds * int(self.profile["base_mhz"]) + self._pending_cycles

    def observe_instruction(self, emu, address: int, size: int, *, code=None) -> None:
        """Advance guest CPU time and handle direct TSC instructions."""
        self._instructions += 1
        self._pending_cycles += 100
        if self._instructions % 1000 == 0:
            self.flush_cycles()
        if self.avx_fallback is not None:
            self.avx_fallback.observe_instruction(emu.emu_eng.emu, address, size, code=code)
        if size not in (2, 3):
            return
        op = code if code is not None else emu.mem_read(address, size)
        if op not in (b"\x0f\x31", b"\x0f\x01\xf9", b"\x0f\x01\xd0"):
            return
        from speakeasy.winenv import arch as e_arch
        if emu.get_ptr_size() == 8:
            eax, edx, ecx = (e_arch.AMD64_REG_RAX, e_arch.AMD64_REG_RDX,
                             e_arch.AMD64_REG_RCX)
        else:
            eax, edx, ecx = (e_arch.X86_REG_EAX, e_arch.X86_REG_EDX,
                             e_arch.X86_REG_ECX)
        if op == b"\x0f\x01\xd0":
            # XCR0 enables x87, SSE, and AVX, matching CPUID leaf 1/D.
            value = 7 if emu.reg_read(ecx) == 0 else 0
            emu.reg_write(eax, value)
            emu.reg_write(edx, 0)
        else:
            self.flush_cycles()
            value = self.tsc() & 0xFFFFFFFFFFFFFFFF
            emu.reg_write(eax, value & 0xFFFFFFFF)
            emu.reg_write(edx, (value >> 32) & 0xFFFFFFFF)
        if op == b"\x0f\x01\xf9":
            emu.reg_write(ecx, self.processor_id)  # IA32_TSC_AUX within group 0.
        emu.set_pc(address + size)

    def install(self, emulator) -> None:
        emulator.add_api_hook(self._get_system_info, "kernel32", "GetSystemInfo")
        emulator.add_api_hook(self._get_system_info, "kernel32", "GetNativeSystemInfo")
        emulator.add_api_hook(self._is_processor_feature_present, "kernel32",
                              "IsProcessorFeaturePresent")
        emulator.add_api_hook(self._rtl_get_version, "ntdll", "RtlGetVersion")
        emulator.add_api_hook(self._rtl_get_nt_version_numbers, "ntdll",
                              "RtlGetNtVersionNumbers")
        emulator.add_api_hook(self._get_version, "kernel32", "GetVersion")
        for name in ("GetVersionExA", "GetVersionExW"):
            emulator.add_api_hook(self._get_version_ex, "kernel32", name)
        emulator.add_api_hook(self._ver_set_condition_mask, "kernel32",
                              "VerSetConditionMask", argc=4,
                              call_conv=e_arch.CALL_CONV_STDCALL)
        emulator.add_api_hook(self._ver_set_condition_mask, "ntdll",
                              "VerSetConditionMask", argc=4,
                              call_conv=e_arch.CALL_CONV_STDCALL)
        for name in ("VerifyVersionInfoA", "VerifyVersionInfoW"):
            emulator.add_api_hook(self._verify_version_info, "kernel32", name,
                                  argc=4, call_conv=e_arch.CALL_CONV_STDCALL)
        emulator.add_api_hook(self._rtl_verify_version_info, "ntdll",
                              "RtlVerifyVersionInfo", argc=4,
                              call_conv=e_arch.CALL_CONV_STDCALL)
        emulator.add_api_hook(self._global_memory_status, "kernel32",
                              "GlobalMemoryStatus")
        emulator.add_api_hook(self._global_memory_status_ex, "kernel32",
                              "GlobalMemoryStatusEx")

    def attach(self, emu) -> None:
        if emu.get_ptr_size() == 4 and not getattr(emu, "kernel_mode", False):
            # Speakeasy's stock declarations count a ULONGLONG as one x86
            # stack slot and mark these WinAPI exports cdecl. Correct the
            # current engine instance so real stdcall callers keep ESP intact.
            kernel = emu.api.load_api_handler("kernel32")
            for name in ("VerSetConditionMask", "VerifyVersionInfo"):
                handler_name, func, _argc, _conv, ordinal = kernel.funcs[name]
                kernel.funcs[name] = (handler_name, func, 4,
                                      e_arch.CALL_CONV_STDCALL, ordinal)
            ntdll = emu.api.load_api_handler("ntdll")
            if "VerSetConditionMask" in ntdll.funcs:
                handler_name, func, _argc, _conv, ordinal = ntdll.funcs["VerSetConditionMask"]
                ntdll.funcs["VerSetConditionMask"] = (
                    handler_name, func, 4, e_arch.CALL_CONV_STDCALL, ordinal)
        # The installed Unicorn CPUID hook returns nonzero to suppress its
        # built-in QEMU CPU result. Every leaf is handled, so no guest request
        # can fall through to an engine or host CPU identity.
        self._hook = emu.emu_eng.emu.hook_add(
            UC_HOOK_INSN, self._cpuid, None, 1, 0, UC_X86_INS_CPUID)
        self.avx_fallback = AVXFallback(emu.get_ptr_size())
        self.avx_fallback.read_guard = self.avx_read_guard
        self.avx_fallback.write_guard = self.avx_write_guard
        self.avx_fallback.attach(emu.emu_eng.emu)
        self._populate_shared_data(emu)

    def _populate_shared_data(self, emu) -> None:
        """Fill stable KUSER_SHARED_DATA fields from the guest persona."""
        features = bytearray(64)
        for index in PRESENT_PROCESSOR_FEATURES:
            features[index] = 1
        root = r"C:\Windows".encode("utf-16le") + b"\0\0"
        fields = ((0x02C, struct.pack("<HH", 0x8664, 0x8664)),
                  (0x030, root.ljust(520, b"\0")),
                  (0x260, struct.pack("<I", int(self.persona["windows_build"]))),
                  (0x264, struct.pack("<I", 1)),  # workstation product
                  (0x268, struct.pack("<BBH", 1, 0, 9)),
                  (0x26C, struct.pack("<I", 10)),
                  (0x270, struct.pack("<I", 0)),
                  (0x274, bytes(features)),
                  (0x2E8, struct.pack("<I", int(self.persona["physical_memory_mb"]) * 256)),
                  (0x3C0, struct.pack("<I", self.logical)),
                  (0x3C4, struct.pack("<B", 1)))
        aliases = (self.clock._shared_data_addresses if self.clock is not None
                   else (0x7FFE0000,))
        for base in aliases:
            for offset, data in fields:
                emu.mem_write(base + offset, data)

    @staticmethod
    def _cache_leaf(kind: int, level: int, size: int, ways: int,
                    sharing: int, cores: int) -> tuple[int, int, int, int]:
        line = 64
        sets = size // (ways * line)
        eax = (kind | (level << 5) | ((sharing - 1) << 14) |
               ((cores - 1) << 26))
        ebx = ((ways - 1) << 22) | (line - 1)
        return eax, ebx, sets - 1, 0

    def leaf(self, function: int, subleaf: int = 0) -> tuple[int, int, int, int]:
        function &= 0xFFFFFFFF
        subleaf &= 0xFFFFFFFF
        vendor = b"GenuineIntel"
        cores = int(self.profile["cores"])
        threads = int(self.profile["threads_per_core"])
        if function == 0:
            ebx, edx, ecx = struct.unpack("<III", vendor)
            return 0x16, ebx, ecx, edx
        if function == 1:
            ebx = ((self.processor_id & 255) << 24) | ((min(self.logical, 255) << 16) | (8 << 8))
            # The fixed feature profile matches the modeled modern Intel CPU.
            # In particular ECX[31] is clear and AVX/XSAVE match leaf 7/D.
            ecx_bits = (0, 1, 3, 5, 9, 12, 13, 17, 19, 20, 21, 22, 23,
                        24, 25, 26, 27, 28, 29, 30)
            ecx = sum(1 << bit for bit in ecx_bits)
            edx = 0xBFEBFBFF
            return int(self.profile["signature"]), ebx, ecx, edx
        if function == 4:
            caches = ((1, 1, 32 * 1024, 8, threads),
                      (2, 1, 32 * 1024, 8, threads),
                      (3, 2, 256 * 1024, 4, threads),
                      (3, 3, 12 * 1024 * 1024, 12, self.logical))
            if subleaf < len(caches):
                return self._cache_leaf(*caches[subleaf], cores)
            return 0, 0, 0, 0
        if function == 7:
            if subleaf:
                return 0, 0, 0, 0
            ebx_bits = (0, 3, 5, 7, 8, 9, 10, 18, 19, 20, 23, 24, 29)
            return 0, sum(1 << bit for bit in ebx_bits), 0, 0
        if function == 0xB:
            if subleaf == 0:
                return (threads - 1).bit_length(), threads, 1 << 8, self.processor_id
            if subleaf == 1:
                return (self.logical - 1).bit_length(), self.logical, (2 << 8) | 1, self.processor_id
            return 0, 0, 0, self.processor_id
        if function == 0xD:
            if subleaf == 0:
                return 7, 832, 832, 0
            if subleaf == 1:
                return 1, 0, 0, 0
            if subleaf == 2:
                return 256, 576, 0, 0
            return 0, 0, 0, 0
        if function == 0x15:
            return 24, int(self.profile["base_mhz"]), 24_000_000, 0
        if function == 0x16:
            return (int(self.profile["base_mhz"]),
                    int(self.profile["max_mhz"]), 100, 0)
        if function == 0x80000000:
            return 0x80000008, 0, 0, 0
        if function == 0x80000001:
            return 0, 0, 1, sum(1 << bit for bit in (11, 20, 27, 29))
        if 0x80000002 <= function <= 0x80000004:
            brand = self.profile["brand"].encode("ascii").ljust(48, b" ")
            return struct.unpack_from("<IIII", brand, (function - 0x80000002) * 16)
        if function == 0x80000007:
            return 0, 0, 0, 1 << 8
        if function == 0x80000008:
            return 39 | (48 << 8), 0, 0, 0
        return 0, 0, 0, 0

    def _cpuid(self, engine, _user_data) -> int:
        function = engine.reg_read(UC_X86_REG_EAX)
        subleaf = engine.reg_read(UC_X86_REG_ECX)
        # Unicorn's API writes to EAX/EBX/... leave upper halves untouched.
        # CPUID itself clears them in 64-bit mode, so write the full registers.
        registers = ((UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX)
                     if engine.query(UC_QUERY_MODE) & UC_MODE_64 else
                     (UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX))
        for register, value in zip(registers, self.leaf(function, subleaf)):
            engine.reg_write(register, value & 0xFFFFFFFF)
        return 1

    def _get_system_info(self, emu, api_name, original, params):
        pointer = int(params[0])
        if not pointer:
            return 0
        is_x64 = emu.get_ptr_size() == 8
        architecture = 9 if is_x64 or api_name.endswith("GetNativeSystemInfo") else 0
        # SYSTEM_INFO exposes one processor group's pointer-width affinity mask.
        # A 32-bit caller cannot represent more than 32 active bits here.
        visible = self.logical if is_x64 else min(self.logical, 32)
        mask = (1 << visible) - 1
        signature = int(self.profile["signature"])
        model = (((signature >> 16) & 0xF) << 4) | ((signature >> 4) & 0xF)
        revision = (model << 8) | (signature & 0xF)
        if is_x64:
            data = struct.pack("<HHI3Q3IHH", architecture, 0, 4096,
                               0x10000, 0x7FFFFFFEFFFF, mask,
                               visible, 586, 0x10000, 6, revision)
        else:
            data = struct.pack("<HHI6IHH", architecture, 0, 4096,
                               0x10000, 0x7FFEFFFF, mask,
                               visible, 586, 0x10000, 6, revision)
        emu.mem_write(pointer, data)
        return 0

    def _is_processor_feature_present(self, emu, api_name, original, params):
        """Match WinAPI queries to the guest shared page for known features."""
        return int(int(params[0]) in PRESENT_PROCESSOR_FEATURES)

    def _rtl_get_version(self, emu, api_name, original, params):
        """Return the same Windows build as the guest PEB and shared page."""
        pointer = int(params[0])
        if not pointer:
            return 0xC000000D  # STATUS_INVALID_PARAMETER
        try:
            size = struct.unpack("<I", emu.mem_read(pointer, 4))[0]
            if size not in (276, 284):
                return 0xC000000D
            data = bytearray(size)
            struct.pack_into("<IIIII", data, 0, size, 10, 0,
                             int(self.persona["windows_build"]), 2)
            if size == 284:
                data[282] = 1  # VER_NT_WORKSTATION
            emu.mem_write(pointer, bytes(data))
        except Exception:
            return 0xC0000005  # STATUS_ACCESS_VIOLATION
        return 0

    def _rtl_get_nt_version_numbers(self, emu, api_name, original, params):
        """Provide NTDLL's three version outputs from the same persona."""
        build = 0xF0000000 | int(self.persona["windows_build"])
        for pointer, value in zip(params, (10, 0, build)):
            if int(pointer):
                emu.mem_write(int(pointer), struct.pack("<I", value))
        return 0

    def register_primary_image(self, base: int, image: bytes) -> None:
        self._primary_image_base = int(base)
        self._primary_compatibility = manifest_compatibility(image)

    def register_child_image(self, process, image: bytes) -> None:
        self._child_compatibility[id(process)] = manifest_compatibility(image)

    def _win32_version(self, emu) -> tuple[int, int, int]:
        process = emu.get_current_process()
        if process is None:
            compatibility = self._primary_compatibility
        elif id(process) in self._child_compatibility:
            compatibility = self._child_compatibility[id(process)]
        elif int(process.base) == self._primary_image_base:
            compatibility = self._primary_compatibility
        else:
            compatibility = "none"
        if compatibility == "win10":
            return 10, 0, int(self.persona["windows_build"])
        if compatibility == "win81":
            return 6, 3, 9600
        return 6, 2, 9200

    def _get_version(self, emu, api_name, original, params):
        major, minor, build = self._win32_version(emu)
        return ((build << 16) | (minor << 8) | major) & 0xFFFFFFFF

    def _get_version_ex(self, emu, api_name, original, params):
        pointer = int(params[0])
        if not pointer:
            emu.set_last_error(87)
            return 0
        wide = not api_name.lower().endswith("a")
        base_size, extended_size = ((276, 284) if wide else (148, 156))
        try:
            size = struct.unpack("<I", emu.mem_read(pointer, 4))[0]
            if size not in (base_size, extended_size):
                emu.set_last_error(87)
                return 0
            major, minor, build = self._win32_version(emu)
            data = bytearray(size)
            struct.pack_into("<IIIII", data, 0, size, major, minor, build, 2)
            if size == extended_size:
                data[282 if wide else 154] = 1  # VER_NT_WORKSTATION
            emu.mem_write(pointer, bytes(data))
        except Exception:
            emu.set_last_error(998)
            return 0
        return 1

    @staticmethod
    def _condition_args(emu, params, *, version_query: bool):
        if emu.get_ptr_size() == 8:
            return int(params[0]), int(params[1]), int(params[2])
        if len(params) < 4:
            # Speakeasy declares these Win32 exports as three arguments even
            # though their ULONGLONG consumes two x86 stack words.
            params = emu.get_func_argv(e_arch.CALL_CONV_CDECL, 4)
        if version_query:
            return (int(params[0]), int(params[1]),
                    int(params[2]) | (int(params[3]) << 32))
        return (int(params[0]) | (int(params[1]) << 32),
                int(params[2]), int(params[3]))

    def _ver_set_condition_mask(self, emu, api_name, original, params):
        mask, type_mask, condition = self._condition_args(
            emu, params, version_query=False)
        result = set_condition(mask, type_mask, condition)
        if emu.get_ptr_size() == 4 and hasattr(emu, "reg_write"):
            emu.reg_write(e_arch.X86_REG_EDX, result >> 32)
        return result & (0xFFFFFFFF if emu.get_ptr_size() == 4 else
                         0xFFFFFFFFFFFFFFFF)

    def _verify_version_info(self, emu, api_name, original, params):
        pointer, type_mask, condition_mask = self._condition_args(
            emu, params, version_query=True)
        try:
            request = read_request(emu, pointer,
                                   wide=api_name.lower().endswith("w"))
        except Exception:
            emu.set_last_error(998)  # ERROR_NOACCESS
            return 0
        if request is None:
            emu.set_last_error(87)  # ERROR_INVALID_PARAMETER
            return 0
        result = matches_version(request,
                                 actual_version(*self._win32_version(emu)),
                                 type_mask, condition_mask)
        if result is None:
            emu.set_last_error(87)
            return 0
        if not result:
            emu.set_last_error(ERROR_OLD_WIN_VERSION)
            return 0
        return 1

    def _rtl_verify_version_info(self, emu, api_name, original, params):
        pointer, type_mask, condition_mask = self._condition_args(
            emu, params, version_query=True)
        try:
            request = read_request(emu, pointer, wide=True)
        except Exception:
            return 0xC0000005  # STATUS_ACCESS_VIOLATION
        if request is None:
            return STATUS_INVALID_PARAMETER
        result = matches_version(
            request, actual_version(10, 0, int(self.persona["windows_build"])),
            type_mask, condition_mask)
        if result is None:
            return STATUS_INVALID_PARAMETER
        return 0 if result else STATUS_REVISION_MISMATCH

    def _memory_values(self, width: int) -> tuple[int, ...]:
        mib = 1024 * 1024
        total = int(self.persona["physical_memory_mb"]) * mib
        available = int(self.persona["available_memory_mb"]) * mib
        load = round(100 * (total - available) / total)
        pagefile_total = total + 8192 * mib
        pagefile_available = available + 4096 * mib
        virtual_total = ((0x7FFFFFFEFFFF - 0x10000) if width == 8
                         else (0x7FFEFFFF - 0x10000))
        virtual_available = virtual_total - (1024 if width == 8 else 256) * mib
        return (load, total, available, pagefile_total, pagefile_available,
                virtual_total, virtual_available)

    def _global_memory_status_ex(self, emu, api_name, original, params):
        pointer = int(params[0])
        if not pointer:
            emu.set_last_error(87)
            return 0
        try:
            length = struct.unpack("<I", emu.mem_read(pointer, 4))[0]
            if length != 64:
                emu.set_last_error(87)
                return 0
            load, total, available, page_total, page_available, virtual_total, virtual_available = (
                self._memory_values(emu.get_ptr_size()))
            emu.mem_write(pointer, struct.pack(
                "<II7Q", 64, load, total, available, page_total, page_available,
                virtual_total, virtual_available, 0))
        except Exception:
            emu.set_last_error(998)
            return 0
        return 1

    def _global_memory_status(self, emu, api_name, original, params):
        pointer = int(params[0])
        if not pointer:
            return 0
        width = emu.get_ptr_size()
        load, total, available, page_total, page_available, virtual_total, virtual_available = (
            self._memory_values(width))
        if width == 8:
            data = struct.pack("<II6Q", 56, load, total, available, page_total,
                               page_available, virtual_total, virtual_available)
        else:
            data = struct.pack("<8I", 32, load, *(min(value, 0xFFFFFFFF) for value in
                                                   (total, available, page_total,
                                                    page_available, virtual_total,
                                                    virtual_available)))
        emu.mem_write(pointer, data)
        return 0
