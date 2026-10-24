"""Kernel API models installed before modeled system exports are built."""

from speakeasy.winenv import arch
import datetime as dt
import struct
from collections import deque
from .crt import LegacyCRTStreams


def guest_range(emu, address, size, permission):
    if size < 0 or not address or address + size > 1 << (emu.get_ptr_size() * 8):
        return False
    cursor, stop = address, address + size
    for start, end, permissions in sorted(emu.emu_eng.emu.mem_regions()):
        if start <= cursor <= end:
            if not permissions & permission:
                return False
            cursor = min(stop, end + 1)
            if cursor == stop:
                return True
    return False


def require_range(emu, address, size, write=False):
    if not guest_range(emu, address, size, 2 if write else 1):
        raise ValueError("Kernel API guest pointer is not " + ("writable" if write else "readable"))


def rtl_pc_to_file_header(_handler, emu, argv, ctx=None):
    pc, output = (int(value) for value in argv)
    width = emu.get_ptr_size()
    # Python memory helpers bypass guest page permissions. Validate the output
    # across every covered native region before writing through such a helper.
    if not guest_range(emu, output, width, 2):
        raise ValueError("RtlPcToFileHeader output is not a writable guest pointer")
    # The engine's current-module shortcut includes its one-past-end address.
    # This API uses the image's half-open range, as the loader does.
    module = next((item for item in emu.modules if item.base <= pc < item.base + item.image_size), None)
    base = module.base if module is not None else 0
    emu.mem_write(output, int(base).to_bytes(width, "little"))
    return base


def rtl_duplicate_unicode_string(_handler, emu, argv, ctx=None):
    flags, source, output = map(int, argv)
    if flags not in (0, 1, 3):
        return 0xC000000D
    width = emu.get_ptr_size()
    structure_size = 16 if width == 8 else 8
    require_range(emu, source, structure_size)
    require_range(emu, output, structure_size, True)
    data = emu.mem_read(source, structure_size)
    length, maximum = struct.unpack_from("<HH", data)
    pointer = int.from_bytes(data[-width:], "little")
    if length > maximum or length % 2 or maximum % 2:
        return 0xC000000D
    size = length + (2 if flags & 1 else 0)
    if size > 0xFFFF:
        return 0xC000000D
    if length:
        require_range(emu, pointer, length)
    if not length and flags != 3:
        size = 0
    target = emu.pool_alloc(1, size, "Ustr") if size else 0
    if size and not target:
        return 0xC0000017
    if target:
        emu.mem_write(target, (emu.mem_read(pointer, length) if length else b"") + (b"\0\0" if flags & 1 else b""))
    emu.mem_write(output, struct.pack("<HH", length, size) + (bytes(4) if width == 8 else b"") + target.to_bytes(width, "little"))
    return 0


def ex_system_time_to_local_time(_handler, emu, argv, ctx=None):
    source, output = map(int, argv)
    require_range(emu, source, 8)
    require_range(emu, output, 8, True)
    ticks = int.from_bytes(emu.mem_read(source, 8), "little", signed=True)
    ticks += int(emu.virtual_clock.offset.total_seconds()) * 10_000_000
    emu.mem_write(output, ticks.to_bytes(8, "little", signed=True))


def rtl_time_to_time_fields(_handler, emu, argv, ctx=None):
    source, output = map(int, argv)
    require_range(emu, source, 8)
    require_range(emu, output, 16, True)
    ticks = int.from_bytes(emu.mem_read(source, 8), "little", signed=True)
    value = dt.datetime(1601, 1, 1) + dt.timedelta(microseconds=ticks // 10)
    fields = (value.year, value.month, value.day, value.hour, value.minute,
              value.second, value.microsecond // 1000, (value.weekday() + 1) % 7)
    emu.mem_write(output, struct.pack("<8h", *fields))


def swprintf_s(_handler, emu, argv, ctx=None):
    result = emu.kernel_crt._swprintf_s(emu, "ntoskrnl.swprintf_s", None, argv)
    record_format(emu, "swprintf_s", argv, result)
    return result


def vsnwprintf(_handler, emu, argv, ctx=None):
    result = emu.kernel_crt._vsnwprintf(emu, "ntoskrnl._vsnwprintf", None, argv)
    record_format(emu, "_vsnwprintf", argv, result)
    return result


def record_format(emu, api, argv, result):
    """Passive bounded output snapshots, before callers transform/free buffers."""
    state = emu.kernel_formatting
    try:
        buffer, count, format_ptr = map(int, argv[:3])
        chars = min(count, max(0, result), 1024) if result >= 0 else min(count, 1024)
        size = max(0, chars) * 2
        if size and not guest_range(emu, buffer, size, 1):
            raise ValueError("format snapshot is not readable")
        output = emu.mem_read(buffer, size).decode("utf-16le", "surrogatepass").split('\0', 1)[0] if size else ""
        if len(state['observations']) == state['limit']:
            state['omitted'] += 1
        state['observations'].append({'api': api, 'pc': hex(emu.get_pc()),
            'instructions': emu.curr_run.instr_cnt, 'format_address': hex(format_ptr),
            'buffer': hex(buffer), 'result': result, 'text': output,
            'truncated': result > chars or result < 0})
    except Exception:
        state['capture_errors'] += 1


def strcmp(_handler, emu, argv, ctx=None):
    left, right = map(int, argv)
    # No guest code can change mappings during this synchronous read-only API.
    # Validate each byte actually consumed, including equal-pointer inputs;
    # neither a NUL nor a mismatch requires reading a subsequent byte.
    regions = tuple(emu.emu_eng.emu.mem_regions())
    address_limit = 1 << (emu.get_ptr_size() * 8)
    def read_byte(address):
        if not 0 < address < address_limit or not any(
                start <= address <= end and permissions & 1
                for start, end, permissions in regions):
            raise ValueError("strcmp input is not readable guest memory")
        return emu.mem_read(address, 1)[0]
    for offset in range(65536):
        a, b = read_byte(left + offset), read_byte(right + offset)
        if a != b:
            return (a - b) & 0xFFFFFFFF  # native signed 32-bit int result
        if a == 0:
            return 0
    raise ValueError("strcmp exceeded the modeled 65536-byte comparison limit")


def install_kernel_apis(kernel):
    handler = kernel.api.load_api_handler("ntoskrnl")
    from .kernel_debugger import KernelDebuggerState
    kernel.debugger_state = KernelDebuggerState(kernel)
    kernel.debugger_state.install(handler)
    from .kernel_process import KernelInitialSystemProcess
    kernel.initial_system_process = KernelInitialSystemProcess(kernel)
    kernel.initial_system_process.install(handler)
    from .kernel_opaque_data import KernelOpaqueData
    kernel.opaque_data = KernelOpaqueData(kernel)
    kernel.opaque_data.install(handler)
    from .kernel_memory import install as install_memory_helpers
    install_memory_helpers(handler)
    from .kernel_files import KernelFiles
    kernel.kernel_files = KernelFiles(kernel)
    kernel.kernel_files.install(handler)
    from .kernel_callbacks import KernelBugcheckCallbacks
    kernel.bugcheck_callbacks = KernelBugcheckCallbacks(kernel)
    kernel.bugcheck_callbacks.install(handler)
    from .kernel_named_callbacks import KernelNamedCallbacks
    kernel.named_callbacks = KernelNamedCallbacks(kernel)
    kernel.named_callbacks.install(handler)
    from .kernel_sync import KernelSynchronization
    kernel.synchronization = KernelSynchronization(kernel)
    kernel.synchronization.install(handler)
    from .kernel_environment import KernelEnvironment
    kernel.kernel_environment = KernelEnvironment(kernel)
    kernel.kernel_environment.install(handler)
    from .kernel_system_information import KernelSystemInformation
    kernel.kernel_system_information = KernelSystemInformation(kernel)
    kernel.kernel_system_information.install(handler)
    from .kernel_rundown import CacheAwareRundown
    from .kernel_dispatcher import KernelDispatcher
    from .kernel_mdl import KernelMdls
    kernel.cache_aware_rundown = CacheAwareRundown(kernel)
    kernel.dispatcher = KernelDispatcher(kernel)
    kernel.mdls = KernelMdls(kernel)
    kernel.cache_aware_rundown.install(handler)
    kernel.dispatcher.install(handler)
    kernel.mdls.install(handler)
    from .kernel_threads import KernelThreads
    kernel.kernel_threads = KernelThreads(kernel)
    kernel.kernel_threads.install()
    from .kernel_references import KernelReferences
    kernel.object_references = KernelReferences(kernel)
    kernel.object_references.install(handler)
    kernel.kernel_crt = LegacyCRTStreams()
    kernel.kernel_formatting = {'observations': deque(maxlen=128), 'limit': 128,
        'omitted': 0, 'capture_errors': 0,
        'scope': 'Passive bounded kernel CRT formatting output; no guest time or formatting result changes'}
    kernel.kernel_crt.read_guard = lambda emu, address, size: guest_range(emu, address, size, 1)
    kernel.kernel_crt.write_guard = lambda emu, address, size: guest_range(emu, address, size, 2)
    for name, function, count in (("RtlPcToFileHeader", rtl_pc_to_file_header, 2),
        ("RtlDuplicateUnicodeString", rtl_duplicate_unicode_string, 3),
        ("ExSystemTimeToLocalTime", ex_system_time_to_local_time, 2),
        ("RtlTimeToTimeFields", rtl_time_to_time_fields, 2), ("swprintf_s", swprintf_s, 3),
        ("_vsnwprintf", vsnwprintf, 4), ("strcmp", strcmp, 2)):
        handler.funcs[name] = (name, function, count, arch.CALL_CONV_CDECL if name in
                             ("swprintf_s", "_vsnwprintf", "strcmp") else arch.CALL_CONV_STDCALL, None)
    from .kernel_export_catalog import KernelExportCatalog
    kernel.export_catalog = KernelExportCatalog(kernel)
    kernel.export_catalog.install(handler)
