"""Bounded kernel memory helpers with native guest-page permission checks."""
from .artifacts import MAX_MEMORY_SCAN
from .kernel_api import require_range
from speakeasy.winenv import arch


def writable(emu, address, size):
    if not 0 <= size <= MAX_MEMORY_SCAN:
        raise ValueError("Kernel memory operation exceeds modeled byte limit")
    if size:
        emu.mdls.require_api_write(address, size)
        require_range(emu, address, size, True)


def copy_memory(api, emu, argv, ctx=None):
    destination, source, size = map(int, argv)
    writable(emu, destination, size)
    if size:
        require_range(emu, source, size)
        # Capture first so RtlMoveMemory/memmove preserve overlapping bytes.
        emu.mem_write(destination, emu.mem_read(source, size))
    return destination


def move_memory(api, emu, argv, ctx=None):
    copy_memory(api, emu, argv, ctx)


def fill_memory(api, emu, argv, ctx=None):
    destination, size, value = map(int, argv)
    writable(emu, destination, size)
    if size:
        emu.mem_write(destination, bytes([value & 0xFF]) * size)


def zero_memory(api, emu, argv, ctx=None):
    fill_memory(api, emu, [*argv, 0], ctx)


def set_memory(api, emu, argv, ctx=None):
    destination, value, size = map(int, argv)
    fill_memory(api, emu, [destination, size, value], ctx)
    return destination


def install(handler):
    for name, function, argc, cdecl in (
            ("RtlMoveMemory", move_memory, 3, False),
            ("RtlCopyMemory", move_memory, 3, False),
            ("RtlFillMemory", fill_memory, 3, False),
            ("RtlZeroMemory", zero_memory, 2, False),
            ("memcpy", copy_memory, 3, True),
            ("memmove", copy_memory, 3, True),
            ("memset", set_memory, 3, True)):
        handler.funcs[name] = (name, function, argc,
            arch.CALL_CONV_CDECL if cdecl else arch.CALL_CONV_STDCALL, None)
