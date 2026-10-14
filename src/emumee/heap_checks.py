"""Guest-only validation of modeled Windows heap allocations."""

from __future__ import annotations


class GuestHeapChecks:
    def __init__(self):
        self.read_guard = None

    def install(self, emulator) -> None:
        emulator.add_api_hook(self.validate, "kernel32", "HeapValidate", argc=3)
        emulator.add_api_hook(self.validate, "kernelbase", "HeapValidate", argc=3)
        emulator.add_api_hook(self.validate, "api-ms-win-core-heap-l1-1-0",
                              "HeapValidate", argc=3)
        emulator.add_api_hook(self.size, "ntdll", "RtlSizeHeap", argc=3)

    def size(self, emu, _api_name, _original, params) -> int:
        heap, flags, pointer = map(int, params)
        invalid = (1 << (emu.get_ptr_size() * 8)) - 1
        kernel32 = emu.api.load_api_handler("kernel32")
        if flags & ~1 or heap not in (0, *kernel32.heaps) or not pointer:
            return invalid
        for region in emu.get_mem_maps():
            if (int(region.base) == pointer and not region.free and
                    str(region.tag).startswith("api.heap.") and
                    (self.read_guard is None or self.read_guard(emu, pointer, 1))):
                return int(region.size)
        return invalid

    def validate(self, emu, _api_name, _original, params) -> int:
        heap, flags, pointer = map(int, params)
        # HeapValidate leaves GetLastError untouched on both success and
        # failure. Only HEAP_NO_SERIALIZE is a defined flag.
        if flags & ~1:
            return 0
        kernel32 = emu.api.load_api_handler("kernel32")
        if heap not in kernel32.heaps:
            return 0
        if pointer == 0:
            return 1
        mapped = any(int(region.base) == pointer and not region.free and
                     str(region.tag).startswith("api.heap.")
                     for region in emu.get_mem_maps())
        if not mapped:
            return 0
        return int(self.read_guard is None or self.read_guard(emu, pointer, 1))
