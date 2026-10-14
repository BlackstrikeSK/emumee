"""HeapValidate decisions stay inside the guest allocation model."""

from __future__ import annotations

from types import SimpleNamespace
import unittest

from emumee.heap_checks import GuestHeapChecks


class HeapCheckTests(unittest.TestCase):
    def test_heap_api_set_uses_checked_handler(self):
        hooks = {}
        class Registrar:
            def add_api_hook(self, callback, module, name, **kwargs):
                hooks[(module, name)] = (callback.__name__, kwargs["argc"])
        GuestHeapChecks().install(Registrar())
        self.assertEqual(hooks[("api-ms-win-core-heap-l1-1-0", "HeapValidate")],
                         hooks[("kernel32", "HeapValidate")])

    def test_owned_live_block_and_heap_wide_validation(self):
        region = SimpleNamespace(base=0x5000, size=0x30,
                                 tag="api.heap.HeapAlloc.0x5000", free=False)
        handler = SimpleNamespace(heaps=[0x4000])
        emu = SimpleNamespace(
            api=SimpleNamespace(load_api_handler=lambda _name: handler),
            get_mem_maps=lambda: [region], get_ptr_size=lambda: 8)
        check = GuestHeapChecks()
        check.read_guard = lambda _emu, address, size: address == 0x5000 and size == 1
        call = lambda heap, flags, pointer: check.validate(
            emu, "kernel32.HeapValidate", None, [heap, flags, pointer])
        self.assertEqual(call(0x4000, 0, 0), 1)
        self.assertEqual(call(0x4000, 0, 0x5000), 1)
        self.assertEqual(call(0x4001, 0, 0x5000), 0)
        self.assertEqual(call(0x4000, 2, 0x5000), 0)
        self.assertEqual(call(0x4000, 0, 0x5001), 0)
        region.free = True
        self.assertEqual(call(0x4000, 0, 0x5000), 0)

    def test_rtl_size_heap_uses_only_owned_live_heap_mapping(self):
        region = SimpleNamespace(base=0x6000, size=0x40,
                                 tag="api.heap.RtlAllocateHeap.0x6000", free=False)
        handler = SimpleNamespace(heaps=[0x4000])
        emu = SimpleNamespace(
            api=SimpleNamespace(load_api_handler=lambda _name: handler),
            get_mem_maps=lambda: [region], get_ptr_size=lambda: 8)
        check = GuestHeapChecks()
        check.read_guard = lambda _emu, address, _size: address == 0x6000
        call = lambda pointer: check.size(emu, "ntdll.RtlSizeHeap", None,
                                          [0, 0, pointer])
        self.assertEqual(call(0x6000), 0x40)
        self.assertEqual(call(0x6001), 0xFFFFFFFFFFFFFFFF)
        region.free = True
        self.assertEqual(call(0x6000), 0xFFFFFFFFFFFFFFFF)


if __name__ == "__main__":
    unittest.main()
