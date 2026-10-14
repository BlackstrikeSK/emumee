"""HeapValidate decisions stay inside the guest allocation model."""

from __future__ import annotations

from types import SimpleNamespace
import unittest

from emumee.heap_checks import GuestHeapChecks


class HeapCheckTests(unittest.TestCase):
    def test_owned_live_block_and_heap_wide_validation(self):
        region = SimpleNamespace(base=0x5000, tag="api.heap.HeapAlloc.0x5000", free=False)
        handler = SimpleNamespace(heaps=[0x4000])
        emu = SimpleNamespace(
            api=SimpleNamespace(load_api_handler=lambda _name: handler),
            get_mem_maps=lambda: [region])
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


if __name__ == "__main__":
    unittest.main()
