"""Audit read APIs preserve layouts, permission checks, and buffer ownership."""

import struct
import unittest
import uuid
from types import SimpleNamespace

from emumee.audit import CATEGORY_GUIDS, GuestAudit
from emumee.audit_policy import SUBCATEGORIES
from emumee.persona import load_persona


class _Emu:
    def __init__(self, width):
        self.width = width
        self.process = object()
        self.memory = bytearray(0x200000)
        self.maps = [SimpleNamespace(base=0x100, size=0xff00, prot=6, free=False)]
        self.next = 0x10000
        self.error = 0
        self.freed = []

    def set_last_error(self, error): self.error = error
    def get_current_process(self): return self.process
    def get_ptr_size(self): return self.width
    def get_address_map(self, address):
        return next((m for m in reversed(self.maps) if m.base <= address < m.base + m.size), None)
    def mem_read(self, address, size): return bytes(self.memory[address:address + size])
    def mem_write(self, address, data): self.memory[address:address + len(data)] = data
    def mem_map(self, size, **kwargs):
        assert size == 4096 and kwargs["process"] is self.process
        result = self.next
        self.next += size
        self.maps.append(SimpleNamespace(base=result, size=size, prot=6, free=False))
        return result
    def mem_free(self, pointer):
        self.get_address_map(pointer).free = True
        self.freed.append(pointer)
    def pointer(self, address=0x500): return int.from_bytes(self.mem_read(address, self.width), "little")


class AuditAPITests(unittest.TestCase):
    def test_query_returns_contiguous_policy_structures_in_requested_order(self):
        for width in (4, 8):
            with self.subTest(width=width):
                emu = _Emu(width)
                persona = load_persona(None)
                persona["audit_policy"] = {"read_allowed": True, "subcategories": {
                    "Logon": "Success and Failure", "File System": "Failure", "Process Creation": "Success"}}
                api = GuestAudit(persona)
                names = ("Process Creation", "File System", "Logon", "Registry")
                guids = [uuid.UUID(next(g for _, n, g in SUBCATEGORIES if n == name)).bytes_le
                         for name in names]
                emu.mem_write(0x100, b"".join(guids))
                self.assertEqual(api._query(emu, "", None, [0x100, 4, 0x500]), 1)
                result = emu.mem_read(emu.pointer(), 4 * 36)
                for i, (guid, flag) in enumerate(zip(guids, (1, 2, 3, 4))):
                    self.assertEqual(result[i * 36:i * 36 + 16], guid)
                    self.assertEqual(struct.unpack_from("<I", result, i * 36 + 16)[0], flag)
                self.assertEqual(result[20:36], CATEGORY_GUIDS[4])
                self.assertEqual(result[56:72], CATEGORY_GUIDS[2])
                self.assertEqual(emu.error, 0)

    def test_metadata_names_category_ids_and_filtered_subcategories(self):
        for width in (4, 8):
            emu = _Emu(width)
            api = GuestAudit(load_persona(None))
            self.assertEqual(api._categories(emu, "", None, [0x500, 0x600]), 1)
            self.assertEqual(emu.mem_read(0x600, 4), struct.pack("<I", 9))
            self.assertEqual(emu.mem_read(emu.pointer(), 9 * 16), b"".join(CATEGORY_GUIDS))
            self.assertEqual(api._category_guid(emu, "", None, [4, 0x100]), 1)
            self.assertEqual(api._category_id(emu, "", None, [0x100, 0x600]), 1)
            self.assertEqual(emu.mem_read(0x600, 4), struct.pack("<I", 4))
            for suffix, encoding in (("A", "ascii"), ("W", "utf-16le")):
                self.assertEqual(api._name(emu, "AuditLookupCategoryName" + suffix, None, [0x100, 0x500]), 1)
                expected = ("Detailed Tracking\0").encode(encoding)
                self.assertEqual(emu.mem_read(emu.pointer(), len(expected)), expected)
            self.assertEqual(api._subcategories(emu, "", None, [0x100, 0, 0x500, 0x600]), 1)
            self.assertEqual(emu.mem_read(0x600, 4), struct.pack("<I", 6))
            first = emu.mem_read(emu.pointer(), 16)
            self.assertEqual(first, uuid.UUID("0cce922b-69ae-11d9-bed3-505054503030").bytes_le)
            emu.mem_write(0x100, first)
            for suffix, encoding in (("A", "ascii"), ("W", "utf-16le")):
                self.assertEqual(api._name(emu, "AuditLookupSubCategoryName" + suffix, None, [0x100, 0x500]), 1)
                expected = ("Process Creation\0").encode(encoding)
                self.assertEqual(emu.mem_read(emu.pointer(), len(expected)), expected)
            self.assertEqual(api._subcategories(emu, "", None, [0, 1, 0x500, 0x600]), 1)
            self.assertEqual(emu.mem_read(0x600, 4), struct.pack("<I", 59))

    def test_invalid_memory_counts_permissions_and_output_guards_do_not_allocate(self):
        for width in (4, 8):
            emu = _Emu(width)
            persona = load_persona(None)
            api = GuestAudit(persona)
            emu.mem_write(0x100, uuid.UUID(SUBCATEGORIES[0][2]).bytes_le)
            emu.mem_write(0x500, b"\xa5" * width)
            self.assertEqual(api._query(emu, "", None, [0x100, 1, 0x500]), 0)
            self.assertEqual(emu.error, 5)
            persona["audit_policy"]["read_allowed"] = True
            for args in ([0x100, 0, 0x500], [0x100, 60, 0x500], [0x100, 0xffffffff, 0x500],
                         [0, 1, 0x500], [0x100, 1, 0], [0xfff8, 1, 0x500]):
                self.assertEqual(api._query(emu, "", None, args), 0)
                self.assertEqual(emu.error, 87)
            api.read_guard = lambda *args: False
            self.assertEqual(api._query(emu, "", None, [0x100, 1, 0x500]), 0)
            api.read_guard = None
            api.write_guard = lambda *args: False
            self.assertEqual(api._query(emu, "", None, [0x100, 1, 0x500]), 0)
            api.write_guard = None
            self.assertEqual(api._categories(emu, "", None, [0x500, 0x500]), 0)
            self.assertEqual(api._categories(emu, "", None, [0x500, 0]), 0)
            emu.mem_write(0x100, b"\xff" * 16)
            self.assertEqual(api._query(emu, "", None, [0x100, 1, 0x500]), 0)
            self.assertEqual(emu.mem_read(0x500, width), b"\xa5" * width)
            self.assertFalse(api.buffers)
            self.assertEqual(emu.next, 0x10000)

    def test_audit_free_and_exit_cleanup_only_release_original_owner_mappings(self):
        emu = _Emu(8)
        api = GuestAudit(load_persona(None))
        owner = emu.process
        api._categories(emu, "", None, [0x500, 0x600])
        first = emu.pointer()
        emu.process = object()
        api._free(emu, "", None, [first])
        self.assertEqual(emu.freed, [])
        api._categories(emu, "", None, [0x500, 0x600])
        second = emu.pointer()
        api.cleanup_process(emu, owner)
        self.assertEqual(emu.freed, [first])
        self.assertIn((id(emu.process), second), api.buffers)
        api._free(emu, "", None, [second])
        api._free(emu, "", None, [second])
        self.assertEqual(emu.freed, [first, second])
        api._categories(emu, "", None, [0x500, 0x600])
        stale = emu.pointer()
        old = emu.get_address_map(stale)
        old.free = True
        emu.maps.append(SimpleNamespace(base=stale, size=4096, prot=6, free=False))
        api._free(emu, "", None, [stale])
        self.assertFalse(emu.get_address_map(stale).free)
        self.assertFalse(api.buffers)

    def test_response_budget_and_mutation_denial(self):
        emu = _Emu(8)
        api = GuestAudit(load_persona(None))
        for _ in range(128):
            self.assertEqual(api._categories(emu, "", None, [0x500, 0x600]), 1)
        self.assertEqual(api._categories(emu, "", None, [0x500, 0x600]), 0)
        self.assertEqual(emu.error, 8)
        self.assertEqual(api._unsupported(emu, "", None, [0, 0]), 0)
        self.assertEqual(emu.error, 50)
        api.cleanup_process(emu, emu.process)
        self.assertEqual(len(emu.freed), 128)
        self.assertFalse(api.buffers)
