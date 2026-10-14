from __future__ import annotations

import unittest

from emumee.winenvironment import GuestEnvironmentBlocks


class FakeGuest:
    def __init__(self):
        self.process = object()
        self.environment = {"TEMP": r"C:\Users\Alex\AppData\Local\Temp",
                            "USERPROFILE": r"C:\Users\Alex"}
        self.memory = {}
        self.next_address = 0x40000000
        self.last_error = 0

    def get_current_process(self):
        return self.process

    def get_env(self):
        return self.environment

    def mem_map(self, size, **_kwargs):
        address = self.next_address
        self.next_address += 0x1000
        self.memory[address] = bytearray(size)
        return address

    def mem_write(self, address, value):
        self.memory[address][:len(value)] = value

    def mem_free(self, address):
        del self.memory[address]

    def set_last_error(self, value):
        self.last_error = value


class GuestEnvironmentBlockTests(unittest.TestCase):
    def test_ansi_and_wide_blocks_are_double_terminated_guest_copies(self):
        guest = FakeGuest()
        blocks = GuestEnvironmentBlocks()
        for suffix, encoding, nul in (("A", "cp437", b"\0"),
                                      ("W", "utf-16le", b"\0\0")):
            with self.subTest(suffix=suffix):
                address = blocks._get(guest, f"kernel32.GetEnvironmentStrings{suffix}", None, [])
                payload = bytes(guest.memory[address])
                expected = ("TEMP=" + guest.environment["TEMP"] + "\0" +
                            "USERPROFILE=" + guest.environment["USERPROFILE"] + "\0\0")
                self.assertEqual(payload, expected.encode(encoding))
                self.assertTrue(payload.endswith(nul * 2))
                guest.environment["TEMP"] = "CHANGED"
                self.assertEqual(bytes(guest.memory[address]), payload)
                self.assertEqual(blocks._free(
                    guest, f"kernel32.FreeEnvironmentStrings{suffix}", None,
                    [address]), 1)
                self.assertNotIn(address, guest.memory)
                guest.environment["TEMP"] = r"C:\Users\Alex\AppData\Local\Temp"

    def test_free_rejects_foreign_pointer_wrong_width_and_reuse(self):
        guest = FakeGuest()
        blocks = GuestEnvironmentBlocks()
        address = blocks._get(guest, "kernel32.GetEnvironmentStringsW", None, [])
        self.assertEqual(blocks._free(guest, "kernel32.FreeEnvironmentStringsA", None,
                                      [address]), 0)
        self.assertIn(address, guest.memory)
        guest.process = object()
        self.assertEqual(blocks._free(guest, "kernel32.FreeEnvironmentStringsW", None,
                                      [address]), 0)
        self.assertIn(address, guest.memory)
        self.assertEqual(guest.last_error, 87)

    def test_invalid_or_oversized_entries_do_not_allocate(self):
        guest = FakeGuest()
        blocks = GuestEnvironmentBlocks()
        guest.environment = {"BAD=NAME": "value"}
        self.assertEqual(blocks._get(guest, "kernel32.GetEnvironmentStringsW", None, []), 0)
        self.assertFalse(guest.memory)
        guest.environment = {"BIG": "x" * (1 << 20)}
        self.assertEqual(blocks._get(guest, "kernel32.GetEnvironmentStringsA", None, []), 0)
        self.assertFalse(guest.memory)
        self.assertEqual(guest.last_error, 8)


if __name__ == "__main__":
    unittest.main()
