"""Winsock host identity stays tied to the guest persona and guest memory."""

import unittest
from types import SimpleNamespace

from emumee.identity import (ERROR_NOACCESS, GuestIdentity, WSAEFAULT,
                             WSANOTINITIALISED)


class _Emu:
    def __init__(self):
        self.process = object()
        self.memory = bytearray(0x1000)
        self.last_error = 0

    def get_current_process(self):
        return self.process

    def get_ptr_size(self):
        return 8

    def get_address_map(self, address):
        return (SimpleNamespace(base=0, size=len(self.memory), prot=6, free=False)
                if 0 < address < len(self.memory) else None)

    def mem_write(self, address, value):
        self.memory[address:address + len(value)] = value

    def mem_read(self, address, size):
        return bytes(self.memory[address:address + size])

    def set_last_error(self, value):
        self.last_error = value


class HostIdentityTests(unittest.TestCase):
    def test_computer_name_checks_guest_process_memory_guard(self):
        api = GuestIdentity({'hostname': 'DESKTOP-Q3R8V2A'})
        emu = _Emu()
        emu.mem_write(0x100, (32).to_bytes(4, 'little'))
        api.read_guard = lambda _emu, _address, _size: False
        self.assertEqual(api._computer_name(emu, 'kernel32.GetComputerNameW',
                                             None, [0x200, 0x100]), 0)
        self.assertEqual(emu.last_error, ERROR_NOACCESS)
        api.read_guard = lambda _emu, _address, _size: True
        api.write_guard = lambda _emu, address, _size: address == 0x100
        self.assertEqual(api._computer_name(emu, 'kernel32.GetComputerNameW',
                                             None, [0x200, 0x100]), 0)
        self.assertEqual(emu.last_error, ERROR_NOACCESS)

    def test_wide_hostname_requires_winsock_and_writable_guest_capacity(self):
        api = GuestIdentity({'hostname': 'DESKTOP-Q3R8V2A'})
        emu = _Emu()
        call = [0x200, 16]
        self.assertEqual(api._host_name_w(emu, '', None, call), -1)
        self.assertEqual(emu.last_error, WSANOTINITIALISED)
        api.write_guard = lambda _emu, _address, _size: False
        self.assertEqual(api._wsa_startup(emu, '', lambda _args: 0,
                                          [0x101, 0x300]), WSAEFAULT)
        api.write_guard = None
        self.assertEqual(api._wsa_startup(emu, '', lambda _args: 0,
                                          [0x101, 0x300]), 0)
        self.assertEqual(api._host_name_w(emu, '', None, [0x200, 4]), -1)
        self.assertEqual(emu.last_error, WSAEFAULT)
        self.assertEqual(api._host_name_w(emu, '', None, [0x200, 0xFFFFFFFF]), -1)
        api.write_guard = lambda _emu, _address, _size: False
        self.assertEqual(api._host_name_w(emu, '', None, call), -1)
        api.write_guard = lambda _emu, _address, _size: True
        self.assertEqual(api._host_name_w(emu, '', None, call), 0)
        self.assertEqual(emu.mem_read(0x200, 32),
                         'DESKTOP-Q3R8V2A\0'.encode('utf-16le'))
        emu.process = object()
        self.assertEqual(api._host_name_w(emu, '', None, call), -1)
        api.cleanup_process(emu.process)


if __name__ == '__main__':
    unittest.main()
