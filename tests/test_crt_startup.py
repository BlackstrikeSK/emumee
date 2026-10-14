"""Initial UCRT environment arrays remain in guest process memory."""

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from emumee.crt_startup import CRTStartup, process_argv
from emumee.native import run_native
from emumee.pe import inspect_pe
from emumee.persona import load_persona, make_speakeasy_config
from tests.fixtures.build_native import build_crt_args


class _Emu:
    def __init__(self, width):
        self.width = width
        self.process = object()
        self.memory = bytearray(0x10000)
        self.next_address = 0x1000
        self.maps = []

    def get_ptr_size(self):
        return self.width

    def get_current_process(self):
        return self.process

    def get_env(self):
        return {'username': 'Morgan', 'computername': 'DESKTOP-Q3R8V2A'}

    def get_argv(self):
        return ['reg.exe', 'query', r'HKCU\Control Panel\Desktop']

    def mem_map(self, size, **kwargs):
        base = self.next_address
        self.next_address += 0x1000
        self.maps.append((base, size, kwargs))
        return base

    def mem_write(self, address, data):
        self.memory[address:address + len(data)] = data

    def mem_read(self, address, size):
        return bytes(self.memory[address:address + size])

    def mem_free(self, address):
        pass


class CRTStartupTests(unittest.TestCase):
    def test_explicit_raw_argument_quotes_leave_crt_value_plain(self):
        persona = load_persona(None)
        guest_args = ['Coffee', r'C:\Users\Alex\Documents\shopping-list.txt']
        config = make_speakeasy_config(
            persona, 'find.exe', 10, 100_000, guest_args,
            quoted_arg_indices=[0])
        self.assertIn('find.exe "Coffee" C:\\Users\\Alex', config['command_line'])
        self.assertEqual(guest_args[0], 'Coffee')
        with self.assertRaises(ValueError):
            make_speakeasy_config(persona, 'find.exe', 10, 100_000,
                                  guest_args, quoted_arg_indices=[2])

    def test_active_guest_image_is_argv_zero_on_both_architectures(self):
        original = CRTStartup._mainargs
        for machine, arch in ((0x14C, "x86"), (0x8664, "x64")):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as temp:
                observed = []
                def capture(self, emu, api_name, params, *, wide):
                    observed.append(emu.get_argv())
                    return original(self, emu, api_name, params, wide=wide)
                data = build_crt_args(machine, wide=False)
                name = "argv_probe.exe"
                with mock.patch.object(CRTStartup, "_mainargs", capture):
                    result = run_native(data, inspect_pe(data, name),
                                        load_persona(None), Path(temp), [],
                                        10, 100_000, guest_args=["/probe"])
                self.assertFalse(result["errors"])
                self.assertEqual(observed, [[r"C:\Users\Alex\Downloads\argv_probe.exe",
                                             "/probe"]])

    def test_process_argv_keeps_original_when_no_process_path_exists(self):
        source = ["ntoskrnl.exe", "/probe"]
        emu = type("Emu", (), {"get_current_process":
                               lambda _self: type("Process", (), {"path": ""})()})()
        self.assertEqual(process_argv(emu, source), source)
        self.assertIsNot(process_argv(emu, source), source)

    def test_private_argument_globals_return_pointer_slots(self):
        for width in (4, 8):
            with self.subTest(width=width):
                emu = _Emu(width)
                crt = CRTStartup()
                prefix = 'api-ms-win-crt-private-l1-1-0._o___p___'
                argc = crt._argument_global(emu, prefix + 'argc', None, [])
                wargv = crt._argument_global(emu, prefix + 'wargv', None, [])
                self.assertEqual(emu.mem_read(argc, 4), (3).to_bytes(4, 'little'))
                array = int.from_bytes(emu.mem_read(wargv, width), 'little')
                first = int.from_bytes(emu.mem_read(array, width), 'little')
                self.assertEqual(emu.mem_read(first, len('reg.exe\0') * 2),
                                 'reg.exe\0'.encode('utf-16le'))
                self.assertEqual(emu.mem_read(array + 3 * width, width),
                                 b'\0' * width)
                self.assertEqual(crt._argument_global(
                    emu, prefix + 'wargv', None, []), wargv)
                self.assertEqual(len(emu.maps), 1)

    def test_private_initial_wide_environment_is_null_terminated_and_owned(self):
        for width in (4, 8):
            with self.subTest(width=width):
                emu = _Emu(width)
                crt = CRTStartup()
                name = 'api-ms-win-crt-private-l1-1-0._o__get_initial_wide_environment'
                base = crt._initial_environment(emu, name, None, [])
                self.assertEqual(crt._initial_environment(emu, name, None, []),
                                 base)
                self.assertEqual(len(emu.maps), 1)
                self.assertIs(emu.maps[0][2]['process'], emu.process)
                first = int.from_bytes(emu.mem_read(base, width), 'little')
                second = int.from_bytes(emu.mem_read(base + width, width), 'little')
                self.assertEqual(emu.mem_read(base + 2 * width, width),
                                 b'\0' * width)
                expected = 'username=Morgan\0'.encode('utf-16le')
                self.assertEqual(emu.mem_read(first, len(expected)), expected)
                prefix = 'computername'.encode('utf-16le')
                self.assertEqual(emu.mem_read(second, len(prefix)), prefix)
                crt.cleanup_process(emu.process)
                emu.process = object()
                self.assertNotEqual(crt._initial_environment(emu, name, None, []),
                                    base)


if __name__ == '__main__':
    unittest.main()
