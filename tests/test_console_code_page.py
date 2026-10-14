"""Guest console code page agrees with the persona locale."""

import unittest
import struct
from types import SimpleNamespace

from emumee.console_output import ConsoleOutput
from emumee.persona_content import oem_code_page
from emumee.virtualfs import VirtualFileBridge


class ConsoleCodePageTests(unittest.TestCase):
    def test_console_file_type_and_redirected_handle_delegation(self):
        handles = {0xFFFFFFF6: 0xF001, 0xFFFFFFF5: 0xF002,
                   0xFFFFFFF4: 0xF003}
        process = SimpleNamespace(get_std_handle=lambda code: handles[code])
        errors = []
        emu = SimpleNamespace(get_current_process=lambda: process,
                              set_last_error=errors.append)
        console = ConsoleOutput()
        delegated = []
        def original(params):
            delegated.append(params[0])
            return 1  # FILE_TYPE_DISK for a redirected guest file.
        for handle in handles.values():
            self.assertEqual(console._get_file_type(
                emu, 'kernel32.GetFileType', original, [handle]), 2)
        self.assertFalse(delegated)
        handles[0xFFFFFFF5] = 0x2000
        self.assertEqual(console._get_file_type(
            emu, 'kernel32.GetFileType', original, [0xF002]), 1)
        self.assertEqual(delegated, [0xF002])
        self.assertEqual(console._get_file_type(
            emu, 'kernel32.GetFileType', None, [0x9999]), 0)
        self.assertEqual(errors, [6])

    def test_console_modes_are_stateful_and_invalid_handles_do_not_succeed(self):
        handles = {0xFFFFFFF6: 0xF001, 0xFFFFFFF5: 0xF002,
                   0xFFFFFFF4: 0xF003}
        process = SimpleNamespace(get_std_handle=lambda code: handles[code])
        memory = {}
        errors = []
        emu = SimpleNamespace(
            get_current_process=lambda: process,
            mem_write=lambda address, data: memory.__setitem__(address, data),
            set_last_error=errors.append)
        console = ConsoleOutput()
        self.assertEqual(console._get_console_mode(
            emu, '', None, [0xF001, 0x1000]), 1)
        self.assertEqual(memory[0x1000], struct.pack('<I', 0xF7))
        self.assertEqual(console._get_console_mode(
            emu, '', None, [0xF002, 0x1004]), 1)
        self.assertEqual(memory[0x1004], struct.pack('<I', 3))
        self.assertEqual(console._set_console_mode(
            emu, '', None, [0xF003, 7]), 1)
        self.assertEqual(console._get_console_mode(
            emu, '', None, [0xF002, 0x1004]), 1)
        self.assertEqual(memory[0x1004], struct.pack('<I', 7))
        self.assertEqual(console._set_console_mode(
            emu, '', None, [0xF001, 4]), 0)
        self.assertEqual(errors[-1], 87)
        self.assertEqual(console._get_console_mode(
            emu, '', None, [0xFFFFFFFF, 0x1000]), 0)
        self.assertEqual(errors[-1], 6)
        console.write_guard = lambda *_args: False
        self.assertEqual(console._get_console_mode(
            emu, '', None, [0xF001, 0x1000]), 0)
        self.assertEqual(errors[-1], 998)

    def test_console_device_alias_open_mode_and_close_stay_guest_owned(self):
        process = SimpleNamespace(get_std_handle=lambda code: {
            0xFFFFFFF6: 0xF001, 0xFFFFFFF5: 0xF002,
            0xFFFFFFF4: 0xF003}[code])
        names = {0x1000: 'CONIN$', 0x2000: 'CONOUT$'}
        errors = []
        memory = {}
        emu = SimpleNamespace(
            get_current_process=lambda: process,
            get_file_manager=lambda: SimpleNamespace(),
            read_mem_string=lambda pointer, _width: names[pointer],
            mem_write=lambda address, data: memory.__setitem__(address, data),
            set_last_error=errors.append)
        console = ConsoleOutput()
        files = VirtualFileBridge(r'C:\Users\Alex\Downloads', None)
        files.console_open_handler = console.open_console_handle
        files.console_close_handler = console.close_console_handle
        params = [0x1000, 0xC0000000, 3, 0, 3, 0, 0]
        input_handle = files._create_file(emu, 'kernel32.CreateFileW', None, params)
        self.assertEqual(input_handle, 0xF100)
        self.assertEqual(console._get_file_type(emu, '', None, [input_handle]), 2)
        self.assertEqual(console._get_console_mode(
            emu, '', None, [input_handle, 0x3000]), 1)
        self.assertEqual(memory[0x3000], struct.pack('<I', 0xF7))
        params[0] = 0x2000
        output_handle = files._create_file(emu, 'kernel32.CreateFileA', None, params)
        self.assertEqual(output_handle, 0xF101)
        self.assertEqual(console._stream(emu, output_handle), 'stdout')
        self.assertEqual(files._close_handle(
            emu, 'kernel32.CloseHandle', None, [input_handle]), 1)
        self.assertEqual(console._get_file_type(
            emu, '', lambda _args: 1, [input_handle]), 0)
        self.assertEqual(errors[-1], 6)
        self.assertEqual(files._close_handle(
            emu, 'kernel32.CloseHandle', None, [input_handle]), 0)

    def test_narrow_console_bytes_use_oem_code_page(self):
        process = SimpleNamespace(get_std_handle=lambda _code: 0xF002)
        emu = SimpleNamespace(get_current_process=lambda: process,
                              mem_read=lambda _address, _size: b'\x82',
                              mem_write=lambda *_args: None,
                              set_last_error=lambda _code: None)
        console = ConsoleOutput(437)
        self.assertEqual(console._write_console(
            emu, 'kernel32.WriteConsoleA', None,
            [0xF002, 0x1000, 1, 0, 0]), 1)
        self.assertEqual(console.report()['stdout'], 'é')

    def test_screen_buffer_info_is_written_for_guest_stdout(self):
        output = []
        process = SimpleNamespace(get_std_handle=lambda code: 0xF002)
        emu = SimpleNamespace(get_current_process=lambda: process,
                              mem_write=lambda address, data: output.append((address, data)),
                              set_last_error=lambda _code: None)
        console = ConsoleOutput()
        self.assertEqual(console._screen_buffer_info(
            emu, '', None, [0xF002, 0x2000]), 1)
        self.assertEqual(output[0][0], 0x2000)
        self.assertEqual(len(output[0][1]), 22)
        self.assertEqual(struct.unpack_from('<hh', output[0][1]), (80, 25))

    def test_locale_mapping_and_native_api_hooks(self):
        self.assertEqual(oem_code_page('en-US'), 437)
        self.assertEqual(oem_code_page('de-DE'), 850)
        callbacks = {}

        class Registrar:
            def add_api_hook(self, callback, module, name, **_kwargs):
                callbacks[(module, name)] = callback

        console = ConsoleOutput(850)
        console.install(Registrar())
        self.assertEqual(callbacks[('api-ms-win-core-console-l1-1-0',
                                    'GetConsoleOutputCP')](None, '', None, []), 850)
        self.assertEqual(callbacks[('kernel32', 'GetConsoleCP')](
            None, '', None, []), 850)
        self.assertIs(callbacks[('api-ms-win-core-console-l1-1-0',
                                 'WriteConsoleW')].__self__, console)


if __name__ == '__main__':
    unittest.main()
