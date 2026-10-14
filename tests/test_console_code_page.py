"""Guest console code page agrees with the persona locale."""

import unittest
import struct
from types import SimpleNamespace

from emumee.console_output import ConsoleOutput
from emumee.persona_content import oem_code_page


class ConsoleCodePageTests(unittest.TestCase):
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


if __name__ == '__main__':
    unittest.main()
