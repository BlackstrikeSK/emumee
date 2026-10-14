import unittest

from emumee.ui_language import ThreadUILanguage


class _Emulator:
    def __init__(self):
        self.thread = object()
        self.last_error = None

    def get_current_thread(self):
        return self.thread

    def set_last_error(self, value):
        self.last_error = value


class ThreadUILanguageTests(unittest.TestCase):
    def test_api_set_alias_registers_persona_language_hooks(self):
        hooks = []
        class Registrar:
            def add_api_hook(self, handler, module, name, argc):
                hooks.append((module, name, argc))
        ThreadUILanguage({'locale': 'en-US'}).install(Registrar())
        self.assertIn(('api-ms-win-core-localization-l1-2-0',
                       'SetThreadUILanguage', 1), hooks)

    def test_zero_selects_persona_language_and_state_is_per_thread(self):
        model = ThreadUILanguage({"locale": "de-DE"})
        emu = _Emulator()
        self.assertEqual(model._user(emu, "", None, []), 0x0407)
        self.assertEqual(model._set(emu, "kernel32.SetThreadUILanguage", None, [0]),
                         0x0407)
        self.assertEqual(model._set(emu, "kernel32.SetThreadUILanguage", None,
                                    [0x0409]), 0x0409)
        self.assertEqual(model._get(emu, "", None, []), 0x0409)
        emu.thread = object()
        self.assertEqual(model._get(emu, "", None, []), 0x0407)
        self.assertFalse(model.unsupported)

    def test_unknown_langid_is_reported(self):
        model = ThreadUILanguage({"locale": "en-US"})
        emu = _Emulator()
        self.assertEqual(model._set(emu, "kernel32.SetThreadUILanguage", None,
                                    [0xFFFF]), 0x0409)
        self.assertEqual(emu.last_error, 87)
        self.assertEqual(len(model.unsupported), 1)
