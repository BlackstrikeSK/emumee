"""Registry hooks are available through the Windows API-set DLL too."""

import unittest
from types import SimpleNamespace

from speakeasy.windows.regman import RegKey

from emumee.virtualregistry import VirtualRegistryBridge


class RegistryHookTests(unittest.TestCase):
    def test_registry_api_set_aliases_use_same_handlers(self):
        hooks = {}

        class Registrar:
            def add_api_hook(self, callback, module, name, **kwargs):
                hooks[(module, name)] = (callback.__name__, kwargs["argc"])

        VirtualRegistryBridge(None).install(Registrar())
        alias = "api-ms-win-core-registry-l1-1-0"
        for name in ("RegOpenKeyExW", "RegQueryValueExW", "RegCloseKey"):
            self.assertEqual(hooks[(alias, name)], hooks[("advapi32", name)])
        self.assertEqual(hooks[(alias, "RegGetValueW")],
                         hooks[("advapi32", "RegGetValueW")])

    def test_sign_extended_predefined_handle(self):
        bridge = VirtualRegistryBridge(None)
        self.assertEqual(bridge._canonical_handle(0xffffffff80000001), 0x80000001)
        self.assertEqual(bridge._canonical_handle(0x100000001), 0x100000001)

    def test_reg_get_value_size_then_exact_guest_bytes(self):
        key = RegKey(None, r"HKEY_CURRENT_USER\Control Panel\Desktop")
        key.create_value("ScreenSaveActive", 1, "1")
        key.create_value("Expandable", 2, "%TEMP%")
        memory = {0x100: b"\0" * 4, 0x200: b"\0" * 4}
        emu = SimpleNamespace(
            reg_get_key=lambda handle: key if handle == 7 else None,
            read_mem_string=lambda address, _width: (
                "Expandable" if address == 12 else "ScreenSaveActive"),
            mem_read=lambda address, size: memory[address][:size],
            mem_write=lambda address, data: memory.__setitem__(address, data))
        bridge = VirtualRegistryBridge(None)
        bridge.handle_owners[7] = id(emu)
        name = "api-ms-win-core-registry-l1-1-0.RegGetValueW"
        self.assertEqual(bridge._get_value(
            emu, name, None, [7, 0, 11, 0xffff, 0x200, 0, 0x100]), 0)
        self.assertEqual(memory[0x100], (4).to_bytes(4, "little"))
        self.assertEqual(memory[0x200], (1).to_bytes(4, "little"))
        memory[0x100] = (2).to_bytes(4, "little")
        memory[0x300] = b"unchanged"
        self.assertEqual(bridge._get_value(
            emu, name, None, [7, 0, 11, 0x1000ffff, 0x200, 0x300, 0x100]), 234)
        self.assertEqual(memory[0x300], b"unchanged")
        self.assertEqual(memory[0x100], (4).to_bytes(4, "little"))
        self.assertEqual(bridge._get_value(
            emu, name, None, [7, 0, 11, 0x1000ffff, 0x200, 0x300, 0x100]), 0)
        self.assertEqual(memory[0x300], b"1\0\0\0")
        self.assertEqual(bridge._get_value(
            emu, name, None, [7, 0, 11, 0x2000ffff, 0, 0, 0x100]), 50)
        self.assertEqual(bridge._get_value(
            emu, name, None, [7, 0, 12, 0xffff, 0, 0, 0x100]), 50)


if __name__ == "__main__":
    unittest.main()
