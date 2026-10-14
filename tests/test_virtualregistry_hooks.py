"""Registry hooks are available through the Windows API-set DLL too."""

import unittest
from types import SimpleNamespace

from speakeasy.config import SpeakeasyConfig
from speakeasy.windows.objman import HandleAllocator
from speakeasy.windows.regman import RegKey
from speakeasy.windows.regman import RegistryManager

from emumee.persona import load_persona, make_speakeasy_config
from emumee.virtualregistry import VirtualRegistryBridge


class RegistryHookTests(unittest.TestCase):
    def test_ansi_expansion_uses_guest_environment_and_preserves_unknown_name(self):
        key = RegKey(None, r"HKEY_CURRENT_USER\Environment")
        key.create_value("Mixed", 2, "%Unknown%|%TeMp%")
        memory = {0x100: (128).to_bytes(4, "little"), 0x200: b"\0" * 4}
        emu = SimpleNamespace(
            reg_get_key=lambda handle: key if handle == 7 else None,
            get_env=lambda: {"temp": r"C:\T"},
            read_mem_string=lambda _address, _width: "Mixed",
            mem_read=lambda address, size: memory[address][:size],
            mem_write=lambda address, data: memory.__setitem__(address, data))
        bridge = VirtualRegistryBridge(None)
        bridge.handle_owners[7] = id(emu)
        self.assertEqual(bridge._get_value(
            emu, "advapi32.RegGetValueA", None,
            [7, 0, 11, 0xffff, 0x200, 0x300, 0x100]), 0)
        self.assertEqual(memory[0x200], (1).to_bytes(4, "little"))
        self.assertEqual(memory[0x300], b"%Unknown%|C:\\T\0")
        self.assertEqual(memory[0x100], max(len(b"%Unknown%|%TeMp%\0"),
                                            len(memory[0x300])).to_bytes(4, "little"))

    def test_registry_api_set_aliases_use_same_handlers(self):
        hooks = {}

        class Registrar:
            def add_api_hook(self, callback, module, name, **kwargs):
                hooks[(module, name)] = (callback.__name__, kwargs["argc"])

        VirtualRegistryBridge(None).install(Registrar())
        alias = "api-ms-win-core-registry-l1-1-0"
        for name in ("RegOpenKeyExW", "RegQueryValueExW", "RegEnumValueW",
                     "RegEnumKeyExW", "RegQueryInfoKeyW", "RegCloseKey"):
            self.assertEqual(hooks[(alias, name)], hooks[("advapi32", name)])
        self.assertEqual(hooks[(alias, "RegGetValueW")],
                         hooks[("advapi32", "RegGetValueW")])

    def test_sign_extended_predefined_handle(self):
        bridge = VirtualRegistryBridge(None)
        self.assertEqual(bridge._canonical_handle(0xffffffff80000001), 0x80000001)
        self.assertEqual(bridge._canonical_handle(0x100000001), 0x100000001)

    def test_configured_binary_hex_decodes_exact_guest_bytes(self):
        key = RegKey(None, r"HKEY_LOCAL_MACHINE\SOFTWARE\Example")
        value = key.create_value("TZI", 3, b"\xf0\x00\x80\xff")
        self.assertEqual(VirtualRegistryBridge(None)._configured_value(value, True),
                         (3, b"\xf0\x00\x80\xff"))
        configured = key.create_value("Configured", "REG_BINARY", "hex:f00080ff")
        self.assertEqual(VirtualRegistryBridge(None)._configured_value(configured, True),
                         (3, b"\xf0\x00\x80\xff"))
        bad = key.create_value("Broken", "REG_BINARY", "hex:zz")
        self.assertIsNone(VirtualRegistryBridge(None)._configured_value(bad, True))

    def test_configured_dword_string_is_returned_as_little_endian_bytes(self):
        key = RegKey(None, r"HKEY_LOCAL_MACHINE\SOFTWARE\Example")
        value = key.create_value("Flag", "REG_DWORD", "0x10203")
        self.assertEqual(VirtualRegistryBridge(None)._configured_value(value, True),
                         (4, b"\x03\x02\x01\x00"))
        malformed = key.create_value("Broken", "REG_DWORD", "not a number")
        self.assertIsNone(VirtualRegistryBridge(None)._configured_value(malformed, True))

    def test_reg_get_value_size_then_exact_guest_bytes(self):
        key = RegKey(None, r"HKEY_CURRENT_USER\Control Panel\Desktop")
        key.create_value("ScreenSaveActive", 1, "1")
        key.create_value("Expandable", 2, "%TEMP%")
        memory = {0x100: b"\0" * 4, 0x200: b"\0" * 4}
        emu = SimpleNamespace(
            reg_get_key=lambda handle: key if handle == 7 else None,
            get_env=lambda: {"temp": r"C:\Temp"},
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
        memory[0x100] = b"\0" * 4
        self.assertEqual(bridge._get_value(
            emu, name, None, [7, 0, 12, 0xffff, 0x200, 0, 0x100]), 0)
        expanded = 'C:\\Temp\0'.encode('utf-16le')
        self.assertEqual(memory[0x100], len(expanded).to_bytes(4, 'little'))
        self.assertEqual(memory[0x200], (1).to_bytes(4, 'little'))
        memory[0x100] = (2).to_bytes(4, 'little')
        self.assertEqual(bridge._get_value(
            emu, name, None, [7, 0, 12, 0xffff, 0x200, 0x300, 0x100]), 234)
        self.assertEqual(memory[0x300], b'1\0\0\0')
        memory[0x100] = len(expanded).to_bytes(4, 'little')
        self.assertEqual(bridge._get_value(
            emu, name, None, [7, 0, 12, 0xffff, 0x200, 0x300, 0x100]), 0)
        self.assertEqual(memory[0x300], expanded)
        memory[0x100] = b"\0" * 4
        self.assertEqual(bridge._get_value(
            emu, name, None, [7, 0, 12, 0x1000ffff, 0x200, 0, 0x100]), 0)
        self.assertEqual(memory[0x200], (2).to_bytes(4, 'little'))
        self.assertEqual(memory[0x100], len('%TEMP%\0'.encode('utf-16le'))
                         .to_bytes(4, 'little'))
        emu.get_env = lambda: {"temp": r"C:\T"}
        memory[0x100] = b"\0" * 4
        self.assertEqual(bridge._get_value(
            emu, name, None, [7, 0, 12, 0xffff, 0x200, 0, 0x100]), 0)
        self.assertEqual(memory[0x100], len('%TEMP%\0'.encode('utf-16le'))
                         .to_bytes(4, 'little'))
        memory[0x100] = (12).to_bytes(4, 'little')
        self.assertEqual(bridge._get_value(
            emu, name, None, [7, 0, 12, 0xffff, 0x200, 0x300, 0x100]), 234)
        memory[0x100] = (14).to_bytes(4, 'little')
        self.assertEqual(bridge._get_value(
            emu, name, None, [7, 0, 12, 0xffff, 0x200, 0x300, 0x100]), 0)
        self.assertEqual(memory[0x300], 'C:\\T\0'.encode('utf-16le'))


    def test_enum_values_exposes_persona_data_and_buffer_contract(self):
        config = make_speakeasy_config(load_persona(None), "sample.exe", 10, 1000)
        manager = RegistryManager(HandleAllocator(),
                                  SpeakeasyConfig.model_validate(config).registry)
        key = manager.get_key_from_config(r"HKEY_CURRENT_USER\Control Panel\Desktop")
        memory = {0x100: (2).to_bytes(4, "little"),
                  0x200: (2).to_bytes(4, "little"), 0x300: b"untouched"}
        emu = SimpleNamespace(regman=manager,
                              reg_get_key=lambda handle: key if handle == 7 else None,
                              mem_read=lambda address, size: memory[address][:size],
                              mem_write=lambda address, data: memory.__setitem__(address, data))
        bridge = VirtualRegistryBridge(None)
        bridge.handle_owners[7] = id(emu)
        call = [7, 0, 0x300, 0x100, 0, 0x400, 0x500, 0x200]
        self.assertEqual(bridge._enum_value(emu, "advapi32.RegEnumValueW", None, call), 234)
        self.assertEqual(memory[0x300], b"untouched")
        self.assertEqual(memory[0x100], (2).to_bytes(4, "little"))
        self.assertEqual(memory[0x200], len("400\0".encode("utf-16le")).to_bytes(4, "little"))
        memory[0x100] = (32).to_bytes(4, "little")
        memory[0x200] = (1).to_bytes(4, "little")
        self.assertEqual(bridge._enum_value(emu, "advapi32.RegEnumValueW", None, call), 234)
        self.assertEqual(memory[0x300], "MenuShowDelay\0".encode("utf-16le"))
        self.assertEqual(memory[0x100], len("MenuShowDelay").to_bytes(4, "little"))
        self.assertEqual(memory[0x400], (1).to_bytes(4, "little"))
        memory[0x100] = (32).to_bytes(4, "little")
        memory[0x200] = (32).to_bytes(4, "little")
        self.assertEqual(bridge._enum_value(emu, "advapi32.RegEnumValueW", None, call), 0)
        self.assertEqual(memory[0x300], "MenuShowDelay\0".encode("utf-16le"))
        self.assertEqual(memory[0x400], (1).to_bytes(4, "little"))
        self.assertEqual(memory[0x500], "400\0".encode("utf-16le"))
        self.assertEqual(bridge._enum_value(
            emu, "advapi32.RegEnumValueW", None,
            [7, len(key.get_values()), 0x300, 0x100, 0, 0, 0, 0]), 259)

    def test_enum_subkeys_includes_configured_children_and_guest_timestamp(self):
        config = make_speakeasy_config(load_persona(None), "sample.exe", 10, 1000)
        manager = RegistryManager(HandleAllocator(),
                                  SpeakeasyConfig.model_validate(config).registry)
        parent = manager.get_key_from_config(
            r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer")
        memory = {0x100: (1).to_bytes(4, "little"),
                  0x200: b"untouched", 0x300: (1).to_bytes(4, "little")}
        emu = SimpleNamespace(regman=manager,
                              reg_get_key=lambda handle: parent if handle == 7 else None,
                              mem_read=lambda address, size: memory[address][:size],
                              mem_write=lambda address, data: memory.__setitem__(address, data))
        bridge = VirtualRegistryBridge(None, filetime_ticks=132000000000000000)
        bridge.handle_owners[7] = id(emu)
        names = bridge._direct_subkeys(manager, parent.get_path())
        self.assertIn("TypedPaths", names)
        self.assertIn("RunMRU", names)
        index = names.index("TypedPaths")
        call = [7, index, 0x200, 0x100, 0, 0x400, 0x300, 0x500]
        self.assertEqual(bridge._enum_key_ex(emu, "advapi32.RegEnumKeyExA", None, call), 234)
        self.assertEqual(memory[0x200], b"untouched")
        self.assertEqual(memory[0x100], (1).to_bytes(4, "little"))
        memory[0x100] = (32).to_bytes(4, "little")
        memory[0x300] = (1).to_bytes(4, "little")
        self.assertEqual(bridge._enum_key_ex(emu, "advapi32.RegEnumKeyExA", None, call), 0)
        self.assertEqual(memory[0x200], b"TypedPaths\0")
        self.assertEqual(memory[0x100], (10).to_bytes(4, "little"))
        self.assertEqual(memory[0x400], b"\0")
        self.assertEqual(memory[0x300], (0).to_bytes(4, "little"))
        self.assertEqual(memory[0x500], (132000000000000000).to_bytes(8, "little"))
        self.assertEqual(bridge._enum_key_ex(
            emu, "advapi32.RegEnumKeyExA", None,
            [7, len(names), 0x200, 0x100, 0, 0, 0, 0]), 259)

    def test_query_info_sizes_match_persona_enumeration(self):
        config = make_speakeasy_config(load_persona(None), "sample.exe", 10, 1000)
        manager = RegistryManager(HandleAllocator(),
                                  SpeakeasyConfig.model_validate(config).registry)
        key = manager.get_key_from_config(r"HKEY_CURRENT_USER\Control Panel\Desktop")
        memory = {0x100: (1).to_bytes(4, "little")}
        emu = SimpleNamespace(regman=manager,
                              reg_get_key=lambda handle: key if handle == 7 else None,
                              mem_read=lambda address, size: memory[address][:size],
                              mem_write=lambda address, data: memory.__setitem__(address, data))
        bridge = VirtualRegistryBridge(None, filetime_ticks=132000000000000000)
        bridge.handle_owners[7] = id(emu)
        call = [7, 0x110, 0x100, 0, 0x120, 0x130, 0x140,
                0x150, 0x160, 0x170, 0x180, 0x190]
        self.assertEqual(bridge._query_info_key(
            emu, "advapi32.RegQueryInfoKeyW", None, call), 0)
        self.assertEqual(memory[0x110], b"\0\0")
        self.assertEqual(memory[0x120], (0).to_bytes(4, "little"))
        self.assertEqual(memory[0x150], len(key.get_values()).to_bytes(4, "little"))
        self.assertEqual(memory[0x160], len("ScreenSaveTimeOut").to_bytes(4, "little"))
        self.assertEqual(memory[0x170], len("400\0".encode("utf-16le")).to_bytes(4, "little"))
        self.assertEqual(memory[0x190], (132000000000000000).to_bytes(8, "little"))
        memory[0x100] = (0).to_bytes(4, "little")
        self.assertEqual(bridge._query_info_key(
            emu, "advapi32.RegQueryInfoKeyW", None, call), 234)

    def test_guest_write_remains_visible_after_reopening_configured_key(self):
        config = make_speakeasy_config(load_persona(None), "sample.exe", 10, 1000)
        manager = RegistryManager(HandleAllocator(),
                                  SpeakeasyConfig.model_validate(config).registry)
        name = "GuestMarker"
        raw = "seen\0".encode("utf-16le")
        memory = {0x300: raw, 0x400: (32).to_bytes(4, "little"),
                  0x500: (32).to_bytes(4, "little")}
        strings = {0x200: r"Control Panel\Desktop", 0x250: name}
        emu = SimpleNamespace(regman=manager, reg_get_key=manager.get_key_from_handle,
                              read_mem_string=lambda address, _width: strings[address],
                              mem_read=lambda address, size: memory[address][:size],
                              mem_write=lambda address, data: memory.__setitem__(address, data),
                              get_ptr_size=lambda: 8)
        bridge = VirtualRegistryBridge(None)
        root = 0x80000001
        open_call = [root, 0x200, 0, 0, 0x100]
        self.assertEqual(bridge._open_key_ex(
            emu, "advapi32.RegOpenKeyExW", None, open_call), 0)
        first = int.from_bytes(memory[0x100], "little")
        self.assertEqual(bridge._set_value(
            emu, "advapi32.RegSetValueExW", lambda _: 0,
            [first, 0x250, 0, 1, 0x300, len(raw)]), 0)
        self.assertEqual(bridge._close_key(emu, "advapi32.RegCloseKey", None,
                                           [first]), 0)
        self.assertEqual(bridge._open_key_ex(
            emu, "advapi32.RegOpenKeyExW", None, open_call), 0)
        second = int.from_bytes(memory[0x100], "little")
        self.assertNotEqual(first, second)
        self.assertEqual(bridge._enum_value(
            emu, "advapi32.RegEnumValueW", None,
            [second, 4, 0x600, 0x400, 0, 0x700, 0x800, 0x500]), 0)
        self.assertEqual(memory[0x600], (name + "\0").encode("utf-16le"))
        self.assertEqual(memory[0x800], raw)
        self.assertEqual(memory[0x700], (1).to_bytes(4, "little"))
        memory[0xA00] = (16).to_bytes(4, "little")
        self.assertEqual(bridge._query_value(
            emu, "advapi32.RegQueryValueExA", None,
            [second, 0x250, 0, 0, 0x900, 0xA00]), 0)
        self.assertEqual(memory[0x900], b"seen\0")
        self.assertEqual(len(manager.get_key_from_handle(second).get_values()), 5)


if __name__ == "__main__":
    unittest.main()
