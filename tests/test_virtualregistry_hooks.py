"""Registry hooks are available through the Windows API-set DLL too."""

import unittest

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

    def test_sign_extended_predefined_handle(self):
        bridge = VirtualRegistryBridge(None)
        self.assertEqual(bridge._canonical_handle(0xffffffff80000001), 0x80000001)
        self.assertEqual(bridge._canonical_handle(0x100000001), 0x100000001)


if __name__ == "__main__":
    unittest.main()
