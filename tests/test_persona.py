"""The guest desktop, registry, environment, and process view agree."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from speakeasy.config import SpeakeasyConfig
from speakeasy.windows.objman import HandleAllocator
from speakeasy.windows.regman import RegistryManager
from speakeasy.windows.fileman import File as GuestFile

from emumee.artifacts import ArtifactCatalog
from emumee.persona import load_persona, make_speakeasy_config, materialize_virtual_files
from emumee.persona_content import desktop_directories
from emumee.virtualfs import VirtualFileBridge
from emumee.virtualprocess import VirtualProcessBridge


class PersonaContentTests(unittest.TestCase):
    def test_default_guest_has_coherent_files_registry_and_processes(self):
        persona = load_persona(None)
        config = make_speakeasy_config(persona, "sample.exe", 10, 1000)
        parsed = SpeakeasyConfig.model_validate(config)
        self.assertGreaterEqual(len(persona["virtual_files"]), 20)
        self.assertGreaterEqual(len(persona["registry_keys"]), 40)
        self.assertGreaterEqual(len(config["processes"]), 15)
        self.assertEqual(config["filesystem"]["files"], [])
        self.assertEqual([drive["root_path"] for drive in config["drives"]], ["C:\\"])
        self.assertFalse(any("usbsamp" in item["path"].casefold()
                             for item in config["registry"]["keys"]))
        self.assertEqual(config["env"]["number_of_processors"], "12")
        self.assertEqual(next(item["path"] for item in config["processes"]
                              if item["name"] == "OneDrive.exe"),
                         r"C:\Users\Alex\AppData\Local\Microsoft\OneDrive\OneDrive.exe")
        registry = RegistryManager(HandleAllocator(), parsed.registry)
        version = registry.get_key_from_config(
            r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion")
        self.assertEqual(version.get_value("CurrentBuild").get_data(), "22631")
        self.assertEqual(version.get_value("DisplayVersion").get_data(), "23H2")
        self.assertIsNotNone(registry.get_key_from_config(
            r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"))
        with tempfile.TemporaryDirectory() as directory:
            staged = dict(materialize_virtual_files(persona, Path(directory)))
            self.assertIn(r"C:\Users\Alex\Documents\readme.txt", staged)
            self.assertIn(b"localhost", staged[
                r"C:\Windows\System32\drivers\etc\hosts"].read_bytes())

    def test_overrides_refresh_dependent_guest_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "persona.json"
            path.write_text(json.dumps({
                "user_name": "Morgan", "hostname": "DESKTOP-Q3R8V2A",
                "windows_build": 26100, "locale": "en-US",
                "cpu": {"cores": 8, "threads_per_core": 2},
            }), encoding="utf-8")
            persona = load_persona(path)
            self.assertEqual(persona["current_dir"], r"C:\Users\Morgan\Downloads")
            self.assertTrue(all("\\Alex\\" not in item["path"]
                                for item in persona["virtual_files"]))
            self.assertIn(r"C:\Users\Morgan\Desktop\Welcome.txt",
                          {item["path"] for item in persona["virtual_files"]})
            config = make_speakeasy_config(persona, "test.exe", 10, 1000)
            self.assertEqual(config["env"]["number_of_processors"], "16")
            self.assertIn(r"C:\Users\Morgan", next(item["path"] for item in
                          config["processes"] if item["name"] == "OneDrive.exe"))
            version = persona["registry_keys"][0]["values"]
            self.assertEqual(next(v["data"] for v in version
                                  if v["name"] == "DisplayVersion"), "24H2")
            self.assertEqual(next(v["data"] for v in version
                                  if v["name"] == "RegisteredOwner"), "Morgan")
            self.assertTrue(any(item["path"].endswith("\\" + persona["user_sid"])
                                for item in persona["registry_keys"]))

    def test_custom_files_and_registry_are_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "persona.json"
            path.write_text(json.dumps({
                "user_name": "Morgan", "registry_keys": [],
                "virtual_files": [{"path": r"C:\Users\Morgan\note.txt", "text": "hello"}],
            }), encoding="utf-8")
            persona = load_persona(path)
            self.assertEqual(persona["registry_keys"], [])
            self.assertEqual(len(persona["virtual_files"]), 1)
            self.assertEqual(persona["virtual_files"][0]["text"], "hello")

    def test_guest_program_search_uses_only_staged_files(self):
        system_tool = SimpleNamespace(path=r"C:\Windows\System32\whoami.exe")
        local_tool = SimpleNamespace(path=r"C:\Users\Alex\Downloads\helper.exe")
        files = SimpleNamespace(files=[system_tool, local_tool])
        emu = SimpleNamespace(get_cd=lambda: r"C:\Users\Alex\Downloads",
                              get_file_manager=lambda: files)
        resolve = VirtualProcessBridge._guest_executable
        self.assertEqual(resolve(emu, "helper"), (local_tool.path, local_tool))
        self.assertEqual(resolve(emu, "whoami"), (system_tool.path, system_tool))
        self.assertEqual(resolve(emu, "absent"),
                         (r"C:\Users\Alex\Downloads\absent", None))

    def test_default_guest_directories_include_empty_windows_locations(self):
        directories = desktop_directories("Morgan")
        self.assertIn(r"C:\Windows\Temp", directories)
        self.assertIn(r"C:\Users\Morgan\AppData\Local\Temp", directories)

    def test_create_process_can_resolve_command_line_only_guest_image(self):
        image = (Path(__file__).parent / "fixtures" / "native_x64.exe").read_bytes()
        guest_path = r"C:\Windows\System32\helper.exe"
        memory = {0x1000: "helper.exe /quiet", 0x2000: ""}
        allocated = {}
        errors = []
        emu = SimpleNamespace(
            read_mem_string=lambda address, _: memory[address],
            get_cd=lambda: r"C:\Users\Alex\Downloads",
            get_file_manager=lambda: SimpleNamespace(files=[GuestFile(None, guest_path,
                                                                        data=image)]),
            get_ptr_size=lambda: 8,
            get_current_process=lambda: object(),
            set_last_error=errors.append,
            mem_map=lambda size, tag, process: 0x3000,
            mem_write=lambda address, data: allocated.__setitem__(address, data),
            mem_free=lambda address: allocated.pop(address),
        )
        bridge = VirtualProcessBridge(None)
        observed = []
        def loader(params):
            observed.append((params[0], allocated[params[0]].decode("utf-16-le").rstrip("\0")))
            return 0
        params = [0, 0x1000, 0, 0, 0, 0, 0, 0, 0x2000, 0x2000]
        self.assertEqual(bridge._create_process(emu, "kernel32.CreateProcessW",
                                                 loader, params), 0)
        self.assertEqual(observed, [(0x3000, guest_path)])
        self.assertEqual(allocated, {})

    def test_volume_information_writes_bounded_windows_volume_data(self):
        with tempfile.TemporaryDirectory() as directory:
            bridge = VirtualFileBridge(r"C:\Users\Alex\Downloads",
                                       ArtifactCatalog(Path(directory) / "artifacts"))
            writes, errors = {}, []
            emu = SimpleNamespace(
                read_mem_string=lambda ptr, width: "C:\\" if ptr == 0x1000 else "",
                mem_write=lambda ptr, data: writes.__setitem__(ptr, data),
                set_last_error=errors.append,
            )
            args = [0x1000, 0x2000, 8, 0x3000, 0x4000, 0x5000, 0x6000, 5]
            self.assertEqual(bridge._get_volume_information(
                emu, "kernel32.GetVolumeInformationW", None, args), 1)
            self.assertEqual(writes[0x2000], "Windows\0".encode("utf-16-le"))
            self.assertEqual(writes[0x3000], (0x4C2F91A7).to_bytes(4, "little"))
            self.assertEqual(writes[0x4000], (255).to_bytes(4, "little"))
            self.assertEqual(writes[0x6000], "NTFS\0".encode("utf-16-le"))
            writes.clear()
            args[2] = 7
            self.assertEqual(bridge._get_volume_information(
                emu, "kernel32.GetVolumeInformationW", None, args), 0)
            self.assertEqual(errors[-1], 122)
            self.assertEqual(writes, {})
            args[2] = 8
            emu.read_mem_string = lambda ptr, width: "D:\\"
            self.assertEqual(bridge._get_volume_information(
                emu, "kernel32.GetVolumeInformationW", None, args), 0)
            self.assertEqual(errors[-1], 3)

    def test_temp_path_small_buffer_has_no_write(self):
        with tempfile.TemporaryDirectory() as directory:
            bridge = VirtualFileBridge(r"C:\Users\Alex\Downloads",
                                       ArtifactCatalog(Path(directory) / "artifacts"))
            writes, errors = {}, []
            emu = SimpleNamespace(
                get_env=lambda: {"tmp": r"C:\Users\Alex\AppData\Local\Temp"},
                mem_write=lambda ptr, data: writes.__setitem__(ptr, data),
                set_last_error=errors.append,
            )
            path = "C:\\Users\\Alex\\AppData\\Local\\Temp\\"
            self.assertEqual(bridge._get_temp_path(
                emu, "kernel32.GetTempPathW", None, [4, 0x1000]), len(path) + 1)
            self.assertEqual(writes, {})
            self.assertEqual(bridge._get_temp_path(
                emu, "kernel32.GetTempPathW", None, [len(path) + 1, 0x1000]), len(path))
            self.assertEqual(writes[0x1000], (path + "\0").encode("utf-16-le"))


if __name__ == "__main__":
    unittest.main()
