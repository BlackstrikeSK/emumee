"""The guest desktop, registry, environment, and process view agree."""

from __future__ import annotations

import base64
import json
import struct
import tempfile
import unittest
import uuid
import zipfile
from pathlib import Path
from types import SimpleNamespace

from speakeasy.config import SpeakeasyConfig
from speakeasy.windows.objman import HandleAllocator
from speakeasy.windows.regman import RegistryManager
from speakeasy.windows.fileman import File as GuestFile

from emumee.artifacts import ArtifactCatalog
from emumee.guest_programs import hostname_exe, whoami_exe
from emumee.identity import GuestIdentity
from emumee.native import run_native
from emumee.pe import inspect_pe
from emumee.persona import (load_persona, make_speakeasy_config,
                            materialize_virtual_files, virtual_file_bytes)
from emumee.persona_content import desktop_directories
from emumee.virtualregistry import VirtualRegistryBridge
from emumee.virtualfs import VirtualFileBridge
from emumee.virtualprocess import VirtualProcessBridge
from emumee.winenvironment import GuestEnvironmentBlocks
from tests.fixtures.build_native import (build as build_test_pe,
                                         build_host_process_probe,
                                         build_host_winexec_probe)


class PersonaContentTests(unittest.TestCase):
    def test_guest_path_contains_modeled_windows_directories_and_can_be_overridden(self):
        persona = load_persona(None)
        cfg = make_speakeasy_config(persona, "where.exe", 10, 100_000)
        self.assertEqual(cfg["env"]["path"],
                         r"C:\Windows\System32;C:\Windows;C:\Windows\System32\Wbem")
        changed = make_speakeasy_config(persona, "where.exe", 10, 100_000,
                                        guest_env={"PATH": r"C:\Tools"})
        self.assertEqual(changed["env"]["path"], r"C:\Tools")

    def test_computer_name_api_set_uses_persona_dns_domain(self):
        persona = load_persona(None)
        bridge = GuestIdentity(persona)
        hooks = {}
        class Registrar:
            def add_api_hook(self, callback, module, name, **_kwargs):
                hooks[(module, name)] = callback
        bridge.install(Registrar())
        self.assertEqual(hooks[("api-ms-win-core-sysinfo-l1-1-0",
                                "GetComputerNameExW")].__name__,
                         bridge._computer_name_ex.__name__)
        memory = {0x1000: (32).to_bytes(4, "little")}
        emu = SimpleNamespace(
            mem_read=lambda address, size: memory[address][:size],
            mem_write=lambda address, data: memory.__setitem__(address, data),
            set_last_error=lambda _code: None,
        )
        self.assertEqual(bridge._computer_name_ex(
            emu, "api-ms-win-core-sysinfo-l1-1-0.GetComputerNameExW", None,
            [2, 0x2000, 0x1000]), 1)
        self.assertEqual(memory[0x2000], b"\0\0")
        self.assertEqual(memory[0x1000], (0).to_bytes(4, "little"))

    def test_network_adapter_override_updates_registry_and_rejects_bad_addresses(self):
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "persona.json"
            config.write_text(json.dumps({"network_adapter": {
                "name": "Office Ethernet", "ipv4": "10.20.30.44",
                "prefix_length": 24, "gateway": "10.20.30.1",
                "dns_servers": ["10.20.30.2"]}}), encoding="utf-8")
            persona = load_persona(config)
            self.assertEqual(persona["network_adapter"]["mac"],
                             "3C-52-82-4A-6F-19")
            interface = next(item for item in persona["registry_keys"]
                             if item["path"].endswith(
                                 "Tcpip\\Parameters\\Interfaces\\" +
                                 persona["network_adapter"]["guid"]))
            values = {item["name"]: item["data"] for item in interface["values"]}
            self.assertEqual(values["DhcpIPAddress"], "10.20.30.44")
            self.assertEqual(values["DhcpSubnetMask"], "255.255.255.0")
            self.assertEqual(values["DhcpDefaultGateway"], "10.20.30.1")
            self.assertEqual(values["DhcpNameServer"], "10.20.30.2")

            config.write_text(json.dumps({"network_adapter": {
                "ipv4": "10.20.30.44", "gateway": "192.168.1.1"}}),
                encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "IPv4 settings"):
                load_persona(config)

    def test_computer_and_user_name_api_sizes_and_formats(self):
        persona = load_persona(None)
        bridge = GuestIdentity(persona)
        memory = {0x1000: (2).to_bytes(4, "little")}
        errors = []
        emu = SimpleNamespace(
            mem_read=lambda ptr, size: memory[ptr][:size],
            mem_write=lambda ptr, data: memory.__setitem__(ptr, data),
            set_last_error=errors.append,
        )
        self.assertEqual(bridge._computer_name(
            emu, "kernel32.GetComputerNameW", None, [0x2000, 0x1000]), 0)
        self.assertEqual(errors[-1], 111)
        self.assertEqual(int.from_bytes(memory[0x1000], "little"), len(persona["hostname"]) + 1)
        self.assertNotIn(0x2000, memory)
        self.assertEqual(bridge._computer_name(
            emu, "kernel32.GetComputerNameW", None, [0x2000, 0x1000]), 1)
        self.assertEqual(memory[0x2000], (persona["hostname"] + "\0").encode("utf-16-le"))
        self.assertEqual(int.from_bytes(memory[0x1000], "little"), len(persona["hostname"]))

        memory[0x1000] = (0).to_bytes(4, "little")
        self.assertEqual(bridge._computer_name_ex(
            emu, "kernel32.GetComputerNameExA", None, [3, 0, 0x1000]), 0)
        self.assertEqual(errors[-1], 234)
        self.assertEqual(int.from_bytes(memory[0x1000], "little"), len(persona["hostname"]) + 1)
        self.assertEqual(bridge._computer_name_ex(
            emu, "kernel32.GetComputerNameExA", None, [3, 0x3000, 0x1000]), 1)
        self.assertEqual(memory[0x3000], persona["hostname"].encode() + b"\0")
        self.assertEqual(bridge._computer_name_ex(
            emu, "kernel32.GetComputerNameExA", None, [8, 0x3000, 0x1000]), 0)
        self.assertEqual(errors[-1], 87)

        memory[0x1000] = (2).to_bytes(4, "little")
        self.assertEqual(bridge._user_name(
            emu, "advapi32.GetUserNameW", None, [0x4000, 0x1000]), 0)
        self.assertEqual(errors[-1], 122)
        self.assertEqual(int.from_bytes(memory[0x1000], "little"), len(persona["user_name"]) + 1)
        self.assertEqual(bridge._user_name(
            emu, "advapi32.GetUserNameW", None, [0x4000, 0x1000]), 1)
        self.assertEqual(memory[0x4000], (persona["user_name"] + "\0").encode("utf-16-le"))
        self.assertEqual(int.from_bytes(memory[0x1000], "little"), len(persona["user_name"]) + 1)

    def test_guest_pe_calls_computer_name_hook_on_both_architectures(self):
        for machine, arch in ((0x14C, "x86"), (0x8664, "x64")):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as directory:
                base = 0x400000 if arch == "x86" else 0x140000000
                image = bytearray(build_test_pe(machine))
                image[0x470:0x490] = (b"\0\0GetComputerNameW\0").ljust(0x20, b"\0")
                struct.pack_into("<I", image, 0x5E0, 64)
                if arch == "x64":
                    code = bytearray(b"\x48\x83\xec\x28\x48\xb9" +
                                     struct.pack("<Q", base + 0x21A0) + b"\x48\xba" +
                                     struct.pack("<Q", base + 0x21E0))
                    code.extend(b"\xff\x15" + struct.pack(
                        "<i", 0x2040 - (0x1000 + len(code) + 6)))
                    code.extend(b"\x48\x83\xc4\x28\xc3")
                else:
                    code = (b"\x68" + struct.pack("<I", base + 0x21E0) +
                            b"\x68" + struct.pack("<I", base + 0x21A0) +
                            b"\xff\x15" + struct.pack("<I", base + 0x2040) + b"\xc3")
                image[0x200:0x200 + len(code)] = code
                name = f"computer_name_{arch}.exe"
                payload = bytes(image)
                root = Path(directory)
                result = run_native(payload, inspect_pe(payload, name), load_persona(None),
                                    root, [], 10, 100_000)
                self.assertFalse(result["errors"])
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertTrue(any(event.get("api_name") == "kernel32.GetComputerNameW"
                                    and event.get("ret_val") == "0x1"
                                    for entry in report["entry_points"]
                                    for event in entry["events"]))

    def test_staged_guest_pe_runs_as_child_without_host_launch(self):
        for machine, arch in ((0x14C, "x86"), (0x8664, "x64")):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                persona = load_persona(None)
                child = build_test_pe(machine)
                source = root / "verified-child.exe"
                source.write_bytes(child)
                parent = bytearray(build_host_process_probe(machine, "unused-marker"))
                guest_path = persona["current_dir"] + r"\helper.exe"
                parent[0x500:0x700] = b"\0" * 0x200
                parent[0x700:0x900] = b"\0" * 0x200
                parent[0x500:0x500 + len(guest_path.encode("utf-16-le")) + 2] = (
                    guest_path + "\0").encode("utf-16-le")
                parent[0x700:0x700 + len(guest_path.encode("utf-16-le")) + 2] = (
                    guest_path + "\0").encode("utf-16-le")
                payload = bytes(parent)
                result = run_native(payload, inspect_pe(payload, "parent.exe"), persona,
                                    root / "run", [], 10, 100_000,
                                    bundle_files=[("helper.exe", source, child)])
                self.assertFalse(result["errors"])
                report = json.loads(((root / "run") /
                                     result["engine_report"]).read_text())
                created = [item for item in report["virtual_process_events"]
                           if item["event"] == "virtual_process_create"]
                self.assertEqual(len(created), 1)
                self.assertTrue(created[0]["success"])
                self.assertEqual(len(report["entry_points"]), 2)

    def test_default_hostname_program_executes_and_prints_guest_name(self):
        for machine, arch in ((0x14C, "x86"), (0x8664, "x64")):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as directory:
                persona = load_persona(None)
                utility = hostname_exe(arch == "x64")
                self.assertEqual(inspect_pe(utility, "hostname.exe").architecture, arch)
                parent = bytearray(build_host_process_probe(machine, "unused-marker"))
                guest_path = r"C:\Windows\System32\hostname.exe"
                encoded = (guest_path + "\0").encode("utf-16-le")
                parent[0x500:0x700] = b"\0" * 0x200
                parent[0x700:0x900] = b"\0" * 0x200
                parent[0x500:0x500 + len(encoded)] = encoded
                parent[0x700:0x700 + len(encoded)] = encoded
                payload = bytes(parent)
                root = Path(directory)
                result = run_native(payload, inspect_pe(payload, "parent.exe"), persona,
                                    root, [], 10, 100_000)
                self.assertFalse(result["errors"])
                self.assertEqual(result["console_output"]["stdout"], persona["hostname"])
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertEqual(len(report["entry_points"]), 2)
                self.assertTrue(any(item["event"] == "virtual_process_create" and
                                    item["success"] for item in report["virtual_process_events"]))

    def test_winexec_finds_default_hostname_program_by_bare_name(self):
        for machine, arch in ((0x14C, "x86"), (0x8664, "x64")):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as directory:
                parent = bytearray(build_host_winexec_probe(machine, "unused-marker"))
                parent[0x700:0x900] = b"\0" * 0x200
                parent[0x700:0x70D] = b"hostname.exe\0"
                payload = bytes(parent)
                root = Path(directory)
                persona = load_persona(None)
                result = run_native(payload, inspect_pe(payload, "parent.exe"), persona,
                                    root, [], 10, 100_000)
                self.assertFalse(result["errors"])
                self.assertEqual(result["console_output"]["stdout"], persona["hostname"])
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertEqual(len(report["entry_points"]), 2)

    def test_default_whoami_program_executes_for_custom_persona(self):
        for machine, arch in ((0x14C, "x86"), (0x8664, "x64")):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                custom = root / "persona.json"
                custom.write_text(json.dumps({"hostname": "DESKTOP-Q3R8V2A",
                                              "user_name": "Morgan"}), encoding="utf-8")
                persona = load_persona(custom)
                utility = whoami_exe(arch == "x64", persona["hostname"])
                self.assertEqual(inspect_pe(utility, "whoami.exe").architecture, arch)
                parent = bytearray(build_host_process_probe(machine, "unused-marker"))
                guest_path = r"C:\Windows\System32\whoami.exe"
                encoded = (guest_path + "\0").encode("utf-16-le")
                parent[0x500:0x700] = b"\0" * 0x200
                parent[0x700:0x900] = b"\0" * 0x200
                parent[0x500:0x500 + len(encoded)] = encoded
                parent[0x700:0x700 + len(encoded)] = encoded
                payload = bytes(parent)
                result = run_native(payload, inspect_pe(payload, "parent.exe"), persona,
                                    root / "run", [], 10, 100_000,
                                    guest_env={"USERNAME": "Eve"})
                self.assertFalse(result["errors"])
                self.assertEqual(result["console_output"]["stdout"],
                                 r"DESKTOP-Q3R8V2A\Morgan")
                report = json.loads(((root / "run") /
                                     result["engine_report"]).read_text())
                self.assertEqual(len(report["entry_points"]), 2)

    def test_environment_variable_api_checks_size_and_missing_name(self):
        bridge = GuestEnvironmentBlocks()
        names = {0x1000: "USERNAME", 0x1100: "ABSENT"}
        writes, errors = {}, []
        emu = SimpleNamespace(
            read_mem_string=lambda ptr, width: names[ptr],
            get_env=lambda: {"username": "Morgan"},
            mem_write=lambda ptr, data: writes.__setitem__(ptr, data),
            set_last_error=errors.append,
        )
        self.assertEqual(bridge._get_variable(
            emu, "kernel32.GetEnvironmentVariableW", None, [0x1000, 0x2000, 2]), 7)
        self.assertEqual(errors[-1], 122)
        self.assertEqual(writes, {})
        self.assertEqual(bridge._get_variable(
            emu, "kernel32.GetEnvironmentVariableW", None, [0x1000, 0x2000, 7]), 6)
        self.assertEqual(writes[0x2000], "Morgan\0".encode("utf-16-le"))
        self.assertEqual(bridge._get_variable(
            emu, "kernel32.GetEnvironmentVariableA", None, [0x1100, 0x2000, 32]), 0)
        self.assertEqual(errors[-1], 203)

    def test_guest_pe_environment_variable_returns_required_length(self):
        for machine, arch in ((0x14C, "x86"), (0x8664, "x64")):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as directory:
                base = 0x400000 if arch == "x86" else 0x140000000
                image = bytearray(build_test_pe(machine))
                image[0x470:0x490] = (b"\0\0GetEnvironmentVariableA\0").ljust(0x20, b"\0")
                image[0x580:0x589] = b"USERNAME\0"
                if arch == "x64":
                    code = bytearray(b"\x48\x83\xec\x28\x48\xb9" +
                                     struct.pack("<Q", base + 0x2180) + b"\x48\xba" +
                                     struct.pack("<Q", base + 0x21A0) +
                                     b"\x41\xb8\x02\0\0\0")
                    code.extend(b"\xff\x15" + struct.pack(
                        "<i", 0x2040 - (0x1000 + len(code) + 6)))
                    code.extend(b"\x48\x83\xc4\x28\xc3")
                else:
                    code = (b"\x6a\x02\x68" + struct.pack("<I", base + 0x21A0) +
                            b"\x68" + struct.pack("<I", base + 0x2180) +
                            b"\xff\x15" + struct.pack("<I", base + 0x2040) + b"\xc3")
                image[0x200:0x200 + len(code)] = code
                payload = bytes(image)
                root = Path(directory)
                result = run_native(payload, inspect_pe(payload, "env.exe"),
                                    load_persona(None), root, [], 10, 100_000)
                self.assertFalse(result["errors"])
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertTrue(any(event.get("api_name") ==
                                    "kernel32.GetEnvironmentVariableA" and
                                    event.get("ret_val") == "0x5"
                                    for entry in report["entry_points"]
                                    for event in entry["events"]))
    def test_default_guest_has_coherent_files_registry_and_processes(self):
        persona = load_persona(None)
        config = make_speakeasy_config(persona, "sample.exe", 10, 1000)
        parsed = SpeakeasyConfig.model_validate(config)
        self.assertGreaterEqual(len(persona["virtual_files"]), 20)
        self.assertGreaterEqual(len(persona["registry_keys"]), 45)
        self.assertGreaterEqual(len(config["processes"]), 15)
        self.assertEqual(config["filesystem"]["files"], [])
        self.assertEqual([drive["root_path"] for drive in config["drives"]], ["C:\\"])
        self.assertFalse(any("usbsamp" in item["path"].casefold()
                             for item in config["registry"]["keys"]))
        self.assertEqual(config["env"]["number_of_processors"], "12")
        self.assertEqual(config["env"]["systemdrive"], "C:")
        self.assertEqual(config["env"]["commonprogramfiles"],
                         r"C:\Program Files\Common Files")
        self.assertEqual(next(item["path"] for item in config["processes"]
                              if item["name"] == "OneDrive.exe"),
                         r"C:\Users\Alex\AppData\Local\Microsoft\OneDrive\OneDrive.exe")
        registry = RegistryManager(HandleAllocator(), parsed.registry)
        version = registry.get_key_from_config(
            r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion")
        self.assertEqual(version.get_value("CurrentBuild").get_data(), "22631")
        self.assertEqual(version.get_value("DisplayVersion").get_data(), "23H2")
        machine = registry.get_key_from_config(
            r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography")
        machine_guid = machine.get_value("MachineGuid").get_data()
        self.assertEqual(uuid.UUID(machine_guid).version, 4)
        self.assertEqual(machine_guid, next(item for item in persona["registry_keys"]
                                            if item["path"] == r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography")
                         ["values"][0]["data"])
        install_paths = registry.get_key_from_config(
            r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion")
        self.assertEqual(install_paths.get_value("ProgramFilesDir").get_data(),
                         config["env"]["programfiles"])
        self.assertEqual(install_paths.get_value("CommonFilesDir").get_data(),
                         config["env"]["commonprogramfiles"])
        profiles = registry.get_key_from_config(
            r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList")
        self.assertEqual(profiles.get_value("ProfilesDirectory").get_data(),
                         r"%SystemDrive%\Users")
        self.assertIn(r"C:\Program Files\Common Files", desktop_directories("Alex"))
        self.assertIsNotNone(registry.get_key_from_config(
            r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"))
        with tempfile.TemporaryDirectory() as directory:
            staged = dict(materialize_virtual_files(persona, Path(directory)))
            self.assertIn(r"C:\Users\Alex\Documents\readme.txt", staged)
            self.assertIn(b"localhost", staged[
                r"C:\Windows\System32\drivers\etc\hosts"].read_bytes())
            self.assertIn("bookmark_bar", json.loads(staged[
                r"C:\Users\Alex\AppData\Local\Microsoft\Edge\User Data\Default\Bookmarks"].read_text())["roots"])
            self.assertIn("BEGIN:VCALENDAR", staged[
                r"C:\Users\Alex\Documents\Work\schedule.ics"].read_text())
            run_mru = next(item for item in persona["registry_keys"]
                           if item["path"].endswith(r"\Explorer\RunMRU"))
            self.assertIn(r"C:\Users\Alex\Documents\Work\meeting-notes.txt",
                          next(value["data"] for value in run_mru["values"]
                               if value["name"] == "a"))

    def test_extended_desktop_files_and_registry_follow_custom_persona(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            override = root / 'persona.json'
            override.write_text(json.dumps({
                'user_name': 'Morgan', 'hostname': 'DESKTOP-Q3R8V2A',
                'locale': 'de-DE', 'timezone': 'W. Europe Standard Time',
                'utc_offset_minutes': 60,
            }), encoding='utf-8')
            persona = load_persona(override)
            self.assertEqual(len(persona['virtual_files']), 49)
            staged = dict(materialize_virtual_files(persona, root / 'staged'))
            receipt = staged[r'C:\Users\Morgan\Documents\Receipts\train-apr-2026.txt']
            self.assertIn(b'24.50', receipt.read_bytes())
            pdf = staged[r'C:\Users\Morgan\Documents\Receipts\train-apr-2026.pdf'].read_bytes()
            self.assertTrue(pdf.startswith(b'%PDF-1.4\n'))
            self.assertIn(b'(Rail fare: 24.50)', pdf)
            self.assertTrue(pdf.rstrip().endswith(b'%%EOF'))
            xref = int(pdf.split(b'startxref\n')[1].splitlines()[0])
            self.assertEqual(pdf[xref:xref + 9], b'xref\n0 6\n')
            offsets = [int(line[:10]) for line in
                       pdf[xref:].splitlines()[3:8]]
            for number, offset in enumerate(offsets, 1):
                self.assertTrue(pdf[offset:].startswith(f'{number} 0 obj\n'.encode()))
            with zipfile.ZipFile(staged[r'C:\Users\Morgan\Downloads\trip-documents.zip']) as archive:
                self.assertEqual(archive.testzip(), None)
                self.assertEqual(archive.read('trip-checklist.txt'),
                                 staged[r'C:\Users\Morgan\Downloads\trip-checklist.txt'].read_bytes())
                self.assertEqual(archive.read('travel-expenses.csv'),
                                 staged[r'C:\Users\Morgan\Downloads\travel-expenses.csv'].read_bytes())
            self.assertIn(r'C:\Users\Morgan\Documents\Receipts',
                          desktop_directories('Morgan'))
            config = make_speakeasy_config(persona, 'sample.exe', 10, 1000)
            registry = RegistryManager(
                HandleAllocator(), SpeakeasyConfig.model_validate(config).registry)
            timezone = registry.get_key_from_config(
                r'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\TimeZoneInformation')
            self.assertEqual(timezone.get_value('TimeZoneKeyName').get_data(),
                             'W. Europe Standard Time')
            self.assertEqual(int(timezone.get_value('ActiveTimeBias').get_data()),
                             0xFFFFFFC4)
            self.assertEqual(int(timezone.get_value('DynamicDaylightTimeDisabled').get_data()),
                             1)
            zone = registry.get_key_from_config(
                r'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Time Zones'
                r'\W. Europe Standard Time')
            self.assertIsNotNone(zone)
            kind, tzi = VirtualRegistryBridge(None)._configured_value(
                zone.get_value('TZI'), True)
            self.assertEqual(kind, 3)
            self.assertEqual(len(tzi), 44)
            self.assertEqual(struct.unpack_from('<i', tzi)[0], -60)
            shell = registry.get_key_from_config(
                r'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders')
            self.assertEqual(shell.get_value('Downloads').get_data(),
                             r'C:\Users\Morgan\Downloads')
            self.assertEqual(shell.get_value('Startup').get_data(),
                             r'C:\Users\Morgan\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup')
            international = registry.get_key_from_config(
                r'HKEY_CURRENT_USER\Control Panel\International')
            self.assertEqual(international.get_value('sShortDate').get_data(),
                             'dd.MM.yyyy')
            self.assertEqual(international.get_value('sTimeFormat').get_data(),
                             'HH:mm:ss')
            machine = registry.get_key_from_config(
                r'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography')
            self.assertNotEqual(machine.get_value('MachineGuid').get_data(),
                                next(item for item in load_persona(None)['registry_keys']
                                     if item['path'] == r'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography')
                                ['values'][0]['data'])
            with self.assertRaisesRegex(ValueError, 'utc_offset_minutes'):
                override.write_text(json.dumps({'utc_offset_minutes': 'invalid'}),
                                    encoding='utf-8')
                load_persona(override)
            with self.assertRaisesRegex(ValueError, 'timezone'):
                override.write_text(json.dumps({'timezone': r'Invalid\Path'}),
                                    encoding='utf-8')
                load_persona(override)

    def test_machine_guid_tracks_machine_identity_not_account_name(self):
        key = r'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography'

        def guid(persona):
            return next(item for item in persona['registry_keys']
                        if item['path'] == key)['values'][0]['data']

        default = load_persona(None)
        with tempfile.TemporaryDirectory() as directory:
            override = Path(directory) / 'persona.json'
            override.write_text(json.dumps({'user_name': 'Morgan'}), encoding='utf-8')
            self.assertEqual(guid(load_persona(override)), guid(default))
            override.write_text(json.dumps({'hostname': 'DESKTOP-Q3R8V2A'}),
                                encoding='utf-8')
            self.assertNotEqual(guid(load_persona(override)), guid(default))

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
            run_mru = next(item for item in persona["registry_keys"]
                           if item["path"].endswith(r"\Explorer\RunMRU"))
            self.assertIn(r"C:\Users\Morgan\Documents",
                          next(value["data"] for value in run_mru["values"]
                               if value["name"] == "a"))

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

    def test_binary_virtual_files_are_bounded_and_decoded_exactly(self):
        payload = b"\0\xffPK\x03\x04\0"
        guest_path = r"C:\Users\Alex\Downloads\probe.zip"
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / "persona.json"
            entry = {"path": guest_path,
                     "base64": base64.b64encode(payload).decode("ascii")}
            config.write_text(json.dumps({"virtual_files": [entry]}), encoding="utf-8")
            persona = load_persona(config)
            self.assertEqual(virtual_file_bytes(persona["virtual_files"][0]), payload)
            self.assertEqual(dict(materialize_virtual_files(
                persona, Path(directory) / "staged"))[guest_path].read_bytes(), payload)
            for broken in ("%%%", base64.b64encode(b"A" * (1024 * 1024 + 1)).decode("ascii")):
                entry["base64"] = broken
                config.write_text(json.dumps({"virtual_files": [entry]}), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "base64|1 MiB"):
                    load_persona(config)
            entry["base64"] = base64.b64encode(payload).decode("ascii")
            entry["text"] = "ambiguous"
            config.write_text(json.dumps({"virtual_files": [entry]}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "exactly one"):
                load_persona(config)

    def test_guest_program_search_uses_only_staged_files(self):
        system_tool = SimpleNamespace(path=r"C:\Windows\System32\whoami.exe")
        local_tool = SimpleNamespace(path=r"C:\Users\Alex\Downloads\helper.exe")
        files = SimpleNamespace(files=[system_tool, local_tool])
        emu = SimpleNamespace(get_cd=lambda: r"C:\Users\Alex\Downloads",
                              get_file_manager=lambda: files)
        resolve = VirtualProcessBridge(None)._guest_executable
        self.assertEqual(resolve(emu, "helper"), (local_tool.path, local_tool))
        self.assertEqual(resolve(emu, "whoami"), (system_tool.path, system_tool))
        self.assertEqual(resolve(emu, "absent"),
                         (r"C:\Users\Alex\Downloads\absent", None))
        files.file_config = SimpleNamespace(files=[SimpleNamespace(
            mode="full_path", emu_path=r"C:\Windows\System32\not-verified.exe",
            path=r"D:\outside\not-verified.exe")])
        self.assertEqual(resolve(emu, "not-verified"),
                         (r"C:\Users\Alex\Downloads\not-verified", None))

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
