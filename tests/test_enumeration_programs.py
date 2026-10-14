"""Generated enumeration programs execute as guest children from persona data."""

import json
import tempfile
import unittest
from pathlib import Path

from emumee.enumeration_programs import enumeration_programs, enumeration_text
from emumee.native import run_native
from emumee.pe import inspect_pe
from emumee.persona import load_persona, make_speakeasy_config
from tests.fixtures.build_native import build_host_process_probe, build_host_winexec_probe


class EnumerationProgramTests(unittest.TestCase):
    def test_createprocess_launches_guest_ipconfig(self):
        for machine, arch in ((0x14C, "x86"), (0x8664, "x64")):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as directory:
                persona = load_persona(None)
                parent = bytearray(build_host_process_probe(machine, "unused-marker"))
                path = r"C:\Windows\System32\ipconfig.exe"
                encoded = (path + "\0").encode("utf-16-le")
                parent[0x500:0x700] = b"\0" * 0x200
                parent[0x700:0x900] = b"\0" * 0x200
                parent[0x500:0x500 + len(encoded)] = encoded
                parent[0x700:0x700 + len(encoded)] = encoded
                payload = bytes(parent)
                root = Path(directory)
                result = run_native(payload, inspect_pe(payload, "parent.exe"),
                                    persona, root, [], 10, 100_000)
                self.assertFalse(result["errors"])
                self.assertEqual(result["console_output"]["stdout"],
                                 enumeration_text("ipconfig.exe", persona))
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertTrue(any(item["event"] == "virtual_process_create" and
                                    item["success"] and item["api"].endswith("CreateProcessW")
                                    for item in report["virtual_process_events"]))

    def test_generated_programs_run_as_guest_children_on_both_architectures(self):
        for machine, arch in ((0x14C, "x86"), (0x8664, "x64")):
            for name in ("ipconfig.exe", "systeminfo.exe", "tasklist.exe"):
                with self.subTest(arch=arch, name=name), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    custom = root / "persona.json"
                    custom.write_text(json.dumps({
                        "hostname": "DESKTOP-TEST432",
                        "user_name": "Morgan",
                        "windows_build": 26100,
                        "processes": ["System", "explorer.exe", "OneDrive.exe"],
                        "network_adapter": {"name": "Office Ethernet",
                                            "ipv4": "192.168.8.42",
                                            "gateway": "192.168.8.1",
                                            "dns_servers": ["192.168.8.1"]},
                    }), encoding="utf-8")
                    persona = load_persona(custom)
                    generated = enumeration_programs(arch == "x64", persona)[name]
                    self.assertEqual(inspect_pe(generated, name).architecture, arch)
                    parent = bytearray(build_host_winexec_probe(machine, "unused-marker"))
                    parent[0x700:0x900] = b"\0" * 0x200
                    parent[0x700:0x700 + len(name) + 1] = name.encode("ascii") + b"\0"
                    payload = bytes(parent)
                    result = run_native(payload, inspect_pe(payload, "parent.exe"), persona,
                                        root / "run", [], 10, 100_000)
                    self.assertFalse(result["errors"])
                    self.assertEqual(result["console_output"]["stdout"],
                                     enumeration_text(name, persona))
                    report = json.loads(((root / "run") /
                                         result["engine_report"]).read_text())
                    self.assertEqual(len(report["entry_points"]), 2)
                    self.assertTrue(any(event["event"] == "virtual_process_create" and
                                        event["success"] and event["path"].casefold() ==
                                        ("C:\\Windows\\System32\\" + name).casefold()
                                        for event in report["virtual_process_events"]))

    def test_outputs_agree_with_other_persona_surfaces(self):
        persona = load_persona(None)
        config = make_speakeasy_config(persona, "parent.exe", 10, 100_000)
        ipconfig = enumeration_text("ipconfig.exe", persona)
        self.assertIn(persona["network_adapter"]["ipv4"], ipconfig)
        self.assertIn(persona["network_adapter"]["gateway"], ipconfig)
        systeminfo = enumeration_text("systeminfo.exe", persona)
        self.assertIn(persona["hostname"], systeminfo)
        self.assertIn(str(persona["windows_build"]), systeminfo)
        tasklist = enumeration_text("tasklist.exe", persona)
        for process in config["processes"]:
            self.assertIn(process["name"], tasklist)
            self.assertIn(str(process["pid"]), tasklist)

    def test_unmodeled_switches_fail_without_persona_output(self):
        persona = load_persona(None)
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as directory:
                image = enumeration_programs(arch == "x64", persona)["ipconfig.exe"]
                result = run_native(image, inspect_pe(image, "ipconfig.exe"), persona,
                                    Path(directory), [], 10, 100_000,
                                    guest_args=["/all"])
                self.assertFalse(result["errors"])
                self.assertEqual(result["guest_exit_code"], 87)
                self.assertEqual(result["console_output"]["stdout"], "")

    def test_non_ascii_owner_uses_persona_console_code_page(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            custom = root / "persona.json"
            custom.write_text(json.dumps({"user_name": "Jörg", "locale": "de-DE"}),
                              encoding="utf-8")
            persona = load_persona(custom)
            image = enumeration_programs(True, persona)["systeminfo.exe"]
            result = run_native(image, inspect_pe(image, "systeminfo.exe"),
                                persona, root / "run", [], 10, 100_000)
            self.assertFalse(result["errors"])
            self.assertEqual(result["guest_exit_code"], 0)
            self.assertIn("Registered Owner:          Jörg",
                          result["console_output"]["stdout"])

    def test_long_but_valid_process_list_fits_guest_program(self):
        persona = load_persona(None)
        persona["processes"] = [f"process-{index:03d}-" + "x" * 105 + ".exe"
                                for index in range(128)]
        image = enumeration_programs(True, persona)["tasklist.exe"]
        self.assertEqual(inspect_pe(image, "tasklist.exe").architecture, "x64")
        with tempfile.TemporaryDirectory() as directory:
            result = run_native(image, inspect_pe(image, "tasklist.exe"), persona,
                                Path(directory), [], 10, 100_000)
        self.assertFalse(result["errors"])
        self.assertEqual(result["guest_exit_code"], 0)
        self.assertEqual(result["console_output"]["stdout"],
                         enumeration_text("tasklist.exe", persona))
        self.assertIn("process-127-", result["console_output"]["stdout"])


if __name__ == "__main__":
    unittest.main()
