"""Generated enumeration programs execute as guest children from persona data."""

import ipaddress
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

    def test_winexec_ipconfig_all_uses_guest_persona(self):
        for machine, arch in ((0x14C, "x86"), (0x8664, "x64")):
            for command in (b"ipconfig.exe /all\0",
                            b'"C:\\Windows\\System32\\ipconfig.exe" /all\0'):
                with self.subTest(arch=arch, command=command), tempfile.TemporaryDirectory() as directory:
                    persona = load_persona(None)
                    parent = bytearray(build_host_winexec_probe(machine, "unused-marker"))
                    parent[0x700:0x900] = b"\0" * 0x200
                    parent[0x700:0x700 + len(command)] = command
                    payload = bytes(parent)
                    result = run_native(payload, inspect_pe(payload, "parent.exe"),
                                        persona, Path(directory), [], 10, 100_000)
                    self.assertFalse(result["errors"])
                    self.assertEqual(result["console_output"]["stdout"],
                                     enumeration_text("ipconfig.exe", persona, "/all"))

    def test_winexec_route_and_timezone_queries_use_custom_persona(self):
        for machine, arch in ((0x14C, "x86"), (0x8664, "x64")):
            for name, arguments in (("route.exe", "print -4"),
                                    ("tzutil.exe", "/g"),
                                    ("arp.exe", "-a"),
                                    ("netsh.exe", "interface ipv4 show config"),
                                    ("whoami.exe", "/user"),
                                    ("query.exe", "user"),
                                    ("quser.exe", ""),
                                    ("qwinsta.exe", ""),
                                    ("net.exe", "localgroup administrators"),
                                    ("net1.exe", "user")):
                with self.subTest(arch=arch, name=name), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    custom = root / "persona.json"
                    custom.write_text(json.dumps({
                        "timezone": "W. Europe Standard Time",
                        "utc_offset_minutes": 60,
                        "clock_utc": "2026-10-14T12:00:00Z",
                        "network_adapter": {"ipv4": "192.168.8.42",
                                            "gateway": "192.168.8.1"},
                    }), encoding="utf-8")
                    persona = load_persona(custom)
                    parent = bytearray(build_host_winexec_probe(machine, "unused-marker"))
                    parent[0x700:0x900] = b"\0" * 0x200
                    command = f"{name}{' ' + arguments if arguments else ''}\0".encode("ascii")
                    parent[0x700:0x700 + len(command)] = command
                    payload = bytes(parent)
                    result = run_native(payload, inspect_pe(payload, "parent.exe"),
                                        persona, root / "run", [], 10, 100_000)
                    self.assertFalse(result["errors"])
                    self.assertEqual(result["console_output"]["stdout"],
                                     enumeration_text(name, persona, arguments))

    def test_generated_programs_run_as_guest_children_on_both_architectures(self):
        for machine, arch in ((0x14C, "x86"), (0x8664, "x64")):
            for name in ("whoami.exe", "ipconfig.exe", "systeminfo.exe", "tasklist.exe",
                         "getmac.exe", "arp.exe", "route.exe", "netsh.exe",
                         "tzutil.exe", "query.exe", "quser.exe", "qwinsta.exe",
                         "net.exe", "net1.exe"):
                with self.subTest(arch=arch, name=name), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    custom = root / "persona.json"
                    custom.write_text(json.dumps({
                        "hostname": "DESKTOP-TEST432",
                        "user_name": "Morgan",
                        "windows_build": 26100,
                        "timezone": "W. Europe Standard Time",
                        "utc_offset_minutes": 60,
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
        self.assertEqual(enumeration_text("whoami.exe", persona),
                         persona["hostname"] + "\\" + persona["user_name"])
        self.assertIn(persona["user_sid"],
                      enumeration_text("whoami.exe", persona, "/user"))
        ipconfig = enumeration_text("ipconfig.exe", persona)
        self.assertIn(persona["network_adapter"]["ipv4"], ipconfig)
        self.assertIn(persona["network_adapter"]["gateway"], ipconfig)
        detailed = enumeration_text("ipconfig.exe", persona, "/all")
        getmac = enumeration_text("getmac.exe", persona)
        self.assertIn(persona["network_adapter"]["mac"], detailed)
        self.assertIn(persona["network_adapter"]["mac"], getmac)
        self.assertIn(persona["network_adapter"]["guid"], getmac)
        route = enumeration_text("route.exe", persona, "print -4")
        self.assertIn(persona["network_adapter"]["gateway"], route)
        self.assertIn(str(persona["network_adapter"]["if_index"]), route)
        subnet = ipaddress.IPv4Network(
            (persona["network_adapter"]["ipv4"],
             persona["network_adapter"]["prefix_length"]), strict=False)
        self.assertIn(str(subnet.network_address), route)
        self.assertIn(str(subnet.netmask), route)
        arp = enumeration_text("arp.exe", persona, "-a")
        self.assertIn(persona["network_adapter"]["ipv4"], arp)
        self.assertIn(str(subnet.broadcast_address), arp)
        self.assertIn("ff-ff-ff-ff-ff-ff", arp)
        netsh = enumeration_text("netsh.exe", persona, "interface ipv4 show config")
        self.assertIn(persona["network_adapter"]["ipv4"], netsh)
        self.assertIn(persona["network_adapter"]["gateway"], netsh)
        for server in persona["network_adapter"]["dns_servers"]:
            self.assertIn(server, netsh)
        self.assertEqual(enumeration_text("tzutil.exe", persona, "/g"),
                         persona["timezone"] + "_dstoff\r\n")
        systeminfo = enumeration_text("systeminfo.exe", persona)
        self.assertIn(persona["hostname"], systeminfo)
        self.assertIn(str(persona["windows_build"]), systeminfo)
        tasklist = enumeration_text("tasklist.exe", persona)
        for process in config["processes"]:
            self.assertIn(process["name"], tasklist)
            self.assertIn(str(process["pid"]), tasklist)

    def test_ipconfig_all_and_unmodeled_switches(self):
        persona = load_persona(None)
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as directory:
                image = enumeration_programs(arch == "x64", persona)["ipconfig.exe"]
                for argument in ("/all", "/ALL", "/release"):
                    with self.subTest(argument=argument):
                        result = run_native(image, inspect_pe(image, "ipconfig.exe"),
                                            persona, Path(directory) / argument[1:],
                                            [], 10, 100_000, guest_args=[argument])
                        self.assertFalse(result["errors"])
                        if argument.casefold() == "/all":
                            self.assertEqual(result["guest_exit_code"], 0)
                            self.assertEqual(result["console_output"]["stdout"],
                                             enumeration_text("ipconfig.exe", persona,
                                                              "/all"))
                        else:
                            self.assertEqual(result["guest_exit_code"], 87)
                            self.assertEqual(result["console_output"]["stdout"], "")

    def test_whoami_user_and_groups_match_guest_token(self):
        for arch in ("x86", "x64"):
            for is_admin in (False, True):
                with self.subTest(arch=arch, admin=is_admin), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    custom = root / "persona.json"
                    custom.write_text(json.dumps({"hostname": "DESKTOP-CHECK42",
                                                  "user_name": "Morgan",
                                                  "user_sid": "S-1-5-21-1-2-3-1001",
                                                  "user_is_admin": is_admin}), encoding="utf-8")
                    persona = load_persona(custom)
                    image = enumeration_programs(arch == "x64", persona)["whoami.exe"]
                    for index, argument in enumerate(("/user", "/groups", "/priv",
                                                       "/all", "/upn")):
                        result = run_native(image, inspect_pe(image, "whoami.exe"), persona,
                                            root / str(index), [], 10, 100_000,
                                            guest_args=[argument])
                        self.assertFalse(result["errors"])
                        if argument == "/upn":
                            self.assertEqual(result["guest_exit_code"], 87)
                            self.assertEqual(result["console_output"]["stdout"], "")
                        else:
                            self.assertEqual(result["guest_exit_code"], 0)
                            self.assertEqual(result["console_output"]["stdout"],
                                             enumeration_text("whoami.exe", persona, argument))
                    groups = enumeration_text("whoami.exe", persona, "/groups")
                    self.assertIn("BUILTIN\\Users", groups)
                    self.assertEqual("BUILTIN\\Administrators" in groups, is_admin)
                    privileges = enumeration_text("whoami.exe", persona, "/priv")
                    self.assertIn("SeChangeNotifyPrivilege", privileges)
                    self.assertEqual("SeDebugPrivilege" in privileges, is_admin)
                    combined = enumeration_text("whoami.exe", persona, "/all")
                    self.assertIn(persona["user_sid"], combined)
                    self.assertIn(groups, combined)
                    self.assertIn(privileges, combined)

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

    def test_route_print_reads_persona_and_add_is_rejected(self):
        persona = load_persona(None)
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as directory:
                image = enumeration_programs(arch == "x64", persona)["route.exe"]
                for index, argument in enumerate(("print", "print -4", "add 0.0.0.0")):
                    result = run_native(image, inspect_pe(image, "route.exe"), persona,
                                        Path(directory) / str(index), [], 10, 100_000,
                                        guest_args=argument.split())
                    self.assertFalse(result["errors"])
                    if argument.startswith("print"):
                        self.assertEqual(result["guest_exit_code"], 0)
                        self.assertEqual(result["console_output"]["stdout"],
                                         enumeration_text("route.exe", persona, argument))
                    else:
                        self.assertEqual(result["guest_exit_code"], 87)
                        self.assertEqual(result["console_output"]["stdout"], "")

    def test_tzutil_query_runs_in_guest_and_mutating_command_fails(self):
        persona = load_persona(None)
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as directory:
                image = enumeration_programs(arch == "x64", persona)["tzutil.exe"]
                for argument in ("/g", "/s"):
                    result = run_native(image, inspect_pe(image, "tzutil.exe"), persona,
                                        Path(directory) / argument[1:], [], 10, 100_000,
                                        guest_args=[argument])
                    self.assertFalse(result["errors"])
                    if argument == "/g":
                        self.assertEqual(result["guest_exit_code"], 0)
                        self.assertEqual(result["console_output"]["stdout"],
                                         enumeration_text("tzutil.exe", persona, "/g"))
                    else:
                        self.assertEqual(result["guest_exit_code"], 87)
                        self.assertEqual(result["console_output"]["stdout"], "")

    def test_arp_listing_tracks_guest_table_without_invented_gateway_mac(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as directory:
                persona = load_persona(None)
                image = enumeration_programs(arch == "x64", persona)["arp.exe"]
                for argument in ("-a", "-d"):
                    result = run_native(image, inspect_pe(image, "arp.exe"), persona,
                                        Path(directory) / argument[1:], [], 10, 100_000,
                                        guest_args=[argument])
                    self.assertFalse(result["errors"])
                    if argument == "-a":
                        self.assertEqual(result["guest_exit_code"], 0)
                        self.assertEqual(result["console_output"]["stdout"],
                                         enumeration_text("arp.exe", persona, "-a"))
                    else:
                        self.assertEqual(result["guest_exit_code"], 87)
                        self.assertEqual(result["console_output"]["stdout"], "")
                persona["network_adapter"].update({"ipv4": "10.0.0.0",
                                                   "gateway": "10.0.0.1",
                                                   "prefix_length": 31})
                self.assertEqual(enumeration_text("arp.exe", persona, "-a"),
                                 "No ARP Entries Found.\r\n")

    def test_netsh_queries_use_guest_adapter_and_reject_mutation(self):
        persona = load_persona(None)
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as directory:
                image = enumeration_programs(arch == "x64", persona)["netsh.exe"]
                commands = ("interface ipv4 show config",
                            "interface ipv4 show dnsservers",
                            "interface ipv4 set address")
                for index, command in enumerate(commands):
                    result = run_native(image, inspect_pe(image, "netsh.exe"), persona,
                                        Path(directory) / str(index), [], 10, 100_000,
                                        guest_args=command.split())
                    self.assertFalse(result["errors"])
                    if " show " in command:
                        self.assertEqual(result["guest_exit_code"], 0)
                        self.assertEqual(result["console_output"]["stdout"],
                                         enumeration_text("netsh.exe", persona, command))
                    else:
                        self.assertEqual(result["guest_exit_code"], 87)
                        self.assertEqual(result["console_output"]["stdout"], "")

    def test_query_uses_guest_user_session_and_clock(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                custom = root / "persona.json"
                custom.write_text(json.dumps({"user_name": "Morgan",
                                              "clock_utc": "2026-10-14T12:00:00Z",
                                              "utc_offset_minutes": 60,
                                              "uptime_ms": 3_600_000}), encoding="utf-8")
                persona = load_persona(custom)
                image = enumeration_programs(arch == "x64", persona)["query.exe"]
                for index, argument in enumerate(("user", "session", "process")):
                    result = run_native(image, inspect_pe(image, "query.exe"), persona,
                                        root / str(index), [], 10, 100_000,
                                        guest_args=[argument])
                    self.assertFalse(result["errors"])
                    if argument == "process":
                        self.assertEqual(result["guest_exit_code"], 87)
                        self.assertEqual(result["console_output"]["stdout"], "")
                    else:
                        self.assertEqual(result["guest_exit_code"], 0)
                        self.assertEqual(result["console_output"]["stdout"],
                                         enumeration_text("query.exe", persona, argument))
                user = enumeration_text("query.exe", persona, "user")
                self.assertIn("Morgan", user)
                self.assertIn("10/14/2026 12:00 PM", user)
                session = enumeration_text("query.exe", persona, "session")
                self.assertIn("services", session)
                self.assertIn("console", session)
                for name, expected in (("quser.exe", user), ("qwinsta.exe", session)):
                    self.assertEqual(enumeration_text(name, persona), expected)
                    alias = enumeration_programs(arch == "x64", persona)[name]
                    result = run_native(alias, inspect_pe(alias, name), persona,
                                        root / name, [], 10, 100_000)
                    self.assertFalse(result["errors"])
                    self.assertEqual(result["console_output"]["stdout"], expected)
                    unsupported = run_native(alias, inspect_pe(alias, name), persona,
                                             root / (name + "-unsupported"), [],
                                             10, 100_000, guest_args=["/server:HOST"])
                    self.assertFalse(unsupported["errors"])
                    self.assertEqual(unsupported["guest_exit_code"], 87)
                    self.assertEqual(unsupported["console_output"]["stdout"], "")

    def test_net_local_account_queries_match_guest_token(self):
        for arch in ("x86", "x64"):
            for is_admin in (False, True):
                with self.subTest(arch=arch, admin=is_admin), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    custom = root / "persona.json"
                    custom.write_text(json.dumps({"hostname": "DESKTOP-CHECK42",
                                                  "user_name": "Morgan",
                                                  "user_is_admin": is_admin}), encoding="utf-8")
                    persona = load_persona(custom)
                    for name in ("net.exe", "net1.exe"):
                        image = enumeration_programs(arch == "x64", persona)[name]
                        commands = ("user", "user Morgan", "localgroup",
                                    "localgroup administrators", "localgroup users",
                                    "user Morgan /add")
                        for index, command in enumerate(commands):
                            result = run_native(image, inspect_pe(image, name), persona,
                                                root / name / str(index), [], 10, 100_000,
                                                guest_args=command.split())
                            self.assertFalse(result["errors"])
                            if command.endswith("/add"):
                                self.assertEqual(result["guest_exit_code"], 87)
                                self.assertEqual(result["console_output"]["stdout"], "")
                            else:
                                self.assertEqual(result["guest_exit_code"], 0)
                                self.assertEqual(result["console_output"]["stdout"],
                                                 enumeration_text(name, persona, command))
                    admins = enumeration_text("net.exe", persona,
                                              "localgroup administrators")
                    self.assertEqual("Morgan" in admins, is_admin)
                    self.assertIn("Morgan", enumeration_text("net.exe", persona,
                                                            "localgroup users"))
                    self.assertEqual("BUILTIN\\Administrators" in
                                     enumeration_text("whoami.exe", persona, "/groups"),
                                     is_admin)
        persona = load_persona(None)
        persona["user_name"] = "Administrator"
        persona["user_is_admin"] = False
        accounts = enumeration_text("net.exe", persona, "user")
        self.assertEqual(accounts.count("Administrator"), 1)
        administrators = enumeration_text("net.exe", persona,
                                          "localgroup administrators")
        self.assertNotIn("\r\nAdministrator\r\n", administrators)

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
