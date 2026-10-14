"""Generated enumeration programs execute as guest children from persona data."""

import ipaddress
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from emumee.enumeration_programs import enumeration_programs, enumeration_text
from emumee.native import run_native
from emumee.network_adapter import GuestNetworkAdapter
from emumee.pe import inspect_pe
from emumee.persona import load_persona, make_speakeasy_config
from tests.fixtures.build_native import build_host_process_probe, build_host_winexec_probe


class EnumerationProgramTests(unittest.TestCase):
    def test_driverquery_uses_only_configured_guest_drivers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "persona.json"
            driver = {"name": "ExampleFilter", "display_name": "Example File Filter",
                      "path": r"System32\drivers\ExampleFilter.sys", "start": 3,
                      "type": 2, "running": False}
            config.write_text(json.dumps({"drivers": [driver]}), encoding="utf-8")
            persona = load_persona(config)
            for is_x64 in (False, True):
                with self.subTest(arch="x64" if is_x64 else "x86"):
                    image = enumeration_programs(is_x64, persona)["driverquery.exe"]
                    pe = inspect_pe(image, "driverquery.exe")
                    self.assertEqual(pe.architecture, "x64" if is_x64 else "x86")
                    for index, (args, expected) in enumerate((
                            ([], "ExampleFilter"),
                            (["/v"], r"C:\Windows\System32\drivers\ExampleFilter.sys"),
                            (["/fo", "csv"], '"ExampleFilter","Example File Filter","File System","Stopped"'),
                            (["/fo", "list"], "Start Mode: 3"),
                            (["/nh"], "ExampleFilter"))):
                        result = run_native(image, pe, persona, root / f"{is_x64}-{index}",
                                            [], 10, 100_000, guest_args=args)
                        self.assertFalse(result["errors"])
                        self.assertEqual(result["guest_exit_code"], 0)
                        self.assertIn(expected, result["console_output"]["stdout"])
                        self.assertNotIn("Wdf01000", result["console_output"]["stdout"])
                    rejected = run_native(image, pe, persona, root / f"{is_x64}-remote",
                                          [], 10, 100_000, guest_args=["/s", "host"])
                    self.assertFalse(rejected["errors"])
                    self.assertEqual(rejected["guest_exit_code"], 87)
                    self.assertEqual(rejected["console_output"]["stdout"], "")
                    reg_image = enumeration_programs(is_x64, persona)["reg.exe"]
                    reg_result = run_native(
                        reg_image, inspect_pe(reg_image, "reg.exe"), persona,
                        root / f"{is_x64}-registry", [], 10, 100_000,
                        guest_args=["query", r"HKLM\SYSTEM\CurrentControlSet\Services\ExampleFilter",
                                    "/v", "ImagePath"])
                    self.assertFalse(reg_result["errors"])
                    self.assertEqual(reg_result["guest_exit_code"], 0)
                    self.assertIn(driver["path"], reg_result["console_output"]["stdout"])

    def test_winexec_launches_guest_driverquery(self):
        for machine, arch in ((0x14C, "x86"), (0x8664, "x64")):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as directory:
                persona = load_persona(None)
                parent = bytearray(build_host_winexec_probe(machine, "unused-marker"))
                parent[0x700:0x900] = b"\0" * 0x200
                command = b"driverquery.exe /v\0"
                parent[0x700:0x700 + len(command)] = command
                payload = bytes(parent)
                root = Path(directory)
                result = run_native(payload, inspect_pe(payload, "parent.exe"),
                                    persona, root, [], 10, 100_000)
                self.assertFalse(result["errors"])
                self.assertIn("ACPI.sys", result["console_output"]["stdout"])
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertTrue(any(event["event"] == "virtual_process_create" and
                                    event["success"] and event["path"].casefold() ==
                                    r"C:\Windows\System32\driverquery.exe".casefold()
                                    for event in report["virtual_process_events"]))

    def test_fsutil_reads_guest_volume_and_rejects_other_drives(self):
        persona = load_persona(None)
        for is_x64 in (False, True):
            with self.subTest(arch="x64" if is_x64 else "x86"), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                image = enumeration_programs(is_x64, persona)["fsutil.exe"]
                pe = inspect_pe(image, "fsutil.exe")
                self.assertEqual(pe.architecture, "x64" if is_x64 else "x86")
                cases = (
                    (["fsinfo", "drives"], 0, "Drives: C:\\\r\n"),
                    (["fsinfo", "drivetype", "C:"], 0, "Fixed Drive\r\n"),
                    (["fsinfo", "volumeinfo", "C:"], 0,
                     "Volume Name : Windows\r\nSerial Number : 0x4c2f91a7\r\n"
                     "Max Component Length : 255\r\nFile System Name : NTFS\r\n"),
                    (["fsinfo", "volumeinfo", "D:"], 3, ""),
                    (["fsinfo", "ntfsinfo", "C:"], 87, ""),
                )
                for index, (args, status, expected) in enumerate(cases):
                    result = run_native(image, pe, persona, root / str(index), [],
                                        10, 100_000, guest_args=args)
                    self.assertFalse(result["errors"])
                    self.assertEqual(result["guest_exit_code"], status)
                    self.assertEqual(result["console_output"]["stdout"], expected)
                    if args[1] == "volumeinfo" and status == 0:
                        report = json.loads((root / str(index) /
                                             result["engine_report"]).read_text())
                        self.assertTrue(any(event["event"] == "virtual_volume_query"
                                            for event in report["virtual_file_events"]))

    def test_winexec_launches_guest_fsutil(self):
        for machine, arch in ((0x14C, "x86"), (0x8664, "x64")):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as directory:
                persona = load_persona(None)
                parent = bytearray(build_host_winexec_probe(machine, "unused-marker"))
                parent[0x700:0x900] = b"\0" * 0x200
                command = b"fsutil.exe fsinfo drives\0"
                parent[0x700:0x700 + len(command)] = command
                payload = bytes(parent)
                root = Path(directory)
                result = run_native(payload, inspect_pe(payload, "parent.exe"),
                                    persona, root, [], 10, 100_000)
                self.assertFalse(result["errors"])
                self.assertEqual(result["console_output"]["stdout"],
                                 "Drives: C:\\\r\n")
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertTrue(any(event["event"] == "virtual_process_create" and
                                    event["success"] and event["path"].casefold() ==
                                    r"C:\Windows\System32\fsutil.exe".casefold()
                                    for event in report["virtual_process_events"]))

    def test_tasklist_service_view_matches_guest_process_and_service_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            custom = root / "persona.json"
            custom.write_text(json.dumps({
                "processes": ["System", "svchost.exe", "svchost.exe", "MsMpEng.exe"],
                "services": [
                    {"name": "EventLog", "display_name": "Windows Event Log",
                     "process": "svchost.exe", "start": 2, "type": 32},
                    {"name": "WinDefend", "display_name": "Microsoft Defender Antivirus Service",
                     "process": "MsMpEng.exe", "start": 2, "type": 16},
                    {"name": "DormantSvc", "display_name": "Dormant Service",
                     "process": "svchost.exe", "start": 4, "type": 32},
                ],
            }), encoding="utf-8")
            persona = load_persona(custom)
            for is_x64 in (False, True):
                with self.subTest(arch="x64" if is_x64 else "x86"):
                    image = enumeration_programs(is_x64, persona)["tasklist.exe"]
                    result = run_native(image, inspect_pe(image, "tasklist.exe"),
                                        persona, root / str(is_x64), [], 10, 100_000,
                                        guest_args=["/svc"])
                    self.assertFalse(result["errors"])
                    self.assertEqual(result["guest_exit_code"], 0)
                    output = result["console_output"]["stdout"]
                    self.assertEqual(output, enumeration_text("tasklist.exe", persona, "/svc"))
                    svchost_rows = [line for line in output.splitlines()
                                    if line.startswith("svchost.exe")]
                    self.assertEqual(len(svchost_rows), 2)
                    self.assertIn("588", svchost_rows[0])
                    self.assertIn("EventLog", svchost_rows[0])
                    self.assertIn("756", svchost_rows[1])
                    self.assertIn("N/A", svchost_rows[1])
                    self.assertIn("WinDefend", output)
                    self.assertNotIn("DormantSvc", output)
                    self.assertIn("EventLog", enumeration_text("sc.exe", persona, "query"))

    def test_schtasks_queries_use_guest_task_inventory_and_reject_create(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            custom = root / "persona.json"
            tasks = [
                {"name": r"\Ops\DailyInventory", "status": "Ready",
                 "next_run_minutes": 30},
                {"name": r"\Ops\DisabledTask", "status": "Disabled",
                 "next_run_minutes": None},
            ]
            custom.write_text(json.dumps({
                "clock_utc": "2026-10-14T12:00:00Z", "utc_offset_minutes": 60,
                "scheduled_tasks": tasks,
            }), encoding="utf-8")
            persona = load_persona(custom)
            for is_x64 in (False, True):
                with self.subTest(arch="x64" if is_x64 else "x86"):
                    image = enumeration_programs(is_x64, persona)["schtasks.exe"]
                    self.assertEqual(inspect_pe(image, "schtasks.exe").architecture,
                                     "x64" if is_x64 else "x86")
                    for index, (args, expected) in enumerate((
                            (["/query"], "\\Ops\\DailyInventory"),
                            (["/query", "/fo", "LIST"], "TaskName:      \\Ops\\DailyInventory"),
                            (["/query", "/fo", "CSV"], '"\\Ops\\DisabledTask"'),
                            (["/query", "/tn", r"\Ops\DailyInventory"],
                             "\\Ops\\DailyInventory"))):
                        result = run_native(image, inspect_pe(image, "schtasks.exe"),
                                            persona, root / f"{is_x64}-{index}", [],
                                            10, 100_000, guest_args=args)
                        self.assertFalse(result["errors"])
                        self.assertEqual(result["guest_exit_code"], 0)
                        self.assertIn(expected, result["console_output"]["stdout"])
                        if index == 0:
                            self.assertIn("10/14/2026 01:30:00 PM",
                                          result["console_output"]["stdout"])
                            self.assertIn("N/A", result["console_output"]["stdout"])
                        self.assertNotIn("Windows Defender Scheduled Scan",
                                         result["console_output"]["stdout"])
                    rejected = run_native(image, inspect_pe(image, "schtasks.exe"),
                                          persona, root / f"{is_x64}-create", [],
                                          10, 100_000,
                                          guest_args=["/Create", "/TN", "HostTask"])
                    self.assertFalse(rejected["errors"])
                    self.assertEqual(rejected["guest_exit_code"], 87)
                    self.assertEqual(rejected["console_output"]["stdout"], "")

    def test_netstat_reads_guest_tcp_table_on_both_architectures(self):
        original = GuestNetworkAdapter._get_extended_tcp_table

        def with_guest_connection(model, emu, api_name, prior, params):
            model.network_bridge.connected_tcp[17] = {
                "local_port": 49152, "remote_ip": "203.0.113.7",
                "remote_port": 443, "pid": 9876,
            }
            return original(model, emu, api_name, prior, params)

        for is_x64 in (False, True):
            with self.subTest(arch="x64" if is_x64 else "x86"), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                custom = root / "persona.json"
                custom.write_text(json.dumps({"network_adapter": {
                    "ipv4": "10.10.4.22", "gateway": "10.10.4.1"}}), encoding="utf-8")
                persona = load_persona(custom)
                image = enumeration_programs(is_x64, persona)["netstat.exe"]
                self.assertEqual(inspect_pe(image, "netstat.exe").architecture,
                                 "x64" if is_x64 else "x86")
                with patch.object(GuestNetworkAdapter, "_get_extended_tcp_table",
                                  with_guest_connection):
                    result = run_native(image, inspect_pe(image, "netstat.exe"),
                                        persona, root / "connected", [], 10, 100_000,
                                        guest_args=["-ano"])
                self.assertFalse(result["errors"])
                self.assertEqual(result["guest_exit_code"], 0)
                output = result["console_output"]["stdout"]
                for part in ("10.10.4.22:49152", "203.0.113.7:443", "ESTABLISHED", "9876"):
                    self.assertIn(part, output)
                empty = run_native(image, inspect_pe(image, "netstat.exe"), persona,
                                   root / "empty", [], 10, 100_000,
                                   guest_args=["-ano"])
                self.assertFalse(empty["errors"])
                self.assertEqual(empty["guest_exit_code"], 0)
                self.assertNotIn("203.0.113.7", empty["console_output"]["stdout"])
                unsupported = run_native(image, inspect_pe(image, "netstat.exe"), persona,
                                         root / "unsupported", [], 10, 100_000,
                                         guest_args=["-b"])
                self.assertFalse(unsupported["errors"])
                self.assertEqual(unsupported["guest_exit_code"], 87)
                self.assertEqual(unsupported["console_output"]["stdout"], "")

    def test_winexec_launches_guest_netstat(self):
        for machine, arch in ((0x14C, "x86"), (0x8664, "x64")):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as directory:
                persona = load_persona(None)
                parent = bytearray(build_host_winexec_probe(machine, "unused-marker"))
                parent[0x700:0x900] = b"\0" * 0x200
                command = b"netstat.exe -ano\0"
                parent[0x700:0x700 + len(command)] = command
                payload = bytes(parent)
                root = Path(directory)
                result = run_native(payload, inspect_pe(payload, "parent.exe"),
                                    persona, root, [], 10, 100_000)
                self.assertFalse(result["errors"])
                self.assertIn("Active Connections", result["console_output"]["stdout"])
                self.assertIn("PID", result["console_output"]["stdout"])
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertTrue(any(event["event"] == "virtual_process_create" and
                                    event["success"] and event["path"].casefold() ==
                                    r"C:\Windows\System32\netstat.exe".casefold()
                                    for event in report["virtual_process_events"]))

    def test_where_reads_guest_search_path_without_host_files(self):
        for is_x64 in (False, True):
            with self.subTest(arch="x64" if is_x64 else "x86"), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                host_only = root / "host_only.exe"
                host_only.write_bytes(b"not a guest file")
                custom = root / "persona.json"
                custom.write_text(json.dumps({
                    "current_dir": str(root),
                    "virtual_files": [
                        {"path": str(root / "portable.exe"), "text": "guest-only"},
                        {"path": r"C:\GuestTools\customtool.exe", "text": "guest-path-only"},
                    ],
                }), encoding="utf-8")
                persona = load_persona(custom)
                image = enumeration_programs(is_x64, persona)["where.exe"]
                self.assertEqual(inspect_pe(image, "where.exe").architecture,
                                 "x64" if is_x64 else "x86")
                for index, (name, expected, status, stream) in enumerate((
                        ("ipconfig", r"C:\Windows\System32\ipconfig.exe", 0, "stdout"),
                        ("portable.exe", str(root / "portable.exe"), 0, "stdout"),
                        ("host_only.exe", "Could not find files", 1, "stderr"),
                        ("/r", "", 87, "stdout"))):
                    result = run_native(image, inspect_pe(image, "where.exe"), persona,
                                        root / f"run-{index}", [], 10, 100_000,
                                        guest_args=[name])
                    self.assertFalse(result["errors"])
                    self.assertEqual(result["guest_exit_code"], status)
                    self.assertIn(expected, result["console_output"][stream])
                    if status == 1:
                        self.assertEqual(result["console_output"]["stdout"], "")
                    self.assertNotIn(str(host_only), result["console_output"]["stdout"])
                custom_path = run_native(image, inspect_pe(image, "where.exe"), persona,
                                         root / "custom-path", [], 10, 100_000,
                                         guest_args=["customtool"],
                                         guest_env={"PATH": r"C:\GuestTools"})
                self.assertFalse(custom_path["errors"])
                self.assertEqual(custom_path["guest_exit_code"], 0)
                self.assertEqual(custom_path["console_output"]["stdout"],
                                 "C:\\GuestTools\\customtool.exe\r\n")

    def test_winexec_launches_guest_where(self):
        for machine, arch in ((0x14C, "x86"), (0x8664, "x64")):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as directory:
                persona = load_persona(None)
                parent = bytearray(build_host_winexec_probe(machine, "unused-marker"))
                parent[0x700:0x900] = b"\0" * 0x200
                command = b"where.exe ipconfig.exe\0"
                parent[0x700:0x700 + len(command)] = command
                payload = bytes(parent)
                root = Path(directory)
                result = run_native(payload, inspect_pe(payload, "parent.exe"),
                                    persona, root, [], 10, 100_000)
                self.assertFalse(result["errors"])
                self.assertEqual(result["console_output"]["stdout"],
                                 "C:\\Windows\\System32\\ipconfig.exe\r\n")
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertTrue(any(event["event"] == "virtual_process_create" and
                                    event["success"] and event["path"].casefold() ==
                                    r"C:\Windows\System32\where.exe".casefold()
                                    for event in report["virtual_process_events"]))

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
                                    ("tasklist.exe", "/svc"),
                                    ("query.exe", "user"),
                                    ("quser.exe", ""),
                                    ("qwinsta.exe", ""),
                                    ("net.exe", "localgroup administrators"),
                                    ("net1.exe", "user"),
                                    ("sc.exe", "query WinDefend"),
                                    ("schtasks.exe", "/query"),
                                    ("reg.exe", r'query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"')):
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
                    if name == "reg.exe":
                        self.assertIn("CurrentBuild    REG_SZ    ",
                                      result["console_output"]["stdout"])
                        self.assertIn("RegisteredOwner    REG_SZ    ",
                                      result["console_output"]["stdout"])
                    else:
                        self.assertEqual(result["console_output"]["stdout"],
                                         enumeration_text(name, persona, arguments))

    def test_generated_programs_run_as_guest_children_on_both_architectures(self):
        for machine, arch in ((0x14C, "x86"), (0x8664, "x64")):
            for name in ("whoami.exe", "ipconfig.exe", "systeminfo.exe", "tasklist.exe",
                         "getmac.exe", "arp.exe", "route.exe", "netsh.exe",
                         "tzutil.exe", "query.exe", "quser.exe", "qwinsta.exe",
                         "net.exe", "net1.exe", "sc.exe", "schtasks.exe"):
                with self.subTest(arch=arch, name=name), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    custom = root / "persona.json"
                    custom.write_text(json.dumps({
                        "hostname": "DESKTOP-TEST432",
                        "user_name": "Morgan",
                        "clock_utc": "2026-10-14T12:00:00Z",
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

    def test_sc_service_views_match_registry_and_process_snapshot(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                custom = root / "persona.json"
                custom.write_text(json.dumps({
                    "processes": ["System", "svchost.exe", "explorer.exe"],
                    "services": [
                        {"name": "WinDefend", "display_name": "Microsoft Defender Antivirus Service",
                         "process": "MsMpEng.exe", "start": 2, "type": 16},
                        {"name": "EventLog", "display_name": "Windows Event Log",
                         "process": "svchost.exe", "start": 2, "type": 32},
                    ],
                }), encoding="utf-8")
                persona = load_persona(custom)
                registry = {item["path"].casefold(): item for item in persona["registry_keys"]}
                self.assertIn(r"hkey_local_machine\system\currentcontrolset\services\eventlog",
                              registry)
                image = enumeration_programs(arch == "x64", persona)["sc.exe"]
                for index, argument in enumerate(("query", "query state= all",
                                                  "query WinDefend", "query EventLog",
                                                  "stop WinDefend")):
                    result = run_native(image, inspect_pe(image, "sc.exe"), persona,
                                        root / str(index), [], 10, 100_000,
                                        guest_args=argument.split())
                    self.assertFalse(result["errors"])
                    if argument.startswith("stop"):
                        self.assertEqual(result["guest_exit_code"], 87)
                        self.assertEqual(result["console_output"]["stdout"], "")
                    else:
                        self.assertEqual(result["guest_exit_code"], 0)
                        self.assertEqual(result["console_output"]["stdout"],
                                         enumeration_text("sc.exe", persona, argument))
                active = enumeration_text("sc.exe", persona, "query")
                self.assertIn("EventLog", active)
                self.assertNotIn("WinDefend", active)
                self.assertIn("STATE              : 1  STOPPED",
                              enumeration_text("sc.exe", persona,
                                               "query WinDefend"))

    def test_reg_queries_use_persona_registry_and_reject_writes(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                custom = root / "persona.json"
                custom.write_text(json.dumps({"user_name": "Morgan",
                                              "windows_build": 26100}), encoding="utf-8")
                persona = load_persona(custom)
                image = enumeration_programs(arch == "x64", persona)["reg.exe"]
                commands = (
                    r'query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"',
                    r'query "HKCU\Control Panel\Desktop"',
                    r'query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v ProductName',
                    r'query "HKCU\Control Panel\Desktop" /v ScreenSaveActive',
                    r'query HKLM\SYSTEM\CurrentControlSet\Services\WinDefend',
                    r'add HKCU\Control Panel\Desktop',
                    r'query HKLM\Software\DefinitelyAbsent',
                    r'query "HKCU\Control Panel\Desktop" /f unsupported',
                )
                for index, command in enumerate(commands):
                    if command.startswith('query "'):
                        closing = command.index('"', len('query "'))
                        guest_args = ["query", command[len('query "'):closing],
                                      *command[closing + 1:].split()]
                    else:
                        guest_args = command.split()
                    result = run_native(image, inspect_pe(image, "reg.exe"), persona,
                                        root / str(index), [], 10, 100_000,
                                        guest_args=guest_args)
                    self.assertFalse(result["errors"])
                    if (command.startswith("add") or command.endswith("DefinitelyAbsent") or
                            "/f " in command):
                        self.assertEqual(result["guest_exit_code"],
                                         2 if command.endswith("DefinitelyAbsent") else 87)
                        self.assertEqual(result["console_output"]["stdout"], "")
                    else:
                        self.assertEqual(result["guest_exit_code"], 0)
                        self.assertIn("REG_", result["console_output"]["stdout"])
                        if "/v " in command:
                            self.assertEqual(result["console_output"]["stdout"].count("REG_"), 1)
                version_result = run_native(image, inspect_pe(image, "reg.exe"), persona,
                                            root / "version", [], 10, 100_000,
                                            guest_args=["query",
                                                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"])
                self.assertFalse(version_result["errors"])
                version = version_result["console_output"]["stdout"]
                self.assertIn("CurrentBuild    REG_SZ    26100", version)
                self.assertIn("RegisteredOwner    REG_SZ    Morgan", version)
                custom.write_text(json.dumps({"registry_keys": [{
                    "path": r"HKEY_CURRENT_USER\Software\GuestProbe",
                    "values": [{"name": "Answer", "type": "REG_SZ", "data": "persona-only"},
                               {"name": "", "type": "REG_SZ", "data": "default-value"}]
                }, {"path": r"HKEY_CURRENT_USER\Software\GuestProbe\Child",
                    "values": [{"name": "ChildValue", "type": "REG_SZ", "data": "child-only"}]},
                   {"path": r"HKEY_CURRENT_USER\Software\GuestProbe\Child\Leaf",
                    "values": [{"name": "LeafValue", "type": "REG_SZ", "data": "leaf-only"}]}]}),
                                  encoding="utf-8")
                custom_persona = load_persona(custom)
                custom_result = run_native(image, inspect_pe(image, "reg.exe"),
                                           custom_persona, root / "custom", [],
                                           10, 100_000,
                                           guest_args=["query", r"HKCU\Software\GuestProbe"])
                self.assertFalse(custom_result["errors"])
                self.assertEqual(custom_result["guest_exit_code"], 0)
                self.assertIn("Answer    REG_SZ    persona-only",
                              custom_result["console_output"]["stdout"])
                default_result = run_native(image, inspect_pe(image, "reg.exe"),
                                            custom_persona, root / "default", [],
                                            10, 100_000,
                                            guest_args=["query", r"HKCU\Software\GuestProbe", "/ve"])
                self.assertFalse(default_result["errors"])
                self.assertEqual(default_result["guest_exit_code"], 0)
                self.assertIn("(Default)    REG_SZ    default-value",
                              default_result["console_output"]["stdout"])
                recursive = run_native(image, inspect_pe(image, "reg.exe"),
                                       custom_persona, root / "recursive", [],
                                       10, 100_000,
                                       guest_args=["query", r"HKCU\Software\GuestProbe", "/s"])
                self.assertFalse(recursive["errors"])
                self.assertEqual(recursive["guest_exit_code"], 0)
                self.assertIn("ChildValue    REG_SZ    child-only",
                              recursive["console_output"]["stdout"])
                self.assertIn("LeafValue    REG_SZ    leaf-only",
                              recursive["console_output"]["stdout"])
                self.assertNotIn("LeafValue", custom_result["console_output"]["stdout"])

    def test_reg_recursive_query_stops_at_guest_depth_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            custom = root / "persona.json"
            base = r"HKEY_CURRENT_USER\Software\DepthProbe"
            keys = [{"path": base + "\\X" * depth, "values": []}
                    for depth in range(27)]
            custom.write_text(json.dumps({"registry_keys": keys}), encoding="utf-8")
            persona = load_persona(custom)
            image = enumeration_programs(True, persona)["reg.exe"]
            result = run_native(image, inspect_pe(image, "reg.exe"), persona,
                                root / "run", [], 10, 200_000,
                                guest_args=["query", r"HKCU\Software\DepthProbe", "/s"])
            self.assertFalse(result["errors"])
            self.assertEqual(result["guest_exit_code"], 234)

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
