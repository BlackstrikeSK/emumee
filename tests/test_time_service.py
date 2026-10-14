"""Windows Time utility, service inventory, and registry share guest state."""

import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import socket

from emumee.enumeration_programs import enumeration_programs, enumeration_text
from emumee.native import run_native
from emumee.pe import inspect_pe
from emumee.persona import load_persona
from tests.fixtures.build_native import build_host_winexec_probe


def time_persona():
    return {"user_is_admin": True, "clock_utc": "2026-10-14T12:00:00Z", "utc_offset_minutes": 120,
            "time_service": {"type": "NTP", "source": "clock.corp.example", "reference_ipv4": "192.168.1.5",
                "stratum": 2, "last_sync_utc": "2026-10-14T10:00:00Z", "poll_interval": 10,
                "root_delay_ms": 12, "root_dispersion_ms": 250,
                "peers": [{"name": "clock.corp.example", "state": "Active", "stratum": 1,
                           "poll_interval": 6, "mode": 3}]},
            "dns_records": [{"name": "clock.corp.example", "type": "A", "data": "192.168.1.5", "ttl": 60}]}


class TimeServiceTests(unittest.TestCase):
    def test_time_metadata_rejects_inconsistent_sources_peers_and_dates(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "persona.json"
            config = time_persona()
            path.write_text(json.dumps(config))
            self.assertEqual(load_persona(path)["time_service"]["source"], "clock.corp.example")
            invalid = ([], {"unknown": True}, {"poll_interval": True}, {"poll_interval": 18},
                       {"precision": -31}, {"root_delay_ms": -1}, {"type": "NT5DS"},
                       {"source": "other.example"}, {"reference_ipv4": "192.168.1.6"},
                       {"reference_ipv4": "192.168.1.107"}, {"source": "bad\nsource"},
                       {"stratum": 0}, {"last_sync_utc": None},
                       {"last_sync_utc": "2026-10-15T10:00:00Z"}, {"last_sync_utc": "not-a-time"},
                       {"peers": config["time_service"]["peers"] * 2},
                       {"peers": [{**config["time_service"]["peers"][0], "mode": 2}]},
                       {"peers": [{**config["time_service"]["peers"][0], "stratum": 3}]})
            for override in invalid:
                current = copy.deepcopy(config)
                current["time_service"] = ({**current["time_service"], **override}
                                           if isinstance(override, dict) else override)
                path.write_text(json.dumps(current))
                with self.subTest(override=override), self.assertRaisesRegex(ValueError, "time_service"):
                    load_persona(path)

    def test_w32tm_child_time_views_and_registry_agree_without_network(self):
        for machine, arch in ((0x14c, "x86"), (0x8664, "x64")):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                path = root / "persona.json"
                path.write_text(json.dumps(time_persona()))
                persona = load_persona(path)
                parent = bytearray(build_host_winexec_probe(machine, "unused-marker"))
                parent[0x700:0x900] = b"\0" * 0x200
                command = b"w32tm.exe /query /status /verbose\0"
                parent[0x700:0x700 + len(command)] = command
                with patch.object(socket, "getaddrinfo", side_effect=AssertionError("host DNS used")), \
                     patch.object(socket, "socket", side_effect=AssertionError("host socket used")):
                    result = run_native(bytes(parent), inspect_pe(bytes(parent), "parent.exe"), persona,
                                        root / "child", [], 10, 100_000)
                self.assertFalse(result["errors"])
                text = result["console_output"]["stdout"]
                for expected in ("Source: clock.corp.example", "ReferenceId: 0xC0A80105", "Stratum: 2",
                                 "10/14/2026 12:00:00", "7200s", "Poll Interval: 10 (1024s)",
                                 "Root Delay: 0.0120000s", "Root Dispersion: 0.2500000s"):
                    self.assertIn(expected, text)
                report = json.loads((root / "child" / result["engine_report"]).read_text())
                self.assertEqual(report["network_events"], [])
                self.assertTrue(any(e["event"] == "virtual_process_create" and e["success"] and
                                    e["path"].casefold().endswith("\\w32tm.exe") for e in report["virtual_process_events"]))
                images = enumeration_programs(arch == "x64", persona)
                image = images["w32tm.exe"]
                for index, args in enumerate((["/query", "/source"], ["/query", "/configuration"],
                                              ["/query", "/peers"], ["/query", "/status"])):
                    result = run_native(image, inspect_pe(image, "w32tm.exe"), persona,
                                        root / f"read-{index}", [], 10, 100_000, guest_args=args)
                    self.assertFalse(result["errors"])
                    self.assertEqual(result["guest_exit_code"], 0)
                    self.assertEqual(result["console_output"]["stdout"],
                                     enumeration_text("w32tm.exe", persona, " ".join(args)))
                for index, (suffix, name, expected) in enumerate((
                    ("Parameters", "NtpServer", "clock.corp.example,0x9"),
                    ("Parameters", "Type", "NTP"),
                    (r"TimeProviders\NtpClient", "SpecialPollInterval", "1024"))):
                    args = ["query", r"HKLM\SYSTEM\CurrentControlSet\Services\W32Time" + "\\" + suffix, "/v", name]
                    result = run_native(images["reg.exe"], inspect_pe(images["reg.exe"], "reg.exe"), persona,
                                        root / f"reg-{index}", [], 10, 100_000, guest_args=args)
                    self.assertFalse(result["errors"])
                    self.assertIn(expected, result["console_output"]["stdout"])
                self.assertIn("W32Time", enumeration_text("tasklist.exe", persona, "/svc"))
                self.assertIn("RUNNING", enumeration_text("sc.exe", persona, "query W32Time"))
                for index, args in enumerate((["/resync"], ["/register"], ["/unregister"],
                    ["/config", "/update"], ["/query", "/computer:host.example", "/status"],
                    ["/stripchart", "/computer:host.example"])):
                    result = run_native(image, inspect_pe(image, "w32tm.exe"), persona,
                                        root / f"unsupported-{index}", [], 10, 100_000, guest_args=args)
                    self.assertFalse(result["errors"])
                    self.assertEqual(result["guest_exit_code"], 87)
                    self.assertEqual(result["console_output"]["stdout"], "")

    def test_time_service_absent_disabled_nonadmin_and_unsynchronized_views(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                for mode, expected in (("nonadmin", 0x80070005), ("missing", 0x80070424),
                                       ("disabled", 0x80070426), ("no-process", 0x80070426), ("unsynced", 0)):
                    persona = load_persona(None)
                    persona["user_is_admin"] = mode != "nonadmin"
                    if mode == "missing":
                        persona["services"] = [s for s in persona["services"] if s["name"] != "W32Time"]
                    if mode == "disabled":
                        next(s for s in persona["services"] if s["name"] == "W32Time")["start"] = 4
                    if mode == "no-process":
                        persona["processes"] = [p for p in persona["processes"] if p.casefold() != "svchost.exe"]
                    image = enumeration_programs(arch == "x64", persona)["w32tm.exe"]
                    result = run_native(image, inspect_pe(image, "w32tm.exe"), persona,
                                        root / mode, [], 10, 100_000, guest_args=["/query", "/status"])
                    self.assertFalse(result["errors"])
                    self.assertEqual(result["guest_exit_code"] & 0xffffffff, expected)
                    text = result["console_output"]["stdout"]
                    if expected:
                        self.assertIn(f"0x{expected:08X}", text)
                        self.assertNotIn("ReferenceId:", text)
                    else:
                        self.assertIn("3(not synchronized)", text)
                        self.assertIn("Last Successful Sync Time: unspecified", text)
