"""Guest ICMP layouts, ownership, timing, and native ping confinement."""

import hashlib
import ipaddress
import json
import socket
import struct
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from emumee.clock import VirtualClock
from emumee.enumeration_programs import enumeration_programs
from emumee.icmp import GuestICMP
from emumee.native import run_native
from emumee.pe import inspect_pe
from emumee.persona import load_persona
from tests.fixtures.build_native import build_host_winexec_probe


class _Memory:
    def __init__(self, width):
        self.width = width
        self.base = 0x10000 if width == 4 else 0x100000000
        self.memory = bytearray(0x10000)
        self.mapping = SimpleNamespace(base=self.base, size=len(self.memory), prot=6, free=False)
        self.process = object()
        self.error = 0
    def get_current_process(self): return self.process
    def get_ptr_size(self): return self.width
    def set_last_error(self, value): self.error = value
    def get_address_map(self, address):
        return self.mapping if self.base <= address < self.base + len(self.memory) else None
    def mem_read(self, address, size): return bytes(self.memory[address - self.base:address - self.base + size])
    def mem_write(self, address, data):
        assert isinstance(data, bytes)
        self.memory[address - self.base:address - self.base + len(data)] = data


def address_value(text):
    return int.from_bytes(ipaddress.IPv4Address(text).packed, "little")


class ICMPTests(unittest.TestCase):
    def test_handle_budget_is_released_on_owner_exit(self):
        for width in (4, 8):
            emu = _Memory(width)
            api = GuestICMP(load_persona(None))
            handles = [api._create(emu, "", None, []) for _ in range(128)]
            self.assertEqual(len(set(handles)), 128)
            self.assertEqual(api._create(emu, "", None, []), (1 << (width * 8)) - 1)
            self.assertEqual(emu.error, 8)
            api.cleanup_process(emu, emu.process)
            self.assertFalse(api.handles)
            self.assertNotIn(api._create(emu, "", None, []), handles)

    def test_fixture_validation_rejects_reserved_duplicate_and_malformed_replies(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "persona.json"
            entry = {"address": "203.0.113.5", "round_trip_ms": 12, "ttl": 57}
            for records in (None, [entry] * 65, [entry, entry],
                [{**entry, "address": "localhost"}], [{**entry, "address": "::1"}],
                [{**entry, "address": "0.0.0.0"}], [{**entry, "address": "127.0.0.1"}],
                [{**entry, "address": "192.168.1.107"}], [{**entry, "address": "224.0.0.1"}],
                [{**entry, "address": "192.168.1.255"}], [{**entry, "address": "255.255.255.255"}],
                [{**entry, "round_trip_ms": True}], [{**entry, "round_trip_ms": 60001}],
                [{**entry, "ttl": 0}], [{**entry, "ttl": 256}]):
                path.write_text(json.dumps({"icmp_responses": records}))
                with self.subTest(records=records), self.assertRaisesRegex(ValueError, "icmp_responses"):
                    load_persona(path)
            path.write_text(json.dumps({"icmp_responses": [entry]}))
            self.assertEqual(load_persona(path)["icmp_responses"], [entry])

    def test_echo_layout_payload_ttl_and_virtual_time_at_both_pointer_widths(self):
        for width in (4, 8):
            with self.subTest(width=width):
                emu = _Memory(width)
                persona = load_persona(None)
                persona["icmp_responses"] = [{"address": "203.0.113.5", "round_trip_ms": 12, "ttl": 57}]
                clock = VirtualClock(persona)
                api = GuestICMP(persona, clock)
                handle = api._create(emu, "", None, [])
                request, output = emu.base + 0x100, emu.base + 0x2000
                data = b"\0\xffpayload\0"
                emu.mem_write(request, data)
                before = clock.uptime_ms
                with patch.object(socket, "socket", side_effect=AssertionError("host socket used")):
                    self.assertEqual(api._echo(emu, "iphlpapi.IcmpSendEcho", None,
                        [handle, address_value("203.0.113.5"), request, len(data), 0, output, 128, 100]), 1)
                header = 28 if width == 4 else 40
                reply = emu.mem_read(output, header + len(data))
                self.assertEqual(reply[:4], ipaddress.IPv4Address("203.0.113.5").packed)
                self.assertEqual(struct.unpack_from("<IIHH", reply, 4), (0, 12, len(data), 0))
                self.assertEqual(int.from_bytes(reply[16:16 + width], "little"), output + header)
                self.assertEqual(reply[16 + width], 57)
                self.assertEqual(reply[header:], data)
                self.assertEqual(clock.uptime_ms, before + 12)
                self.assertEqual(api.events[-1]["data_sha256"], hashlib.sha256(data).hexdigest())
                self.assertFalse(api.events[-1]["network_used"])
                before = clock.uptime_ms
                self.assertEqual(api._echo(emu, "icmp.IcmpSendEcho", None,
                    [handle, address_value("203.0.113.5"), request, len(data), 0, output, 128, 5]), 0)
                self.assertEqual(emu.error, 11010)
                self.assertEqual(clock.uptime_ms, before + 5)
                self.assertEqual(api._echo(emu, "icmp.IcmpSendEcho", None,
                    [handle, address_value(persona["network_adapter"]["ipv4"]), 0, 0, 0, output, 128, 0]), 1)
                self.assertEqual(emu.mem_read(output + 16, width), b"\0" * width)

    def test_invalid_memory_options_foreign_handles_and_exit_cleanup(self):
        for width in (4, 8):
            emu = _Memory(width)
            api = GuestICMP(load_persona(None))
            handle = api._create(emu, "", None, [])
            owner = emu.process
            request, output = emu.base + 0x100, emu.base + 0x2000
            base = [handle, address_value("127.0.0.1"), request, 4, 0, output, 128, 100]
            emu.mem_write(request, b"test")
            emu.mem_write(output, b"\xa5" * 128)
            for index, value, error in ((0, 123, 87), (2, 0, 87), (3, 4097, 87),
                                       (5, 0, 87), (6, 1, 87), (6, 28 if width == 4 else 40, 122)):
                args = list(base)
                args[index] = value
                self.assertEqual(api._echo(emu, "", None, args), 0)
                self.assertEqual(emu.error, error)
            api.write_guard = lambda *args: False
            self.assertEqual(api._echo(emu, "", None, base), 0)
            api.write_guard = None
            api.read_guard = lambda *args: False
            self.assertEqual(api._echo(emu, "", None, base), 0)
            api.read_guard = None
            options = emu.base + 0x500
            emu.mem_write(options, bytes((64, 1, 0, 0)))
            self.assertEqual(api._echo(emu, "", None, [*base[:4], options, *base[5:]]), 0)
            self.assertEqual(emu.error, 50)
            for destination in ("192.168.1.255", "255.255.255.255", "224.0.0.1", "0.0.0.0"):
                args = list(base)
                args[1] = address_value(destination)
                self.assertEqual(api._echo(emu, "", None, args), 0)
                self.assertEqual(emu.error, 50)
            self.assertEqual(emu.mem_read(output, 128), b"\xa5" * 128)
            emu.process = object()
            self.assertEqual(api._echo(emu, "", None, base), 0)
            self.assertEqual(api._close(emu, "", None, [handle]), 0)
            self.assertIn((id(owner), handle), api.handles)
            api.cleanup_process(emu, owner)
            self.assertFalse(api.handles)

    def test_native_ping_children_dns_options_timeout_and_no_host_network(self):
        for machine, arch in ((0x14c, "x86"), (0x8664, "x64")):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                path = root / "persona.json"
                path.write_text(json.dumps({"icmp_responses": [{"address": "203.0.113.5", "round_trip_ms": 12, "ttl": 57}],
                    "dns_records": [{"name": "peer.example", "type": "A", "data": "203.0.113.5", "ttl": 60}]}))
                persona = load_persona(path)
                parent = bytearray(build_host_winexec_probe(machine, "unused-marker"))
                parent[0x700:0x900] = b"\0" * 0x200
                command = b"ping.exe -n 2 -l 96 peer.example\0"
                parent[0x700:0x700 + len(command)] = command
                with patch.object(socket, "socket", side_effect=AssertionError("host socket used")), \
                     patch.object(socket, "getaddrinfo", side_effect=AssertionError("host DNS used")):
                    result = run_native(bytes(parent), inspect_pe(bytes(parent), "parent.exe"), persona,
                                        root / "child", [], 10, 300_000)
                self.assertFalse(result["errors"])
                text = result["console_output"]["stdout"]
                for value in ("peer.example [203.0.113.5]", "bytes=96 time=12ms TTL=57", "Received = 2", "0% loss"):
                    self.assertIn(value, text)
                report = json.loads((root / "child" / result["engine_report"]).read_text())
                echoes = [e for e in report["network_events"] if e["event"] == "guest_icmp_echo"]
                self.assertEqual(len(echoes), 2)
                self.assertTrue(all(e["status"] == 0 and e["network_used"] is False for e in echoes))
                self.assertTrue(all(e["network_used"] is False for e in report["network_events"]))
                self.assertTrue(any(e["event"] == "virtual_process_create" and e["success"] and
                    e["path"].casefold().endswith("\\ping.exe") for e in report["virtual_process_events"]))
                image = enumeration_programs(arch == "x64", persona)["ping.exe"]
                cases = ((["localhost", "-n", "1"], 0, "127.0.0.1"),
                         ([persona["hostname"], "/n", "1", "/4"], 0, persona["network_adapter"]["ipv4"]),
                         (["203.0.113.8", "-n", "1", "-w", "5"], 1, "Request timed out."),
                         (["203.0.113.5", "-n", "1", "-w", "5"], 1, "Request timed out."),
                         (["missing.invalid", "-n", "1"], 1, "could not find host"),
                         (["127.0.0.1", "-n", "1", "-l", "0"], 0, "bytes=0"),
                         (["127.0.0.1", "-t"], 87, ""), (["127.0.0.1", "-n", "17"], 87, ""),
                         (["127.0.0.1", "-l", "4097"], 87, ""), (["127.0.0.1", "-6"], 87, ""),
                         (["127.0.0.1", "-n", "1", "-n", "1"], 87, ""))
                for index, (args, status, expected) in enumerate(cases):
                    with patch.object(socket, "socket", side_effect=AssertionError("host socket used")), \
                         patch.object(socket, "getaddrinfo", side_effect=AssertionError("host DNS used")):
                        result = run_native(image, inspect_pe(image, "ping.exe"), persona,
                                            root / f"query-{index}", [], 10, 300_000, guest_args=args)
                    self.assertFalse(result["errors"])
                    self.assertEqual(result["guest_exit_code"], status)
                    if expected:
                        self.assertIn(expected, result["console_output"]["stdout"])
                    else:
                        self.assertEqual(result["console_output"]["stdout"], "")
