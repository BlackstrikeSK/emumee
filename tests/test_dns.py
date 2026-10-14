"""DNS fixtures, guest record layouts, no-wire queries, and utility execution."""

import ipaddress
import json
import socket
import struct
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from emumee.dns import GuestDNS
from emumee.dns_records import record_catalog
from emumee.enumeration_programs import enumeration_programs
from emumee.native import run_native
from emumee.network import NetworkBridge
from emumee.artifacts import ArtifactCatalog
from emumee.pe import inspect_pe
from emumee.persona import load_persona
from tests.fixtures.build_native import build_host_winexec_probe


class _Memory:
    def __init__(self, width):
        self.width = width
        self.memory = bytearray(0x200000)
        self.process = object()
        self.maps = [SimpleNamespace(base=0x100, size=0xff00, prot=6, free=False)]
        self.next = 0x10000
        self.freed = []
    def get_current_process(self): return self.process
    def get_ptr_size(self): return self.width
    def get_address_map(self, address):
        return next((m for m in reversed(self.maps) if m.base <= address < m.base + m.size), None)
    def mem_read(self, address, size): return bytes(self.memory[address:address + size])
    def mem_write(self, address, data): self.memory[address:address + len(data)] = data
    def mem_map(self, size, **kwargs):
        assert size % 4096 == 0 and kwargs["process"] is self.process
        result = self.next
        self.next += size
        self.maps.append(SimpleNamespace(base=result, size=size, prot=6, free=False))
        return result
    def mem_free(self, pointer):
        self.get_address_map(pointer).free = True
        self.freed.append(pointer)
    def pointer(self, at=0x500): return int.from_bytes(self.mem_read(at, self.width), "little")


class DNSTests(unittest.TestCase):
    def test_fixture_validation_rejects_malformed_data_and_identity_conflicts(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "persona.json"
            record = {"name": "fixture.example", "type": "A", "data": "203.0.113.42", "ttl": 60}
            for records in (None, [record] * 65, [record, record],
                [{**record, "name": "bad..example"}], [{**record, "name": "bad.example.."}],
                [{**record, "data": 1234}], [{**record, "data": "::1"}],
                [{**record, "type": "AAAA"}], [{**record, "type": "MX"}],
                [{**record, "ttl": True}], [{**record, "ttl": -1}],
                [{**record, "name": load_persona(None)["hostname"]}]):
                path.write_text(json.dumps({"dns_records": records}))
                with self.subTest(records=records), self.assertRaisesRegex(ValueError, "dns_records"):
                    load_persona(path)
            path.write_text(json.dumps({"dns_records": [record]}))
            persona = load_persona(path)
            self.assertIn(record, record_catalog(persona))

    def test_dns_record_layout_links_charset_data_and_ttl_for_all_entry_points(self):
        for width in (4, 8):
            for suffix, charset, encoding in (("A", 3, "ascii"), ("UTF8", 2, "ascii"), ("W", 1, "utf-16le")):
                with self.subTest(width=width, suffix=suffix):
                    emu = _Memory(width)
                    persona = load_persona(None)
                    persona["dns_records"] = [
                        {"name": "fixture.example", "type": "A", "data": "203.0.113.42", "ttl": 123},
                        {"name": "fixture.example", "type": "A", "data": "203.0.113.43", "ttl": 456}]
                    api = GuestDNS(persona)
                    emu.mem_write(0x100, ("FIXTURE.EXAMPLE.\0").encode(encoding))
                    with patch.object(socket, "getaddrinfo", side_effect=AssertionError("host DNS used")):
                        self.assertEqual(api._query(emu, "dnsapi.DnsQuery_" + suffix, None,
                                                   [0x100, 1, 0x10, 0, 0x500, 0]), 0)
                    first = emu.pointer()
                    header = 24 if width == 4 else 32
                    for index, ttl in ((0, 123), (1, 456)):
                        offset = first + index * (header + 16)
                        link = emu.pointer(offset)
                        self.assertEqual(link, first + header + 16 if not index else 0)
                        self.assertEqual(struct.unpack("<HHIII", emu.mem_read(offset + width * 2, 16)),
                                         (1, 4, 1 | charset << 3, ttl, 0))
                        self.assertEqual(emu.mem_read(offset + header, 4), bytes((203, 0, 113, 42 + index)))
                    self.assertFalse(api.events[-1]["network_used"])
                    self.assertEqual(api.events[-1]["answers"], ["203.0.113.42", "203.0.113.43"])

    def test_unknown_types_servers_flags_and_invalid_memory_never_fall_back(self):
        emu = _Memory(8)
        api = GuestDNS(load_persona(None))
        emu.mem_write(0x100, b"absent.invalid\0")
        with patch.object(socket, "getaddrinfo", side_effect=AssertionError("host DNS used")), \
             patch.object(socket, "socket", side_effect=AssertionError("host socket used")):
            for params, status in (([0x100, 1, 0, 0, 0x500, 0], 9003),
                ([0x100, 15, 0, 0, 0x500, 0], 50), ([0x100, 1, 0x100, 0, 0x500, 0], 50),
                ([0x100, 1, 0, 0x700, 0x500, 0], 50), ([0, 1, 0, 0, 0x500, 0], 87),
                ([0x100, 1, 0, 0, 0, 0], 87), ([0x100, 1, 0, 0, 0x500, 1], 87)):
                self.assertEqual(api._query(emu, "dnsapi.DnsQuery_A", None, params), status)
        self.assertEqual(emu.next, 0x10000)
        self.assertFalse(api.buffers)
        emu.mem_write(0x100, (api.persona["hostname"] + "\0").encode("ascii"))
        api.write_guard = lambda *args: False
        self.assertEqual(api._query(emu, "dnsapi.DnsQuery_A", None, [0x100, 1, 0, 0, 0x500, 0]), 87)
        api.write_guard = None
        self.assertEqual(api._query(emu, "dnsapi.DnsQuery_A", None, [0x100, 28, 0, 0, 0x500, 0]), 9501)

    def test_free_and_cleanup_preserve_foreign_or_replaced_mappings(self):
        emu = _Memory(8)
        api = GuestDNS(load_persona(None))
        emu.mem_write(0x100, (api.persona["hostname"] + "\0").encode("ascii"))
        api._query(emu, "dnsapi.DnsQuery_A", None, [0x100, 1, 0, 0, 0x500, 0])
        pointer, owner = emu.pointer(), emu.process
        emu.process = object()
        api._free(emu, "dnsapi.DnsFree", None, [pointer, 1])
        self.assertFalse(emu.freed)
        emu.process = owner
        api._free(emu, "dnsapi.DnsRecordListFree", None, [pointer, 99])
        self.assertFalse(emu.freed)
        api._free(emu, "dnsapi.DnsRecordListFree", None, [pointer, 1])
        self.assertEqual(emu.freed, [pointer])
        api._query(emu, "dnsapi.DnsQuery_A", None, [0x100, 1, 0, 0, 0x500, 0])
        pointer = emu.pointer()
        emu.get_address_map(pointer).free = True
        emu.maps.append(SimpleNamespace(base=pointer, size=4096, prot=6, free=False))
        api.cleanup_process(emu, owner)
        self.assertFalse(emu.get_address_map(pointer).free)
        self.assertFalse(api.buffers)
        self.assertIsNone(api._free(emu, "dnsapi.DnsFree", None, [0, 0]))

    def test_response_size_budget_and_legacy_resolver_persona_precedence(self):
        emu = _Memory(8)
        persona = load_persona(None)
        persona["dns_records"] = [{"name": "many.example", "type": "AAAA",
                                   "data": f"2001:db8::{i + 1:x}", "ttl": 60} for i in range(64)]
        api = GuestDNS(persona)
        emu.mem_write(0x100, "many.example\0".encode("utf-16le"))
        for _ in range(64):
            self.assertEqual(api._query(emu, "dnsapi.DnsQuery_W", None, [0x100, 28, 0, 0, 0x500, 0]), 0)
        self.assertGreater(emu.next, 0x10000 + 64 * 4096)
        self.assertEqual(api._query(emu, "dnsapi.DnsQuery_W", None, [0x100, 28, 0, 0, 0x500, 0]), 8)
        api.cleanup_process(emu, emu.process)
        self.assertEqual(len(emu.freed), 64)
        self.assertFalse(api.buffers)
        with tempfile.TemporaryDirectory() as directory:
            bridge = NetworkBridge(ArtifactCatalog(Path(directory)))
            bridge.guest_dns = api
            bridge.rpc = SimpleNamespace(call=lambda *a, **kw: self.fail("known name reached network broker"))
            dns = SimpleNamespace(names={})
            legacy = SimpleNamespace(read_mem_string=lambda *a: persona["hostname"],
                                     get_network_manager=lambda: SimpleNamespace(dns=dns))
            def original(_params):
                self.assertEqual(dns.names[persona["hostname"].lower()], persona["network_adapter"]["ipv4"])
                self.assertEqual(dns.names[persona["hostname"]], persona["network_adapter"]["ipv4"])
                return 1234
            self.assertEqual(bridge._gethostbyname(legacy, "ws2_32.gethostbyname", original, [0x100]), 1234)
            self.assertFalse(bridge.events[-1]["network_used"])
            legacy.read_mem_string = lambda *a: "many.example"
            self.assertEqual(bridge._gethostbyname(legacy, "ws2_32.gethostbyname", original, [0x100]), 0)
            self.assertEqual(bridge.events[-1]["status"], 9501)

    def test_nslookup_child_queries_persona_and_never_opens_host_network(self):
        for machine, arch in ((0x14c, "x86"), (0x8664, "x64")):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                config = root / "persona.json"
                config.write_text(json.dumps({"hostname": "DNS-GUEST", "domain": "corp.example",
                    "network_adapter": {"ipv4": "192.168.1.111", "dns_servers": ["192.168.1.5"]},
                    "dns_records": [{"name": "fixture.example", "type": "AAAA", "data": "2001:db8::42", "ttl": 60}]}))
                persona = load_persona(config)
                parent = bytearray(build_host_winexec_probe(machine, "unused-marker"))
                parent[0x700:0x900] = b"\0" * 0x200
                command = b"nslookup.exe DNS-GUEST.corp.example\0"
                parent[0x700:0x700 + len(command)] = command
                with patch.object(socket, "getaddrinfo", side_effect=AssertionError("host DNS used")), \
                     patch.object(socket, "socket", side_effect=AssertionError("host socket used")):
                    result = run_native(bytes(parent), inspect_pe(bytes(parent), "parent.exe"), persona,
                                        root / "child", [], 10, 200_000)
                self.assertFalse(result["errors"])
                self.assertIn("192.168.1.111", result["console_output"]["stdout"])
                self.assertIn("192.168.1.5", result["console_output"]["stdout"])
                report = json.loads((root / "child" / result["engine_report"]).read_text())
                self.assertEqual(len(report["network_events"]), 1)
                self.assertEqual(report["network_events"][0]["answers"], ["192.168.1.111"])
                self.assertFalse(report["network_events"][0]["network_used"])
                self.assertTrue(any(event["event"] == "virtual_process_create" and event["success"] and
                                    event["path"].casefold().endswith("\\nslookup.exe")
                                    for event in report["virtual_process_events"]))
                image = enumeration_programs(arch == "x64", persona)["nslookup.exe"]
                queries = ((["-type=AAAA", "fixture.example"], 0, "2001:db8::42"),
                           (["192.168.1.111"], 0, "dns-guest.corp.example"),
                           (["absent.invalid"], 1, "Nonexistent domain"),
                           (["dns-guest", "192.168.1.5"], 0, "192.168.1.111"),
                           (["dns-guest", "8.8.8.8"], 87, ""),
                           (["-type=MX", "corp.example"], 87, ""), ([], 87, ""))
                for index, (args, status, expected) in enumerate(queries):
                    with patch.object(socket, "getaddrinfo", side_effect=AssertionError("host DNS used")), \
                         patch.object(socket, "socket", side_effect=AssertionError("host socket used")):
                        result = run_native(image, inspect_pe(image, "nslookup.exe"), persona,
                                            root / f"query-{index}", [], 10, 200_000, guest_args=args)
                    self.assertFalse(result["errors"])
                    self.assertEqual(result["guest_exit_code"], status)
                    if expected:
                        self.assertIn(expected, result["console_output"]["stdout"])
                    else:
                        self.assertEqual(result["console_output"]["stdout"], "")
