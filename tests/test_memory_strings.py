"""Memory indicators are bounded, attributable, and visible in PE reports."""

import contextlib
import io
import json
import shutil
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from emumee.cli import main
from emumee.dashboard import create_app
from emumee.memory_strings import (MAX_MATCHES, WINDOW_CHARS, MemoryStringCapture,
                                   valid_capture, validate_options)
from emumee.native import run_native
from emumee.managed import run_managed
from emumee.driver import run_driver
from emumee.pe import inspect_pe
from emumee.persona import load_persona
from emumee.reports import valid_summary
from tests.fixtures.build_native import build
from tests.fixtures.build_driver import build_driver


class MemoryStringTests(unittest.TestCase):
    def test_short_ipv6_strings_are_captured_in_isolation(self):
        capture = MemoryStringCapture()
        capture.scan_memory(b"\0::1\0::\0", "heap", 0x1000)
        self.assertEqual({item["value"] for item in capture.matches}, {"::1", "::"})

    def test_formats_offsets_and_invalid_addresses(self):
        capture = MemoryStringCapture({"regex": [r"KEY-([A-Z]{4})"]})
        text = b"IP=203.0.113.7 ::1 2001:db8::42 999.1.2.3 01.2.3.4 https://example.test/a?q=1 KEY-ABCD"
        capture.scan_memory(b"\0" + text + b"\0", "heap", 0x1000)
        matches = capture.report()["matches"]
        values = {item["value"] for item in matches}
        self.assertTrue({"203.0.113.7", "::1", "2001:db8::42", "https://example.test/a?q=1", "KEY-ABCD"} <= values)
        self.assertFalse({"999.1.2.3", "01.2.3.4", "1.2.3.4"} & values)
        item = next(item for item in matches if item["format"] == "custom_1")
        self.assertEqual(item["value"], "KEY-ABCD")  # Whole match, not the capture group.
        self.assertEqual(item["offset"], 1 + text.index(b"KEY-ABCD"))
        self.assertEqual(item["address"], hex(0x1000 + item["offset"]))
        self.assertTrue(valid_capture(capture.report()))

    def test_wide_odd_alignment_and_duplicate_scans(self):
        capture = MemoryStringCapture()
        blob = b"\xff" + "https://wide.test/path 192.0.2.9".encode("utf-16le") + b"\0\0"
        for _ in range(2):
            capture.scan_memory(blob, "wide_heap", 0x2000)
        matches = capture.report()["matches"]
        self.assertEqual(len(matches), 2)
        url = next(item for item in matches if item["format"] == "url")
        self.assertEqual(url["encoding"], "utf-16le")
        self.assertEqual(url["address"], "0x2001")

    def test_window_crossing_keeps_full_matches_and_exact_offsets(self):
        for wide in (False, True):
            with self.subTest(wide=wide):
                capture = MemoryStringCapture({"regex": [r"TOKEN-[0-9]{8}"]})
                prefix = "x" * (WINDOW_CHARS - 12) + " "
                value = "https://boundary.test/path TOKEN-12345678"
                text = prefix + value + " " + "z" * WINDOW_CHARS
                capture.scan_memory(text.encode("utf-16le" if wide else "ascii"), "long", 0x3000)
                rows = capture.report()["matches"]
                self.assertEqual([r["value"] for r in rows if r["format"] == "url"], [value.split()[0]])
                token = next(r for r in rows if r["format"] == "custom_1")
                self.assertEqual(token["offset"], text.index("TOKEN-") * (2 if wide else 1))

    def test_custom_unicode_and_empty_matches(self):
        capture = MemoryStringCapture({"regex": [r"秘密-[0-9]+", r"(?=.)"]})
        capture.scan_string("prefix 秘密-1234", "managed_return:Decode")
        self.assertEqual(len(capture.matches), 1)
        self.assertEqual(capture.matches[0]["encoding"], "managed")
        self.assertIsNone(capture.matches[0]["address"])
        self.assertEqual(capture.matches[0]["offset"], 7)

    def test_limits_disabled_capture_and_regex_timeout(self):
        capture = MemoryStringCapture({"enabled": False})
        capture.scan_string("http://disabled.test", "managed")
        self.assertEqual(capture.report()["scanned_bytes"], 0)
        capture = MemoryStringCapture()
        capture.scan_string(" ".join(f"192.0.2.{i % 250}" for i in range(MAX_MATCHES + 10)), "managed")
        self.assertEqual(len(capture.matches), MAX_MATCHES)
        self.assertIn("match_limit", capture.report()["limits"])
        with patch("emumee.memory_strings.MAX_MEMORY_SCAN", 16):
            capture = MemoryStringCapture()
            capture.scan_memory(b"a" * 50, "heap", 0)
            self.assertEqual(capture.scanned_bytes, 16)
            self.assertIn("scan_byte_limit", capture.report()["limits"])
        capture = MemoryStringCapture({"regex": [r"(a|aa)+$", r"SAFE-[0-9]+"]})
        capture.scan_string("a" * 5000 + "! SAFE-123", "managed")
        self.assertIn("regex_1_timeout", capture.report()["limits"])
        self.assertTrue(any(item["value"] == "SAFE-123" for item in capture.matches))

    def test_invalid_patterns_and_cli_rejection(self):
        for options in ({"regex": ["["]}, {"regex": [""]}, {"regex": ["x"] * 17},
                        {"enabled": 1}, {"regex": "foo"}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                validate_options(options)
        for command in ("run", "batch"):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                main([command, "unused", "--string-regex", "["])
            self.assertEqual(error.exception.code, 2)

    def test_unicode_output_budget_and_oversized_values_are_explicit(self):
        capture = MemoryStringCapture({"regex": ["😀{100}"]})
        with patch("emumee.memory_strings.MAX_CAPTURE_BYTES", 4096):
            capture.scan_string(" ".join(["😀" * 100] * 10), "managed")
            self.assertIn("match_byte_limit", capture.report()["limits"])
            self.assertTrue(valid_capture(capture.report()))
        capture = MemoryStringCapture()
        capture.scan_string("https://long.test/" + "a" * 1500, "managed")
        self.assertEqual(capture.matches, [])
        self.assertIn("match_length_limit", capture.report()["limits"])
        capture = MemoryStringCapture({"regex": ["TOKEN"]})
        with patch("emumee.memory_strings.REGEX_BUDGET", 0):
            capture.scan_string("https://still.test/ TOKEN", "managed")
        self.assertIn("regex_time_budget", capture.report()["limits"])
        self.assertEqual([item["format"] for item in capture.matches], ["url"])

    def test_dashboard_escaping_and_summary_validation(self):
        capture = MemoryStringCapture({"regex": [r"<script>.*?</script>"]})
        capture.scan_string("<script>alert(1)</script>", "managed")
        summary = {"id": "20261017T000000Z-12345678", "sample": {"name": "test.exe"},
                   "status": "partial", "errors": [], "memory_strings": capture.report()}
        self.assertTrue(valid_summary(summary))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = root / summary["id"]
            run.mkdir()
            (run / "summary.json").write_text(json.dumps(summary), encoding="utf-8")
            response = create_app(root).test_client().get(f'/runs/{summary["id"]}')
            self.assertEqual(response.status_code, 200)
            markup = response.get_data(as_text=True)
            self.assertIn("Memory strings", markup)
            self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", markup)
            self.assertNotIn("<script>alert(1)</script>", markup)
        for update in ({"matches": [{}]}, {"scanned_bytes": -1}, {"regex": ["x"] * 17}):
            self.assertFalse(valid_summary({**summary, "memory_strings": {**capture.report(), **update}}))
        malformed = {**capture.matches[0], "format": []}
        self.assertFalse(valid_capture({**capture.report(), "matches": [malformed]}))


class MemoryStringIntegrationTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("dotnet"), ".NET SDK is unavailable")
    def test_managed_captures_decoded_method_return(self):
        project = Path(__file__).parent / "fixtures" / "ManagedHello"
        subprocess.run(["dotnet", "build", str(project / "ManagedHello.csproj"), "-c", "Release"],
                       check=True, stdout=subprocess.DEVNULL)
        assembly = project / "bin" / "Release" / "net8.0" / "ManagedHello.dll"
        data = assembly.read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = run_managed(data, inspect_pe(data, assembly.name), load_persona(None),
                                 root, 100_000, memory_strings={"regex": [r"managed payload marker"]})
            self.assertEqual(result["errors"], [])
            decoded = [r for r in result["memory_strings"]["matches"]
                       if r["value"] == "managed payload marker"]
            self.assertTrue(any(r["source"].startswith("managed_return:") for r in decoded))
            report = json.loads((root / "engine-report.json").read_text())
            self.assertEqual(report["memory_strings"], result["memory_strings"])

    def test_native_captures_runtime_decoded_strings_on_both_architectures(self):
        value = b"203.0.113.42 https://decoded.test/path TOKEN-12345678\0"
        for machine in (0x14C, 0x8664):
            with self.subTest(machine=machine), tempfile.TemporaryDirectory() as directory:
                x64 = machine == 0x8664
                image = bytearray(build(machine))
                image[0x500:0x500 + len(value)] = bytes(b ^ 0x55 for b in value)
                if x64:
                    code = b"\x48\x8d\x05" + struct.pack("<i", 0x2100 - 0x1007)
                    code += b"\xb9" + struct.pack("<I", len(value))
                    code += b"\x80\x30\x55\x48\xff\xc0\xe2\xf8\x48\x31\xc9"
                    code += b"\xff\x15" + struct.pack("<i", 0x2040 - (0x1000 + len(code) + 6)) + b"\xc3"
                else:
                    code = b"\xb8" + struct.pack("<I", 0x402100)
                    code += b"\xb9" + struct.pack("<I", len(value))
                    code += b"\x80\x30\x55\x40\xe2\xfa\x6a\x00\xff\x15" + struct.pack("<I", 0x402040) + b"\xc3"
                image[0x200:0x200 + len(code)] = code
                self.assertNotIn(value[:-1], image)
                root = Path(directory)
                result = run_native(bytes(image), inspect_pe(bytes(image), "decode.exe"),
                                    load_persona(None), root, [], 5, 1000,
                                    memory_strings={"regex": [r"TOKEN-[0-9]{8}"]})
                self.assertEqual(result["errors"], [])
                rows = result["memory_strings"]["matches"]
                self.assertTrue({"203.0.113.42", "https://decoded.test/path", "TOKEN-12345678"}
                                <= {r["value"] for r in rows})
                token = next(r for r in rows if r["value"] == "TOKEN-12345678")
                base = 0x140002100 if x64 else 0x402100
                self.assertEqual(token["address"], hex(base + value.index(b"TOKEN-")))
                report = json.loads((root / "engine-report.json").read_text())
                self.assertEqual(report["memory_strings"], result["memory_strings"])

    def test_driver_memory_strings_are_in_both_reports(self):
        for machine in (0x14C, 0x8664):
            with self.subTest(machine=machine), tempfile.TemporaryDirectory() as directory:
                image = bytearray(build_driver(machine))
                value = b"https://driver.test/ TOKEN-12345678\0"
                image[0x300:0x300 + len(value)] = value
                root = Path(directory)
                result = run_driver(bytes(image), inspect_pe(bytes(image), "probe.sys"),
                                    load_persona(None), root, 5, 1000,
                                    memory_strings={"regex": [r"TOKEN-[0-9]{8}"]})
                self.assertEqual(result["errors"], [])
                self.assertTrue(any(r["value"] == "TOKEN-12345678" for r in result["memory_strings"]["matches"]))
                report = json.loads((root / "engine-report.json").read_text())
                self.assertEqual(report["memory_strings"], result["memory_strings"])


if __name__ == "__main__":
    unittest.main()
