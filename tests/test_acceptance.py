"""Harmless acceptance fixtures for the emulation boundary and extraction path."""

from __future__ import annotations

import json
import base64
import ctypes
import gc
import gzip
import zlib
import zipfile
import random
import hashlib
from itertools import product
import os
import socket
from io import BytesIO
from http.server import BaseHTTPRequestHandler, HTTPServer
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from pathlib import Path

from emumee.dashboard import create_app
from emumee.cli import _recover_network_report, _worker_stage, _worker_summary
from emumee.job import OutputWatchdog
from emumee.managed import ManagedRunner, ManagedThrown, UnsupportedManaged, run_managed
from emumee.native import (_api_coverage, _has_supported_base_relocations,
                           _report_blob, run_native)
from emumee.network import MAX_TRANSFER, NetworkDenied, public_ipv4
from emumee.artifacts import ArtifactCatalog, MAX_ARTIFACT
from emumee.network import NetworkBridge
from tests.fixtures.build_native import (build_urlmon_download,
                                         build_registry_key_lifecycle,
                                         build_nt_version_consistency_check,
                                         build_open_host_named_mapping_probe,
                                         build_host_process_probe,
                                         build_relocatable_companion,
                                         build_wininet_session_probe,
                                         build_wininet_post_probe,
                                         build_wininet_stream_probe,
                                         build_winhttp_post_probe)
from emumee.networkipc import (BROKER_JOURNAL, FileRPCClient, NetworkBroker,
                               MAX_BROKER_EVENT_BYTES, MAX_HEADER_BYTES,
                               MAX_MESSAGE, MAX_URL, read_broker_journal)
from emumee.pe import InvalidSample, inspect_pe, inspect_pe_header
from emumee.persona import load_persona
from emumee.reports import read_verified_artifact, valid_summary, verify_artifact_manifest
from emumee.virtualfs import SharedGuestFileView, VirtualFileBridge
from emumee.virtualprocess import (VirtualProcessBridge, PROCESS_DUP_HANDLE,
                                   PROCESS_TERMINATE, PROCESS_QUERY_LIMITED_INFORMATION,
                                   PROCESS_QUERY_INFORMATION,
                                   PROCESS_VM_READ, PROCESS_VM_WRITE,
                                   THREAD_TERMINATE, THREAD_QUERY_LIMITED_INFORMATION,
                                   SYNCHRONIZE, WAIT_FAILED, WAIT_TIMEOUT)
from emumee.virtualregistry import VirtualRegistryBridge
from emumee.worker import execute as execute_worker
from dncil.cil.body.reader import read_method_body_from_bytes
from dncil.cil.opcode import OpCodes
from Crypto.Cipher import AES
import pefile
from speakeasy.windows.fileman import File as GuestFile, FileManager
from speakeasy.config import FileEntryFullPath
from speakeasy.errors import SpeakeasyError
from speakeasy.windows.regman import RegKey, RegistryManager
from speakeasy.windows.objman import HandleAllocator


FIXTURES = Path(__file__).parent / "fixtures"


class EmumeeAcceptance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        subprocess.run([shutil.which("python") or "python", str(FIXTURES / "build_native.py")], check=True)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.persona = load_persona(None)

    def tearDown(self):
        self.temp.cleanup()

    def native(self, name: str):
        data = (FIXTURES / name).read_bytes()
        info = inspect_pe(data, name)
        return run_native(data, info, self.persona, self.root, [], 10, 100_000)

    def test_both_native_architectures_reach_exitprocess(self):
        for name in ("native_x86.exe", "native_x64.exe"):
            with self.subTest(name=name):
                header = inspect_pe_header((FIXTURES / name).read_bytes(), name)
                self.assertEqual(header.architecture, "x64" if "x64" in name else "x86")
                with tempfile.TemporaryDirectory() as temp:
                    self.root = Path(temp)
                    result = self.native(name)
                    report = json.loads((self.root / result["engine_report"]).read_text())
                    self.assertFalse(result["errors"])
                    self.assertEqual(report["entry_points"][0]["ret_val"], "0x0")
                    self.assertTrue(any(e.get("api_name", "").endswith("ExitProcess")
                                        for e in report["entry_points"][0]["events"]))

    def test_crt_initializers_execute_in_guest_cpu_on_both_architectures(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as temp:
                self.root = Path(temp)
                result = self.native(f"crt_initializer_{arch}.exe")
                report = json.loads((self.root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                self.assertEqual(report["entry_points"][0]["ret_val"], "0x1")
                self.assertEqual([event["index"] for event in
                                  report["crt_initialization_events"]
                                  if event["event"] == "crt_initializer"], [0])
                self.assertTrue(any(event.get("event") == "crt_initializer_result" and
                                    event.get("result") == 0
                                    for event in report["crt_initialization_events"]))

    def test_crt_wide_argument_arrays_are_guest_owned_on_both_architectures(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as temp:
                self.root = Path(temp)
                result = self.native(f"crt_wide_args_{arch}.exe")
                report = json.loads((self.root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                self.assertEqual(report["entry_points"][0]["ret_val"], "0x1")
                self.assertTrue(any(event.get("event") == "crt_wide_arguments" and
                                    event.get("argc") == 1
                                    for event in report["crt_initialization_events"]))

    def test_crt_narrow_argument_arrays_preserve_cdecl_stack_on_both_architectures(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as temp:
                self.root = Path(temp)
                result = self.native(f"crt_narrow_args_{arch}.exe")
                report = json.loads((self.root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                self.assertEqual(report["entry_points"][0]["ret_val"], "0x1")
                self.assertTrue(any(event.get("event") == "crt_arguments" and
                                    event.get("argc") == 1 and
                                    event.get("environment_count", 0) > 0
                                    for event in report["crt_initialization_events"]))

    def test_guest_environment_blocks_dispatch_on_both_architectures(self):
        for arch in ("x86", "x64"):
            for suffix in ("a", "w"):
                with self.subTest(arch=arch, suffix=suffix), tempfile.TemporaryDirectory() as temp:
                    self.root = Path(temp)
                    result = self.native(f"environment_block_{suffix}_{arch}.exe")
                    report = json.loads((self.root / result["engine_report"]).read_text())
                    self.assertFalse(result["errors"])
                    self.assertEqual(report["entry_points"][0]["ret_val"], "0x1")
                    self.assertTrue(any(event.get("api_name", "").endswith(
                        "GetEnvironmentStrings" + suffix.upper())
                        for event in report["entry_points"][0]["events"]))
                    self.assertTrue(any(event.get("event") == "environment_block_allocated"
                                        and event.get("encoding") == (
                                            "utf-16le" if suffix == "w" else "cp437")
                                        for event in report["environment_block_events"]))

    def test_ucrt_stream_pointer_is_guest_mapped_on_both_architectures(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as temp:
                self.root = Path(temp)
                result = self.native(f"acrt_stream_{arch}.exe")
                report = json.loads((self.root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                self.assertEqual(report["entry_points"][0]["ret_val"], "0x1")
                self.assertTrue(any("__acrt_iob_func" in event.get("api_name", "")
                                    for event in report["entry_points"][0]["events"]))

    def test_crt_error_initializer_stops_before_second_callback(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as temp:
                self.root = Path(temp)
                result = self.native(f"crt_error_initializer_{arch}.exe")
                report = json.loads((self.root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                self.assertEqual(report["entry_points"][0]["ret_val"], "0x7")
                self.assertEqual([event["index"] for event in
                                  report["crt_initialization_events"]
                                  if event["event"] == "crt_initializer"], [0])
                self.assertTrue(any(event.get("event") == "crt_initializer_result" and
                                    event.get("result") == 7
                                    for event in report["crt_initialization_events"]))

    def test_crt_initializer_rejects_unmapped_guest_target(self):
        for arch, fmt, target in (("x86", "<I", 0xFFFFFFFF),
                                  ("x64", "<Q", 0xFFFFFFFFFFFFFFFF)):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as temp:
                image = bytearray((FIXTURES / f"crt_initializer_{arch}.exe").read_bytes())
                struct.pack_into(fmt, image, 0x580, target)
                self.root = Path(temp)
                info = inspect_pe(bytes(image), f"invalid_initializer_{arch}.exe")
                result = run_native(bytes(image), info, self.persona,
                                    self.root, [], 10, 50_000)
                report = json.loads((self.root / result["engine_report"]).read_text())
                self.assertEqual(report["entry_points"][0]["ret_val"], "0x0")
                self.assertFalse(report["entry_points"][0].get("error"))
                self.assertTrue(any("initializer target" in error and
                                    "not executable by guest" in error
                                    for error in result["errors"]))
                self.assertFalse(report["crt_initialization_events"])

    def test_crt_wide_arguments_reject_unmapped_output_pointer(self):
        for arch, fmt, base in (("x86", "<I", 0x400000),
                                ("x64", "<Q", 0x140000000)):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as temp:
                image = bytearray((FIXTURES / f"crt_wide_args_{arch}.exe").read_bytes())
                marker = struct.pack(fmt, base + 0x21A0)
                offset = image.find(marker, 0x200, 0x300)
                self.assertGreaterEqual(offset, 0)
                image[offset:offset + len(marker)] = b"\xff" * len(marker)
                self.root = Path(temp)
                info = inspect_pe(bytes(image), f"invalid_crt_output_{arch}.exe")
                result = run_native(bytes(image), info, self.persona,
                                    self.root, [], 10, 50_000)
                report = json.loads((self.root / result["engine_report"]).read_text())
                self.assertEqual(report["entry_points"][0]["ret_val"], "0x0")
                self.assertIn("msvcrt.__wgetmainargs: output pointer denied",
                              result["errors"])
                self.assertFalse(report["crt_initialization_events"])

    def test_parent_header_check_rejects_truncated_pe(self):
        data = bytearray((FIXTURES / "native_x86.exe").read_bytes())
        data[0x3C:0x40] = (len(data) - 8).to_bytes(4, "little")
        with self.assertRaises(InvalidSample):
            inspect_pe_header(bytes(data), "bad.exe")

    def test_parent_header_parser_handles_bounded_mutations(self):
        original = (FIXTURES / "native_x86.exe").read_bytes()
        rng = random.Random(0xE11E)
        for _ in range(256):
            data = bytearray(original)
            for _ in range(rng.randrange(1, 9)):
                offset = rng.choice(list(range(0x3C, 0x40)) + list(range(0x80, 0x130)))
                data[offset] = rng.randrange(256)
            try:
                info = inspect_pe_header(bytes(data), "mutated.exe")
                self.assertEqual(info.architecture, "x86")
            except InvalidSample:
                pass

    def test_worker_stage_accepts_only_bounded_fixed_markers(self):
        marker = self.root / "worker-stage.txt"
        marker.write_text("collecting native report", encoding="ascii")
        self.assertEqual(_worker_stage(marker), "collecting native report")
        for content in ("collecting native report\n", "unexpected stage",
                        "collecting native report" + "x" * 1024, "\u00e9"):
            with self.subTest(content=content[:30]):
                marker.write_text(content, encoding="utf-8")
                self.assertIsNone(_worker_stage(marker))
        marker.unlink()
        outside = self.root / "outside.txt"
        outside.write_text("collecting native report", encoding="ascii")
        marker.hardlink_to(outside)
        self.assertIsNone(_worker_stage(marker))
        marker.unlink()
        try:
            marker.symlink_to(outside)
        except (OSError, NotImplementedError):
            pass
        else:
            self.assertIsNone(_worker_stage(marker))

    def test_structured_native_fault_has_valid_summary_errors(self):
        from tools.malformed_pe_package_smoke import mutations

        original = (FIXTURES / "native_x86.exe").read_bytes()
        image = next(data for name, data in mutations(original) if name == "section-bytes")
        info = inspect_pe(image, "section-bytes.exe")
        result = run_native(image, info, self.persona, self.root, [], 10, 50_000)
        engine = json.loads((self.root / "engine-report.json").read_text(encoding="utf-8"))
        self.assertIsInstance(engine["entry_points"][0]["error"], dict)
        self.assertTrue(result["errors"])
        self.assertTrue(all(isinstance(error, str) for error in result["errors"]))
        self.assertIn("invalid_read", result["errors"][0])
        self.assertTrue(valid_summary({"id": "20261010T000000Z-deadbeef",
                                       "sample": info.to_dict(), "status": "partial",
                                       "api_coverage": result["api_coverage"],
                                       "errors": result["errors"],
                                       "artifacts": result["artifacts"]}))

    def test_worker_reports_native_entry_and_import_ranges_before_emulation(self):
        run_dir = self.root / "20261010T000000Z-deadbeef"
        run_dir.mkdir()
        for arch, directory_offset in (("x86", 96), ("x64", 112)):
            original = (FIXTURES / f"native_{arch}.exe").read_bytes()
            pe_offset = struct.unpack_from("<I", original, 0x3C)[0]
            optional = pe_offset + 24
            for name, offset, message in (
                    ("entry", optional + 16, "entry point lies outside"),
                    ("imports", optional + directory_offset + 8,
                     "import directory lies outside")):
                with self.subTest(arch=arch, mutation=name):
                    data = bytearray(original)
                    data[offset:offset + (8 if name == "imports" else 4)] = (
                        b"\xff" * (8 if name == "imports" else 4))
                    image = bytes(data)
                    self.assertEqual(inspect_pe_header(image, f"native_{arch}.exe").architecture,
                                     arch)
                    with self.assertRaisesRegex(InvalidSample, message):
                        inspect_pe(image, f"native_{arch}.exe")
                    (run_dir / "input.pe").write_bytes(image)
                    (run_dir / "request.json").write_text(json.dumps({
                        "sample_name": f"native_{arch}.exe", "persona": self.persona,
                        "dlls": [], "timeout": 10, "max_instructions": 100_000,
                    }), encoding="utf-8")
                    with patch("emumee.worker.verify_worker_containment",
                               return_value={"app_container": True, "job_object": True,
                                             "child_process_blocked": True}):
                        result = execute_worker(run_dir)
                    self.assertEqual(result["status"], "failed")
                    self.assertIn(message, result["errors"][0])
                    self.assertTrue(valid_summary(json.loads(
                        (run_dir / "summary.json").read_text(encoding="utf-8"))))

    def test_native_file_write_is_recovered(self):
        result = self.native("drop_x86.exe")
        self.assertFalse(result["errors"])
        self.assertEqual({item["source"] for item in result["artifacts"]},
                         {"file_write", "virtual_file_final"})
        self.assertEqual(len({item["sha256"] for item in result["artifacts"]}), 1)
        for artifact in result["artifacts"]:
            self.assertEqual((self.root / "artifacts" / artifact["file"]).read_bytes(),
                             b"native payload marker")
        self.assertEqual(len(result["artifact_groups"]), 1)
        self.assertEqual(len(result["artifact_groups"][0]["observations"]), 2)

    def test_signature_only_winapi_is_reported_as_partial_coverage(self):
        result = self.native("signature_stub_x86.exe")
        self.assertEqual(result["api_coverage"]["signature_only_calls"], [
            {"api": "kernel32.MoveFileWithProgressW", "count": 1}])
        self.assertGreater(result["api_coverage"]["api_calls"], 0)
        self.assertTrue(any(item["api"] == "kernel32.MoveFileWithProgressW"
                            and item["signature_only_count"] == 1
                            for item in result["api_coverage"]["observed_calls"]))
        self.assertTrue(any("Signature-only" in error for error in result["errors"]))
        report = json.loads((self.root / result["engine_report"]).read_text())
        self.assertTrue(any(e.get("api_name") == "kernel32.ExitProcess"
                            for e in report["entry_points"][0]["events"]))

    def test_movefileex_moves_guest_file_and_extracts_new_path(self):
        for arch in ("x86", "x64"):
            for variant in ("W", "A"):
                with self.subTest(arch=arch, variant=variant), tempfile.TemporaryDirectory() as folder:
                    root = Path(folder)
                    fixture = f"move_file{'_a' if variant == 'A' else ''}_{arch}.exe"
                    exe = FIXTURES / fixture
                    image = exe.read_bytes()
                    result = run_native(image, inspect_pe(image, exe.name), self.persona,
                                        root, [], 10, 100_000)
                    report = json.loads((root / result["engine_report"]).read_text())
                    self.assertFalse(result["errors"])
                    self.assertFalse(result["api_coverage"]["signature_only_calls"])
                    move = next(e for e in report["virtual_file_events"]
                                if e["event"] == "virtual_file_move")
                    self.assertEqual(move["api"], f"kernel32.MoveFileEx{variant}")
                    self.assertTrue(move["success"])
                    self.assertFalse(move["old_exists_after"])
                    self.assertTrue(move["new_exists_after"])
                    self.assertTrue(any(event.get("api_name", "").endswith("ExitProcess")
                                        and event.get("args") == ["0x1"]
                                        for event in report["entry_points"][0]["events"]))
                    self.assertTrue(any(item["source"] == "virtual_file_move"
                                        and item["guest_path"].endswith("new.bin")
                                        and (root / "artifacts" / item["file"]).read_bytes() ==
                                        b"moved payload marker" for item in result["artifacts"]))

    def test_open_handle_delete_and_rename_sharing_inside_cpu_emulation(self):
        for operation in ("move", "delete"):
            for sharing in ("locked", "shared"):
                for arch in ("x86", "x64"):
                    for variant in ("W", "A"):
                        with self.subTest(operation=operation, sharing=sharing, arch=arch,
                                          variant=variant), tempfile.TemporaryDirectory() as folder:
                            root = Path(folder)
                            name = (f"{operation}_open_{sharing}"
                                    f"{'_a' if variant == 'A' else ''}_{arch}.exe")
                            image = (FIXTURES / name).read_bytes()
                            result = run_native(image, inspect_pe(image, name), self.persona,
                                                root, [], 10, 100_000)
                            report = json.loads((root / result["engine_report"]).read_text())
                            self.assertFalse(result["errors"])
                            self.assertFalse(result["api_coverage"]["signature_only_calls"])
                            mutation = next(event for event in report["virtual_file_events"]
                                            if event["event"] == f"virtual_file_{operation}")
                            self.assertEqual(mutation["success"], sharing == "shared")
                            if sharing == "locked":
                                self.assertEqual(mutation["reason"], "sharing violation")
                            self.assertTrue(any(event.get("api_name") == "kernel32.ExitProcess"
                                                and event.get("args") ==
                                                (["0x1"] if sharing == "shared" else ["0x0"])
                                                for entry in report["entry_points"]
                                                for event in entry["events"]))

    def test_copyfile_copies_guest_file_on_both_architectures(self):
        for arch in ("x86", "x64"):
            for variant in ("W", "A"):
                with self.subTest(arch=arch, variant=variant), tempfile.TemporaryDirectory() as folder:
                    root = Path(folder)
                    fixture = f"copy_file{'_a' if variant == 'A' else ''}_{arch}.exe"
                    exe = FIXTURES / fixture
                    image = exe.read_bytes()
                    result = run_native(image, inspect_pe(image, exe.name), self.persona,
                                        root, [], 10, 100_000)
                    report = json.loads((root / result["engine_report"]).read_text())
                    self.assertFalse(result["errors"])
                    self.assertFalse(result["api_coverage"]["signature_only_calls"])
                    copy = next(e for e in report["virtual_file_events"]
                                if e["event"] == "virtual_file_copy")
                    self.assertEqual(copy["api"], f"kernel32.CopyFile{variant}")
                    self.assertTrue(copy["success"])
                    self.assertTrue(copy["source_exists_after"])
                    self.assertTrue(copy["destination_exists_after"])
                    self.assertTrue(any(event.get("api_name", "").endswith("ExitProcess")
                                        and event.get("args") == ["0x1"]
                                        for event in report["entry_points"][0]["events"]))
                    self.assertTrue(any(item["source"] == "virtual_file_copy"
                                        and item["guest_path"].endswith("new.bin")
                                        and (root / "artifacts" / item["file"]).read_bytes() ==
                                        b"copied payload marker" for item in result["artifacts"]))

    def test_open_handle_copyfile_sharing_inside_cpu_emulation(self):
        for subject in ("source", "target"):
            for sharing in ("locked", "shared"):
                for arch in ("x86", "x64"):
                    for variant in ("W", "A"):
                        with self.subTest(subject=subject, sharing=sharing, arch=arch,
                                          variant=variant), tempfile.TemporaryDirectory() as folder:
                            root = Path(folder)
                            name = (f"copy_{subject}_open_{sharing}"
                                    f"{'_a' if variant == 'A' else ''}_{arch}.exe")
                            image = (FIXTURES / name).read_bytes()
                            result = run_native(image, inspect_pe(image, name), self.persona,
                                                root, [], 10, 100_000)
                            report = json.loads((root / result["engine_report"]).read_text())
                            self.assertFalse(result["errors"])
                            self.assertFalse(result["api_coverage"]["signature_only_calls"])
                            event = next(item for item in report["virtual_file_events"]
                                         if item["event"] == "virtual_file_copy")
                            self.assertEqual(event["success"], sharing == "shared")
                            if sharing == "locked":
                                self.assertEqual(event["reason"],
                                                 f"{'destination' if subject == 'target' else 'source'}"
                                                 " sharing violation")
                            else:
                                self.assertTrue(any(
                                    item["source"] == "virtual_file_copy"
                                    and (root / "artifacts" / item["file"]).read_bytes() ==
                                    b"copied payload marker" for item in result["artifacts"]))
                            self.assertTrue(any(trace.get("api_name") == "kernel32.ExitProcess"
                                                and trace.get("args") ==
                                                (["0x1"] if sharing == "shared" else ["0x0"])
                                                for entry in report["entry_points"]
                                                for trace in entry["events"]))

    def test_directory_lifecycle_uses_guest_state_on_both_architectures(self):
        for arch in ("x86", "x64"):
            for variant in ("W", "A"):
                with self.subTest(arch=arch, variant=variant), tempfile.TemporaryDirectory() as folder:
                    root = Path(folder)
                    name = f"directory{'_a' if variant == 'A' else ''}_{arch}.exe"
                    exe = FIXTURES / name
                    image = exe.read_bytes()
                    result = run_native(image, inspect_pe(image, name), self.persona,
                                        root, [], 10, 100_000)
                    report = json.loads((root / result["engine_report"]).read_text())
                    self.assertFalse(result["errors"])
                    self.assertFalse(result["api_coverage"]["signature_only_calls"])
                    events = report["virtual_file_events"]
                    self.assertEqual([event["event"] for event in events], [
                        "virtual_directory_create", "virtual_file_attributes",
                        "virtual_directory_remove", "virtual_file_attributes",
                        "virtual_file_process_cleanup"])
                    self.assertTrue(events[0]["success"])
                    self.assertEqual(events[1]["attributes"], 0x10)
                    self.assertTrue(events[2]["success"])
                    self.assertEqual(events[3]["attributes"], 0xFFFFFFFF)
                    find = [event for event in report["entry_points"][0]["events"]
                            if event.get("api_name") == f"kernel32.FindFirstFile{variant}"]
                    self.assertEqual(len(find), 1)
                    self.assertNotEqual(find[0]["ret_val"], "0xffffffff")
                    self.assertTrue(any(event.get("api_name", "").endswith("ExitProcess")
                                        and event.get("args") == ["0x1"]
                                        for event in report["entry_points"][0]["events"]))

    def test_open_always_last_error_and_closed_file_handle_inside_cpu_emulation(self):
        for arch in ("x86", "x64"):
            for variant in ("W", "A"):
                with self.subTest(arch=arch, variant=variant), tempfile.TemporaryDirectory() as folder:
                    root = Path(folder)
                    name = f"open_always{'_a' if variant == 'A' else ''}_{arch}.exe"
                    exe = FIXTURES / name
                    image = exe.read_bytes()
                    result = run_native(image, inspect_pe(image, name), self.persona,
                                        root, [], 10, 100_000)
                    report = json.loads((root / result["engine_report"]).read_text())
                    self.assertFalse(result["errors"])
                    self.assertFalse(result["api_coverage"]["signature_only_calls"])
                    events = report["virtual_file_events"]
                    opens = [e for e in events if e["event"] == "virtual_file_open_always"]
                    closes = [e for e in events if e["event"] == "virtual_file_close"]
                    self.assertEqual([e["existed_before"] for e in opens], [False, True])
                    self.assertEqual([e["success"] for e in closes], [True, True, False])
                    self.assertTrue(any(e.get("api_name") == "kernel32.ExitProcess"
                                        and e.get("args") == ["0x1"]
                                        for e in report["entry_points"][0]["events"]))

    def test_reopened_guest_file_shares_bytes_inside_cpu_emulation(self):
        for arch in ("x86", "x64"):
            for variant in ("W", "A"):
                with self.subTest(arch=arch, variant=variant), tempfile.TemporaryDirectory() as folder:
                    root = Path(folder)
                    name = f"reopen_overwrite{'_a' if variant == 'A' else ''}_{arch}.exe"
                    image = (FIXTURES / name).read_bytes()
                    result = run_native(image, inspect_pe(image, name), self.persona,
                                        root, [], 10, 100_000)
                    report = json.loads((root / result["engine_report"]).read_text())
                    self.assertFalse(result["errors"])
                    self.assertFalse(result["api_coverage"]["signature_only_calls"])
                    self.assertTrue(any(event.get("api_name") == "kernel32.ExitProcess"
                                        and event.get("args") == ["0x1"]
                                        for entry in report["entry_points"]
                                        for event in entry["events"]))
                    self.assertTrue(any(item["source"] == "virtual_file_final"
                                        and (root / "artifacts" / item["file"]).read_bytes() == b"NEW!"
                                        for item in result["artifacts"]))

    def test_append_only_guest_file_inside_cpu_emulation(self):
        for arch in ("x86", "x64"):
            for variant in ("W", "A"):
                with self.subTest(arch=arch, variant=variant), tempfile.TemporaryDirectory() as folder:
                    root = Path(folder)
                    name = f"append_only{'_a' if variant == 'A' else ''}_{arch}.exe"
                    image = (FIXTURES / name).read_bytes()
                    result = run_native(image, inspect_pe(image, name), self.persona,
                                        root, [], 10, 100_000)
                    report = json.loads((root / result["engine_report"]).read_text())
                    self.assertFalse(result["errors"])
                    self.assertFalse(result["api_coverage"]["signature_only_calls"])
                    self.assertTrue(any(event.get("api_name") == "kernel32.ExitProcess"
                                        and event.get("args") == ["0x1"]
                                        for entry in report["entry_points"]
                                        for event in entry["events"]))
                    self.assertTrue(any(item["source"] in ("file_write", "virtual_file_final")
                                        and (root / "artifacts" / item["file"]).read_bytes() == b"OLD!NEW!"
                                        for item in result["artifacts"]))

    def test_delete_on_close_inside_cpu_emulation(self):
        for arch in ("x86", "x64"):
            for variant in ("W", "A"):
                with self.subTest(arch=arch, variant=variant), tempfile.TemporaryDirectory() as folder:
                    root = Path(folder)
                    name = f"delete_on_close{'_a' if variant == 'A' else ''}_{arch}.exe"
                    image = (FIXTURES / name).read_bytes()
                    result = run_native(image, inspect_pe(image, name), self.persona,
                                        root, [], 10, 100_000)
                    report = json.loads((root / result["engine_report"]).read_text())
                    self.assertFalse(result["errors"])
                    self.assertFalse(result["api_coverage"]["signature_only_calls"])
                    self.assertTrue(any(event.get("api_name") == "kernel32.ExitProcess"
                                        and event.get("args") == ["0x1"]
                                        for entry in report["entry_points"]
                                        for event in entry["events"]))
                    deleted = [event for event in report["virtual_file_events"]
                               if event["event"] == "virtual_file_delete_on_close"]
                    self.assertEqual(len(deleted), 1)
                    self.assertFalse(deleted[0]["exists_after"])
                    self.assertTrue(any(item["source"] == "virtual_file_delete_on_close"
                                        and (root / "artifacts" / item["file"]).read_bytes() == b"OLD!"
                                        for item in result["artifacts"]))

    def test_delete_on_close_at_guest_process_exit(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                name = f"delete_on_exit_{arch}.exe"
                image = (FIXTURES / name).read_bytes()
                result = run_native(image, inspect_pe(image, name), self.persona,
                                    root, [], 10, 100_000)
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                self.assertTrue(any(event.get("api_name") == "kernel32.ExitProcess"
                                    and event.get("args") == ["0x1"]
                                    for entry in report["entry_points"]
                                    for event in entry["events"]))
                deleted = [event for event in report["virtual_file_events"]
                           if event["event"] == "virtual_file_delete_on_close"]
                self.assertEqual(len(deleted), 1)
                self.assertIsInstance(deleted[0]["handle"], int)
                self.assertFalse(deleted[0]["exists_after"])
                self.assertTrue(any(item["source"] == "virtual_file_delete_on_close"
                                    and (root / "artifacts" / item["file"]).read_bytes() == b"OLD!"
                                    for item in result["artifacts"]))

    def test_delete_on_create_inside_cpu_emulation(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                name = f"delete_on_create_{arch}.exe"
                image = (FIXTURES / name).read_bytes()
                result = run_native(image, inspect_pe(image, name), self.persona,
                                    root, [], 10, 100_000)
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                self.assertTrue(any(event.get("api_name") == "kernel32.ExitProcess"
                                    and event.get("args") == ["0x1"]
                                    for entry in report["entry_points"]
                                    for event in entry["events"]))
                self.assertTrue(any(event["event"] == "virtual_file_delete_on_close"
                                    and event["exists_after"] is False
                                    for event in report["virtual_file_events"]))
                self.assertTrue(any(item["source"] == "virtual_file_delete_on_close"
                                    and (root / "artifacts" / item["file"]).read_bytes() == b"OLD!"
                                    for item in result["artifacts"]))

    def test_file_disposition_inside_cpu_emulation(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                name = f"file_disposition_{arch}.exe"
                image = (FIXTURES / name).read_bytes()
                result = run_native(image, inspect_pe(image, name), self.persona,
                                    root, [], 10, 100_000)
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                self.assertFalse(result["api_coverage"]["signature_only_calls"])
                self.assertTrue(any(event.get("api_name") == "kernel32.ExitProcess"
                                    and event.get("args") == ["0x1"]
                                    for entry in report["entry_points"]
                                    for event in entry["events"]))
                marks = [event for event in report["virtual_file_events"]
                         if event["event"] == "virtual_file_disposition"]
                deleted = [event for event in report["virtual_file_events"]
                           if event["event"] == "virtual_file_disposition_delete"]
                self.assertEqual(len(marks), 1)
                self.assertTrue(marks[0]["delete"])
                self.assertEqual(len(deleted), 1)
                self.assertFalse(deleted[0]["exists_after"])
                self.assertTrue(any(item["source"] == "virtual_file_disposition_delete"
                                    and (root / "artifacts" / item["file"]).read_bytes() == b"OLD!"
                                    for item in result["artifacts"]))

    def test_file_disposition_cancel_inside_cpu_emulation(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                name = f"file_disposition_cancel_{arch}.exe"
                image = (FIXTURES / name).read_bytes()
                result = run_native(image, inspect_pe(image, name), self.persona,
                                    root, [], 10, 100_000)
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                self.assertTrue(any(event.get("api_name") == "kernel32.ExitProcess"
                                    and event.get("args") == ["0x1"]
                                    for entry in report["entry_points"]
                                    for event in entry["events"]))
                marks = [event for event in report["virtual_file_events"]
                         if event["event"] == "virtual_file_disposition"]
                self.assertEqual([event["delete"] for event in marks], [True, False])
                self.assertFalse(any(event["event"] == "virtual_file_disposition_delete"
                                     for event in report["virtual_file_events"]))
                self.assertTrue(any((root / "artifacts" / item["file"]).read_bytes() == b"OLD!"
                                    for item in result["artifacts"]))

    def test_file_disposition_at_guest_process_exit(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                name = f"file_disposition_exit_{arch}.exe"
                image = (FIXTURES / name).read_bytes()
                result = run_native(image, inspect_pe(image, name), self.persona,
                                    root, [], 10, 100_000)
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                self.assertTrue(any(event.get("api_name") == "kernel32.ExitProcess"
                                    and event.get("args") == ["0x1"]
                                    for entry in report["entry_points"]
                                    for event in entry["events"]))
                deleted = [event for event in report["virtual_file_events"]
                           if event["event"] == "virtual_file_disposition_delete"]
                self.assertEqual(len(deleted), 1)
                self.assertIsInstance(deleted[0]["handle"], int)
                self.assertFalse(deleted[0]["exists_after"])
                self.assertTrue(any(item["source"] == "virtual_file_disposition_delete"
                                    and (root / "artifacts" / item["file"]).read_bytes() == b"OLD!"
                                    for item in result["artifacts"]))

    def test_truncate_existing_clears_guest_file_inside_cpu_emulation(self):
        for arch in ("x86", "x64"):
            for variant in ("W", "A"):
                with self.subTest(arch=arch, variant=variant), tempfile.TemporaryDirectory() as folder:
                    root = Path(folder)
                    name = f"truncate_existing{'_a' if variant == 'A' else ''}_{arch}.exe"
                    image = (FIXTURES / name).read_bytes()
                    result = run_native(image, inspect_pe(image, name), self.persona,
                                        root, [], 10, 100_000)
                    report = json.loads((root / result["engine_report"]).read_text())
                    self.assertFalse(result["errors"])
                    self.assertFalse(result["api_coverage"]["signature_only_calls"])
                    self.assertTrue(any(event.get("api_name") == "kernel32.ExitProcess"
                                        and event.get("args") == ["0x1"]
                                        for entry in report["entry_points"]
                                        for event in entry["events"]))
                    self.assertEqual(len([event for event in report["virtual_file_events"]
                                          if event["event"] == "virtual_file_truncate"]), 1)
                    self.assertTrue(any((root / "artifacts" / item["file"]).read_bytes() == b"NEW!"
                                        for item in result["artifacts"]))

    def test_setendoffile_truncates_guest_payload_inside_cpu_emulation(self):
        for arch in ("x86", "x64"):
            for variant in ("W", "A"):
                with self.subTest(arch=arch, variant=variant), tempfile.TemporaryDirectory() as folder:
                    root = Path(folder)
                    name = f"set_end_of_file{'_a' if variant == 'A' else ''}_{arch}.exe"
                    image = (FIXTURES / name).read_bytes()
                    result = run_native(image, inspect_pe(image, name), self.persona,
                                        root, [], 10, 100_000)
                    report = json.loads((root / result["engine_report"]).read_text())
                    self.assertFalse(result["errors"])
                    self.assertFalse(result["api_coverage"]["signature_only_calls"])
                    resize = next(event for event in report["virtual_file_events"]
                                  if event["event"] == "virtual_file_resize")
                    self.assertEqual((resize["old_size"], resize["new_size"]), (8, 3))
                    self.assertTrue(any(item["source"] == "virtual_file_final"
                                        and (root / "artifacts" / item["file"]).read_bytes() == b"ABC"
                                        for item in result["artifacts"]))
                    self.assertTrue(any(event.get("api_name") == "kernel32.ExitProcess"
                                        and event.get("args") == ["0x1"]
                                        for entry in report["entry_points"]
                                        for event in entry["events"]))

    def test_file_end_info_truncates_guest_payload_inside_cpu_emulation(self):
        for arch in ("x86", "x64"):
            for variant in ("W", "A"):
                with self.subTest(arch=arch, variant=variant), tempfile.TemporaryDirectory() as folder:
                    root = Path(folder)
                    name = f"file_end_info{'_a' if variant == 'A' else ''}_{arch}.exe"
                    image = (FIXTURES / name).read_bytes()
                    result = run_native(image, inspect_pe(image, name), self.persona,
                                        root, [], 10, 100_000)
                    report = json.loads((root / result["engine_report"]).read_text())
                    self.assertFalse(result["errors"])
                    self.assertFalse(result["api_coverage"]["signature_only_calls"])
                    resize = next(event for event in report["virtual_file_events"]
                                  if event["event"] == "virtual_file_resize")
                    self.assertEqual((resize["old_size"], resize["new_size"]), (8, 3))
                    self.assertIn("SetFileInformationByHandle", resize["api"])
                    self.assertTrue(any(item["source"] == "virtual_file_final"
                                        and (root / "artifacts" / item["file"]).read_bytes() == b"ABC"
                                        for item in result["artifacts"]))
                    self.assertTrue(any(event.get("api_name") == "kernel32.ExitProcess"
                                        and event.get("args") == ["0x1"]
                                        for entry in report["entry_points"]
                                        for event in entry["events"]))

    def test_file_rename_info_moves_open_guest_file_inside_cpu_emulation(self):
        for arch in ("x86", "x64"):
            for variant in ("W", "A"):
                with self.subTest(arch=arch, variant=variant), tempfile.TemporaryDirectory() as folder:
                    root = Path(folder)
                    name = f"file_rename_info{'_a' if variant == 'A' else ''}_{arch}.exe"
                    image = (FIXTURES / name).read_bytes()
                    result = run_native(image, inspect_pe(image, name), self.persona,
                                        root, [], 10, 100_000)
                    report = json.loads((root / result["engine_report"]).read_text())
                    self.assertFalse(result["errors"])
                    self.assertFalse(result["api_coverage"]["signature_only_calls"])
                    rename = next(event for event in report["virtual_file_events"]
                                  if event["event"] == "virtual_file_rename_by_handle")
                    self.assertTrue(rename["success"])
                    self.assertFalse(rename["old_exists_after"])
                    self.assertTrue(rename["new_exists_after"])
                    self.assertTrue(any(item["guest_path"].endswith("renamed.bin")
                                        and (root / "artifacts" / item["file"]).read_bytes() == b"ABCDEFGH"
                                        for item in result["artifacts"]))
                    self.assertTrue(any(event.get("api_name") == "kernel32.ExitProcess"
                                        and event.get("args") == ["0x1"]
                                        for entry in report["entry_points"]
                                        for event in entry["events"]))

    def test_writable_file_mapping_writes_back_guest_payload(self):
        for arch in ("x86", "x64"):
            for unmap in (True, False):
                with self.subTest(arch=arch, unmap=unmap), tempfile.TemporaryDirectory() as folder:
                    root = Path(folder)
                    name = f"mapped_file_{arch}.exe" if unmap else f"mapped_file_live_{arch}.exe"
                    image = (FIXTURES / name).read_bytes()
                    result = run_native(image, inspect_pe(image, name), self.persona,
                                        root, [], 10, 100_000)
                    report = json.loads((root / result["engine_report"]).read_text())
                    self.assertFalse(result["errors"])
                    self.assertTrue(any(event["event"] == "virtual_mapping_writeback"
                                        and event["offset"] == 0
                                        and event["reason"] == "live_write"
                                        for event in report["virtual_file_events"]))
                    self.assertTrue(any(item["source"] == "virtual_file_final"
                                        and (root / "artifacts" / item["file"]).read_bytes() == b"XYZ!EFGH"
                                        for item in result["artifacts"]))
                    self.assertTrue(any(event.get("api_name") == "kernel32.ExitProcess"
                                        and event.get("args") == ["0x1"]
                                        for entry in report["entry_points"]
                                        for event in entry["events"]))

    def test_process_memory_write_extracts_guest_pe_and_rejects_bad_handle(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                name = f"process_memory_write_{arch}.exe"
                image = (FIXTURES / name).read_bytes()
                nested = image[0xA00:0x1000]
                result = run_native(image, inspect_pe(image, name), self.persona,
                                    root, [], 10, 100_000)
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                events = [event for event in report["virtual_process_events"]
                          if event["event"] == "virtual_process_memory_write"]
                self.assertEqual([event["success"] for event in events], [False, True])
                self.assertEqual(events[0]["reason"], "invalid process handle")
                self.assertEqual(events[1]["sha256"], hashlib.sha256(nested).hexdigest())
                self.assertTrue(any(item["source"] == "process_memory_write@0x0"
                                    and (root / "artifacts" / item["file"]).read_bytes() == nested
                                    for item in result["artifacts"]))
                self.assertTrue(any(event.get("api_name") == "kernel32.ExitProcess"
                                    and event.get("args") == ["0x1"]
                                    for entry in report["entry_points"]
                                    for event in entry["events"]))

    def test_guest_child_receives_remote_pe_write_and_executes(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                name = f"child_process_{arch}.exe"
                image = (FIXTURES / name).read_bytes()
                nested = image[0xA00:0x1000]
                result = run_native(image, inspect_pe(image, name), self.persona,
                                    root, [], 10, 100_000)
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                self.assertEqual(len(report["entry_points"]), 2)
                self.assertFalse(any(entry.get("error") for entry in report["entry_points"]))
                self.assertEqual(report["entry_points"][1]["ret_val"], "0x0")
                creates = [item for item in report["virtual_process_events"]
                           if item["event"] == "virtual_process_create"]
                self.assertEqual(len(creates), 1)
                self.assertTrue(creates[0]["success"])
                writes = [item for item in report["virtual_process_events"]
                          if item["event"] == "virtual_process_memory_write"]
                self.assertEqual(len(writes), 1)
                self.assertTrue(writes[0]["success"])
                self.assertTrue(writes[0]["path"].endswith(r"\child-stage.exe"))
                self.assertEqual(writes[0]["sha256"], hashlib.sha256(nested).hexdigest())
                self.assertTrue(any(item["source"] == "process_memory_write@0x0"
                                    and (root / "artifacts" / item["file"]).read_bytes() == nested
                                    for item in result["artifacts"]))

    def test_suspended_child_runs_only_after_resume(self):
        for arch in ("x86", "x64"):
            for resumed in (False, True):
                with self.subTest(arch=arch, resumed=resumed), tempfile.TemporaryDirectory() as folder:
                    root = Path(folder)
                    stem = "child_resumed" if resumed else "child_suspended"
                    name = f"{stem}_{arch}.exe"
                    image = (FIXTURES / name).read_bytes()
                    result = run_native(image, inspect_pe(image, name), self.persona,
                                        root, [], 10, 100_000)
                    report = json.loads((root / result["engine_report"]).read_text())
                    self.assertFalse(result["errors"])
                    self.assertEqual(len(report["entry_points"]), 2 if resumed else 1)
                    self.assertFalse(any(entry.get("error") for entry in report["entry_points"]))
                    events = report["virtual_process_events"]
                    self.assertTrue(any(event["event"] == "virtual_process_create"
                                        and event["success"] for event in events))
                    if resumed:
                        self.assertEqual(report["entry_points"][1]["ret_val"], "0x0")
                        self.assertEqual([event["previous_suspend_count"] for event in events
                                          if event["event"] == "virtual_thread_resume"], [1])
                    else:
                        self.assertTrue(any(event["event"] == "virtual_process_suspended"
                                            and event["suspend_count"] == 1 for event in events))

    def test_guest_child_memory_read_checks_handle_and_extracts_bytes(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                name = f"child_memory_read_{arch}.exe"
                image = (FIXTURES / name).read_bytes()
                nested = image[0xA00:0xA10]
                result = run_native(image, inspect_pe(image, name), self.persona,
                                    root, [], 10, 100_000)
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                self.assertEqual(len(report["entry_points"]), 2)
                self.assertFalse(any(entry.get("error") for entry in report["entry_points"]))
                reads = [item for item in report["virtual_process_events"]
                         if item["event"] == "virtual_process_memory_read"]
                self.assertEqual([item["success"] for item in reads], [False, True])
                self.assertEqual(reads[0]["reason"], "invalid process handle")
                self.assertEqual(reads[1]["sha256"], hashlib.sha256(nested).hexdigest())
                self.assertTrue(any(item["source"] == "process_memory_read"
                                    and (root / "artifacts" / item["file"]).read_bytes() == nested
                                    for item in result["artifacts"]))

    def test_child_handle_cannot_write_parent_owned_memory(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                name = f"child_cross_owner_write_{arch}.exe"
                image = (FIXTURES / name).read_bytes()
                result = run_native(image, inspect_pe(image, name), self.persona,
                                    root, [], 10, 100_000)
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                self.assertEqual(len(report["entry_points"]), 2)
                writes = [item for item in report["virtual_process_events"]
                          if item["event"] == "virtual_process_memory_write"]
                self.assertEqual([item["success"] for item in writes], [False, True])
                self.assertEqual(writes[0]["reason"], "memory belongs to different guest process")
                self.assertEqual(writes[1]["sha256"],
                                 hashlib.sha256(image[0xA00:0x1000]).hexdigest())

    def test_child_handle_cannot_allocate_or_protect_parent_owned_memory(self):
        for arch in ("x86", "x64"):
            for operation in ("alloc", "protect"):
                with self.subTest(arch=arch, operation=operation), tempfile.TemporaryDirectory() as folder:
                    root = Path(folder)
                    name = f"child_cross_owner_{operation}_{arch}.exe"
                    image = (FIXTURES / name).read_bytes()
                    result = run_native(image, inspect_pe(image, name), self.persona,
                                        root, [], 10, 100_000)
                    report = json.loads((root / result["engine_report"]).read_text())
                    self.assertFalse(result["errors"])
                    self.assertEqual(len(report["entry_points"]), 2)
                    event_name = ("virtual_process_allocate" if operation == "alloc"
                                  else "virtual_process_protect")
                    events = [item for item in report["virtual_process_events"]
                              if item["event"] == event_name]
                    self.assertEqual([item["success"] for item in events], [False, True])
                    self.assertIn("different guest process", events[0]["reason"])
                    writes = [item for item in report["virtual_process_events"]
                              if item["event"] == "virtual_process_memory_write"]
                    self.assertEqual(len(writes), 1)
                    self.assertTrue(writes[0]["success"])

    def test_direct_cpu_access_cannot_cross_guest_process_boundary(self):
        for arch in ("x86", "x64"):
            for access in ("read", "write", "write_rep", "execute"):
                with self.subTest(arch=arch, access=access), tempfile.TemporaryDirectory() as folder:
                    operation = "write" if access == "write_rep" else access
                    root = Path(folder)
                    name = f"child_direct_{access}_{arch}.exe"
                    image = (FIXTURES / name).read_bytes()
                    result = run_native(image, inspect_pe(image, name), self.persona,
                                        root, [], 10, 100_000)
                    report = json.loads((root / result["engine_report"]).read_text())
                    self.assertTrue(any(f"guest {operation} denied: different guest process" in error
                                        for error in result["errors"]))
                    self.assertEqual(len(report["entry_points"]), 1)
                    denied = [event for event in report["virtual_process_events"]
                              if event["event"] == "virtual_cpu_memory_denied"]
                    self.assertEqual(len(denied), 1)
                    self.assertEqual((denied[0]["access"], denied[0]["reason"]),
                                     (operation, "different guest process"))
                    self.assertNotEqual(denied[0]["pid"], denied[0]["owner_pid"])
                    self.assertFalse(any(event["event"] == "virtual_process_memory_write"
                                         for event in report["virtual_process_events"]))
                    if operation == "write":
                        restored = [event for event in report["virtual_process_events"]
                                    if event["event"] == "virtual_cpu_memory_restored"]
                        self.assertEqual(len(restored), 1)
                        self.assertTrue(restored[0]["success"])
                        maps = [mapping for mapping in report["entry_points"][-1]["memory"]["layout"]
                                if mapping["tag"].startswith("api.VirtualAllocEx.child-stage")]
                        self.assertEqual(len(maps), 1)
                        length = 16 if access == "write_rep" else 4
                        self.assertEqual(_report_blob(report["data"], maps[0]["data_ref"])[:length],
                                         b"\0" * length)

    def test_child_cpu_cannot_access_parent_image(self):
        for arch in ("x86", "x64"):
            for access in ("read", "write", "execute"):
                with self.subTest(arch=arch, access=access), tempfile.TemporaryDirectory() as folder:
                    root = Path(folder)
                    name = f"child_parent_image_{access}_{arch}.exe"
                    image = (FIXTURES / name).read_bytes()
                    result = run_native(image, inspect_pe(image, name), self.persona,
                                        root, [], 10, 100_000)
                    report = json.loads((root / result["engine_report"]).read_text())
                    denied = [event for event in report["virtual_process_events"]
                              if event["event"] == "virtual_cpu_memory_denied"]
                    self.assertEqual(len(denied), 1, (arch, access, result["errors"]))
                    self.assertEqual((denied[0]["access"], denied[0]["reason"]),
                                     (access, "different guest process"))
                    self.assertNotEqual(denied[0]["pid"], denied[0]["owner_pid"])
                    if access == "write":
                        restored = [event for event in report["virtual_process_events"]
                                    if event["event"] == "virtual_cpu_memory_restored"]
                        self.assertEqual(len(restored), 1)
                        self.assertTrue(restored[0]["success"])

    def test_child_cpu_cannot_access_parent_companion_dll(self):
        for arch, machine, preferred in (("x86", 0x14C, 0x50000000),
                                         ("x64", 0x8664, 0x180000000)):
            for load_mode in ("static", "dynamic", "guest"):
                for access in ("read", "write", "execute"):
                    with self.subTest(arch=arch, load_mode=load_mode, access=access), tempfile.TemporaryDirectory() as folder:
                        self._check_child_parent_dll_cpu_case(
                            Path(folder), arch, machine, preferred, load_mode, access)

    def _check_child_parent_dll_cpu_case(self, root, arch, machine, preferred,
                                         load_mode, access):
        prefix = "" if load_mode == "static" else f"{load_mode}_"
        name = f"child_parent_{prefix}dll_cpu_{access}_{arch}.exe"
        image = (FIXTURES / name).read_bytes()
        dll = root / f"companion_{arch}.dll"
        supplied = []
        if load_mode != "guest":
            dll.write_bytes(build_relocatable_companion(machine, preferred))
            supplied = [dll]
        result = run_native(image, inspect_pe(image, name), self.persona,
                            root, supplied, 10, 200_000)
        report = json.loads((root / result["engine_report"]).read_text())
        if load_mode == "guest":
            loaded = [event for event in report["dll_initialization_events"]
                      if event["event"] == "virtual_dll_load" and event.get("mapped")]
            self.assertEqual(len(loaded), 1)
            self.assertEqual(loaded[0]["base"], hex(preferred))
        denied = [event for event in report["virtual_process_events"]
                  if event["event"] == "virtual_cpu_memory_denied"]
        self.assertEqual(len(denied), 1, (arch, load_mode, access, result["errors"]))
        self.assertEqual((denied[0]["access"], denied[0]["reason"]),
                         (access, "different guest process"))
        self.assertNotEqual(denied[0]["pid"], denied[0]["owner_pid"])
        if access == "write":
            restored = [event for event in report["virtual_process_events"]
                        if event["event"] == "virtual_cpu_memory_restored"]
            self.assertEqual(len(restored), 1)
            self.assertTrue(restored[0]["success"])

    def test_child_api_cannot_copy_parent_guest_dll(self):
        for (arch, machine, preferred), access in product(
                (("x86", 0x14C, 0x50000000), ("x64", 0x8664, 0x180000000)),
                ("copy", "write")):
            with self.subTest(arch=arch, access=access), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                name = f"child_parent_guest_dll_api_{access}_{arch}.exe"
                image = (FIXTURES / name).read_bytes()
                result = run_native(image, inspect_pe(image, name), self.persona,
                                    root, [], 10, 200_000)
                report = json.loads((root / result["engine_report"]).read_text())
                loaded = [event for event in report["dll_initialization_events"]
                          if event["event"] == "virtual_dll_load" and event.get("mapped")]
                self.assertEqual(len(loaded), 1)
                self.assertEqual(loaded[0]["base"], hex(preferred))
                denied = [event for event in report["virtual_process_events"]
                          if event["event"] == "virtual_memory_api_denied"]
                self.assertEqual(len(denied), 1, (arch, result["errors"]))
                self.assertEqual(denied[0]["reason"],
                                 ("source" if access == "copy" else "destination") +
                                 " belongs to different guest process")
                self.assertFalse(any(event["event"] == "virtual_cpu_memory_denied"
                                     for event in report["virtual_process_events"]))

    def test_bulk_memory_api_cannot_read_child_owned_page(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                name = f"child_api_copy_{arch}.exe"
                image = (FIXTURES / name).read_bytes()
                result = run_native(image, inspect_pe(image, name), self.persona,
                                    root, [], 10, 100_000)
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertTrue(any("RtlMoveMemory: source belongs to different guest process"
                                    in error for error in result["errors"]))
                self.assertEqual(len(report["entry_points"]), 1)
                denied = [event for event in report["virtual_process_events"]
                          if event["event"] == "virtual_memory_api_denied"]
                self.assertEqual(len(denied), 1)
                self.assertEqual(denied[0]["reason"],
                                 "source belongs to different guest process")
                self.assertFalse(any(event["event"] == "virtual_cpu_memory_denied"
                                     for event in report["virtual_process_events"]))
                writes = [event for event in report["virtual_process_events"]
                          if event["event"] == "virtual_process_memory_write"]
                self.assertEqual(len(writes), 1)
                self.assertTrue(writes[0]["success"])
                if arch == "x64":
                    address = 0x140002400
                    maps = [mapping for mapping in report["entry_points"][-1]["memory"]["layout"]
                            if int(mapping["address"], 16) <= address <
                            int(mapping["address"], 16) + int(mapping["size"], 16)]
                    self.assertEqual(len(maps), 1)
                    offset = address - int(maps[0]["address"], 16)
                    self.assertEqual(_report_blob(report["data"], maps[0]["data_ref"])[offset:offset + 2],
                                     b"\0\0")

    def test_bulk_memory_api_checks_ownership_before_engine_side_effect(self):
        bridge = VirtualProcessBridge(ArtifactCatalog(self.root / "artifacts"))
        parent = SimpleNamespace(pid=1)
        child = SimpleNamespace(pid=2)
        foreign = SimpleNamespace(base=0x1000, size=0x1000, process=child, shared=False)
        local = SimpleNamespace(base=0x3000, size=0x1000, process=parent, shared=False)
        stopped = []
        run = SimpleNamespace(error=None)
        def forbidden(_args):
            self.fail("foreign pointer reached original API handler")
        emu = SimpleNamespace(get_current_process=lambda: parent,
                              get_address_map=lambda address: foreign if 0x1000 <= address < 0x2000
                              else local if 0x3000 <= address < 0x4000 else None,
                              curr_run=run,
                              get_error_info=lambda message, _pc: message,
                              get_pc=lambda: 0x400000,
                              stop=lambda: stopped.append(True))
        self.assertIsNone(bridge._bulk_memory_api(
            emu, "kernel32.RtlMoveMemory", forbidden, [0x3000, 0x1000, 4]))
        self.assertEqual(bridge.events[-1]["reason"],
                         "source belongs to different guest process")
        run.error = None
        self.assertEqual(bridge._bulk_memory_api(
            emu, "msvcrt.memcpy", forbidden, [0x1000, 0x3000, 4]), 0)
        self.assertEqual(bridge.events[-1]["reason"],
                         "destination belongs to different guest process")
        run.error = None
        self.assertIsNone(bridge._bulk_memory_api(
            emu, "ntdll.RtlZeroMemory", forbidden, [0x1000, 4]))
        self.assertEqual(bridge.events[-1]["reason"],
                         "destination belongs to different guest process")
        self.assertEqual(len(stopped), 3)
        run.error = None
        self.assertIsNone(bridge._bulk_memory_api(
            emu, "kernel32.RtlMoveMemory", forbidden,
            [0x3000, 0x3004, MAX_ARTIFACT + 1]))
        self.assertEqual(bridge.events[-1]["reason"],
                         "transfer exceeds guest memory limit")
        written = []
        emu.mem_read = lambda address, size: b"ABCD"[:size]
        emu.mem_write = lambda address, data: written.append((address, data))
        self.assertIsNone(bridge._bulk_memory_api(
            emu, "ntdll.RtlCopyMemory", None, [0x3000, 0x3004, 4]))
        self.assertEqual(written, [(0x3000, b"ABCD")])
        original_calls = []
        self.assertEqual(bridge._bulk_memory_api(
            emu, "msvcrt.memcpy",
            lambda params: original_calls.append(params) or 0x3000,
            [0x3000, 0x3004, 4]), 0x3000)
        self.assertEqual(original_calls, [[0x3000, 0x3004, 4]])
        self.assertEqual(len(stopped), 4)

    def test_string_api_cannot_copy_child_owned_page(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                name = f"child_api_string_{arch}.exe"
                image = (FIXTURES / name).read_bytes()
                result = run_native(image, inspect_pe(image, name), self.persona,
                                    root, [], 10, 100_000)
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertTrue(any("lstrcpyA: source belongs to different guest process"
                                    in error for error in result["errors"]))
                self.assertEqual(len(report["entry_points"]), 1)
                events = report["virtual_process_events"]
                denied = [event for event in events
                          if event["event"] == "virtual_memory_api_denied"]
                self.assertEqual(len(denied), 1)
                self.assertEqual(denied[0]["reason"],
                                 "source belongs to different guest process")
                writes = [event for event in events
                          if event["event"] == "virtual_process_memory_write"]
                self.assertEqual(len(writes), 1)
                self.assertTrue(writes[0]["success"])
                if arch == "x64":
                    address = 0x140002400
                    maps = [mapping for mapping in report["entry_points"][-1]["memory"]["layout"]
                            if int(mapping["address"], 16) <= address <
                            int(mapping["address"], 16) + int(mapping["size"], 16)]
                    self.assertEqual(len(maps), 1)
                    offset = address - int(maps[0]["address"], 16)
                    self.assertEqual(_report_blob(report["data"], maps[0]["data_ref"])[offset:offset + 2],
                                     b"\0\0")

    def test_string_api_can_copy_same_process_page(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                name = f"local_api_string_{arch}.exe"
                image = (FIXTURES / name).read_bytes()
                result = run_native(image, inspect_pe(image, name), self.persona,
                                    root, [], 10, 100_000)
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                self.assertEqual(len(report["entry_points"]), 2)
                calls = [event for event in report["entry_points"][0]["events"]
                         if event.get("api_name") == "kernel32.lstrcpyA"]
                self.assertEqual(len(calls), 1)
                self.assertFalse(any(event["event"] == "virtual_memory_api_denied"
                                     for event in report["virtual_process_events"]))
                if arch == "x64":
                    address = 0x140002400
                    maps = [mapping for mapping in report["entry_points"][-1]["memory"]["layout"]
                            if int(mapping["address"], 16) <= address <
                            int(mapping["address"], 16) + int(mapping["size"], 16)]
                    self.assertEqual(len(maps), 1)
                    offset = address - int(maps[0]["address"], 16)
                    self.assertEqual(_report_blob(report["data"], maps[0]["data_ref"])[offset:offset + 2],
                                     b"MZ")

    def test_string_api_checks_all_bytes_before_engine_side_effect(self):
        bridge = VirtualProcessBridge(ArtifactCatalog(self.root / "artifacts"))
        parent = SimpleNamespace(pid=1)
        child = SimpleNamespace(pid=2)
        local = SimpleNamespace(base=0x3000, size=0x1000, process=parent, shared=False)
        foreign = SimpleNamespace(base=0x4000, size=0x1000, process=child, shared=False)
        memory = {0x3010: b"O", 0x3011: b"K", 0x3012: b"\0",
                  0x3030: b"W\0", 0x3032: b"\0\0", 0x3FFF: b"A"}
        stopped = []
        called = []
        run = SimpleNamespace(error=None)
        def read(address, size):
            self.assertLess(address, 0x4000, "foreign string reached engine read")
            return memory.get(address, b"\0" * size)
        emu = SimpleNamespace(get_current_process=lambda: parent,
                              get_address_map=lambda address:
                              local if 0x3000 <= address < 0x4000 else
                              foreign if 0x4000 <= address < 0x5000 else None,
                              mem_read=read, curr_run=run,
                              get_error_info=lambda message, _pc: message,
                              get_pc=lambda: 0x400000,
                              stop=lambda: stopped.append(True))
        original = lambda params: called.append(params) or params[0]
        self.assertEqual(bridge._string_memory_api(
            emu, "kernel32.lstrcpyA", original, [0x3020, 0x3010]), 0x3020)
        self.assertEqual(called, [[0x3020, 0x3010]])
        self.assertEqual(bridge._string_memory_api(
            emu, "kernel32.lstrlenA", original, [0]), 0)
        self.assertEqual(bridge._string_memory_api(
            emu, "kernel32.lstrlenW", original, [0x3030]), 0x3030)
        self.assertEqual(bridge._string_memory_api(
            emu, "kernel32.lstrcpynA", original, [0x3020, 0x3010, 0]), 0)
        self.assertEqual(bridge.events[-1]["reason"],
                         "copy length exceeds guest string limit")
        self.assertEqual(bridge._string_memory_api(
            emu, "kernel32.lstrcpyA", original, [0x3020, 0x4000]), 0)
        self.assertEqual(bridge.events[-1]["reason"],
                         "source belongs to different guest process")
        self.assertEqual(bridge._string_memory_api(
            emu, "kernel32.lstrcpyA", original, [0x4000, 0x3010]), 0)
        self.assertEqual(bridge.events[-1]["reason"],
                         "destination belongs to different guest process")
        self.assertEqual(bridge._string_memory_api(
            emu, "kernel32.lstrlenA", original, [0x3FFF]), 0)
        self.assertEqual(bridge.events[-1]["reason"],
                         "source belongs to different guest process")
        bridge._released_extents[0x3020] = 4
        self.assertEqual(bridge._string_memory_api(
            emu, "kernel32.lstrcpyA", original, [0x3020, 0x3010]), 0)
        self.assertEqual(bridge.events[-1]["reason"], "destination is released memory")
        self.assertEqual(len(called), 2)
        self.assertEqual(len(stopped), 5)

    def test_dispatch_guard_stops_unhooked_api_handler_foreign_read(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                name = f"child_api_env_{arch}.exe"
                image = (FIXTURES / name).read_bytes()
                result = run_native(image, inspect_pe(image, name), self.persona,
                                    root, [], 10, 100_000)
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertTrue(any("GetEnvironmentVariableA: guest API read denied: "
                                    "different guest process" in error
                                    for error in result["errors"]))
                self.assertEqual(len(report["entry_points"]), 1)
                events = report["virtual_process_events"]
                denied = [event for event in events
                          if event["event"] == "virtual_handler_memory_denied"]
                self.assertEqual(len(denied), 1)
                self.assertEqual((denied[0]["api"], denied[0]["access"],
                                  denied[0]["address"], denied[0]["size"],
                                  denied[0]["reason"]),
                                 ("kernel32.GetEnvironmentVariableA", "read",
                                  0x50000, 1, "different guest process"))
                writes = [event for event in events
                          if event["event"] == "virtual_process_memory_write"]
                self.assertEqual(len(writes), 1)
                self.assertTrue(writes[0]["success"])
                self.assertFalse(any(event["event"] == "virtual_cpu_memory_denied"
                                     for event in events))

    def test_dispatch_guard_preserves_local_environment_read(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                name = f"local_api_env_{arch}.exe"
                image = (FIXTURES / name).read_bytes()
                result = run_native(image, inspect_pe(image, name), self.persona,
                                    root, [], 10, 100_000)
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                self.assertEqual(len(report["entry_points"]), 2)
                calls = [event for event in report["entry_points"][0]["events"]
                         if event.get("api_name") == "kernel32.GetEnvironmentVariableA"]
                self.assertEqual(len(calls), 1)
                self.assertEqual(calls[0]["ret_val"], "0x5")
                self.assertFalse(any(event["event"] == "virtual_handler_memory_denied"
                                     for event in report["virtual_process_events"]))
                if arch == "x64":
                    address = 0x140002400
                    maps = [mapping for mapping in report["entry_points"][-1]["memory"]["layout"]
                            if int(mapping["address"], 16) <= address <
                            int(mapping["address"], 16) + int(mapping["size"], 16)]
                    self.assertEqual(len(maps), 1)
                    offset = address - int(maps[0]["address"], 16)
                    self.assertEqual(_report_blob(report["data"], maps[0]["data_ref"])[offset:offset + 5],
                                     b"Alex\0")

    def test_dispatch_guard_checks_handler_access_before_engine_side_effect(self):
        bridge = VirtualProcessBridge(ArtifactCatalog(self.root / "artifacts"))
        parent = SimpleNamespace(pid=1)
        child = SimpleNamespace(pid=2)
        local = SimpleNamespace(base=0x3000, size=0x1000, process=parent, shared=False)
        foreign = SimpleNamespace(base=0x4000, size=0x1000, process=child, shared=False)
        underlying = []
        stopped = []
        run = SimpleNamespace(error=None)
        emu = SimpleNamespace(get_current_process=lambda: parent,
                              get_address_map=lambda address:
                              local if 0x3000 <= address < 0x4000 else
                              foreign if 0x4000 <= address < 0x5000 else None,
                              curr_run=run,
                              get_error_info=lambda message, _pc: message,
                              get_pc=lambda: 0x3000,
                              stop=lambda: stopped.append(True))
        emu.mem_read = lambda address, size: underlying.append(("read", address, size)) or b"A" * size
        emu.mem_write = lambda address, data: underlying.append(("write", address, bytes(data)))
        def dispatch(_dll, name):
            if name == "Read":
                return emu.mem_read(0x4000, 2)
            if name == "Write":
                return emu.mem_write(0x4000, b"B")
            return emu.mem_read(0x3000, 1)
        emu.handle_import_func = dispatch
        bridge._foreign_allocation_seen = True
        bridge.install_dispatch_memory_guard(emu)
        self.assertIsNone(emu.handle_import_func("test", "Read"))
        self.assertEqual(bridge.events[-1]["access"], "read")
        self.assertIsNone(emu.handle_import_func("test", "Write"))
        self.assertEqual(bridge.events[-1]["access"], "write")
        self.assertEqual(underlying, [])
        self.assertEqual(emu.handle_import_func("test", "Local"), b"A")
        bridge._released_extents[0x3000] = 1
        self.assertIsNone(emu.handle_import_func("test", "Local"))
        self.assertEqual(bridge.events[-1]["reason"], "released memory")
        bridge._released_extents.clear()
        with bridge._allow_api_memory(0x4000, 2, "r"):
            self.assertEqual(emu.handle_import_func("test", "Read"), b"AA")
            self.assertIsNone(emu.handle_import_func("test", "Write"))
        self.assertEqual(underlying, [("read", 0x3000, 1), ("read", 0x4000, 2)])
        self.assertEqual(len(stopped), 4)

    def test_dispatch_guard_assigns_private_api_map_owner(self):
        bridge = VirtualProcessBridge(ArtifactCatalog(self.root / "artifacts"))
        parent = SimpleNamespace(pid=1)
        child = SimpleNamespace(pid=2)
        calls = []
        emu = SimpleNamespace(get_current_process=lambda: parent,
                              mem_read=lambda _address, _size: b"",
                              mem_write=lambda _address, _data: None,
                              mem_map=lambda *args, **kwargs:
                              calls.append((args, kwargs)) or args[1],
                              curr_run=SimpleNamespace(error=None),
                              get_error_info=lambda message, _pc: message,
                              get_pc=lambda: 0x3000,
                              stop=lambda: None)

        def dispatch(_dll, name):
            if name == "Private":
                return emu.mem_map(0x1000, 0x3000)
            if name == "Positional":
                return emu.mem_map(0x1000, 0x4000, 7, None, 0, False, None)
            if name == "Shared":
                return emu.mem_map(0x1000, 0x5000, shared=True)
            if name == "Oversized":
                return emu.mem_map(0x30000000, 0x1000)
            if name == "Reserved":
                return emu.mem_map(0x2000, 0x1000)
            return emu.mem_map(0x1000, 0x6000, process=child)

        emu.handle_import_func = dispatch
        bridge.install_dispatch_memory_guard(emu)
        for name in ("Private", "Positional", "Shared", "Explicit"):
            emu.handle_import_func("test", name)
        emu.mem_map(0x1000, 0x7000)
        self.assertIs(calls[0][1]["process"], parent)
        self.assertIs(calls[1][0][6], parent)
        self.assertTrue(calls[2][1]["shared"])
        self.assertNotIn("process", calls[2][1])
        self.assertIs(calls[3][1]["process"], child)
        self.assertNotIn("process", calls[4][1])
        self.assertIsNone(emu.handle_import_func("test", "Oversized"))
        self.assertEqual(bridge.events[-1]["reason"], "API map size exceeds limit")
        self.assertIsNone(emu.handle_import_func("test", "Reserved"))
        self.assertEqual(bridge.events[-1]["reason"], "untagged API map at reserved page")
        self.assertEqual(len(calls), 5)

    def test_ole32_invalid_pointer_map_is_bounded_and_local_pointer_works(self):
        for arch in ("x86", "x64"):
            for kind in ("child_read", "foreign_write", "local_read"):
                with self.subTest(arch=arch, kind=kind), tempfile.TemporaryDirectory() as folder:
                    root = Path(folder)
                    name = f"private_api_map_{kind}_{arch}.exe"
                    image = (FIXTURES / name).read_bytes()
                    result = run_native(image, inspect_pe(image, name), self.persona,
                                        root, [], 10, 100_000)
                    report = json.loads((root / result["engine_report"]).read_text())
                    entries = report["entry_points"]
                    denied = [event for event in report["virtual_process_events"]
                              if event["event"] == "virtual_handler_memory_denied"]
                    if kind in ("child_read", "foreign_write"):
                        self.assertTrue(result["errors"])
                        self.assertEqual(len(entries), 1)
                        self.assertEqual(len(denied), 1)
                        self.assertEqual((denied[0]["api"], denied[0]["access"],
                                          denied[0]["reason"]),
                                         ("ole32.CoCreateGuid",
                                          "map" if kind == "child_read" else "write",
                                          "API map size exceeds limit" if kind == "child_read"
                                          else "different guest process"))
                        if kind == "child_read":
                            self.assertFalse(any(int(mapping["address"], 16) == 0x30000000
                                                 for mapping in entries[0]["memory"]["layout"]))
                        else:
                            self.assertEqual((denied[0]["address"], denied[0]["size"]),
                                             (0x50000, 16))
                    else:
                        self.assertFalse(result["errors"])
                        self.assertEqual(len(entries), 2)
                        self.assertEqual(entries[0]["ret_val"], "0xdec0adde")
                        self.assertFalse(denied)
                        self.assertTrue(any(event.get("api_name") == "ole32.CoCreateGuid"
                                            and event.get("ret_val") == "0x0"
                                            for event in entries[0]["events"]))

    def test_child_process_structures_have_private_owners(self):
        for arch in ("x86", "x64"):
            for kind in ("peb", "parameters", "ldr", "parent_peb", "parent_ldr"):
                with self.subTest(arch=arch, kind=kind), tempfile.TemporaryDirectory() as folder:
                    root = Path(folder)
                    name = f"child_{kind}_read_{arch}.exe"
                    image = (FIXTURES / name).read_bytes()
                    result = run_native(image, inspect_pe(image, name), self.persona,
                                        root, [], 10, 100_000)
                    report = json.loads((root / result["engine_report"]).read_text())
                    entries = report["entry_points"]
                    self.assertEqual(len(entries), 2)
                    self.assertFalse(entries[0].get("error"))
                    denied = [event for event in report["virtual_process_events"]
                              if event["event"] == "virtual_cpu_memory_denied"]
                    if kind.startswith("parent_"):
                        self.assertTrue(result["errors"])
                        self.assertEqual(len(denied), 1)
                        self.assertEqual((denied[0]["access"], denied[0]["reason"]),
                                         ("read", "different guest process"))
                        self.assertNotEqual(denied[0]["pid"], denied[0]["owner_pid"])
                        self.assertEqual(denied[0]["address"],
                                         0x4040 if kind == "parent_peb" else
                                         0x49F0 if arch == "x64" else 0x4650)
                    else:
                        self.assertFalse(result["errors"])
                        self.assertFalse(entries[1].get("error"))
                        self.assertFalse(denied)
                        self.assertEqual(entries[1]["ret_val"],
                                         "0x118" if kind == "parameters" and arch == "x64"
                                         else "0xb8" if kind == "parameters" else "0x0")

    def test_child_stack_is_private_and_teb_page_is_reset(self):
        for arch in ("x86", "x64"):
            for kind in ("stack", "parent_stack", "teb_leak"):
                with self.subTest(arch=arch, kind=kind), tempfile.TemporaryDirectory() as folder:
                    root = Path(folder)
                    name = f"child_{kind}_read_{arch}.exe" if kind != "teb_leak" else (
                        f"child_teb_leak_{arch}.exe")
                    image = (FIXTURES / name).read_bytes()
                    result = run_native(image, inspect_pe(image, name), self.persona,
                                        root, [], 10, 100_000)
                    report = json.loads((root / result["engine_report"]).read_text())
                    entries = report["entry_points"]
                    self.assertEqual(len(entries), 2)
                    events = report["virtual_process_events"]
                    stacks = [event for event in events
                              if event["event"] == "virtual_process_stack"]
                    resets = [event for event in events
                              if event["event"] == "virtual_process_segment_reset"]
                    self.assertEqual(len(stacks), 1)
                    self.assertEqual((stacks[0]["address"], stacks[0]["size"]),
                                     (0x1400000, 0x100000))
                    self.assertEqual(len(resets), 1)
                    self.assertEqual((resets[0]["address"], resets[0]["size"]),
                                     (0x3000, 0x1000))
                    denied = [event for event in events
                              if event["event"] == "virtual_cpu_memory_denied"]
                    if kind == "parent_stack":
                        self.assertTrue(result["errors"])
                        self.assertEqual(len(denied), 1)
                        self.assertEqual((denied[0]["access"], denied[0]["address"],
                                          denied[0]["reason"]),
                                         ("read", 0x12FFF00, "different guest process"))
                        self.assertNotEqual(denied[0]["pid"], denied[0]["owner_pid"])
                    else:
                        self.assertFalse(result["errors"])
                        self.assertFalse(denied)
                        self.assertEqual(entries[1]["ret_val"],
                                         "0x0" if kind == "teb_leak" else "0xfeedf000")

    def test_open_process_rights_and_independent_closes(self):
        expected = [
            ("virtual_process_open", True, None),
            ("virtual_process_open", True, None),
            ("virtual_process_memory_write", False, "process handle lacks write rights"),
            ("virtual_process_allocate", False, "process handle lacks VM operation rights"),
            ("virtual_process_memory_read", False, "process handle lacks read rights"),
            ("virtual_process_close", True, None),
            ("virtual_process_allocate", False, "invalid process handle"),
            ("virtual_process_allocate", True, None),
            ("virtual_process_close", True, None),
            ("virtual_thread_exit", True, "ExitProcess"),
            ("virtual_process_exit", True, None),
            ("virtual_process_cleanup", True, None),
        ]
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                name = f"process_access_{arch}.exe"
                image = (FIXTURES / name).read_bytes()
                result = run_native(image, inspect_pe(image, name), self.persona,
                                    root, [], 10, 100_000)
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                self.assertEqual(report["entry_points"][0]["ret_val"], "0x1")
                events = report["virtual_process_events"]
                self.assertEqual([(item["event"], item["success"], item.get("reason"))
                                  for item in events], expected)
                self.assertEqual([item["requested_access"] for item in events
                                  if item["event"] == "virtual_process_open"], [0x10, 0x08])
                self.assertNotEqual(events[0]["handle"], events[1]["handle"])

    def test_duplicate_guest_process_handle_can_recheck_own_access(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                name = f"process_duplicate_{arch}.exe"
                image = (FIXTURES / name).read_bytes()
                result = run_native(image, inspect_pe(image, name), self.persona,
                                    root, [], 10, 100_000)
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                self.assertEqual(report["entry_points"][0]["ret_val"], "0x1")
                events = report["virtual_process_events"]
                duplicates = [item for item in events
                              if item["event"] == "virtual_process_handle_duplicate"]
                self.assertEqual([item["success"] for item in duplicates], [True, True])
                self.assertEqual(duplicates[0]["granted_access"], 0x38)
                self.assertEqual(duplicates[1]["granted_access"], PROCESS_VM_READ)
                self.assertNotEqual(duplicates[1]["handle"], events[0]["handle"])
                self.assertEqual([item["success"] for item in events
                                  if item["event"] == "virtual_process_close"], [True, True, True])
                writes = [item for item in events if item["event"] == "virtual_process_memory_write"]
                self.assertEqual(len(writes), 1)
                self.assertTrue(writes[0]["success"])
                reads = [item for item in events if item["event"] == "virtual_process_memory_read"]
                self.assertEqual(len(reads), 1)
                self.assertTrue(reads[0]["success"])
                self.assertEqual(reads[0]["sha256"], hashlib.sha256(b"MZ").hexdigest())
                self.assertTrue(any(item["source"] == "process_memory_read"
                                    and (root / "artifacts" / item["file"]).read_bytes() == b"MZ"
                                    for item in result["artifacts"]))

    def test_duplicate_guest_process_requires_duplicate_right_on_process_handles(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                name = f"process_duplicate_rights_{arch}.exe"
                image = (FIXTURES / name).read_bytes()
                result = run_native(image, inspect_pe(image, name), self.persona,
                                    root, [], 10, 100_000)
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                self.assertEqual(report["entry_points"][0]["ret_val"], "0x1")
                duplicates = [item for item in report["virtual_process_events"]
                              if item["event"] == "virtual_process_handle_duplicate"]
                self.assertEqual([item["success"] for item in duplicates],
                                 [False, False, True, True])
                self.assertEqual([item["reason"] for item in duplicates[:2]],
                                 ["source process handle lacks duplicate right",
                                  "target process handle lacks duplicate right"])
                self.assertTrue(any(item["source"] == "process_memory_read"
                                    and (root / "artifacts" / item["file"]).read_bytes() == b"MZ"
                                    for item in result["artifacts"]))

    def test_guest_remote_thread_runs_only_when_runnable(self):
        for arch in ("x86", "x64"):
            for mode in ("", "_suspended", "_resumed"):
                with self.subTest(arch=arch, mode=mode), tempfile.TemporaryDirectory() as folder:
                    root = Path(folder)
                    name = f"child_remote_thread{mode}_{arch}.exe"
                    image = (FIXTURES / name).read_bytes()
                    result = run_native(image, inspect_pe(image, name), self.persona,
                                        root, [], 10, 100_000)
                    report = json.loads((root / result["engine_report"]).read_text())
                    self.assertFalse(result["errors"])
                    entries = report["entry_points"]
                    self.assertEqual(len(entries), 2 if mode == "_suspended" else 3)
                    self.assertFalse(any(entry.get("error") for entry in entries))
                    injected = [entry for entry in entries if str(entry.get("ep_type", "")).startswith(
                        "injected_thread_")]
                    self.assertEqual(len(injected), 0 if mode == "_suspended" else 1)
                    if injected:
                        self.assertEqual(injected[0]["ret_val"], "0x0")
                    events = report["virtual_process_events"]
                    stacks = [item for item in events
                              if item["event"] == "virtual_process_stack"]
                    segments = [item for item in events
                                if item["event"] == "virtual_process_segment_reset"]
                    self.assertEqual(len(stacks), 1 if mode == "_suspended" else 2)
                    self.assertEqual(len(segments), len(stacks))
                    self.assertEqual(len({item["address"] for item in stacks}), len(stacks))
                    self.assertTrue(all(item["address"] != 0x1200000 and
                                        item["size"] == 0x100000 for item in stacks))
                    threads = [item for item in events
                               if item["event"] == "virtual_remote_thread_create"]
                    self.assertEqual(len(threads), 1)
                    self.assertTrue(threads[0]["success"])
                    self.assertEqual(threads[0]["flags"], 0 if not mode else 4)
                    writes = [item for item in events
                              if item["event"] == "virtual_process_memory_write"]
                    self.assertEqual(len(writes), 2)
                    self.assertEqual(writes[1]["sha256"], hashlib.sha256(b"\x31\xc0\xc3").hexdigest())
                    self.assertTrue(any(item["source"] == "process_memory_write"
                                        and (root / "artifacts" / item["file"]).read_bytes() == b"\x31\xc0\xc3"
                                        for item in result["artifacts"]))
                    resumes = [item for item in events if item["event"] == "virtual_thread_resume"]
                    self.assertEqual(len(resumes), 1 if mode == "_resumed" else 0)
                    if resumes:
                        self.assertEqual(resumes[0]["previous_suspend_count"], 1)
                        self.assertEqual(resumes[0]["suspend_count"], 0)

    def test_remote_thread_teb_is_private(self):
        for arch in ("x86", "x64"):
            for mode in ("read", "write"):
                with self.subTest(arch=arch, mode=mode), tempfile.TemporaryDirectory() as folder:
                    root = Path(folder)
                    name = f"child_remote_teb_{mode}_{arch}.exe"
                    image = (FIXTURES / name).read_bytes()
                    result = run_native(image, inspect_pe(image, name), self.persona,
                                        root, [], 10, 100_000)
                    report = json.loads((root / result["engine_report"]).read_text())
                    self.assertFalse(result["errors"])
                    entries = report["entry_points"]
                    self.assertEqual(len(entries), 3)
                    self.assertFalse(any(entry.get("error") for entry in entries))
                    self.assertEqual([entry["ret_val"] for entry in entries[1:]],
                                     ["0x0", "0x0"])
                    events = report["virtual_process_events"]
                    stacks = [item for item in events
                              if item["event"] == "virtual_process_stack"]
                    switches = [item for item in events
                                if item["event"] == "virtual_process_segment_reset"]
                    self.assertEqual(len(stacks), 2)
                    self.assertEqual(len(switches), 2)
                    self.assertEqual(len({item["address"] for item in stacks}), 2)
                    self.assertNotEqual(stacks[0]["tid"], stacks[1]["tid"])
                    self.assertFalse(any(item["event"] == "virtual_cpu_memory_denied"
                                         for item in events))
                    remote_code = (
                        (b"\x65\x8b\x04\x25\0\x02\0\0\xc3" if arch == "x64" else
                         b"\x64\xa1\0\x02\0\0\xc3") if mode == "read" else
                        (b"\x65\xc7\x04\x25\0\x02\0\0\x44\x33\x22\x11\x31\xc0\xc3"
                         if arch == "x64" else
                         b"\x64\xc7\x05\0\x02\0\0\x44\x33\x22\x11\x31\xc0\xc3"))
                    writes = [item for item in events
                              if item["event"] == "virtual_process_memory_write"]
                    self.assertEqual(writes[-1]["sha256"],
                                     hashlib.sha256(remote_code).hexdigest())

    def test_process_memory_write_bounds_before_guest_memory_access(self):
        bridge = VirtualProcessBridge(ArtifactCatalog(self.root / "artifacts"))
        errors = []
        process = SimpleNamespace(pid=123, path=r"C:\guest.exe")
        emu = SimpleNamespace(get_ptr_size=lambda: 8,
                              get_current_process=lambda: process,
                              get_object_from_handle=lambda _: None,
                              set_last_error=errors.append,
                              mem_read=lambda *_: self.fail("oversized read reached guest memory"))
        def forbidden(_params):
            self.fail("invalid write reached the engine")
        self.assertEqual(bridge._write_process_memory(
            emu, "kernel32.WriteProcessMemory", forbidden,
            [0xBAD, 0x1000, 0x2000, MAX_ARTIFACT + 1, 0]), 0)
        self.assertEqual(errors[-1], 6)
        self.assertEqual(bridge._write_process_memory(
            emu, "kernel32.WriteProcessMemory", forbidden,
            [0xFFFFFFFFFFFFFFFF, 0x1000, 0x2000, MAX_ARTIFACT + 1, 0]), 0)
        self.assertEqual(errors[-1], 223)
        self.assertTrue(bridge.unsupported)

    def test_process_memory_read_bounds_before_guest_memory_access(self):
        bridge = VirtualProcessBridge(ArtifactCatalog(self.root / "artifacts"))
        errors = []
        process = SimpleNamespace(pid=123, path=r"C:\guest.exe")
        emu = SimpleNamespace(get_ptr_size=lambda: 8,
                              get_current_process=lambda: process,
                              get_object_from_handle=lambda _: None,
                              set_last_error=errors.append,
                              mem_read=lambda *_: self.fail("invalid read reached guest memory"))
        def forbidden(_params):
            self.fail("invalid read reached the engine")
        self.assertEqual(bridge._read_process_memory(
            emu, "kernel32.ReadProcessMemory", forbidden,
            [0xBAD, 0x1000, 0x2000, MAX_ARTIFACT + 1, 0]), 0)
        self.assertEqual(errors[-1], 6)
        self.assertEqual(bridge._read_process_memory(
            emu, "kernel32.ReadProcessMemory", forbidden,
            [0xFFFFFFFFFFFFFFFF, 0x1000, 0x2000, MAX_ARTIFACT + 1, 0]), 0)
        self.assertEqual(errors[-1], 223)
        self.assertTrue(bridge.unsupported)

    def test_guest_thread_handles_enforce_rights_and_independent_close(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch):
                result = self.native(f"thread_handles_{arch}.exe")
                report = json.loads((self.root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                self.assertEqual(report["entry_points"][0]["ret_val"], "0x1")
                events = report["virtual_process_events"]
                opened = [event for event in events if event["event"] == "virtual_thread_open"]
                self.assertEqual(len(opened), 1)
                self.assertTrue(opened[0]["success"])
                self.assertEqual(opened[0]["requested_access"], 0x40)
                duplicate = [event for event in events
                             if event["event"] == "virtual_process_handle_duplicate"]
                self.assertEqual(len(duplicate), 1)
                self.assertTrue(duplicate[0]["success"])
                self.assertEqual(duplicate[0]["object_type"], "thread")
                self.assertEqual(duplicate[0]["granted_access"], 2)
                resumes = [event for event in events if event["event"] == "virtual_thread_resume"]
                self.assertEqual([event["success"] for event in resumes],
                                 [False, False, False, True])
                self.assertEqual(resumes[-1]["previous_suspend_count"], 1)
                closes = [event for event in events if event["event"] == "virtual_thread_close"]
                self.assertEqual(len(closes), 3)
                self.assertTrue(all(event["success"] for event in closes))

    def test_process_bridge_rejects_unissued_and_closed_object_handles(self):
        bridge = VirtualProcessBridge(ArtifactCatalog(self.root / "artifacts"))
        process = SimpleNamespace(pid=123, path=r"C:\guest.exe", handles=[0x200])
        thread = SimpleNamespace(tid=456, process=process, suspend_count=0,
                                 handles=[0x300])
        objects = {0x200: process, 0x300: thread}
        errors = []
        emu = SimpleNamespace(get_ptr_size=lambda: 4,
                              get_current_process=lambda: process,
                              get_object_from_handle=objects.get,
                              set_last_error=errors.append)
        self.assertIsNone(bridge._process(emu, 0x200))
        self.assertIsNone(bridge._thread(emu, 0x300))
        self.assertEqual(bridge.close_process_handle(emu, 0x200), 0)
        self.assertEqual(errors[-1], 6)
        self.assertEqual(bridge.events[-1]["reason"], "unissued guest handle")
        bridge.process_handle_owners[0x200] = id(process)
        bridge.thread_handle_owners[0x300] = id(process)
        self.assertIs(bridge._process(emu, 0x200), process)
        self.assertIs(bridge._thread(emu, 0x300), thread)
        self.assertEqual(bridge.close_process_handle(emu, 0x200), 1)
        self.assertIsNone(bridge._process(emu, 0x200))
        self.assertEqual(bridge.close_process_handle(emu, 0x200), 0)
        self.assertEqual(bridge.events[-1]["reason"], "already closed")

    def test_resume_thread_keeps_nested_suspend_counts_dormant(self):
        bridge = VirtualProcessBridge(ArtifactCatalog(self.root / "artifacts"))
        process = SimpleNamespace(pid=123)
        thread = SimpleNamespace(tid=456, suspend_count=2, process=process)
        errors = []
        emu = SimpleNamespace(get_object_from_handle=lambda _: thread,
                              get_current_process=lambda: process,
                              child_processes=[], set_last_error=errors.append)
        bridge.thread_handle_owners[0x200] = id(process)
        def forbidden(_params):
            self.fail("dormant or already running thread reached engine resume")
        self.assertEqual(bridge._resume_thread(emu, "kernel32.ResumeThread",
                                               forbidden, [0x200]), 2)
        self.assertEqual(thread.suspend_count, 1)
        self.assertEqual(bridge._resume_thread(emu, "kernel32.ResumeThread",
                                               lambda _: setattr(thread, "suspend_count", 0) or 1,
                                               [0x200]), 1)
        self.assertEqual(bridge._resume_thread(emu, "kernel32.ResumeThread",
                                               forbidden, [0x200]), 0)
        self.assertEqual([event["previous_suspend_count"] for event in bridge.events],
                         [2, 1, 0])

    def test_terminate_thread_checks_owner_rights_and_cancels_pending_run(self):
        bridge = VirtualProcessBridge(ArtifactCatalog(self.root / "artifacts"))
        parent = SimpleNamespace(pid=10)
        child = SimpleNamespace(pid=11)
        thread = SimpleNamespace(tid=31, suspend_count=1, process=child)
        child.threads = [thread]
        current = [parent]
        queued = SimpleNamespace(thread=thread)
        other = SimpleNamespace(thread=object())
        errors, killed, exited, writes = [], [], [], {}
        emu = SimpleNamespace(get_current_process=lambda: current[0],
                              get_current_thread=lambda: None,
                              get_object_from_handle=lambda handle: thread if handle == 0x220 else None,
                              set_last_error=errors.append,
                              mem_read=lambda address, size: b"\0" * size,
                              mem_write=lambda address, data: writes.__setitem__(address, data),
                              run_queue=[queued, other], suspended_runs=[queued],
                              child_processes=[], kill_process=killed.append,
                              exit_process=lambda: exited.append(True))
        bridge.created_processes.add(id(child))
        forbidden = lambda _: self.fail("thread operation reached engine handler")
        args = [0x220, 7]
        self.assertEqual(bridge._terminate_thread(
            emu, "kernel32.TerminateThread", forbidden, args), 0)
        self.assertEqual(errors[-1], 6)
        self.assertEqual(bridge._get_exit_code_thread(
            emu, "kernel32.GetExitCodeThread", forbidden, [0x220, 0x1000]), 0)
        self.assertEqual(errors[-1], 6)
        bridge.thread_handle_owners[0x220] = id(parent)
        bridge.thread_access[0x220] = THREAD_TERMINATE
        self.assertEqual(bridge._get_exit_code_thread(
            emu, "kernel32.GetExitCodeThread", forbidden, [0x220, 0x1000]), 0)
        self.assertEqual(errors[-1], 5)
        bridge.thread_access[0x220] = THREAD_QUERY_LIMITED_INFORMATION
        self.assertEqual(bridge._terminate_thread(
            emu, "kernel32.TerminateThread", forbidden, args), 0)
        self.assertEqual(errors[-1], 5)
        bridge.thread_access[0x220] |= THREAD_TERMINATE
        self.assertEqual(bridge._get_exit_code_thread(
            emu, "kernel32.GetExitCodeThread", forbidden, [0x220, 0]), 0)
        self.assertEqual(errors[-1], 87)
        self.assertEqual(bridge._get_exit_code_thread(
            emu, "kernel32.GetExitCodeThread", forbidden, [0x220, 0x1000]), 1)
        self.assertEqual(int.from_bytes(writes[0x1000], "little"), 259)
        current[0] = child
        self.assertEqual(bridge._terminate_thread(
            emu, "kernel32.TerminateThread", forbidden, args), 0)
        self.assertEqual(errors[-1], 6)
        current[0] = parent
        self.assertEqual(bridge._terminate_thread(
            emu, "kernel32.TerminateThread", forbidden, args), 1)
        self.assertEqual(emu.run_queue, [other])
        self.assertEqual(emu.suspended_runs, [])
        self.assertEqual(killed, [])
        self.assertEqual(exited, [])
        self.assertEqual(bridge._get_exit_code_thread(
            emu, "kernel32.GetExitCodeThread", forbidden, [0x220, 0x1000]), 1)
        self.assertEqual(int.from_bytes(writes[0x1000], "little"), 7)
        self.assertEqual(bridge._terminate_thread(
            emu, "kernel32.TerminateThread", forbidden, args), 0)
        self.assertEqual(errors[-1], 5)

    def test_terminate_child_primary_thread_cancels_child_and_self_run(self):
        bridge = VirtualProcessBridge(ArtifactCatalog(self.root / "artifacts"))
        parent = SimpleNamespace(pid=10)
        child = SimpleNamespace(pid=11)
        child_thread = SimpleNamespace(tid=31, suspend_count=1, process=child,
                                       handles=[0x220])
        parent_thread = SimpleNamespace(tid=32, suspend_count=0, process=parent,
                                        handles=[0x224])
        child.threads = [child_thread]
        parent.threads = [parent_thread]
        current = [parent_thread]
        errors, killed, exited = [], [], []
        emu = SimpleNamespace(get_current_process=lambda: current[0].process,
                              get_current_thread=lambda: current[0],
                              get_object_from_handle=lambda handle: {
                                  0x220: child_thread, 0x224: parent_thread}.get(handle),
                              set_last_error=errors.append,
                              run_queue=[SimpleNamespace(thread=parent_thread)],
                              suspended_runs=[], child_processes=[child],
                              kill_process=killed.append,
                              exit_process=lambda: exited.append(True))
        bridge.created_processes.add(id(child))
        bridge.thread_handle_owners.update({0x220: id(parent), 0x224: id(parent)})
        forbidden = lambda _: self.fail("thread operation reached engine handler")
        self.assertEqual(bridge._terminate_thread(
            emu, "kernel32.TerminateThread", forbidden, [0x220, 3]), 1)
        self.assertEqual(emu.child_processes, [])
        self.assertEqual(killed, [child])
        self.assertEqual(bridge.process_exit_codes[id(child)], 3)
        self.assertEqual(exited, [])
        self.assertEqual(bridge._terminate_thread(
            emu, "kernel32.TerminateThread", forbidden, [0x224, 9]), 1)
        self.assertEqual(emu.run_queue, [])
        self.assertEqual(exited, [True])

    def test_native_terminate_suspended_thread_prevents_execution(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch):
                result = self.native(f"thread_termination_{arch}.exe")
                report = json.loads((self.root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                entries = report["entry_points"]
                self.assertEqual(len(entries), 1)
                exits = [item for item in entries[0]["events"]
                         if item.get("api_name") == "kernel32.ExitProcess"]
                self.assertEqual(len(exits), 1)
                self.assertEqual(exits[0]["args"], ["0x1"])
                events = report["virtual_process_events"]
                termination = [item for item in events
                               if item["event"] == "virtual_thread_terminate"]
                self.assertEqual(len(termination), 1)
                self.assertTrue(termination[0]["success"])
                self.assertEqual(termination[0]["exit_code"], 7)
                self.assertEqual(termination[0]["cancelled_runs"], 1)
                status = [item for item in events
                          if item["event"] == "virtual_thread_exit_code"]
                self.assertEqual(len(status), 1)
                self.assertEqual(status[0]["exit_code"], 7)

    def test_native_returned_thread_is_signaled_with_return_status(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch):
                result = self.native(f"thread_return_wait_{arch}.exe")
                report = json.loads((self.root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                entries = report["entry_points"]
                self.assertEqual(len(entries), 3)
                self.assertEqual(entries[1]["ret_val"], "0x2a")
                exits = [item for item in entries[2]["events"]
                         if item.get("api_name") == "kernel32.ExitProcess"]
                self.assertEqual(len(exits), 1)
                self.assertEqual(exits[0]["args"], ["0x1"])
                events = report["virtual_process_events"]
                statuses = [item for item in events
                            if item["event"] == "virtual_thread_exit_code"]
                self.assertEqual(len(statuses), 1)
                self.assertEqual(statuses[0]["exit_code"], 42)
                waits = [item for item in events
                         if item["event"] == "virtual_object_wait"]
                self.assertEqual(len(waits), 1)
                self.assertEqual(waits[0]["result"], 0)

    def test_wait_on_guest_thread_and_process_checks_owner_rights_and_state(self):
        bridge = VirtualProcessBridge(ArtifactCatalog(self.root / "artifacts"))
        parent = SimpleNamespace(pid=10, path=r"C:\parent.exe")
        child = SimpleNamespace(pid=11, path=r"C:\child.exe")
        thread = SimpleNamespace(tid=31, suspend_count=0, process=child)
        current = [parent]
        objects = {0x220: thread, 0x224: child}
        errors = []
        emu = SimpleNamespace(get_ptr_size=lambda: 8,
                              get_current_process=lambda: current[0],
                              get_current_thread=lambda: None,
                              get_object_from_handle=objects.get,
                              set_last_error=errors.append,
                              run_queue=[], suspended_runs=[])
        forbidden = lambda _: self.fail("wait reached engine's unconditional-success handler")
        wait = lambda handle, timeout: bridge._wait_for_single_object(
            emu, "kernel32.WaitForSingleObject", forbidden, [handle, timeout])
        self.assertEqual(wait(0x220, 0), WAIT_FAILED)
        self.assertEqual(errors[-1], 6)
        bridge.thread_handle_owners[0x220] = id(parent)
        bridge.thread_access[0x220] = THREAD_QUERY_LIMITED_INFORMATION
        self.assertEqual(wait(0x220, 0), WAIT_FAILED)
        self.assertEqual(errors[-1], 5)
        bridge.thread_access[0x220] |= SYNCHRONIZE
        self.assertEqual(wait(0x220, 0), WAIT_TIMEOUT)
        self.assertEqual(wait(0x220, 0xFFFFFFFF), WAIT_FAILED)
        self.assertEqual(errors[-1], 50)
        bridge.terminated_threads.add(id(thread))
        bridge.thread_exit_codes[id(thread)] = 7
        self.assertEqual(wait(0x220, 0), 0)
        self.assertEqual(wait(0x220, 0xFFFFFFFF), 0)
        current[0] = child
        self.assertEqual(wait(0x220, 0), WAIT_FAILED)
        self.assertEqual(errors[-1], 6)
        current[0] = parent
        self.assertEqual(wait(0x224, 0), WAIT_FAILED)
        self.assertEqual(errors[-1], 6)
        bridge.process_handle_owners[0x224] = id(parent)
        bridge.process_access[0x224] = PROCESS_QUERY_LIMITED_INFORMATION
        self.assertEqual(wait(0x224, 0), WAIT_FAILED)
        self.assertEqual(errors[-1], 5)
        bridge.process_access[0x224] |= SYNCHRONIZE
        self.assertEqual(wait(0x224, 0), WAIT_TIMEOUT)
        bridge.terminated_processes.add(id(child))
        bridge.process_exit_codes[id(child)] = 9
        self.assertEqual(wait(0x224, 0), 0)

    def test_last_runnable_thread_sets_guest_process_exit_status(self):
        bridge = VirtualProcessBridge(ArtifactCatalog(self.root / "artifacts"))
        process = SimpleNamespace(pid=10, path=r"C:\guest.exe")
        first = SimpleNamespace(tid=21, process=process)
        second = SimpleNamespace(tid=22, process=process)
        current = [first]
        emu = SimpleNamespace(get_current_process=lambda: process,
                              get_current_thread=lambda: current[0],
                              run_queue=[SimpleNamespace(thread=second,
                                                         process_context=process)],
                              suspended_runs=[])
        bridge._record_thread_exit(emu, first, 3, "ExitThread")
        self.assertNotIn(id(process), bridge.terminated_processes)
        self.assertEqual(bridge.thread_exit_codes[id(first)], 3)
        emu.run_queue.clear()
        current[0] = second
        bridge._record_thread_exit(emu, second, 42, "thread_return")
        self.assertIn(id(process), bridge.terminated_processes)
        self.assertEqual(bridge.process_exit_codes[id(process)], 42)

    def test_child_cannot_terminate_parent_with_unowned_thread_handle(self):
        for arch, machine in (("x86", 0x14C), ("x64", 0x8664)):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                name = f"child_parent_thread_terminate_foreign_{arch}.exe"
                image = (FIXTURES / name).read_bytes()
                dll = root / f"companion_{arch}.dll"
                dll.write_bytes(build_relocatable_companion(
                    machine, 0x180000000 if arch == "x64" else 0x50000000))
                result = run_native(image, inspect_pe(image, name), self.persona,
                                    root, [dll], 10, 200_000)
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                entries = report["entry_points"]
                self.assertEqual(len(entries), 3)
                self.assertEqual(entries[2]["ret_val"], "0x0")
                attempts = [item for item in report["virtual_process_events"]
                            if item["event"] == "virtual_thread_terminate"]
                self.assertEqual(len(attempts), 1)
                self.assertFalse(attempts[0]["success"])
                self.assertEqual(attempts[0]["reason"], "invalid thread handle")
                self.assertTrue(any(item.get("api_name") == "kernel32.TerminateThread"
                                    and item.get("ret_val") == "0x0"
                                    for item in entries[2]["events"]))

    def test_remote_thread_rejects_invalid_handle_and_unsupported_flags(self):
        bridge = VirtualProcessBridge(ArtifactCatalog(self.root / "artifacts"))
        errors = []
        process = SimpleNamespace(pid=123, path=r"C:\guest.exe", id=123)
        emu = SimpleNamespace(get_ptr_size=lambda: 8,
                              get_current_process=lambda: process,
                              get_object_from_handle=lambda _: None,
                              get_address_map=lambda _: None,
                              set_last_error=errors.append)
        def forbidden(_params):
            self.fail("invalid thread reached the engine")
        args = [0xBAD, 0, 0, 0x1000, 0, 0, 0]
        self.assertEqual(bridge._create_remote_thread(
            emu, "kernel32.CreateRemoteThread", forbidden, args), 0)
        self.assertEqual(errors[-1], 6)
        args[0] = 0xFFFFFFFFFFFFFFFF
        args[5] = 0x80000000
        self.assertEqual(bridge._create_remote_thread(
            emu, "kernel32.CreateRemoteThread", forbidden, args), 0)
        self.assertEqual(errors[-1], 87)
        self.assertTrue(bridge.unsupported)
        bridge.events = [{"event": "virtual_remote_thread_create", "success": True}
                         for _ in range(64)]
        args[5] = 0
        self.assertEqual(bridge._create_remote_thread(
            emu, "kernel32.CreateRemoteThread", forbidden, args), 0)
        self.assertEqual(errors[-1], 8)
        bridge.events.clear()
        args[6] = 0x1234
        emu.mem_read = lambda *_: (_ for _ in ()).throw(ValueError("unmapped guest pointer"))
        self.assertEqual(bridge._create_remote_thread(
            emu, "kernel32.CreateRemoteThread", forbidden, args), 0)
        self.assertEqual(errors[-1], 87)

    def test_guest_memory_api_rejects_known_foreign_mappings(self):
        bridge = VirtualProcessBridge(ArtifactCatalog(self.root / "artifacts"))
        parent = SimpleNamespace(pid=1, path=r"C:\parent.exe", id=1)
        child = SimpleNamespace(pid=2, path=r"C:\child.exe", id=2)
        mapping = SimpleNamespace(base=0x1000, size=0x1000, process=parent, shared=False)
        errors = []
        emu = SimpleNamespace(get_ptr_size=lambda: 8,
                              get_current_process=lambda: parent,
                              get_object_from_handle=lambda _: child,
                              get_address_map=lambda address: mapping if 0x1000 <= address < 0x2000 else None,
                              set_last_error=errors.append,
                              mem_read=lambda *_: self.fail("foreign memory was read"))
        bridge.process_handle_owners[0xABCD] = id(parent)
        def forbidden(_params):
            self.fail("foreign memory reached the engine")
        self.assertEqual(bridge._write_process_memory(
            emu, "kernel32.WriteProcessMemory", forbidden,
            [0xABCD, 0x1000, 0x3000, 16, 0]), 0)
        self.assertEqual(bridge.events[-1]["reason"], "memory belongs to different guest process")
        self.assertEqual(bridge._read_process_memory(
            emu, "kernel32.ReadProcessMemory", forbidden,
            [0xABCD, 0x1000, 0x3000, 16, 0]), 0)
        self.assertEqual(bridge.events[-1]["reason"], "memory belongs to different guest process")
        self.assertEqual(bridge._create_remote_thread(
            emu, "kernel32.CreateRemoteThread", forbidden,
            [0xABCD, 0, 0, 0x1000, 0, 0, 0]), 0)
        self.assertEqual(bridge.events[-1]["reason"],
                         "start address belongs to different guest process")
        self.assertEqual(bridge._virtual_alloc_ex(
            emu, "kernel32.VirtualAllocEx", forbidden,
            [0xABCD, 0x1000, 0x1000, 0x3000, 4]), 0)
        self.assertEqual(bridge.events[-1]["reason"],
                         "requested address belongs to different guest process")
        self.assertEqual(bridge._virtual_protect_ex(
            emu, "kernel32.VirtualProtectEx", forbidden,
            [0xABCD, 0x1000, 0x1000, 0x40, 0x3000]), 0)
        self.assertEqual(bridge.events[-1]["reason"],
                         "memory belongs to different guest process")
        self.assertEqual(errors, [299, 299, 487, 487, 487])
        self.assertTrue(bridge.unsupported)

    def test_local_virtualprotect_cannot_change_foreign_guest_mapping(self):
        for pointer_size in (4, 8):
            with self.subTest(pointer_size=pointer_size):
                bridge = VirtualProcessBridge(ArtifactCatalog(self.root / "artifacts"))
                parent = SimpleNamespace(pid=1, path=r"C:\parent.exe", id=1)
                child = SimpleNamespace(pid=2, path=r"C:\child.exe", id=2)
                mapping = SimpleNamespace(base=0x1000, size=0x1000,
                                          process=child, shared=False)
                errors = []
                emu = SimpleNamespace(
                    get_ptr_size=lambda: pointer_size,
                    get_current_process=lambda: parent,
                    get_address_map=lambda address: mapping if 0x1000 <= address < 0x2000 else None,
                    set_last_error=errors.append,
                    mem_read=lambda *_: self.fail("foreign memory reached engine"))
                self.assertEqual(bridge._virtual_protect(
                    emu, "kernel32.VirtualProtect",
                    lambda _params: self.fail("foreign mapping changed"),
                    [0x1000, 0x1000, 0x40, 0x3000]), 0)
                self.assertEqual(errors, [487])
                self.assertEqual(bridge.events[-1]["reason"],
                                 "memory belongs to different guest process")

    def test_local_virtualprotect_keeps_own_guest_page_usable(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                exe = FIXTURES / f"local_virtualprotect_{arch}.exe"
                data = exe.read_bytes()
                result = run_native(data, inspect_pe(data, exe.name), self.persona,
                                    root, [], 10, 100_000)
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                self.assertEqual(report["entry_points"][0]["ret_val"], "0x1")
                protections = [event for event in report["virtual_process_events"]
                               if event["event"] == "virtual_process_protect"]
                self.assertEqual(len(protections), 1)
                self.assertTrue(protections[0]["success"])

    def test_process_memory_byte_count_outputs_must_belong_to_caller(self):
        bridge = VirtualProcessBridge(ArtifactCatalog(self.root / "artifacts"))
        parent = SimpleNamespace(pid=1, path=r"C:\parent.exe", id=1)
        child = SimpleNamespace(pid=2, path=r"C:\child.exe", id=2)
        local = SimpleNamespace(base=0x3000, size=0x1000, process=parent, shared=False)
        foreign = SimpleNamespace(base=0x1000, size=0x1000, process=child, shared=False)
        errors = []
        emu = SimpleNamespace(get_ptr_size=lambda: 8,
                              get_current_process=lambda: parent,
                              get_object_from_handle=lambda _: child,
                              get_address_map=lambda address:
                              local if 0x3000 <= address < 0x4000 else
                              foreign if 0x1000 <= address < 0x2000 else None,
                              set_last_error=errors.append,
                              mem_read=lambda *_: self.fail("foreign output pointer reached memory"))
        bridge.process_handle_owners[0xABCD] = id(parent)
        def forbidden(_params):
            self.fail("foreign output pointer reached engine")
        self.assertEqual(bridge._write_process_memory(
            emu, "kernel32.WriteProcessMemory", forbidden,
            [0xABCD, 0x1000, 0x3000, 16, 0x1008]), 0)
        self.assertEqual(bridge._read_process_memory(
            emu, "kernel32.ReadProcessMemory", forbidden,
            [0xABCD, 0x1000, 0x3000, 16, 0x1008]), 0)
        self.assertEqual([event["reason"] for event in bridge.events],
                         ["memory belongs to different guest process"] * 2)
        self.assertEqual(errors, [299, 299])

    def test_virtual_free_ex_checks_rights_base_owner_and_released_memory(self):
        bridge = VirtualProcessBridge(ArtifactCatalog(self.root / "artifacts"))
        parent = SimpleNamespace(pid=1, path=r"C:\parent.exe")
        child = SimpleNamespace(pid=2, path=r"C:\child.exe")
        mapping = SimpleNamespace(base=0x1000, size=0x1000, process=child,
                                  tag="api.VirtualAllocEx.child_exe.2", free=False)
        errors = []
        emu = SimpleNamespace(get_ptr_size=lambda: 8,
                              get_current_process=lambda: parent,
                              get_object_from_handle=lambda handle: child if handle == 0x200 else None,
                              get_address_map=lambda address: mapping if 0x1000 <= address < 0x2000 else None,
                              mem_free=lambda address: setattr(mapping, "free", True),
                              set_last_error=errors.append,
                              mem_read=lambda *_: self.fail("released memory was read"))
        def forbidden(_params):
            self.fail("unvalidated guest memory reached the engine")
        args = [0x200, 0x1000, 0, 0x8000]
        bridge.process_handle_owners[0x200] = id(parent)
        bridge.process_access[0x200] = PROCESS_VM_READ
        self.assertEqual(bridge._virtual_free_ex(emu, "kernel32.VirtualFreeEx", forbidden, args), 0)
        self.assertEqual(errors[-1], 5)
        bridge.process_access[0x200] = 0x8
        for invalid, error in (([0xBAD, 0x1000, 0, 0x8000], 6),
                               ([0x200, 0x1000, 1, 0x8000], 87),
                               ([0x200, 0x1000, 0, 0x4000], 87),
                               ([0x200, 0x1001, 0, 0x8000], 487)):
            self.assertEqual(bridge._virtual_free_ex(
                emu, "kernel32.VirtualFreeEx", forbidden, invalid), 0)
            self.assertEqual(errors[-1], error)
        mapping.process = parent
        self.assertEqual(bridge._virtual_free_ex(emu, "kernel32.VirtualFreeEx", forbidden, args), 0)
        self.assertEqual(errors[-1], 487)
        mapping.process = child
        self.assertEqual(bridge._virtual_free_ex(emu, "kernel32.VirtualFreeEx", forbidden, args), 1)
        self.assertTrue(mapping.free)
        self.assertTrue(bridge.events[-1]["success"])
        self.assertEqual(bridge._virtual_free_ex(emu, "kernel32.VirtualFreeEx", forbidden, args), 0)
        self.assertEqual(errors[-1], 487)
        bridge.process_access[0x200] |= PROCESS_VM_READ
        self.assertEqual(bridge._read_process_memory(
            emu, "kernel32.ReadProcessMemory", forbidden,
            [0x200, 0x1000, 0x3000, 1, 0]), 0)
        self.assertEqual(bridge.events[-1]["reason"], "memory was released")

    def test_virtual_free_rejects_nonallocations_and_repeated_release(self):
        bridge = VirtualProcessBridge(ArtifactCatalog(self.root / "artifacts"))
        process = SimpleNamespace(pid=1, path=r"C:\local.exe")
        mapping = SimpleNamespace(base=0x1000, size=0x1000, process=None,
                                  tag="api.VirtualAlloc", free=False)
        errors = []
        emu = SimpleNamespace(get_ptr_size=lambda: 8,
                              get_current_process=lambda: process,
                              get_address_map=lambda address: mapping if 0x1000 <= address < 0x2000 else None,
                              mem_free=lambda address: setattr(mapping, "free", True),
                              set_last_error=errors.append)
        def forbidden(_params):
            self.fail("invalid release reached the engine")
        self.assertEqual(bridge._virtual_alloc(emu, "kernel32.VirtualAlloc",
                                               lambda _: 0x1000, [0, 0x1000, 0x3000, 4]),
                         0x1000)
        self.assertIs(mapping.process, process)
        self.assertEqual(bridge._virtual_free(emu, "kernel32.VirtualFree", forbidden,
                                              [0x1000, 1, 0x8000]), 0)
        self.assertEqual(errors[-1], 87)
        self.assertEqual(bridge._virtual_free(emu, "kernel32.VirtualFree", forbidden,
                                              [0x1000, 0, 0x8000]), 1)
        self.assertTrue(mapping.free)
        self.assertEqual(bridge._virtual_free(emu, "kernel32.VirtualFree", forbidden,
                                              [0x1000, 0, 0x8000]), 0)
        self.assertEqual(errors[-1], 487)
        self.assertEqual(bridge._virtual_alloc(emu, "kernel32.VirtualAlloc",
                                               lambda _: 0x1000, [0x1000, 0x1000, 0x3000, 4]),
                         0x1000)
        self.assertFalse(mapping.free)
        self.assertEqual(bridge._virtual_free(emu, "kernel32.VirtualFree", forbidden,
                                              [0x1000, 0, 0x8000]), 1)
        mapping.free = False
        mapping.tag = "emu.module.local.exe"
        self.assertEqual(bridge._virtual_free(emu, "kernel32.VirtualFree", forbidden,
                                              [0x1000, 0, 0x8000]), 0)
        self.assertEqual(errors[-1], 487)

    def test_virtual_free_ex_executes_in_both_native_architectures(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                self.root = Path(folder)
                result = self.native(f"virtual_free_ex_{arch}.exe")
                report = json.loads((self.root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                exits = [event for event in report["entry_points"][0]["events"]
                         if event.get("api_name") == "kernel32.ExitProcess"]
                self.assertEqual(len(exits), 1)
                self.assertEqual(exits[0]["args"], ["0x1"])
                frees = [event for event in report["virtual_process_events"]
                         if event["event"] == "virtual_process_free"]
                self.assertEqual([event["success"] for event in frees],
                                 [False, True, False])
                self.assertEqual(frees[0]["size"], 1)
                self.assertEqual(frees[2]["reason"],
                                 "address is not a live virtual allocation base")

    def test_transient_pe_is_recovered_before_guest_allocation_release(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                name = f"transient_free_stage_{arch}.exe"
                image = (FIXTURES / name).read_bytes()
                result = run_native(image, inspect_pe(image, name), self.persona,
                                    root, [], 10, 100_000)
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                frees = [item for item in report["virtual_process_events"]
                         if item["event"] == "virtual_process_free" and item["success"]]
                self.assertEqual(len(frees), 1)
                self.assertIn("snapshot_sha256", frees[0])
                recovered = [item for item in result["artifacts"]
                             if item["source"] == "virtual_memory_before_free@0x0"]
                self.assertEqual(len(recovered), 1)
                payload = (root / "artifacts" / recovered[0]["file"]).read_bytes()
                self.assertEqual(payload[:2], b"MZ")
                recovered_pe = pefile.PE(data=payload, fast_load=True)
                self.assertEqual(recovered_pe.FILE_HEADER.Machine,
                                 0x14C if arch == "x86" else 0x8664)
                self.assertEqual(recovered[0]["kind"], "pe")
                self.assertEqual(recovered[0]["context"]["capture_point"], "before_free")
                self.assertFalse(any(item["source"].startswith("memory:api.VirtualAllocEx.")
                                     for item in result["artifacts"]))

    def test_transient_protect_capture_is_owned_bounded_and_committed_on_success(self):
        bridge = VirtualProcessBridge(ArtifactCatalog(self.root / "artifacts"))
        process = SimpleNamespace(pid=17, path=r"C:\guest.exe")
        stage = b"MZ" + bytes(range(1, 255)) * 16
        mapping = SimpleNamespace(base=0x1000, size=len(stage), process=process,
                                  tag="api.VirtualAlloc", free=False)
        old_map = SimpleNamespace(base=0x3000, size=0x1000, process=process,
                                  tag="emu.stack", free=False)
        reads = []

        def mem_read(address, size):
            reads.append((address, size))
            if address == 0x1000 and size == len(stage):
                return stage
            if address == 0x3000 and size == 4:
                return b"\0" * 4
            self.fail("unexpected guest memory read")

        emu = SimpleNamespace(
            get_ptr_size=lambda: 8, get_current_process=lambda: process,
            get_address_map=lambda address: mapping if 0x1000 <= address < 0x1000 + len(stage)
                            else old_map if 0x3000 <= address < 0x4000 else None,
            set_last_error=lambda _: None, mem_read=mem_read)
        params = [0x1000, len(stage), 0x40, 0x3000]
        self.assertEqual(bridge._virtual_protect(
            emu, "kernel32.VirtualProtect", lambda _: 0, params), 0)
        self.assertFalse(bridge.catalog.items)
        self.assertEqual(bridge._virtual_protect(
            emu, "kernel32.VirtualProtect", lambda _: 1, params), 1)
        self.assertEqual(bridge.events[-1]["snapshot_sha256"],
                         hashlib.sha256(stage).hexdigest())
        self.assertEqual(bridge.catalog.items[0]["source"],
                         "virtual_memory_before_execute")
        self.assertEqual(bridge.catalog.items[0]["context"]["target_pid"], 17)
        self.assertIn((0x1000, len(stage)), reads)
        mapping.process = SimpleNamespace(pid=18, path=r"C:\other.exe")
        before = len(reads)
        self.assertEqual(bridge._virtual_protect(
            emu, "kernel32.VirtualProtect", lambda _: self.fail("foreign call"),
            params), 0)
        self.assertEqual(len(reads), before)

    def test_direct_cpu_read_after_release_is_denied(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                name = f"virtual_free_ex_direct_read_{arch}.exe"
                image = (FIXTURES / name).read_bytes()
                result = run_native(image, inspect_pe(image, name), self.persona,
                                    root, [], 10, 100_000)
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertTrue(any("guest read denied: released memory" in error
                                    for error in result["errors"]))
                frees = [event for event in report["virtual_process_events"]
                         if event["event"] == "virtual_process_free"]
                self.assertEqual([event["success"] for event in frees], [False, True])
                denied = [event for event in report["virtual_process_events"]
                          if event["event"] == "virtual_cpu_memory_denied"]
                self.assertEqual(len(denied), 1)
                self.assertEqual((denied[0]["access"], denied[0]["reason"]),
                                 ("read", "released memory"))

    def test_cpu_rollback_failure_stops_queued_guest_runs(self):
        bridge = VirtualProcessBridge(ArtifactCatalog(self.root / "artifacts"))
        bridge._pending_cpu_writes.append((0x1000, b"before"))
        def fail_write(_address, _data):
            raise ValueError("guest mapping unavailable")
        emu = SimpleNamespace(mem_write=fail_write, run_queue=[object()])
        bridge.restore_denied_writes(emu)
        self.assertTrue(bridge.cpu_isolation_failed)
        self.assertEqual(emu.run_queue, [])
        self.assertEqual(bridge.events[-1]["success"], False)
        self.assertTrue(any("rollback failed" in item for item in bridge.unsupported))

    def test_cpu_write_capture_failure_stops_queued_guest_runs(self):
        bridge = VirtualProcessBridge(ArtifactCatalog(self.root / "artifacts"))
        bridge.created_processes.add(1)
        parent = SimpleNamespace(pid=1)
        child = SimpleNamespace(pid=2)
        mapping = SimpleNamespace(base=0x1000, size=0x1000, process=child, shared=False)
        run = SimpleNamespace(error=None)
        stopped = []
        def fail_read(_address, _size):
            raise ValueError("guest page unavailable")
        emu = SimpleNamespace(curr_run=run, get_current_process=lambda: parent,
                              get_address_map=lambda address: mapping,
                              mem_read=fail_read, run_queue=[object()],
                              get_error_info=lambda message, _pc: message,
                              get_pc=lambda: 0x400000,
                              stop=lambda: stopped.append(True))
        self.assertFalse(bridge._cpu_access(emu, 0x1000, 4, "write"))
        self.assertTrue(bridge.cpu_isolation_failed)
        self.assertEqual(emu.run_queue, [])
        self.assertEqual(stopped, [True])
        self.assertTrue(any("rollback unavailable" in item for item in bridge.unsupported))

    def test_foreign_persona_allocation_activates_cpu_guard(self):
        bridge = VirtualProcessBridge(ArtifactCatalog(self.root / "artifacts"))
        current = SimpleNamespace(pid=1, path=r"C:\current.exe")
        persona = SimpleNamespace(pid=2, path=r"C:\persona.exe")
        mapping = SimpleNamespace(base=0x1000, size=0x1000, process=persona,
                                  shared=False, tag="api.VirtualAllocEx.persona_exe.2")
        run = SimpleNamespace(error=None)
        stopped = []
        emu = SimpleNamespace(get_ptr_size=lambda: 8,
                              get_current_process=lambda: current,
                              get_object_from_handle=lambda handle: persona if handle == 0x200 else None,
                              get_address_map=lambda address: mapping if 0x1000 <= address < 0x2000 else None,
                              set_last_error=lambda _: None,
                              curr_run=run,
                              get_error_info=lambda message, _pc: message,
                              get_pc=lambda: 0x400000,
                              stop=lambda: stopped.append(True))
        bridge.process_handle_owners[0x200] = id(current)
        self.assertEqual(bridge._virtual_alloc_ex(
            emu, "kernel32.VirtualAllocEx", lambda _: 0x1000,
            [0x200, 0, 0x1000, 0x3000, 4]), 0x1000)
        self.assertTrue(bridge._foreign_allocation_seen)
        self.assertFalse(bridge._cpu_access(emu, 0x1000, 4, "read"))
        self.assertEqual(stopped, [True])
        self.assertEqual(bridge.events[-1]["reason"], "different guest process")

    def test_duplicate_process_handle_preserves_or_limits_rights(self):
        bridge = VirtualProcessBridge(ArtifactCatalog(self.root / "artifacts"))
        process = SimpleNamespace(pid=123, path=r"C:\guest.exe", handles=[0x220])
        errors, written = [], {}
        def object_from_handle(handle):
            return process if handle in process.handles else None
        def new_handle(obj):
            handle = 0x224 + 4 * (len(obj.handles) - 1)
            obj.handles.append(handle)
            return handle
        emu = SimpleNamespace(get_ptr_size=lambda: 8,
                              get_current_process=lambda: process,
                              get_object_from_handle=object_from_handle,
                              get_object_handle=new_handle,
                              set_last_error=errors.append,
                              mem_read=lambda *_: b"\0" * 8,
                              mem_write=lambda address, data: written.__setitem__(address, data))
        bridge.process_access[0x220] = PROCESS_VM_READ
        bridge.process_handle_owners[0x220] = id(process)
        pseudo = 0xFFFFFFFFFFFFFFFF
        args = [pseudo, 0x220, pseudo, 0x1000, 0, 0, 2]
        def forbidden(_params):
            self.fail("duplicate reached signature-only engine handler")
        self.assertEqual(bridge._duplicate_handle(
            emu, "kernel32.DuplicateHandle", forbidden, args), 1)
        duplicate = int.from_bytes(written[0x1000], "little")
        self.assertTrue(bridge._rights_allow(emu, duplicate, PROCESS_VM_READ))
        self.assertFalse(bridge._rights_allow(emu, duplicate, PROCESS_VM_WRITE))
        args[0] = duplicate  # Read-only source-process handle lacks PROCESS_DUP_HANDLE.
        self.assertEqual(bridge._duplicate_handle(
            emu, "kernel32.DuplicateHandle", forbidden, args), 0)
        self.assertEqual(errors[-1], 5)
        args[0], args[2] = pseudo, duplicate  # Target-process handle needs it too.
        self.assertEqual(bridge._duplicate_handle(
            emu, "kernel32.DuplicateHandle", forbidden, args), 0)
        self.assertEqual(errors[-1], 5)
        bridge.process_access[0x220] |= PROCESS_DUP_HANDLE
        args[0], args[2] = 0x220, 0x220
        self.assertEqual(bridge._duplicate_handle(
            emu, "kernel32.DuplicateHandle", forbidden, args), 1)
        close_source = int.from_bytes(written[0x1000], "little")
        args[0], args[1], args[2], args[6] = 0x220, close_source, duplicate, 3
        self.assertEqual(bridge._duplicate_handle(
            emu, "kernel32.DuplicateHandle", forbidden, args), 0)
        self.assertEqual(errors[-1], 5)
        self.assertIsNone(object_from_handle(close_source))
        self.assertTrue(bridge.events[-2]["source_closed"])
        args[1], args[6] = 0x220, 2
        args[0], args[2] = pseudo, pseudo
        args[4], args[6] = PROCESS_VM_WRITE, 0
        self.assertEqual(bridge._duplicate_handle(
            emu, "kernel32.DuplicateHandle", forbidden, args), 1)
        write_duplicate = int.from_bytes(written[0x1000], "little")
        self.assertTrue(bridge._rights_allow(emu, write_duplicate, PROCESS_VM_WRITE))
        self.assertFalse(bridge._rights_allow(emu, write_duplicate, PROCESS_VM_READ))
        args[1], args[4], args[6] = write_duplicate, 0x80000000, 1
        self.assertEqual(bridge._duplicate_handle(
            emu, "kernel32.DuplicateHandle", forbidden, args), 0)
        self.assertEqual(errors[-1], 87)
        self.assertIsNone(object_from_handle(write_duplicate))
        self.assertEqual(bridge.close_process_handle(emu, 0x220), 1)
        self.assertIsNone(object_from_handle(0x220))
        self.assertIs(object_from_handle(duplicate), process)
        self.assertEqual(bridge.close_process_handle(emu, 0x220), 0)
        emu.get_file_manager = lambda: SimpleNamespace(file_handles={0x888: object()})
        args[1], args[4], args[6] = 0x888, 0, 2
        self.assertEqual(bridge._duplicate_handle(
            emu, "kernel32.DuplicateHandle", forbidden, args), 0)
        self.assertEqual(bridge.events[-1]["reason"],
                         "non-process handle duplication unsupported")
        self.assertTrue(any("non-process handle" in item for item in bridge.unsupported))

    def test_duplicate_guest_file_and_mapping_entries_share_objects_and_limit_rights(self):
        process = SimpleNamespace(pid=1, path=r"C:\guest.exe")
        current = [process]
        file = GuestFile(None, r"C:\guest.bin", data=b"ABCDEFGH")
        opened = SharedGuestFileView(file)
        opened.position = 2
        mapping = SimpleNamespace(size=8, prot=4, views={})
        mapping.get_handle = lambda: 0xA00
        manager = SimpleNamespace(file_handles={0x80: opened}, file_maps={0x88: mapping},
                                  get_mapping_from_handle=lambda handle: manager.file_maps.get(handle))
        class Allocator:
            def allocate_file_handle(self):
                return 0x900
        written, errors = {}, []
        emu = SimpleNamespace(get_current_process=lambda: current[0],
                              get_ptr_size=lambda: 8, get_file_manager=lambda: manager,
                              get_object_from_handle=lambda _: None,
                              handle_allocator=Allocator(),
                              mem_read=lambda _, size: b"\0" * size,
                              mem_write=lambda address, data: written.__setitem__(address, data),
                              set_last_error=errors.append)
        files = VirtualFileBridge(self.persona["current_dir"],
                                  ArtifactCatalog(self.root / "artifacts"))
        processes = VirtualProcessBridge(ArtifactCatalog(self.root / "artifacts"))
        processes.file_duplicate_handler = files.duplicate_guest_handle
        files.file_handle_owners[0x80] = {id(process)}
        files.file_handle_flags[(id(process), 0x80)] = 0
        files.file_open_options[0x80] = (files._key(file.path), 1, 7)
        files.file_open_raw_access[0x80] = 0x80000000
        files.mapping_handle_owners[0x88] = {id(process)}
        files.mapping_handle_access[(id(process), 0x88)] = 6
        pseudo = 0xFFFFFFFFFFFFFFFF
        forbidden = lambda _: self.fail("duplicate reached engine handler")
        args = [pseudo, 0x80, pseudo, 0x1000, 0, 1, 2]
        emu.get_object_from_handle = lambda handle: process if handle == 0x890 else None
        processes.process_handle_owners[0x890] = id(process)
        processes.process_access[0x890] = PROCESS_VM_READ
        processes.file_close_handler = lambda guest, handle, owner: files._close_handle(
            guest, "kernel32.CloseHandle", None, [handle], owner_override=id(owner))
        manager.file_handles[0x830] = SharedGuestFileView(file)
        files.file_handle_owners[0x830] = {id(process)}
        files.file_open_options[0x830] = (files._key(file.path), 1, 7)
        files.file_open_raw_access[0x830] = 0x80000000
        args[0], args[1], args[6] = 0x890, 0x830, 3
        self.assertEqual(processes._duplicate_handle(
            emu, "kernel32.DuplicateHandle", forbidden, args), 0)
        self.assertIn(0x830, manager.file_handles)
        args[0], args[2] = pseudo, 0x890
        self.assertEqual(processes._duplicate_handle(
            emu, "kernel32.DuplicateHandle", forbidden, args), 0)
        self.assertNotIn(0x830, manager.file_handles)
        self.assertTrue(processes.events[-1]["source_closed"])
        args[0], args[1], args[2], args[6] = pseudo, 0x80, pseudo, 2
        args[0] = 0x890
        self.assertEqual(processes._duplicate_handle(
            emu, "kernel32.DuplicateHandle", forbidden, args), 0)
        self.assertEqual(errors[-1], 5)
        args[0], args[2] = pseudo, 0x890
        self.assertEqual(processes._duplicate_handle(
            emu, "kernel32.DuplicateHandle", forbidden, args), 0)
        self.assertEqual(errors[-1], 5)
        processes.process_access[0x890] |= PROCESS_DUP_HANDLE
        args[0], args[2] = 0x890, 0x890
        self.assertEqual(processes._duplicate_handle(
            emu, "kernel32.DuplicateHandle", forbidden, args), 1)
        args[0], args[2] = pseudo, pseudo
        duplicate = int.from_bytes(written[0x1000], "little")
        self.assertEqual(duplicate, 0x900)
        self.assertIs(manager.file_handles[duplicate], opened)
        self.assertEqual(opened.get_data(2), b"CD")
        self.assertEqual(manager.file_handles[duplicate].tell(), 4)
        self.assertEqual(files.file_handle_flags[(id(process), duplicate)], 1)
        self.assertEqual(files._close_handle(emu, "kernel32.CloseHandle", None, [0x80]), 1)
        self.assertIs(manager.file_handles[duplicate], opened)
        args[1], args[4], args[5], args[6] = 0x88, 4, 0, 0
        self.assertEqual(processes._duplicate_handle(
            emu, "kernel32.DuplicateHandle", forbidden, args), 1)
        mapped_duplicate = int.from_bytes(written[0x1000], "little")
        self.assertEqual(mapped_duplicate, 0xA00)
        self.assertIs(manager.file_maps[mapped_duplicate], mapping)
        self.assertEqual(files.mapping_handle_access[(id(process), mapped_duplicate)], 4)
        self.assertEqual(files._map_view_of_file(
            emu, "kernel32.MapViewOfFile", forbidden,
            [mapped_duplicate, 2, 0, 0, 4]), 0)
        self.assertEqual(errors[-1], 5)
        self.assertEqual(files._close_handle(emu, "kernel32.CloseHandle", None, [0x88]), 1)
        self.assertIs(manager.file_maps[mapped_duplicate], mapping)
        args[1], args[4], args[6] = mapped_duplicate, 2, 0
        self.assertEqual(processes._duplicate_handle(
            emu, "kernel32.DuplicateHandle", forbidden, args), 0)
        self.assertEqual(errors[-1], 5)
        args[1], args[3], args[4], args[6] = duplicate, 0, 0, 3
        self.assertEqual(processes._duplicate_handle(
            emu, "kernel32.DuplicateHandle", forbidden, args), 0)
        self.assertEqual(errors[-1], 87)
        self.assertNotIn(duplicate, manager.file_handles)
        manager.file_handles[0x810] = SharedGuestFileView(file, append_only=True)
        files.file_handle_owners[0x810] = {id(process)}
        files.file_open_options[0x810] = (files._key(file.path), 2, 7)
        files.file_open_raw_access[0x810] = 0x4  # FILE_APPEND_DATA only.
        args[1], args[3], args[4], args[6] = 0x810, 0x1000, 0x2, 0
        self.assertEqual(processes._duplicate_handle(
            emu, "kernel32.DuplicateHandle", forbidden, args), 0)
        self.assertEqual(errors[-1], 5)
        self.assertEqual(files.file_open_raw_access[0x810], 0x4)
        manager.file_handles[0x820] = SharedGuestFileView(file)
        files.file_handle_owners[0x820] = {id(process)}
        files.file_open_options[0x820] = (files._key(file.path), 2, 7)
        files.file_open_raw_access[0x820] = 0x40000000  # GENERIC_WRITE.
        args[1] = 0x820
        self.assertEqual(processes._duplicate_handle(
            emu, "kernel32.DuplicateHandle", forbidden, args), 1)
        self.assertEqual(files.file_open_raw_access[0x900], 0x2)
        self.assertEqual(files._close_handle(emu, "kernel32.CloseHandle", None, [0x900]), 1)
        current[0] = SimpleNamespace(pid=2, path=r"C:\child.exe")
        args[1], args[3], args[6] = mapped_duplicate, 0x1000, 2
        self.assertEqual(processes._duplicate_handle(
            emu, "kernel32.DuplicateHandle", forbidden, args), 0)
        self.assertEqual(errors[-1], 6)

    def test_guest_file_handle_duplicate_keeps_shared_cursor_after_source_close(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                name = f"duplicate_guest_file_{arch}.exe"
                image = (FIXTURES / name).read_bytes()
                result = run_native(image, inspect_pe(image, name), self.persona,
                                    root, [], 10, 100_000)
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                calls = [event for entry in report["entry_points"]
                         for event in entry.get("events") or []]
                self.assertEqual(sum(event.get("api_name") == "kernel32.WriteFile"
                                     and event.get("ret_val") == "0x1" for event in calls), 2)
                self.assertEqual(sum(event.get("api_name") == "kernel32.DuplicateHandle"
                                     and event.get("ret_val") == "0x1" for event in calls), 1)
                self.assertTrue(any(event.get("api_name") == "kernel32.CloseHandle"
                                    and event.get("ret_val") == "0x1" for event in calls))
                self.assertTrue(any(event.get("api_name") == "kernel32.ExitProcess"
                                    and event.get("args") == ["0x1"] for event in calls))
                self.assertTrue(any(item["source"] == "file_write"
                                    and (root / "artifacts" / item["file"]).read_bytes()
                                    == b"ABCDEFGHQRST" for item in result["artifacts"]))

    def test_duplicate_guest_file_and_mapping_into_child_gives_child_only_entries(self):
        parent = SimpleNamespace(pid=1, path=r"C:\parent.exe")
        child = SimpleNamespace(pid=2, path=r"C:\child.exe")
        current = [parent]
        file = GuestFile(None, r"C:\guest.bin", data=b"ABCDEFGH")
        opened = SharedGuestFileView(file)
        mapping = SimpleNamespace(size=8, prot=4, views={})
        mapping_handles = iter((0xA00, 0xA04))
        mapping.get_handle = lambda: next(mapping_handles)
        manager = SimpleNamespace(file_handles={0x80: opened}, file_maps={0x88: mapping},
                                  get_mapping_from_handle=lambda h: manager.file_maps.get(h))
        class Allocator:
            def __init__(self):
                self.next = 0x900
            def allocate_file_handle(self):
                handle = self.next
                self.next += 4
                return handle
        written, errors = {}, []
        emu = SimpleNamespace(get_current_process=lambda: current[0],
                              get_ptr_size=lambda: 8, get_file_manager=lambda: manager,
                              get_object_from_handle=lambda h: child if h == 0x890 else
                              parent if h == 0x880 else None,
                              handle_allocator=Allocator(),
                              mem_read=lambda _, size: b"\0" * size,
                              mem_write=lambda address, data: written.__setitem__(address, data),
                              set_last_error=errors.append)
        files = VirtualFileBridge(self.persona["current_dir"],
                                  ArtifactCatalog(self.root / "artifacts"))
        processes = VirtualProcessBridge(ArtifactCatalog(self.root / "artifacts"))
        processes.file_duplicate_handler = files.duplicate_guest_handle
        processes.file_close_handler = lambda guest, handle, owner: files._close_handle(
            guest, "kernel32.CloseHandle", None, [handle], owner_override=id(owner))
        processes.process_handle_owners.update({0x890: id(parent), 0x880: id(parent)})
        processes.process_access.update({0x890: PROCESS_DUP_HANDLE,
                                         0x880: PROCESS_VM_READ})
        processes.created_processes.add(id(child))
        files.file_handle_owners[0x80] = {id(parent)}
        files.file_open_options[0x80] = (files._key(file.path), 1, 7)
        files.file_open_raw_access[0x80] = 0x80000000
        files.mapping_handle_owners[0x88] = {id(parent)}
        files.mapping_handle_access[(id(parent), 0x88)] = 6
        pseudo = 0xFFFFFFFFFFFFFFFF
        forbidden = lambda _: self.fail("duplicate reached engine handler")
        args = [pseudo, 0x80, 0x890, 0x1000, 0, 0, 2]
        self.assertEqual(processes._duplicate_handle(
            emu, "kernel32.DuplicateHandle", forbidden, args), 1)
        self.assertEqual(files.file_handle_owners[0x900], {id(child)})
        self.assertFalse(files._owns_file_handle(emu, 0x900))
        self.assertTrue(files._owns_file_handle(emu, 0x80))
        args[1] = 0x88
        self.assertEqual(processes._duplicate_handle(
            emu, "kernel32.DuplicateHandle", forbidden, args), 1)
        self.assertEqual(files.mapping_handle_owners[0xA00], {id(child)})
        self.assertFalse(files._owns_mapping_handle(emu, 0xA00))
        self.assertEqual(files._close_handle(emu, "kernel32.CloseHandle", None, [0x80]), 1)
        self.assertEqual(files._close_handle(emu, "kernel32.CloseHandle", None, [0x88]), 1)
        current[0] = child
        self.assertTrue(files._owns_file_handle(emu, 0x900))
        self.assertTrue(files._owns_mapping_handle(emu, 0xA00))
        self.assertIs(manager.file_handles[0x900], opened)
        self.assertIs(manager.file_maps[0xA00], mapping)
        current[0] = parent
        args[0], args[1], args[2], args[6] = 0x890, 0x900, pseudo, 3
        self.assertEqual(processes._duplicate_handle(
            emu, "kernel32.DuplicateHandle", forbidden, args), 1)
        self.assertNotIn(0x900, manager.file_handles)
        self.assertEqual(files.file_handle_owners[0x904], {id(parent)})
        args[1], args[6] = 0xA00, 2
        self.assertEqual(processes._duplicate_handle(
            emu, "kernel32.DuplicateHandle", forbidden, args), 1)
        self.assertEqual(files.mapping_handle_owners[0xA04], {id(parent)})
        args[0], args[1], args[2], args[6] = 0x890, 0xA00, 0x880, 3
        self.assertEqual(processes._duplicate_handle(
            emu, "kernel32.DuplicateHandle", forbidden, args), 0)
        self.assertTrue(processes.events[-1]["source_closed"])
        self.assertNotIn(0xA00, manager.file_maps)
        current[0] = child
        self.assertFalse(files._owns_file_handle(emu, 0x904))
        self.assertFalse(files._owns_mapping_handle(emu, 0xA04))
        self.assertIs(manager.file_maps[0xA04], mapping)

    def test_duplicate_guest_process_and_thread_entries_across_modeled_processes(self):
        parent = SimpleNamespace(pid=1, path=r"C:\parent.exe", handles=[0x220])
        child = SimpleNamespace(pid=2, path=r"C:\child.exe", handles=[0x890])
        thread = SimpleNamespace(tid=3, suspend_count=1, process=parent,
                                 handles=[0x230])
        current = [parent]
        objects = {0x220: parent, 0x230: thread, 0x890: child}
        next_handle = [0xA10]
        written, errors = {}, []
        def issue(obj):
            handle = next_handle[0]
            next_handle[0] += 4
            objects[handle] = obj
            obj.handles.append(handle)
            return handle
        emu = SimpleNamespace(get_current_process=lambda: current[0],
                              get_ptr_size=lambda: 8,
                              get_file_manager=lambda: SimpleNamespace(
                                  file_handles={}, file_maps={}),
                              get_object_from_handle=objects.get,
                              get_object_handle=issue,
                              mem_read=lambda _, size: b"\0" * size,
                              mem_write=lambda address, data: written.__setitem__(address, data),
                              set_last_error=errors.append)
        bridge = VirtualProcessBridge(ArtifactCatalog(self.root / "artifacts"))
        bridge.process_handle_owners.update({0x220: id(parent), 0x890: id(parent)})
        bridge.process_access.update({0x220: PROCESS_VM_READ,
                                      0x890: PROCESS_DUP_HANDLE})
        bridge.thread_handle_owners[0x230] = id(parent)
        bridge.thread_access[0x230] = 2
        bridge.created_processes.add(id(child))
        pseudo = 0xFFFFFFFFFFFFFFFF
        forbidden = lambda _: self.fail("duplicate reached engine handler")
        for source, owner_table, expected in (
                (0x220, bridge.process_handle_owners, parent),
                (0x230, bridge.thread_handle_owners, thread)):
            args = [pseudo, source, 0x890, 0x1000, 0, 0, 2]
            self.assertEqual(bridge._duplicate_handle(
                emu, "kernel32.DuplicateHandle", forbidden, args), 1)
            child_handle = int.from_bytes(written[0x1000], "little")
            self.assertEqual(owner_table[child_handle], id(child))
            self.assertIsNone(bridge._process(emu, child_handle) if expected is parent
                              else bridge._thread(emu, child_handle))
            current[0] = child
            self.assertIs(bridge._process(emu, child_handle) if expected is parent
                          else bridge._thread(emu, child_handle), expected)
            current[0] = parent
            args[0], args[1], args[2], args[6] = 0x890, child_handle, pseudo, 3
            self.assertEqual(bridge._duplicate_handle(
                emu, "kernel32.DuplicateHandle", forbidden, args), 1)
            returned = int.from_bytes(written[0x1000], "little")
            self.assertNotIn(child_handle, owner_table)
            self.assertEqual(owner_table[returned], id(parent))
            current[0] = child
            self.assertIsNone(bridge._process(emu, returned) if expected is parent
                              else bridge._thread(emu, returned))
            current[0] = parent

    def test_duplicate_guest_file_into_child_runs_under_x86_and_x64_cpu(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                name = f"child_parent_file_handle_duplicate_{arch}.exe"
                image = (FIXTURES / name).read_bytes()
                result = run_native(image, inspect_pe(image, name), self.persona,
                                    root, [FIXTURES / f"companion_{arch}.dll"], 10, 100_000)
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                self.assertEqual(len(report["entry_points"]), 3)
                self.assertEqual(report["entry_points"][-1]["ret_val"], "0x1")
                creates = [item for item in report["virtual_process_events"]
                           if item["event"] == "virtual_process_create"]
                self.assertEqual(len(creates), 1)
                self.assertEqual(report["entry_points"][1]["guest_pid"],
                                 report["entry_points"][0]["guest_pid"])
                self.assertEqual(report["entry_points"][2]["guest_pid"],
                                 creates[0]["pid"])
                duplicates = [item for item in report["virtual_file_events"]
                              if item["event"] == "virtual_guest_handle_duplicate"]
                self.assertEqual(len(duplicates), 1)
                self.assertTrue(duplicates[0]["success"])
                self.assertEqual(duplicates[0]["object_type"], "file")
                self.assertTrue(any(item.get("api_name") == "kernel32.DuplicateHandle"
                                    and item.get("ret_val") == "0x1"
                                    for item in report["entry_points"][1]["events"] or []))

    def test_handle_information_flags_are_per_guest_process(self):
        bridge = VirtualProcessBridge(ArtifactCatalog(self.root / "artifacts"))
        parent = SimpleNamespace(pid=1, path=r"C:\parent.exe", handles=[0x220])
        child = SimpleNamespace(pid=2, path=r"C:\child.exe")
        current = [parent]
        errors, written = [], {}
        emu = SimpleNamespace(get_ptr_size=lambda: 8,
                              get_current_process=lambda: current[0],
                              get_object_from_handle=lambda handle: (
                                  parent if handle in parent.handles else None),
                              set_last_error=errors.append,
                              mem_write=lambda address, data: written.__setitem__(address, data))
        bridge.process_handle_owners[0x220] = id(parent)
        bridge.shared_process_handle_owners[0x220] = {id(child)}
        bridge.process_handle_flags[(id(parent), 0x220)] = 1
        bridge.process_handle_flags[(id(child), 0x220)] = 1
        forbidden = lambda _params: self.fail("engine handle stub called")
        current[0] = child
        self.assertEqual(bridge._set_handle_information(
            emu, "kernel32.SetHandleInformation", forbidden, [0x220, 1, 0]), 1)
        self.assertEqual(bridge._get_handle_information(
            emu, "kernel32.GetHandleInformation", forbidden, [0x220, 0x1000]), 1)
        self.assertEqual(written[0x1000], b"\0" * 4)
        self.assertEqual(bridge.close_process_handle(emu, 0x220), 1)
        self.assertIn(0x220, parent.handles)
        current[0] = parent
        self.assertEqual(bridge._set_handle_information(
            emu, "kernel32.SetHandleInformation", forbidden, [0x220, 2, 2]), 1)
        self.assertEqual(bridge._get_handle_information(
            emu, "kernel32.GetHandleInformation", forbidden, [0x220, 0x1000]), 1)
        self.assertEqual(written[0x1000], (3).to_bytes(4, "little"))
        self.assertEqual(bridge.close_process_handle(emu, 0x220), 0)
        self.assertEqual(errors[-1], 6)
        self.assertIn(0x220, parent.handles)
        self.assertEqual(bridge._set_handle_information(
            emu, "kernel32.SetHandleInformation", forbidden, [0x220, 2, 0]), 1)
        self.assertEqual(bridge.close_process_handle(emu, 0x220), 1)
        self.assertNotIn(0x220, parent.handles)
        self.assertEqual(bridge._get_handle_information(
            emu, "kernel32.GetHandleInformation", forbidden, [0x220, 0x1000]), 0)
        self.assertEqual(errors[-1], 6)

    def test_inherited_file_handle_flags_and_close_are_process_scoped(self):
        files = VirtualFileBridge(self.persona["current_dir"],
                                  ArtifactCatalog(self.root / "artifacts"))
        processes = VirtualProcessBridge(ArtifactCatalog(self.root / "process-artifacts"))
        processes.file_flag_entry_handler = files.handle_flag_entry
        parent = SimpleNamespace(pid=1, path=r"C:\parent.exe")
        child = SimpleNamespace(pid=2, path=r"C:\child.exe")
        current = [parent]
        manager = SimpleNamespace(file_handles={0x80: SimpleNamespace(path=r"C:\guest.txt")},
                                  file_maps={}, files=[])
        errors, written = [], {}
        emu = SimpleNamespace(get_ptr_size=lambda: 8,
                              get_current_process=lambda: current[0],
                              get_file_manager=lambda: manager,
                              get_object_from_handle=lambda _: None,
                              set_last_error=errors.append,
                              mem_write=lambda address, data: written.__setitem__(address, data))
        files.file_handle_owners[0x80] = {id(parent)}
        files.file_handle_flags[(id(parent), 0x80)] = 0
        forbidden = lambda _params: self.fail("engine handle stub called")
        self.assertEqual(processes._set_handle_information(
            emu, "kernel32.SetHandleInformation", forbidden, [0x80, 1, 1]), 1)
        self.assertEqual(files.inherit_file_handles(emu, parent, child), 1)
        current[0] = child
        self.assertEqual(processes._set_handle_information(
            emu, "kernel32.SetHandleInformation", forbidden, [0x80, 1, 0]), 1)
        self.assertEqual(processes._get_handle_information(
            emu, "kernel32.GetHandleInformation", forbidden, [0x80, 0x1000]), 1)
        self.assertEqual(written[0x1000], b"\0" * 4)
        current[0] = parent
        self.assertEqual(processes._get_handle_information(
            emu, "kernel32.GetHandleInformation", forbidden, [0x80, 0x1000]), 1)
        self.assertEqual(written[0x1000], (1).to_bytes(4, "little"))
        self.assertEqual(files._close_handle(emu, "kernel32.CloseHandle", forbidden, [0x80]), 1)
        self.assertIn(0x80, manager.file_handles)
        current[0] = child
        self.assertEqual(processes._set_handle_information(
            emu, "kernel32.SetHandleInformation", forbidden, [0x80, 2, 2]), 1)
        self.assertEqual(files._close_handle(emu, "kernel32.CloseHandle", forbidden, [0x80]), 0)
        self.assertEqual(errors[-1], 6)
        self.assertEqual(processes._set_handle_information(
            emu, "kernel32.SetHandleInformation", forbidden, [0x80, 2, 0]), 1)
        self.assertEqual(files._close_handle(emu, "kernel32.CloseHandle", forbidden, [0x80]), 1)
        self.assertNotIn(0x80, manager.file_handles)

    def test_process_exit_forces_protected_handles_closed_but_preserves_child_file(self):
        files = VirtualFileBridge(self.persona["current_dir"],
                                  ArtifactCatalog(self.root / "artifacts"))
        parent = SimpleNamespace(pid=1)
        child = SimpleNamespace(pid=2)
        current = [parent]
        section = object()
        manager = SimpleNamespace(
            file_handles={0x80: SimpleNamespace(path=r"C:\guest.txt")},
            file_maps={0x300: section}, files=[])
        errors = []
        emu = SimpleNamespace(get_current_process=lambda: current[0],
                              get_file_manager=lambda: manager,
                              set_last_error=errors.append)
        files.file_handle_owners[0x80] = {id(parent), id(child)}
        files.file_handle_flags[(id(parent), 0x80)] = 2
        files.file_handle_flags[(id(child), 0x80)] = 0
        files.mapping_handle_owners[0x300] = {id(parent)}
        files.mapping_handle_flags[(id(parent), 0x300)] = 2
        forbidden = lambda _params: self.fail("engine close handler called")
        self.assertEqual(files._close_handle(
            emu, "kernel32.CloseHandle", forbidden, [0x80]), 0)
        self.assertEqual(files._close_handle(
            emu, "kernel32.CloseHandle", forbidden, [0x300]), 0)
        self.assertEqual(files.cleanup_process(emu, parent),
                         {"views": 0, "files": 1, "mappings": 1})
        self.assertIn(0x80, manager.file_handles)
        self.assertEqual(files.file_handle_owners[0x80], {id(child)})
        self.assertNotIn(0x300, manager.file_maps)
        self.assertNotIn((id(parent), 0x80), files.file_handle_flags)
        current[0] = child
        self.assertEqual(files._close_handle(
            emu, "kernel32.CloseHandle", forbidden, [0x80]), 1)
        self.assertNotIn(0x80, manager.file_handles)

    def test_mapping_handle_flags_and_views_are_process_scoped(self):
        files = VirtualFileBridge(self.persona["current_dir"],
                                  ArtifactCatalog(self.root / "artifacts"))
        processes = VirtualProcessBridge(ArtifactCatalog(self.root / "process-artifacts"))
        processes.file_flag_entry_handler = files.handle_flag_entry
        parent = SimpleNamespace(pid=1, path=r"C:\parent.exe")
        child = SimpleNamespace(pid=2, path=r"C:\child.exe")
        current = [parent]
        manager = SimpleNamespace(file_handles={}, file_maps={0x300: object()})
        errors, written = [], {}
        emu = SimpleNamespace(get_ptr_size=lambda: 8,
                              get_current_process=lambda: current[0],
                              get_file_manager=lambda: manager,
                              get_object_from_handle=lambda _: None,
                              set_last_error=errors.append,
                              mem_write=lambda address, data: written.__setitem__(address, data))
        files.mapping_handle_owners[0x300] = {id(parent)}
        files.mapping_handle_flags[(id(parent), 0x300)] = 0
        forbidden = lambda _params: self.fail("engine mapping stub called")
        self.assertEqual(processes._set_handle_information(
            emu, "kernel32.SetHandleInformation", forbidden, [0x300, 1, 1]), 1)
        self.assertEqual(files.inherit_mapping_handles(emu, parent, child), 1)
        current[0] = child
        self.assertEqual(processes._set_handle_information(
            emu, "kernel32.SetHandleInformation", forbidden, [0x300, 1, 0]), 1)
        self.assertEqual(processes._get_handle_information(
            emu, "kernel32.GetHandleInformation", forbidden, [0x300, 0x1000]), 1)
        self.assertEqual(written[0x1000], b"\0" * 4)
        self.assertEqual(processes._set_handle_information(
            emu, "kernel32.SetHandleInformation", forbidden, [0x300, 2, 2]), 1)
        self.assertEqual(files._close_handle(emu, "kernel32.CloseHandle", forbidden, [0x300]), 0)
        self.assertEqual(errors[-1], 6)
        self.assertEqual(processes._set_handle_information(
            emu, "kernel32.SetHandleInformation", forbidden, [0x300, 2, 0]), 1)
        current[0] = parent
        self.assertEqual(processes._get_handle_information(
            emu, "kernel32.GetHandleInformation", forbidden, [0x300, 0x1000]), 1)
        self.assertEqual(written[0x1000], (1).to_bytes(4, "little"))
        file = GuestFile(None, r"C:\guest.bin", data=b"Pers")
        files.mapped_guest_views[0x1000] = (file, 0, 4, False)
        files.mapped_guest_view_owners[0x1000] = id(parent)
        current[0] = child
        self.assertEqual(files._flush_view_of_file(
            emu, "kernel32.FlushViewOfFile", forbidden, [0x1000, 0]), 0)
        self.assertEqual(files._unmap_view_of_file(
            emu, "kernel32.UnmapViewOfFile", forbidden, [0x1000]), 0)
        self.assertEqual(errors[-1], 6)
        current[0] = parent
        self.assertEqual(files._flush_view_of_file(
            emu, "kernel32.FlushViewOfFile", forbidden, [0x1000, 0]), 1)
        self.assertEqual(files._unmap_view_of_file(
            emu, "kernel32.UnmapViewOfFile", lambda _: 1, [0x1000]), 1)
        self.assertNotIn(0x1000, files.mapped_guest_view_owners)
        self.assertEqual(files._close_handle(emu, "kernel32.CloseHandle", forbidden, [0x300]), 1)
        current[0] = child
        self.assertEqual(files._close_handle(emu, "kernel32.CloseHandle", forbidden, [0x300]), 1)
        self.assertNotIn(0x300, manager.file_maps)

    def test_guest_process_creation_fails_visibly_for_absent_or_invalid_image(self):
        path = self.persona["current_dir"] + r"\missing-child.exe"
        manager = SimpleNamespace(files=[])
        errors = []
        emu = SimpleNamespace(read_mem_string=lambda *_: path,
                              get_cd=lambda: self.persona["current_dir"],
                              get_file_manager=lambda: manager,
                              set_last_error=errors.append,
                              get_ptr_size=lambda: 8)
        bridge = VirtualProcessBridge(ArtifactCatalog(self.root / "artifacts"))
        args = [1, 0, 0, 0, 0, 0, 0, 0, 2, 3]
        def forbidden(_params):
            self.fail("invalid child reached Speakeasy's process loader")
        self.assertEqual(bridge._create_process(
            emu, "kernel32.CreateProcessW", forbidden, args), 0)
        self.assertEqual(errors[-1], 2)
        self.assertTrue(bridge.unsupported)
        manager.files.append(GuestFile(None, path, data=b"not a PE"))
        self.assertEqual(bridge._create_process(
            emu, "kernel32.CreateProcessW", forbidden, args), 0)
        self.assertEqual(errors[-1], 193)
        manager.files[0] = GuestFile(None, path,
                                     data=(FIXTURES / "native_x86.exe").read_bytes())
        self.assertEqual(bridge._create_process(
            emu, "kernel32.CreateProcessW", forbidden, args), 0)
        self.assertEqual(errors[-1], 50)
        manager.files[0] = GuestFile(None, path,
                                     data=(FIXTURES / "native_x64.exe").read_bytes())
        bridge.events = [{"event": "virtual_process_create", "success": True}
                         for _ in range(32)]
        self.assertEqual(bridge._create_process(
            emu, "kernel32.CreateProcessW", forbidden, args), 0)
        self.assertEqual(errors[-1], 8)
        self.assertEqual(bridge.events[-1]["reason"], "guest child process limit reached")

    def test_guest_cannot_launch_host_cmd_through_createprocess(self):
        for arch, machine in (("x86", 0x14C), ("x64", 0x8664)):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                marker = self.root.parent / f"{self.root.name}-host-process-{arch}.txt"
                try:
                    image = build_host_process_probe(machine, str(marker))
                    root = Path(folder)
                    name = f"host_process_probe_{arch}.exe"
                    result = run_native(image, inspect_pe(image, name), self.persona,
                                        root, [], 10, 100_000)
                    report = json.loads((root / result["engine_report"]).read_text())
                    creates = [event for event in report["virtual_process_events"]
                               if event.get("event") == "virtual_process_create"]
                    self.assertEqual(len(creates), 1)
                    self.assertFalse(creates[0]["success"])
                    self.assertEqual(creates[0]["reason"], "executable absent from guest filesystem")
                    self.assertEqual(creates[0]["application"], r"C:\Windows\System32\cmd.exe")
                    self.assertIn(str(marker), creates[0]["command_line"])
                    self.assertTrue(any("executable unavailable in guest" in error
                                        for error in result["errors"]))
                    self.assertFalse(marker.exists())
                finally:
                    marker.unlink(missing_ok=True)

    def test_guest_file_mapping_rejects_invalid_handles_and_views(self):
        path = self.persona["current_dir"] + r"\mapping-check.bin"
        file = GuestFile(None, path, data=b"ABCDEFGH")
        view = SharedGuestFileView(file)
        view.position = 3
        maps = {}
        manager = SimpleNamespace(file_handles={0x888: view}, file_maps=maps,
                                  get_mapping_from_handle=maps.get)
        def create_mapping(handle, name, size, protection):
            maps[0x999] = SimpleNamespace(backed_file=manager.file_handles[handle],
                                          size=size, prot=protection)
            return 0x999
        manager.file_create_mapping = create_mapping
        errors = []
        emu = SimpleNamespace(get_file_manager=lambda: manager,
                              set_last_error=errors.append, get_ptr_size=lambda: 8)
        bridge = VirtualFileBridge(self.persona["current_dir"],
                                   ArtifactCatalog(self.root / "artifacts"))
        bridge.file_open_raw_access[0x888] = 0xC0000000
        original = lambda _params: self.fail("invalid mapping reached engine")
        self.assertEqual(bridge._create_file_mapping(
            emu, "kernel32.CreateFileMappingW", original, [0xBAD, 0, 4, 0, 0, 0]), 0)
        self.assertEqual(errors[-1], 6)
        self.assertEqual(bridge._create_file_mapping(
            emu, "kernel32.CreateFileMappingW", original, [0x888, 0, 4, 0, 0, 0]), 0x999)
        self.assertEqual(maps[0x999].size, 8)
        self.assertEqual(bridge._map_view_of_file(
            emu, "kernel32.MapViewOfFile", original, [0x999, 2, 0, 1, 4]), 0)
        self.assertEqual(errors[-1], 87)  # allocation granularity
        self.assertEqual(bridge._map_view_of_file(
            emu, "kernel32.MapViewOfFile", original, [0x999, 2, 0, 0, 9]), 0)
        self.assertEqual(errors[-1], 87)  # mapping bounds
        seen = []
        def map_original(params):
            seen.append((params, view.tell()))
            return 0x10000 + len(seen) * 0x10000
        self.assertEqual(bridge._map_view_of_file(
            emu, "kernel32.MapViewOfFile", map_original, [0x999, 2, 0, 0, 0]),
                         0x20000)
        self.assertEqual(seen, [([0x999, 2, 0, 0, 8], 0)])
        self.assertEqual(view.tell(), 3)
        self.assertEqual(bridge._map_view_of_file(
            emu, "kernel32.MapViewOfFile", map_original, [0x999, 2, 0, 0, 8]),
                         0x30000)
        self.assertEqual(seen[-1], ([0x999, 2, 0, 0, 8], 0))
        self.assertEqual(len(bridge.mapped_guest_views), 2)

    def test_pagefile_views_validate_bounds_access_and_cpu_permissions(self):
        for ptr_size in (4, 8):
            with self.subTest(ptr_size=ptr_size):
                section = SimpleNamespace(backed_file=None, size=0x20000, prot=4)
                manager = SimpleNamespace(file_maps={0x999: section},
                                          get_mapping_from_handle=lambda _: section)
                process = object()
                view_map = SimpleNamespace(base=0x40000, size=0x10000,
                                           prot=0x16, process=None, shared=True)
                errors, calls, protections = [], [], []
                emu = SimpleNamespace(get_file_manager=lambda: manager,
                                      get_ptr_size=lambda: ptr_size,
                                      get_current_process=lambda: process,
                                      get_address_map=lambda _: view_map,
                                      mem_write=lambda *_: None,
                                      mem_protect=lambda *args: protections.append(args),
                                      set_last_error=errors.append)
                bridge = VirtualFileBridge(self.persona["current_dir"],
                                           ArtifactCatalog(self.root / "artifacts"))
                bridge.mapping_handle_owners[0x999] = {id(process)}
                def original(params):
                    calls.append(params)
                    return 0x40000
                for access, high, low, length, expected_error in (
                    (2, 0, 1, 4, 87),       # offset must align to 64 KiB
                    (2, 0, 0, 0x20001, 87),
                    (2, 0, 0x20000, 0, 87),
                    (1, 0, 0, 4, 50),      # copy-on-write is not modeled
                    (0x22, 0, 0, 4, 5),   # executable view of RW section
                    (2, 1, 0, 4, 87),
                ):
                    self.assertEqual(bridge._map_view_of_file(
                        emu, "kernel32.MapViewOfFile", original,
                        [0x999, access, high, low, length]), 0)
                    self.assertEqual(errors[-1], expected_error)
                self.assertFalse(calls)
                self.assertEqual(bridge._map_view_of_file(
                    emu, "kernel32.MapViewOfFile", original,
                    [0x999, 4, 0, 0x10000, 0]), 0x40000)
                self.assertEqual(calls[-1], [0x999, 4, 0, 0x10000, 0x10000])
                self.assertEqual(protections[-1], (0x40000, 0x10000, 2))
                self.assertEqual(view_map.prot, 2)
                self.assertIs(view_map.process, process)
                self.assertFalse(view_map.shared)
                section.prot = 0x40
                self.assertEqual(bridge._map_view_of_file(
                    emu, "kernel32.MapViewOfFile", original,
                    [0x999, 0x22, 0, 0, 4]), 0x40000)
                self.assertEqual(protections[-1], (0x40000, 0x10000, 0x16))

    def test_pagefile_section_rejects_unmodeled_protection_before_engine(self):
        manager = SimpleNamespace(file_handles={})
        errors = []
        emu = SimpleNamespace(get_file_manager=lambda: manager,
                              get_ptr_size=lambda: 8, set_last_error=errors.append)
        bridge = VirtualFileBridge(self.persona["current_dir"],
                                   ArtifactCatalog(self.root / "artifacts"))
        original = lambda _: self.fail("invalid pagefile section reached engine")
        for protection in (0, 0x2000004, 0x4000004):
            self.assertEqual(bridge._create_file_mapping(
                emu, "kernel32.CreateFileMappingW", original,
                [0xFFFFFFFFFFFFFFFF, 0, protection, 0, 0x1000, 0]), 0)
            self.assertEqual(errors[-1], 50)

    def test_named_pagefile_mapping_open_runs_under_x86_and_x64_cpu(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                name = f"named_pagefile_mapping_{arch}.exe"
                image = (FIXTURES / name).read_bytes()
                result = run_native(image, inspect_pe(image, name), self.persona,
                                    root, [], 10, 100_000)
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                calls = [event for entry in report["entry_points"]
                         for event in entry["events"]]
                opens = [event for event in calls
                         if event.get("api_name") == "kernel32.OpenFileMappingW"]
                self.assertEqual(len(opens), 1)
                self.assertNotEqual(opens[0]["ret_val"], "0x0")
                self.assertTrue(any(event.get("api_name") == "kernel32.ExitProcess"
                                    and event.get("args") == ["0x1"] for event in calls))
                views = [event for event in report["virtual_file_events"]
                         if event["event"] == "virtual_mapping_view"
                         and event.get("path") == "<pagefile>"]
                self.assertEqual(len(views), 2)

    def test_guest_mapping_duplicate_runs_under_x86_and_x64_cpu(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                name = f"named_pagefile_duplicate_{arch}.exe"
                image = (FIXTURES / name).read_bytes()
                result = run_native(image, inspect_pe(image, name), self.persona,
                                    root, [], 10, 100_000)
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                calls = [event for entry in report["entry_points"]
                         for event in entry.get("events") or []]
                self.assertEqual(len([event for event in calls
                                      if event.get("api_name") == "kernel32.DuplicateHandle"
                                      and event.get("ret_val") == "0x1"]), 1)
                self.assertTrue(any(event.get("api_name") == "kernel32.ExitProcess"
                                    and event.get("args") == ["0x1"] for event in calls))
                views = [item for item in report["entry_points"][-1]["memory"]["layout"]
                         if item["tag"].startswith("api.MapViewOfFile.")]
                self.assertEqual(len(views), 2)
                self.assertTrue(all(_report_blob(report["data"], item["data_ref"])[:4]
                                    == b"Pers" for item in views))

    def test_pagefile_views_share_committed_cpu_writes(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                name = f"named_pagefile_coherent_{arch}.exe"
                image = (FIXTURES / name).read_bytes()
                result = run_native(image, inspect_pe(image, name), self.persona,
                                    root, [], 10, 100_000)
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                calls = [event for entry in report["entry_points"]
                         for event in entry.get("events") or []]
                self.assertTrue(any(event.get("api_name") == "kernel32.ExitProcess"
                                    and event.get("args") == ["0x1"] for event in calls))
                maps = [item for item in report["entry_points"][-1]["memory"]["layout"]
                        if item["tag"].startswith("api.MapViewOfFile.")]
                self.assertEqual(len(maps), 2)
                self.assertTrue(all(_report_blob(report["data"], item["data_ref"])[:4]
                                    == b"Cohr" for item in maps))

    def test_guest_file_views_share_committed_cpu_writes(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                name = f"mapped_file_coherent_{arch}.exe"
                image = (FIXTURES / name).read_bytes()
                result = run_native(image, inspect_pe(image, name), self.persona,
                                    root, [], 10, 100_000)
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                self.assertFalse(result["api_coverage"]["signature_only_calls"])
                calls = [event for entry in report["entry_points"]
                         for event in entry.get("events") or []]
                self.assertTrue(any(event.get("api_name") == "kernel32.ExitProcess"
                                    and event.get("args") == ["0x1"] for event in calls))
                maps = [item for item in report["entry_points"][-1]["memory"]["layout"]
                        if item["tag"].startswith("api.MapViewOfFile.")]
                self.assertEqual(len(maps), 2)
                self.assertTrue(all(_report_blob(report["data"], item["data_ref"])[:8]
                                    == b"XYZ!EFGH" for item in maps))
                self.assertTrue(any(item["source"] == "virtual_file_final"
                                    and (root / "artifacts" / item["file"]).read_bytes()
                                    == b"XYZ!EFGH" for item in result["artifacts"]))

    def test_guest_file_io_refreshes_two_live_views(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                name = f"mapped_file_io_coherent_{arch}.exe"
                image = (FIXTURES / name).read_bytes()
                result = run_native(image, inspect_pe(image, name), self.persona,
                                    root, [], 10, 100_000)
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                calls = [event for entry in report["entry_points"]
                         for event in entry.get("events") or []]
                self.assertEqual(sum(event.get("api_name") == "kernel32.WriteFile"
                                     and event.get("ret_val") == "0x1" for event in calls), 2)
                self.assertTrue(any(event.get("api_name") == "kernel32.ExitProcess"
                                    and event.get("args") == ["0x1"] for event in calls))
                maps = [item for item in report["entry_points"][-1]["memory"]["layout"]
                        if item["tag"].startswith("api.MapViewOfFile.")]
                self.assertEqual(len(maps), 2)
                self.assertTrue(all(_report_blob(report["data"], item["data_ref"])[:8]
                                    == b"QRSTEFGH" for item in maps))
                self.assertTrue(any(item["source"] == "virtual_file_final"
                                    and (root / "artifacts" / item["file"]).read_bytes()
                                    == b"QRSTEFGH" for item in result["artifacts"]))

    def test_guest_file_views_mirror_only_overlapping_offsets(self):
        file = SimpleNamespace(path=r"C:\guest.bin", data=BytesIO(b"\0" * 0x20000),
                               bytes_written=0)
        first = bytearray(0x20000)
        second = bytearray(0x10000)
        regions = {0x10000: first, 0x40000: second}
        def locate(address, size):
            for base, data in regions.items():
                if base <= address and address + size <= base + len(data):
                    return data, address - base
            raise ValueError("address outside modeled views")
        def read(address, size):
            data, offset = locate(address, size)
            return bytes(data[offset:offset + size])
        def write(address, value):
            data, offset = locate(address, len(value))
            data[offset:offset + len(value)] = value
        emu = SimpleNamespace(mem_read=read, mem_write=write,
                              get_address_map=lambda address: SimpleNamespace(free=False))
        bridge = VirtualFileBridge(self.persona["current_dir"],
                                   ArtifactCatalog(self.root / "artifacts"))
        bridge.mapped_guest_views[0x10000] = (file, 0, len(first), True)
        bridge.mapped_guest_views[0x40000] = (file, 0x10000, len(second), False)
        write(0x20000, b"ABCD")
        bridge.observe_mapped_api_write(emu, 0x20000, 4)
        self.assertEqual(second[:4], b"ABCD")
        self.assertEqual(file.data.getvalue()[0x10000:0x10004], b"ABCD")
        self.assertEqual(first[:4], b"\0" * 4)

    def test_inherited_file_io_does_not_read_foreign_view_and_scopes_refresh(self):
        parent, child = object(), object()
        file = GuestFile(None, r"C:\guest.bin", data=b"ABCDEFGH")
        opened = SharedGuestFileView(file)
        manager = SimpleNamespace(file_handles={17: opened})
        bridge = VirtualFileBridge(self.persona["current_dir"],
                                   ArtifactCatalog(self.root / "artifacts"))
        bridge.file_handle_owners[17] = {id(child)}
        bridge.mapped_guest_views[0x30000] = (file, 0, 8, True)
        bridge.mapped_guest_view_owners[0x30000] = id(parent)
        view_data = bytearray(b"ABCDEFGH")
        allowed = []
        scopes = []
        def read(address, size):
            if 0x30000 <= address < 0x30008:
                raise AssertionError("file I/O read a foreign guest view")
            return b"\0" * size
        def write(address, data):
            if 0x30000 <= address < 0x30008:
                if not allowed or (address, len(data), "w") != allowed[-1]:
                    raise AssertionError("unscoped foreign guest view write")
                view_data[address - 0x30000:address - 0x30000 + len(data)] = data
        class Allowance:
            def __init__(self, address, size, mode):
                self.entry = (address, size, mode)
            def __enter__(self):
                allowed.append(self.entry)
                scopes.append(self.entry)
            def __exit__(self, *_):
                allowed.pop()
        bridge.api_memory_allowance = Allowance
        emu = SimpleNamespace(get_current_process=lambda: child,
                              get_file_manager=lambda: manager,
                              mem_read=read, mem_write=write)
        self.assertEqual(bridge._closed_file_operation(
            emu, "kernel32.ReadFile", lambda _: 1, [17, 0x10000, 4, 0, 0]), 1)
        self.assertEqual(bridge._closed_file_operation(
            emu, "kernel32.WriteFile",
            lambda _: (opened.add_data(b"ZZZZ"), 1)[1],
            [17, 0x10000, 4, 0, 0]), 1)
        self.assertEqual(file.data.getvalue(), b"ZZZZEFGH")
        self.assertEqual(view_data, b"ZZZZEFGH")
        self.assertEqual(scopes, [(0x30000, 8, "w")])

    def test_pagefile_section_bytes_survive_unmap_and_remap(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                name = f"named_pagefile_remap_{arch}.exe"
                image = (FIXTURES / name).read_bytes()
                result = run_native(image, inspect_pe(image, name), self.persona,
                                    root, [], 10, 100_000)
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                calls = [event for entry in report["entry_points"]
                         for event in entry.get("events") or []]
                self.assertTrue(any(event.get("api_name") == "kernel32.UnmapViewOfFile"
                                    and event.get("ret_val") == "0x1" for event in calls))
                self.assertTrue(any(event.get("api_name") == "kernel32.ExitProcess"
                                    and event.get("args") == ["0x1"] for event in calls))
                maps = [item for item in report["entry_points"][-1]["memory"]["layout"]
                        if item["tag"].startswith("api.MapViewOfFile.")]
                self.assertEqual(len(maps), 2)
                self.assertTrue(all(item["is_free"] for item in maps))
                self.assertTrue(all(_report_blob(report["data"], item["data_ref"])[:4]
                                    == b"Pers" for item in maps))

    def test_pagefile_views_mirror_only_overlapping_section_offsets(self):
        section = SimpleNamespace(size=0x20000)
        first = bytearray(0x20000)
        second = bytearray(0x10000)
        regions = {0x10000: first, 0x40000: second}
        def locate(address, size):
            for base, data in regions.items():
                if base <= address and address + size <= base + len(data):
                    return data, address - base
            raise ValueError("address outside modeled views")
        def read(address, size):
            data, offset = locate(address, size)
            return bytes(data[offset:offset + size])
        def write(address, value):
            data, offset = locate(address, len(value))
            data[offset:offset + len(value)] = value
        emu = SimpleNamespace(mem_read=read, mem_write=write,
                              get_address_map=lambda address: SimpleNamespace(
                                  base=0x10000 if address < 0x40000 else 0x40000,
                                  free=False))
        bridge = VirtualFileBridge(self.persona["current_dir"],
                                   ArtifactCatalog(self.root / "artifacts"))
        bridge.pagefile_views[0x10000] = (section, 0, len(first))
        bridge.pagefile_views[0x40000] = (section, 0x10000, len(second))
        write(0x20000, b"ABCD")
        bridge.observe_mapped_api_write(emu, 0x20000, 4)
        self.assertEqual(second[:4], b"ABCD")
        self.assertEqual(bridge._pagefile_bytes(section)[0x10000:0x10004], b"ABCD")
        write(0x40002, b"WXYZ")
        bridge.observe_mapped_api_write(emu, 0x40002, 4)
        self.assertEqual(first[0x10002:0x10006], b"WXYZ")
        self.assertEqual(second[:6], b"ABWXYZ")
        self.assertEqual(first[:4], b"\0" * 4)

    def test_guest_child_cannot_open_parent_named_mapping_after_parent_exit(self):
        for arch, machine in (("x86", 0x14C), ("x64", 0x8664)):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                name = f"child_parent_named_mapping_{arch}.exe"
                image = (FIXTURES / name).read_bytes()
                dll = root / f"companion_{arch}.dll"
                dll.write_bytes(build_relocatable_companion(
                    machine, 0x180000000 if arch == "x64" else 0x50000000))
                result = run_native(image, inspect_pe(image, name), self.persona,
                                    root, [dll], 10, 200_000)
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                entries = report["entry_points"]
                self.assertEqual(len(entries), 3)
                self.assertEqual(entries[-1]["ret_val"], "0x0")
                opens = [event for event in entries[-1]["events"]
                         if event.get("api_name") == "kernel32.OpenFileMappingW"]
                self.assertEqual(len(opens), 1)
                self.assertEqual(opens[0]["ret_val"], "0x0")
                views = [event for event in report["virtual_file_events"]
                         if event["event"] == "virtual_mapping_view"
                         and event.get("path") == "<pagefile>"]
                self.assertEqual(len(views), 1)
                cleanup = [event for event in report["virtual_file_events"]
                           if event["event"] == "virtual_file_process_cleanup"
                           and event["views"] == 1 and event["mappings"] == 1]
                self.assertEqual(len(cleanup), 1)
                retired = [event for event in report["virtual_file_events"]
                           if event["event"] == "virtual_mapping_view_process_exit"
                           and event["base"] == views[0]["base"]]
                self.assertEqual(len(retired), 1)

    def test_parent_named_mapping_view_is_retired_before_child_runs(self):
        for arch, machine in (("x86", 0x14C), ("x64", 0x8664)):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                name = f"child_parent_named_mapping_foreign_read_{arch}.exe"
                image = (FIXTURES / name).read_bytes()
                dll = root / f"companion_{arch}.dll"
                dll.write_bytes(build_relocatable_companion(
                    machine, 0x180000000 if arch == "x64" else 0x50000000))
                result = run_native(image, inspect_pe(image, name), self.persona,
                                    root, [dll], 10, 200_000)
                report = json.loads((root / result["engine_report"]).read_text())
                views = [event for event in report["virtual_file_events"]
                         if event["event"] == "virtual_mapping_view"
                         and event.get("path") == "<pagefile>"]
                self.assertFalse(result["errors"])
                self.assertEqual(report["entry_points"][-1]["ret_val"], "0x0")
                self.assertEqual(len(views), 1)
                retired = [event for event in report["virtual_file_events"]
                           if event["event"] == "virtual_mapping_view_process_exit"
                           and event["base"] == views[0]["base"]]
                self.assertEqual(len(retired), 1)
                opens = [event for event in report["entry_points"][-1]["events"]
                         if event.get("api_name") == "kernel32.OpenFileMappingW"]
                self.assertEqual([event["ret_val"] for event in opens], ["0x0"])

    def test_guest_named_mapping_open_cannot_reach_host_section(self):
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.CreateFileMappingW.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                               ctypes.c_uint32, ctypes.c_uint32,
                                               ctypes.c_uint32, ctypes.c_wchar_p]
        kernel.CreateFileMappingW.restype = ctypes.c_void_p
        kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel.CloseHandle.restype = ctypes.c_int
        for arch, machine in (("x86", 0x14C), ("x64", 0x8664)):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                name = "Local\\EmumeeHostCanary-" + uuid.uuid4().hex
                host_handle = kernel.CreateFileMappingW(
                    ctypes.c_void_p(-1), None, 4, 0, 4096, name)
                self.assertTrue(host_handle, ctypes.get_last_error())
                try:
                    root = Path(folder)
                    filename = f"host_named_mapping_probe_{arch}.exe"
                    image = build_open_host_named_mapping_probe(machine, name)
                    result = run_native(image, inspect_pe(image, filename),
                                        self.persona, root, [], 10, 100_000)
                    report = json.loads((root / result["engine_report"]).read_text())
                    self.assertFalse(result["errors"])
                    calls = [event for entry in report["entry_points"]
                             for event in entry.get("events") or []]
                    opens = [event for event in calls
                             if event.get("api_name") == "kernel32.OpenFileMappingW"]
                    self.assertEqual(len(opens), 1)
                    self.assertEqual(opens[0]["ret_val"], "0x0")
                    self.assertTrue(any(event.get("api_name") == "kernel32.ExitProcess"
                                        and event.get("args") == ["0x1"] for event in calls))
                finally:
                    self.assertTrue(kernel.CloseHandle(host_handle))

    def test_named_mapping_opens_existing_guest_section_with_scoped_rights(self):
        parent = SimpleNamespace(pid=1)
        child = SimpleNamespace(pid=2)
        current = [parent]
        names = {0x1000: "Local\\section-a", 0x2000: "section-a",
                 0x3000: "GLOBAL\\section-a", 0x4000: "missing"}
        maps = {}
        next_handle = [0x900]
        def allocate():
            next_handle[0] += 1
            return next_handle[0]
        def create_map(_file, name, size, protection):
            handle = allocate()
            maps[handle] = SimpleNamespace(name=name, backed_file=None,
                                            size=size, prot=protection,
                                            get_handle=allocate)
            return handle
        manager = SimpleNamespace(file_handles={}, file_maps=maps,
                                  file_create_mapping=create_map,
                                  get_mapping_from_handle=maps.get)
        view_map = SimpleNamespace(base=0x40000, size=0x1000, prot=0x16,
                                   process=None, shared=True)
        errors, protections, map_calls = [], [], []
        emu = SimpleNamespace(get_file_manager=lambda: manager,
                              get_current_process=lambda: current[0],
                              get_ptr_size=lambda: 8,
                              read_mem_string=lambda address, width, **_: names[address],
                              get_address_map=lambda _: view_map,
                              mem_read=lambda _, size: b"\0" * size,
                              mem_write=lambda *_: None,
                              mem_protect=lambda *args: protections.append(args),
                              set_last_error=errors.append)
        bridge = VirtualFileBridge(self.persona["current_dir"],
                                   ArtifactCatalog(self.root / "artifacts"))
        def create_original(params):
            errors.append(0)
            return create_map(params[0], names[params[5]], params[4], params[2])
        invalid = 0xFFFFFFFFFFFFFFFF
        first = bridge._create_file_mapping(
            emu, "kernel32.CreateFileMappingW", create_original,
            [invalid, 0, 4, 0, 4, 0x1000])
        self.assertIn(first, maps)
        self.assertEqual(errors[-1], 0)
        current[0] = child
        read_handle = bridge._open_file_mapping(
            emu, "kernel32.OpenFileMappingW", None, [4, 0, 0x2000])
        self.assertIs(maps[read_handle], maps[first])
        self.assertEqual(errors[-1], 0)
        self.assertEqual(bridge._map_view_of_file(
            emu, "kernel32.MapViewOfFile", lambda _: self.fail("write reached engine"),
            [read_handle, 2, 0, 0, 4]), 0)
        self.assertEqual(errors[-1], 5)
        self.assertEqual(bridge._map_view_of_file(
            emu, "kernel32.MapViewOfFile",
            lambda params: (map_calls.append(params) or 0x40000),
            [read_handle, 4, 0, 0, 0]), 0x40000)
        self.assertEqual(map_calls[-1], [read_handle, 4, 0, 0, 4])
        self.assertEqual(protections[-1], (0x40000, 0x1000, 2))
        self.assertIs(view_map.process, child)
        self.assertEqual(bridge._unmap_view_of_file(
            emu, "kernel32.UnmapViewOfFile", lambda _: 1, [0x40000]), 1)
        duplicate = bridge._create_file_mapping(
            emu, "kernel32.CreateFileMappingW",
            lambda _: self.fail("existing name reached engine"),
            [invalid, 0, 2, 0, 999, 0x2000])
        self.assertIs(maps[duplicate], maps[first])
        self.assertEqual(maps[duplicate].size, 4)
        self.assertEqual(errors[-1], 183)
        self.assertEqual(bridge._open_file_mapping(
            emu, "kernel32.OpenFileMappingW", None, [4, 0, 0x3000]), 0)
        self.assertEqual(errors[-1], 2)  # Global namespace is separate.
        current[0] = parent
        self.assertEqual(bridge._close_handle(
            emu, "kernel32.CloseHandle", None, [first]), 1)
        current[0] = child
        self.assertEqual(bridge._close_handle(
            emu, "kernel32.CloseHandle", None, [read_handle]), 1)
        self.assertEqual(bridge._close_handle(
            emu, "kernel32.CloseHandle", None, [duplicate]), 1)
        self.assertEqual(bridge._open_file_mapping(
            emu, "kernel32.OpenFileMappingW", None, [4, 0, 0x2000]), 0)
        self.assertEqual(errors[-1], 2)

    def test_guest_mapping_flush_and_file_io_share_bytes(self):
        path = self.persona["current_dir"] + r"\mapping-io.bin"
        file = GuestFile(None, path, data=b"ABCDEFGH")
        opened = SharedGuestFileView(file)
        manager = SimpleNamespace(file_handles={0x888: opened})
        memory = {0x20000: b"XYZ!EFGH"}
        writes, errors = [], []
        def memory_write(address, data):
            writes.append((address, data))
            memory[address] = data
        emu = SimpleNamespace(get_file_manager=lambda: manager,
                              mem_read=lambda address, size: memory[address][:size],
                              mem_write=memory_write, set_last_error=errors.append,
                              get_address_map=lambda _: SimpleNamespace(
                                  base=0x20000, size=8, free=False))
        bridge = VirtualFileBridge(self.persona["current_dir"],
                                   ArtifactCatalog(self.root / "artifacts"))
        bridge.mapped_guest_views[0x20000] = (file, 0, 8, True)
        bridge.file_open_options[0x888] = (bridge._key(path), 3, 7)
        bridge.record_cpu_mapped_write(emu, 0x20000, 8)
        bridge.flush_pending_mapped_cpu_writes(emu)
        self.assertEqual(bridge._closed_file_operation(
            emu, "kernel32.ReadFile", lambda _: opened.get_data(8),
            [0x888, 0, 8, 0, 0]), b"XYZ!EFGH")
        self.assertEqual(file.data.getvalue(), b"XYZ!EFGH")
        self.assertEqual(bridge._flush_view_of_file(
            emu, "kernel32.FlushViewOfFile", None, [0x20002, 7]), 0)
        self.assertEqual(errors[-1], 87)
        memory[0x20000] = b"QRSTEFGH"
        self.assertEqual(bridge._flush_view_of_file(
            emu, "kernel32.FlushViewOfFile", None, [0x20002, 0]), 1)
        self.assertEqual(file.data.getvalue(), b"QRSTEFGH")
        opened.position = 4
        self.assertEqual(bridge._closed_file_operation(
            emu, "kernel32.WriteFile", lambda _: (opened.add_data(b"zz") or 1),
            [0x888, 0, 2, 0, 0]), 1)
        self.assertEqual(file.data.getvalue(), b"QRSTzzGH")
        self.assertEqual(writes[-1], (0x20000, b"QRSTzzGH"))
        memory[0x20000] = b"LIVEzzGH"
        bridge.capture_live_views(emu)
        self.assertEqual(file.data.getvalue(), b"LIVEzzGH")
        self.assertTrue(any(e["event"] == "virtual_mapping_writeback"
                            and e["reason"] == "end_of_run" for e in bridge.events))

    def test_exclusive_guest_file_open_inside_cpu_emulation(self):
        for arch in ("x86", "x64"):
            for variant in ("W", "A"):
                with self.subTest(arch=arch, variant=variant), tempfile.TemporaryDirectory() as folder:
                    root = Path(folder)
                    name = f"sharing{'_a' if variant == 'A' else ''}_{arch}.exe"
                    image = (FIXTURES / name).read_bytes()
                    result = run_native(image, inspect_pe(image, name), self.persona,
                                        root, [], 10, 100_000)
                    report = json.loads((root / result["engine_report"]).read_text())
                    self.assertFalse(result["errors"])
                    self.assertFalse(result["api_coverage"]["signature_only_calls"])
                    self.assertEqual(len([event for event in report["virtual_file_events"]
                                          if event["event"] == "virtual_file_open_denied"
                                          and event["reason"] == "sharing violation"]), 1)
                    self.assertTrue(any(event.get("api_name") == "kernel32.ExitProcess"
                                        and event.get("args") == ["0x1"]
                                        for entry in report["entry_points"]
                                        for event in entry["events"]))

    def test_guest_file_sharing_and_access_rights(self):
        path = self.persona["current_dir"] + r"\sharing.bin"
        source = GuestFile(None, path, data=b"ABCDE")
        manager = SimpleNamespace(files=[source], file_handles={})
        manager.does_file_exist = lambda candidate: candidate.lower() == path.lower()
        errors, writes = [], []
        emu = SimpleNamespace(get_file_manager=lambda: manager,
                              read_mem_string=lambda _pointer, _width: path,
                              set_last_error=errors.append,
                              mem_write=lambda address, data: writes.append((address, data)))
        bridge = VirtualFileBridge(self.persona["current_dir"],
                                   ArtifactCatalog(self.root / "artifacts"))
        next_handle = iter((0x101, 0x102, 0x103))
        def original(_params):
            handle = next(next_handle)
            manager.file_handles[handle] = source.duplicate()
            return handle
        read_only = [1, 0x80000000, 1, 0, 3, 0x80, 0]
        first = bridge._create_file(emu, "kernel32.CreateFileW", original, read_only[:])
        self.assertEqual(first, 0x101)
        self.assertEqual(bridge._create_file(emu, "kernel32.CreateFileW", original,
                                             [1, 0x40000000, 7, 0, 3, 0x80, 0]),
                         0xFFFFFFFF)
        self.assertEqual(errors[-1], 32)
        self.assertEqual(bridge._closed_file_operation(
            emu, "kernel32.WriteFile", lambda _params: self.fail("write reached Speakeasy"),
            [first, 1, 1, 2, 0]), 0)
        self.assertEqual(errors[-1], 5)
        self.assertEqual(writes[-1], (2, b"\0" * 4))
        self.assertEqual(bridge._close_handle(emu, "kernel32.CloseHandle", None, [first]), 1)
        second = bridge._create_file(emu, "kernel32.CreateFileW", original,
                                     [1, 0x40000000, 7, 0, 3, 0x80, 0])
        self.assertEqual(second, 0x102)
        self.assertEqual(bridge._create_file(emu, "kernel32.CreateFileW", original,
                                             [1, 0x80000000, 1, 0, 3, 0x80, 0]),
                         0xFFFFFFFF)
        self.assertEqual(errors[-1], 32)
        self.assertEqual(bridge._close_handle(emu, "kernel32.CloseHandle", None, [second]), 1)

    def test_delete_on_close_waits_for_last_guest_handle_and_extracts_bytes(self):
        path = self.persona["current_dir"] + r"\temporary-payload.bin"
        source = GuestFile(None, path, data=b"PAYLOAD")
        manager = SimpleNamespace(files=[source], file_handles={})
        manager.does_file_exist = lambda candidate: any(
            item.path.lower() == candidate.lower() for item in manager.files)
        errors = []
        emu = SimpleNamespace(get_file_manager=lambda: manager,
                              read_mem_string=lambda _pointer, _width: path,
                              set_last_error=errors.append)
        bridge = VirtualFileBridge(self.persona["current_dir"],
                                   ArtifactCatalog(self.root / "artifacts"))
        handles = iter((0x401, 0x402))
        def original(_params):
            handle = next(handles)
            manager.file_handles[handle] = source.duplicate()
            return handle
        first = bridge._create_file(emu, "kernel32.CreateFileW", original,
                                    [1, 0x40000000, 7, 0, 3, 0x04000000, 0])
        self.assertEqual(first, 0x401)
        second = bridge._create_file(emu, "kernel32.CreateFileW", original,
                                     [1, 0x80000000, 7, 0, 3, 0x80, 0])
        self.assertEqual(second, 0x402)
        self.assertEqual(bridge._close_handle(emu, "kernel32.CloseHandle", None, [first]), 1)
        self.assertTrue(manager.does_file_exist(path))
        self.assertEqual(bridge._create_file(
            emu, "kernel32.CreateFileW", lambda _params: self.fail("forbidden open reached Speakeasy"),
            [1, 0x80000000, 3, 0, 3, 0x80, 0]), 0xFFFFFFFF)
        self.assertEqual(errors[-1], 32)
        self.assertEqual(bridge._close_handle(emu, "kernel32.CloseHandle", None, [second]), 1)
        self.assertFalse(manager.does_file_exist(path))
        self.assertEqual(len([event for event in bridge.events
                              if event["event"] == "virtual_file_delete_on_close"]), 1)
        self.assertTrue(any(item["source"] == "virtual_file_delete_on_close"
                            and (self.root / "artifacts" / item["file"]).read_bytes() == b"PAYLOAD"
                            for item in bridge.catalog.items))

    def test_delete_on_close_rejects_nonsharing_and_configured_mapping(self):
        path = self.persona["current_dir"] + r"\delete-flag.bin"
        source = GuestFile(None, path, data=b"A")
        manager = SimpleNamespace(files=[source], file_handles={0x403: SharedGuestFileView(source)})
        manager.does_file_exist = lambda candidate: candidate.lower() == path.lower()
        errors = []
        emu = SimpleNamespace(get_file_manager=lambda: manager,
                              read_mem_string=lambda _pointer, _width: path,
                              set_last_error=errors.append)
        bridge = VirtualFileBridge(self.persona["current_dir"],
                                   ArtifactCatalog(self.root / "artifacts"))
        bridge.file_open_options[0x403] = (bridge._key(path), 1, 3)
        params = [1, 0x40000000, 7, 0, 3, 0x04000000, 0]
        self.assertEqual(bridge._create_file(
            emu, "kernel32.CreateFileW", lambda _params: self.fail("sharing denial missed"),
            params), 0xFFFFFFFF)
        self.assertEqual(errors[-1], 32)
        manager.files.clear()
        manager.file_handles.clear()
        bridge.file_open_options.clear()
        manager.does_file_exist = lambda candidate: candidate.lower() == path.lower()
        self.assertEqual(bridge._create_file(
            emu, "kernel32.CreateFileW", lambda _params: self.fail("mapping reached Speakeasy"),
            params), 0xFFFFFFFF)
        self.assertEqual(errors[-1], 50)
        self.assertTrue(bridge.unsupported)

    def test_file_disposition_waits_for_last_handle_and_blocks_reopen(self):
        path = self.persona["current_dir"] + r"\disposition.bin"
        source = GuestFile(None, path, data=b"PAYLOAD")
        manager = SimpleNamespace(files=[source], file_handles={
            0x501: SharedGuestFileView(source), 0x502: SharedGuestFileView(source)})
        manager.does_file_exist = lambda candidate: any(
            item.path.lower() == candidate.lower() for item in manager.files)
        errors = []
        emu = SimpleNamespace(get_file_manager=lambda: manager,
                              read_mem_string=lambda _pointer, _width: path,
                              mem_read=lambda address, size: b"\x01" if address == 1 and size == 1 else b"",
                              set_last_error=errors.append)
        bridge = VirtualFileBridge(self.persona["current_dir"],
                                   ArtifactCatalog(self.root / "artifacts"))
        bridge.file_open_options[0x501] = (bridge._key(path), 4, 7)
        bridge.file_open_options[0x502] = (bridge._key(path), 1, 7)
        self.assertEqual(bridge._set_file_information(
            emu, "kernel32.SetFileInformationByHandle", None, [0x501, 4, 1, 1]), 1)
        self.assertEqual(bridge._create_file(
            emu, "kernel32.CreateFileW", lambda _params: self.fail("pending reopen reached Speakeasy"),
            [1, 0x80000000, 7, 0, 3, 0x80, 0]), 0xFFFFFFFF)
        self.assertEqual(errors[-1], 5)
        bridge._close_handle(emu, "kernel32.CloseHandle", None, [0x501])
        self.assertTrue(manager.does_file_exist(path))
        bridge._close_handle(emu, "kernel32.CloseHandle", None, [0x502])
        self.assertFalse(manager.does_file_exist(path))
        self.assertTrue(any(item["source"] == "virtual_file_disposition_delete"
                            and (self.root / "artifacts" / item["file"]).read_bytes() == b"PAYLOAD"
                            for item in bridge.catalog.items))

    def test_file_disposition_cancel_rights_and_flag_invariance(self):
        path = self.persona["current_dir"] + r"\cancel-disposition.bin"
        source = GuestFile(None, path, data=b"A")
        manager = SimpleNamespace(files=[source], file_handles={0x503: SharedGuestFileView(source)})
        errors = []
        emu = SimpleNamespace(get_file_manager=lambda: manager,
                              mem_read=lambda address, _size: b"\x01" if address == 1 else b"\x00",
                              set_last_error=errors.append)
        bridge = VirtualFileBridge(self.persona["current_dir"],
                                   ArtifactCatalog(self.root / "artifacts"))
        bridge.file_open_options[0x503] = (bridge._key(path), 2, 7)
        api = "kernel32.SetFileInformationByHandle"
        self.assertEqual(bridge._set_file_information(emu, api, None, [0x503, 4, 1, 1]), 0)
        self.assertEqual(errors[-1], 5)
        bridge.file_open_options[0x503] = (bridge._key(path), 4, 7)
        self.assertEqual(bridge._set_file_information(emu, api, None, [0x503, 4, 1, 0]), 0)
        self.assertEqual(errors[-1], 24)
        self.assertEqual(bridge._set_file_information(emu, api, None, [0x503, 4, 1, 2]), 1)
        self.assertEqual(bridge._set_file_information(emu, api, None, [0x503, 4, 2, 1]), 1)
        self.assertFalse(bridge.pending_disposition_files)
        bridge._close_handle(emu, "kernel32.CloseHandle", None, [0x503])
        self.assertIn(source, manager.files)
        manager.file_handles[0x504] = SharedGuestFileView(source)
        bridge.file_open_options[0x504] = (bridge._key(path), 4, 7)
        bridge.delete_on_close_files[id(source)] = source
        self.assertEqual(bridge._set_file_information(emu, api, None, [0x504, 4, 2, 1]), 1)
        bridge._close_handle(emu, "kernel32.CloseHandle", None, [0x504])
        self.assertNotIn(source, manager.files)

    def test_file_disposition_invalid_buffers_and_host_mapping_fail_closed(self):
        path = self.persona["current_dir"] + r"\disposition-guard.bin"
        source = GuestFile(None, path, data=b"A")
        manager = SimpleNamespace(file_handles={0x505: SharedGuestFileView(source)})
        errors = []
        emu = SimpleNamespace(get_file_manager=lambda: manager,
                              mem_read=lambda _address, _size: (_ for _ in ()).throw(OSError("invalid guest pointer")),
                              set_last_error=errors.append)
        bridge = VirtualFileBridge(self.persona["current_dir"],
                                   ArtifactCatalog(self.root / "artifacts"))
        bridge.file_open_options[0x505] = (bridge._key(path), 4, 7)
        api = "kernel32.SetFileInformationByHandle"
        self.assertEqual(bridge._set_file_information(emu, api, None, [0x505, 4, 1, 1]), 0)
        self.assertEqual(errors[-1], 998)
        self.assertEqual(bridge._set_file_information(emu, api, None, [0x505, 4, 1, 65]), 0)
        self.assertEqual(errors[-1], 50)
        self.assertEqual(bridge._set_file_information(emu, api, None, [0x505, 9, 1, 1]), 0)
        self.assertEqual(errors[-1], 50)
        self.assertFalse(bridge.pending_disposition_files)
        manager.file_handles[0x505] = GuestFile(None, path, config=SimpleNamespace())
        self.assertEqual(bridge._set_file_information(emu, api, None, [0x505, 4, 1, 1]), 0)
        self.assertEqual(errors[-1], 50)
        self.assertEqual(len(bridge.unsupported), 3)

    def test_file_end_info_resizes_shared_bytes_without_moving_pointer(self):
        path = self.persona["current_dir"] + r"\end-info.bin"
        source = GuestFile(None, path, data=b"ABCDE")
        first, second = SharedGuestFileView(source), SharedGuestFileView(source)
        first.seek(4, 0)
        manager = SimpleNamespace(file_handles={0x506: first, 0x507: second})
        errors = []
        values = {1: (3).to_bytes(8, "little", signed=True),
                  2: (6).to_bytes(8, "little", signed=True)}
        emu = SimpleNamespace(get_file_manager=lambda: manager,
                              mem_read=lambda address, _size: values[address],
                              set_last_error=errors.append)
        bridge = VirtualFileBridge(self.persona["current_dir"],
                                   ArtifactCatalog(self.root / "artifacts"))
        bridge.file_open_raw_access[0x506] = 0x2  # FILE_WRITE_DATA alone.
        api = "kernel32.SetFileInformationByHandle"
        self.assertEqual(bridge._set_file_information(emu, api, None, [0x506, 6, 1, 8]), 1)
        self.assertEqual((source.data.getvalue(), first.tell()), (b"ABC", 4))
        self.assertEqual(bridge._set_file_information(emu, api, None, [0x506, 6, 2, 16]), 1)
        self.assertEqual((source.data.getvalue(), first.tell()), (b"ABC\0\0\0", 4))
        self.assertEqual(second.get_data(6), b"ABC\0\0\0")
        self.assertEqual(errors[-1], 0)
        self.assertEqual([(event["old_size"], event["new_size"])
                          for event in bridge.events if event["event"] == "virtual_file_resize"],
                         [(5, 3), (3, 6)])

    def test_file_end_info_rejects_rights_bounds_and_unreadable_guest_memory(self):
        path = self.persona["current_dir"] + r"\end-info-guard.bin"
        source = GuestFile(None, path, data=b"ABCDE")
        view = SharedGuestFileView(source)
        manager = SimpleNamespace(file_handles={0x508: view})
        errors = []
        values = {1: (3).to_bytes(8, "little", signed=True),
                  2: (-1).to_bytes(8, "little", signed=True),
                  3: (MAX_ARTIFACT + 1).to_bytes(8, "little", signed=True)}
        emu = SimpleNamespace(get_file_manager=lambda: manager,
                              mem_read=lambda address, _size: values[address],
                              set_last_error=errors.append)
        bridge = VirtualFileBridge(self.persona["current_dir"],
                                   ArtifactCatalog(self.root / "artifacts"))
        api = "kernel32.SetFileInformationByHandle"
        for access in (0x4, 0x80000000):
            bridge.file_open_raw_access[0x508] = access
            self.assertEqual(bridge._set_file_information(emu, api, None, [0x508, 6, 1, 8]), 0)
            self.assertEqual(errors[-1], 5)
        bridge.file_open_raw_access[0x508] = 0x40000000
        for address, size, expected in ((1, 7, 24), (2, 8, 87),
                                        (3, 8, 223), (4, 8, 998)):
            self.assertEqual(bridge._set_file_information(emu, api, None,
                                                          [0x508, 6, address, size]), 0)
            self.assertEqual(errors[-1], expected)
        bridge.mapped_guest_views[0x1000] = (source, 0, 5, True)
        self.assertEqual(bridge._set_file_information(emu, api, None, [0x508, 6, 1, 8]), 0)
        self.assertEqual(errors[-1], 50)
        self.assertEqual(source.data.getvalue(), b"ABCDE")
        self.assertEqual(len(bridge.unsupported), 2)

    def test_file_rename_info_preserves_handle_and_recovers_replaced_bytes(self):
        old = self.persona["current_dir"] + r"\rename-old.bin"
        first = self.persona["current_dir"] + r"\rename-first.bin"
        final = self.persona["current_dir"] + r"\rename-final.bin"
        source = GuestFile(None, old, data=b"PAYLOAD")
        destination = GuestFile(None, final, data=b"OLD!")
        view = SharedGuestFileView(source)
        view.seek(3, 0)
        manager = SimpleNamespace(files=[source, destination], file_handles={0x509: view})
        errors = []
        memory = {}

        def put(address, name, *, replace=False, root=0):
            encoded = name.encode("utf-16le")
            memory[address] = struct.pack("<I4xQI", int(replace), root, len(encoded)) + encoded
            return len(memory[address])

        def read(address, size):
            for start, raw in memory.items():
                if start <= address < start + len(raw):
                    return raw[address - start:address - start + size]
            raise OSError("unmapped guest address")

        emu = SimpleNamespace(get_file_manager=lambda: manager, get_ptr_size=lambda: 8,
                              mem_read=read, set_last_error=errors.append)
        bridge = VirtualFileBridge(self.persona["current_dir"],
                                   ArtifactCatalog(self.root / "artifacts"))
        bridge.file_open_options[0x509] = (bridge._key(old), 4, 0)
        api = "kernel32.SetFileInformationByHandle"
        size_first = put(0x1000, first)
        self.assertEqual(bridge._set_file_information(emu, api, None,
                                                       [0x509, 3, 0x1000, size_first]), 1)
        self.assertEqual(view.tell(), 3)
        self.assertIsNone(bridge._file(manager, old))
        self.assertIs(bridge._file(manager, first), source)
        self.assertEqual(bridge.file_open_options[0x509][0], bridge._key(first))
        size_final = put(0x2000, final)
        self.assertEqual(bridge._set_file_information(emu, api, None,
                                                       [0x509, 3, 0x2000, size_final]), 0)
        self.assertEqual(errors[-1], 183)
        size_replace = put(0x3000, final, replace=True)
        manager.file_handles[0x50B] = SharedGuestFileView(destination)
        bridge.file_open_options[0x50B] = (bridge._key(final), 1, 7)
        self.assertEqual(bridge._set_file_information(emu, api, None,
                                                       [0x509, 3, 0x3000, size_replace]), 0)
        self.assertEqual(errors[-1], 5)
        manager.file_handles.pop(0x50B)
        bridge.file_open_options.pop(0x50B)
        bridge.file_open_options[0x509] = (bridge._key(first), 2, 0)
        self.assertEqual(bridge._set_file_information(emu, api, None,
                                                       [0x509, 3, 0x3000, size_replace]), 0)
        self.assertEqual(errors[-1], 5)
        bridge.file_open_options[0x509] = (bridge._key(first), 4, 0)
        self.assertEqual(bridge._set_file_information(emu, api, None,
                                                       [0x509, 3, 0x3000, size_replace]), 1)
        self.assertIs(bridge._file(manager, final), source)
        self.assertEqual((view.tell(), view._bytes()), (3, b"PAYLOAD"))
        self.assertTrue(any(item["source"] == "virtual_file_rename_replaced"
                            and (self.root / "artifacts" / item["file"]).read_bytes() == b"OLD!"
                            for item in bridge.catalog.items))
        size_directory = put(0x4000, self.persona["current_dir"])
        self.assertEqual(bridge._set_file_information(emu, api, None,
                                                       [0x509, 3, 0x4000, size_directory]), 0)
        self.assertEqual(errors[-1], 183)
        size_case = put(0x5000, final.upper())
        self.assertEqual(bridge._set_file_information(emu, api, None,
                                                       [0x509, 3, 0x5000, size_case]), 1)
        self.assertEqual(source.path, final.upper())
        self.assertEqual(errors[-1], 0)

    def test_file_rename_info_rejects_invalid_guest_buffers_and_root(self):
        path = self.persona["current_dir"] + r"\rename-guard.bin"
        source = GuestFile(None, path, data=b"A")
        manager = SimpleNamespace(files=[source], file_handles={0x50A: SharedGuestFileView(source)})
        errors = []
        target = (self.persona["current_dir"] + r"\not-renamed.bin").encode("utf-16le")
        raw = struct.pack("<I4xQI", 0, 0, len(target)) + target
        bad_root = struct.pack("<I4xQI", 0, 0x1234, len(target)) + target
        memory = {0x1000: raw, 0x2000: bad_root}

        def read(address, size):
            for start, data in memory.items():
                if start <= address < start + len(data):
                    return data[address - start:address - start + size]
            raise OSError("unmapped guest address")

        emu = SimpleNamespace(get_file_manager=lambda: manager, get_ptr_size=lambda: 8,
                              mem_read=read, set_last_error=errors.append)
        bridge = VirtualFileBridge(self.persona["current_dir"],
                                   ArtifactCatalog(self.root / "artifacts"))
        bridge.file_open_options[0x50A] = (bridge._key(path), 4, 7)
        api = "kernel32.SetFileInformationByHandle"
        for address, size, expected in ((0x1000, 19, 24), (0x1000, 20, 24),
                                        (0x2000, len(bad_root), 6),
                                        (0x3000, len(raw), 998)):
            self.assertEqual(bridge._set_file_information(emu, api, None,
                                                          [0x50A, 3, address, size]), 0)
            self.assertEqual(errors[-1], expected)
        self.assertEqual(source.path, path)
        self.assertEqual(manager.file_handles[0x50A]._bytes(), b"A")

    def test_truncate_existing_keeps_other_open_handle_on_same_guest_bytes(self):
        path = self.persona["current_dir"] + r"\truncate.bin"
        source = GuestFile(None, path, data=b"ABCDE")
        manager = SimpleNamespace(files=[source], file_handles={})
        manager.does_file_exist = lambda candidate: candidate.lower() == path.lower()
        manager.file_open = lambda _path, create=False: manager.file_handles.setdefault(
            0x202, source.duplicate()) and 0x202
        errors = []
        emu = SimpleNamespace(get_file_manager=lambda: manager,
                              read_mem_string=lambda _pointer, _width: path,
                              set_last_error=errors.append)
        bridge = VirtualFileBridge(self.persona["current_dir"],
                                   ArtifactCatalog(self.root / "artifacts"))
        manager.file_handles[0x201] = source.duplicate()
        first = bridge._create_file(emu, "kernel32.CreateFileW", lambda _params: 0x201,
                                     [1, 0x80000000, 7, 0, 3, 0x80, 0])
        view = manager.file_handles[first]
        self.assertEqual(view.get_data(2), b"AB")
        self.assertEqual(bridge._create_file(emu, "kernel32.CreateFileW", None,
                                             [1, 0x80000000, 7, 0, 5, 0x80, 0]),
                         0xFFFFFFFF)
        self.assertEqual(errors[-1], 87)
        second = bridge._create_file(emu, "kernel32.CreateFileW", None,
                                      [1, 0x40000000, 7, 0, 5, 0x80, 0])
        self.assertEqual(second, 0x202)
        self.assertEqual(source.data.getvalue(), b"")
        self.assertEqual(view.get_data(10), b"")
        manager.file_handles[second].add_data(b"NEW")
        view.seek(0, 0)
        self.assertEqual(view.get_data(3), b"NEW")

    def test_create_always_truncates_shared_guest_file_object(self):
        path = self.persona["current_dir"] + r"\create-always.bin"
        source = GuestFile(None, path, data=b"ABCDE")
        manager = SimpleNamespace(files=[source], file_handles={0x201: source.duplicate()})
        manager.does_file_exist = lambda candidate: candidate.lower() == path.lower()
        errors = []
        emu = SimpleNamespace(get_file_manager=lambda: manager,
                              read_mem_string=lambda _pointer, _width: path,
                              set_last_error=errors.append)
        bridge = VirtualFileBridge(self.persona["current_dir"],
                                   ArtifactCatalog(self.root / "artifacts"))
        old_handle = bridge._create_file(emu, "kernel32.CreateFileW", lambda _params: 0x201,
                                          [1, 0x80000000, 7, 0, 3, 0x80, 0])
        old_view = manager.file_handles[old_handle]
        replacement = GuestFile(None, path)
        def original(_params):
            manager.files.remove(source)
            manager.files.append(replacement)
            manager.file_handles[0x202] = replacement
            return 0x202
        new_handle = bridge._create_file(emu, "kernel32.CreateFileW", original,
                                          [1, 0x40000000, 7, 0, 2, 0x80, 0])
        self.assertEqual(new_handle, 0x202)
        self.assertIs(manager.files[0], source)
        self.assertEqual(old_view.get_data(5), b"")
        manager.file_handles[new_handle].add_data(b"NEW")
        old_view.seek(0, 0)
        self.assertEqual(old_view.get_data(3), b"NEW")

    def test_guest_file_handles_have_independent_positions_and_shared_bytes(self):
        file = GuestFile(None, r"C:\Users\Alex\Downloads\shared.bin", data=b"ABCDE")
        first, second = SharedGuestFileView(file), SharedGuestFileView(file)
        self.assertEqual(first.get_data(2), b"AB")
        self.assertEqual(second.get_data(1), b"A")
        first.add_data(b"xy")
        self.assertEqual(file.data.getvalue(), b"ABxyE")
        self.assertEqual(second.tell(), 1)
        self.assertEqual(second.get_data(4), b"BxyE")
        first.seek(2, 0)
        first.add_data(b"!")
        self.assertEqual(file.data.getvalue(), b"AB!yE")
        first.seek(7, 0)
        first.add_data(b"Z")
        self.assertEqual(file.data.getvalue(), b"AB!yE\0\0Z")
        first.seek(12, 0)
        self.assertEqual(first.get_data(4), b"")
        self.assertEqual(first.tell(), 12)

    def test_append_only_view_uses_current_eof_for_each_write(self):
        file = GuestFile(None, r"C:\Users\Alex\Downloads\append.bin", data=b"AB")
        append = SharedGuestFileView(file, append_only=True)
        other = SharedGuestFileView(file)
        append.seek(0, 0)
        append.add_data(b"C")
        self.assertEqual((file.data.getvalue(), append.tell()), (b"ABC", 3))
        other.seek(0, 2)
        other.add_data(b"D")
        append.seek(0, 0)
        append.add_data(b"E")
        self.assertEqual((file.data.getvalue(), append.tell()), (b"ABCDE", 5))

    def test_append_only_access_is_set_only_without_write_data(self):
        path = self.persona["current_dir"] + r"\append-rights.bin"
        source = GuestFile(None, path, data=b"AB")
        manager = SimpleNamespace(files=[source], file_handles={})
        manager.does_file_exist = lambda candidate: candidate.lower() == path.lower()
        emu = SimpleNamespace(get_file_manager=lambda: manager,
                              read_mem_string=lambda _pointer, _width: path,
                              set_last_error=lambda _error: None)
        bridge = VirtualFileBridge(self.persona["current_dir"],
                                   ArtifactCatalog(self.root / "artifacts"))
        for handle, access, expected in ((0x301, 0x4, True),
                                         (0x302, 0x40000000, False),
                                         (0x303, 0x6, False)):
            manager.file_handles[handle] = source.duplicate()
            opened = bridge._create_file(emu, "kernel32.CreateFileW",
                                         lambda _params, h=handle: h,
                                         [1, access, 7, 0, 3, 0x80, 0])
            self.assertEqual(opened, handle)
            self.assertEqual(manager.file_handles[handle].append_only, expected)

    def test_append_only_limit_uses_eof_instead_of_stale_pointer(self):
        handle = 0x304
        file = GuestFile(None, r"C:\Users\Alex\Downloads\append-limit.bin", data=b"AB")
        view = SharedGuestFileView(file, append_only=True)
        view.seek(MAX_ARTIFACT, 0)
        manager = SimpleNamespace(file_handles={handle: view})
        errors = []
        emu = SimpleNamespace(get_file_manager=lambda: manager,
                              set_last_error=errors.append)
        bridge = VirtualFileBridge(self.persona["current_dir"],
                                   ArtifactCatalog(self.root / "artifacts"))
        result = bridge._closed_file_operation(
            emu, "kernel32.WriteFile", lambda _params: (view.add_data(b"C") or 1),
            [handle, 1, 1, 0, 0])
        self.assertEqual(result, 1)
        self.assertEqual((file.data.getvalue(), view.tell()), (b"ABC", 3))
        self.assertEqual(errors, [])

    def test_overlapped_guest_file_io_fails_visibly(self):
        handle = 0x305
        file = GuestFile(None, r"C:\Users\Alex\Downloads\overlapped.bin", data=b"AB")
        manager = SimpleNamespace(file_handles={handle: SharedGuestFileView(file)})
        errors, writes = [], []
        emu = SimpleNamespace(get_file_manager=lambda: manager,
                              set_last_error=errors.append,
                              mem_write=lambda address, data: writes.append((address, data)))
        bridge = VirtualFileBridge(self.persona["current_dir"],
                                   ArtifactCatalog(self.root / "artifacts"))
        bridge.file_open_options[handle] = (file.path.lower(), 3, 7)
        for api in ("kernel32.ReadFile", "kernel32.WriteFile"):
            result = bridge._closed_file_operation(
                emu, api, lambda _params: self.fail("overlapped I/O reached Speakeasy"),
                [handle, 1, 1, 2, 3])
            self.assertEqual(result, 0)
            self.assertEqual(errors[-1], 50)
            self.assertEqual(writes[-1], (2, b"\0" * 4))
        self.assertEqual(file.data.getvalue(), b"AB")
        self.assertEqual(len(bridge.unsupported), 2)

    def test_guest_file_write_limit_rejects_before_reading_guest_memory(self):
        handle = 0x888
        file = GuestFile(None, r"C:\Users\Alex\Downloads\bounded.bin", data=b"A")
        view = SharedGuestFileView(file)
        view.seek(MAX_ARTIFACT, 0)
        writes, errors = [], []
        manager = SimpleNamespace(file_handles={handle: view})
        emu = SimpleNamespace(get_file_manager=lambda: manager,
                              mem_write=lambda address, data: writes.append((address, data)),
                              set_last_error=errors.append)
        bridge = VirtualFileBridge(self.persona["current_dir"],
                                   ArtifactCatalog(self.root / "artifacts"))
        def forbidden(_params):
            self.fail("oversized request reached Speakeasy's guest-memory read")
        self.assertEqual(bridge._closed_file_operation(
            emu, "kernel32.WriteFile", forbidden, [handle, 1, 1, 2, 0]), 0)
        self.assertEqual(errors, [223])
        self.assertEqual(writes, [(2, b"\0" * 4)])
        self.assertEqual(file.data.getvalue(), b"A")

    def test_guest_seek_and_setendoffile_change_shared_bytes(self):
        handle = 0x888
        path = self.persona["current_dir"] + r"\resize.bin"
        file = GuestFile(None, path, data=b"ABCDEFGH")
        first, second = SharedGuestFileView(file), SharedGuestFileView(file)
        manager = SimpleNamespace(file_handles={handle: first, handle + 1: second})
        errors, writes = [], []
        emu = SimpleNamespace(get_file_manager=lambda: manager,
                              set_last_error=errors.append,
                              mem_write=lambda address, data: writes.append((address, data)),
                              get_ptr_size=lambda: 8)
        bridge = VirtualFileBridge(self.persona["current_dir"],
                                   ArtifactCatalog(self.root / "artifacts"))
        bridge.file_open_options[handle] = (bridge._key(path), 3, 7)
        bridge.file_open_raw_access[handle] = 0xC0000000
        self.assertEqual(bridge._closed_file_operation(
            emu, "kernel32.SetFilePointer", None, [handle, 3, 0, 0]), 3)
        self.assertEqual(bridge._set_end_of_file(emu, "kernel32.SetEndOfFile", None,
                                                 [handle]), 1)
        self.assertEqual(file.data.getvalue(), b"ABC")
        self.assertEqual(second.get_data(), b"ABC")
        self.assertEqual(bridge._closed_file_operation(
            emu, "kernel32.SetFilePointerEx", None, [handle, 3, 10, 1, 0]), 1)
        self.assertEqual(writes[-1], (10, (6).to_bytes(8, "little")))
        self.assertEqual(bridge._set_end_of_file(emu, "kernel32.SetEndOfFile", None,
                                                 [handle]), 1)
        self.assertEqual(file.data.getvalue(), b"ABC\0\0\0")
        self.assertEqual(first.tell(), 6)
        self.assertEqual(bridge._closed_file_operation(
            emu, "kernel32.SetFilePointer", None, [handle, 0xFFFFFFFE, 0, 0]),
                         0xFFFFFFFF)
        self.assertEqual(errors[-1], 131)
        self.assertEqual(first.tell(), 6)
        emu.get_ptr_size = lambda: 4
        self.assertEqual(bridge._closed_file_operation(
            emu, "kernel32.SetFilePointerEx", None, [handle, 2, 0, 12, 1]), 1)
        self.assertEqual(writes[-1], (12, (8).to_bytes(8, "little")))
        self.assertEqual(bridge._closed_file_operation(
            emu, "kernel32.SetFilePointerEx", None,
            [handle, 0xFFFFFFFE, 0xFFFFFFFF, 13, 1]), 1)
        self.assertEqual(first.tell(), 6)
        emu.get_ptr_size = lambda: 8
        self.assertEqual(bridge._closed_file_operation(
            emu, "kernel32.SetFilePointerEx", None,
            [handle, (1 << 64) - 8, 11, 1, 0]), 0)
        self.assertEqual(errors[-1], 131)
        self.assertEqual(first.tell(), 6)
        self.assertEqual(bridge._closed_file_operation(
            emu, "kernel32.SetFilePointer", None, [handle, MAX_ARTIFACT + 1, 0, 0]),
                         0xFFFFFFFF)
        self.assertEqual(errors[-1], 223)
        self.assertTrue(bridge.unsupported)
        bridge.file_open_raw_access[handle] = 0x80000000
        self.assertEqual(bridge._set_end_of_file(emu, "kernel32.SetEndOfFile", None,
                                                 [handle]), 0)
        self.assertEqual(errors[-1], 5)
        self.assertEqual(bridge._set_end_of_file(emu, "kernel32.SetEndOfFile", None,
                                                 [0xBAD]), 0)
        self.assertEqual(errors[-1], 6)

    def test_setendoffile_does_not_modify_open_persona_backing_file(self):
        path = self.persona["current_dir"] + r"\mapped-resize.bin"
        backing = self.root / "mapped-resize.bin"
        backing.write_bytes(b"host backing")
        entry = FileEntryFullPath(mode="full_path", emu_path=path, path=str(backing))
        manager = SimpleNamespace(file_handles={0x888: GuestFile(None, path, config=entry)})
        errors = []
        emu = SimpleNamespace(get_file_manager=lambda: manager,
                              set_last_error=errors.append)
        bridge = VirtualFileBridge(self.persona["current_dir"],
                                   ArtifactCatalog(self.root / "artifacts"))
        bridge.file_open_raw_access[0x888] = 0x40000000
        self.assertEqual(bridge._set_end_of_file(
            emu, "kernel32.SetEndOfFile", None, [0x888]), 0)
        self.assertEqual(errors[-1], 50)
        self.assertTrue(bridge.unsupported)
        self.assertEqual(backing.read_bytes(), b"host backing")

    def test_closed_guest_file_handle_rejects_followup_io(self):
        path = self.persona["current_dir"] + r"\closed.bin"
        handle = 0x888
        manager = SimpleNamespace(file_handles={handle: GuestFile(None, path, data=b"marker")})
        errors = []
        emu = SimpleNamespace(get_file_manager=lambda: manager, set_last_error=errors.append)
        bridge = VirtualFileBridge(self.persona["current_dir"],
                                   ArtifactCatalog(self.root / "artifacts"))
        self.assertEqual(bridge._close_handle(emu, "kernel32.CloseHandle", None, [handle]), 1)
        self.assertNotIn(handle, manager.file_handles)
        self.assertEqual(bridge._closed_file_operation(emu, "kernel32.GetFileSize", None,
                                                        [handle, 0]), 0xFFFFFFFF)
        self.assertEqual(errors[-1], 6)
        self.assertEqual(bridge._closed_file_operation(emu, "kernel32.ReadFile", None,
                                                        [handle, 1, 4, 0, 0]), 0)
        self.assertEqual(errors[-1], 6)

    def test_directory_conflicts_and_nonempty_rejection(self):
        base = self.persona["current_dir"]
        folder = base + r"\new-dir"
        child = folder + r"\payload.bin"
        manager = SimpleNamespace(files=[], file_config=SimpleNamespace(files=[]))
        manager.does_file_exist = lambda path: False
        errors = []
        emu = SimpleNamespace(read_mem_string=lambda address, _width: {
            1: folder, 2: child, 3: base + r"\missing\child"}[address],
            get_file_manager=lambda: manager, set_last_error=errors.append)
        bridge = VirtualFileBridge(base, ArtifactCatalog(self.root / "artifacts"))
        self.assertEqual(bridge._create_directory(emu, "kernel32.CreateDirectoryW", None, [3, 0]), 0)
        self.assertEqual(errors[-1], 3)
        self.assertEqual(bridge._create_directory(emu, "kernel32.CreateDirectoryW", None, [1, 0]), 1)
        self.assertEqual(bridge._create_directory(emu, "kernel32.CreateDirectoryW", None, [1, 0]), 0)
        self.assertEqual(errors[-1], 183)
        manager.files.append(GuestFile(None, child, data=b"harmless"))
        self.assertEqual(bridge._get_file_attributes(emu, "kernel32.GetFileAttributesW", None, [2]),
                         0x80)
        self.assertEqual(bridge._remove_directory(emu, "kernel32.RemoveDirectoryW", None, [1]), 0)
        self.assertEqual(errors[-1], 145)
        manager.files.clear()
        self.assertEqual(bridge._remove_directory(emu, "kernel32.RemoveDirectoryW", None, [1]), 1)
        self.assertEqual(bridge._get_file_attributes(emu, "kernel32.GetFileAttributesW", None, [1]),
                         0xFFFFFFFF)
        self.assertEqual(bridge._remove_directory(emu, "kernel32.RemoveDirectoryW", None, [1]), 0)
        self.assertEqual(errors[-1], 3)

    def test_guest_files_and_directories_appear_in_findfirstfile_walker(self):
        base = self.persona["current_dir"]
        folder = base + r"\new-dir"
        guest_file = base + r"\written.bin"

        class Manager:
            find_matching_entries = FileManager.find_matching_entries

            def __init__(self):
                self.files = [GuestFile(None, guest_file, data=b"harmless")]
                self.file_config = SimpleNamespace(files=[])

            def walk_files(self):
                yield base + r"\configured.txt"

        manager = Manager()
        emu = SimpleNamespace(get_file_manager=lambda: manager,
                              read_mem_string=lambda _address, _width: folder,
                              set_last_error=lambda _value: None)
        bridge = VirtualFileBridge(base, ArtifactCatalog(self.root / "artifacts"))
        bridge.extend_enumeration(emu)
        self.assertEqual(bridge._create_directory(emu, "kernel32.CreateDirectoryW", None, [1, 0]), 1)
        found = dict(manager.find_matching_entries(base + r"\*"))
        self.assertEqual(found["new-dir"], True)
        self.assertEqual(found["written.bin"], False)
        self.assertEqual(found["configured.txt"], False)
        self.assertEqual(bridge._remove_directory(emu, "kernel32.RemoveDirectoryW", None, [1]), 1)
        self.assertNotIn("new-dir", dict(manager.find_matching_entries(base + r"\*")))

    def test_getfileattributesex_reads_persona_size_inside_cpu_emulation(self):
        for arch in ("x86", "x64"):
            for variant in ("W", "A"):
                with self.subTest(arch=arch, variant=variant), tempfile.TemporaryDirectory() as folder:
                    root = Path(folder)
                    name = f"attributes_ex{'_a' if variant == 'A' else ''}_{arch}.exe"
                    exe = FIXTURES / name
                    image = exe.read_bytes()
                    result = run_native(image, inspect_pe(image, name), self.persona,
                                        root, [], 10, 100_000)
                    report = json.loads((root / result["engine_report"]).read_text())
                    self.assertFalse(result["errors"])
                    self.assertFalse(result["api_coverage"]["signature_only_calls"])
                    event = next(e for e in report["virtual_file_events"]
                                 if e["event"] == "virtual_file_attributes_ex")
                    self.assertEqual(event["api"], f"kernel32.GetFileAttributesEx{variant}")
                    self.assertTrue(event["success"])
                    self.assertEqual((event["attributes"], event["size"]), (0x80, 15))
                    self.assertTrue(any(e.get("api_name") == "kernel32.ExitProcess"
                                        and e.get("args") == ["0x1"]
                                        for e in report["entry_points"][0]["events"]))

    def test_getfileattributesex_reports_directory_empty_and_invalid_inputs(self):
        base = self.persona["current_dir"]
        folder = base + r"\metadata-dir"
        empty = base + r"\empty.bin"
        missing = base + r"\missing.bin"
        manager = SimpleNamespace(files=[GuestFile(None, empty)],
                                  file_config=SimpleNamespace(files=[]),
                                  does_file_exist=lambda _path: False)
        writes, errors = [], []
        emu = SimpleNamespace(read_mem_string=lambda address, _width: {
            1: folder, 2: empty, 3: missing}[address],
            get_file_manager=lambda: manager, set_last_error=errors.append,
            mem_write=lambda address, data: writes.append((address, data)))
        bridge = VirtualFileBridge(base, ArtifactCatalog(self.root / "artifacts"),
                                   filetime_ticks=1234567890)
        self.assertEqual(bridge._create_directory(emu, "kernel32.CreateDirectoryW", None, [1, 0]), 1)
        self.assertEqual(bridge._get_file_attributes_ex(emu, "kernel32.GetFileAttributesExW",
                                                        None, [1, 0, 4]), 1)
        self.assertEqual(struct.unpack("<IQQQII", writes[-1][1]),
                         (0x10, 1234567890, 1234567890, 1234567890, 0, 0))
        self.assertEqual(bridge._get_file_attributes_ex(emu, "kernel32.GetFileAttributesExW",
                                                        None, [2, 0, 4]), 1)
        self.assertEqual(struct.unpack("<IQQQII", writes[-1][1])[-2:], (0, 0))
        self.assertEqual(bridge._get_file_attributes_ex(emu, "kernel32.GetFileAttributesExW",
                                                        None, [3, 0, 4]), 0)
        self.assertEqual(errors[-1], 2)
        count = len(writes)
        self.assertEqual(bridge._get_file_attributes_ex(emu, "kernel32.GetFileAttributesExW",
                                                        None, [1, 1, 4]), 0)
        self.assertEqual(errors[-1], 87)
        self.assertEqual(len(writes), count)

    def test_guest_file_attributes_roundtrip_and_readonly_namespace_rules(self):
        base = self.persona["current_dir"]
        file_path, directory = base + r"\attributes-roundtrip.bin", base + r"\hidden-dir"
        created = base + r"\created-hidden.bin"
        source = GuestFile(None, file_path, data=b"ABC")
        manager = SimpleNamespace(files=[source], file_handles={},
                                  file_config=SimpleNamespace(files=[]),
                                  does_file_exist=lambda path: path.lower() == file_path.lower())
        errors, writes = [], []
        emu = SimpleNamespace(get_file_manager=lambda: manager,
                              read_mem_string=lambda address, _width:
                              {1: file_path, 2: directory, 3: created}[address],
                              set_last_error=errors.append,
                              mem_write=lambda address, data: writes.append((address, data)))
        bridge = VirtualFileBridge(base, ArtifactCatalog(self.root / "artifacts"),
                                   filetime_ticks=1234)
        set_api = "kernel32.SetFileAttributesW"
        self.assertEqual(bridge._set_file_attributes(emu, set_api, None, [1, 3]), 1)
        self.assertEqual(bridge._get_file_attributes(emu, "kernel32.GetFileAttributesW",
                                                       None, [1]), 3)
        self.assertEqual(bridge._get_file_attributes_ex(emu, "kernel32.GetFileAttributesExW",
                                                          None, [1, 0, 0x3000]), 1)
        self.assertEqual(struct.unpack("<IQQQII", writes[-1][1]),
                         (3, 1234, 1234, 1234, 0, 3))
        self.assertEqual(bridge._create_file(emu, "kernel32.CreateFileW",
                                               lambda _args: self.fail("opened read-only file"),
                                               [1, 0x40000000, 7, 0, 3, 0x80, 0]),
                         0xFFFFFFFF)
        self.assertEqual(errors[-1], 5)
        self.assertEqual(bridge._delete_file(emu, "kernel32.DeleteFileW", None, [1]), 0)
        self.assertEqual(errors[-1], 5)
        self.assertEqual(bridge._set_file_attributes(emu, set_api, None, [1, 0]), 1)
        self.assertEqual(bridge._get_file_attributes(emu, "kernel32.GetFileAttributesW",
                                                       None, [1]), 0x80)
        self.assertEqual(bridge._create_directory(emu, "kernel32.CreateDirectoryW",
                                                   None, [2, 0]), 1)
        self.assertEqual(bridge._set_file_attributes(emu, set_api, None, [2, 3]), 1)
        self.assertEqual(bridge._get_file_attributes(emu, "kernel32.GetFileAttributesW",
                                                       None, [2]), 0x13)
        self.assertEqual(bridge._set_file_attributes(emu, set_api, None, [2, 0x12]), 1)
        self.assertEqual(bridge._get_file_attributes(emu, "kernel32.GetFileAttributesW",
                                                       None, [2]), 0x12)
        def open_new(_params):
            new_file = GuestFile(None, created)
            manager.files.append(new_file)
            manager.file_handles[0x50D] = new_file
            return 0x50D
        self.assertEqual(bridge._create_file(emu, "kernel32.CreateFileW", open_new,
                                               [3, 0x40000000, 7, 0, 2, 0x2, 0]), 0x50D)
        self.assertEqual(bridge._get_file_attributes(emu, "kernel32.GetFileAttributesW",
                                                       None, [3]), 0x2)
        self.assertEqual(source.data.getvalue(), b"ABC")

    def test_file_basic_info_checks_rights_buffer_and_updates_times(self):
        base = self.persona["current_dir"]
        path = base + r"\basic-info.bin"
        source = GuestFile(None, path, data=b"PAYLOAD")
        manager = SimpleNamespace(files=[source], file_handles={0x50C: SharedGuestFileView(source)},
                                  file_config=SimpleNamespace(files=[]),
                                  does_file_exist=lambda candidate: candidate.lower() == path.lower())
        memory = {0x1000: struct.pack("<qqqqI4x", 2222, 0, 3333, 0, 2),
                  0x2000: struct.pack("<qqqqI4x", 0, 4444, 0, 0, 0),
                  0x3000: struct.pack("<qqqqI4x", -1, 0, 0, 0, 0)}
        errors, writes = [], []
        emu = SimpleNamespace(get_file_manager=lambda: manager,
                              mem_read=lambda address, size: memory[address][:size],
                              read_mem_string=lambda _address, _width: path,
                              mem_write=lambda address, data: writes.append((address, data)),
                              set_last_error=errors.append)
        bridge = VirtualFileBridge(base, ArtifactCatalog(self.root / "artifacts"),
                                   filetime_ticks=1234)
        api = "kernel32.SetFileInformationByHandle"
        bridge.file_open_raw_access[0x50C] = 0x2  # FILE_WRITE_DATA is insufficient.
        self.assertEqual(bridge._set_file_information(emu, api, None, [0x50C, 0, 0x1000, 40]), 0)
        self.assertEqual(errors[-1], 5)
        bridge.file_open_raw_access[0x50C] = 0x100  # FILE_WRITE_ATTRIBUTES alone.
        self.assertEqual(bridge._set_file_information(emu, api, None, [0x50C, 0, 0x1000, 36]), 0)
        self.assertEqual(errors[-1], 24)
        self.assertEqual(bridge._set_file_information(emu, api, None, [0x50C, 0, 0x1000, 40]), 1)
        self.assertEqual(bridge._set_file_information(emu, api, None, [0x50C, 0, 0x2000, 40]), 1)
        self.assertEqual(bridge._get_file_attributes_ex(emu, "kernel32.GetFileAttributesExW",
                                                          None, [1, 0, 0x5000]), 1)
        self.assertEqual(struct.unpack("<IQQQII", writes[-1][1]),
                         (2, 2222, 4444, 3333, 0, 7))
        self.assertEqual(bridge._set_file_information(emu, api, None, [0x50C, 0, 0x3000, 40]), 0)
        self.assertEqual(errors[-1], 50)
        self.assertEqual(bridge._set_file_information(emu, api, None, [0x50C, 0, 0x4000, 40]), 0)
        self.assertEqual(errors[-1], 998)
        self.assertEqual(source.data.getvalue(), b"PAYLOAD")

    def test_guest_attribute_mutation_roundtrips_inside_cpu_emulation(self):
        for arch in ("x86", "x64"):
            for variant in ("W", "A"):
                for by_handle in (False, True):
                    with self.subTest(arch=arch, variant=variant, by_handle=by_handle), \
                            tempfile.TemporaryDirectory() as folder:
                        root = Path(folder)
                        stem = "file_basic_info" if by_handle else "file_attributes"
                        name = f"{stem}{'_a' if variant == 'A' else ''}_{arch}.exe"
                        image = (FIXTURES / name).read_bytes()
                        result = run_native(image, inspect_pe(image, name), self.persona,
                                            root, [], 10, 100_000)
                        report = json.loads((root / result["engine_report"]).read_text())
                        self.assertFalse(result["errors"])
                        self.assertFalse(result["api_coverage"]["signature_only_calls"])
                        change = next(event for event in report["virtual_file_events"]
                                      if event["event"] == ("virtual_file_basic_info" if by_handle
                                                            else "virtual_file_set_attributes"))
                        self.assertEqual(change["attributes"], 3)
                        if not by_handle:
                            self.assertTrue(change["success"])
                        attributes = [event for event in report["virtual_file_events"]
                                      if event["event"] == "virtual_file_attributes"]
                        extended = [event for event in report["virtual_file_events"]
                                    if event["event"] == "virtual_file_attributes_ex"]
                        self.assertEqual(attributes[-1]["attributes"], 3)
                        self.assertEqual((extended[-1]["attributes"], extended[-1]["size"]),
                                         (3, 8))
                        self.assertTrue(any(event.get("api_name") == "kernel32.ExitProcess"
                                            and event.get("args") == ["0x1"]
                                            for entry in report["entry_points"]
                                            for event in entry["events"]))
                        self.assertTrue(any(item["guest_path"].endswith("metadata.bin")
                                            and (root / "artifacts" / item["file"]).read_bytes()
                                            == b"ABCDEFGH" for item in result["artifacts"]))

    def test_copy_file_carries_guest_attributes_and_times(self):
        base = self.persona["current_dir"]
        old, new = base + r"\source-metadata.bin", base + r"\copied-metadata.bin"
        source = GuestFile(None, old, data=b"COPY")
        source.virtual_attributes = 3
        source.virtual_times = (111, 222, 333, 444)
        manager = SimpleNamespace(files=[source], file_config=SimpleNamespace(files=[]),
                                  does_file_exist=lambda path: path.lower() == old.lower())
        writes, errors = [], []
        emu = SimpleNamespace(get_file_manager=lambda: manager,
                              read_mem_string=lambda address, _width: {1: old, 2: new}[address],
                              mem_write=lambda address, data: writes.append((address, data)),
                              set_last_error=errors.append)
        bridge = VirtualFileBridge(base, ArtifactCatalog(self.root / "artifacts"),
                                   filetime_ticks=999)
        self.assertEqual(bridge._copy_file(emu, "kernel32.CopyFileW", None, [1, 2, 0]), 1)
        self.assertEqual(bridge._get_file_attributes_ex(emu, "kernel32.GetFileAttributesExW",
                                                          None, [2, 0, 0x6000]), 1)
        self.assertEqual(struct.unpack("<IQQQII", writes[-1][1]),
                         (3, 111, 222, 333, 0, 4))
        self.assertEqual(bridge._copy_file(emu, "kernel32.CopyFileW", None, [1, 2, 0]), 0)
        self.assertEqual(errors[-1], 5)
        self.assertEqual(bridge._file(manager, new).data.getvalue(), b"COPY")

    def test_registry_binary_roundtrip_and_extraction_inside_cpu_emulation(self):
        marker = b"BLUE_TEAM_REGISTRY_MARKER"
        for arch in ("x86", "x64"):
            for variant in ("W", "A"):
                with self.subTest(arch=arch, variant=variant), tempfile.TemporaryDirectory() as folder:
                    root = Path(folder)
                    name = f"registry{'_a' if variant == 'A' else ''}_{arch}.exe"
                    exe = FIXTURES / name
                    image = exe.read_bytes()
                    result = run_native(image, inspect_pe(image, name), self.persona,
                                        root, [], 10, 100_000)
                    report = json.loads((root / result["engine_report"]).read_text())
                    self.assertFalse(result["errors"])
                    self.assertFalse(result["api_coverage"]["signature_only_calls"])
                    events = report["virtual_registry_events"]
                    self.assertEqual([e["event"] for e in events],
                                     ["virtual_registry_write", "virtual_registry_query",
                                      "virtual_registry_process_cleanup"])
                    self.assertEqual([e["status"] for e in events[:2]], [0, 0])
                    self.assertEqual(events[-1]["handles"], 0)
                    self.assertEqual(events[1]["size"], len(marker))
                    self.assertTrue(any(e.get("api_name") == "kernel32.ExitProcess"
                                        and e.get("args") == ["0x1"]
                                        for e in report["entry_points"][0]["events"]))
                    self.assertTrue(any(item["source"] == "registry_value"
                                        and (root / "artifacts" / item["file"]).read_bytes() == marker
                                        for item in result["artifacts"]))

    def test_registry_query_missing_small_buffer_and_configured_dword(self):
        key = RegKey(None, "HKEY_CURRENT_USER\\Software\\Probe")
        key.create_value("Count", 4, 42)
        memory = {1: (0).to_bytes(4, "little"), 2: b"unchanged", 3: b"\0" * 4}
        writes = []

        def mem_read(address, size):
            return memory[address][:size]

        def mem_write(address, data):
            writes.append((address, data))
            memory[address] = data

        emu = SimpleNamespace(reg_get_key=lambda handle: key if handle == 7 else None,
                              read_mem_string=lambda address, _width: {11: "Count", 12: "Absent"}[address],
                              mem_read=mem_read, mem_write=mem_write)
        bridge = VirtualRegistryBridge(ArtifactCatalog(self.root / "artifacts"))
        bridge.handle_owners[7] = id(emu)
        self.assertEqual(bridge._query_value(emu, "advapi32.RegQueryValueExW", None,
                                             [7, 12, 0, 3, 2, 1]), 2)
        self.assertFalse(writes)
        self.assertEqual(bridge._query_value(emu, "advapi32.RegQueryValueExW", None,
                                             [7, 11, 0, 3, 2, 1]), 234)
        self.assertEqual(memory[1], (4).to_bytes(4, "little"))
        self.assertEqual(memory[2], b"unchanged")
        self.assertEqual(bridge._query_value(emu, "advapi32.RegQueryValueExW", None,
                                             [7, 11, 0, 3, 2, 1]), 0)
        self.assertEqual(memory[2], (42).to_bytes(4, "little"))
        self.assertEqual(memory[3], (4).to_bytes(4, "little"))
        key.create_value("", 1, "default")
        memory[1] = (32).to_bytes(4, "little")
        self.assertEqual(bridge._query_value(emu, "advapi32.RegQueryValueExW", None,
                                             [7, 0, 0, 3, 2, 1]), 0)
        self.assertEqual(memory[2], "default\0".encode("utf-16le"))

    def test_registry_key_lifecycle_inside_cpu_emulation(self):
        for arch in ("x86", "x64"):
            for variant in ("W", "A"):
                with self.subTest(arch=arch, variant=variant), tempfile.TemporaryDirectory() as folder:
                    root = Path(folder)
                    name = f"registry_key{'_a' if variant == 'A' else ''}_{arch}.exe"
                    exe = FIXTURES / name
                    image = exe.read_bytes()
                    result = run_native(image, inspect_pe(image, name), self.persona,
                                        root, [], 10, 100_000)
                    report = json.loads((root / result["engine_report"]).read_text())
                    self.assertFalse(result["errors"])
                    self.assertFalse(result["api_coverage"]["signature_only_calls"])
                    events = report["virtual_registry_events"]
                    self.assertEqual([e["event"] for e in events], [
                        "virtual_registry_key_create", "virtual_registry_key_open",
                        "virtual_registry_key_close", "virtual_registry_key_delete",
                        "virtual_registry_key_open", "virtual_registry_key_close",
                        "virtual_registry_process_cleanup"])
                    self.assertEqual([e["status"] for e in events[:6]], [0, 0, 0, 0, 2, 0])
                    self.assertTrue(any(e.get("api_name") == "kernel32.ExitProcess"
                                        and e.get("args") == ["0x1"]
                                        for e in report["entry_points"][0]["events"]))

    def test_registry_handle_left_open_is_retired_at_guest_exit(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                name = f"registry_key_exit_{arch}.exe"
                image = (FIXTURES / name).read_bytes()
                result = run_native(image, inspect_pe(image, name), self.persona,
                                    root, [], 10, 100_000)
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                events = report["virtual_registry_events"]
                self.assertEqual([e["status"] for e in events[:-1]],
                                 [0, 0, 0, 0, 2])
                self.assertEqual(events[-1]["event"],
                                 "virtual_registry_process_cleanup")
                self.assertEqual(events[-1]["handles"], 1)
                cleanup = [e for e in report["virtual_process_events"]
                           if e["event"] == "virtual_process_cleanup"]
                self.assertEqual(len(cleanup), 1)
                self.assertEqual(cleanup[0]["registry_handles"], 1)

    def test_registry_key_deletion_rejects_children_and_closed_handles(self):
        manager = RegistryManager(HandleAllocator(), config=SimpleNamespace(keys=[]))
        memory = {}
        paths = {1: r"Software\EmumeeParent\Child", 2: r"Software\EmumeeParent",
                 3: r"Software\EmumeeParent\Child"}
        emu = SimpleNamespace(regman=manager, reg_get_key=manager.get_key_from_handle,
                              read_mem_string=lambda address, _width: paths[address],
                              mem_write=lambda address, data: memory.__setitem__(address, data),
                              get_ptr_size=lambda: 8)
        bridge = VirtualRegistryBridge(ArtifactCatalog(self.root / "artifacts"))
        root_handle = 0x80000001
        self.assertEqual(bridge._create_key(emu, "advapi32.RegCreateKeyW", None,
                                             [root_handle, 1, 10]), 0)
        child_handle = int.from_bytes(memory[10], "little")
        self.assertEqual(bridge._delete_key(emu, "advapi32.RegDeleteKeyW", None,
                                             [root_handle, 2]), 5)
        self.assertEqual(bridge._delete_key(emu, "advapi32.RegDeleteKeyW", None,
                                             [root_handle, 3]), 0)
        self.assertEqual(bridge._close_key(emu, "advapi32.RegCloseKey", None,
                                            [child_handle]), 0)
        self.assertEqual(bridge._close_key(emu, "advapi32.RegCloseKey", None,
                                            [child_handle]), 6)
        manager.config.keys.append(SimpleNamespace(
            path=r"HKEY_CURRENT_USER\Software\Preset", values=[]))
        paths[4] = r"Software\Preset"
        self.assertEqual(bridge._delete_key(emu, "advapi32.RegDeleteKeyW", None,
                                             [root_handle, 4]), 50)
        self.assertTrue(bridge.unsupported)
        manager.config.keys.append(SimpleNamespace(
            path=r"HKEY_CURRENT_USER\Software\SeededParent\Child", values=[]))
        paths[5] = r"Software\SeededParent"
        self.assertEqual(bridge._open_key_ex(emu, "advapi32.RegOpenKeyExW", None,
                                              [root_handle, 5, 0, 0, 11]), 0)
        self.assertEqual(bridge._delete_key(emu, "advapi32.RegDeleteKeyW", None,
                                             [root_handle, 5]), 5)

    def test_registry_handles_are_process_owned_and_retired_on_exit(self):
        manager = RegistryManager(HandleAllocator(), config=SimpleNamespace(keys=[]))
        parent = SimpleNamespace(pid=10)
        child = SimpleNamespace(pid=11)
        current = [parent]
        memory = {}
        emu = SimpleNamespace(
            regman=manager, reg_get_key=manager.get_key_from_handle,
            get_current_process=lambda: current[0],
            read_mem_string=lambda address, _width: r"Software\GuestOwner",
            mem_write=lambda address, data: memory.__setitem__(address, data),
            get_ptr_size=lambda: 8)
        bridge = VirtualRegistryBridge(ArtifactCatalog(self.root / "artifacts"))
        root = 0x80000001
        self.assertEqual(bridge._create_key(
            emu, "advapi32.RegCreateKeyW", None, [root, 1, 0x1000]), 0)
        parent_handle = int.from_bytes(memory[0x1000], "little")
        self.assertIn(parent_handle, manager.reg_handles)
        current[0] = child
        self.assertEqual(bridge._close_key(
            emu, "advapi32.RegCloseKey", None, [parent_handle]), 6)
        self.assertEqual(bridge._open_key_ex(
            emu, "advapi32.RegOpenKeyExW", None,
            [parent_handle, 1, 0, 0, 0x1800]), 6)
        self.assertEqual(bridge._query_value(
            emu, "advapi32.RegQueryValueExW", None,
            [parent_handle, 0, 0, 0, 0, 0]), 6)
        self.assertEqual(bridge._delete_key(
            emu, "advapi32.RegDeleteKeyW", None, [parent_handle, 1]), 6)
        self.assertEqual(bridge._set_value(
            emu, "advapi32.RegSetValueExW",
            lambda _: self.fail("foreign registry write reached engine"),
            [parent_handle, 0, 0, 3, 0, 0]), 6)
        self.assertEqual(bridge._open_key_ex(
            emu, "advapi32.RegOpenKeyExW", None,
            [root, 1, 0, 0, 0x2000]), 0)
        child_handle = int.from_bytes(memory[0x2000], "little")
        self.assertNotEqual(parent_handle, child_handle)
        current[0] = parent
        self.assertEqual(bridge.cleanup_process(emu, parent), 1)
        self.assertNotIn(parent_handle, manager.reg_handles)
        self.assertIn(child_handle, manager.reg_handles)
        current[0] = child
        self.assertEqual(bridge._close_key(
            emu, "advapi32.RegCloseKey", None, [child_handle]), 0)
        self.assertEqual(bridge.cleanup_process(emu, child), 0)
        issued = set(manager.reg_handles)
        emu.mem_write = lambda _address, _data: (_ for _ in ()).throw(ValueError("bad pointer"))
        self.assertEqual(bridge._open_key_ex(
            emu, "advapi32.RegOpenKeyExW", None,
            [root, 1, 0, 0, 0x3000]), 998)
        self.assertEqual(set(manager.reg_handles), issued)
        self.assertFalse(bridge.handle_owners)

    def test_regcreatekeyex_issues_owned_virtual_handle_and_disposition(self):
        manager = RegistryManager(HandleAllocator(), config=SimpleNamespace(keys=[]))
        parent = SimpleNamespace(pid=10)
        child = SimpleNamespace(pid=11)
        current = [parent]
        memory = {}
        strings = {1: r"Software\EmumeeEx", 2: "Payload"}
        emu = SimpleNamespace(
            regman=manager, reg_get_key=manager.get_key_from_handle,
            get_current_process=lambda: current[0],
            read_mem_string=lambda address, _width: strings[address],
            mem_write=lambda address, data: memory.__setitem__(address, data),
            mem_read=lambda address, size: b"abc"[:size] if address == 3 else b"\0" * size,
            get_ptr_size=lambda: 8)
        bridge = VirtualRegistryBridge(ArtifactCatalog(self.root / "artifacts"))
        hooks = []
        bridge.install(SimpleNamespace(add_api_hook=lambda _fn, _dll, name, argc:
                                            hooks.append((name, argc))))
        self.assertIn(("RegCreateKeyExW", 9), hooks)
        self.assertIn(("RegCreateKeyExA", 9), hooks)
        root = 0x80000001
        create = [root, 1, 0, 0, 0, 0xF003F, 0, 0x1000, 0x1008]
        self.assertEqual(bridge._create_key_ex(
            emu, "advapi32.RegCreateKeyExW", None, create), 0)
        first_handle = int.from_bytes(memory[0x1000], "little")
        self.assertEqual(int.from_bytes(memory[0x1008], "little"), 1)
        self.assertEqual(bridge._set_value(
            emu, "advapi32.RegSetValueExW", lambda _params: 0,
            [first_handle, 2, 0, 3, 3, 3]), 0)
        current[0] = child
        self.assertEqual(bridge._set_value(
            emu, "advapi32.RegSetValueExW", lambda _params: self.fail("foreign write"),
            [first_handle, 2, 0, 3, 3, 3]), 6)
        create[7:] = [0x1010, 0x1018]
        self.assertEqual(bridge._create_key_ex(
            emu, "advapi32.RegCreateKeyExW", None, create), 0)
        self.assertEqual(int.from_bytes(memory[0x1018], "little"), 2)
        self.assertNotEqual(int.from_bytes(memory[0x1010], "little"), first_handle)
        self.assertEqual(bridge._create_key_ex(
            emu, "advapi32.RegCreateKeyExW", None,
            [root, 1, 0, 0, 2, 0xF003F, 0, 0x1020, 0]), 50)
        self.assertTrue(bridge.unsupported)

    def test_regcreatekeyex_runs_inside_x86_and_x64_cpu_emulation(self):
        for arch, machine in (("x86", 0x14C), ("x64", 0x8664)):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as directory:
                image = build_registry_key_lifecycle(machine, create_ex=True)
                root = Path(directory)
                result = run_native(image, inspect_pe(image, f"registry_ex_{arch}.exe"),
                                    self.persona, root, [], 10, 100_000)
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertEqual(result["guest_exit_code"], 1)
                self.assertFalse(result["errors"])
                creates = [event for event in report["virtual_registry_events"]
                           if event.get("event") == "virtual_registry_key_create"]
                self.assertEqual(len(creates), 1)
                self.assertEqual(creates[0]["status"], 0)
                self.assertEqual(creates[0]["disposition"], 1)
                self.assertEqual(creates[0]["desired_access"], 0xF003F)

    def test_copyfile_fail_if_exists_overwrite_and_same_file(self):
        old = r"C:\Users\Alex\Downloads\old.bin"
        new = r"C:\Users\Alex\Downloads\new.bin"
        source = GuestFile(None, old, data=b"source bytes")
        target = GuestFile(None, new, data=b"old target")
        manager = SimpleNamespace(files=[source, target],
                                  file_config=SimpleNamespace(files=[]))
        manager.does_file_exist = lambda path: any(
            item.path.lower() == path.lower() for item in manager.files)
        errors = []
        emu = SimpleNamespace(read_mem_string=lambda address, _width: {1: old, 2: new}[address],
                              get_file_manager=lambda: manager, set_last_error=errors.append)
        bridge = VirtualFileBridge(self.persona["current_dir"],
                                   ArtifactCatalog(self.root / "artifacts"))
        self.assertEqual(bridge._copy_file(emu, "kernel32.CopyFileW", None, [1, 2, 1]), 0)
        self.assertEqual(errors[-1], 80)
        self.assertEqual(target.data.getvalue(), b"old target")
        self.assertEqual(bridge._copy_file(emu, "kernel32.CopyFileW", None, [1, 2, 0]), 1)
        self.assertEqual(errors[-1], 0)
        self.assertEqual(source.data.getvalue(), b"source bytes")
        self.assertEqual(bridge._file(manager, new).data.getvalue(), b"source bytes")
        self.assertIsNot(bridge._file(manager, new), source)
        self.assertEqual(bridge._copy_file(emu, "kernel32.CopyFileW", None, [1, 1, 0]), 0)
        self.assertEqual(errors[-1], 32)

    def test_copyfile_requires_source_read_sharing(self):
        old = self.persona["current_dir"] + r"\copy-source.bin"
        new = self.persona["current_dir"] + r"\copy-destination.bin"
        source = GuestFile(None, old, data=b"SOURCE")
        manager = SimpleNamespace(files=[source], file_config=SimpleNamespace(files=[]))
        manager.does_file_exist = lambda path: any(
            item.path.lower() == path.lower() for item in manager.files)
        errors = []
        emu = SimpleNamespace(read_mem_string=lambda address, _width: {1: old, 2: new}[address],
                              get_file_manager=lambda: manager, set_last_error=errors.append)
        bridge = VirtualFileBridge(self.persona["current_dir"],
                                   ArtifactCatalog(self.root / "artifacts"))
        bridge.file_open_options[0x201] = (bridge._key(old), 2, 0)
        self.assertEqual(bridge._copy_file(emu, "kernel32.CopyFileW", None, [1, 2, 0]), 0)
        self.assertEqual(errors[-1], 32)
        self.assertEqual(len(manager.files), 1)
        bridge.file_open_options[0x201] = (bridge._key(old), 2, 1)
        self.assertEqual(bridge._copy_file(emu, "kernel32.CopyFileW", None, [1, 2, 0]), 1)
        self.assertEqual(bridge._file(manager, new).data.getvalue(), b"SOURCE")

    def test_copyfile_overwrites_bytes_seen_by_open_destination_handle(self):
        old = self.persona["current_dir"] + r"\copy-source.bin"
        new = self.persona["current_dir"] + r"\copy-destination.bin"
        source = GuestFile(None, old, data=b"ABCDE")
        target = GuestFile(None, new, data=b"old target")
        view = SharedGuestFileView(target)
        view.seek(2, 0)
        manager = SimpleNamespace(files=[source, target], file_config=SimpleNamespace(files=[]))
        manager.does_file_exist = lambda path: any(
            item.path.lower() == path.lower() for item in manager.files)
        errors = []
        emu = SimpleNamespace(read_mem_string=lambda address, _width: {1: old, 2: new}[address],
                              get_file_manager=lambda: manager, set_last_error=errors.append)
        bridge = VirtualFileBridge(self.persona["current_dir"],
                                   ArtifactCatalog(self.root / "artifacts"))
        bridge.file_open_options[0x202] = (bridge._key(new), 3, 1)
        self.assertEqual(bridge._copy_file(emu, "kernel32.CopyFileW", None, [1, 2, 0]), 0)
        self.assertEqual(errors[-1], 32)
        self.assertEqual(target.data.getvalue(), b"old target")
        self.assertEqual(bridge._copy_file(emu, "kernel32.CopyFileW", None, [1, 2, 1]), 0)
        self.assertEqual(errors[-1], 80)
        bridge.file_open_options[0x202] = (bridge._key(new), 3, 2)
        self.assertEqual(bridge._copy_file(emu, "kernel32.CopyFileW", None, [1, 2, 0]), 1)
        self.assertIs(bridge._file(manager, new), target)
        self.assertEqual(view.tell(), 2)
        self.assertEqual(view.get_data(4), b"CDE")
        self.assertEqual(source.data.getvalue(), b"ABCDE")

    def test_copyfile_open_configured_destination_fails_visibly(self):
        old = self.persona["current_dir"] + r"\copy-source.bin"
        new = self.persona["current_dir"] + r"\copy-mapped.bin"
        backing = self.root / "mapped-destination.bin"
        backing.write_bytes(b"host backing")
        entry = FileEntryFullPath(mode="full_path", emu_path=new, path=str(backing))
        source = GuestFile(None, old, data=b"SOURCE")
        target = GuestFile(None, new, config=entry)
        manager = SimpleNamespace(files=[source, target],
                                  file_config=SimpleNamespace(files=[entry]))
        manager.does_file_exist = lambda path: any(
            item.path.lower() == path.lower() for item in manager.files)
        errors = []
        emu = SimpleNamespace(read_mem_string=lambda address, _width: {1: old, 2: new}[address],
                              get_file_manager=lambda: manager, set_last_error=errors.append)
        bridge = VirtualFileBridge(self.persona["current_dir"],
                                   ArtifactCatalog(self.root / "artifacts"))
        bridge.file_open_options[0x202] = (bridge._key(new), 3, 2)
        self.assertEqual(bridge._copy_file(emu, "kernel32.CopyFileW", None, [1, 2, 0]), 0)
        self.assertEqual(errors[-1], 50)
        self.assertTrue(bridge.unsupported)
        self.assertEqual(backing.read_bytes(), b"host backing")

    def test_copyfile_persona_mapping_is_snapshot_in_guest(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                exe = FIXTURES / f"copy_config_{arch}.exe"
                image = exe.read_bytes()
                result = run_native(image, inspect_pe(image, exe.name), self.persona,
                                    root, [], 10, 100_000)
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                copy = report["virtual_file_events"][0]
                self.assertTrue(copy["success"])
                self.assertTrue(copy["source_exists_after"])
                self.assertTrue(copy["destination_exists_after"])
                self.assertEqual((root / "persona-files" / "file-0000.bin").read_bytes(),
                                 b"Personal notes\n")
                self.assertTrue(any(item["source"] == "virtual_file_copy"
                                    and (root / "artifacts" / item["file"]).read_bytes() ==
                                    b"Personal notes\n" for item in result["artifacts"]))

    def test_copyfile_rejects_configured_source_outside_persona_directory(self):
        old = r"C:\Users\Alex\Documents\outside.txt"
        new = r"C:\Users\Alex\Documents\copy.txt"
        outside = self.root / "outside.bin"
        outside.write_bytes(b"host marker")
        entry = FileEntryFullPath(mode="full_path", emu_path=old, path=str(outside))
        manager = SimpleNamespace(files=[], file_config=SimpleNamespace(files=[entry]),
                                  does_file_exist=lambda _path: False)
        emu = SimpleNamespace(read_mem_string=lambda address, _width: {1: old, 2: new}[address],
                              get_file_manager=lambda: manager, set_last_error=lambda error: None)
        bridge = VirtualFileBridge(self.persona["current_dir"],
                                   ArtifactCatalog(self.root / "artifacts"))
        with patch.object(Path, "open", side_effect=AssertionError("outside backing read")):
            self.assertEqual(bridge._copy_file(emu, "kernel32.CopyFileW", None, [1, 2, 0]), 0)
            manager.files.append(GuestFile(None, old, config=entry, data=b"cached host marker"))
            self.assertEqual(bridge._copy_file(emu, "kernel32.CopyFileW", None, [1, 2, 0]), 0)
        self.assertTrue(bridge.unsupported)
        self.assertEqual(len(manager.files), 1)
        self.assertEqual(outside.read_bytes(), b"host marker")

    def test_copyfile_uses_persona_bytes_without_opening_backing_file(self):
        old = r"C:\Users\Alex\Documents\readme.txt"
        new = r"C:\Users\Alex\Documents\copied.txt"
        backing = self.root / "persona-files" / "file-0000.bin"
        entry = FileEntryFullPath(mode="full_path", emu_path=old, path=str(backing))
        manager = SimpleNamespace(files=[], file_config=SimpleNamespace(files=[entry]),
                                  emu=SimpleNamespace(handle_allocator=None),
                                  does_file_exist=lambda _path: False)
        errors = []
        emu = SimpleNamespace(read_mem_string=lambda address, _width: {1: old, 2: new}[address],
                              get_file_manager=lambda: manager, set_last_error=errors.append)
        bridge = VirtualFileBridge(self.persona["current_dir"],
                                   ArtifactCatalog(self.root / "artifacts"),
                                   {str(backing): b"in-memory persona bytes"})
        original_open = Path.open

        def open_except_backing(path, *args, **kwargs):
            if path == backing:
                raise AssertionError("backing file opened")
            return original_open(path, *args, **kwargs)

        with patch.object(Path, "open", open_except_backing):
            self.assertEqual(bridge._copy_file(emu, "kernel32.CopyFileW", None, [1, 2, 0]), 1)
        self.assertEqual(errors[-1], 0)
        self.assertFalse(backing.exists())
        self.assertEqual(bridge._file(manager, new).data.getvalue(), b"in-memory persona bytes")

    def test_movefileex_replace_and_unsupported_flags(self):
        old = r"C:\Users\Alex\Downloads\old.bin"
        new = r"C:\Users\Alex\Downloads\new.bin"
        source = GuestFile(None, old, data=b"source bytes")
        target = GuestFile(None, new, data=b"old target")
        manager = SimpleNamespace(files=[source, target])
        manager.does_file_exist = lambda path: any(
            item.path.lower() == path.lower() for item in manager.files)
        errors = []
        emu = SimpleNamespace(read_mem_string=lambda address, _width: {1: old, 2: new}[address],
                              get_file_manager=lambda: manager, set_last_error=errors.append)
        bridge = VirtualFileBridge(self.persona["current_dir"],
                                   ArtifactCatalog(self.root / "artifacts"))
        self.assertEqual(bridge._move_file_ex(emu, "kernel32.MoveFileExW", None, [1, 2, 0]), 0)
        self.assertEqual(errors[-1], 183)
        self.assertEqual(bridge._move_file_ex(emu, "kernel32.MoveFileExW", None, [1, 2, 1]), 1)
        self.assertEqual(errors[-1], 0)
        self.assertEqual(manager.files, [source])
        self.assertEqual(source.path, new)
        self.assertEqual(bridge._move_file_ex(emu, "kernel32.MoveFileExW", None, [1, 2, 4]), 0)
        self.assertTrue(bridge.unsupported)

    def test_open_guest_file_delete_unlinks_name_and_preserves_handle_bytes(self):
        path = self.persona["current_dir"] + r"\delete-open.bin"
        source = GuestFile(None, path, data=b"payload")
        source.bytes_written = 7
        manager = SimpleNamespace(files=[source], file_config=SimpleNamespace(files=[]),
                                  file_handles={0x201: SharedGuestFileView(source)})
        manager.does_file_exist = lambda candidate: any(
            item.path.lower() == candidate.lower() for item in manager.files)
        errors = []
        emu = SimpleNamespace(read_mem_string=lambda _pointer, _width: path,
                              get_file_manager=lambda: manager, set_last_error=errors.append)
        bridge = VirtualFileBridge(self.persona["current_dir"],
                                   ArtifactCatalog(self.root / "artifacts"))
        bridge.file_open_options[0x201] = (bridge._key(path), 2, 3)
        self.assertEqual(bridge._delete_file(emu, "kernel32.DeleteFileW", None, [1]), 0)
        self.assertEqual(errors[-1], 32)
        self.assertIn(source, manager.files)
        bridge.file_open_options[0x201] = (bridge._key(path), 2, 7)
        self.assertEqual(bridge._delete_file(emu, "kernel32.DeleteFileW", None, [1]), 1)
        self.assertEqual(manager.files, [])
        self.assertIsNone(bridge.file_open_options[0x201][0])
        self.assertEqual(manager.file_handles[0x201].get_data(), b"payload")
        self.assertTrue(any(item["source"] == "virtual_file_delete"
                            for item in bridge.catalog.items))
        def create_new(_params):
            replacement = GuestFile(None, path)
            manager.files.append(replacement)
            manager.file_handles[0x202] = replacement
            return 0x202
        self.assertEqual(bridge._create_file(
            emu, "kernel32.CreateFileW", create_new,
            [1, 0x40000000, 0, 0, 4, 0x80, 0]), 0x202)
        self.assertEqual(errors[-1], 0)

    def test_open_guest_file_rename_follows_new_name_and_rejects_open_target(self):
        old = self.persona["current_dir"] + r"\rename-open.bin"
        new = self.persona["current_dir"] + r"\rename-new.bin"
        source = GuestFile(None, old, data=b"source")
        target = GuestFile(None, new, data=b"target")
        manager = SimpleNamespace(files=[source, target], file_config=SimpleNamespace(files=[]),
                                  file_handles={0x201: SharedGuestFileView(source),
                                                0x202: SharedGuestFileView(target)})
        manager.does_file_exist = lambda candidate: any(
            item.path.lower() == candidate.lower() for item in manager.files)
        errors = []
        emu = SimpleNamespace(read_mem_string=lambda pointer, _width: {1: old, 2: new}[pointer],
                              get_file_manager=lambda: manager, set_last_error=errors.append)
        bridge = VirtualFileBridge(self.persona["current_dir"],
                                   ArtifactCatalog(self.root / "artifacts"))
        bridge.file_open_options[0x201] = (bridge._key(old), 2, 3)
        bridge.file_open_options[0x202] = (bridge._key(new), 2, 7)
        self.assertEqual(bridge._move_file_ex(emu, "kernel32.MoveFileExW", None, [1, 2, 1]), 0)
        self.assertEqual(errors[-1], 32)
        bridge.file_open_options[0x201] = (bridge._key(old), 2, 7)
        self.assertEqual(bridge._move_file_ex(emu, "kernel32.MoveFileExW", None, [1, 2, 1]), 0)
        self.assertEqual(errors[-1], 5)
        self.assertEqual(manager.file_handles[0x202].get_data(), b"target")
        bridge.file_open_options.pop(0x202)
        manager.file_handles.pop(0x202)
        self.assertEqual(bridge._move_file_ex(emu, "kernel32.MoveFileExW", None, [1, 2, 1]), 1)
        self.assertEqual(source.path, new)
        self.assertEqual(manager.file_handles[0x201].path, new)
        self.assertEqual(bridge.file_open_options[0x201][0], bridge._key(new))
        self.assertNotIn(target, manager.files)

    def test_movefileex_retargets_configured_file_without_host_move(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                exe = FIXTURES / f"move_config_{arch}.exe"
                image = exe.read_bytes()
                result = run_native(image, inspect_pe(image, exe.name), self.persona,
                                    root, [], 10, 100_000)
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                self.assertEqual(len(report["virtual_file_events"]), 2)
                move = report["virtual_file_events"][0]
                self.assertTrue(move["success"])
                self.assertFalse(move["old_exists_after"])
                self.assertTrue(move["new_exists_after"])
                self.assertTrue(any(event.get("api_name", "").endswith("ExitProcess")
                                    and event.get("args") == ["0x1"]
                                    for event in report["entry_points"][0]["events"]))
                self.assertEqual((root / "persona-files" / "file-0000.bin").read_bytes(),
                                 b"Personal notes\n")

    def test_movefileex_replaces_configured_destination_in_guest_only(self):
        old = r"C:\Users\Alex\Documents\source.txt"
        new = r"C:\Users\Alex\Documents\target.txt"
        target = FileEntryFullPath(mode="full_path", emu_path=new, path=r"D:\preset-target")
        source = FileEntryFullPath(mode="full_path", emu_path=old, path=r"D:\preset-source")
        manager = SimpleNamespace(files=[], file_config=SimpleNamespace(files=[target, source]))
        errors = []
        emu = SimpleNamespace(read_mem_string=lambda address, _width: {1: old, 2: new}[address],
                              get_file_manager=lambda: manager, set_last_error=errors.append)
        bridge = VirtualFileBridge(self.persona["current_dir"],
                                   ArtifactCatalog(self.root / "artifacts"))
        self.assertEqual(bridge._move_file_ex(emu, "kernel32.MoveFileExW", None, [1, 2, 0]), 0)
        self.assertEqual(errors[-1], 183)
        self.assertEqual(bridge._move_file_ex(emu, "kernel32.MoveFileExW", None, [1, 2, 1]), 1)
        self.assertEqual(errors[-1], 0)
        self.assertEqual(len(manager.file_config.files), 1)
        self.assertEqual(manager.file_config.files[0].emu_path, new)
        self.assertEqual(manager.file_config.files[0].path, r"D:\preset-source")
        self.assertEqual(source.emu_path, old)
        mapped = GuestFile(None, new, config=manager.file_config.files[0])
        manager.files.append(mapped)
        reverse_emu = SimpleNamespace(read_mem_string=lambda address, _width: {1: new, 2: old}[address],
                                      get_file_manager=lambda: manager, set_last_error=errors.append)
        self.assertEqual(bridge._move_file_ex(reverse_emu, "kernel32.MoveFileExW", None, [1, 2, 0]), 1)
        self.assertEqual(mapped.path, old)

    def test_deletefile_removes_guest_file_on_both_architectures(self):
        for arch in ("x86", "x64"):
            for variant in ("W", "A"):
                with self.subTest(arch=arch, variant=variant), tempfile.TemporaryDirectory() as folder:
                    root = Path(folder)
                    name = f"delete_file{'_a' if variant == 'A' else ''}_{arch}.exe"
                    exe = FIXTURES / name
                    image = exe.read_bytes()
                    result = run_native(image, inspect_pe(image, exe.name), self.persona,
                                        root, [], 10, 100_000)
                    report = json.loads((root / result["engine_report"]).read_text())
                    self.assertFalse(result["errors"])
                    self.assertFalse(result["api_coverage"]["signature_only_calls"])
                    deletion = next(e for e in report["virtual_file_events"]
                                    if e["event"] == "virtual_file_delete")
                    self.assertEqual(deletion["api"], f"kernel32.DeleteFile{variant}")
                    self.assertTrue(deletion["success"])
                    self.assertFalse(deletion["exists_after"])
                    self.assertTrue(any(event.get("api_name", "").endswith("ExitProcess")
                                        and event.get("args") == ["0x1"]
                                        for event in report["entry_points"][0]["events"]))

    def test_deletefile_retires_exact_mapping_without_touching_backing_file(self):
        guest = r"C:\Users\Alex\Documents\mapped.txt"
        backing = self.root / "mapped.bin"
        backing.write_bytes(b"host backing bytes")
        entry = FileEntryFullPath(mode="full_path", emu_path=guest, path=str(backing))
        mapped = GuestFile(None, guest, config=entry)
        manager = SimpleNamespace(files=[mapped], file_config=SimpleNamespace(files=[entry]))
        manager.does_file_exist = lambda path: any(
            item.path.lower() == path.lower() for item in manager.files) or any(
                item.emu_path.lower() == path.lower() for item in manager.file_config.files)
        errors = []
        emu = SimpleNamespace(read_mem_string=lambda _address, _width: guest,
                              get_file_manager=lambda: manager, set_last_error=errors.append)
        bridge = VirtualFileBridge(self.persona["current_dir"],
                                   ArtifactCatalog(self.root / "artifacts"))
        self.assertEqual(bridge._delete_file(emu, "kernel32.DeleteFileW", None, [1]), 1)
        self.assertEqual(errors[-1], 0)
        self.assertFalse(manager.does_file_exist(guest))
        self.assertEqual(backing.read_bytes(), b"host backing bytes")
        self.assertEqual(bridge._delete_file(emu, "kernel32.DeleteFileW", None, [1]), 0)
        self.assertEqual(errors[-1], 2)

    def test_deletefile_retires_persona_mapping_inside_cpu_emulation(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                exe = FIXTURES / f"delete_config_{arch}.exe"
                image = exe.read_bytes()
                result = run_native(image, inspect_pe(image, exe.name), self.persona,
                                    root, [], 10, 100_000)
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                first_delete = report["virtual_file_events"][0]
                self.assertEqual({key: first_delete[key] for key in (
                    "event", "api", "path", "success", "exists_after")}, {
                    "event": "virtual_file_delete", "api": "kernel32.DeleteFileW",
                    "path": r"C:\Users\Alex\Documents\readme.txt", "success": True,
                    "exists_after": False})
                self.assertIsInstance(first_delete["pos"]["tick"], int)
                self.assertEqual(report["virtual_file_events"][1]["event"],
                                 "virtual_file_process_cleanup")
                self.assertTrue(any(event.get("api_name", "").endswith("ExitProcess")
                                    and event.get("args") == ["0x1"]
                                    for event in report["entry_points"][0]["events"]))
                self.assertEqual((root / "persona-files" / "file-0000.bin").read_bytes(),
                                 b"Personal notes\n")

    def test_deletefile_marks_pattern_mapping_as_unsupported(self):
        guest = r"C:\Users\Alex\Downloads\pattern.txt"
        manager = SimpleNamespace(files=[], file_config=SimpleNamespace(files=[]),
                                  does_file_exist=lambda _path: True)
        errors = []
        emu = SimpleNamespace(read_mem_string=lambda _address, _width: guest,
                              get_file_manager=lambda: manager, set_last_error=errors.append)
        bridge = VirtualFileBridge(self.persona["current_dir"],
                                   ArtifactCatalog(self.root / "artifacts"))
        self.assertEqual(bridge._delete_file(emu, "kernel32.DeleteFileW", None, [1]), 0)
        self.assertEqual(errors[-1], 50)
        self.assertTrue(bridge.unsupported)

    def test_guest_dropped_dll_executes_from_virtual_file_bytes(self):
        for arch in ("x86", "x64"):
            for variant in ("", "tls_", "import_"):
                with self.subTest(arch=arch, variant=variant):
                    name = f"dropped_{variant}dll_{arch}.exe"
                    result = self.native(name)
                    report = json.loads((self.root / result["engine_report"]).read_text())
                    self.assertFalse(result["errors"])
                    self.assertEqual(report["entry_points"][0]["ret_val"], "0x2a")
                    events = result["dll_initialization_events"]
                    self.assertEqual([event["event"] for event in events],
                                     (["virtual_dll_load", "dll_tls_callback",
                                       "dll_process_attach"] if variant == "tls_" else
                                      ["virtual_dll_load", "dll_process_attach"]))
                    self.assertTrue(events[0]["mapped"] and events[-1]["success"])
                    if variant == "import_":
                        imported = [event for event in report["entry_points"][0]["events"]
                                    if str(event.get("api_name", "")).endswith("GetCurrentProcessId")]
                        self.assertEqual(len(imported), 1)
                        self.assertNotEqual(imported[0]["ret_val"], "0x0")
                    dll = (FIXTURES / name).read_bytes()[0xA00:0x1000]
                    self.assertEqual(events[0]["sha256"], hashlib.sha256(dll).hexdigest())
                    artifact = next(item for item in result["artifacts"]
                                    if item["source"] == "guest_dll_load")
                    self.assertEqual((self.root / "artifacts" / artifact["file"]).read_bytes(), dll)

    def test_guest_dropped_dll_relocation_gate(self):
        for arch in ("x86", "x64"):
            for mode in ("valid", "missing", "bad_block"):
                with self.subTest(arch=arch, mode=mode):
                    name = f"dropped_reloc_{mode}_{arch}.exe"
                    dll = (FIXTURES / name).read_bytes()[0xA00:0x1000]
                    result = self.native(name)
                    report = json.loads((self.root / result["engine_report"]).read_text())
                    self.assertFalse(result["errors"])
                    events = result["dll_initialization_events"]
                    self.assertEqual(events[0]["event"], "virtual_dll_load")
                    embedded = next(item for item in result["artifacts"]
                                    if item["source"] == "embedded_input@0xa00")
                    self.assertEqual((self.root / "artifacts" / embedded["file"]).read_bytes(), dll)
                    if mode == "valid":
                        self.assertEqual(report["entry_points"][0]["ret_val"], "0x2a")
                        self.assertEqual([event["event"] for event in events],
                                         ["virtual_dll_load", "dll_process_attach"])
                        self.assertTrue(events[0]["mapped"] and events[1]["success"])
                        self.assertNotEqual(int(events[0]["base"], 16),
                                            0x140000000 if arch == "x64" else 0x400000)
                        self.assertEqual(events[0]["sha256"], hashlib.sha256(dll).hexdigest())
                        artifact = next(item for item in result["artifacts"]
                                        if item["source"] == "guest_dll_load")
                        self.assertEqual((self.root / "artifacts" / artifact["file"]).read_bytes(), dll)
                    else:
                        self.assertEqual(report["entry_points"][0]["ret_val"], "0x0")
                        self.assertEqual(len(events), 1)
                        self.assertFalse(events[0]["mapped"])
                        self.assertIn("cannot be mapped at preferred base", events[0]["reason"])
                        self.assertFalse(any(item["source"] == "guest_dll_load"
                                             for item in result["artifacts"]))

    def test_guest_created_forwarder_target(self):
        for arch in ("x86", "x64"):
            for mode in ("valid", "missing_reloc", "failed_attach"):
                with self.subTest(arch=arch, mode=mode):
                    name = f"dropped_guest_forwarder_{mode}_{arch}.exe"
                    image = (FIXTURES / name).read_bytes()
                    stage, leaf = image[0xA00:0x1000], image[0x1000:0x1600]
                    result = self.native(name)
                    report = json.loads((self.root / result["engine_report"]).read_text())
                    events = result["dll_initialization_events"]
                    self.assertEqual([item["event"] for item in events[:2]],
                                     ["virtual_dll_load", "dll_process_attach"])
                    self.assertTrue(events[0]["mapped"] and events[1]["success"])
                    for offset, payload in (("0xa00", stage), ("0x1000", leaf)):
                        artifact = next(item for item in result["artifacts"]
                                        if item["source"] == f"embedded_input@{offset}")
                        self.assertEqual((self.root / "artifacts" / artifact["file"]).read_bytes(),
                                         payload)
                    loaded = [item for item in result["artifacts"]
                              if item["source"] == "guest_dll_load"]
                    self.assertTrue(any((self.root / "artifacts" / item["file"]).read_bytes() == stage
                                        for item in loaded))
                    if mode == "missing_reloc":
                        self.assertEqual(report["entry_points"][0]["ret_val"], "0x0")
                        self.assertEqual(len(events), 2)
                        self.assertTrue(any("Forwarded guest DLL relocation unavailable"
                                            in error for error in result["errors"]))
                        self.assertFalse(any((self.root / "artifacts" / item["file"]).read_bytes() == leaf
                                             for item in loaded))
                        continue
                    self.assertFalse(result["errors"])
                    self.assertEqual(events[2]["event"], "dll_forwarder_map")
                    self.assertEqual(events[2]["required_by"], "guest-stage")
                    self.assertNotEqual(events[0]["base"], events[2]["base"])
                    self.assertTrue(any((self.root / "artifacts" / item["file"]).read_bytes() == leaf
                                        for item in loaded))
                    if mode == "valid":
                        self.assertEqual(report["entry_points"][0]["ret_val"], "0x2a")
                        self.assertEqual([item["event"] for item in events[2:]],
                                         ["dll_forwarder_map", "dll_process_attach"])
                        self.assertTrue(events[3]["success"])
                    else:
                        self.assertEqual(report["entry_points"][0]["ret_val"], "0x0")
                        self.assertEqual([item["event"] for item in events[2:]],
                                         ["dll_forwarder_map", "dll_process_attach",
                                          "dll_process_detach", "dll_forwarder_load_failed"])
                        self.assertFalse(events[3]["success"])

    def test_dynamic_dependency_import_forwarders(self):
        for arch in ("x86", "x64"):
            for mode in ("valid", "missing_reloc", "failed_attach", "chain"):
                with self.subTest(arch=arch, mode=mode):
                    name = f"dropped_dependency_dll_{arch}.exe"
                    data = (FIXTURES / name).read_bytes()
                    folder = FIXTURES / f"forwarded_implicit_{mode}"
                    stems = ("companion", "leaf", "terminal") if mode == "chain" else (
                        "companion", "leaf")
                    with tempfile.TemporaryDirectory() as path:
                        root = Path(path)
                        dlls = [folder / f"{stem}_{arch}.dll" for stem in stems]
                        result = run_native(data, inspect_pe(data, name), self.persona,
                                            root, dlls, 10, 100_000)
                        report = json.loads((root / result["engine_report"]).read_text())
                        events = result["dll_initialization_events"]
                        self.assertEqual(events[0]["event"], "virtual_dll_load")
                        self.assertEqual(events[1]["module"], f"companion_{arch}")
                        if mode == "missing_reloc":
                            self.assertEqual(report["entry_points"][0]["ret_val"], "0x0")
                            self.assertTrue(any("dependency relocation unavailable" in error
                                                for error in result["errors"]))
                            self.assertEqual([item["event"] for item in events[1:]], [
                                "dll_dependency_map", "virtual_dll_load_failed"])
                            continue
                        self.assertFalse(result["errors"])
                        mapped = [item["module"] for item in events
                                  if item["event"] == "dll_dependency_map"]
                        expected = ([f"companion_{arch}", f"leaf_{arch}",
                                     f"terminal_{arch}"] if mode == "chain" else
                                    [f"companion_{arch}", f"leaf_{arch}"])
                        self.assertEqual(mapped, expected)
                        attached = [item["module"] for item in events
                                    if item["event"] == "dll_process_attach"]
                        if mode == "failed_attach":
                            self.assertEqual(report["entry_points"][0]["ret_val"], "0x0")
                            self.assertEqual(attached, [f"leaf_{arch}"])
                            self.assertFalse(next(item for item in events
                                                  if item["event"] == "dll_process_attach")["success"])
                            self.assertTrue(any(item["event"] == "dll_process_detach"
                                                for item in events))
                        else:
                            self.assertEqual(report["entry_points"][0]["ret_val"], "0x2a")
                            self.assertEqual(attached, [*reversed(expected), "guest-stage"])

    def test_dynamic_dependency_forwarders_use_guest_bytes_and_release(self):
        for arch in ("x86", "x64"):
            for direction in ("guest_import", "import_guest"):
                modes = ("valid", "missing_reloc", "failed_attach") if direction == "import_guest" else (
                    "valid",)
                for mode in modes:
                    for release in ((False, True) if mode == "valid" else (False,)):
                        with self.subTest(arch=arch, direction=direction, mode=mode,
                                          release=release):
                            stem = (f"dropped_guest_import_forwarder{'_release' if release else ''}_{arch}"
                                    if direction == "guest_import" else
                                    f"dropped_import_guest_forwarder_{'release' if release else mode}_{arch}")
                            data = (FIXTURES / f"{stem}.exe").read_bytes()
                            supplied = (FIXTURES / "forwarded_implicit_chain" /
                                        f"terminal_{arch}.dll" if direction == "guest_import" else
                                        FIXTURES / "forwarded_dependency_guest" /
                                        f"companion_{arch}.dll")
                            with tempfile.TemporaryDirectory() as path:
                                root = Path(path)
                                result = run_native(data, inspect_pe(data, stem + ".exe"),
                                                    self.persona, root, [supplied], 10, 100_000)
                                report = json.loads((root / result["engine_report"]).read_text())
                                events = result["dll_initialization_events"]
                                guest_leaf = data[0x1000:0x1600]
                                embedded = next(item for item in result["artifacts"]
                                                if item["source"] == "embedded_input@0x1000")
                                self.assertEqual((root / "artifacts" / embedded["file"]).read_bytes(),
                                                 guest_leaf)
                                if mode == "missing_reloc":
                                    self.assertEqual(report["entry_points"][0]["ret_val"], "0x0")
                                    self.assertTrue(any("guest dependency cannot be mapped" in error
                                                        for error in result["errors"]))
                                    self.assertEqual(len([item for item in events if
                                                          item["event"] == "dll_process_attach"]), 0)
                                    continue
                                self.assertFalse(result["errors"])
                                mapped = [item["module"] for item in events
                                          if item["event"] == "dll_dependency_map"]
                                expected = (["guest-leaf", f"terminal_{arch}"]
                                            if direction == "guest_import" else
                                            [f"companion_{arch}", "guest-leaf"])
                                self.assertEqual(mapped, expected)
                                if mode == "failed_attach":
                                    self.assertEqual(report["entry_points"][0]["ret_val"], "0x0")
                                    self.assertTrue(any(item["event"] == "dll_process_detach"
                                                        for item in events))
                                else:
                                    self.assertEqual(report["entry_points"][0]["ret_val"],
                                                     "0x1" if release else "0x2a")
                                    if release:
                                        detached = [item["module"] for item in events
                                                    if item["event"] == "dll_process_detach"]
                                        self.assertEqual(detached, ["guest-stage", *expected])

    def test_guest_dll_literal_32_module_budget(self):
        for arch in ("x86", "x64"):
            name = f"guest_module_budget_{arch}.exe"
            data = (FIXTURES / name).read_bytes()
            for limit, expected_mapped, exit_arg in (
                (31, 31, "0x0"), (32, 32, "0x2a"), (33, 33, "0x0")):
                with self.subTest(arch=arch, limit=limit):
                    with tempfile.TemporaryDirectory() as path, patch(
                            "emumee.native.MAX_GUEST_DLLS", limit):
                        root = Path(path)
                        result = run_native(data, inspect_pe(data, name), self.persona,
                                            root, [], 30, 500_000)
                        report = json.loads((root / result["engine_report"]).read_text())
                        self.assertFalse(result["errors"])
                        events = [item for item in result["dll_initialization_events"]
                                  if item["event"] == "virtual_dll_load"]
                        mapped = [item for item in events if item["mapped"]]
                        refused = [item for item in events if not item["mapped"]]
                        self.assertEqual(len(mapped), expected_mapped)
                        self.assertEqual(len({item["path"].casefold() for item in mapped}),
                                         expected_mapped)
                        self.assertEqual(len({item["base"] for item in mapped}),
                                         expected_mapped)
                        if limit == 33:
                            self.assertFalse(refused)
                        else:
                            self.assertEqual(len(refused), 1)
                            self.assertIn("guest DLL load budget exceeded",
                                          refused[0]["reason"])
                            self.assertTrue(refused[0]["path"].endswith(
                                f"budget-{limit - 1:02d}.dll"))
                        exits = [item for item in report["entry_points"][0]["events"]
                                 if str(item.get("api_name", "")).endswith("ExitProcess")]
                        self.assertEqual(exits[-1]["args"], [exit_arg])

    def test_guest_dll_same_basename_full_path_and_name(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as path:
                name = f"guest_same_basename_{arch}.exe"
                data = (FIXTURES / name).read_bytes()
                root = Path(path)
                result = run_native(data, inspect_pe(data, name), self.persona,
                                    root, [], 30, 500_000)
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                loads = [item for item in result["dll_initialization_events"]
                         if item["event"] == "virtual_dll_load"]
                self.assertEqual(len(loads), 34)
                self.assertTrue(all(item["mapped"] for item in loads[:-1]))
                self.assertTrue(loads[0]["path"].endswith(r"Downloads\guest-stage.dll"))
                self.assertTrue(loads[1]["path"].endswith(r"Documents\guest-stage.dll"))
                self.assertNotEqual(loads[0]["base"], loads[1]["base"])
                self.assertTrue(loads[2]["reused_by_name"])
                self.assertEqual(loads[2]["base"], loads[0]["base"])
                self.assertEqual(len({item["base"] for item in loads[:-1]}), 32)
                self.assertEqual(loads[-1]["reason"], "guest DLL load budget exceeded")
                exits = [item for item in report["entry_points"][0]["events"]
                         if str(item.get("api_name", "")).endswith("ExitProcess")]
                self.assertEqual(exits[-1]["args"], ["0x2a"])

    def test_child_cannot_reuse_parent_companion_module(self):
        for arch, machine, preferred in (("x86", 0x14C, 0x50000000),
                                         ("x64", 0x8664, 0x180000000)):
            for kind in ("lookup", "handle", "handle_ex", "free", "proc",
                         "filename", "peb", "psapi_name", "psapi_path",
                         "psapi_self", "psapi_enum", "psapi_name_valid",
                         "psapi_path_valid"):
                with self.subTest(arch=arch, kind=kind), tempfile.TemporaryDirectory() as path:
                    root = Path(path)
                    name = f"child_parent_module_{kind}_{arch}.exe"
                    data = (FIXTURES / name).read_bytes()
                    dll = root / f"companion_{arch}.dll"
                    dll.write_bytes(build_relocatable_companion(machine, preferred))
                    result = run_native(data, inspect_pe(data, name), self.persona,
                                        root, [dll], 10, 200_000)
                    report = json.loads((root / result["engine_report"]).read_text())
                    if kind in ("free", "proc"):
                        self.assertEqual(len(result["errors"]), 1)
                        self.assertIn("DLL handle belongs to different guest process",
                                      result["errors"][0])
                    else:
                        self.assertFalse(result["errors"])
                    self.assertFalse(result["api_coverage"]["signature_only_calls"])
                    entries = report["entry_points"]
                    self.assertEqual(len(entries), 3)
                    self.assertEqual(entries[0]["pid"], entries[1]["pid"])
                    self.assertNotEqual(entries[0]["pid"], entries[2]["pid"])
                    self.assertEqual(entries[0]["ep_args"][0], hex(preferred))
                    if kind.endswith("_valid"):
                        opened = [event for event in report["virtual_process_events"]
                                  if event["event"] == "virtual_process_open"]
                        self.assertEqual(len(opened), 1)
                        self.assertTrue(opened[0]["success"])
                        pid_calls = [event for event in entries[2]["events"]
                                     if str(event.get("api_name", "")).endswith(
                                         "GetCurrentProcessId")]
                        self.assertEqual(len(pid_calls), 1)
                        self.assertEqual(int(pid_calls[0]["ret_val"], 16),
                                         opened[0]["pid"])
                    if kind == "lookup":
                        self.assertNotEqual(entries[2]["ret_val"], hex(preferred))
                        self.assertNotEqual(entries[2]["ret_val"], "0x0")
                        attach = [event for event in result["dll_initialization_events"]
                                  if event["event"] == "dll_process_attach"]
                        self.assertEqual(len(attach), 1)
                        self.assertEqual(attach[0]["base"], entries[2]["ret_val"])
                    elif kind == "psapi_self":
                        self.assertGreater(int(entries[2]["ret_val"], 16), 0)
                        self.assertFalse(any(event["event"] == "dll_process_attach"
                                             for event in result["dll_initialization_events"]))
                    else:
                        self.assertEqual(entries[2]["ret_val"], "0x0")
                        self.assertFalse(any(event["event"] == "dll_process_attach"
                                             for event in result["dll_initialization_events"]))

    def test_toolhelp_snapshot_uses_requested_guest_process(self):
        for arch, machine, parent_base, child_base in (
                ("x86", 0x14C, 0x400000, 0x500000),
                ("x64", 0x8664, 0x140000000, 0x1A0000000)):
            for target, expected in (("self", child_base), ("parent", parent_base),
                                     ("next", None)):
                with self.subTest(arch=arch, target=target), tempfile.TemporaryDirectory() as path:
                    root = Path(path)
                    name = f"child_parent_module_toolhelp_{target}_{arch}.exe"
                    data = (FIXTURES / name).read_bytes()
                    dll = root / f"companion_{arch}.dll"
                    dll.write_bytes(build_relocatable_companion(
                        machine, 0x180000000 if arch == "x64" else 0x50000000))
                    result = run_native(data, inspect_pe(data, name), self.persona,
                                        root, [dll], 10, 200_000)
                    report = json.loads((root / result["engine_report"]).read_text())
                    self.assertFalse(result["errors"])
                    self.assertFalse(result["api_coverage"]["signature_only_calls"])
                    entries = report["entry_points"]
                    self.assertEqual(len(entries), 3)
                    self.assertNotEqual(entries[0]["pid"], entries[2]["pid"])
                    if expected is None:
                        self.assertNotIn(int(entries[2]["ret_val"], 16),
                                         (0, child_base, parent_base))
                    else:
                        self.assertEqual(entries[2]["ret_val"], hex(expected))
                    calls_to_check = ("CreateToolhelp32Snapshot", "Module32FirstW",
                                      "Module32NextW" if target == "next" else "CloseHandle")
                    for api in calls_to_check:
                        calls = [item for item in entries[2]["events"]
                                 if str(item.get("api_name", "")).endswith(api)]
                        self.assertEqual(len(calls), 1)
                        self.assertNotEqual(calls[0]["ret_val"], "0x0")

    def test_child_cannot_use_parent_snapshot_handle(self):
        for arch, machine in (("x86", 0x14C), ("x64", 0x8664)):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as path:
                root = Path(path)
                name = f"child_parent_module_toolhelp_foreign_{arch}.exe"
                data = (FIXTURES / name).read_bytes()
                dll = root / f"companion_{arch}.dll"
                dll.write_bytes(build_relocatable_companion(
                    machine, 0x180000000 if arch == "x64" else 0x50000000))
                result = run_native(data, inspect_pe(data, name), self.persona,
                                    root, [dll], 10, 200_000)
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                self.assertFalse(result["api_coverage"]["signature_only_calls"])
                entries = report["entry_points"]
                self.assertEqual(len(entries), 3)
                self.assertNotEqual(entries[1]["pid"], entries[2]["pid"])
                snapshots = [item for item in entries[1]["events"]
                             if str(item.get("api_name", "")).endswith(
                                 "CreateToolhelp32Snapshot")]
                self.assertEqual(len(snapshots), 1)
                handle = snapshots[0]["ret_val"]
                self.assertNotIn(handle, ("0x0", "0xffffffff", "0xffffffffffffffff"))
                self.assertEqual(entries[2]["ret_val"], "0x0")
                for operation in ("Module32FirstW", "CloseHandle"):
                    calls = [item for item in entries[2]["events"]
                             if str(item.get("api_name", "")).endswith(operation)]
                    self.assertEqual(len(calls), 1)
                    self.assertEqual(calls[0]["ret_val"], "0x0")
                    self.assertEqual(calls[0]["args"][0], handle)

    def test_child_cannot_use_parent_process_handle_number(self):
        for arch, machine in (("x86", 0x14C), ("x64", 0x8664)):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                name = f"child_parent_process_handle_foreign_{arch}.exe"
                image = (FIXTURES / name).read_bytes()
                dll = root / f"companion_{arch}.dll"
                dll.write_bytes(build_relocatable_companion(
                    machine, 0x180000000 if arch == "x64" else 0x50000000))
                result = run_native(image, inspect_pe(image, name), self.persona,
                                    root, [dll], 10, 200_000)
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                entries = report["entry_points"]
                self.assertEqual(len(entries), 3)
                self.assertEqual(entries[0]["pid"], entries[1]["pid"])
                self.assertNotEqual(entries[1]["pid"], entries[2]["pid"])
                opens = [event for event in report["virtual_process_events"]
                         if event["event"] == "virtual_process_open"]
                self.assertEqual(len(opens), 1)
                self.assertTrue(opens[0]["success"])
                self.assertFalse(opens[0]["inherit"])
                reads = [event for event in report["virtual_process_events"]
                         if event["event"] == "virtual_process_memory_read"]
                self.assertEqual(len(reads), 1)
                self.assertFalse(reads[0]["success"])
                self.assertEqual(reads[0]["reason"], "invalid process handle")
                closes = [event for event in report["virtual_process_events"]
                          if event["event"] == "virtual_process_handle_close"]
                self.assertEqual(closes, [])
                self.assertEqual(reads[0]["handle"], opens[0]["handle"])
                retired = [event for event in report["virtual_process_events"]
                           if event["event"] == "virtual_process_close"
                           and event["handle"] == opens[0]["handle"]]
                self.assertTrue(retired)
                self.assertTrue(any(event["success"] for event in retired))
                self.assertTrue(any(not event["success"] and
                                    event.get("reason") == "already closed"
                                    for event in retired))
                self.assertEqual(entries[2]["ret_val"], "0x0")

    def test_child_cannot_terminate_parent_with_unowned_process_handle(self):
        for arch, machine in (("x86", 0x14C), ("x64", 0x8664)):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                name = f"child_parent_process_terminate_foreign_{arch}.exe"
                image = (FIXTURES / name).read_bytes()
                dll = root / f"companion_{arch}.dll"
                dll.write_bytes(build_relocatable_companion(
                    machine, 0x180000000 if arch == "x64" else 0x50000000))
                result = run_native(image, inspect_pe(image, name), self.persona,
                                    root, [dll], 10, 200_000)
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                entries = report["entry_points"]
                self.assertEqual(len(entries), 3)
                self.assertEqual(entries[2]["ret_val"], "0x0")
                attempts = [item for item in report["virtual_process_events"]
                            if item["event"] == "virtual_process_terminate"]
                self.assertEqual(len(attempts), 1)
                self.assertFalse(attempts[0]["success"])
                self.assertEqual(attempts[0]["reason"], "invalid process handle")
                self.assertTrue(any(item.get("api_name") == "kernel32.TerminateProcess"
                                    and item.get("ret_val") == "0x0"
                                    for item in entries[2]["events"]))

    def test_terminate_guest_process_requires_owned_terminate_right_and_cancels_child(self):
        bridge = VirtualProcessBridge(ArtifactCatalog(self.root / "artifacts"))
        parent = SimpleNamespace(pid=1, path=r"C:\parent.exe")
        child = SimpleNamespace(pid=2, path=r"C:\child.exe", handles=[0x220])
        current = [parent]
        errors, killed, exited = [], [], []
        emu = SimpleNamespace(get_ptr_size=lambda: 8,
                              get_current_process=lambda: current[0],
                              get_object_from_handle=lambda handle: (
                                  child if handle in child.handles else None),
                              set_last_error=errors.append,
                              kill_process=killed.append,
                              exit_process=lambda: exited.append(True),
                              run_queue=["caller pending run"],
                              child_processes=[child])
        bridge.created_processes.add(id(child))
        bridge.process_handle_owners[0x220] = id(parent)
        bridge.process_access[0x220] = PROCESS_VM_READ
        forbidden = lambda _: self.fail("TerminateProcess reached engine handler")
        args = [0x220, 7]
        self.assertEqual(bridge._terminate_process(
            emu, "kernel32.TerminateProcess", forbidden, args), 0)
        self.assertEqual(errors[-1], 5)
        self.assertEqual(emu.child_processes, [child])
        current[0] = child
        self.assertEqual(bridge._terminate_process(
            emu, "kernel32.TerminateProcess", forbidden, args), 0)
        self.assertEqual(errors[-1], 6)
        current[0] = parent
        bridge.process_access[0x220] |= PROCESS_TERMINATE
        self.assertEqual(bridge._terminate_process(
            emu, "kernel32.TerminateProcess", forbidden, args), 1)
        self.assertEqual(emu.child_processes, [])
        self.assertEqual(killed, [child])
        self.assertEqual(exited, [])
        self.assertEqual(emu.run_queue, ["caller pending run"])
        self.assertEqual(bridge._terminate_process(
            emu, "kernel32.TerminateProcess", forbidden, args), 0)
        self.assertEqual(errors[-1], 5)
        self.assertEqual(bridge._terminate_process(
            emu, "kernel32.TerminateProcess", forbidden,
            [0xFFFFFFFFFFFFFFFF, 9]), 1)
        self.assertEqual(killed, [child, parent])
        self.assertEqual(exited, [True])
        self.assertEqual(emu.run_queue, [])

    def test_native_get_exit_code_process_reports_still_active(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch):
                result = self.native(f"process_exit_status_{arch}.exe")
                report = json.loads((self.root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                entry = report["entry_points"][0]
                exits = [item for item in entry["events"]
                         if item.get("api_name") == "kernel32.ExitProcess"]
                self.assertEqual(len(exits), 1)
                self.assertEqual(exits[0]["args"], ["0x1"])
                queries = [item for item in report["virtual_process_events"]
                           if item["event"] == "virtual_process_exit_code"]
                self.assertEqual(len(queries), 1)
                self.assertEqual(queries[0]["exit_code"], 259)
                self.assertTrue(queries[0]["success"])

    def test_native_remote_debug_check_validates_guest_handle(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                name = f"remote_debug_check_{arch}.exe"
                image = (FIXTURES / name).read_bytes()
                result = run_native(image, inspect_pe(image, name), self.persona,
                                    root, [], 10, 100_000)
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                entry = report["entry_points"][0]
                exits = [item for item in entry["events"]
                         if item.get("api_name") == "kernel32.ExitProcess"]
                self.assertEqual(len(exits), 1)
                self.assertEqual(exits[0]["args"], ["0x1"])
                checks = [item for item in report["virtual_process_events"]
                          if item["event"] == "virtual_debugger_check"]
                self.assertEqual([item["success"] for item in checks], [True, False])

    def test_native_is_debugger_present_matches_peb(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                name = f"is_debugger_present_{arch}.exe"
                image = (FIXTURES / name).read_bytes()
                result = run_native(image, inspect_pe(image, name), self.persona,
                                    root, [], 10, 100_000)
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                exits = [item for item in report["entry_points"][0]["events"]
                         if item.get("api_name") == "kernel32.ExitProcess"]
                self.assertEqual(len(exits), 1)
                self.assertEqual(exits[0]["args"], ["0x1"])
                checks = [item for item in report["virtual_process_events"]
                          if item["event"] == "virtual_debugger_check"]
                self.assertEqual(len(checks), 1)
                self.assertEqual(checks[0]["debugger_present"], False)

    def test_native_peb_debug_flag_is_clear(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                name = f"peb_debug_check_{arch}.exe"
                image = (FIXTURES / name).read_bytes()
                result = run_native(image, inspect_pe(image, name), self.persona,
                                    root, [], 10, 100_000)
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                exits = [item for item in report["entry_points"][0]["events"]
                         if item.get("api_name") == "kernel32.ExitProcess"]
                self.assertEqual(len(exits), 1)
                self.assertEqual(exits[0]["args"], ["0x1"])

    def test_native_nt_debug_queries_are_consistent_with_no_debugger(self):
        for arch, (label, information_class, status) in product(
                ("x86", "x64"), (("port", 7, 0), ("object", 30, 0xC0000353),
                                  ("flags", 31, 0))):
            with self.subTest(arch=arch, info=label), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                name = f"nt_debug_{label}_{arch}.exe"
                image = (FIXTURES / name).read_bytes()
                result = run_native(image, inspect_pe(image, name), self.persona,
                                    root, [], 10, 100_000)
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                self.assertEqual(report["entry_points"][0]["ret_val"], "0x1")
                checks = [item for item in report["virtual_process_events"]
                          if item["event"] == "virtual_nt_process_debug_query"]
                self.assertEqual(len(checks), 1)
                self.assertEqual(checks[0]["information_class"], information_class)
                self.assertEqual(checks[0]["status"], status)

    def test_debug_queries_check_guest_handle_rights_and_buffer(self):
        for ptr_size in (4, 8):
            with self.subTest(ptr_size=ptr_size):
                bridge = VirtualProcessBridge(ArtifactCatalog(self.root / "artifacts"))
                parent = SimpleNamespace(pid=11, path=r"C:\parent.exe")
                child = SimpleNamespace(pid=12, path=r"C:\child.exe")
                current = [parent]
                objects = {0x220: parent, 0x224: child}
                memory = bytearray(b"\x7f" * 0x1000)
                errors = []

                def read(address, size):
                    if address < 0x100 or address + size > len(memory):
                        raise ValueError("bad guest pointer")
                    return bytes(memory[address:address + size])

                def write(address, data):
                    read(address, len(data))
                    memory[address:address + len(data)] = data

                emu = SimpleNamespace(get_ptr_size=lambda: ptr_size,
                                      get_current_process=lambda: current[0],
                                      get_object_from_handle=lambda handle: objects.get(handle),
                                      mem_read=read, mem_write=write,
                                      set_last_error=errors.append)
                pseudo = (1 << (ptr_size * 8)) - 1
                bridge.process_handle_owners[0x220] = id(parent)
                bridge.process_access[0x220] = PROCESS_QUERY_LIMITED_INFORMATION
                bridge.process_handle_owners[0x224] = id(child)
                bridge.process_access[0x224] = PROCESS_QUERY_INFORMATION

                self.assertEqual(bridge._is_debugger_present(
                    emu, "kernel32.IsDebuggerPresent", None, []), 0)
                self.assertEqual(bridge._check_remote_debugger_present(
                    emu, "kernel32.CheckRemoteDebuggerPresent", None,
                    [pseudo, 0x100]), 1)
                self.assertEqual(read(0x100, 4), b"\0" * 4)
                self.assertEqual(bridge._check_remote_debugger_present(
                    emu, "kernel32.CheckRemoteDebuggerPresent", None,
                    [0x220, 0x104]), 1)
                self.assertEqual(read(0x104, 4), b"\0" * 4)
                self.assertEqual(bridge._check_remote_debugger_present(
                    emu, "kernel32.CheckRemoteDebuggerPresent", None,
                    [0x224, 0x108]), 0)
                self.assertEqual(errors[-1], 6)
                self.assertEqual(read(0x108, 4), b"\x7f" * 4)
                self.assertEqual(bridge._check_remote_debugger_present(
                    emu, "kernel32.CheckRemoteDebuggerPresent", None,
                    [pseudo, 0xFFFF]), 0)
                self.assertEqual(errors[-1], 998)

                query = bridge._nt_query_information_process
                api = "ntdll.NtQueryInformationProcess"
                self.assertEqual(query(emu, api, None,
                                       [pseudo, 7, 0x200, ptr_size, 0x220]), 0)
                self.assertEqual(read(0x200, ptr_size), b"\0" * ptr_size)
                self.assertEqual(read(0x220, 4), ptr_size.to_bytes(4, "little"))
                self.assertEqual(query(emu, api, None,
                                       [pseudo, 31, 0x208, 4, 0]), 0)
                self.assertEqual(read(0x208, 4), b"\x01\0\0\0")
                self.assertEqual(query(emu, api, None,
                                       [pseudo, 30, 0x210, ptr_size, 0]),
                                 0xC0000353)
                self.assertEqual(read(0x210, ptr_size), b"\0" * ptr_size)
                self.assertEqual(query(emu, api, None,
                                       [pseudo, 7, 0x230, ptr_size - 1, 0x238]),
                                 0xC0000004)
                self.assertEqual(read(0x238, 4), ptr_size.to_bytes(4, "little"))
                self.assertEqual(read(0x230, ptr_size), b"\x7f" * ptr_size)
                self.assertEqual(query(emu, api, None,
                                       [0x220, 7, 0x240, ptr_size, 0]),
                                 0xC0000022)
                self.assertEqual(query(emu, api, None,
                                       [0x224, 7, 0x240, ptr_size, 0]),
                                 0xC0000008)
                self.assertEqual(query(emu, api, None,
                                       [pseudo, 7, 0xFFFF, ptr_size, 0]),
                                 0xC0000005)
                self.assertEqual(query(emu, api, None,
                                       [pseudo, 999, 0x240, ptr_size, 0]),
                                 0xC0000002)
                self.assertTrue(any("information class 999" in item
                                    for item in bridge.unsupported))

    def test_native_qpc_advances_between_consecutive_calls(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                name = f"qpc_progress_{arch}.exe"
                image = (FIXTURES / name).read_bytes()
                result = run_native(image, inspect_pe(image, name), self.persona,
                                    root, [], 10, 100_000)
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                events = report["entry_points"][0]["events"]
                qpc = [item for item in events
                       if item.get("api_name") == "kernel32.QueryPerformanceCounter"]
                exits = [item for item in events
                         if item.get("api_name") == "kernel32.ExitProcess"]
                self.assertEqual(len(qpc), 2)
                self.assertEqual(len(exits), 1)
                self.assertEqual(exits[0]["args"], ["0x1"])

    def test_native_shared_user_time_matches_time_apis(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                name = f"shared_time_check_{arch}.exe"
                image = (FIXTURES / name).read_bytes()
                result = run_native(image, inspect_pe(image, name), self.persona,
                                    root, [], 10, 100_000)
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                events = report["entry_points"][0]["events"]
                calls = [item.get("api_name") for item in events]
                self.assertIn("kernel32.GetSystemTimeAsFileTime", calls)
                self.assertIn("kernel32.GetTickCount", calls)
                self.assertIn("kernel32.Sleep", calls)
                exits = [item for item in events
                         if item.get("api_name") == "kernel32.ExitProcess"]
                self.assertEqual(len(exits), 1)
                self.assertEqual(exits[0]["args"], ["0x1"])

    def test_native_cpuid_has_consistent_cpu_identity(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                name = f"cpuid_identity_check_{arch}.exe"
                image = (FIXTURES / name).read_bytes()
                result = run_native(image, inspect_pe(image, name), self.persona,
                                    root, [], 10, 100_000)
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                events = report["entry_points"][0]["events"]
                exits = [item for item in events
                         if item.get("api_name") == "kernel32.ExitProcess"]
                self.assertEqual(len(exits), 1)
                self.assertEqual(exits[0]["args"], ["0x1"])

    def test_native_processor_features_match_cpuid_and_shared_page(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                name = f"processor_feature_check_{arch}.exe"
                image = (FIXTURES / name).read_bytes()
                result = run_native(image, inspect_pe(image, name), self.persona,
                                    root, [], 10, 100_000)
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                events = report["entry_points"][0]["events"]
                self.assertEqual(len([item for item in events if item.get("api_name") ==
                                      "kernel32.IsProcessorFeaturePresent"]), 8)
                exits = [item for item in events if item.get("api_name") ==
                         "kernel32.ExitProcess"]
                self.assertEqual(len(exits), 1)
                self.assertEqual(exits[0]["args"], ["0x1"])

    def test_native_nt_version_queries_match_shared_page(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                name = f"nt_version_consistency_check_{arch}.exe"
                image = (FIXTURES / name).read_bytes()
                result = run_native(image, inspect_pe(image, name), self.persona,
                                    root, [], 10, 100_000)
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                events = report["entry_points"][0]["events"]
                names = [item.get("api_name") for item in events]
                self.assertIn("ntdll.RtlGetVersion", names)
                self.assertIn("ntdll.RtlGetNtVersionNumbers", names)
                exits = [item for item in events if item.get("api_name") ==
                         "kernel32.ExitProcess"]
                self.assertEqual(len(exits), 1)
                self.assertEqual(exits[0]["args"], ["0x1"])

    def test_native_nt_version_queries_follow_custom_persona(self):
        for arch, machine in (("x86", 0x14C), ("x64", 0x8664)):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                path = root / "persona.json"
                path.write_text(json.dumps({"windows_build": 26100}),
                                encoding="utf-8")
                persona = load_persona(path)
                name = f"custom_nt_version_{arch}.exe"
                image = build_nt_version_consistency_check(machine, 26100)
                result = run_native(image, inspect_pe(image, name), persona,
                                    root, [], 10, 100_000)
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                exits = [item for item in report["entry_points"][0]["events"]
                         if item.get("api_name") == "kernel32.ExitProcess"]
                self.assertEqual(len(exits), 1)
                self.assertEqual(exits[0]["args"], ["0x1"])

    def test_native_win32_version_respects_application_manifest(self):
        for arch in ("x86", "x64"):
            for compatibility in ("none", "win81", "win10"):
                with self.subTest(arch=arch, compatibility=compatibility), \
                        tempfile.TemporaryDirectory() as folder:
                    root = Path(folder)
                    name = f"version_compat_{compatibility}_{arch}.exe"
                    image = (FIXTURES / name).read_bytes()
                    result = run_native(image, inspect_pe(image, name),
                                        self.persona, root, [], 10, 100_000)
                    report = json.loads((root / result["engine_report"]).read_text())
                    self.assertFalse(result["errors"])
                    events = report["entry_points"][0]["events"]
                    names = {item.get("api_name") for item in events}
                    self.assertIn("kernel32.GetVersion", names)
                    self.assertIn("kernel32.GetVersionExW", names)
                    exits = [item for item in events if item.get("api_name") ==
                             "kernel32.ExitProcess"]
                    self.assertEqual(len(exits), 1)
                    self.assertEqual(exits[0]["args"], ["0x1"])

    def test_native_version_verification_respects_manifest_and_true_build(self):
        for arch in ("x86", "x64"):
            for compatibility in ("none", "win81", "win10"):
                with self.subTest(arch=arch, compatibility=compatibility), \
                        tempfile.TemporaryDirectory() as folder:
                    root = Path(folder)
                    name = f"version_verify_{compatibility}_{arch}.exe"
                    image = (FIXTURES / name).read_bytes()
                    result = run_native(image, inspect_pe(image, name),
                                        self.persona, root, [], 10, 100_000)
                    report = json.loads((root / result["engine_report"]).read_text())
                    self.assertFalse(result["errors"])
                    events = report["entry_points"][0]["events"]
                    names = {item.get("api_name") for item in events}
                    self.assertIn("kernel32.VerifyVersionInfoW", names)
                    self.assertIn("ntdll.RtlVerifyVersionInfo", names)
                    exits = [item for item in events if item.get("api_name") ==
                             "kernel32.ExitProcess"]
                    self.assertEqual(len(exits), 1)
                    self.assertEqual(exits[0]["args"], ["0x1"])

    def test_native_tsc_tracks_virtual_sleep(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                name = f"tsc_sleep_check_{arch}.exe"
                image = (FIXTURES / name).read_bytes()
                result = run_native(image, inspect_pe(image, name), self.persona,
                                    root, [], 10, 100_000)
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                events = report["entry_points"][0]["events"]
                self.assertTrue(any(item.get("api_name") == "kernel32.Sleep"
                                    for item in events))
                exits = [item for item in events
                         if item.get("api_name") == "kernel32.ExitProcess"]
                self.assertEqual(len(exits), 1)
                self.assertEqual(exits[0]["args"], ["0x1"])

    def test_native_avx_fallback_preserves_vector_stores(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                name = f"avx_fallback_check_{arch}.exe"
                image = (FIXTURES / name).read_bytes()
                result = run_native(image, inspect_pe(image, name),
                                    self.persona, root, [], 10, 100_000)
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                self.assertEqual(report["avx_fallback_counts"],
                                 {"vinsertf128": 1, "vmovdqa": 1,
                                  "vmovdqu": 1, "vzeroupper": 1})
                events = report["entry_points"][0]["events"]
                exits = [item for item in events if item.get("api_name") ==
                         "kernel32.ExitProcess"]
                self.assertEqual(len(exits), 1)
                self.assertEqual(exits[0]["args"], ["0x1"])

    def test_native_console_output_is_captured_without_host_stdio(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                name = f"console_output_{arch}.exe"
                image = (FIXTURES / name).read_bytes()
                result = run_native(image, inspect_pe(image, name),
                                    self.persona, root, [], 10, 100_000)
                report = json.loads((root / result["engine_report"]).read_text())
                expected = {"stdout": "native stdout\nwide console ✓\n",
                            "stderr": "native stderr\n",
                            "stdout_truncated": False,
                            "stderr_truncated": False}
                self.assertEqual(result["console_output"], expected)
                self.assertEqual(report["console_output"], expected)
                self.assertFalse(result["errors"])
                names = {event.get("api_name") for entry in report["entry_points"]
                         for event in entry.get("events", [])}
                self.assertIn("kernel32.WriteConsoleW", names)

    def test_dashboard_renders_bounded_console_output_as_text(self):
        run_id = "20261012T200000Z-1234abcd"
        run_dir = self.root / run_id
        run_dir.mkdir()
        summary = {"id": run_id, "sample": {"name": "console.exe"},
                   "status": "completed", "console_output": {
                       "stdout": "<script>alert(1)</script>\n",
                       "stderr": "warning\n", "stdout_truncated": False,
                       "stderr_truncated": True}}
        (run_dir / "summary.json").write_text(json.dumps(summary), encoding="utf-8")
        self.assertTrue(valid_summary(summary))
        response = create_app(self.root).test_client().get(f"/runs/{run_id}")
        self.assertEqual(response.status_code, 200)
        page = response.get_data(as_text=True)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", page)
        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertIn("Standard error · truncated", page)
        summary["console_output"]["stdout"] = "x" * (128 * 1024 + 1)
        self.assertFalse(valid_summary(summary))

    def test_native_memory_status_matches_shared_page(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                name = f"memory_persona_check_{arch}.exe"
                image = (FIXTURES / name).read_bytes()
                result = run_native(image, inspect_pe(image, name), self.persona,
                                    root, [], 10, 100_000)
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                events = report["entry_points"][0]["events"]
                self.assertTrue(any(item.get("api_name") ==
                                    "kernel32.GlobalMemoryStatusEx" for item in events))
                exits = [item for item in events
                         if item.get("api_name") == "kernel32.ExitProcess"]
                self.assertEqual(len(exits), 1)
                self.assertEqual(exits[0]["args"], ["0x1"])

    def test_get_exit_code_process_checks_owner_right_and_termination_state(self):
        bridge = VirtualProcessBridge(ArtifactCatalog(self.root / "artifacts"))
        parent = SimpleNamespace(pid=1, path=r"C:\parent.exe")
        child = SimpleNamespace(pid=2, path=r"C:\child.exe", handles=[0x220])
        current = [parent]
        errors, writes, killed, exited = [], {}, [], []
        emu = SimpleNamespace(get_ptr_size=lambda: 8,
                              get_current_process=lambda: current[0],
                              get_object_from_handle=lambda handle: (
                                  child if handle in child.handles else None),
                              set_last_error=errors.append,
                              mem_read=lambda address, size: b"\0" * size,
                              mem_write=lambda address, data: writes.__setitem__(address, data),
                              kill_process=killed.append,
                              exit_process=lambda: exited.append(True),
                              run_queue=[], child_processes=[child])
        bridge.created_processes.add(id(child))
        bridge.process_handle_owners[0x220] = id(parent)
        bridge.process_access[0x220] = PROCESS_VM_READ
        forbidden = lambda _: self.fail("GetExitCodeProcess reached engine handler")
        query = [0x220, 0x1000]
        self.assertEqual(bridge._get_exit_code_process(
            emu, "kernel32.GetExitCodeProcess", forbidden, query), 0)
        self.assertEqual(errors[-1], 5)
        self.assertNotIn(0x1000, writes)
        current[0] = child
        self.assertEqual(bridge._get_exit_code_process(
            emu, "kernel32.GetExitCodeProcess", forbidden, query), 0)
        self.assertEqual(errors[-1], 6)
        current[0] = parent
        bridge.process_access[0x220] |= PROCESS_QUERY_LIMITED_INFORMATION
        self.assertEqual(bridge._get_exit_code_process(
            emu, "kernel32.GetExitCodeProcess", forbidden, query), 1)
        self.assertEqual(int.from_bytes(writes[0x1000], "little"), 259)
        self.assertEqual(bridge._get_exit_code_process(
            emu, "kernel32.GetExitCodeProcess", forbidden, [0x220, 0]), 0)
        self.assertEqual(errors[-1], 87)
        bridge.process_access[0x220] |= PROCESS_TERMINATE
        self.assertEqual(bridge._terminate_process(
            emu, "kernel32.TerminateProcess", forbidden, [0x220, 7]), 1)
        self.assertEqual(bridge._get_exit_code_process(
            emu, "kernel32.GetExitCodeProcess", forbidden, query), 1)
        self.assertEqual(int.from_bytes(writes[0x1000], "little"), 7)
        self.assertEqual(bridge._exit_process(
            emu, "kernel32.ExitProcess", lambda _: exited.append(True), [9]), None)
        self.assertEqual(bridge._get_exit_code_process(
            emu, "kernel32.GetExitCodeProcess", forbidden,
            [0xFFFFFFFFFFFFFFFF, 0x1000]), 1)
        self.assertEqual(int.from_bytes(writes[0x1000], "little"), 9)

    def test_child_process_handle_inheritance_requires_both_flags(self):
        for arch, machine in (("x86", 0x14C), ("x64", 0x8664)):
            for opened, created in product((False, True), repeat=2):
                with self.subTest(arch=arch, opened=opened, created=created), tempfile.TemporaryDirectory() as folder:
                    root = Path(folder)
                    name = (f"child_parent_process_handle_inherit_"
                            f"{int(opened)}{int(created)}_{arch}.exe")
                    image = (FIXTURES / name).read_bytes()
                    dll = root / f"companion_{arch}.dll"
                    dll.write_bytes(build_relocatable_companion(
                        machine, 0x180000000 if arch == "x64" else 0x50000000))
                    result = run_native(image, inspect_pe(image, name), self.persona,
                                        root, [dll], 10, 200_000)
                    report = json.loads((root / result["engine_report"]).read_text())
                    self.assertFalse(result["errors"])
                    entries = report["entry_points"]
                    self.assertEqual(len(entries), 3)
                    self.assertEqual(entries[2]["ret_val"],
                                     "0x1" if opened and created else "0x0")
                    opens = [event for event in report["virtual_process_events"]
                             if event["event"] == "virtual_process_open"]
                    creates = [event for event in report["virtual_process_events"]
                               if event["event"] == "virtual_process_create"]
                    reads = [event for event in report["virtual_process_events"]
                             if event["event"] == "virtual_process_memory_read"]
                    self.assertEqual(len(opens), 1)
                    self.assertEqual(len(creates), 1)
                    self.assertEqual(len(reads), 1)
                    self.assertEqual(opens[0]["inherit"], opened)
                    self.assertEqual(creates[0]["inherited_process_handles"],
                                     int(opened and created))
                    self.assertEqual(reads[0]["handle"], opens[0]["handle"])
                    self.assertEqual(reads[0]["success"], opened and created)

    def test_child_file_handle_inheritance_requires_both_flags(self):
        for arch, machine in (("x86", 0x14C), ("x64", 0x8664)):
            for opened, created in product((False, True), repeat=2):
                with self.subTest(arch=arch, opened=opened, created=created), tempfile.TemporaryDirectory() as folder:
                    root = Path(folder)
                    name = (f"child_parent_file_handle_inherit_"
                            f"{int(opened)}{int(created)}_{arch}.exe")
                    image = (FIXTURES / name).read_bytes()
                    dll = root / f"companion_{arch}.dll"
                    dll.write_bytes(build_relocatable_companion(
                        machine, 0x180000000 if arch == "x64" else 0x50000000))
                    result = run_native(image, inspect_pe(image, name), self.persona,
                                        root, [dll], 10, 200_000)
                    report = json.loads((root / result["engine_report"]).read_text())
                    self.assertFalse(result["errors"])
                    entries = report["entry_points"]
                    self.assertEqual(len(entries), 3)
                    self.assertEqual(entries[2]["ret_val"],
                                     "0x1" if opened and created else "0x0")
                    creates = [event for event in report["virtual_process_events"]
                               if event["event"] == "virtual_process_create"]
                    self.assertEqual(len(creates), 1)
                    self.assertEqual(creates[0]["inherited_file_handles"], int(opened and created))
                    child_calls = [event for event in entries[2]["events"]
                                   if str(event.get("api_name", "")).endswith(("ReadFile", "CloseHandle"))]
                    self.assertEqual([event["ret_val"] for event in child_calls],
                                     ["0x1", "0x1"] if opened and created else ["0x0", "0x0"])
                    cleanup = [event for event in report["virtual_file_events"]
                               if event["event"] == "virtual_file_process_cleanup"
                               and event["files"] == 1]
                    self.assertEqual(len(cleanup), 1)
                    closes = [event for event in report["virtual_file_events"]
                              if event["event"] == "virtual_file_close"
                              and event.get("path", "").endswith("readme.txt")]
                    self.assertEqual(len(closes), 2 if opened and created else 1)
                    if opened and created:
                        self.assertEqual(closes[0]["remaining_owners"], 1)

    def test_inherited_file_handle_survives_parent_close(self):
        for arch, machine in (("x86", 0x14C), ("x64", 0x8664)):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                name = f"child_parent_file_handle_inherit_closed_{arch}.exe"
                image = (FIXTURES / name).read_bytes()
                dll = root / f"companion_{arch}.dll"
                dll.write_bytes(build_relocatable_companion(
                    machine, 0x180000000 if arch == "x64" else 0x50000000))
                result = run_native(image, inspect_pe(image, name), self.persona,
                                    root, [dll], 10, 200_000)
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                self.assertEqual(report["entry_points"][2]["ret_val"], "0x1")
                creates = [event for event in report["virtual_process_events"]
                           if event["event"] == "virtual_process_create"]
                self.assertEqual(creates[0]["inherited_file_handles"], 1)
                closes = [event for event in report["virtual_file_events"]
                          if event["event"] == "virtual_file_close" and
                          event.get("path", "").endswith("readme.txt")]
                self.assertEqual(len(closes), 2)
                self.assertTrue(all(event["success"] for event in closes))
                self.assertEqual(closes[0]["remaining_owners"], 1)

    def test_child_mapping_handle_inheritance_requires_both_flags(self):
        for arch, machine in (("x86", 0x14C), ("x64", 0x8664)):
            for mapped, created in product((False, True), repeat=2):
                with self.subTest(arch=arch, mapped=mapped, created=created), tempfile.TemporaryDirectory() as folder:
                    root = Path(folder)
                    name = (f"child_parent_mapping_handle_inherit_"
                            f"{int(mapped)}{int(created)}_{arch}.exe")
                    image = (FIXTURES / name).read_bytes()
                    dll = root / f"companion_{arch}.dll"
                    dll.write_bytes(build_relocatable_companion(
                        machine, 0x180000000 if arch == "x64" else 0x50000000))
                    result = run_native(image, inspect_pe(image, name), self.persona,
                                        root, [dll], 10, 200_000)
                    report = json.loads((root / result["engine_report"]).read_text())
                    self.assertFalse(result["errors"])
                    entries = report["entry_points"]
                    self.assertEqual(len(entries), 3)
                    expected = mapped and created
                    self.assertEqual(entries[2]["ret_val"], "0x1" if expected else "0x0")
                    creates = [event for event in report["virtual_process_events"]
                               if event["event"] == "virtual_process_create"]
                    self.assertEqual(len(creates), 1)
                    self.assertEqual(creates[0]["inherited_mapping_handles"], int(expected))
                    child_calls = [event for event in entries[2]["events"]
                                   if str(event.get("api_name", "")).endswith(("MapViewOfFile", "CloseHandle"))]
                    self.assertEqual(len(child_calls), 2)
                    self.assertEqual(child_calls[0]["ret_val"] != "0x0", expected)
                    self.assertEqual(child_calls[1]["ret_val"], "0x1" if expected else "0x0")
                    cleanup = [event for event in report["virtual_file_events"]
                               if event["event"] == "virtual_file_process_cleanup"
                               and event["mappings"] == 1]
                    self.assertEqual(len(cleanup), 1)
                    closes = [event for event in report["virtual_file_events"]
                              if event["event"] == "virtual_mapping_close"]
                    self.assertEqual(len(closes), 2 if expected else 1)
                    if expected:
                        self.assertEqual(closes[0]["remaining_owners"], 1)

    def test_inherited_mapping_handle_survives_parent_close(self):
        for arch, machine in (("x86", 0x14C), ("x64", 0x8664)):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                name = f"child_parent_mapping_handle_inherit_closed_{arch}.exe"
                image = (FIXTURES / name).read_bytes()
                dll = root / f"companion_{arch}.dll"
                dll.write_bytes(build_relocatable_companion(
                    machine, 0x180000000 if arch == "x64" else 0x50000000))
                result = run_native(image, inspect_pe(image, name), self.persona,
                                    root, [dll], 10, 200_000)
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                self.assertEqual(report["entry_points"][2]["ret_val"], "0x1")
                creates = [event for event in report["virtual_process_events"]
                           if event["event"] == "virtual_process_create"]
                self.assertEqual(creates[0]["inherited_mapping_handles"], 1)
                closes = [event for event in report["virtual_file_events"]
                          if event["event"] == "virtual_mapping_close"]
                self.assertEqual(len(closes), 2)
                self.assertTrue(all(event["success"] for event in closes))
                self.assertEqual(closes[0]["remaining_owners"], 1)

    def test_child_cpu_cannot_access_parent_mapping_view(self):
        for arch, machine in (("x86", 0x14C), ("x64", 0x8664)):
            for access in ("read", "write"):
                with self.subTest(arch=arch, access=access), tempfile.TemporaryDirectory() as folder:
                    root = Path(folder)
                    name = f"child_parent_mapping_view_{access}_{arch}.exe"
                    image = (FIXTURES / name).read_bytes()
                    dll = root / f"companion_{arch}.dll"
                    dll.write_bytes(build_relocatable_companion(
                        machine, 0x180000000 if arch == "x64" else 0x50000000))
                    result = run_native(image, inspect_pe(image, name), self.persona,
                                        root, [dll], 10, 200_000)
                    report = json.loads((root / result["engine_report"]).read_text())
                    views = [event for event in report["virtual_file_events"]
                             if event["event"] == "virtual_mapping_view"]
                    self.assertEqual(len(views), 1, (arch, result["errors"]))
                    denied = [event for event in report["virtual_process_events"]
                              if event["event"] == "virtual_cpu_memory_denied"]
                    self.assertEqual(len(denied), 1, (arch, result["errors"]))
                    self.assertEqual((denied[0]["access"], denied[0]["reason"]),
                                     (access, "different guest process"))
                    self.assertNotEqual(denied[0]["pid"], denied[0]["owner_pid"])
                    if access == "write":
                        restored = [event for event in report["virtual_process_events"]
                                    if event["event"] == "virtual_cpu_memory_restored"]
                        self.assertEqual(len(restored), 1)
                        self.assertTrue(restored[0]["success"])
                        guest_data = [item for item in result["artifacts"]
                                      if item.get("guest_path", "").endswith("map-data.bin")]
                        self.assertTrue(guest_data)
                        self.assertTrue(all((root / "artifacts" / item["file"]).read_bytes() == b"Pers"
                                            for item in guest_data))

    def test_child_cpu_cannot_access_parent_pagefile_view(self):
        for arch, machine in (("x86", 0x14C), ("x64", 0x8664)):
            for access in ("read", "execute"):
                with self.subTest(arch=arch, access=access), tempfile.TemporaryDirectory() as folder:
                    root = Path(folder)
                    name = f"child_parent_pagefile_view_{access}_{arch}.exe"
                    image = (FIXTURES / name).read_bytes()
                    dll = root / f"companion_{arch}.dll"
                    dll.write_bytes(build_relocatable_companion(
                        machine, 0x180000000 if arch == "x64" else 0x50000000))
                    result = run_native(image, inspect_pe(image, name), self.persona,
                                        root, [dll], 10, 200_000)
                    report = json.loads((root / result["engine_report"]).read_text())
                    denied = [event for event in report["virtual_process_events"]
                              if event["event"] == "virtual_cpu_memory_denied"]
                    self.assertEqual(len(denied), 1, (arch, result["errors"]))
                    self.assertEqual((denied[0]["access"], denied[0]["reason"]),
                                     (access, "different guest process"))
                    self.assertNotEqual(denied[0]["pid"], denied[0]["owner_pid"])
                    maps = [item for item in report["entry_points"][-1]["memory"]["layout"]
                            if item["tag"].startswith("api.MapViewOfFile.")]
                    self.assertEqual(len(maps), 1)
                    self.assertEqual(int(maps[0]["address"], 16), denied[0]["address"])
                    self.assertEqual(maps[0]["prot"], "rw-" if access == "read" else "rwx")
                    self.assertEqual(_report_blob(report["data"], maps[0]["data_ref"])[:4],
                                     b"Pers" if access == "read" else b"\xc3\x90\x90\x90")

    def test_child_api_cannot_access_parent_pagefile_view(self):
        for arch, machine in (("x86", 0x14C), ("x64", 0x8664)):
            for access in ("read", "write"):
                with self.subTest(arch=arch, access=access), tempfile.TemporaryDirectory() as folder:
                    root = Path(folder)
                    name = f"child_parent_pagefile_view_api_{access}_{arch}.exe"
                    image = (FIXTURES / name).read_bytes()
                    dll = root / f"companion_{arch}.dll"
                    dll.write_bytes(build_relocatable_companion(
                        machine, 0x180000000 if arch == "x64" else 0x50000000))
                    result = run_native(image, inspect_pe(image, name), self.persona,
                                        root, [dll], 10, 200_000)
                    report = json.loads((root / result["engine_report"]).read_text())
                    role = "source" if access == "read" else "destination"
                    self.assertTrue(any(f"RtlMoveMemory: {role} belongs to different guest process"
                                        in error for error in result["errors"]))
                    denied = [item for item in report["virtual_process_events"]
                              if item["event"] == "virtual_memory_api_denied"]
                    self.assertEqual(len(denied), 1)
                    self.assertEqual((denied[0]["api"], denied[0]["size"], denied[0]["reason"]),
                                     ("kernel32.RtlMoveMemory", 4,
                                      f"{role} belongs to different guest process"))
                    self.assertFalse(any(item["event"] == "virtual_cpu_memory_denied"
                                         for item in report["virtual_process_events"]))
                    maps = [item for item in report["entry_points"][-1]["memory"]["layout"]
                            if item["tag"].startswith("api.MapViewOfFile.")]
                    self.assertEqual(len(maps), 1)
                    self.assertEqual(int(maps[0]["address"], 16),
                                     denied[0]["pointers"][role])
                    self.assertEqual(_report_blob(report["data"], maps[0]["data_ref"])[:4], b"Pers")

    def test_child_cannot_flush_or_unmap_parent_pagefile_view(self):
        for arch, machine in (("x86", 0x14C), ("x64", 0x8664)):
            for operation in ("flush", "unmap", "unmap_interior"):
                with self.subTest(arch=arch, operation=operation), tempfile.TemporaryDirectory() as folder:
                    root = Path(folder)
                    name = f"child_parent_pagefile_view_{operation}_{arch}.exe"
                    image = (FIXTURES / name).read_bytes()
                    dll = root / f"companion_{arch}.dll"
                    dll.write_bytes(build_relocatable_companion(
                        machine, 0x180000000 if arch == "x64" else 0x50000000))
                    result = run_native(image, inspect_pe(image, name), self.persona,
                                        root, [dll], 10, 200_000)
                    report = json.loads((root / result["engine_report"]).read_text())
                    self.assertFalse(result["errors"], (arch, operation))
                    entries = report["entry_points"]
                    self.assertEqual(len(entries), 3)
                    self.assertEqual(entries[-1]["ret_val"], "0x0")
                    denied = [event for event in report["virtual_file_events"]
                              if event["event"] == "virtual_mapping_view_denied"]
                    self.assertEqual(len(denied), 0 if operation == "flush" else 1)
                    if denied:
                        self.assertEqual(denied[0]["api"], "kernel32.UnmapViewOfFile")
                        self.assertEqual(denied[0]["reason"], "untracked view")
                    maps = [item for item in entries[-1]["memory"]["layout"]
                            if item["tag"].startswith("api.MapViewOfFile.")]
                    self.assertEqual(len(maps), 1)
                    if denied:
                        self.assertEqual(int(maps[0]["address"], 16), denied[0]["base"])
                    self.assertTrue(maps[0]["is_free"])
                    self.assertEqual(_report_blob(report["data"], maps[0]["data_ref"])[:4], b"Pers")

    def test_pagefile_flush_succeeds_for_owner_and_rejects_foreign_or_invalid(self):
        bridge = VirtualFileBridge(self.persona["current_dir"],
                                   ArtifactCatalog(self.root / "artifacts"))
        parent, child = object(), object()
        current = [parent]
        errors = []
        mapping = SimpleNamespace(base=0x3000, size=0x1000)
        emu = SimpleNamespace(get_current_process=lambda: current[0],
                              get_address_map=lambda address: mapping if 0x3000 <= address < 0x4000 else None,
                              set_last_error=errors.append)
        bridge.mapped_guest_view_owners[0x3000] = id(parent)
        current[0] = child
        self.assertEqual(bridge._flush_view_of_file(
            emu, "kernel32.FlushViewOfFile", None, [0x3000, 4]), 0)
        self.assertEqual(errors[-1], 6)
        current[0] = parent
        self.assertEqual(bridge._flush_view_of_file(
            emu, "kernel32.FlushViewOfFile", None, [0x3000, 4]), 1)
        self.assertEqual(errors[-1], 0)
        self.assertEqual(bridge._flush_view_of_file(
            emu, "kernel32.FlushViewOfFile", None, [0x3FFE, 4]), 0)
        self.assertEqual(errors[-1], 87)
        self.assertEqual(bridge._flush_view_of_file(
            emu, "kernel32.FlushViewOfFile", None, [0x5000, 4]), 0)
        self.assertEqual(errors[-1], 87)
        forwarded = []
        def unmap_original(params):
            forwarded.append(params)
            return 1
        self.assertEqual(bridge._unmap_view_of_file(
            emu, "kernel32.UnmapViewOfFile", unmap_original, [0x3001]), 1)
        self.assertEqual(forwarded, [[0x3000]])
        self.assertNotIn(0x3000, bridge.mapped_guest_view_owners)
        forbidden = lambda _params: self.fail("unmap engine called for an untracked address")
        self.assertEqual(bridge._unmap_view_of_file(
            emu, "kernel32.UnmapViewOfFile", forbidden, [0x5000]), 0)
        self.assertEqual(errors[-1], 87)

    def test_inherited_process_handle_survives_parent_close(self):
        for arch, machine in (("x86", 0x14C), ("x64", 0x8664)):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                name = f"child_parent_process_handle_inherit_closed_{arch}.exe"
                image = (FIXTURES / name).read_bytes()
                dll = root / f"companion_{arch}.dll"
                dll.write_bytes(build_relocatable_companion(
                    machine, 0x180000000 if arch == "x64" else 0x50000000))
                result = run_native(image, inspect_pe(image, name), self.persona,
                                    root, [dll], 10, 200_000)
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                self.assertEqual(report["entry_points"][2]["ret_val"], "0x1")
                events = report["virtual_process_events"]
                opens = [item for item in events if item["event"] == "virtual_process_open"]
                closes = [item for item in events if item["event"] == "virtual_process_close"
                          and item["handle"] == opens[0]["handle"]]
                reads = [item for item in events if item["event"] == "virtual_process_memory_read"]
                self.assertEqual(len(closes), 2)
                self.assertEqual(len(reads), 1)
                self.assertTrue(all(item["success"] for item in closes))
                self.assertTrue(reads[0]["success"])
                self.assertEqual([item["handle"] for item in closes],
                                 [opens[0]["handle"]] * 2)

    def test_set_handle_information_changes_child_inheritance(self):
        for arch, machine in (("x86", 0x14C), ("x64", 0x8664)):
            for inheritable in (False, True):
                with self.subTest(arch=arch, inheritable=inheritable), tempfile.TemporaryDirectory() as folder:
                    root = Path(folder)
                    name = (f"child_parent_process_handle_set_inherit_"
                            f"{int(inheritable)}_{arch}.exe")
                    image = (FIXTURES / name).read_bytes()
                    dll = root / f"companion_{arch}.dll"
                    dll.write_bytes(build_relocatable_companion(
                        machine, 0x180000000 if arch == "x64" else 0x50000000))
                    result = run_native(image, inspect_pe(image, name), self.persona,
                                        root, [dll], 10, 200_000)
                    report = json.loads((root / result["engine_report"]).read_text())
                    self.assertFalse(result["errors"])
                    self.assertEqual(report["entry_points"][2]["ret_val"],
                                     "0x1" if inheritable else "0x0")
                    events = report["virtual_process_events"]
                    opens = [item for item in events if item["event"] == "virtual_process_open"]
                    changed = [item for item in events
                               if item["event"] == "virtual_handle_information_set"]
                    creates = [item for item in events if item["event"] == "virtual_process_create"]
                    reads = [item for item in events if item["event"] == "virtual_process_memory_read"]
                    self.assertEqual(len(opens), len(changed))
                    self.assertEqual(len(changed), len(creates))
                    self.assertEqual(len(creates), len(reads))
                    self.assertEqual(len(reads), 1)
                    self.assertEqual(opens[0]["inherit"], not inheritable)
                    self.assertTrue(changed[0]["success"])
                    self.assertEqual(changed[0]["result_flags"], int(inheritable))
                    self.assertEqual(creates[0]["inherited_process_handles"], int(inheritable))
                    self.assertEqual(reads[0]["success"], inheritable)

    def test_child_can_use_its_own_opened_parent_process_handle(self):
        for arch, machine in (("x86", 0x14C), ("x64", 0x8664)):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                name = f"child_parent_process_handle_open_{arch}.exe"
                image = (FIXTURES / name).read_bytes()
                dll = root / f"companion_{arch}.dll"
                dll.write_bytes(build_relocatable_companion(
                    machine, 0x180000000 if arch == "x64" else 0x50000000))
                result = run_native(image, inspect_pe(image, name), self.persona,
                                    root, [dll], 10, 200_000)
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertEqual(result["errors"], [
                    "kernel32.OpenProcess: guest parent process access control not modeled"])
                entries = report["entry_points"]
                self.assertEqual(len(entries), 3)
                self.assertEqual(entries[2]["ret_val"], "0x1")
                opens = [event for event in report["virtual_process_events"]
                         if event["event"] == "virtual_process_open"]
                self.assertEqual(len(opens), 2)
                self.assertTrue(all(event["success"] for event in opens))
                self.assertNotEqual(opens[0]["handle"], opens[1]["handle"])
                reads = [event for event in report["virtual_process_events"]
                         if event["event"] == "virtual_process_memory_read"]
                self.assertEqual(len(reads), 1)
                self.assertTrue(reads[0]["success"])
                self.assertEqual(reads[0]["handle"], opens[1]["handle"])
                closes = [event for event in report["virtual_process_events"]
                          if event["event"] == "virtual_process_close"
                          and event["handle"] == opens[1]["handle"]]
                self.assertEqual(len(closes), 1)
                self.assertTrue(closes[0]["success"])
                self.assertEqual(closes[0]["handle"], opens[1]["handle"])

    def test_child_closed_process_handle_cannot_read_again(self):
        for arch, machine in (("x86", 0x14C), ("x64", 0x8664)):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                name = f"child_parent_process_handle_closed_{arch}.exe"
                image = (FIXTURES / name).read_bytes()
                dll = root / f"companion_{arch}.dll"
                dll.write_bytes(build_relocatable_companion(
                    machine, 0x180000000 if arch == "x64" else 0x50000000))
                result = run_native(image, inspect_pe(image, name), self.persona,
                                    root, [dll], 10, 200_000)
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertEqual(result["errors"], [
                    "kernel32.OpenProcess: guest parent process access control not modeled"])
                entries = report["entry_points"]
                self.assertEqual(len(entries), 3)
                self.assertEqual(entries[2]["ret_val"], "0x0")
                reads = [event for event in report["virtual_process_events"]
                         if event["event"] == "virtual_process_memory_read"]
                self.assertEqual(len(reads), 2)
                self.assertTrue(reads[0]["success"])
                self.assertFalse(reads[1]["success"])
                self.assertEqual(reads[1]["reason"], "invalid process handle")
                self.assertEqual(reads[0]["handle"], reads[1]["handle"])

    def test_guest_dll_aggregate_module_budget(self):
        for arch in ("x86", "x64"):
            for name, limit, expected in (
                (f"dropped_guest_dependency_dll_{arch}.exe", 1, "0x0"),
                (f"dropped_guest_dependency_dll_{arch}.exe", 2, "0x2a"),
                (f"dropped_guest_forwarder_valid_{arch}.exe", 1, "0x0"),
                (f"dropped_guest_forwarder_valid_{arch}.exe", 2, "0x2a"),
                (f"dropped_lifecycle_dll_{arch}.exe", 1, "0x2a"),
                (f"dropped_guest_cycle_dll_{arch}.exe", 1, "0x0"),
            ):
                with self.subTest(arch=arch, name=name, limit=limit):
                    data = (FIXTURES / name).read_bytes()
                    with tempfile.TemporaryDirectory() as path, patch(
                            "emumee.native.MAX_GUEST_DLLS", limit):
                        root = Path(path)
                        result = run_native(data, inspect_pe(data, name), self.persona,
                                            root, [], 10, 100_000)
                        report = json.loads((root / result["engine_report"]).read_text())
                        self.assertEqual(report["entry_points"][0]["ret_val"], expected)
                        events = result["dll_initialization_events"]
                        if name.startswith("dropped_guest_dependency_dll_") and limit == 1:
                            self.assertTrue(any("guest DLL load budget exceeded" in error
                                                for error in result["errors"]))
                            self.assertEqual([item["event"] for item in events], [
                                "virtual_dll_load", "virtual_dll_load_failed"])
                            self.assertEqual(sum(item["source"] == "guest_dll_load"
                                                 for item in result["artifacts"]), 1)
                        elif name.startswith("dropped_guest_forwarder_valid_") and limit == 1:
                            self.assertTrue(any("Forwarded guest DLL memory budget exceeded"
                                                in error for error in result["errors"]))
                            self.assertFalse(any(item["event"] == "dll_forwarder_map"
                                                 for item in events))
                        elif name.startswith("dropped_guest_cycle_dll_"):
                            self.assertEqual(sum(item["event"] == "virtual_dll_load_failed"
                                                 for item in events), 2)
                            loads = [item for item in events
                                     if item["event"] == "virtual_dll_load"]
                            self.assertEqual(loads[0]["base"], loads[1]["base"])
                            self.assertTrue(all("guest DLL load budget exceeded" in error
                                                for error in result["errors"]))
                        else:
                            self.assertFalse(result["errors"])

    def test_guest_dependency_relocation_gate(self):
        for arch in ("x86", "x64"):
            for mode in ("valid", "missing", "bad_block"):
                with self.subTest(arch=arch, mode=mode):
                    name = f"dropped_guest_dependency_reloc_{mode}_{arch}.exe"
                    image = (FIXTURES / name).read_bytes()
                    leaf = image[0x1000:0x1600]
                    result = self.native(name)
                    report = json.loads((self.root / result["engine_report"]).read_text())
                    events = result["dll_initialization_events"]
                    embedded = next(item for item in result["artifacts"]
                                    if item["source"] == "embedded_input@0x1000")
                    self.assertEqual((self.root / "artifacts" / embedded["file"]).read_bytes(), leaf)
                    self.assertEqual(events[0]["event"], "virtual_dll_load")
                    self.assertTrue(events[0]["mapped"])
                    if mode == "valid":
                        self.assertFalse(result["errors"])
                        self.assertEqual(report["entry_points"][0]["ret_val"], "0x2a")
                        self.assertEqual([event["event"] for event in events],
                                         ["virtual_dll_load", "dll_dependency_map",
                                          "dll_process_attach", "dll_process_attach"])
                        self.assertNotEqual(events[0]["base"], events[1]["base"])
                        self.assertTrue(events[2]["success"] and events[3]["success"])
                        loaded = [item for item in result["artifacts"]
                                  if item["source"] == "guest_dll_load"]
                        self.assertEqual(len(loaded), 2)
                        self.assertTrue(any((self.root / "artifacts" / item["file"]).read_bytes() == leaf
                                            for item in loaded))
                    else:
                        self.assertEqual(report["entry_points"][0]["ret_val"], "0x0")
                        self.assertEqual([event["event"] for event in events],
                                         ["virtual_dll_load", "virtual_dll_load_failed"])
                        self.assertIn("cannot be mapped at preferred base", events[1]["reason"])
                        self.assertTrue(any("guest dependency cannot be mapped at preferred base" in error
                                            for error in result["errors"]))
                        self.assertFalse(any(event["event"] == "dll_process_attach"
                                             for event in events))
                        self.assertFalse(any((self.root / "artifacts" / item["file"]).read_bytes() == leaf
                                             for item in result["artifacts"]
                                             if item["source"] == "guest_dll_load"))

    def test_invalid_guest_dll_fails_without_decoy_load(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch):
                result = self.native(f"dropped_invalid_dll_{arch}.exe")
                report = json.loads((self.root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                events = result["dll_initialization_events"]
                self.assertEqual(len(events), 1)
                self.assertEqual(events[0]["event"], "virtual_dll_load")
                self.assertFalse(events[0]["mapped"])
                self.assertIn("not a PE", events[0]["reason"])
                self.assertFalse(any(item["source"] == "guest_dll_load"
                                     for item in result["artifacts"]))
                exits = [event for event in report["entry_points"][0]["events"]
                         if str(event.get("api_name", "")).endswith("ExitProcess")]
                self.assertEqual(exits[-1]["args"], ["0x1"])

    def test_guest_dll_full_path_wins_over_companion_basename(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch):
                name = f"dropped_shadow_dll_{arch}.exe"
                data = (FIXTURES / name).read_bytes()
                with tempfile.TemporaryDirectory() as temp:
                    root = Path(temp)
                    result = run_native(data, inspect_pe(data, name), self.persona,
                                        root, [FIXTURES / f"companion_{arch}.dll"],
                                        10, 100_000)
                    report = json.loads((root / result["engine_report"]).read_text())
                    self.assertFalse(result["errors"])
                    self.assertEqual(report["entry_points"][0]["ret_val"], "0x2a")
                    events = result["dll_initialization_events"]
                    self.assertEqual(events[0]["event"], "virtual_dll_load")
                    self.assertIn("Documents", events[0]["path"])
                    self.assertEqual(events[1]["event"], "dll_process_attach")

    def test_guest_dll_dependency_initializes_before_import_call(self):
        for arch in ("x86", "x64"):
            name = f"dropped_dependency_dll_{arch}.exe"
            data = (FIXTURES / name).read_bytes()
            for failing in (False, True):
                with self.subTest(arch=arch, failing=failing):
                    with tempfile.TemporaryDirectory() as temp:
                        root = Path(temp)
                        companion = (FIXTURES / "failing" if failing else FIXTURES) / f"companion_{arch}.dll"
                        result = run_native(data, inspect_pe(data, name), self.persona,
                                            root, [companion], 10, 100_000)
                        report = json.loads((root / result["engine_report"]).read_text())
                        self.assertFalse(result["errors"])
                        events = result["dll_initialization_events"]
                        self.assertEqual([event["event"] for event in events[:3]],
                                         ["virtual_dll_load", "dll_dependency_map",
                                          "dll_process_attach"])
                        self.assertEqual(events[2]["module"], f"companion_{arch}")
                        self.assertEqual(events[2]["success"], not failing)
                        if failing:
                            self.assertEqual([event["event"] for event in events[3:]],
                                             ["dll_process_detach", "virtual_dll_load_failed"])
                            self.assertEqual(events[3]["module"], f"companion_{arch}")
                            self.assertEqual(report["entry_points"][0]["ret_val"], "0x0")
                        else:
                            self.assertEqual(len(events), 4)
                            self.assertEqual(events[3]["module"], "guest-stage")
                            self.assertTrue(events[3]["success"])
                            self.assertEqual(report["entry_points"][0]["ret_val"], "0x2a")

    def test_guest_created_dependency_executes_before_parent(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch):
                name = f"dropped_guest_dependency_dll_{arch}.exe"
                result = self.native(name)
                report = json.loads((self.root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                self.assertEqual(report["entry_points"][0]["ret_val"], "0x2a")
                events = result["dll_initialization_events"]
                self.assertEqual([item["event"] for item in events],
                                 ["virtual_dll_load", "dll_dependency_map",
                                  "dll_process_attach", "dll_process_attach"])
                self.assertEqual([item["module"] for item in events[2:]],
                                 ["guest-leaf", "guest-stage"])
                self.assertTrue(all(item["success"] for item in events[2:]))
                files = (FIXTURES / name).read_bytes()
                artifacts = {item["guest_path"].split("\\")[-1]: item
                             for item in result["artifacts"] if item["source"] == "guest_dll_load"}
                self.assertEqual((self.root / "artifacts" / artifacts["guest-stage.dll"]["file"]).read_bytes(),
                                 files[0xA00:0x1000])
                self.assertEqual((self.root / "artifacts" / artifacts["guest-leaf.dll"]["file"]).read_bytes(),
                                 files[0x1000:0x1600])

    def test_guest_created_dependency_detaches_after_parent(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch):
                result = self.native(f"dropped_guest_dependency_release_dll_{arch}.exe")
                report = json.loads((self.root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                exits = [item for item in report["entry_points"][0]["events"]
                         if str(item.get("api_name", "")).endswith("ExitProcess")]
                self.assertEqual(exits[-1]["args"], ["0x2a"])
                events = result["dll_initialization_events"]
                self.assertEqual([item["module"] for item in events
                                  if item["event"] == "dll_process_detach"],
                                 ["guest-stage", "guest-leaf"])
                self.assertEqual([item["module"] for item in events
                                  if item["event"] == "virtual_dll_unload"],
                                 ["guest-stage", "guest-leaf"])

    def test_nested_guest_and_companion_dependencies_attach_and_detach(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch):
                name = f"dropped_guest_nested_dll_{arch}.exe"
                data = (FIXTURES / name).read_bytes()
                result = run_native(data, inspect_pe(data, name), self.persona,
                                    self.root, [FIXTURES / f"companion_{arch}.dll"],
                                    10, 100_000)
                report = json.loads((self.root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                exits = [item for item in report["entry_points"][0]["events"]
                         if str(item.get("api_name", "")).endswith("ExitProcess")]
                self.assertEqual(exits[-1]["args"], ["0x2a"])
                events = result["dll_initialization_events"]
                self.assertEqual([item["module"] for item in events
                                  if item["event"] == "dll_process_attach"],
                                 [f"companion_{arch}", "guest-leaf", "guest-stage"])
                self.assertEqual([item["module"] for item in events
                                  if item["event"] == "dll_process_detach"],
                                 ["guest-stage", "guest-leaf", f"companion_{arch}"])

    def test_cyclic_guest_dependency_fails_and_retry_remaps(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch):
                result = self.native(f"dropped_guest_cycle_dll_{arch}.exe")
                report = json.loads((self.root / result["engine_report"]).read_text())
                self.assertTrue(any("cyclic guest DLL dependency" in item
                                    for item in result["errors"]))
                exits = [item for item in report["entry_points"][0]["events"]
                         if str(item.get("api_name", "")).endswith("ExitProcess")]
                self.assertEqual(exits[-1]["args"], ["0x2a"])
                events = result["dll_initialization_events"]
                loads = [item for item in events if item["event"] == "virtual_dll_load"]
                self.assertEqual(len(loads), 2)
                self.assertEqual(loads[0]["base"], loads[1]["base"])
                self.assertEqual(sum(item["event"] == "virtual_dll_load_failed"
                                     for item in events), 2)
                self.assertFalse(any(item["event"] == "dll_process_attach" for item in events))

    def test_guest_dll_reference_count_and_detach(self):
        for arch in ("x86", "x64"):
            for tls in (False, True):
              with self.subTest(arch=arch, tls=tls):
                result = self.native(f"dropped_{'tls_' if tls else ''}lifecycle_dll_{arch}.exe")
                report = json.loads((self.root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                self.assertEqual(report["entry_points"][0]["ret_val"], "0x2a")
                events = result["dll_initialization_events"]
                expected = (["virtual_dll_load", "dll_tls_callback", "dll_process_attach"]
                            if tls else ["virtual_dll_load", "dll_process_attach"])
                expected += ["virtual_dll_load", "virtual_dll_release"]
                if tls:
                    expected.append("dll_tls_detach")
                expected += ["dll_process_detach", "virtual_dll_unload",
                             "virtual_dll_load"]
                if tls:
                    expected.append("dll_tls_callback")
                expected.append("dll_process_attach")
                self.assertEqual([event["event"] for event in events], expected)
                release = next(event for event in events
                               if event["event"] == "virtual_dll_release")
                self.assertEqual(release["references"], 1)
                self.assertTrue(any(event.get("references") == 2 for event in events))
                self.assertTrue(events[-1]["success"])

    def test_guest_dll_unload_releases_companion_dependency(self):
        for arch in ("x86", "x64"):
            name = f"dropped_dependency_lifecycle_dll_{arch}.exe"
            data = (FIXTURES / name).read_bytes()
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                result = run_native(data, inspect_pe(data, name), self.persona, root,
                                    [FIXTURES / f"companion_{arch}.dll"], 10, 100_000)
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                exits = [event for event in report["entry_points"][0]["events"]
                         if str(event.get("api_name", "")).endswith("ExitProcess")]
                self.assertEqual(exits[-1]["args"], ["0x2a"])
                events = result["dll_initialization_events"]
                self.assertEqual([event["event"] for event in events], [
                    "virtual_dll_load", "dll_dependency_map", "dll_process_attach",
                    "dll_process_attach", "virtual_dll_load", "virtual_dll_release",
                    "dll_process_detach", "virtual_dll_unload", "dll_process_detach",
                    "companion_dll_unload", "virtual_dll_load", "dll_dependency_map",
                    "dll_process_attach", "dll_process_attach"])
                self.assertEqual([event["module"] for event in events
                                  if event["event"] == "dll_process_detach"],
                                 ["guest-stage", f"companion_{arch}"])

    def test_guest_dll_unload_retains_preloaded_companion_until_last_reference(self):
        for arch in ("x86", "x64"):
            for tls in (False, True):
                name = f"dropped_dependency_preload_dll_{arch}.exe"
                data = (FIXTURES / name).read_bytes()
                with self.subTest(arch=arch, tls=tls), tempfile.TemporaryDirectory() as temp:
                    root = Path(temp)
                    dll = (FIXTURES / "tls" if tls else FIXTURES) / f"companion_{arch}.dll"
                    result = run_native(data, inspect_pe(data, name), self.persona,
                                        root, [dll], 10, 100_000)
                    report = json.loads((root / result["engine_report"]).read_text())
                    self.assertFalse(result["errors"])
                    exits = [event for event in report["entry_points"][0]["events"]
                             if str(event.get("api_name", "")).endswith("ExitProcess")]
                    self.assertEqual(exits[-1]["args"], ["0x2a"])
                    events = result["dll_initialization_events"]
                    detach = [event["module"] for event in events
                              if event["event"] == "dll_process_detach"]
                    self.assertEqual(detach, ["guest-stage", "guest-stage",
                                              f"companion_{arch}"])
                    companion_release = [event for event in events
                                         if event["event"] == "companion_dll_release"]
                    self.assertEqual([event["references"] for event in companion_release],
                                     [1, 1])
                    self.assertEqual(sum(event["event"] == "companion_dll_unload"
                                         for event in events), 1)

    def test_guest_dll_failed_attach_detaches_and_reloads(self):
        for arch in ("x86", "x64"):
            for tls in (False, True):
              with self.subTest(arch=arch, tls=tls):
                result = self.native(f"dropped_{'tls_' if tls else ''}failed_attach_dll_{arch}.exe")
                report = json.loads((self.root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                exits = [event for event in report["entry_points"][0]["events"]
                         if str(event.get("api_name", "")).endswith("ExitProcess")]
                self.assertEqual(exits[-1]["args"], ["0x2a"])
                events = result["dll_initialization_events"]
                expected = ["virtual_dll_load"]
                if tls:
                    expected.append("dll_tls_callback")
                expected.append("dll_process_attach")
                if tls:
                    expected.append("dll_tls_detach")
                expected += ["dll_process_detach", "virtual_dll_load_failed"]
                self.assertEqual([event["event"] for event in events], expected * 2)
                self.assertFalse(any(event["success"] for event in events
                                     if event["event"] == "dll_process_attach"))
                self.assertEqual(events[0]["base"], events[len(expected)]["base"])

    def test_guest_dll_failed_attach_releases_new_companion_dependency(self):
        for arch in ("x86", "x64"):
            name = f"dropped_dependency_failed_attach_dll_{arch}.exe"
            data = (FIXTURES / name).read_bytes()
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                result = run_native(data, inspect_pe(data, name), self.persona, root,
                                    [FIXTURES / f"companion_{arch}.dll"], 10, 100_000)
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                exits = [event for event in report["entry_points"][0]["events"]
                         if str(event.get("api_name", "")).endswith("ExitProcess")]
                self.assertEqual(exits[-1]["args"], ["0x2a"])
                events = result["dll_initialization_events"]
                expected = ["virtual_dll_load", "dll_dependency_map",
                            "dll_process_attach", "dll_process_attach",
                            "dll_process_detach", "dll_process_detach",
                            "virtual_dll_load_failed"]
                self.assertEqual([event["event"] for event in events], expected * 2)
                self.assertEqual([event["success"] for event in events
                                  if event["event"] == "dll_process_attach"],
                                 [True, False, True, False])
                self.assertEqual([event["module"] for event in events
                                  if event["event"] == "dll_process_detach"],
                                 ["guest-stage", f"companion_{arch}"] * 2)

    def test_unresolved_guest_dll_dependency_does_not_leave_mapped_modules(self):
        for arch in ("x86", "x64"):
            name = f"dropped_dependency_failed_attach_dll_{arch}.exe"
            data = (FIXTURES / name).read_bytes()
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                companion = root / f"companion_{arch}.dll"
                image = bytearray((FIXTURES / companion.name).read_bytes())
                image[0x570:0x57B] = b"OtherValue\0"
                companion.write_bytes(image)
                result = run_native(data, inspect_pe(data, name), self.persona,
                                    root, [companion], 10, 100_000)
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertTrue(any("unresolved dependency export" in error
                                    for error in result["errors"]))
                events = result["dll_initialization_events"]
                self.assertEqual([event["event"] for event in events],
                                 ["virtual_dll_load", "dll_dependency_map",
                                  "virtual_dll_load_failed"] * 2)
                self.assertEqual(events[0]["base"], events[3]["base"])
                exits = [event for event in report["entry_points"][0]["events"]
                         if str(event.get("api_name", "")).endswith("ExitProcess")]
                self.assertEqual(exits[-1]["args"], ["0x2a"])

    def test_missing_full_dll_path_does_not_resolve_companion_basename(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch):
                name = f"missing_companion_path_{arch}.exe"
                data = (FIXTURES / name).read_bytes()
                with tempfile.TemporaryDirectory() as temp:
                    root = Path(temp)
                    result = run_native(data, inspect_pe(data, name), self.persona,
                                        root, [FIXTURES / f"companion_{arch}.dll"],
                                        10, 100_000)
                    report = json.loads((root / result["engine_report"]).read_text())
                    self.assertFalse(result["errors"])
                    self.assertEqual(report["entry_points"][0]["ret_val"], "0x0")
                    events = result["dll_initialization_events"]
                    self.assertEqual(len(events), 1)
                    self.assertFalse(events[0]["mapped"])
                    self.assertIn("absent", events[0]["reason"])

    def test_companion_dll_export_executes_on_both_architectures(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch):
                exe = FIXTURES / f"call_export_{arch}.exe"
                dll = FIXTURES / f"companion_{arch}.dll"
                with tempfile.TemporaryDirectory() as folder:
                    root = Path(folder)
                    result = run_native(exe.read_bytes(), inspect_pe(exe.read_bytes(), exe.name),
                                        self.persona, root, [dll], 10, 100_000)
                    report = json.loads((root / result["engine_report"]).read_text())
                    self.assertFalse(result["errors"])
                    events = report["entry_points"][0]["events"]
                    self.assertTrue(any("LoadLibrary" in e.get("api_name", "") and
                                        int(e.get("ret_val", "0"), 16) != 0 for e in events))
                    self.assertTrue(any(e.get("api_name", "").endswith("ExitProcess") and
                                        e.get("args") == ["0x2a"] for e in events))
                    self.assertEqual(len(result["dll_initialization_events"]), 1)
                    attach = result["dll_initialization_events"][0]
                    self.assertEqual({key: attach[key] for key in (
                        "event", "module", "base", "success")},
                        {"event": "dll_process_attach", "module": f"companion_{arch}",
                         "base": "0x180000000" if arch == "x64" else "0x50000000",
                         "success": True})
                    self.assertIsInstance(attach["pos"]["tick"], int)
                    gc.collect()  # Speakeasy's PE loader holds the mapped DLL file until GC.

    def test_direct_nt_loader_uses_guest_companion_on_both_architectures(self):
        for arch in ("x86", "x64"):
            for tls in (False, True):
                with self.subTest(arch=arch, tls=tls), tempfile.TemporaryDirectory() as temp:
                    root = Path(temp)
                    exe = FIXTURES / f"ldr_companion_{arch}.exe"
                    dll = (FIXTURES / "tls" if tls else FIXTURES) / f"companion_{arch}.dll"
                    data = exe.read_bytes()
                    try:
                        result = run_native(data, inspect_pe(data, exe.name), self.persona,
                                            root, [dll], 10, 100_000)
                        report = json.loads((root / result["engine_report"]).read_text())
                        self.assertFalse(result["errors"])
                        self.assertEqual(report["entry_points"][0]["ret_val"], "0x2a")
                        calls = [event for event in report["entry_points"][0]["events"]
                                 if event.get("api_name", "").endswith(
                                     ("LdrLoadDll", "LdrGetProcedureAddress",
                                      "LdrUnloadDll"))]
                        self.assertEqual([event["api_name"].split(".")[-1]
                                          for event in calls],
                                         ["LdrLoadDll", "LdrGetProcedureAddress",
                                          "LdrUnloadDll"])
                        self.assertTrue(all(event["ret_val"] == "0x0" for event in calls))
                        expected = (["dll_tls_callback"] if tls else []) + [
                            "dll_process_attach"]
                        expected += (["dll_tls_detach"] if tls else []) + [
                            "dll_process_detach", "companion_dll_unload"]
                        self.assertEqual([event["event"] for event in
                                          result["dll_initialization_events"]], expected)
                    finally:
                        gc.collect()

    def test_direct_nt_loader_rejects_bad_name_and_failed_dll_init(self):
        for arch in ("x86", "x64"):
            exe = FIXTURES / f"ldr_companion_{arch}.exe"
            for variant in ("bad_counted_name", "failed_tls_init"):
                with self.subTest(arch=arch, variant=variant), tempfile.TemporaryDirectory() as temp:
                    root = Path(temp)
                    data = bytearray(exe.read_bytes())
                    dll = root / f"companion_{arch}.dll"
                    if variant == "bad_counted_name":
                        struct.pack_into("<H", data, 0x650, 0xFFFF)
                        dll.write_bytes((FIXTURES / dll.name).read_bytes())
                        expected_status = "0xc000000d"
                    else:
                        broken = bytearray((FIXTURES / "tls" / dll.name).read_bytes())
                        broken[0x266] = 0
                        dll.write_bytes(broken)
                        expected_status = "0xc0000142"
                    try:
                        result = run_native(bytes(data), inspect_pe(bytes(data), exe.name),
                                            self.persona, root, [dll], 10, 100_000)
                        report = json.loads((root / result["engine_report"]).read_text())
                        self.assertFalse(result["errors"])
                        self.assertEqual(report["entry_points"][0]["ret_val"], "0x1")
                        loads = [event for event in report["entry_points"][0]["events"]
                                 if event.get("api_name", "").endswith("LdrLoadDll")]
                        self.assertEqual(len(loads), 1)
                        self.assertEqual(loads[0]["ret_val"], expected_status)
                        self.assertFalse(any(event["event"] == "companion_dll_unload"
                                             for event in result["dll_initialization_events"]))
                    finally:
                        gc.collect()

    def test_dynamic_companion_relocation_checks_base_collision(self):
        for arch in ("x86", "x64"):
            exe = FIXTURES / f"call_export_{arch}.exe"
            data = exe.read_bytes()
            preferred = 0x140000000 if arch == "x64" else 0x400000
            for variant in ("reloc_dynamic", "no_reloc_dynamic", "bad_reloc_dynamic"):
                with self.subTest(arch=arch, variant=variant), tempfile.TemporaryDirectory() as folder:
                    root = Path(folder)
                    dll = FIXTURES / variant / f"companion_{arch}.dll"
                    result = run_native(data, inspect_pe(data, exe.name), self.persona,
                                        root, [dll], 10, 100_000)
                    report = json.loads((root / result["engine_report"]).read_text())
                    entry = report["entry_points"][0]
                    api_events = entry["events"]
                    loads = [item for item in api_events
                             if item.get("api_name", "").endswith("LoadLibraryA")]
                    self.assertEqual(len(loads), 1)
                    if variant == "reloc_dynamic":
                        self.assertFalse(result["errors"])
                        self.assertFalse(entry.get("error"))
                        self.assertEqual(entry["ret_val"], "0x2a")
                        loaded_base = int(loads[0]["ret_val"], 16)
                        self.assertNotEqual(loaded_base, preferred)
                        self.assertEqual(len(result["dll_initialization_events"]), 1)
                        attach = result["dll_initialization_events"][0]
                        self.assertEqual({key: attach[key] for key in (
                            "event", "module", "base", "success")},
                            {"event": "dll_process_attach", "module": f"companion_{arch}",
                             "base": hex(loaded_base), "success": True})
                        self.assertIsInstance(attach["pos"]["tick"], int)
                    else:
                        self.assertEqual(loads[0]["ret_val"], "0x0")
                        self.assertTrue(any("companion relocation unavailable" in error
                                            for error in result["errors"]))
                        self.assertFalse(result["dll_initialization_events"])

    def test_dynamic_companion_tls_precedes_dllmain(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                exe = FIXTURES / f"call_export_{arch}.exe"
                dll = FIXTURES / "tls" / f"companion_{arch}.dll"
                try:
                    image = exe.read_bytes()
                    result = run_native(image, inspect_pe(image, exe.name), self.persona,
                                        root, [dll], 10, 100_000)
                    report = json.loads((root / result["engine_report"]).read_text())
                    self.assertFalse(result["errors"])
                    self.assertEqual([event["event"] for event in result["dll_initialization_events"]],
                                     ["dll_tls_callback", "dll_process_attach"])
                    self.assertTrue(result["dll_initialization_events"][1]["success"])
                    self.assertTrue(any(event.get("api_name", "").endswith("ExitProcess")
                                        and event.get("args") == ["0x2a"]
                                        for event in report["entry_points"][0]["events"]))
                finally:
                    gc.collect()

    def test_dynamic_companion_reference_count_detach_and_reload(self):
        for arch in ("x86", "x64"):
            for tls in (False, True):
                with self.subTest(arch=arch, tls=tls), tempfile.TemporaryDirectory() as temp:
                    root = Path(temp)
                    exe = FIXTURES / f"companion_lifecycle_{arch}.exe"
                    dll = (FIXTURES / "tls" if tls else FIXTURES) / f"companion_{arch}.dll"
                    image = exe.read_bytes()
                    result = run_native(image, inspect_pe(image, exe.name), self.persona,
                                        root, [dll], 10, 100_000)
                    report = json.loads((root / result["engine_report"]).read_text())
                    self.assertFalse(result["errors"])
                    exits = [event for event in report["entry_points"][0]["events"]
                             if str(event.get("api_name", "")).endswith("ExitProcess")]
                    self.assertEqual(exits[-1]["args"], ["0x2a"])
                    events = result["dll_initialization_events"]
                    expected = (["dll_tls_callback"] if tls else []) + [
                        "dll_process_attach", "companion_dll_retain",
                        "companion_dll_release"]
                    if tls:
                        expected.append("dll_tls_detach")
                    expected += ["dll_process_detach", "companion_dll_unload"]
                    if tls:
                        expected.append("dll_tls_callback")
                    expected.append("dll_process_attach")
                    self.assertEqual([event["event"] for event in events], expected)
                    frees = [event for event in report["entry_points"][0]["events"]
                             if str(event.get("api_name", "")).endswith("FreeLibrary")]
                    self.assertEqual([event["ret_val"] for event in frees],
                                     ["0x1", "0x1", "0x0"])

    def test_dynamic_tls_initialization_failure_returns_null(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                exe = FIXTURES / f"load_result_{arch}.exe"
                dll = root / f"companion_{arch}.dll"
                data = bytearray((FIXTURES / "tls" / dll.name).read_bytes())
                data[0x266] = 0  # TLS callback no longer writes the required marker.
                dll.write_bytes(data)
                try:
                    image = exe.read_bytes()
                    result = run_native(image, inspect_pe(image, exe.name), self.persona,
                                        root, [dll], 10, 100_000)
                    report = json.loads((root / result["engine_report"]).read_text())
                    self.assertFalse(result["errors"])
                    self.assertEqual([event["event"] for event in result["dll_initialization_events"]],
                                     ["dll_tls_callback", "dll_process_attach",
                                      "dll_tls_detach", "dll_process_detach",
                                      "virtual_dll_load_failed"])
                    self.assertFalse(result["dll_initialization_events"][1]["success"])
                    self.assertTrue(any(event.get("api_name", "").endswith("ExitProcess")
                                        and event.get("args") == ["0x0"]
                                        for event in report["entry_points"][0]["events"]))
                finally:
                    gc.collect()

    def test_loadlibraryex_companion_stack_and_return(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                exe = FIXTURES / f"load_library_ex_{arch}.exe"
                dll = FIXTURES / "tls" / f"companion_{arch}.dll"
                try:
                    image = exe.read_bytes()
                    result = run_native(image, inspect_pe(image, exe.name), self.persona,
                                        root, [dll], 10, 100_000)
                    report = json.loads((root / result["engine_report"]).read_text())
                    self.assertFalse(result["errors"])
                    self.assertTrue(result["dll_initialization_events"][-1]["success"])
                    expected = "0x180000000" if arch == "x64" else "0x50000000"
                    self.assertTrue(any(event.get("api_name", "").endswith("ExitProcess")
                                        and event.get("args") == [expected]
                                        for event in report["entry_points"][0]["events"]))
                finally:
                    gc.collect()

    def test_failed_companion_initialization_returns_null_hmodule(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                exe = FIXTURES / f"load_result_{arch}.exe"
                dll = root / f"companion_{arch}.dll"
                data = bytearray((FIXTURES / dll.name).read_bytes())
                data[0x208] = 0  # DllMain returns FALSE after the marker write.
                dll.write_bytes(data)
                try:
                    image = exe.read_bytes()
                    result = run_native(image, inspect_pe(image, exe.name), self.persona,
                                        root, [dll], 10, 100_000)
                    report = json.loads((root / result["engine_report"]).read_text())
                    self.assertFalse(result["errors"])
                    self.assertTrue(any(e.get("api_name", "").endswith("ExitProcess")
                                        and e.get("args") == ["0x0"]
                                        for e in report["entry_points"][0]["events"]))
                    self.assertEqual([event["event"] for event in result["dll_initialization_events"]],
                                     ["dll_process_attach", "dll_process_detach",
                                      "virtual_dll_load_failed"])
                    self.assertFalse(result["dll_initialization_events"][0]["success"])
                    self.assertTrue(any(e.get("api_name", "").endswith("LoadLibraryA")
                                        and e.get("ret_val") == "0x0"
                                        for e in report["entry_points"][0]["events"]))
                finally:
                    gc.collect()

    def test_static_companion_import_runs_initialization_before_exe(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                exe = FIXTURES / f"static_companion_{arch}.exe"
                dll = FIXTURES / f"companion_{arch}.dll"
                try:
                    image = exe.read_bytes()
                    result = run_native(image, inspect_pe(image, exe.name), self.persona,
                                        root, [dll], 10, 100_000)
                    report = json.loads((root / result["engine_report"]).read_text())
                    self.assertFalse(result["errors"])
                    self.assertEqual(report["entry_points"][0]["ep_type"],
                                     f"static_dll_entry_companion_{arch}")
                    self.assertEqual(report["entry_points"][0]["ret_val"], "0x1")
                    self.assertTrue(any(e.get("api_name", "").endswith("ExitProcess")
                                        and e.get("args") == ["0x2a"]
                                        for e in report["entry_points"][1]["events"]))
                finally:
                    gc.collect()

    def test_static_companion_reference_survives_one_dynamic_release(self):
        for arch in ("x86", "x64"):
            for tls in (False, True):
                name = f"static_companion_lifecycle_{arch}.exe"
                image = (FIXTURES / name).read_bytes()
                dll = (FIXTURES / "tls" if tls else FIXTURES) / f"companion_{arch}.dll"
                with self.subTest(arch=arch, tls=tls), tempfile.TemporaryDirectory() as temp:
                    root = Path(temp)
                    result = run_native(image, inspect_pe(image, name), self.persona,
                                        root, [dll], 10, 100_000)
                    report = json.loads((root / result["engine_report"]).read_text())
                    self.assertFalse(result["errors"])
                    exits = [event for entry in report["entry_points"]
                             for event in (entry.get("events") or [])
                             if str(event.get("api_name", "")).endswith("ExitProcess")]
                    self.assertEqual(exits[-1]["args"], ["0x2a"])
                    events = result["dll_initialization_events"]
                    expected = ["companion_dll_retain", "companion_dll_release"]
                    if tls:
                        expected.append("dll_tls_detach")
                    expected += ["dll_process_detach", "companion_dll_unload"]
                    if tls:
                        expected.append("dll_tls_callback")
                    expected.append("dll_process_attach")
                    self.assertEqual([event["event"] for event in events], expected)

    def test_static_companion_tls_precedes_dllmain(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                exe = FIXTURES / f"static_companion_{arch}.exe"
                dll = FIXTURES / "tls" / f"companion_{arch}.dll"
                try:
                    image = exe.read_bytes()
                    result = run_native(image, inspect_pe(image, exe.name), self.persona,
                                        root, [dll], 10, 100_000)
                    report = json.loads((root / result["engine_report"]).read_text())
                    self.assertFalse(result["errors"])
                    self.assertEqual(report["entry_points"][0]["ep_type"],
                                     f"static_dll_tls_companion_{arch}_0")
                    self.assertEqual(report["entry_points"][1]["ret_val"], "0x1")
                    self.assertTrue(any(event.get("api_name", "").endswith("ExitProcess")
                                        and event.get("args") == ["0x2a"]
                                        for event in report["entry_points"][2]["events"]))
                finally:
                    gc.collect()

    def test_static_companion_failed_initialization_is_partial(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                exe = FIXTURES / f"static_companion_{arch}.exe"
                dll = root / f"companion_{arch}.dll"
                data = bytearray((FIXTURES / dll.name).read_bytes())
                data[0x208] = 0
                dll.write_bytes(data)
                try:
                    image = exe.read_bytes()
                    result = run_native(image, inspect_pe(image, exe.name), self.persona,
                                        root, [dll], 10, 100_000)
                    report = json.loads((root / result["engine_report"]).read_text())
                    self.assertEqual([entry["ep_type"] for entry in report["entry_points"]],
                                     [f"static_dll_entry_companion_{arch}",
                                      f"static_dll_detach_companion_{arch}"])
                    self.assertEqual(report["entry_points"][0]["ret_val"], "0x0")
                    self.assertFalse(any(item.get("api_name", "").endswith("ExitProcess")
                                         for entry in report["entry_points"]
                                         for item in (entry.get("events") or [])))
                    self.assertTrue(any("Static companion initialization failed" in str(error)
                                        for error in result["errors"]))
                    self.assertEqual([event["event"] for event in
                                      result["dll_initialization_events"]],
                                     ["static_dll_process_attach_failed",
                                      "dll_process_detach"])
                finally:
                    gc.collect()

    def test_nested_static_companions_attach_in_dependency_order(self):
        for arch in ("x86", "x64"):
            for variant in ("", "tls_leaf", "failing_leaf", "failing_middle",
                            "failing_tls_leaf", "failing_middle_tls_leaf",
                            "no_entry_tls_leaf", "failing_middle_no_entry_tls_leaf"):
                with self.subTest(arch=arch, variant=variant), tempfile.TemporaryDirectory() as folder:
                    root = Path(folder)
                    exe = FIXTURES / f"static_companion_{arch}.exe"
                    companion_dir = FIXTURES / "static_chain" / variant
                    data = exe.read_bytes()
                    result = run_native(data, inspect_pe(data, exe.name), self.persona,
                                        root, [companion_dir / f"companion_{arch}.dll",
                                               companion_dir / f"leaf_{arch}.dll"],
                                        10, 100_000)
                    report = json.loads((root / result["engine_report"]).read_text())
                    kinds = [item["ep_type"] for item in report["entry_points"]]
                    self.assertFalse(report.get("errors"))
                    self.assertFalse(any(item.get("error") for item in report["entry_points"]))
                    expected = ([f"static_dll_tls_leaf_{arch}_0"]
                                if "tls_leaf" in variant else [])
                    if "no_entry_tls_leaf" not in variant:
                        expected.append(f"static_dll_entry_leaf_{arch}")
                    if variant not in ("failing_leaf", "failing_tls_leaf"):
                        expected.append(f"static_dll_entry_companion_{arch}")
                    if variant.startswith("failing"):
                        failed_stem = (f"leaf_{arch}" if variant in ("failing_leaf", "failing_tls_leaf")
                                       else f"companion_{arch}")
                        if variant == "failing_tls_leaf":
                            expected.append(f"static_dll_tls_detach_leaf_{arch}_0")
                        expected.append(f"static_dll_detach_{failed_stem}")
                        if variant in ("failing_middle_tls_leaf",
                                       "failing_middle_no_entry_tls_leaf"):
                            expected.append(f"static_dll_tls_detach_leaf_{arch}_0")
                        if variant.startswith("failing_middle") and "no_entry" not in variant:
                            expected.append(f"static_dll_detach_leaf_{arch}")
                    else:
                        expected.append("module_entry")
                    self.assertEqual(kinds, expected)
                    if variant.startswith("failing"):
                        self.assertTrue(any("Static companion initialization failed" in item
                                            for item in result["errors"]))
                        self.assertEqual(len(result["errors"]), 1)
                        self.assertNotIn("module_entry", kinds)
                        events = result["dll_initialization_events"]
                        detached = [item["module"] for item in events
                                    if item["event"] == "dll_process_detach"]
                        self.assertEqual(detached, [failed_stem] +
                                         ([f"leaf_{arch}"] if variant.startswith("failing_middle")
                                           and "no_entry" not in variant
                                          else []))
                        if variant == "failing_middle_no_entry_tls_leaf":
                            self.assertEqual([item["module"] for item in events
                                              if item["event"] == "dll_tls_detach"],
                                             [f"leaf_{arch}"])
                        if variant in ("failing_leaf", "failing_middle"):
                            probed = [entry["ret_val"] for entry in report["entry_points"]
                                      if entry["ep_type"].startswith("static_dll_detach_")]
                            self.assertEqual(probed, ["0x4d"] * len(detached))
                    else:
                        self.assertFalse(result["errors"])
                        exits = [event for event in report["entry_points"][-1]["events"]
                                 if str(event.get("api_name", "")).endswith("ExitProcess")]
                        self.assertEqual(exits[-1]["args"], ["0x2a"])

    def test_loaded_companion_export_forwarders(self):
        for arch in ("x86", "x64"):
            for mode in ("name", "ordinal", "missing", "cycle"):
                for kind in ("static", "dynamic"):
                    with self.subTest(arch=arch, mode=mode, kind=kind):
                        chain = (FIXTURES / "static_chain" / f"forwarded_{mode}"
                                 if kind == "static" else
                                 FIXTURES / f"forwarded_dynamic_{mode}")
                        name = f"{'static_companion' if kind == 'static' else 'checked_call_export'}_{arch}.exe"
                        data = (FIXTURES / name).read_bytes()
                        with tempfile.TemporaryDirectory() as folder:
                            root = Path(folder)
                            dlls = [chain / f"companion_{arch}.dll",
                                    chain / f"leaf_{arch}.dll"]
                            if kind == "static" and mode in ("missing", "cycle"):
                                expected = ("Forwarded DLL target not loaded" if mode == "missing"
                                            else "Cyclic DLL export forwarder")
                                with self.assertRaisesRegex(ValueError, expected):
                                    run_native(data, inspect_pe(data, name), self.persona,
                                               root, dlls, 10, 100_000)
                                continue
                            result = run_native(data, inspect_pe(data, name), self.persona,
                                                root, dlls, 10, 100_000)
                            report = json.loads((root / result["engine_report"]).read_text())
                            entries = report["entry_points"]
                            if mode in ("name", "ordinal"):
                                self.assertFalse(result["errors"])
                                self.assertEqual(entries[-1]["ret_val"], "0x2a")
                                self.assertFalse(any(item.get("error") for item in entries))
                                if kind == "static":
                                    self.assertEqual([item["ep_type"] for item in entries],
                                                     [f"static_dll_entry_leaf_{arch}",
                                                      f"static_dll_entry_companion_{arch}",
                                                      "module_entry"])
                                else:
                                    self.assertEqual([item["event"] for item in
                                                      result["dll_initialization_events"]],
                                                     ["dll_dependency_map", "dll_process_attach",
                                                      "dll_process_attach"])
                            else:
                                expected = ("Forwarded DLL target not loaded" if mode == "missing"
                                            else "Cyclic DLL export forwarder")
                                self.assertTrue(any(expected in error for error in result["errors"]))
                                self.assertEqual(entries[0]["ret_val"], "0x0")
                                self.assertFalse(any(item.get("ret_val") == "0x2a"
                                                     for item in entries))

    def test_static_import_maps_implicit_forwarder_target(self):
        for arch in ("x86", "x64"):
            for mode in ("valid", "missing_reloc", "failed_attach", "chain"):
                with self.subTest(arch=arch, mode=mode):
                    name = f"static_companion_{arch}.exe"
                    data = (FIXTURES / name).read_bytes()
                    folder = FIXTURES / f"forwarded_implicit_{mode}"
                    stems = ("companion", "leaf", "terminal") if mode == "chain" else (
                        "companion", "leaf")
                    dlls = [folder / f"{stem}_{arch}.dll" for stem in stems]
                    with tempfile.TemporaryDirectory() as path:
                        root = Path(path)
                        if mode == "missing_reloc":
                            with self.assertRaisesRegex(ValueError,
                                                        "Static companion relocation unavailable"):
                                run_native(data, inspect_pe(data, name), self.persona,
                                           root, dlls, 10, 100_000)
                            continue
                        result = run_native(data, inspect_pe(data, name), self.persona,
                                            root, dlls, 10, 100_000)
                        report = json.loads((root / result["engine_report"]).read_text())
                        entries = report["entry_points"]
                        if mode == "failed_attach":
                            self.assertTrue(any("Static companion initialization failed" in error
                                                for error in result["errors"]))
                            self.assertEqual([entry["ep_type"] for entry in entries], [
                                f"static_dll_entry_leaf_{arch}",
                                f"static_dll_detach_leaf_{arch}"])
                            self.assertFalse(any(entry["ep_type"] == "module_entry"
                                                 for entry in entries))
                        else:
                            self.assertFalse(result["errors"])
                            expected = ([f"static_dll_entry_terminal_{arch}"]
                                        if mode == "chain" else [])
                            self.assertEqual([entry["ep_type"] for entry in entries], [
                                *expected, f"static_dll_entry_leaf_{arch}",
                                f"static_dll_entry_companion_{arch}", "module_entry"])
                            self.assertEqual(entries[-1]["ret_val"], "0x2a")

    def test_static_forwarder_target_survives_middle_reload(self):
        for arch in ("x86", "x64"):
            for mode in ("valid", "chain"):
                with self.subTest(arch=arch, mode=mode):
                    name = f"static_companion_lifecycle_{arch}.exe"
                    data = (FIXTURES / name).read_bytes()
                    folder = FIXTURES / f"forwarded_implicit_{mode}"
                    stems = ("companion", "leaf", "terminal") if mode == "chain" else (
                        "companion", "leaf")
                    dlls = [folder / f"{stem}_{arch}.dll" for stem in stems]
                    with tempfile.TemporaryDirectory() as path:
                        root = Path(path)
                        result = run_native(data, inspect_pe(data, name), self.persona,
                                            root, dlls, 10, 100_000)
                        report = json.loads((root / result["engine_report"]).read_text())
                        events = result["dll_initialization_events"]
                        self.assertFalse(result["errors"])
                        self.assertEqual(report["entry_points"][-1]["ret_val"], "0x2a")
                        self.assertEqual([event["event"] for event in events], [
                            "companion_dll_retain", "companion_dll_release",
                            "companion_dll_release", "dll_process_detach",
                            "companion_dll_unload", "dll_process_attach"])
                        self.assertEqual(events[3]["module"], f"companion_{arch}")
                        self.assertEqual(events[5]["module"], f"companion_{arch}")
                        self.assertEqual(events[2]["references"], 1)

    def test_implicit_companion_forwarder_target_loads_and_unloads(self):
        for arch in ("x86", "x64"):
            for mode in ("valid", "missing_reloc", "failed_attach", "chain"):
                with self.subTest(arch=arch, mode=mode), tempfile.TemporaryDirectory() as folder:
                    root = Path(folder)
                    source = FIXTURES / f"forwarded_implicit_{mode}"
                    stems = ("companion", "leaf", "terminal") if mode == "chain" else (
                        "companion", "leaf")
                    dlls = [source / f"{stem}_{arch}.dll" for stem in stems]
                    name = f"checked_call_export_{arch}.exe"
                    data = (FIXTURES / name).read_bytes()
                    result = run_native(data, inspect_pe(data, name), self.persona,
                                        root, dlls, 10, 100_000)
                    report = json.loads((root / result["engine_report"]).read_text())
                    self.assertEqual(len(report["entry_points"]), 1)
                    self.assertFalse(report["entry_points"][0].get("error"))
                    for dll in dlls:
                        self.assertEqual((root / "inputs" / dll.name).read_bytes(),
                                         dll.read_bytes())
                    events = result["dll_initialization_events"]
                    if mode in ("valid", "chain"):
                        self.assertFalse(result["errors"])
                        self.assertEqual(report["entry_points"][0]["ret_val"], "0x2a")
                        mapped = [event for event in events
                                  if event["event"] == "dll_forwarder_map"]
                        attached = [event for event in events
                                    if event["event"] == "dll_process_attach"]
                        expected = ([f"leaf_{arch}"] if mode == "valid" else
                                    [f"leaf_{arch}", f"terminal_{arch}"])
                        self.assertEqual([event["module"] for event in mapped], expected)
                        self.assertEqual([event["module"] for event in attached],
                                         [f"companion_{arch}", *reversed(expected)])
                        self.assertTrue(all(event["success"] for event in attached))
                        self.assertEqual(len({event["base"] for event in attached}),
                                         len(attached))
                    elif mode == "missing_reloc":
                        self.assertEqual(report["entry_points"][0]["ret_val"], "0x0")
                        self.assertTrue(any("Forwarded DLL relocation unavailable" in error
                                            for error in result["errors"]))
                        self.assertEqual([event["event"] for event in events],
                                         ["dll_process_attach"])
                    else:
                        self.assertFalse(result["errors"])
                        self.assertEqual(report["entry_points"][0]["ret_val"], "0x0")
                        self.assertEqual([event["event"] for event in events],
                                         ["dll_process_attach", "dll_forwarder_map",
                                          "dll_process_attach", "dll_process_detach",
                                          "dll_forwarder_load_failed"])
                        self.assertFalse(events[2]["success"])

            for mode in ("valid", "chain"):
                with self.subTest(arch=arch, lifecycle=mode), tempfile.TemporaryDirectory() as folder:
                    root = Path(folder)
                    source = FIXTURES / f"forwarded_implicit_{mode}"
                    stems = ("companion", "leaf", "terminal") if mode == "chain" else (
                        "companion", "leaf")
                    name = f"companion_lifecycle_{arch}.exe"
                    data = (FIXTURES / name).read_bytes()
                    result = run_native(data, inspect_pe(data, name), self.persona,
                                        root, [source / f"{stem}_{arch}.dll" for stem in stems],
                                        10, 100_000)
                    report = json.loads((root / result["engine_report"]).read_text())
                    self.assertFalse(result["errors"])
                    self.assertEqual(report["entry_points"][0]["ret_val"], "0x2a")
                    detached = [event["module"] for event in result["dll_initialization_events"]
                                if event["event"] == "dll_process_detach"]
                    self.assertEqual(detached, [f"{stem}_{arch}" for stem in stems])
                    self.assertEqual(len([event for event in result["dll_initialization_events"]
                                          if event["event"] == "dll_forwarder_map"]),
                                     (len(stems) - 1) * 2)

    def test_relocatable_static_companion_loads_after_base_collision(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                exe = FIXTURES / f"static_companion_{arch}.exe"
                chain = FIXTURES / "static_chain" / "reloc_leaf"
                data = exe.read_bytes()
                result = run_native(data, inspect_pe(data, exe.name), self.persona,
                                    root, [chain / f"companion_{arch}.dll",
                                           chain / f"leaf_{arch}.dll"], 10, 100_000)
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                entries = report["entry_points"]
                self.assertEqual([item["ep_type"] for item in entries],
                                 [f"static_dll_entry_leaf_{arch}",
                                  f"static_dll_entry_companion_{arch}", "module_entry"])
                self.assertFalse(any(item.get("error") for item in entries))
                self.assertEqual([item["ret_val"] for item in entries],
                                 ["0x1", "0x1", "0x2a"])
                leaf_base = int(entries[0]["start_addr"], 16) - 0x1000
                preferred = 0x1A0000000 if arch == "x64" else 0x52000000
                self.assertNotEqual(leaf_base, preferred)
                self.assertEqual(int(entries[0]["ep_args"][0], 16), leaf_base)
                middle_base = int(entries[1]["start_addr"], 16) - 0x1000
                self.assertEqual(middle_base, preferred)

                for variant in ("no_reloc_collision", "bad_reloc_block"):
                    with self.subTest(arch=arch, variant=variant):
                        negative = FIXTURES / "static_chain" / variant
                        with self.assertRaisesRegex(
                                ValueError, "Static companion relocation unavailable"):
                            run_native(data, inspect_pe(data, exe.name), self.persona,
                                       root / variant,
                                       [negative / f"companion_{arch}.dll",
                                        negative / f"leaf_{arch}.dll"], 10, 100_000)

    def test_malformed_companion_relocation_blocks_are_rejected(self):
        for arch in ("x86", "x64"):
            source = (FIXTURES / "static_chain" / "reloc_leaf" /
                      f"leaf_{arch}.dll").read_bytes()
            for kind in ("valid", "high_low", "zero_block", "wrong_type",
                         "out_of_range", "dangling_highadj"):
                with self.subTest(arch=arch, kind=kind):
                    payload = bytearray(source)
                    if kind == "zero_block":
                        struct.pack_into("<I", payload, 0x5B4, 0)
                    elif kind == "high_low":
                        struct.pack_into("<HH", payload, 0x5B8, 0x1002, 0x2032)
                    elif kind == "wrong_type":
                        struct.pack_into("<H", payload, 0x5B8, 0x6002)
                    elif kind == "out_of_range":
                        relocation_type = 10 if arch == "x64" else 3
                        struct.pack_into("<IIH", payload, 0x5B0, 0x2000, 12,
                                         (relocation_type << 12) | 0xFFF)
                    elif kind == "dangling_highadj":
                        struct.pack_into("<H", payload, 0x5BA, 0x4032)
                    parsed = pefile.PE(data=bytes(payload), fast_load=True)
                    try:
                        self.assertEqual(_has_supported_base_relocations(parsed),
                                         kind in ("valid", "high_low"))
                    finally:
                        parsed.close()

    def test_nested_static_reference_survives_dynamic_release(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                exe = FIXTURES / f"static_companion_lifecycle_{arch}.exe"
                chain = FIXTURES / "static_chain"
                data = exe.read_bytes()
                result = run_native(data, inspect_pe(data, exe.name), self.persona,
                                    root, [chain / f"companion_{arch}.dll",
                                           chain / f"leaf_{arch}.dll"], 10, 100_000)
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                exits = [item for item in report["entry_points"][-1]["events"]
                         if str(item.get("api_name", "")).endswith("ExitProcess")]
                self.assertEqual(exits[-1]["args"], ["0x2a"])
                events = result["dll_initialization_events"]
                self.assertTrue(any(item["event"] == "companion_dll_retain" and
                                    item["module"] == f"companion_{arch}" for item in events))
                self.assertEqual([item["module"] for item in events
                                  if item["event"] == "companion_dll_unload"],
                                 [f"companion_{arch}"])
                self.assertTrue(any(item["event"] == "companion_dll_release" and
                                    item["base"] == ("0x50000000" if arch == "x86"
                                                     else "0x180000000") and
                                    item["references"] == 1 for item in events))

    def test_host_local_socket_is_denied_and_logged(self):
        result = self.native("local_network_x86.exe")
        report = json.loads((self.root / result["engine_report"]).read_text())
        self.assertTrue(any("broker unavailable" in e.get("error", "").lower()
                            for e in report["network_events"]))
        with self.assertRaises(NetworkDenied):
            public_ipv4("127.0.0.1", 80)
        with self.assertRaises(NetworkDenied):
            public_ipv4("192.168.1.1", 80)

    def test_urlmon_download_uses_guest_storage_and_extracts_bytes(self):
        payload = b"harmless URLMON download marker"
        with patch.object(NetworkBridge, "fetch", return_value=payload):
            for arch in ("x86", "x64"):
                for cache in (False, True):
                    for wide in (False, True):
                        with self.subTest(arch=arch, cache=cache, wide=wide), tempfile.TemporaryDirectory() as folder:
                            root = Path(folder)
                            name = f"urlmon_{'cache_' if cache else ''}{'w' if wide else 'a'}_{arch}.exe"
                            data = (FIXTURES / name).read_bytes()
                            result = run_native(data, inspect_pe(data, name), self.persona,
                                                root, [], 10, 100_000)
                            report = json.loads((root / result["engine_report"]).read_text())
                            self.assertFalse(result["errors"])
                            exits = [item for item in report["entry_points"][0]["events"]
                                     if str(item.get("api_name", "")).endswith("ExitProcess")]
                            self.assertEqual(exits[-1]["args"], ["0x1"])
                            files = [item for item in report["virtual_file_events"]
                                     if item["event"] == "virtual_network_download"]
                            self.assertEqual(len(files), 1)
                            self.assertIn("INetCache" if cache else "urlmon-output.bin", files[0]["path"])
                            artifacts = [item for item in result["artifacts"]
                                         if item["source"] == "urlmon_download_file"]
                            self.assertEqual(len(artifacts), 1)
                            self.assertEqual((root / "artifacts" / artifacts[0]["file"]).read_bytes(), payload)

    def test_urlmon_without_broker_fails_and_logs_attempt(self):
        for arch in ("x86", "x64"):
            for cache in (False, True):
                with self.subTest(arch=arch, cache=cache), tempfile.TemporaryDirectory() as folder:
                    root = Path(folder)
                    name = f"urlmon_{'cache_' if cache else ''}w_{arch}.exe"
                    data = (FIXTURES / name).read_bytes()
                    result = run_native(data, inspect_pe(data, name), self.persona,
                                        root, [], 10, 100_000)
                    report = json.loads((root / result["engine_report"]).read_text())
                    exits = [item for item in report["entry_points"][0]["events"]
                             if str(item.get("api_name", "")).endswith("ExitProcess")]
                    self.assertEqual(exits[-1]["args"], ["0x0"])
                    self.assertTrue(any(item["event"] == "http_request"
                                        for item in report["network_events"]))
                    self.assertTrue(any(item["event"] == "network_denied"
                                        for item in report["network_events"]))
                    self.assertFalse(any(item["source"] == "urlmon_download_file"
                                         for item in result["artifacts"]))

    def test_urlmon_cpu_fixture_uses_broker_and_logs_transfer(self):
        payload = b"harmless local URLMON transport marker"

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *_args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_address[1]

        def test_resolver(host, _port):
            if host == "public.test":
                return "127.0.0.1"  # Redirect only this harmless local test transport.
            raise NetworkDenied(f"Private or host-local destination denied: {host}")

        try:
            with patch("emumee.networkipc.public_ipv4", side_effect=test_resolver):
                for arch, machine in (("x86", 0x14C), ("x64", 0x8664)):
                    for cache in (False, True):
                        with self.subTest(arch=arch, cache=cache), tempfile.TemporaryDirectory() as folder:
                            root = Path(folder)
                            name = f"urlmon_broker_{arch}.exe"
                            data = build_urlmon_download(
                                machine, cache=cache,
                                url=f"http://public.test:{port}/payload.bin")
                            with NetworkBroker(root):
                                result = run_native(data, inspect_pe(data, name),
                                                    self.persona, root, [], 10, 100_000)
                            report = json.loads((root / result["engine_report"]).read_text())
                            broker = json.loads((root / "network-broker.json").read_text())
                            self.assertFalse(result["errors"])
                            self.assertTrue(any(item["event"] == "http_response" and
                                                item["size"] == len(payload) for item in broker))
                            self.assertTrue(any(item["event"] == "http_request"
                                                for item in report["network_events"]))
                            self.assertTrue(any(item["event"] == "virtual_network_download"
                                                for item in report["virtual_file_events"]))
                            artifact = next(item for item in result["artifacts"]
                                            if item["source"] == "urlmon_download_file")
                            self.assertEqual((root / "artifacts" / artifact["file"]).read_bytes(),
                                             payload)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_urlmon_download_cannot_replace_host_backed_guest_mapping(self):
        path = r"C:\Users\Alex\Downloads\urlmon-output.bin"
        backing = self.root / "configured.bin"
        backing.write_bytes(b"unchanged host-side marker")
        configured = FileEntryFullPath(mode="full_path", emu_path=path,
                                        path=str(backing))
        manager = SimpleNamespace(files=[], file_config=SimpleNamespace(files=[configured]))
        emu = SimpleNamespace(get_file_manager=lambda: manager)
        bridge = VirtualFileBridge(self.persona["current_dir"],
                                   ArtifactCatalog(self.root / "artifacts"))
        with self.assertRaisesRegex(ValueError, "host-backed"):
            bridge.save_network_download(emu, path, b"new bytes", "https://example.com/")
        self.assertEqual(backing.read_bytes(), b"unchanged host-side marker")
        self.assertFalse(manager.files)

    def test_urlmon_rejects_overlong_guest_url_before_broker(self):
        bridge = NetworkBridge(ArtifactCatalog(self.root / "artifacts"), object())
        emu = SimpleNamespace(read_mem_string=lambda pointer, _width, _limit:
                              "h" * 2049 if pointer == 1 else r"C:\guest.bin")
        with patch.object(bridge, "fetch", side_effect=AssertionError("broker called")):
            self.assertNotEqual(bridge._url_download_file(
                emu, "urlmon.URLDownloadToFileW", None, [0, 1, 2, 0, 0]), 0)
            self.assertNotEqual(bridge._url_download_cache(
                emu, "urlmon.URLDownloadToCacheFileW", None, [0, 1, 2, 128, 0, 0]), 0)
        self.assertEqual(sum(item["event"] == "network_denied" for item in bridge.events), 2)

    def test_worker_network_fails_closed_without_broker(self):
        bridge = NetworkBridge(ArtifactCatalog(self.root / "artifacts"))
        self.assertIsNone(bridge.rpc)
        with patch("emumee.network.socket.socket", side_effect=AssertionError("host socket opened")):
            result = bridge._socket(None, "ws2_32.socket", lambda _params: self.fail("guest socket allocated"),
                                    [2, 1, 0])
            self.assertEqual(result, 0xFFFFFFFF)
            self.assertEqual(bridge._send(None, "ws2_32.send", None, [123, 0, 4, 0]), 0xFFFFFFFF)
            self.assertEqual(bridge._recv(None, "ws2_32.recv", None, [123, 0, 4, 0]), 0xFFFFFFFF)
            with self.assertRaisesRegex(NetworkDenied, "broker unavailable"):
                bridge.fetch("https://example.com/")
        self.assertTrue(any("broker unavailable" in event.get("error", "")
                            for event in bridge.events))
        self.assertEqual(sum(event.get("event") == "network_denied" for event in bridge.events), 3)
        bridge.close()

    def test_invalid_native_http_attempts_are_logged_without_broker_calls(self):
        expected_reason = {
            "InternetOpenUrlA": "invalid session handle",
            "HttpSendRequestA": "invalid request handle",
            "WinHttpSendRequest": "invalid request handle",
            "gethostbyname": "missing hostname",
        }
        for arch in ("x86", "x64"):
            for api, reason in expected_reason.items():
                with self.subTest(arch=arch, api=api), tempfile.TemporaryDirectory() as folder:
                    root = Path(folder)
                    name = f"invalid_{api.lower()}_{arch}.exe"
                    data = (FIXTURES / name).read_bytes()
                    result = run_native(data, inspect_pe(data, name), self.persona,
                                        root, [], 10, 100_000)
                    report = json.loads((root / result["engine_report"]).read_text())
                    self.assertFalse(result["errors"])
                    self.assertEqual([event["event"] for event in report["network_events"]],
                                     ["network_attempt", "network_denied"])
                    self.assertEqual(report["network_events"][-1]["reason"], reason)
                    exits = [event for entry in report["entry_points"]
                             for event in entry.get("events") or []
                             if str(event.get("api_name", "")).endswith("ExitProcess")]
                    self.assertEqual(exits[-1]["args"], ["0x0"])

    def test_native_wininet_session_reaches_broker_policy(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                name = f"wininet_session_{arch}.exe"
                data = (FIXTURES / name).read_bytes()
                result = run_native(data, inspect_pe(data, name), self.persona,
                                    root, [], 10, 100_000)
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                events = report["entry_points"][0]["events"]
                opens = [item for item in events if str(item.get("api_name", "")).endswith("InternetOpenA")]
                self.assertTrue(opens and int(opens[-1]["ret_val"], 16) > 0)
                self.assertEqual([item["event"] for item in report["network_events"]],
                                 ["network_attempt", "network_denied"])
                self.assertEqual(report["network_events"][-1]["reason"],
                                 "Network broker unavailable")
                exits = [item for item in events
                         if str(item.get("api_name", "")).endswith("ExitProcess")]
                self.assertEqual(exits[-1]["args"], ["0x0"])

    def test_native_wininet_session_fetches_through_broker(self):
        payload = b"harmless native WinINet response"
        observed = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                observed.append((self.path, self.headers.get("X-Test")))
                self.send_response(206)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *_args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_address[1]

        def test_resolver(host, _port):
            if host == "public.test":
                return "127.0.0.1"  # Test-only local transport.
            raise NetworkDenied(f"Private or host-local destination denied: {host}")

        try:
            with patch("emumee.networkipc.public_ipv4", side_effect=test_resolver):
                for arch, machine in (("x86", 0x14C), ("x64", 0x8664)):
                    with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                        root = Path(folder)
                        name = f"wininet_broker_{arch}.exe"
                        data = build_wininet_session_probe(
                            machine, url=f"http://public.test:{port}/marker",
                            headers="X-Test: emumee\r\n", read_response=True,
                            query_status=True)
                        with NetworkBroker(root):
                            result = run_native(data, inspect_pe(data, name),
                                                self.persona, root, [], 10, 100_000)
                        report = json.loads((root / result["engine_report"]).read_text())
                        broker = json.loads((root / "network-broker.json").read_text())
                        self.assertFalse(result["errors"])
                        self.assertEqual(observed[-1], ("/marker", "emumee"))
                        self.assertTrue(any(item["event"] == "http_response" and
                                            item["size"] == len(payload) and
                                            item["sha256"] == hashlib.sha256(payload).hexdigest()
                                            for item in broker))
                        self.assertTrue(any(item["event"] == "http_request" and
                                            item["headers"].get("X-Test") == "emumee"
                                            for item in broker))
                        self.assertEqual([item["event"] for item in report["network_events"]],
                                         ["network_attempt", "http_request", "http_response",
                                          "http_query_attempt", "http_query",
                                          "http_read_attempt", "http_read"])
                        self.assertEqual(report["network_events"][-1]["size"], 4)
                        exits = [item for entry in report["entry_points"]
                                 for item in entry.get("events") or []
                                 if str(item.get("api_name", "")).endswith("ExitProcess")]
                        self.assertEqual(int(exits[-1]["args"][0], 16),
                                         int.from_bytes(payload[:4], "little") ^ 4 ^ 206)
                        artifact = next(item for item in result["artifacts"]
                                        if item["source"] == "network_download")
                        self.assertEqual((root / "artifacts" / artifact["file"]).read_bytes(),
                                         payload)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_native_winhttp_post_reaches_broker_policy(self):
        for arch in ("x86", "x64"):
            with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                name = f"winhttp_post_{arch}.exe"
                data = (FIXTURES / name).read_bytes()
                result = run_native(data, inspect_pe(data, name), self.persona,
                                    root, [], 10, 100_000)
                report = json.loads((root / result["engine_report"]).read_text())
                self.assertFalse(result["errors"])
                self.assertEqual([item["event"] for item in report["network_events"]],
                                 ["network_attempt", "network_denied"])
                self.assertEqual(report["network_events"][-1]["reason"],
                                 "Network broker unavailable")
                exits = [item for entry in report["entry_points"]
                         for item in entry.get("events") or []
                         if str(item.get("api_name", "")).endswith("ExitProcess")]
                self.assertEqual(exits[-1]["args"], ["0x0"])

    def test_native_wininet_availability_reads_brokered_cursor(self):
        payload = b"harmless availability response"

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *_args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        def test_resolver(host, _port):
            if host == "public.test":
                return "127.0.0.1"
            raise NetworkDenied(f"Private or host-local destination denied: {host}")

        try:
            with patch("emumee.networkipc.public_ipv4", side_effect=test_resolver):
                for arch, machine in (("x86", 0x14C), ("x64", 0x8664)):
                    with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                        root = Path(folder)
                        name = f"wininet_available_{arch}.exe"
                        data = build_wininet_session_probe(
                            machine, url=f"http://public.test:{server.server_address[1]}/marker",
                            read_response=True, query_available=True)
                        with NetworkBroker(root):
                            result = run_native(data, inspect_pe(data, name),
                                                self.persona, root, [], 10, 100_000)
                        report = json.loads((root / result["engine_report"]).read_text())
                        self.assertFalse(result["errors"])
                        self.assertEqual([item["event"] for item in report["network_events"]],
                                         ["network_attempt", "http_request", "http_response",
                                          "http_read_attempt", "http_read",
                                          "http_available_attempt", "http_available"])
                        self.assertEqual(report["network_events"][-1]["size"], len(payload) - 4)
                        exits = [item for entry in report["entry_points"]
                                 for item in entry.get("events") or []
                                 if str(item.get("api_name", "")).endswith("ExitProcess")]
                        self.assertEqual(int(exits[-1]["args"][0], 16),
                                         int.from_bytes(payload[:4], "little") ^ 4 ^
                                         (len(payload) - 4))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_native_wininet_post_forwards_header_body_and_response(self):
        payload = b"harmless WinINet POST response"
        body = b"harmless WinINet body"
        observed = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                received = self.rfile.read(int(self.headers["Content-Length"]))
                observed.append((self.path, self.headers.get("X-Test"), received))
                self.send_response(207)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *_args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        def test_resolver(host, _port):
            if host == "public.test":
                return "127.0.0.1"
            raise NetworkDenied(f"Private or host-local destination denied: {host}")

        try:
            with patch("emumee.networkipc.public_ipv4", side_effect=test_resolver):
                for arch, machine in (("x86", 0x14C), ("x64", 0x8664)):
                    with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                        root = Path(folder)
                        name = f"wininet_post_{arch}.exe"
                        data = build_wininet_post_probe(
                            machine, host="public.test", port=server.server_address[1])
                        with NetworkBroker(root):
                            result = run_native(data, inspect_pe(data, name),
                                                self.persona, root, [], 10, 100_000)
                        report = json.loads((root / result["engine_report"]).read_text())
                        broker = json.loads((root / "network-broker.json").read_text())
                        self.assertFalse(result["errors"])
                        self.assertEqual(observed[-1], ("/marker", "emumee", body))
                        self.assertTrue(any(item["event"] == "http_request" and
                                            item["method"] == "POST" and
                                            item["body_size"] == len(body) and
                                            item["headers"].get("X-Test") == "emumee"
                                            for item in broker))
                        self.assertTrue(any(item["event"] == "http_response" and
                                            item["sha256"] == hashlib.sha256(payload).hexdigest()
                                            for item in broker))
                        self.assertEqual([item["event"] for item in report["network_events"]],
                                         ["http_connect_attempt", "http_connect",
                                          "http_open_request_attempt", "http_request_opened",
                                          "network_attempt", "http_request", "http_response",
                                          "http_query_attempt", "http_query",
                                          "http_read_attempt", "http_read",
                                          "http_available_attempt", "http_available"])
                        self.assertEqual(report["network_events"][-1]["size"], len(payload) - 4)
                        exits = [item for entry in report["entry_points"]
                                 for item in entry.get("events") or []
                                 if str(item.get("api_name", "")).endswith("ExitProcess")]
                        self.assertEqual(int(exits[-1]["args"][0], 16),
                                         int.from_bytes(payload[:4], "little") ^ 4 ^ 207 ^
                                         (len(payload) - 4) ^ 1)
                        artifact = next(item for item in result["artifacts"]
                                        if item["source"] == "network_download")
                        self.assertEqual((root / "artifacts" / artifact["file"]).read_bytes(),
                                         payload)
                        upload = next(item for item in result["artifacts"]
                                      if item["source"] == "network_request_body")
                        self.assertEqual((root / "artifacts" / upload["file"]).read_bytes(),
                                         body)
                        self.assertEqual(upload["sha256"], hashlib.sha256(body).hexdigest())
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_native_wininet_streamed_post_forwards_exact_body(self):
        payload = b"harmless streamed WinINet response"
        body = b"harmless WinINet body"
        observed = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                received = self.rfile.read(int(self.headers["Content-Length"]))
                observed.append((self.path, self.headers.get("X-Test"), received))
                self.send_response(202)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *_args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        def test_resolver(host, _port):
            if host == "public.test":
                return "127.0.0.1"
            raise NetworkDenied(f"Private or host-local destination denied: {host}")

        try:
            with patch("emumee.networkipc.public_ipv4", side_effect=test_resolver):
                for arch, machine in (("x86", 0x14C), ("x64", 0x8664)):
                    with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                        root = Path(folder)
                        name = f"wininet_stream_{arch}.exe"
                        data = build_wininet_stream_probe(machine, host="public.test",
                                                          port=server.server_address[1])
                        with NetworkBroker(root):
                            result = run_native(data, inspect_pe(data, name),
                                                self.persona, root, [], 10, 100_000)
                        report = json.loads((root / result["engine_report"]).read_text())
                        broker = json.loads((root / "network-broker.json").read_text())
                        self.assertFalse(result["errors"])
                        self.assertEqual(observed[-1], ("/marker", "emumee", body))
                        self.assertTrue(any(item["event"] == "http_request" and
                                            item["method"] == "POST" and
                                            item["body_size"] == len(body) and
                                            item["headers"].get("X-Test") == "emumee"
                                            for item in broker))
                        self.assertTrue(any(item["event"] == "http_response" and
                                            item["status"] == 202 and
                                            item["sha256"] == hashlib.sha256(payload).hexdigest()
                                            for item in broker))
                        self.assertEqual([item["event"] for item in report["network_events"]],
                                         ["http_connect_attempt", "http_connect",
                                          "http_open_request_attempt", "http_request_opened",
                                          "network_attempt", "http_request_staged",
                                          "http_write_attempt", "http_write",
                                          "http_end_attempt", "http_request", "http_response",
                                          "http_response_ready", "http_read_attempt",
                                          "http_read"])
                        self.assertEqual(report["network_events"][7]["accumulated"], len(body))
                        exits = [item for entry in report["entry_points"]
                                 for item in entry.get("events") or []
                                 if str(item.get("api_name", "")).endswith("ExitProcess")]
                        self.assertEqual(int(exits[-1]["args"][0], 16),
                                         int.from_bytes(payload[:4], "little") ^ 4 ^
                                         len(b"WinINet body") ^ 1 ^ 1)
                        artifact = next(item for item in result["artifacts"]
                                        if item["source"] == "network_download")
                        self.assertEqual((root / "artifacts" / artifact["file"]).read_bytes(),
                                         payload)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_native_wininet_linked_input_uses_only_head_buffer(self):
        payload = b"harmless linked WinINet response"
        observed = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                observed.append((body, self.headers.get("X-Test"),
                                 self.headers.get("X-Tail")))
                self.send_response(200)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *_args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        def test_resolver(host, _port):
            if host == "public.test":
                return "127.0.0.1"
            raise NetworkDenied(f"Private or host-local destination denied: {host}")

        try:
            with patch("emumee.networkipc.public_ipv4", side_effect=test_resolver):
                for arch, machine in (("x86", 0x14C), ("x64", 0x8664)):
                    with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                        root = Path(folder)
                        name = f"wininet_linked_{arch}.exe"
                        data = build_wininet_stream_probe(
                            machine, host="public.test",
                            port=server.server_address[1], linked=True)
                        with NetworkBroker(root):
                            result = run_native(data, inspect_pe(data, name),
                                                self.persona, root, [], 10, 100_000)
                        report = json.loads((root / result["engine_report"]).read_text())
                        self.assertFalse(result["errors"])
                        self.assertEqual(observed[-1],
                                         (b"harmless WinINet body", "emumee", None))
                        staged = next(item for item in report["network_events"]
                                      if item["event"] == "http_request_staged")
                        self.assertTrue(staged["linked_buffer_ignored"])
                        exits = [item for entry in report["entry_points"]
                                 for item in entry.get("events") or []
                                 if str(item.get("api_name", "")).endswith("ExitProcess")]
                        self.assertEqual(int(exits[-1]["args"][0], 16),
                                         int.from_bytes(payload[:4], "little") ^ 4 ^
                                         len(b"WinINet body") ^ 1 ^ 1)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_native_http_read_and_query_after_denied_request_fail_cleanly(self):
        for arch in ("x86", "x64"):
            for stack, variant, expected in (
                ("wininet", "read", ["network_attempt", "network_denied",
                                      "http_read_attempt", "network_denied"]),
                ("wininet", "query", ["network_attempt", "network_denied",
                                       "http_query_attempt", "network_denied",
                                       "http_read_attempt", "network_denied"]),
                ("wininet", "available", ["network_attempt", "network_denied",
                                           "http_read_attempt", "network_denied",
                                           "http_available_attempt", "network_denied"]),
                ("wininet", "post", ["http_connect_attempt", "http_connect",
                                      "http_open_request_attempt", "http_request_opened",
                                      "network_attempt", "network_denied",
                                      "http_query_attempt", "network_denied",
                                      "http_read_attempt", "network_denied",
                                      "http_available_attempt", "network_denied"]),
                ("wininet", "stream", ["http_connect_attempt", "http_connect",
                                        "http_open_request_attempt", "http_request_opened",
                                        "network_attempt", "network_denied",
                                        "http_write_attempt", "network_denied",
                                        "http_end_attempt", "network_denied",
                                        "http_read_attempt", "network_denied"]),
                ("winhttp", "read", ["network_attempt", "network_denied",
                                      "http_receive_attempt", "network_denied",
                                      "http_read_attempt", "network_denied"]),
                ("winhttp", "query", ["network_attempt", "network_denied",
                                       "http_receive_attempt", "network_denied",
                                       "http_query_attempt", "network_denied",
                                       "http_read_attempt", "network_denied"]),
                ("winhttp", "available", ["network_attempt", "network_denied",
                                           "http_receive_attempt", "network_denied",
                                           "http_query_attempt", "network_denied",
                                           "http_read_attempt", "network_denied",
                                           "http_available_attempt", "network_denied"]),
                ("winhttp", "stream", ["network_attempt", "network_denied",
                                        "http_write_attempt", "network_denied",
                                        "http_receive_attempt", "network_denied",
                                        "http_query_attempt", "network_denied",
                                        "http_read_attempt", "network_denied"]),
            ):
                with self.subTest(arch=arch, stack=stack, variant=variant), tempfile.TemporaryDirectory() as folder:
                    root = Path(folder)
                    name = f"{stack}_{variant}_{arch}.exe"
                    data = (FIXTURES / name).read_bytes()
                    result = run_native(data, inspect_pe(data, name), self.persona,
                                        root, [], 10, 100_000)
                    report = json.loads((root / result["engine_report"]).read_text())
                    self.assertFalse(result["errors"])
                    self.assertEqual([item["event"] for item in report["network_events"]],
                                     expected)
                    exits = [item for entry in report["entry_points"]
                             for item in entry.get("events") or []
                             if str(item.get("api_name", "")).endswith("ExitProcess")]
                    self.assertEqual(exits[-1]["args"], ["0x0"])

    def test_native_wininet_staging_rejects_invalid_handles(self):
        for arch in ("x86", "x64"):
            for stage in ("connect", "request"):
                with self.subTest(arch=arch, stage=stage), tempfile.TemporaryDirectory() as folder:
                    root = Path(folder)
                    name = f"wininet_bad_{stage}_{arch}.exe"
                    data = (FIXTURES / name).read_bytes()
                    with NetworkBroker(root):
                        result = run_native(data, inspect_pe(data, name),
                                            self.persona, root, [], 10, 100_000)
                    report = json.loads((root / result["engine_report"]).read_text())
                    broker = json.loads((root / "network-broker.json").read_text())
                    self.assertFalse(result["errors"])
                    expected = ["http_connect_attempt"]
                    expected += (["http_connect"] if stage == "request" else
                                 ["network_denied"])
                    expected += ["http_open_request_attempt", "network_denied",
                                 "network_attempt", "network_denied",
                                 "http_query_attempt", "network_denied",
                                 "http_read_attempt", "network_denied",
                                 "http_available_attempt", "network_denied"]
                    self.assertEqual([item["event"] for item in report["network_events"]],
                                     expected)
                    self.assertFalse(any(item.get("event") == "http_request"
                                         for item in broker))
                    exits = [item for entry in report["entry_points"]
                             for item in entry.get("events") or []
                             if str(item.get("api_name", "")).endswith("ExitProcess")]
                    self.assertEqual(exits[-1]["args"], ["0x0"])

    def test_native_winhttp_post_forwards_header_and_body(self):
        payload = b"harmless WinHTTP response"
        body = b"harmless WinHTTP body"
        observed = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                received = self.rfile.read(int(self.headers["Content-Length"]))
                observed.append((self.path, self.headers.get("X-Test"), received))
                self.send_response(201)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *_args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_address[1]

        def test_resolver(host, _port):
            if host == "public.test":
                return "127.0.0.1"  # Test-only local transport.
            raise NetworkDenied(f"Private or host-local destination denied: {host}")

        try:
            with patch("emumee.networkipc.public_ipv4", side_effect=test_resolver):
                for arch, machine in (("x86", 0x14C), ("x64", 0x8664)):
                    with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                        root = Path(folder)
                        name = f"winhttp_broker_{arch}.exe"
                        data = build_winhttp_post_probe(machine, host="public.test",
                                                        port=port, read_response=True,
                                                        query_status=True,
                                                        query_available=True)
                        with NetworkBroker(root):
                            result = run_native(data, inspect_pe(data, name),
                                                self.persona, root, [], 10, 100_000)
                        report = json.loads((root / result["engine_report"]).read_text())
                        broker = json.loads((root / "network-broker.json").read_text())
                        self.assertFalse(result["errors"])
                        self.assertEqual(observed[-1], ("/marker", "emumee", body))
                        self.assertTrue(any(item["event"] == "http_request" and
                                            item["method"] == "POST" and
                                            item["body_size"] == len(body) and
                                            item["headers"].get("X-Test") == "emumee"
                                            for item in broker))
                        self.assertTrue(any(item["event"] == "http_response" and
                                            item["sha256"] == hashlib.sha256(payload).hexdigest()
                                            for item in broker))
                        self.assertEqual([item["event"] for item in report["network_events"]],
                                         ["network_attempt", "http_request", "http_response",
                                          "http_receive_attempt", "http_response_ready",
                                          "http_query_attempt", "http_query",
                                          "http_read_attempt", "http_read",
                                          "http_available_attempt", "http_available"])
                        self.assertEqual(report["network_events"][1]["headers"],
                                         {"X-Test": "emumee"})
                        self.assertEqual(report["network_events"][-1]["size"], len(payload) - 4)
                        exits = [item for entry in report["entry_points"]
                                 for item in entry.get("events") or []
                                 if str(item.get("api_name", "")).endswith("ExitProcess")]
                        self.assertEqual(int(exits[-1]["args"][0], 16),
                                         int.from_bytes(payload[:4], "little") ^ 4 ^ 201 ^
                                         (len(payload) - 4))
                        upload = next(item for item in result["artifacts"]
                                      if item["source"] == "network_request_body")
                        self.assertEqual((root / "artifacts" / upload["file"]).read_bytes(),
                                         body)
                        self.assertEqual(upload["sha256"], hashlib.sha256(body).hexdigest())
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_native_winhttp_streamed_post_forwards_exact_chunks(self):
        payload = b"streamed WinHTTP response"
        body = b"harmless WinHTTP body"
        written_chunk = b"WinHTTP body"
        observed = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                received = self.rfile.read(int(self.headers["Content-Length"]))
                observed.append((self.path, self.headers.get("X-Test"), received))
                self.send_response(202)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *_args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_address[1]

        def test_resolver(host, _port):
            if host == "public.test":
                return "127.0.0.1"  # Test-only local transport.
            raise NetworkDenied(f"Private or host-local destination denied: {host}")

        try:
            with patch("emumee.networkipc.public_ipv4", side_effect=test_resolver):
                for arch, machine in (("x86", 0x14C), ("x64", 0x8664)):
                    with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                        root = Path(folder)
                        name = f"winhttp_stream_broker_{arch}.exe"
                        data = build_winhttp_post_probe(machine, host="public.test",
                                                        port=port, read_response=True,
                                                        query_status=True, streamed=True)
                        with NetworkBroker(root):
                            result = run_native(data, inspect_pe(data, name),
                                                self.persona, root, [], 10, 100_000)
                        report = json.loads((root / result["engine_report"]).read_text())
                        broker = json.loads((root / "network-broker.json").read_text())
                        self.assertFalse(result["errors"])
                        self.assertEqual(observed[-1], ("/marker", "emumee", body))
                        self.assertTrue(any(item["event"] == "http_request" and
                                            item["method"] == "POST" and
                                            item["body_size"] == len(body)
                                            for item in broker))
                        self.assertTrue(any(item["event"] == "http_response" and
                                            item["status"] == 202 and
                                            item["sha256"] == hashlib.sha256(payload).hexdigest()
                                            for item in broker))
                        self.assertEqual([item["event"] for item in report["network_events"]],
                                         ["network_attempt", "http_request_staged",
                                          "http_write_attempt", "http_write",
                                          "http_receive_attempt", "http_request", "http_response",
                                          "http_response_ready", "http_query_attempt", "http_query",
                                          "http_read_attempt", "http_read"])
                        exits = [item for entry in report["entry_points"]
                                 for item in entry.get("events") or []
                                 if str(item.get("api_name", "")).endswith("ExitProcess")]
                        self.assertEqual(int(exits[-1]["args"][0], 16),
                                         int.from_bytes(payload[:4], "little") ^ 4 ^ 202 ^
                                         len(written_chunk))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_native_winhttp_chunked_post_uses_broker_wire_encoding(self):
        payload = b"chunked WinHTTP response"
        body = b"harmless WinHTTP body"
        observed = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                chunks = []
                while True:
                    size = int(self.rfile.readline().strip().split(b";", 1)[0], 16)
                    if size == 0:
                        self.rfile.readline()
                        break
                    chunks.append(self.rfile.read(size))
                    assert self.rfile.read(2) == b"\r\n"
                observed.append((self.path, self.headers.get("Transfer-Encoding"),
                                 self.headers.get("Content-Length"), b"".join(chunks)))
                self.send_response(202)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *_args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_address[1]

        def test_resolver(host, _port):
            if host == "public.test":
                return "127.0.0.1"  # Test-only local transport.
            raise NetworkDenied(f"Private or host-local destination denied: {host}")

        try:
            with patch("emumee.networkipc.public_ipv4", side_effect=test_resolver):
                for arch, machine in (("x86", 0x14C), ("x64", 0x8664)):
                    with self.subTest(arch=arch), tempfile.TemporaryDirectory() as folder:
                        root = Path(folder)
                        name = f"winhttp_chunked_broker_{arch}.exe"
                        data = build_winhttp_post_probe(machine, host="public.test",
                                                        port=port, read_response=True,
                                                        query_status=True, streamed=True,
                                                        chunked=True)
                        with NetworkBroker(root):
                            result = run_native(data, inspect_pe(data, name),
                                                self.persona, root, [], 10, 100_000)
                        report = json.loads((root / result["engine_report"]).read_text())
                        broker = json.loads((root / "network-broker.json").read_text())
                        self.assertFalse(result["errors"])
                        self.assertEqual(observed[-1], ("/marker", "chunked", None, body))
                        self.assertTrue(any(item["event"] == "http_request" and
                                            item["chunked"] and item["body_size"] == len(body)
                                            for item in broker), (broker, report["network_events"]))
                        self.assertEqual([item["event"] for item in report["network_events"]],
                                         ["network_attempt", "http_request_staged",
                                          "http_write_attempt", "http_write",
                                          "http_write_attempt", "http_write",
                                          "http_receive_attempt", "http_request", "http_response",
                                          "http_response_ready", "http_query_attempt", "http_query",
                                          "http_read_attempt", "http_read"])
                        self.assertTrue(report["network_events"][5]["chunk_terminated"])
                        exits = [item for entry in report["entry_points"]
                                 for item in entry.get("events") or []
                                 if str(item.get("api_name", "")).endswith("ExitProcess")]
                        self.assertEqual(int(exits[-1]["args"][0], 16),
                                         int.from_bytes(payload[:4], "little") ^ 4 ^ 202 ^
                                         len(body))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_http_bridge_rejects_wrong_handle_type_before_broker(self):
        bridge = NetworkBridge(ArtifactCatalog(self.root / "artifacts"))
        manager = SimpleNamespace(get_wininet_object=lambda _handle:
                                  SimpleNamespace(new_session=lambda *_args: None))
        emu = SimpleNamespace(api=SimpleNamespace(load_api_handler=lambda _module:
                                                  SimpleNamespace(netman=manager)))
        bridge.rpc = SimpleNamespace(call=lambda *_args, **_fields:
                                     self.fail("broker called"), close=lambda: None)
        for api, params in (("wininet.HttpSendRequestA", [1, 0, 0, 0, 0]),
                            ("winhttp.WinHttpSendRequest", [1, 0, 0, 0, 0, 0, 0])):
            with self.subTest(api=api):
                self.assertEqual(bridge._http_send(
                    emu, api, lambda _params: self.fail("API model called"), params), 0)
                self.assertEqual(bridge.events[-1]["reason"], "invalid request handle type")
        bridge.close()

    def test_http_response_reads_are_bounded_and_sequential(self):
        bridge = NetworkBridge(ArtifactCatalog(self.root / "artifacts"))
        request = SimpleNamespace(response=BytesIO(b"abcde"))
        manager = SimpleNamespace(get_wininet_object=lambda handle:
                                  request if handle == 7 else None)
        written = {}
        emu = SimpleNamespace(api=SimpleNamespace(load_api_handler=lambda _module:
                                                  SimpleNamespace(netman=manager)),
                              mem_write=lambda address, data: written.__setitem__(address, data))
        self.assertEqual(bridge._http_receive(emu, "winhttp.WinHttpReceiveResponse",
                                              lambda _params: self.fail("API model called"),
                                              [7, 0]), 0)
        bridge.http_fetched.add(7)
        self.assertEqual(bridge._http_read(emu, "winhttp.WinHttpReadData", None,
                                           [7, 100, 3, 200]), 0)
        self.assertEqual(written[200], b"\0" * 4)
        self.assertEqual(bridge._http_receive(emu, "winhttp.WinHttpReceiveResponse",
                                              lambda _params: 1, [7, 0]), 1)
        self.assertEqual(bridge._http_read(emu, "winhttp.WinHttpReadData", None,
                                           [7, 100, 3, 200]), 1)
        self.assertEqual((written[100], written[200]), (b"abc", (3).to_bytes(4, "little")))
        self.assertEqual(bridge._http_read(emu, "winhttp.WinHttpReadData", None,
                                           [7, 100, 3, 200]), 1)
        self.assertEqual((written[100], written[200]), (b"de", (2).to_bytes(4, "little")))
        self.assertEqual(bridge._http_read(emu, "winhttp.WinHttpReadData", None,
                                           [7, 100, 3, 200]), 1)
        self.assertEqual(written[200], b"\0" * 4)
        self.assertEqual(bridge._http_read(emu, "wininet.InternetReadFile", None,
                                           [8, 100, 3, 200]), 0)
        self.assertEqual(bridge._http_read(emu, "winhttp.WinHttpReadData", None,
                                           [7, 100, MAX_TRANSFER + 1, 200]), 0)
        self.assertEqual(bridge.events[-1]["reason"], "invalid or oversized read buffer")
        request.response = None
        request.get_response = lambda: self.fail("host-backed response loaded")
        self.assertEqual(bridge._http_read(emu, "wininet.InternetReadFile", None,
                                           [7, 100, 3, 200]), 0)
        self.assertEqual(bridge.events[-1]["reason"],
                         "response not ready or invalid request handle")
        request.response = BytesIO(b"xy")
        def bad_write(address, data):
            if address in (101, 201):
                raise SpeakeasyError("invalid guest pointer")
            written[address] = data
        bad_emu = SimpleNamespace(api=emu.api, mem_write=bad_write)
        self.assertEqual(bridge._http_read(bad_emu, "wininet.InternetReadFile", None,
                                           [7, 100, 2, 201]), 0)
        self.assertEqual(bridge.events[-1]["reason"], "invalid byte-count pointer")
        self.assertEqual(bridge._http_read(bad_emu, "wininet.InternetReadFile", None,
                                           [7, 101, 2, 200]), 0)
        self.assertEqual(bridge.events[-1]["reason"], "invalid read buffer")
        self.assertEqual(request.response.tell(), 0)
        bridge.close()

    def test_http_available_tracks_brokered_response_cursor(self):
        bridge = NetworkBridge(ArtifactCatalog(self.root / "artifacts"))
        request = SimpleNamespace(get_handle=lambda: 7, response=BytesIO(b"abcde"),
                                  get_response=lambda: self.fail("host response loaded"))
        manager = SimpleNamespace(get_wininet_object=lambda handle:
                                  request if handle == 7 else None)
        written = {}
        emu = SimpleNamespace(api=SimpleNamespace(load_api_handler=lambda _module:
                                                  SimpleNamespace(netman=manager)),
                              mem_write=lambda address, data: written.__setitem__(address, data))
        self.assertEqual(bridge._http_available(emu, "winhttp.WinHttpQueryDataAvailable",
                                                None, [7, 200]), 0)
        bridge.http_ready.add(7)
        self.assertEqual(bridge._http_available(emu, "wininet.InternetQueryDataAvailable",
                                                None, [7, 200, 0, 0]), 1)
        self.assertEqual(written[200], (5).to_bytes(4, "little"))
        self.assertEqual(bridge._http_read(emu, "wininet.InternetReadFile", None,
                                           [7, 100, 3, 201]), 1)
        self.assertEqual(bridge._http_available(emu, "winhttp.WinHttpQueryDataAvailable",
                                                None, [7, 200]), 1)
        self.assertEqual(written[200], (2).to_bytes(4, "little"))
        self.assertEqual(bridge._http_read(emu, "winhttp.WinHttpReadData", None,
                                           [7, 100, 2, 201]), 1)
        self.assertEqual(bridge._http_available(emu, "wininet.InternetQueryDataAvailable",
                                                None, [7, 200, 0, 0]), 1)
        self.assertEqual(written[200], b"\0" * 4)
        self.assertEqual(bridge._http_available(emu, "wininet.InternetQueryDataAvailable",
                                                None, [7, 0, 0, 0]), 1)
        self.assertEqual(bridge._http_available(emu, "wininet.InternetQueryDataAvailable",
                                                None, [7, 200, 1, 0]), 0)
        self.assertEqual(bridge.events[-1]["reason"],
                         "reserved availability arguments must be zero")
        def invalid_write(_address, _data):
            raise SpeakeasyError("bad pointer")

        invalid_pointer_emu = SimpleNamespace(api=emu.api, mem_write=invalid_write)
        self.assertEqual(bridge._http_available(invalid_pointer_emu,
                                                "wininet.InternetQueryDataAvailable",
                                                None, [7, 999, 0, 0]), 0)
        self.assertEqual(bridge.events[-1]["reason"],
                         "invalid availability output pointer")
        bridge.http_closed.add(7)
        self.assertEqual(bridge._http_available(emu, "winhttp.WinHttpQueryDataAvailable",
                                                None, [7, 200]), 0)
        self.assertEqual(bridge.events[-1]["reason"],
                         "response not ready or invalid request handle")
        bridge.close()

    def test_winhttp_streamed_body_is_bounded_and_sent_on_receive(self):
        bridge = NetworkBridge(ArtifactCatalog(self.root / "artifacts"))
        bridge.rpc = SimpleNamespace(close=lambda: None)
        request = SimpleNamespace(get_handle=lambda: 7,
                                  get_server=lambda: "public.test", get_port=lambda: 80,
                                  is_secure=lambda: False,
                                  objname=SimpleNamespace(path="/upload", query=""),
                                  verb="POST", response=None)
        manager = SimpleNamespace(get_wininet_object=lambda handle:
                                  request if handle == 7 else None)
        memory = {100: b"AB", 101: b"CD", 102: b"XYZ"}
        written = {}
        emu = SimpleNamespace(api=SimpleNamespace(load_api_handler=lambda _module:
                                                  SimpleNamespace(netman=manager)),
                              mem_read=lambda address, size: memory[address][:size],
                              mem_write=lambda address, data: written.__setitem__(address, data))
        self.assertEqual(bridge._http_write(emu, "winhttp.WinHttpWriteData", None,
                                            [7, 101, 2, 200]), 0)
        with patch("emumee.network.MAX_PENDING_HTTP", 0):
            self.assertEqual(bridge._http_send(emu, "winhttp.WinHttpSendRequest",
                                               lambda _params: self.fail("API model called"),
                                               [7, 0, 0, 100, 2, 4, 0]), 0)
        self.assertEqual(bridge.events[-1]["reason"],
                         "streamed request staging quota exceeded")
        self.assertEqual(bridge._http_send(emu, "winhttp.WinHttpSendRequest",
                                           lambda _params: self.fail("API model called"),
                                           [7, 0, 0, 100, 2, 4, 0]), 1)
        self.assertEqual(bridge.pending_winhttp[7]["body"], b"AB")
        self.assertEqual(bridge._http_receive(emu, "winhttp.WinHttpReceiveResponse",
                                              lambda _params: self.fail("API model called"),
                                              [7, 0]), 0)
        self.assertEqual(bridge._http_write(emu, "winhttp.WinHttpWriteData", None,
                                            [7, 102, 3, 200]), 0)
        self.assertEqual(written[200], b"\0" * 4)
        self.assertEqual(bridge._http_write(emu, "winhttp.WinHttpWriteData", None,
                                            [7, 101, 2, 200]), 1)
        self.assertEqual(written[200], (2).to_bytes(4, "little"))
        metadata = {"status": 201, "reason": "Created", "version": "HTTP/1.1",
                    "headers": []}
        with patch.object(bridge, "fetch", return_value=(b"OK", metadata)) as fetch:
            self.assertEqual(bridge._http_receive(emu, "winhttp.WinHttpReceiveResponse",
                                                  lambda _params: 1, [7, 0]), 1)
        fetch.assert_called_once_with("http://public.test:80/upload", method="POST",
                                      body=b"ABCD", headers={}, with_metadata=True)
        self.assertNotIn(7, bridge.pending_winhttp)
        self.assertIn(7, bridge.http_ready)
        self.assertEqual(bridge._http_read(emu, "winhttp.WinHttpReadData", None,
                                           [7, 300, 2, 200]), 1)
        self.assertEqual((written[300], written[200]), (b"OK", (2).to_bytes(4, "little")))
        self.assertEqual(bridge._http_write(emu, "winhttp.WinHttpWriteData", None,
                                            [7, 101, 2, 200]), 0)
        bridge.close()

    def test_winhttp_chunked_requires_header_and_terminal_write(self):
        bridge = NetworkBridge(ArtifactCatalog(self.root / "artifacts"))
        bridge.rpc = SimpleNamespace(close=lambda: None)
        request = SimpleNamespace(get_handle=lambda: 7,
                                  get_server=lambda: "public.test", get_port=lambda: 80,
                                  is_secure=lambda: False,
                                  objname=SimpleNamespace(path="/upload", query=""),
                                  verb="POST", response=None)
        manager = SimpleNamespace(get_wininet_object=lambda handle:
                                  request if handle == 7 else None)
        header = "Transfer-Encoding: chunked\r\n".encode("utf-16le")
        memory = {100: b"AB", 300: header}
        written = {}
        emu = SimpleNamespace(api=SimpleNamespace(load_api_handler=lambda _module:
                                                  SimpleNamespace(netman=manager)),
                              mem_read=lambda address, size: memory[address][:size],
                              mem_write=lambda address, data: written.__setitem__(address, data))
        send = lambda header_ptr, optional_ptr, optional_len: bridge._http_send(
            emu, "winhttp.WinHttpSendRequest",
            lambda _params: self.fail("API model called"),
            [7, header_ptr, len(header) // 2 if header_ptr else 0,
             optional_ptr, optional_len, 0xFFFFFFFF, 0])
        self.assertEqual(send(0, 0, 0), 0)
        self.assertEqual(send(300, 100, 0), 0)
        self.assertEqual(send(300, 100, 1), 0)
        self.assertEqual(send(300, 0, 0), 1)
        self.assertTrue(bridge.pending_winhttp[7]["chunked"])
        self.assertEqual(bridge._http_receive(emu, "winhttp.WinHttpReceiveResponse",
                                              lambda _params: self.fail("API model called"),
                                              [7, 0]), 0)
        self.assertEqual(bridge._http_write(emu, "winhttp.WinHttpWriteData", None,
                                            [7, 100, 2, 200]), 1)
        self.assertEqual(written[200], (2).to_bytes(4, "little"))
        self.assertEqual(bridge._http_receive(emu, "winhttp.WinHttpReceiveResponse",
                                              lambda _params: self.fail("API model called"),
                                              [7, 0]), 0)
        self.assertEqual(bridge._http_write(emu, "winhttp.WinHttpWriteData", None,
                                            [7, 0, 0, 200]), 1)
        self.assertEqual(written[200], b"\0" * 4)
        self.assertEqual(bridge._http_write(emu, "winhttp.WinHttpWriteData", None,
                                            [7, 100, 2, 200]), 0)
        metadata = {"status": 200, "reason": "OK", "version": "HTTP/1.1",
                    "headers": []}
        with patch.object(bridge, "fetch", return_value=(b"OK", metadata)) as fetch:
            self.assertEqual(bridge._http_receive(emu, "winhttp.WinHttpReceiveResponse",
                                                  lambda _params: 1, [7, 0]), 1)
        fetch.assert_called_once_with("http://public.test:80/upload", method="POST",
                                      body=b"AB", headers={"Transfer-Encoding": "chunked"},
                                      with_metadata=True, chunked=True)
        bridge.close()

    def test_http_request_body_artifact_is_bounded_and_survives_broker_denial(self):
        catalog = ArtifactCatalog(self.root / "artifacts")
        bridge = NetworkBridge(catalog)

        def deny(_operation, **_fields):
            raise NetworkDenied("test broker denial")

        bridge.rpc = SimpleNamespace(call=deny, close=lambda: None)
        url = "http://public.test/upload"
        for _ in range(2):
            with self.assertRaisesRegex(NetworkDenied, "test broker denial"):
                bridge.fetch(url, method="POST", body=b"ABC")
        self.assertEqual(len(catalog.items), 1)
        item = catalog.items[0]
        self.assertEqual((item["source"], item["guest_path"], item["size"], item["sha256"]),
                         ("network_request_body", url, 3,
                          hashlib.sha256(b"ABC").hexdigest()))
        self.assertEqual((self.root / "artifacts" / item["file"]).read_bytes(), b"ABC")
        with patch("emumee.network.MAX_REQUEST_BODY_ARTIFACT_BYTES", 3):
            with self.assertRaisesRegex(NetworkDenied, "test broker denial"):
                bridge.fetch(url, method="POST", body=b"DEF")
        self.assertEqual(len(catalog.items), 1)
        self.assertTrue(any(event.get("event") == "http_request_body_artifact_skipped"
                            and event.get("reason") == "per-run extraction quota exceeded"
                            for event in bridge.events))
        bridge.close()

    def test_broker_rejects_inconsistent_transfer_encoding_before_dns(self):
        with NetworkBroker(self.root) as broker:
            for headers, chunked in (({"Transfer-Encoding": "gzip"}, True),
                                     ({"Transfer-Encoding": "chunked",
                                       "Content-Length": "2"}, True),
                                     ({"Transfer-Encoding": "chunked"}, False)):
                with self.subTest(headers=headers, chunked=chunked), patch(
                        "emumee.networkipc.public_ipv4",
                        side_effect=lambda *_args: self.fail("DNS called")):
                    with self.assertRaisesRegex(NetworkDenied,
                                                "Invalid HTTP transfer encoding"):
                        broker._fetch("http://public.test/upload", "POST", b"AB",
                                      headers, chunked=chunked)

    def test_broker_chunked_redirect_303_clears_transfer_header(self):
        observed = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                while True:
                    size = int(self.rfile.readline().strip(), 16)
                    if size == 0:
                        self.rfile.readline()
                        break
                    self.rfile.read(size + 2)
                observed.append(("POST", self.headers.get("Transfer-Encoding")))
                self.send_response(303)
                self.send_header("Location", "/after")
                self.send_header("Content-Length", "0")
                self.end_headers()

            def do_GET(self):
                observed.append(("GET", self.headers.get("Transfer-Encoding")))
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"OK")

            def log_message(self, *_args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_address[1]
        try:
            with patch("emumee.networkipc.public_ipv4", return_value="127.0.0.1"):
                with NetworkBroker(self.root) as broker:
                    body, metadata = broker._fetch(
                        f"http://public.test:{port}/start", "POST", b"AB",
                        {"Transfer-Encoding": "chunked"}, chunked=True)
            self.assertEqual(body, b"OK")
            self.assertEqual(metadata["status"], 200)
            self.assertEqual(observed, [("POST", "chunked"), ("GET", None)])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_wininet_streamed_body_is_bounded_and_sent_on_end(self):
        bridge = NetworkBridge(ArtifactCatalog(self.root / "artifacts"))
        bridge.rpc = SimpleNamespace(close=lambda: None)
        request = SimpleNamespace(get_handle=lambda: 7,
                                  get_server=lambda: "public.test", get_port=lambda: 80,
                                  is_secure=lambda: False,
                                  objname=SimpleNamespace(path="/upload", query=""),
                                  verb="POST", response=None)
        manager = SimpleNamespace(get_wininet_object=lambda handle:
                                  request if handle == 7 else None)
        headers = b"X-Test: emumee\r\n"
        buffers = struct.pack("<10I", 40, 0, 300, len(headers), 0, 400, 2, 4, 0, 0)
        memory = {100: buffers, 300: headers, 400: b"AB", 401: b"CD", 402: b"XYZ"}
        written = {}
        emu = SimpleNamespace(api=SimpleNamespace(load_api_handler=lambda _module:
                                                  SimpleNamespace(netman=manager)),
                              get_ptr_size=lambda: 4,
                              mem_read=lambda address, size: memory[address][:size],
                              mem_write=lambda address, data: written.__setitem__(address, data))
        blocked = lambda _params: self.fail("unsupported API model called")
        self.assertEqual(bridge._wininet_send_ex(
            emu, "wininet.HttpSendRequestExA", blocked, [0, 100, 0, 0, 0]), 0)
        memory[100] = struct.pack("<I", 39) + buffers[4:]
        self.assertEqual(bridge._wininet_send_ex(
            emu, "wininet.HttpSendRequestExA", blocked, [7, 100, 0, 0, 0]), 0)
        memory[100] = buffers[:4] + (0xDEADBEEF).to_bytes(4, "little") + buffers[8:]
        with patch("emumee.network.MAX_PENDING_HTTP", 0):
            self.assertEqual(bridge._wininet_send_ex(
                emu, "wininet.HttpSendRequestExA", blocked, [7, 100, 0, 0, 0]), 0)
        self.assertEqual(bridge._wininet_send_ex(
            emu, "wininet.HttpSendRequestExA", blocked, [7, 100, 0, 0, 0]), 1)
        self.assertTrue(bridge.events[-1]["linked_buffer_ignored"])
        self.assertEqual(bridge.pending_wininet[7]["body"], b"AB")
        with patch.object(bridge, "fetch", side_effect=lambda *_args, **_kwargs:
                          self.fail("premature broker request")):
            self.assertEqual(bridge._wininet_end(
                emu, "wininet.HttpEndRequestA", blocked, [7, 0, 0, 0]), 0)
        self.assertEqual(bridge._http_write(
            emu, "wininet.InternetWriteFile", blocked, [7, 402, 3, 200]), 0)
        self.assertEqual(written[200], b"\0" * 4)
        self.assertEqual(bridge._http_write(
            emu, "wininet.InternetWriteFile", blocked, [7, 401, 2, 200]), 1)
        self.assertEqual(written[200], (2).to_bytes(4, "little"))
        self.assertEqual(bridge._wininet_end(
            emu, "wininet.HttpEndRequestA", blocked, [7, 1, 0, 0]), 0)
        metadata = {"status": 201, "reason": "Created", "version": "HTTP/1.1",
                    "headers": []}
        with patch.object(bridge, "fetch", return_value=(b"OK", metadata)) as fetch:
            self.assertEqual(bridge._wininet_end(
                emu, "wininet.HttpEndRequestA", blocked, [7, 0, 0, 0]), 1)
        fetch.assert_called_once_with("http://public.test:80/upload", method="POST",
                                      body=b"ABCD", headers={"X-Test": "emumee"},
                                      with_metadata=True)
        self.assertNotIn(7, bridge.pending_wininet)
        self.assertIn(7, bridge.http_ready)
        self.assertEqual(bridge._http_read(emu, "wininet.InternetReadFile", None,
                                           [7, 500, 2, 501]), 1)
        self.assertEqual((written[500], written[501]),
                         (b"OK", (2).to_bytes(4, "little")))
        self.assertEqual(bridge._wininet_send_ex(
            emu, "wininet.HttpSendRequestExA", blocked, [7, 100, 0, 0, 0]), 1)
        self.assertEqual(bridge._http_close(
            emu, "wininet.InternetCloseHandle", lambda _params: 1, [7]), 1)
        self.assertNotIn(7, bridge.pending_wininet)
        self.assertEqual(bridge._wininet_end(
            emu, "wininet.HttpEndRequestA", blocked, [7, 0, 0, 0]), 0)
        bridge.close()

    def test_http_response_queries_use_broker_metadata_and_buffer_lengths(self):
        bridge = NetworkBridge(ArtifactCatalog(self.root / "artifacts"))
        bridge.http_ready.add(7)
        bridge.http_metadata[7] = {
            "status": 206, "reason": "Partial Content", "version": "HTTP/1.1",
            "headers": [["Content-Type", "application/octet-stream"],
                        ["Content-Length", "5"],
                        ["X-Run", "one"], ["X-Run", "two"]],
        }
        memory = {200: (4).to_bytes(4, "little"), 400: (0).to_bytes(4, "little")}
        last_errors = []
        request = SimpleNamespace(get_handle=lambda: 7)
        manager = SimpleNamespace(get_wininet_object=lambda handle:
                                  request if handle == 7 else None)
        emu = SimpleNamespace(
            api=SimpleNamespace(load_api_handler=lambda _module:
                                SimpleNamespace(netman=manager)),
            mem_read=lambda address, size: memory[address][:size],
            mem_write=lambda address, data: memory.__setitem__(address, data),
            read_mem_string=lambda address, _width, _limit: "X-Run" if address == 300 else "",
            set_last_error=last_errors.append,
        )
        self.assertEqual(bridge._http_query(emu, "wininet.HttpQueryInfoA", None,
                                             [7, 0x20000013, 100, 200, 0]), 1)
        self.assertEqual(memory[100], (206).to_bytes(4, "little"))
        self.assertEqual(memory[200], (4).to_bytes(4, "little"))
        memory[200] = (0).to_bytes(4, "little")
        self.assertEqual(bridge._http_query(emu, "winhttp.WinHttpQueryHeaders", None,
                                             [7, 1, 0, 0, 200, 0]), 0)
        required = len("application/octet-stream".encode("utf-16le")) + 2
        self.assertEqual(int.from_bytes(memory[200], "little"), required)
        self.assertEqual(last_errors[-1], 122)
        self.assertEqual(bridge._http_query(emu, "winhttp.WinHttpQueryHeaders", None,
                                             [7, 1, 0, 100, 200, 0]), 1)
        self.assertEqual(memory[100], "application/octet-stream".encode("utf-16le") + b"\0\0")
        self.assertEqual(int.from_bytes(memory[200], "little"), required - 2)
        memory[200] = (4).to_bytes(4, "little")
        self.assertEqual(bridge._http_query(emu, "winhttp.WinHttpQueryHeaders", None,
                                             [7, 0x20000005, 0, 100, 200, 0]), 1)
        self.assertEqual(memory[100], (5).to_bytes(4, "little"))
        memory[200] = (512).to_bytes(4, "little")
        self.assertEqual(bridge._http_query(emu, "winhttp.WinHttpQueryHeaders", None,
                                             [7, 22, 0, 100, 200, 0]), 1)
        self.assertTrue(memory[100].startswith(
            "HTTP/1.1 206 Partial Content\r\n".encode("utf-16le")))
        for expected, next_index in (("one", 1), ("two", 2)):
            memory[200] = (16).to_bytes(4, "little")
            self.assertEqual(bridge._http_query(emu, "winhttp.WinHttpQueryHeaders", None,
                                                 [7, 65535, 300, 100, 200, 400]), 1)
            self.assertEqual(memory[100], expected.encode("utf-16le") + b"\0\0")
            self.assertEqual(int.from_bytes(memory[400], "little"), next_index)
        memory[200] = (16).to_bytes(4, "little")
        self.assertEqual(bridge._http_query(emu, "winhttp.WinHttpQueryHeaders", None,
                                             [7, 65535, 300, 100, 200, 400]), 0)
        self.assertEqual(last_errors[-1], 12150)
        self.assertEqual(bridge._http_query(emu, "wininet.HttpQueryInfoA", None,
                                             [8, 19, 100, 200, 0]), 0)
        self.assertEqual(bridge.events[-1]["reason"],
                         "response not ready or invalid query pointer")
        bridge.close()

    def test_http_broker_metadata_is_validated_before_guest_use(self):
        bridge = NetworkBridge(ArtifactCatalog(self.root / "artifacts"))
        good = {"body": "", "status": 200, "reason": "OK", "version": "HTTP/1.1",
                "headers": [["Content-Type", "text/plain"]]}
        malformed = [
            {**good, "status": "200"},
            {**good, "version": []},
            {**good, "headers": [["X-Test", "value\r\nInjected: yes"]]},
            {**good, "headers": [["X-Test", "x" * 16_385]]},
            {**good, "body": "a" * (4 * ((MAX_TRANSFER + 2) // 3) + 1)},
        ]
        for reply in malformed:
            with self.subTest(reply=list(reply)):
                bridge.rpc = SimpleNamespace(call=lambda *_args, **_fields: reply,
                                             close=lambda: None)
                with self.assertRaises(NetworkDenied):
                    bridge.fetch("http://public.test/", with_metadata=True)
        self.assertFalse(bridge.catalog.items)
        bridge.close()

    def test_closing_http_session_invalidates_child_response(self):
        bridge = NetworkBridge(ArtifactCatalog(self.root / "artifacts"))
        instance = SimpleNamespace(get_handle=lambda: 3)
        session = SimpleNamespace(get_handle=lambda: 5, instance=instance)
        request = SimpleNamespace(get_handle=lambda: 7, session=session,
                                  response=BytesIO(b"data"),
                                  get_server=lambda: "public.test", get_port=lambda: 80,
                                  is_secure=lambda: False,
                                  objname=SimpleNamespace(path="/", query=""), verb="GET")
        objects = {3: instance, 5: session, 7: request}
        manager = SimpleNamespace(get_wininet_object=objects.get)
        emu = SimpleNamespace(api=SimpleNamespace(load_api_handler=lambda _module:
                                                  SimpleNamespace(netman=manager)),
                              mem_write=lambda *_args: None)
        bridge.http_fetched.add(7)
        bridge.http_ready.add(7)
        bridge.http_metadata[7] = {"status": 200, "reason": "OK",
                                   "version": "HTTP/1.1", "headers": []}
        self.assertEqual(bridge._http_close(emu, "wininet.InternetCloseHandle",
                                             lambda _params: 1, [5]), 1)
        self.assertNotIn(7, bridge.http_fetched)
        self.assertNotIn(7, bridge.http_ready)
        self.assertNotIn(7, bridge.http_metadata)
        self.assertEqual(bridge._http_read(emu, "wininet.InternetReadFile", None,
                                           [7, 100, 4, 200]), 0)
        self.assertEqual(bridge._http_query(emu, "wininet.HttpQueryInfoA", None,
                                            [7, 19, 100, 200, 0]), 0)
        self.assertEqual(bridge._http_send(emu, "wininet.HttpSendRequestA",
                                            lambda _params: self.fail("API model called"),
                                            [7, 0, 0, 0, 0]), 0)
        self.assertEqual(bridge._http_close(emu, "wininet.InternetCloseHandle",
                                             lambda _params: self.fail("API model called"),
                                             [7]), 0)
        bridge.close()

    def test_http_bridge_rejects_oversized_body_and_url_before_broker(self):
        bridge = NetworkBridge(ArtifactCatalog(self.root / "artifacts"))
        request = SimpleNamespace(get_server=lambda: "example.com", get_port=lambda: 80,
                                  is_secure=lambda: False,
                                  objname=SimpleNamespace(path="/", query=""), verb="POST")
        manager = SimpleNamespace(get_wininet_object=lambda _handle: request)
        emu = SimpleNamespace(api=SimpleNamespace(load_api_handler=lambda _module:
                                                  SimpleNamespace(netman=manager)),
                              mem_read=lambda *_args: self.fail("oversized body read"),
                              read_mem_string=lambda *_args: "x" * 2_049)
        self.assertEqual(bridge._http_send(emu, "wininet.HttpSendRequestA",
                                           lambda _params: self.fail("API model called"),
                                           [1, 0, 0, 1, MAX_TRANSFER + 1]), 0)
        self.assertEqual(bridge.events[-1]["reason"], "invalid or oversized optional data")
        self.assertEqual(bridge._internet_open_url(
            emu, "wininet.InternetOpenUrlA", lambda _params: self.fail("API model called"),
            [1, 1, 0, 0, 0, 0]), 0)
        self.assertEqual(bridge.events[-1]["reason"], "URL exceeds limit")
        self.assertEqual(bridge._http_send(emu, "wininet.HttpSendRequestA",
                                           lambda _params: self.fail("API model called"),
                                           [1, 0, 0, 0, 0]), 0)
        self.assertEqual(bridge.events[-1]["reason"], "Network broker unavailable")
        short_url = SimpleNamespace(
            read_mem_string=lambda *_args: "https://example.com/",
            api=SimpleNamespace(load_api_handler=lambda _module: SimpleNamespace(
                netman=SimpleNamespace(get_wininet_object=lambda _handle:
                    SimpleNamespace(new_session=lambda *_args: None)))))
        self.assertEqual(bridge._internet_open_url(
            short_url, "wininet.InternetOpenUrlA",
            lambda _params: self.fail("API model called"), [1, 1, 0, 0, 0, 0]), 0)
        self.assertEqual(bridge.events[-1]["reason"], "Network broker unavailable")
        self.assertEqual(sum(item["event"] == "network_attempt" for item in bridge.events), 4)
        bridge.rpc = SimpleNamespace(call=lambda *_args, **_fields:
                                     self.fail("broker called"), close=lambda: None)
        self.assertEqual(bridge._internet_open_url(
            short_url, "wininet.InternetOpenUrlA", lambda _params: 0,
            [1, 1, 0, 0, 0, 0]), 0)
        self.assertEqual(bridge.events[-1]["reason"], "invalid session handle or URL")
        self.assertEqual(bridge._http_send(emu, "wininet.HttpSendRequestA",
                                           lambda _params: 0, [1, 0, 0, 0, 0]), 0)
        self.assertEqual(bridge.events[-1]["reason"], "request rejected by API model")
        self.assertEqual(bridge._http_send(emu, "winhttp.WinHttpSendRequest",
                                           lambda _params: self.fail("API model called"),
                                           [1, 0, 0, 0, 0, 1, 0]), 1)
        self.assertEqual(bridge.events[-1]["event"], "http_request_staged")
        self.assertEqual(bridge._http_receive(emu, "winhttp.WinHttpReceiveResponse",
                                              lambda _params: self.fail("API model called"),
                                              [1, 0]), 0)
        self.assertEqual(bridge.events[-1]["reason"],
                         "streamed request body incomplete or invalid")
        bridge.close()

    def test_wininet_staging_bounds_guest_fields_and_normalizes_default_port(self):
        bridge = NetworkBridge(ArtifactCatalog(self.root / "artifacts"))
        instance = SimpleNamespace(get_handle=lambda: 3,
                                   new_session=lambda *_args: self.fail("model bypassed"))
        session = SimpleNamespace(get_handle=lambda: 5,
                                  new_request=lambda *_args: self.fail("model bypassed"))
        manager = SimpleNamespace(get_wininet_object={3: instance, 5: session}.get)
        strings = {101: "a" * 254, 102: "public.test", 201: "POST",
                   202: "/" + "x" * 2_048, 203: "/marker"}
        emu = SimpleNamespace(api=SimpleNamespace(load_api_handler=lambda _module:
                                                  SimpleNamespace(netman=manager)),
                              read_mem_string=lambda pointer, _width, _limit:
                              strings[pointer])
        blocked = lambda _params: self.fail("API model called for rejected request")
        self.assertEqual(bridge._internet_connect(
            emu, "wininet.InternetConnectA", blocked,
            [3, 101, 80, 0, 0, 3, 0, 0]), 0)
        self.assertEqual(bridge.events[-1]["reason"],
                         "invalid or oversized server name")
        self.assertEqual(bridge._internet_connect(
            emu, "wininet.InternetConnectA", blocked,
            [3, 102, 80, 0, 0, 1, 0, 0]), 0)
        self.assertEqual(bridge.events[-1]["reason"],
                         "invalid HTTP server, port, or service")
        self.assertEqual(bridge._http_open_request(
            emu, "wininet.HttpOpenRequestA", blocked,
            [5, 201, 202, 0, 0, 0, 0, 0]), 0)
        self.assertEqual(bridge.events[-1]["reason"],
                         "invalid or oversized HTTP request field")
        self.assertEqual(bridge._http_open_request(
            emu, "wininet.HttpOpenRequestA", blocked,
            [3, 201, 203, 0, 0, 0, 0, 0]), 0)
        self.assertEqual(bridge.events[-1]["reason"],
                         "invalid HTTP connection handle")
        observed = []
        self.assertEqual(bridge._internet_connect(
            emu, "wininet.InternetConnectA",
            lambda params: observed.append(params) or 5,
            [3, 102, 0, 0, 0, 3, 0, 0]), 5)
        self.assertEqual(observed[0][2], 80)
        bridge.close()

    def test_http_header_parser_bounds_and_rejects_unsafe_lines(self):
        def source(data: bytes):
            return SimpleNamespace(mem_read=lambda _ptr, size: data[:size])

        ansi = b"X-Test: emumee\r\nAuthorization: token\r\n"
        wide = "X-Test: emumee\r\n".encode("utf-16le")
        self.assertEqual(NetworkBridge._read_http_headers(
            source(ansi), "wininet.HttpSendRequestA", 1, len(ansi)),
            {"X-Test": "emumee", "Authorization": "token"})
        self.assertEqual(NetworkBridge._read_http_headers(
            source(wide), "winhttp.WinHttpSendRequest", 1, len(wide) // 2),
            {"X-Test": "emumee"})
        for raw in (b"X-Test: ok\r\n Bad: value\r\n",
                    b"Content-Length: 99\r\n", b"X-Test: ok\nBad: value"):
            with self.subTest(raw=raw), self.assertRaises(NetworkDenied):
                NetworkBridge._read_http_headers(
                    source(raw), "wininet.HttpSendRequestA", 1, len(raw))
        with self.assertRaises(NetworkDenied):
            NetworkBridge._read_http_headers(
                source(b""), "wininet.HttpSendRequestA", 1, 16_385)
        with self.assertRaisesRegex(NetworkDenied, "encoding"):
            NetworkBridge._read_http_headers(
                source(b"\0\xd8"), "winhttp.WinHttpSendRequest", 1, 1)

    def test_dns_hook_updates_guest_mapping_and_logs_broker_result(self):
        bridge = NetworkBridge(ArtifactCatalog(self.root / "artifacts"))
        calls = []
        bridge.rpc = SimpleNamespace(call=lambda op, **fields: (
            calls.append((op, fields)) or "93.184.215.14"), close=lambda: None)
        dns = SimpleNamespace(names={})
        emu = SimpleNamespace(read_mem_string=lambda *_args: "example.com",
                              get_network_manager=lambda: SimpleNamespace(dns=dns))
        self.assertEqual(bridge._gethostbyname(emu, "ws2_32.gethostbyname",
                                                lambda _params: 0x1234, [1]), 0x1234)
        self.assertEqual(calls, [("resolve", {"host": "example.com"})])
        self.assertEqual(dns.names["example.com"], "93.184.215.14")
        self.assertEqual([item["event"] for item in bridge.events],
                         ["network_attempt", "dns"])
        bridge.close()

    def test_parent_network_broker_denies_local_targets_and_logs_attempts(self):
        with NetworkBroker(self.root) as broker:
            with_client = FileRPCClient(self.root)
            try:
                with self.assertRaises(NetworkDenied):
                    with_client.call("resolve", host="127.0.0.1")
                sock = with_client.call("socket_open", af=2, type=1)
                with self.assertRaises(NetworkDenied):
                    with_client.call("socket_connect", socket=sock, host="127.0.0.1", port=80)
                with self.assertRaises(NetworkDenied):
                    with_client.call("http_fetch", url="http://127.0.0.1/", method="GET")
                with self.assertRaises(NetworkDenied):
                    with_client.call("socket_send", socket=999,
                                     data=base64.b64encode(b"harmless").decode("ascii"))
                with self.assertRaises(NetworkDenied):
                    with_client.call("socket_recv", socket=999, size=8)
                with_client.call("socket_close", socket=sock)
            finally:
                with_client.close()
        events = json.loads((self.root / "network-broker.json").read_text())
        self.assertEqual(events[-1], {"event": "broker_closed"})
        self.assertTrue(any(event.get("event") == "error" and "127.0.0.1" in event.get("error", "")
                            for event in events))
        self.assertTrue(any(event.get("event") == "dns_attempt" and
                            event.get("host") == "127.0.0.1" for event in events))
        self.assertTrue(any(event.get("event") == "connect_attempt" and
                            event.get("host") == "127.0.0.1" and event.get("port") == 80
                            for event in events))
        self.assertTrue(any(event.get("event") == "http_request_attempt" and
                            event.get("url") == "http://127.0.0.1/" for event in events))
        self.assertTrue(any(event.get("event") == "send_attempt" and
                            event.get("size") == 8 and
                            event.get("sha256") == hashlib.sha256(b"harmless").hexdigest()
                            for event in events))
        self.assertTrue(any(event.get("event") == "recv_attempt" and
                            event.get("size") == 8 for event in events))
        self.assertFalse(any(event.get("event") in
                             {"dns", "connect", "http_request", "send", "recv"}
                             for event in events))

    def test_parent_recovers_bounded_broker_journal_after_process_termination(self):
        journal_path = self.root / BROKER_JOURNAL
        source_dir = Path(__file__).resolve().parents[1] / "src"
        code = (
            "import sys,time;sys.path.insert(0,sys.argv[2]);"
            "from pathlib import Path;from emumee.networkipc import NetworkBroker;"
            "root=Path(sys.argv[1]);broker=NetworkBroker(root);"
            "(root/'broker-ready').write_text('ready');time.sleep(30)"
        )
        with journal_path.open("x+b", buffering=0) as journal:
            process = subprocess.Popen(
                [sys.executable, "-c", code, str(self.root), str(source_dir)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            try:
                deadline = time.monotonic() + 5
                while not (self.root / "broker-ready").is_file():
                    self.assertIsNone(process.poll(), "broker exited before ready")
                    self.assertLess(time.monotonic(), deadline, "broker did not start")
                    time.sleep(0.02)
                client = FileRPCClient(self.root)
                try:
                    with self.assertRaises(NetworkDenied):
                        client.call("http_fetch", url="http://127.0.0.1/",
                                    method="GET", body="", headers={})
                finally:
                    client.close()
                process.kill()
                process.wait(timeout=5)
                self.assertFalse((self.root / "network-broker.json").exists())
                reason = _recover_network_report(self.root, journal)
                self.assertIn("no close marker", reason)
                events = json.loads((self.root / "network-broker.json").read_text())
                self.assertTrue(any(item.get("event") == "http_request_attempt" and
                                    item.get("url") == "http://127.0.0.1/" for item in events))
                self.assertFalse(any(item.get("event") == "http_request" for item in events))
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)

    def test_broker_journal_recovery_stops_at_partial_or_oversized_record(self):
        complete = b'{"event":"request","id":1,"op":"resolve"}\n'
        events, closed, reason = read_broker_journal(BytesIO(complete + b'{"event":"dns"'))
        self.assertEqual(events, [{"event": "request", "id": 1, "op": "resolve"}])
        self.assertFalse(closed)
        self.assertIn("mid-record", reason)
        events, closed, reason = read_broker_journal(BytesIO(
            complete + b"x" * MAX_BROKER_EVENT_BYTES + b"\n"))
        self.assertEqual(len(events), 1)
        self.assertFalse(closed)
        self.assertIn("record limit", reason)

    def test_broker_report_recovery_replaces_link_without_writing_target(self):
        outside = self.root.parent / f"{self.root.name}-outside-marker.txt"
        outside.write_bytes(b"unchanged outside marker")
        report = self.root / "network-broker.json"
        try:
            try:
                report.hardlink_to(outside)
            except OSError:
                self.skipTest("Host does not permit hardlink creation")
            journal = BytesIO(b'{"event":"broker_closed"}\n')
            self.assertIsNone(_recover_network_report(self.root, journal))
            self.assertEqual(outside.read_bytes(), b"unchanged outside marker")
            self.assertEqual(json.loads(report.read_text()), [{"event": "broker_closed"}])
        finally:
            outside.unlink(missing_ok=True)

    def test_broker_rejects_malformed_and_oversized_rpc(self):
        packets = (struct.pack("<I", MAX_MESSAGE + 1),
                   struct.pack("<I", 1) + b"{",
                   struct.pack("<I", 1) + b"\xff")
        for packet in packets:
            with self.subTest(packet=packet[:8]), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                with NetworkBroker(root) as broker:
                    with (root / "network-requests.bin").open("ab", buffering=0) as stream:
                        stream.write(packet)
                    deadline = time.monotonic() + 2
                    while not any(event.get("event") == "protocol_error" for event in broker.events):
                        self.assertLess(time.monotonic(), deadline)
                        time.sleep(0.01)
                self.assertTrue(any(event.get("event") == "protocol_error" for event in
                                    json.loads((root / "network-broker.json").read_text())))

    def test_broker_limits_guest_fields_and_open_sockets(self):
        with patch("emumee.networkipc.MAX_OPEN_SOCKETS", 2), NetworkBroker(self.root) as broker:
            client = FileRPCClient(self.root)
            try:
                with self.assertRaises(NetworkDenied):
                    client.call("http_fetch", url="http://public.test/" + "x" * MAX_URL)
                with self.assertRaises(NetworkDenied):
                    client.call("http_fetch", url="http://public.test/",
                                headers={"X-Test": "v" * (MAX_HEADER_BYTES + 1)})
                first = client.call("socket_open", af=2, type=1)
                second = client.call("socket_open", af=2, type=1)
                with self.assertRaisesRegex(NetworkDenied, "socket quota"):
                    client.call("socket_open", af=2, type=1)
                client.call("socket_close", socket=first)
                client.call("socket_close", socket=second)
            finally:
                client.close()
        self.assertFalse(any(event.get("event") == "http_request" for event in broker.events))
        self.assertEqual(sum(event.get("event") == "socket_open" for event in broker.events), 2)

    def test_broker_malformed_field_corpus_keeps_protocol_alive(self):
        rng = random.Random(0xB20C)
        malformed = [
            ("resolve", {"host": host})
            for host in (None, 0, [], {}, "", "x" * 254, "127.0.0.1")
        ]
        choices = [None, [], {}, "bad", 0, -1, 65536, "9" * 300]
        for _ in range(80):
            value = rng.choice(choices)
            malformed.append(rng.choice([
                ("socket_connect", {"socket": value, "host": value, "port": value}),
                ("socket_send", {"socket": value, "data": value}),
                ("socket_recv", {"socket": value, "size": value}),
                ("socket_close", {"socket": value}),
                ("socket_open", {"af": value, "type": value}),
                ("http_fetch", {"url": value, "method": value, "headers": value,
                                "body": value, "chunked": value}),
                ("unknown_operation", {"value": value}),
            ]))
        with patch("emumee.networkipc.public_ipv4",
                   side_effect=NetworkDenied("test resolver denied")), NetworkBroker(self.root) as broker:
            client = FileRPCClient(self.root)
            try:
                for op, fields in malformed:
                    with self.subTest(op=op, fields=fields), self.assertRaises(NetworkDenied):
                        client.call(op, **fields)
                handle = client.call("socket_open", af=2, type=1)
                self.assertTrue(client.call("socket_close", socket=handle))
            finally:
                client.close()
        events = json.loads((self.root / "network-broker.json").read_text())
        self.assertEqual(sum(event.get("event") == "request" for event in events),
                         len(malformed) + 2)
        self.assertEqual(sum(event.get("event") == "error" for event in events),
                         len(malformed))
        self.assertEqual(events[-1], {"event": "broker_closed"})
        self.assertFalse(any(event.get("event") in {"connect", "http_request"}
                             for event in events))

    def test_broker_request_count_stops_before_network_action(self):
        with patch("emumee.networkipc.MAX_CALLS", 2), NetworkBroker(self.root) as broker:
            client = FileRPCClient(self.root)
            try:
                for _ in range(2):
                    with self.assertRaises(NetworkDenied):
                        client.call("noop")
                with self.assertRaisesRegex(NetworkDenied, "request quota"):
                    client.call("resolve", host="example.com")
            finally:
                client.close()
        self.assertTrue(any(event.get("event") == "protocol_error" for event in broker.events))
        self.assertFalse(any(event.get("event") == "dns" for event in broker.events))

    def test_worker_rejects_malformed_broker_reply(self):
        (self.root / "network-requests.bin").write_bytes(b"")
        payload = b"[]"
        (self.root / "network-responses.bin").write_bytes(struct.pack("<I", len(payload)) + payload)
        client = FileRPCClient(self.root)
        try:
            with self.assertRaisesRegex(NetworkDenied, "Malformed network broker reply"):
                client.call("resolve", host="example.com")
        finally:
            client.close()

    def test_broker_http_transfer_is_logged_and_private_redirect_denied(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", "http://127.0.0.1/private")
                    self.end_headers()
                elif self.path == "/long-redirect":
                    self.send_response(302)
                    self.send_header("Location", "/" + "x" * (MAX_URL + 1))
                    self.end_headers()
                else:
                    payload = b"harmless broker fixture"
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)

            def log_message(self, *_args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_address[1]

        def test_resolver(host, _port):
            if host == "public.test":
                return "127.0.0.1"  # Only test transport is redirected locally.
            raise NetworkDenied(f"Private or host-local destination denied: {host}")

        try:
            with patch("emumee.networkipc.public_ipv4", side_effect=test_resolver):
                with NetworkBroker(self.root):
                    client = FileRPCClient(self.root)
                    try:
                        response = client.call("http_fetch", url=f"http://public.test:{port}/ok",
                                               method="GET", body="", headers={})
                        self.assertEqual(base64.b64decode(response), b"harmless broker fixture")
                        with self.assertRaises(NetworkDenied):
                            client.call("http_fetch", url=f"http://public.test:{port}/redirect",
                                        method="GET", body="", headers={})
                        with self.assertRaisesRegex(NetworkDenied, "redirect URL exceeds"):
                            client.call("http_fetch", url=f"http://public.test:{port}/long-redirect",
                                        method="GET", body="", headers={})
                    finally:
                        client.close()
            events = json.loads((self.root / "network-broker.json").read_text())
            self.assertTrue(any(item.get("event") == "http_response" and item.get("status") == 200
                                and item.get("size") == len(b"harmless broker fixture") for item in events))
            self.assertTrue(any(item.get("event") == "http_request_attempt" and
                                item.get("url") == "http://127.0.0.1/private" and
                                item.get("body_sha256") == hashlib.sha256(b"").hexdigest()
                                for item in events))
            self.assertFalse(any(item.get("event") == "http_request" and
                                 item.get("url") == "http://127.0.0.1/private"
                                 for item in events))
            self.assertTrue(any(item.get("event") == "error" and "127.0.0.1" in item.get("error", "")
                                for item in events))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_broker_http_pins_validated_address_across_dns_change(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                payload = b"pinned harmless HTTP response"
                self.send_response(200)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *_args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_address[1]
        resolutions = []
        connections = []

        def changing_resolver(host, requested_port, *, family, type):
            self.assertEqual((host, requested_port, family, type),
                             ("switch.test", port, socket.AF_INET, socket.SOCK_STREAM))
            resolutions.append(host)
            address = "8.8.8.8" if len(resolutions) == 1 else "127.0.0.1"
            return [(socket.AF_INET, socket.SOCK_STREAM, 0, "", (address, port))]

        def test_connection(target, timeout=None, source_address=None):
            connections.append(target)
            peer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            peer.settimeout(timeout)
            peer.connect(("127.0.0.1", port))
            return peer

        try:
            with patch("emumee.network.socket.getaddrinfo", side_effect=changing_resolver), \
                    patch("emumee.networkipc.socket.create_connection",
                          side_effect=test_connection):
                with NetworkBroker(self.root):
                    client = FileRPCClient(self.root)
                    try:
                        encoded = client.call("http_fetch",
                                              url=f"http://switch.test:{port}/payload",
                                              method="GET", body="", headers={})
                        self.assertEqual(base64.b64decode(encoded),
                                         b"pinned harmless HTTP response")
                    finally:
                        client.close()
            self.assertEqual(resolutions, ["switch.test"])
            self.assertEqual(connections, [("8.8.8.8", port)])
            events = json.loads((self.root / "network-broker.json").read_text())
            self.assertTrue(any(event.get("event") == "http_request" and
                                event.get("address") == "8.8.8.8" and
                                event.get("port") == port for event in events))
            self.assertTrue(any(event.get("event") == "http_response" and
                                event.get("sha256") == hashlib.sha256(
                                    b"pinned harmless HTTP response").hexdigest()
                                for event in events))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_output_watchdog_terminates_oversized_run(self):
        stopped = threading.Event()

        class FakeJob:
            def terminate(self):
                stopped.set()

        (self.root / "large.bin").write_bytes(b"x" * (1024 * 1024 + 1))
        with OutputWatchdog(self.root, FakeJob(), max_mb=1) as watchdog:
            self.assertTrue(stopped.wait(2))
            self.assertIsNotNone(watchdog.violation)

    @unittest.skipUnless(shutil.which("dotnet"), ".NET SDK is unavailable")
    def test_managed_base64_decode_and_virtual_file_write(self):
        project = FIXTURES / "ManagedHello" / "ManagedHello.csproj"
        subprocess.run(["dotnet", "build", str(project), "-c", "Release"],
                       check=True, stdout=subprocess.DEVNULL)
        assembly = FIXTURES / "ManagedHello" / "bin" / "Release" / "net8.0" / "ManagedHello.dll"
        data = assembly.read_bytes()
        result = run_managed(data, inspect_pe(data, assembly.name), self.persona, self.root, 100_000)
        self.assertFalse(result["errors"])
        expected_console = {"stdout": "emumee managed fixture\n", "stderr": "",
                            "stdout_truncated": False, "stderr_truncated": False}
        self.assertEqual(result["console_output"], expected_console)
        report = json.loads((self.root / result["engine_report"]).read_text())
        self.assertEqual(report["console_output"], expected_console)
        self.assertEqual(len(result["artifacts"]), 1)
        artifact = result["artifacts"][0]
        self.assertEqual((self.root / "artifacts" / artifact["file"]).read_bytes(), b"managed payload marker")

    @unittest.skipUnless(shutil.which("dotnet"), ".NET SDK is unavailable")
    def test_managed_console_stdout_and_stderr(self):
        project = FIXTURES / "ManagedConsole" / "ManagedConsole.csproj"
        subprocess.run(["dotnet", "build", str(project), "-c", "Release"],
                       check=True, stdout=subprocess.DEVNULL)
        assembly = FIXTURES / "ManagedConsole" / "bin" / "Release" / "net8.0" / "ManagedConsole.dll"
        data = assembly.read_bytes()
        result = run_managed(data, inspect_pe(data, assembly.name),
                             self.persona, self.root, 100_000)
        self.assertFalse(result["errors"])
        expected = {"stdout": "managed stdout\n", "stderr": "managed stderr\n",
                    "stdout_truncated": False, "stderr_truncated": False}
        self.assertEqual(result["console_output"], expected)
        report = json.loads((self.root / result["engine_report"]).read_text())
        self.assertEqual(report["console_output"], expected)

    @unittest.skipUnless(shutil.which("dotnet"), ".NET SDK is unavailable")
    def test_managed_file_lifecycle_stays_in_guest_namespace(self):
        project = FIXTURES / "ManagedFiles" / "ManagedFiles.csproj"
        subprocess.run(["dotnet", "build", str(project), "-c", "Release"],
                       check=True, stdout=subprocess.DEVNULL)
        assembly = FIXTURES / "ManagedFiles" / "bin" / "Release" / "net8.0" / "ManagedFiles.dll"
        data = assembly.read_bytes()
        runner = ManagedRunner(data, inspect_pe(data, assembly.name), self.persona,
                               self.root, 100_000)
        result = runner.run(self.root)
        self.assertFalse(result["errors"])
        recovered = [(item["guest_path"], (self.root / "artifacts" / item["file"]).read_bytes())
                     for item in result["artifacts"]]
        self.assertIn((r"C:\Users\Alex\Downloads\managed-append.txt",
                       b"harmless managed append marker"), recovered)
        self.assertIn((r"C:\Users\Alex\Downloads\managed-content.txt",
                       b"harmless managed append marker"), recovered)
        self.assertIn((r"C:\Users\Alex\Downloads\managed-persona-copy.txt",
                       b"Personal notes\n"), recovered)
        self.assertEqual([payload for path, payload in recovered
                          if path.endswith("managed-state.txt")],
                         [b"missing", b"present", b"deleted"])
        self.assertNotIn(r"c:\users\alex\downloads\managed-append.txt", runner.files)
        self.assertNotIn(r"c:\users\alex\documents\readme.txt", runner.files)
        self.assertEqual(runner.file_bytes, sum(map(len, runner.files.values())))
        report = json.loads((self.root / result["engine_report"]).read_text())
        self.assertEqual([event["existed"] for event in report["events"]
                          if event.get("event") == "file_delete"],
                         [False, True, True])
        runner._framework("System.IO.File.AppendAllText", ["relative.txt", "text"], None, False)
        self.assertTrue(runner._framework("System.IO.File.Exists", [r"C:\Users\Alex\Downloads\relative.txt"],
                                          None, False))
        self.assertEqual(runner._framework("System.IO.File.ReadAllText", ["relative.txt"], None,
                                           False), "text")
        self.assertEqual(runner._decode_file_text(b"\xff\xfeh\x00i\x00"), "hi")
        self.assertFalse(runner._framework("System.IO.File.Exists", [None], None, False))
        with tempfile.NamedTemporaryFile(delete=False) as outside:
            outside.write(b"host private marker")
            outside_path = Path(outside.name)
        try:
            with self.assertRaises(ManagedThrown) as missing:
                runner._framework("System.IO.File.ReadAllText", [str(outside_path)], None, False)
            self.assertEqual(missing.exception.value["__type"], "System.IO.DirectoryNotFoundException")
            self.assertEqual(outside_path.read_bytes(), b"host private marker")
        finally:
            outside_path.unlink()

    @unittest.skipUnless(shutil.which("dotnet"), ".NET SDK is unavailable")
    def test_managed_read_all_bytes_returns_independent_mutable_guest_array(self):
        project = FIXTURES / "ManagedByteArray" / "ManagedByteArray.csproj"
        subprocess.run(["dotnet", "build", str(project), "-c", "Release"],
                       check=True, stdout=subprocess.DEVNULL)
        assembly = (FIXTURES / "ManagedByteArray" / "bin" / "Release" /
                    "net8.0" / "ManagedByteArray.dll")
        data = assembly.read_bytes()
        runner = ManagedRunner(data, inspect_pe(data, assembly.name), self.persona,
                               self.root, 500_000)
        result = runner.run(self.root)
        self.assertFalse(result["errors"])
        base = r"C:\Users\Alex\Downloads\managed-array-"
        self.assertEqual(runner.files[runner._file_key(base + "source.bin")], b"ABC")
        self.assertEqual(runner.files[runner._file_key(base + "edited.bin")], b"AZC")
        self.assertEqual(runner.files[runner._file_key(base + "state.txt")],
                         b"independent;negative-index;upper-bound;negative-ref;null-array")
        report = json.loads((self.root / result["engine_report"]).read_text())
        self.assertEqual([event["type"] for event in report["events"]
                          if event.get("event") == "managed_catch"],
                         ["System.IndexOutOfRangeException"] * 3 +
                         ["System.NullReferenceException"])
        first = runner._framework("System.IO.File.ReadAllBytes", [base + "source.bin"],
                                  None, False)
        self.assertIsInstance(first, bytearray)
        first[0] = ord("X")
        self.assertEqual(runner.files[runner._file_key(base + "source.bin")], b"ABC")

    @unittest.skipUnless(shutil.which("dotnet"), ".NET SDK is unavailable")
    def test_managed_webclient_downloads_are_brokered_and_guest_only(self):
        project = FIXTURES / "ManagedWebDownload" / "ManagedWebDownload.csproj"
        subprocess.run(["dotnet", "build", str(project), "-c", "Release"],
                       check=True, stdout=subprocess.DEVNULL)
        assembly = (FIXTURES / "ManagedWebDownload" / "bin" / "Release" /
                    "net8.0" / "ManagedWebDownload.dll")

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", "6")
                self.end_headers()
                self.wfile.write(b"ABCDEF")

            def log_message(self, *_args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        persona = dict(self.persona)
        persona["hostname"] = f"public.test:{server.server_address[1]}"
        url = f"http://{persona['hostname']}/payload"

        def test_resolver(host, _port):
            if host == "public.test":
                return "127.0.0.1"  # Test transport only; production broker denies loopback.
            raise NetworkDenied(f"Private or host-local destination denied: {host}")

        try:
            with patch("emumee.networkipc.public_ipv4", side_effect=test_resolver):
                with NetworkBroker(self.root):
                    data = assembly.read_bytes()
                    runner = ManagedRunner(data, inspect_pe(data, assembly.name), persona,
                                           self.root, 500_000)
                    result = runner.run(self.root)
            self.assertFalse(result["errors"])
            recovered = {item["guest_path"]: (self.root / "artifacts" / item["file"]).read_bytes()
                         for item in result["artifacts"] if item.get("guest_path")}
            base = r"C:\Users\Alex\Downloads\managed-web-"
            self.assertEqual(recovered[base + "downloaded.bin"], b"ABCDEF")
            self.assertEqual(recovered[base + "edited.bin"], b"ZBCDEF")
            self.assertEqual(recovered[base + "state.txt"], b"downloaded;mutable;matched")
            self.assertEqual(recovered[url], b"ABCDEF")
            broker = json.loads((self.root / "network-broker.json").read_text())
            self.assertEqual(sum(item.get("event") == "http_request_attempt" for item in broker), 2)
            self.assertEqual(sum(item.get("event") == "http_response" for item in broker), 2)
            self.assertEqual(broker[-1], {"event": "broker_closed"})
            report = json.loads((self.root / result["engine_report"]).read_text())
            self.assertTrue(any(item.get("event") == "managed_download_file" and
                                item.get("path") == base + "downloaded.bin" and
                                item.get("size") == 6 for item in report["events"]))
            with tempfile.NamedTemporaryFile(delete=False) as outside:
                outside.write(b"host private marker")
                outside_path = Path(outside.name)
            try:
                with self.assertRaises(ManagedThrown) as missing_parent:
                    runner._framework("System.Net.WebClient.DownloadFile",
                                      [url, str(outside_path)], {"__type": "System.Net.WebClient"},
                                      False)
                self.assertEqual(missing_parent.exception.value["__type"],
                                 "System.IO.DirectoryNotFoundException")
                self.assertEqual(outside_path.read_bytes(), b"host private marker")
            finally:
                outside_path.unlink()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    @unittest.skipUnless(shutil.which("dotnet"), ".NET SDK is unavailable")
    def test_managed_httpclient_tasks_are_brokered_and_guest_only(self):
        project = FIXTURES / "ManagedHttpClient" / "ManagedHttpClient.csproj"
        subprocess.run(["dotnet", "build", str(project), "-c", "Release"],
                       check=True, stdout=subprocess.DEVNULL)
        assembly = (FIXTURES / "ManagedHttpClient" / "bin" / "Release" /
                    "net8.0" / "ManagedHttpClient.dll")

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", "6")
                self.end_headers()
                self.wfile.write(b"ABCDEF")

            def log_message(self, *_args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        persona = dict(self.persona)
        persona["hostname"] = f"public.test:{server.server_address[1]}"
        persona["user_name"] = Path.home().name
        roaming = rf"C:\Users\{persona['user_name']}\AppData\Roaming"
        host_roaming = Path.home() / "AppData" / "Roaming"
        if not host_roaming.is_dir():
            self.skipTest("Host Roaming AppData directory is unavailable")
        host_edited = host_roaming / "managed-http-edited.bin"
        host_state = host_roaming / "managed-http-state.txt"
        self.assertFalse(host_edited.exists())
        self.assertFalse(host_state.exists())
        host_edited.write_bytes(b"host edited marker")
        host_state.write_bytes(b"host state marker")
        self.addCleanup(host_edited.unlink)
        self.addCleanup(host_state.unlink)
        url = f"http://{persona['hostname']}/payload"

        def test_resolver(host, _port):
            if host == "public.test":
                return "127.0.0.1"  # Harmless local test transport only.
            raise NetworkDenied(f"Private or host-local destination denied: {host}")

        try:
            with patch("emumee.networkipc.public_ipv4", side_effect=test_resolver):
                with NetworkBroker(self.root):
                    data = assembly.read_bytes()
                    runner = ManagedRunner(data, inspect_pe(data, assembly.name), persona,
                                           self.root, 500_000)
                    result = runner.run(self.root)
            self.assertFalse(result["errors"], runner.events[-8:])
            recovered = [(item["source"], item["guest_path"],
                          (self.root / "artifacts" / item["file"]).read_bytes())
                         for item in result["artifacts"]]
            self.assertEqual(recovered, [
                ("network_download", url, b"ABCDEF"),
                ("managed_file_write", roaming + r"\managed-http-edited.bin", b"ZBCDEF"),
                ("managed_file_write", roaming + r"\managed-http-state.txt", b"downloaded"),
            ])
            self.assertEqual(host_edited.read_bytes(), b"host edited marker")
            self.assertEqual(host_state.read_bytes(), b"host state marker")
            broker = json.loads((self.root / "network-broker.json").read_text())
            self.assertEqual(sum(item.get("event") == "http_request_attempt" for item in broker), 2)
            self.assertEqual(sum(item.get("event") == "http_response" for item in broker), 2)
            self.assertEqual(broker[-1], {"event": "broker_closed"})
            report = json.loads((self.root / result["engine_report"]).read_text())
            self.assertEqual([(event["method"], event["faulted"])
                              for event in report["events"]
                              if event.get("event") == "managed_http_task"],
                             [("GetByteArrayAsync", False), ("GetStringAsync", False)])
            client = runner._framework("System.Net.Http.HttpClient..ctor", [], None, True)
            with patch.object(runner.network, "fetch",
                              side_effect=NetworkDenied("private test destination")):
                task = runner._framework("System.Net.Http.HttpClient.GetByteArrayAsync",
                                         ["http://private.test/payload"], client, False)
            awaiter = runner._framework("GetAwaiter", [], task, False)
            with self.assertRaises(ManagedThrown) as denied:
                runner._framework("GetResult", [], awaiter, False)
            self.assertEqual(denied.exception.value["__type"],
                             "System.Net.Http.HttpRequestException")
            with self.assertRaises(ManagedThrown) as aggregate:
                runner._framework("get_Result", [], task, False)
            self.assertEqual(aggregate.exception.value["__type"],
                             "System.AggregateException")
            with patch.object(runner.network, "fetch", return_value=(b"bad", {"status": 404})):
                failed_status = runner._framework(
                    "System.Net.Http.HttpClient.GetByteArrayAsync", [url], client, False)
            with self.assertRaises(ManagedThrown) as status_error:
                runner._framework("GetResult", [], runner._framework(
                    "GetAwaiter", [], failed_status, False), False)
            self.assertEqual(status_error.exception.value["__type"],
                             "System.Net.Http.HttpRequestException")
            runner._framework("System.Net.Http.HttpClient.Dispose", [], client, False)
            with self.assertRaises(ManagedThrown) as disposed:
                runner._framework("System.Net.Http.HttpClient.GetStringAsync", [url], client, False)
            self.assertEqual(disposed.exception.value["__type"],
                             "System.ObjectDisposedException")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    @unittest.skipUnless(shutil.which("dotnet"), ".NET SDK is unavailable")
    def test_managed_http_response_content_and_status_are_guest_only(self):
        project = FIXTURES / "ManagedHttpResponse" / "ManagedHttpResponse.csproj"
        subprocess.run(["dotnet", "build", str(project), "-c", "Release"],
                       check=True, stdout=subprocess.DEVNULL)
        assembly = (FIXTURES / "ManagedHttpResponse" / "bin" / "Release" /
                    "net8.0" / "ManagedHttpResponse.dll")

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                body = b"MISSING" if self.path == "/missing" else b"ABCDEF"
                self.send_response(404 if self.path == "/missing" else 200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        persona = dict(self.persona)
        persona["hostname"] = f"public.test:{server.server_address[1]}"
        persona["user_name"] = Path.home().name
        roaming = rf"C:\Users\{persona['user_name']}\AppData\Roaming"
        host_roaming = Path.home() / "AppData" / "Roaming"
        if not host_roaming.is_dir():
            self.skipTest("Host Roaming AppData directory is unavailable")
        host_edited = host_roaming / "managed-response-edited.bin"
        host_state = host_roaming / "managed-response-state.txt"
        self.assertFalse(host_edited.exists())
        self.assertFalse(host_state.exists())
        host_edited.write_bytes(b"host edited marker")
        host_state.write_bytes(b"host state marker")
        self.addCleanup(host_edited.unlink)
        self.addCleanup(host_state.unlink)
        base_url = f"http://{persona['hostname']}"

        def test_resolver(host, _port):
            if host == "public.test":
                return "127.0.0.1"  # Harmless local test transport only.
            raise NetworkDenied(f"Private or host-local destination denied: {host}")

        try:
            with patch("emumee.networkipc.public_ipv4", side_effect=test_resolver):
                with NetworkBroker(self.root):
                    data = assembly.read_bytes()
                    runner = ManagedRunner(data, inspect_pe(data, assembly.name), persona,
                                           self.root, 500_000)
                    result = runner.run(self.root)
            self.assertFalse(result["errors"], runner.events[-8:])
            recovered = [(item["source"], item["guest_path"],
                          (self.root / "artifacts" / item["file"]).read_bytes())
                         for item in result["artifacts"]]
            self.assertEqual(recovered, [
                ("network_download", base_url + "/payload", b"ABCDEF"),
                ("managed_file_write", roaming + r"\managed-response-edited.bin", b"ZBCDEF"),
                ("network_download", base_url + "/missing", b"MISSING"),
                ("managed_file_write", roaming + r"\managed-response-state.txt", b"downloaded"),
            ])
            self.assertEqual(host_edited.read_bytes(), b"host edited marker")
            self.assertEqual(host_state.read_bytes(), b"host state marker")
            broker = json.loads((self.root / "network-broker.json").read_text())
            self.assertEqual([(item["url"], item["status"]) for item in broker
                              if item.get("event") == "http_response"],
                             [(base_url + "/payload", 200),
                              (base_url + "/missing", 404)])
            self.assertEqual(broker[-1], {"event": "broker_closed"})
            report = json.loads((self.root / result["engine_report"]).read_text())
            self.assertEqual([(item["method"], item["size"]) for item in report["events"]
                              if item.get("event") == "managed_http_content_task"],
                             [("ReadAsByteArrayAsync", 6), ("ReadAsStringAsync", 6),
                              ("ReadAsStringAsync", 7)])
            self.assertIn("System.Net.Http.HttpRequestException", [item.get("type")
                for item in report["events"] if item.get("event") == "managed_catch"])
            client = runner._framework("System.Net.Http.HttpClient..ctor", [], None, True)
            with patch.object(runner.network, "fetch",
                              side_effect=NetworkDenied("private test destination")):
                denied_task = runner._framework("System.Net.Http.HttpClient.GetAsync",
                                                [base_url + "/payload"], client, False)
            self.assertTrue(runner._framework("get_IsFaulted", [], denied_task, False))
            with self.assertRaises(ManagedThrown) as denied:
                runner._framework("GetResult", [], runner._framework(
                    "GetAwaiter", [], denied_task, False), False)
            self.assertEqual(denied.exception.value["__type"],
                             "System.Net.Http.HttpRequestException")
            with patch.object(runner.network, "fetch", return_value=(
                    b"MISSING", {"status": 404})):
                missing_task = runner._framework("System.Net.Http.HttpClient.GetAsync",
                                                 [base_url + "/missing"], client, False)
            self.assertFalse(runner._framework("get_IsFaulted", [], missing_task, False))
            response = runner._framework("get_Result", [], missing_task, False)
            self.assertFalse(runner._framework("get_IsSuccessStatusCode", [], response, False))
            content = runner._framework("get_Content", [], response, False)
            runner._framework("System.Net.Http.HttpContent.Dispose", [], content, False)
            with self.assertRaises(ManagedThrown) as disposed:
                runner._framework("System.Net.Http.HttpContent.ReadAsByteArrayAsync",
                                  [], content, False)
            self.assertEqual(disposed.exception.value["__type"],
                             "System.ObjectDisposedException")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    @unittest.skipUnless(shutil.which("dotnet"), ".NET SDK is unavailable")
    def test_managed_http_post_bodies_are_brokered_and_guest_only(self):
        project = FIXTURES / "ManagedHttpPost" / "ManagedHttpPost.csproj"
        subprocess.run(["dotnet", "build", str(project), "-c", "Release"],
                       check=True, stdout=subprocess.DEVNULL)
        assembly = (FIXTURES / "ManagedHttpPost" / "bin" / "Release" /
                    "net8.0" / "ManagedHttpPost.dll")
        received = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                size = int(self.headers["Content-Length"])
                body = self.rfile.read(size)
                received.append((self.path, body, self.headers.get("Content-Type")))
                self.send_response(201 if self.path == "/json" else 202)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        persona = dict(self.persona)
        persona["hostname"] = f"public.test:{server.server_address[1]}"
        persona["user_name"] = Path.home().name
        roaming = rf"C:\Users\{persona['user_name']}\AppData\Roaming"
        host_roaming = Path.home() / "AppData" / "Roaming"
        if not host_roaming.is_dir():
            self.skipTest("Host Roaming AppData directory is unavailable")
        host_binary = host_roaming / "managed-post-binary.bin"
        host_state = host_roaming / "managed-post-state.txt"
        self.assertFalse(host_binary.exists())
        self.assertFalse(host_state.exists())
        host_binary.write_bytes(b"host binary marker")
        host_state.write_bytes(b"host state marker")
        self.addCleanup(host_binary.unlink)
        self.addCleanup(host_state.unlink)
        base_url = f"http://{persona['hostname']}"
        json_body = '{"safe":"é"}'.encode("utf-8")

        def test_resolver(host, _port):
            if host == "public.test":
                return "127.0.0.1"  # Harmless local test transport only.
            raise NetworkDenied(f"Private or host-local destination denied: {host}")

        try:
            with patch("emumee.networkipc.public_ipv4", side_effect=test_resolver):
                with NetworkBroker(self.root):
                    data = assembly.read_bytes()
                    runner = ManagedRunner(data, inspect_pe(data, assembly.name), persona,
                                           self.root, 500_000)
                    result = runner.run(self.root)
            self.assertFalse(result["errors"], runner.events[-8:])
            self.assertEqual(received, [
                ("/json", json_body, "application/json; charset=utf-8"),
                ("/binary", b"AZC", None),
            ])
            recovered = [(item["source"], item["guest_path"],
                          (self.root / "artifacts" / item["file"]).read_bytes())
                         for item in result["artifacts"]]
            self.assertEqual(recovered, [
                ("network_request_body", base_url + "/json", json_body),
                ("network_download", base_url + "/json", json_body),
                ("network_request_body", base_url + "/binary", b"AZC"),
                ("network_download", base_url + "/binary", b"AZC"),
                ("managed_file_write", roaming + r"\managed-post-binary.bin", b"AZC"),
                ("managed_file_write", roaming + r"\managed-post-state.txt", b"posted"),
            ])
            self.assertEqual(host_binary.read_bytes(), b"host binary marker")
            self.assertEqual(host_state.read_bytes(), b"host state marker")
            broker = json.loads((self.root / "network-broker.json").read_text())
            self.assertEqual([(item["method"], item["body_size"], item["body_sha256"])
                              for item in broker if item.get("event") == "http_request_attempt"],
                             [("POST", len(json_body), hashlib.sha256(json_body).hexdigest()),
                              ("POST", 3, hashlib.sha256(b"AZC").hexdigest())])
            self.assertEqual(broker[-1], {"event": "broker_closed"})
            report = json.loads((self.root / result["engine_report"]).read_text())
            self.assertEqual([(item["method"], item["request_size"], item["faulted"])
                              for item in report["events"]
                              if item.get("event") == "managed_http_task"],
                             [("PostAsync", len(json_body), False),
                              ("PostAsync", 3, False)])
            with self.assertRaises(ManagedThrown) as bad_window:
                runner._framework("System.Net.Http.ByteArrayContent..ctor",
                                  [bytearray(b"ABC"), 2, 2], None, True)
            self.assertEqual(bad_window.exception.value["__type"],
                             "System.ArgumentOutOfRangeException")
            with self.assertRaises(ManagedThrown) as bad_media:
                runner._framework("System.Net.Http.StringContent..ctor",
                                  ["ok", None, "text/plain\r\nX-Test: bad"], None, True)
            self.assertEqual(bad_media.exception.value["__type"],
                             "System.FormatException")
            with patch("emumee.managed.MAX_TRANSFER", 2):
                with self.assertRaises(UnsupportedManaged):
                    runner._framework("System.Net.Http.ByteArrayContent..ctor",
                                      [bytearray(b"ABC")], None, True)
            client = runner._framework("System.Net.Http.HttpClient..ctor", [], None, True)
            content = runner._framework("System.Net.Http.ByteArrayContent..ctor",
                                        [bytearray(b"safe")], None, True)
            runner._framework("System.Net.Http.HttpContent.Dispose", [], content, False)
            with self.assertRaises(ManagedThrown) as disposed:
                runner._framework("System.Net.Http.HttpClient.PostAsync",
                                  [base_url + "/binary", content], client, False)
            self.assertEqual(disposed.exception.value["__type"],
                             "System.ObjectDisposedException")
            retry_content = runner._framework("System.Net.Http.ByteArrayContent..ctor",
                                              [bytearray(b"safe")], None, True)
            with patch.object(runner.network, "fetch", return_value=(
                    b"missing", {"status": 404})):
                missing_task = runner._framework("System.Net.Http.HttpClient.PostAsync",
                                                 [base_url + "/missing", retry_content],
                                                 client, False)
            self.assertFalse(runner._framework("get_IsFaulted", [], missing_task, False))
            missing = runner._framework("get_Result", [], missing_task, False)
            self.assertEqual(runner._framework("get_StatusCode", [], missing, False), 404)
            with self.assertRaises(ManagedThrown) as failed_status:
                runner._framework("EnsureSuccessStatusCode", [], missing, False)
            self.assertEqual(failed_status.exception.value["__type"],
                             "System.Net.Http.HttpRequestException")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    @unittest.skipUnless(shutil.which("dotnet"), ".NET SDK is unavailable")
    def test_managed_http_base_address_resolves_only_through_broker(self):
        project = FIXTURES / "ManagedHttpBase" / "ManagedHttpBase.csproj"
        subprocess.run(["dotnet", "build", str(project), "-c", "Release"],
                       check=True, stdout=subprocess.DEVNULL)
        assembly = (FIXTURES / "ManagedHttpBase" / "bin" / "Release" /
                    "net8.0" / "ManagedHttpBase.dll")
        received = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                received.append(("GET", self.path, b""))
                body = b"ONE" if self.path == "/api/v1/first" else b"ROOT"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                received.append(("POST", self.path, body))
                self.send_response(200)
                self.send_header("Content-Length", "3")
                self.end_headers()
                self.wfile.write(b"ACK")

            def log_message(self, *_args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        persona = dict(self.persona)
        persona["hostname"] = f"public.test:{server.server_address[1]}"
        persona["user_name"] = Path.home().name
        roaming = rf"C:\Users\{persona['user_name']}\AppData\Roaming"
        host_roaming = Path.home() / "AppData" / "Roaming"
        if not host_roaming.is_dir():
            self.skipTest("Host Roaming AppData directory is unavailable")
        host_state = host_roaming / "managed-http-base-state.txt"
        self.assertFalse(host_state.exists())
        host_state.write_bytes(b"host marker")
        self.addCleanup(host_state.unlink)

        def test_resolver(host, _port):
            if host == "public.test":
                return "127.0.0.1"  # Harmless local test transport only.
            raise NetworkDenied(f"Private or host-local destination denied: {host}")

        try:
            with patch("emumee.networkipc.public_ipv4", side_effect=test_resolver):
                with NetworkBroker(self.root):
                    data = assembly.read_bytes()
                    runner = ManagedRunner(data, inspect_pe(data, assembly.name), persona,
                                           self.root, 500_000)
                    result = runner.run(self.root)
            self.assertFalse(result["errors"], runner.events[-8:])
            self.assertEqual(received, [("GET", "/api/v1/first", b""),
                                        ("GET", "/root", b""),
                                        ("POST", "/api/upload", b"PING")])
            recovered = [(item["source"], item["guest_path"],
                          (self.root / "artifacts" / item["file"]).read_bytes())
                         for item in result["artifacts"]]
            base = f"http://{persona['hostname']}"
            self.assertEqual(recovered, [
                ("network_download", base + "/api/v1/first", b"ONE"),
                ("network_download", base + "/root", b"ROOT"),
                ("network_request_body", base + "/api/upload", b"PING"),
                ("network_download", base + "/api/upload", b"ACK"),
                ("managed_file_write", roaming + r"\managed-http-base-state.txt",
                 b"ONE;ROOT;ACK;locked"),
            ])
            self.assertEqual(host_state.read_bytes(), b"host marker")
            broker = json.loads((self.root / "network-broker.json").read_text())
            self.assertEqual([(item["method"], item["url"])
                              for item in broker if item.get("event") == "http_request_attempt"],
                             [("GET", base + "/api/v1/first"),
                              ("GET", base + "/root"),
                              ("POST", base + "/api/upload")])
            self.assertEqual(broker[-1], {"event": "broker_closed"})
            client = runner._framework("System.Net.Http.HttpClient..ctor", [], None, True)
            relative = {"__type": "System.Uri", "args": ["relative"]}
            with self.assertRaises(ManagedThrown) as invalid_base:
                runner._framework("System.Net.Http.HttpClient.set_BaseAddress",
                                  [relative], client, False)
            self.assertEqual(invalid_base.exception.value["__type"],
                             "System.ArgumentException")
            with self.assertRaises(ManagedThrown) as missing_base:
                runner._framework("System.Net.Http.HttpClient.GetStringAsync",
                                  ["stage"], client, False)
            self.assertEqual(missing_base.exception.value["__type"],
                             "System.InvalidOperationException")
            configured = runner._framework("System.Net.Http.HttpClient..ctor", [], None, True)
            base_uri = {"__type": "System.Uri", "args": [base + "/api/v1/"]}
            runner._framework("System.Net.Http.HttpClient.set_BaseAddress",
                              [base_uri], configured, False)
            self.assertIs(runner._framework("System.Net.Http.HttpClient.get_BaseAddress",
                                           [], configured, False), base_uri)
            absolute_url = "http://different.test/override"
            with patch.object(runner.network, "fetch", return_value=(
                    b"OK", {"status": 200})) as fetch:
                runner._framework("System.Net.Http.HttpClient.GetStringAsync",
                                  [absolute_url], configured, False)
            fetch.assert_called_once_with(absolute_url, method="GET", body=None,
                                          headers={}, with_metadata=True)
            with self.assertRaises(ManagedThrown) as locked_base:
                runner._framework("System.Net.Http.HttpClient.set_BaseAddress",
                                  [base_uri], configured, False)
            self.assertEqual(locked_base.exception.value["__type"],
                             "System.InvalidOperationException")
            base_only = runner._framework("System.Net.Http.HttpClient..ctor", [], None, True)
            runner._framework("System.Net.Http.HttpClient.set_BaseAddress",
                              [base_uri], base_only, False)
            get = runner._framework("System.Net.Http.HttpMethod..ctor", ["GET"], None, True)
            request = runner._framework("System.Net.Http.HttpRequestMessage..ctor",
                                        [get, None], None, True)
            with patch.object(runner.network, "fetch", return_value=(
                    b"OK", {"status": 200})) as fetch:
                runner._framework("System.Net.Http.HttpClient.SendAsync",
                                  [request], base_only, False)
            fetch.assert_called_once_with(base + "/api/v1/", method="GET", body=None,
                                          headers={}, with_metadata=True)
            self.assertEqual(runner._framework("get_RequestUri", [], request, False),
                             base + "/api/v1/")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    @unittest.skipUnless(shutil.which("dotnet"), ".NET SDK is unavailable")
    def test_managed_sendasync_headers_and_body_are_brokered(self):
        project = FIXTURES / "ManagedHttpSend" / "ManagedHttpSend.csproj"
        subprocess.run(["dotnet", "build", str(project), "-c", "Release"],
                       check=True, stdout=subprocess.DEVNULL)
        assembly = (FIXTURES / "ManagedHttpSend" / "bin" / "Release" /
                    "net8.0" / "ManagedHttpSend.dll")
        received = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                received.append((self.path, body, self.headers.get("X-Client"),
                                 self.headers.get("X-Request"), self.headers.get("X-Multi"),
                                 self.headers.get("Content-Type")))
                self.send_response(201)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        persona = dict(self.persona)
        persona["hostname"] = f"public.test:{server.server_address[1]}"
        persona["user_name"] = Path.home().name
        roaming = rf"C:\Users\{persona['user_name']}\AppData\Roaming"
        host_roaming = Path.home() / "AppData" / "Roaming"
        if not host_roaming.is_dir():
            self.skipTest("Host Roaming AppData directory is unavailable")
        host_response = host_roaming / "managed-send-response.bin"
        host_state = host_roaming / "managed-send-state.txt"
        self.assertFalse(host_response.exists())
        self.assertFalse(host_state.exists())
        host_response.write_bytes(b"host response marker")
        host_state.write_bytes(b"host state marker")
        self.addCleanup(host_response.unlink)
        self.addCleanup(host_state.unlink)
        url = f"http://{persona['hostname']}/send"

        def test_resolver(host, _port):
            if host == "public.test":
                return "127.0.0.1"  # Harmless local test transport only.
            raise NetworkDenied(f"Private or host-local destination denied: {host}")

        try:
            with patch("emumee.networkipc.public_ipv4", side_effect=test_resolver):
                with NetworkBroker(self.root):
                    data = assembly.read_bytes()
                    runner = ManagedRunner(data, inspect_pe(data, assembly.name), persona,
                                           self.root, 500_000)
                    result = runner.run(self.root)
            self.assertFalse(result["errors"], runner.events[-8:])
            self.assertEqual(received, [("/send", b"PING", "alpha", "beta", "one, two",
                                         "text/plain; charset=utf-8")])
            recovered = [(item["source"], item["guest_path"],
                          (self.root / "artifacts" / item["file"]).read_bytes())
                         for item in result["artifacts"]]
            self.assertEqual(recovered, [
                ("network_request_body", url, b"PING"),
                ("network_download", url, b"PING"),
                ("managed_file_write", roaming + r"\managed-send-response.bin", b"PING"),
                ("managed_file_write", roaming + r"\managed-send-state.txt", b"sent"),
            ])
            self.assertEqual(host_response.read_bytes(), b"host response marker")
            self.assertEqual(host_state.read_bytes(), b"host state marker")
            broker = json.loads((self.root / "network-broker.json").read_text())
            attempts = [item for item in broker if item.get("event") == "http_request_attempt"]
            self.assertEqual(len(attempts), 1)
            self.assertEqual((attempts[0]["method"], attempts[0]["body_size"],
                              attempts[0]["body_sha256"]),
                             ("POST", 4, hashlib.sha256(b"PING").hexdigest()))
            self.assertEqual(attempts[0]["headers"], {
                "X-Client": "alpha", "X-Request": "beta", "X-Multi": "one, two",
                "Content-Type": "text/plain; charset=utf-8"})
            self.assertEqual(broker[-1], {"event": "broker_closed"})
            report = json.loads((self.root / result["engine_report"]).read_text())
            self.assertEqual([(item["method"], item["verb"], item["request_size"])
                              for item in report["events"]
                              if item.get("event") == "managed_http_task"],
                             [("SendAsync", "POST", 4)])
            self.assertIn("System.InvalidOperationException", [item.get("type")
                for item in report["events"] if item.get("event") == "managed_catch"])
            client = runner._framework("System.Net.Http.HttpClient..ctor", [], None, True)
            headers = runner._framework("get_DefaultRequestHeaders", [], client, False)
            with self.assertRaises(ManagedThrown) as bad_name:
                runner._framework("System.Net.Http.Headers.HttpHeaders.Add",
                                  ["X-Bad\r\nInjected", "value"], headers, False)
            self.assertEqual(bad_name.exception.value["__type"], "System.FormatException")
            with self.assertRaises(ManagedThrown) as bad_value:
                runner._framework("System.Net.Http.Headers.HttpHeaders.Add",
                                  ["X-Test", "good\r\nHost: bad"], headers, False)
            self.assertEqual(bad_value.exception.value["__type"], "System.FormatException")
            with self.assertRaises(ManagedThrown) as restricted:
                runner._framework("System.Net.Http.Headers.HttpHeaders.Add",
                                  ["Host", "127.0.0.1"], headers, False)
            self.assertEqual(restricted.exception.value["__type"],
                             "System.InvalidOperationException")
            runner._framework("System.Net.Http.Headers.HttpHeaders.Add",
                              ["X-Scope", "default"], headers, False)
            method = runner._framework("System.Net.Http.HttpMethod..ctor",
                                       ["PATCH"], None, True)
            request = runner._framework("System.Net.Http.HttpRequestMessage..ctor",
                                        [method, url], None, True)
            request_headers = runner._framework("get_Headers", [], request, False)
            runner._framework("System.Net.Http.Headers.HttpHeaders.Add",
                              ["X-Scope", "request"], request_headers, False)
            request_body = runner._framework("System.Net.Http.ByteArrayContent..ctor",
                                             [bytearray(b"XYZ")], None, True)
            runner._framework("set_Content", [request_body], request, False)
            metadata = {"status": 202}
            with patch.object(runner.network, "fetch", return_value=(b"OK", metadata)) as fetch:
                task = runner._framework("System.Net.Http.HttpClient.SendAsync",
                                         [request], client, False)
            fetch.assert_called_once_with(url, method="PATCH", body=b"XYZ",
                                          headers={"X-Scope": "request"},
                                          with_metadata=True)
            self.assertEqual(runner._framework("get_StatusCode", [], runner._framework(
                "get_Result", [], task, False), False), 202)
            with self.assertRaises(ManagedThrown) as sent_header:
                runner._framework("System.Net.Http.Headers.HttpHeaders.Add",
                                  ["X-Late", "blocked"], request_headers, False)
            self.assertEqual(sent_header.exception.value["__type"],
                             "System.InvalidOperationException")
            with self.assertRaises(UnsupportedManaged):
                runner._framework("System.Net.Http.HttpMethod..ctor", ["TRACE"], None, True)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    @unittest.skipUnless(shutil.which("dotnet"), ".NET SDK is unavailable")
    def test_managed_memory_stream_copy_stays_in_guest_and_preserves_positions(self):
        project = FIXTURES / "ManagedMemoryCopy" / "ManagedMemoryCopy.csproj"
        subprocess.run(["dotnet", "build", str(project), "-c", "Release"],
                       check=True, stdout=subprocess.DEVNULL)
        assembly = (FIXTURES / "ManagedMemoryCopy" / "bin" / "Release" /
                    "net8.0" / "ManagedMemoryCopy.dll")
        data = assembly.read_bytes()
        runner = ManagedRunner(data, inspect_pe(data, assembly.name), self.persona,
                               self.root, 500_000)
        result = runner.run(self.root)
        self.assertFalse(result["errors"])
        recovered = {item["guest_path"]: (self.root / "artifacts" / item["file"]).read_bytes()
                     for item in result["artifacts"] if item.get("guest_path")}
        prefix = r"C:\Users\Alex\Downloads\managed-memory-"
        self.assertEqual(recovered[prefix + "read.bin"], b"\0BZD\0")
        self.assertEqual(recovered[prefix + "copy.bin"], b"BZDEF\0\0")
        self.assertEqual(recovered[prefix + "roundtrip.bin"], b"DEF\0\0")
        self.assertEqual(recovered[prefix + "backing.bin"], b"QMN")
        self.assertEqual(recovered[prefix + "state.txt"], b"copy-ok;fixed-ok")
        report = json.loads((self.root / result["engine_report"]).read_text())
        self.assertEqual([event["size"] for event in report["events"]
                          if event.get("event") == "managed_stream_copy"], [7, 5])
        self.assertEqual([event["type"] for event in report["events"]
                          if event.get("event") == "managed_catch"],
                         ["System.NotSupportedException"])
        with patch("emumee.managed.MAX_MEMORY_STREAMS", 0):
            with self.assertRaisesRegex(UnsupportedManaged, "MemoryStream count exceeded"):
                runner._framework("System.IO.MemoryStream..ctor", [], None, True)
        closed = runner._framework("System.IO.MemoryStream..ctor", [bytearray(b"safe")],
                                   None, True)
        runner._framework("System.IO.Stream.Close", [], closed, False)
        self.assertEqual(runner._framework("System.IO.MemoryStream.ToArray", [], closed, False),
                         b"safe")
        with self.assertRaises(ManagedThrown) as disposed:
            runner._framework("System.IO.Stream.ReadByte", [], closed, False)
        self.assertEqual(disposed.exception.value["__type"], "System.ObjectDisposedException")
        empty = runner._framework("System.IO.MemoryStream..ctor", [], None, True)
        runner._framework("System.IO.Stream.set_Position", [5], empty, False)
        runner._framework("System.IO.Stream.Write", [bytearray(), 0, 0], empty, False)
        self.assertEqual(runner._framework("System.IO.Stream.get_Length", [], empty, False), 0)
        self.assertEqual(runner._framework("System.IO.Stream.get_Position", [], empty, False), 5)
        runner._framework("System.IO.Stream.WriteByte", [ord("!")], empty, False)
        self.assertEqual(runner._framework("System.IO.MemoryStream.ToArray", [], empty, False),
                         b"\0" * 5 + b"!")
        compressed = gzip.compress(b"offset payload")
        source = runner._framework("System.IO.MemoryStream..ctor",
                                   [bytearray(b"xx" + compressed)], None, True)
        runner._framework("System.IO.Stream.set_Position", [2], source, False)
        gzip_stream = runner._framework("System.IO.Compression.GZipStream..ctor",
                                        [source, 0], None, True)
        target = runner._framework("System.IO.MemoryStream..ctor", [], None, True)
        runner._framework("System.IO.Stream.WriteByte", [ord("#")], target, False)
        runner._framework("System.IO.Stream.CopyTo", [target], gzip_stream, False)
        self.assertEqual(runner._framework("System.IO.MemoryStream.ToArray", [], target, False),
                         b"#offset payload")
        self.assertEqual(source["position"], len(b"xx" + compressed))
        self.assertEqual(target["position"], len(b"#offset payload"))

    @unittest.skipUnless(shutil.which("dotnet"), ".NET SDK is unavailable")
    def test_managed_full_path_uses_guest_cwd_and_preserves_host_file(self):
        project = FIXTURES / "ManagedFullPath" / "ManagedFullPath.csproj"
        subprocess.run(["dotnet", "build", str(project), "-c", "Release"],
                       check=True, stdout=subprocess.DEVNULL)
        assembly = (FIXTURES / "ManagedFullPath" / "bin" / "Release" /
                    "net8.0" / "ManagedFullPath.dll")
        persona = dict(self.persona)
        persona["user_name"] = Path.home().name
        persona["hostname"] = f"TEST-{random.getrandbits(64):016X}"
        roaming = rf"C:\Users\{persona['user_name']}\AppData\Roaming"
        tag = f"emumee-full-{persona['hostname']}"
        host_roaming = Path.home() / "AppData" / "Roaming"
        if not host_roaming.is_dir():
            self.skipTest("Host Roaming AppData directory is unavailable")
        host_marker = host_roaming / f"{tag}.bin"
        self.assertFalse(host_marker.exists())
        host_cwd = Path.cwd()
        host_marker.write_bytes(b"host private full-path marker")
        try:
            data = assembly.read_bytes()
            runner = ManagedRunner(data, inspect_pe(data, assembly.name), persona,
                                   self.root, 500_000)
            result = runner.run(self.root)
            self.assertFalse(result["errors"], runner.events[-8:])
            recovered = {item["guest_path"]: (self.root / "artifacts" / item["file"]).read_bytes()
                         for item in result["artifacts"] if item.get("guest_path")}
            self.assertEqual(recovered, {
                roaming + "\\" + tag + ".bin": b"guest-full-path-payload",
                roaming + "\\" + tag + "-state.txt":
                    b"full-path-ok;null;empty;base",
            })
            self.assertEqual(host_marker.read_bytes(), b"host private full-path marker")
            self.assertEqual(Path.cwd(), host_cwd)
            self.assertEqual(runner._framework("System.IO.Path.GetFullPath",
                                               [r"\Users\Public\probe.bin"], None, False),
                             r"C:\Users\Public\probe.bin")
            self.assertEqual(runner._framework("System.IO.Path.GetFullPath",
                                               ["C:probe.bin"], None, False),
                             runner.current_dir + r"\probe.bin")
            self.assertEqual(runner._framework("System.IO.Path.GetFullPath",
                                               [r"D:\guest\probe.bin"], None, False),
                             r"D:\guest\probe.bin")
            with self.assertRaisesRegex(UnsupportedManaged, "Other-drive relative"):
                runner._framework("System.IO.Path.GetFullPath",
                                  ["D:probe.bin"], None, False)
            with self.assertRaisesRegex(UnsupportedManaged, "UNC and device"):
                runner._framework("System.IO.Path.GetFullPath",
                                  [r"\\server\share\probe.bin"], None, False)
            with self.assertRaisesRegex(UnsupportedManaged, "full path exceeds limit"):
                runner._framework("System.IO.Path.GetFullPath",
                                  ["a" * 4090], None, False)
            with self.assertRaises(ManagedThrown) as bad_colon:
                runner._framework("System.IO.Path.GetFullPath",
                                  ["file:stream"], None, False)
            self.assertEqual(bad_colon.exception.value["__type"], "System.ArgumentException")
            report = json.loads((self.root / result["engine_report"]).read_text())
            self.assertEqual([event["type"] for event in report["events"]
                              if event.get("event") == "managed_catch"],
                             ["System.ArgumentNullException", "System.ArgumentException",
                              "System.ArgumentException"])
            self.assertEqual(sum(event.get("event") == "current_directory"
                                 for event in report["events"]), 2)
            self.assertEqual(result["cil_coverage"], report["cil_coverage"])
        finally:
            host_marker.unlink()

    @unittest.skipUnless(shutil.which("dotnet"), ".NET SDK is unavailable")
    def test_managed_aes_memory_only_plaintext_is_extracted_with_provenance(self):
        project = FIXTURES / "ManagedAesMemoryOnly" / "ManagedAesMemoryOnly.csproj"
        subprocess.run(["dotnet", "build", str(project), "-c", "Release"],
                       check=True, stdout=subprocess.DEVNULL)
        assembly = (FIXTURES / "ManagedAesMemoryOnly" / "bin" / "Release" /
                    "net8.0" / "ManagedAesMemoryOnly.dll")
        data = assembly.read_bytes()
        result = run_managed(data, inspect_pe(data, assembly.name), self.persona,
                             self.root, 500_000)
        self.assertFalse(result["errors"])
        self.assertEqual(result["guest_entry_return"], 0)
        plaintext = b'{"stage":"memory-only","url":"https://example.invalid/collect"}'
        captures = [item for item in result["artifacts"]
                    if item["source"] == "managed_aes_plaintext"]
        self.assertEqual(len(captures), 1)
        item = captures[0]
        self.assertEqual(item["kind"], "memory")
        self.assertEqual((self.root / "artifacts" / item["file"]).read_bytes(), plaintext)
        self.assertEqual(item["context"]["transform_sequence"], 1)
        self.assertEqual(item["context"]["mode"], 1)
        self.assertEqual(item["context"]["padding"], 2)
        self.assertEqual(item["context"]["final_input_sha256"], hashlib.sha256(
            base64.b64decode("OZk7lxB0x9F9ZkorCqj5Zu8CckKT3e3ajxZ7BzU/aRVu8grkG977SiDlZ0Iq9c7zvgvh/DynYfWX6D5CZz/BJA==")
        ).hexdigest())
        self.assertEqual(result["aes_plaintext_capture"]["captured_artifacts"], 1)
        self.assertEqual(result["aes_plaintext_capture"]["captured_bytes"], len(plaintext))
        self.assertEqual(result["aes_plaintext_capture"]["omitted_bytes"], 0)
        report = json.loads((self.root / result["engine_report"]).read_text())
        transforms = [event for event in report["events"]
                      if event.get("event") == "managed_aes_transform"]
        self.assertEqual(len(transforms), 1)
        self.assertEqual(transforms[0]["plaintext_artifact_status"], "captured")
        self.assertEqual(transforms[0]["plaintext_artifact_sha256"], item["sha256"])
        self.assertEqual(transforms[0]["combined_output_size"], len(plaintext))
        self.assertEqual(report["aes_plaintext_capture"], result["aes_plaintext_capture"])
        self.assertTrue(any(group["sha256"] == item["sha256"] and
                            group["observations"][0]["stage"] == "memory"
                            for group in result["artifact_groups"]))
        with tempfile.TemporaryDirectory() as limited_dir, patch(
                "emumee.managed.MAX_AES_PLAINTEXT_ARTIFACTS", 0):
            limited_root = Path(limited_dir)
            limited = run_managed(data, inspect_pe(data, assembly.name), self.persona,
                                  limited_root, 500_000)
            self.assertFalse(limited["errors"])
            self.assertFalse(any(item["source"] == "managed_aes_plaintext"
                                 for item in limited["artifacts"]))
            self.assertEqual(limited["aes_plaintext_capture"]["omitted_transforms"], 1)
            self.assertEqual(limited["aes_plaintext_capture"]["omitted_bytes"],
                             len(plaintext))
            limited_report = json.loads((limited_root / "engine-report.json").read_text())
            self.assertTrue(any(event.get("plaintext_artifact_status") == "omitted_budget"
                                for event in limited_report["events"]))

    @unittest.skipUnless(shutil.which("dotnet"), ".NET SDK is unavailable")
    def test_managed_aes_decrypts_and_carves_guest_pe_without_host_file_access(self):
        project = FIXTURES / "ManagedAes" / "ManagedAes.csproj"
        subprocess.run(["dotnet", "build", str(project), "-c", "Release"],
                       check=True, stdout=subprocess.DEVNULL)
        assembly = (FIXTURES / "ManagedAes" / "bin" / "Release" /
                    "net8.0" / "ManagedAes.dll")
        persona = dict(self.persona)
        persona["user_name"] = Path.home().name
        persona["hostname"] = f"TEST-{random.getrandbits(64):016X}"
        roaming = rf"C:\Users\{persona['user_name']}\AppData\Roaming"
        tag = f"emumee-aes-{persona['hostname']}"
        host_roaming = Path.home() / "AppData" / "Roaming"
        if not host_roaming.is_dir():
            self.skipTest("Host Roaming AppData directory is unavailable")
        host_marker = host_roaming / f"{tag}-plain.bin"
        self.assertFalse(host_marker.exists())
        host_marker.write_bytes(b"host private AES marker")
        try:
            data = assembly.read_bytes()
            runner = ManagedRunner(data, inspect_pe(data, assembly.name), persona,
                                   self.root, 500_000)
            result = runner.run(self.root)
            self.assertFalse(result["errors"], runner.events[-8:])
            recovered = {item["guest_path"]: (self.root / "artifacts" / item["file"]).read_bytes()
                         for item in result["artifacts"] if item.get("guest_path")}
            prefix = roaming + "\\" + tag
            self.assertEqual(recovered, {
                prefix + "-plain.bin": bytes.fromhex("6bc1bee22e409f96e93d7e117393172a"),
                prefix + "-cipher.bin": bytes.fromhex("7649abac8119b246cee98e9b12e9197d"),
                prefix + "-unpadded.bin": b"hello managed aes payload",
                prefix + "-state.txt": b"aes-ok;bad-input;bad-key",
            })
            self.assertEqual(host_marker.read_bytes(), b"host private AES marker")
            report = json.loads((self.root / result["engine_report"]).read_text())
            transforms = [event for event in report["events"]
                          if event.get("event") == "managed_aes_transform"]
            self.assertEqual([(event["direction"], event["output_size"])
                              for event in transforms],
                             [("decrypt", 16), ("encrypt", 16), ("decrypt", 25)])
            self.assertEqual([event["type"] for event in report["events"]
                              if event.get("event") == "managed_catch"],
                             ["System.Security.Cryptography.CryptographicException"] * 2)

            # A decrypted PE is recovered directly, even if guest code never writes it.
            pe_bytes = (FIXTURES / "native_x86.exe").read_bytes()
            key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
            iv = bytes(range(16))
            padded = pe_bytes + bytes([16 - len(pe_bytes) % 16]) * (16 - len(pe_bytes) % 16)
            encrypted = AES.new(key, AES.MODE_CBC, iv=iv).encrypt(padded)
            aes = runner._framework("System.Security.Cryptography.Aes.Create", [], None, False)
            transform = runner._framework("System.Security.Cryptography.Aes.CreateDecryptor",
                                          [bytearray(key), bytearray(iv)], aes, False)
            before = len(runner.catalog.items)
            decoded = runner._framework(
                "System.Security.Cryptography.ICryptoTransform.TransformFinalBlock",
                [bytearray(encrypted), 0, len(encrypted)], transform, False)
            self.assertEqual(decoded, pe_bytes)
            carved = runner.catalog.items[before:]
            self.assertTrue(any(item["kind"] == "pe" and
                                item["source"].startswith("managed_aes_decrypt@") and
                                (self.root / "artifacts" / item["file"]).read_bytes() == pe_bytes
                                for item in carved))
            # NIST SP 800-38A F.1.1 checks the separate ECB branch.
            ecb = runner._framework("System.Security.Cryptography.Aes.Create", [], None, False)
            runner._framework("System.Security.Cryptography.Aes.set_Mode", [2], ecb, False)
            runner._framework("System.Security.Cryptography.Aes.set_Padding", [1], ecb, False)
            runner._framework("System.Security.Cryptography.Aes.set_Key", [bytearray(key)], ecb, False)
            ecb_transform = runner._framework(
                "System.Security.Cryptography.Aes.CreateEncryptor", [], ecb, False)
            ecb_cipher = runner._framework(
                "System.Security.Cryptography.ICryptoTransform.TransformFinalBlock",
                [bytearray.fromhex("6bc1bee22e409f96e93d7e117393172a"), 0, 16],
                ecb_transform, False)
            self.assertEqual(ecb_cipher,
                             bytes.fromhex("3ad77bb40d7a3660a89ecaf32466ef97"))
            with self.assertRaisesRegex(UnsupportedManaged, "Unsupported AES Mode"):
                runner._framework("System.Security.Cryptography.Aes.set_Mode", [3], aes, False)
            with self.assertRaises(ManagedThrown) as invalid_iv:
                runner._framework("System.Security.Cryptography.Aes.set_IV",
                                  [bytearray(3)], aes, False)
            self.assertEqual(invalid_iv.exception.value["__type"],
                             "System.Security.Cryptography.CryptographicException")
        finally:
            host_marker.unlink()

    @unittest.skipUnless(shutil.which("dotnet"), ".NET SDK is unavailable")
    def test_managed_aes_blocks_hold_padding_and_carve_combined_pe(self):
        project = FIXTURES / "ManagedAesBlocks" / "ManagedAesBlocks.csproj"
        subprocess.run(["dotnet", "build", str(project), "-c", "Release"],
                       check=True, stdout=subprocess.DEVNULL)
        assembly = (FIXTURES / "ManagedAesBlocks" / "bin" / "Release" /
                    "net8.0" / "ManagedAesBlocks.dll")
        persona = dict(self.persona)
        persona["user_name"] = Path.home().name
        persona["hostname"] = f"TEST-{random.getrandbits(64):016X}"
        roaming = rf"C:\Users\{persona['user_name']}\AppData\Roaming"
        tag = f"emumee-aes-blocks-{persona['hostname']}"
        host_roaming = Path.home() / "AppData" / "Roaming"
        if not host_roaming.is_dir():
            self.skipTest("Host Roaming AppData directory is unavailable")
        host_marker = host_roaming / f"{tag}-plain.bin"
        self.assertFalse(host_marker.exists())
        host_marker.write_bytes(b"host private streaming AES marker")
        try:
            data = assembly.read_bytes()
            runner = ManagedRunner(data, inspect_pe(data, assembly.name), persona,
                                   self.root, 500_000)
            result = runner.run(self.root)
            self.assertFalse(result["errors"], runner.events[-8:])
            recovered = {item["guest_path"]: (self.root / "artifacts" / item["file"]).read_bytes()
                         for item in result["artifacts"] if item.get("guest_path")}
            prefix = roaming + "\\" + tag
            self.assertEqual(recovered, {
                prefix + "-cipher.bin": bytes.fromhex(
                    "d6d020609ad1bee66948a5a8ad2b7a122feba8a998d05e66"
                    "c9452bd7d449c923b0b713abbcbb146cf3a7ab917e1d0637"),
                prefix + "-plain.bin": b"managed aes streaming payload verified!",
                prefix + "-state.txt": b"aes-blocks-ok;hold-final;reuse;bounds",
            })
            self.assertEqual(host_marker.read_bytes(), b"host private streaming AES marker")
            report = json.loads((self.root / result["engine_report"]).read_text())
            blocks = [event for event in report["events"]
                      if event.get("event") == "managed_aes_block"]
            self.assertEqual([(event["direction"], event["input_size"], event["output_size"])
                              for event in blocks],
                             [("encrypt", 16, 16), ("encrypt", 16, 16),
                              ("decrypt", 48, 32)])
            self.assertEqual([event["type"] for event in report["events"]
                              if event.get("event") == "managed_catch"],
                             ["System.ArgumentOutOfRangeException"] * 2)

            pe_bytes = (FIXTURES / "native_x86.exe").read_bytes()
            key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
            iv = bytes(range(16))
            pad = 16 - len(pe_bytes) % 16
            encrypted = AES.new(key, AES.MODE_CBC, iv=iv).encrypt(
                pe_bytes + bytes([pad]) * pad)
            aes = runner._framework("System.Security.Cryptography.Aes.Create", [], None, False)
            transform = runner._framework("System.Security.Cryptography.Aes.CreateDecryptor",
                                          [bytearray(key), bytearray(iv)], aes, False)
            first_count = len(encrypted) - 16
            output = bytearray(first_count)
            written = runner._framework(
                "System.Security.Cryptography.ICryptoTransform.TransformBlock",
                [bytearray(encrypted), 0, first_count, output, 0], transform, False)
            before = len(runner.catalog.items)
            last = runner._framework(
                "System.Security.Cryptography.ICryptoTransform.TransformFinalBlock",
                [bytearray(encrypted), first_count, 16], transform, False)
            self.assertEqual(output[:written] + last, pe_bytes)
            self.assertTrue(any(item["source"] == "managed_aes_plaintext" and
                                (self.root / "artifacts" / item["file"]).read_bytes() == pe_bytes
                                for item in runner.catalog.items[before:]))
            self.assertTrue(any(item["kind"] == "pe" and
                                item["source"].startswith("managed_aes_decrypt@") and
                                (self.root / "artifacts" / item["file"]).read_bytes() == pe_bytes
                                for item in runner.catalog.items[before:]))
        finally:
            host_marker.unlink()

    @unittest.skipUnless(shutil.which("dotnet"), ".NET SDK is unavailable")
    def test_managed_crypto_stream_uses_guest_streams_and_carves_pe(self):
        project = FIXTURES / "ManagedCryptoStream" / "ManagedCryptoStream.csproj"
        subprocess.run(["dotnet", "build", str(project), "-c", "Release"],
                       check=True, stdout=subprocess.DEVNULL)
        assembly = (FIXTURES / "ManagedCryptoStream" / "bin" / "Release" /
                    "net8.0" / "ManagedCryptoStream.dll")
        persona = dict(self.persona)
        persona["user_name"] = Path.home().name
        persona["hostname"] = f"TEST-{random.getrandbits(64):016X}"
        roaming = rf"C:\Users\{persona['user_name']}\AppData\Roaming"
        tag = f"emumee-cryptostream-{persona['hostname']}"
        host_roaming = Path.home() / "AppData" / "Roaming"
        if not host_roaming.is_dir():
            self.skipTest("Host Roaming AppData directory is unavailable")
        host_marker = host_roaming / f"{tag}-file.bin"
        self.assertFalse(host_marker.exists())
        host_marker.write_bytes(b"host private CryptoStream marker")
        try:
            data = assembly.read_bytes()
            runner = ManagedRunner(data, inspect_pe(data, assembly.name), persona,
                                   self.root, 750_000)
            result = runner.run(self.root)
            self.assertFalse(result["errors"], runner.events[-8:])
            recovered = [(item["guest_path"], (self.root / "artifacts" / item["file"]).read_bytes())
                         for item in result["artifacts"] if item.get("guest_path")]
            prefix = roaming + "\\" + tag
            plain = b"managed aes streaming payload verified!"
            cipher = bytes.fromhex(
                "d6d020609ad1bee66948a5a8ad2b7a122feba8a998d05e66"
                "c9452bd7d449c923b0b713abbcbb146cf3a7ab917e1d0637")
            self.assertEqual(recovered, [
                (prefix + "-read.bin", plain),
                (prefix + "-write.bin", cipher),
                (prefix + "-write-decrypt.bin", plain),
                (prefix + "-file.bin", plain[:32]),
                (prefix + "-file.bin", plain),
                (prefix + "-state.txt", b"cryptostream-ok;read;write;file;flush;leave-open"),
            ])
            self.assertEqual(host_marker.read_bytes(), b"host private CryptoStream marker")
            report = json.loads((self.root / result["engine_report"]).read_text())
            self.assertEqual(sum(event.get("event") == "managed_crypto_stream_open"
                                 for event in report["events"]), 4)
            self.assertEqual(sum(event.get("event") == "managed_crypto_stream_flush_final"
                                 for event in report["events"]), 3)
            self.assertEqual([event["type"] for event in report["events"]
                              if event.get("event") == "managed_catch"],
                             ["System.NotSupportedException"])

            pe_bytes = (FIXTURES / "native_x86.exe").read_bytes()
            key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
            iv = bytes(range(16))
            pad = 16 - len(pe_bytes) % 16
            encrypted = AES.new(key, AES.MODE_CBC, iv=iv).encrypt(
                pe_bytes + bytes([pad]) * pad)
            encrypted_stream = runner._framework(
                "System.IO.MemoryStream..ctor", [bytearray(encrypted)], None, True)
            aes = runner._framework("System.Security.Cryptography.Aes.Create", [], None, False)
            decryptor = runner._framework(
                "System.Security.Cryptography.Aes.CreateDecryptor",
                [bytearray(key), bytearray(iv)], aes, False)
            crypto = runner._framework(
                "System.Security.Cryptography.CryptoStream..ctor",
                [encrypted_stream, decryptor, 0, True], None, True)
            destination = runner._framework("System.IO.MemoryStream..ctor", [], None, True)
            before = len(runner.catalog.items)
            runner._framework("System.Security.Cryptography.CryptoStream.CopyTo",
                              [destination], crypto, False)
            decoded = runner._framework("System.IO.MemoryStream.ToArray", [], destination, False)
            self.assertEqual(decoded, pe_bytes)
            self.assertTrue(any(item["kind"] == "pe" and
                                item["source"].startswith("managed_aes_decrypt@") and
                                (self.root / "artifacts" / item["file"]).read_bytes() == pe_bytes
                                for item in runner.catalog.items[before:]))
        finally:
            host_marker.unlink()

    @unittest.skipUnless(shutil.which("dotnet"), ".NET SDK is unavailable")
    def test_managed_pbkdf2_derives_guest_aes_key_and_keeps_host_marker(self):
        project = FIXTURES / "ManagedPbkdf2" / "ManagedPbkdf2.csproj"
        subprocess.run(["dotnet", "build", str(project), "-c", "Release"],
                       check=True, stdout=subprocess.DEVNULL)
        assembly = (FIXTURES / "ManagedPbkdf2" / "bin" / "Release" /
                    "net8.0" / "ManagedPbkdf2.dll")
        persona = dict(self.persona)
        persona["user_name"] = Path.home().name
        persona["hostname"] = f"TEST-{random.getrandbits(64):016X}"
        roaming = rf"C:\Users\{persona['user_name']}\AppData\Roaming"
        tag = f"emumee-pbkdf2-{persona['hostname']}"
        host_roaming = Path.home() / "AppData" / "Roaming"
        if not host_roaming.is_dir():
            self.skipTest("Host Roaming AppData directory is unavailable")
        host_marker = host_roaming / f"{tag}-payload.bin"
        self.assertFalse(host_marker.exists())
        host_marker.write_bytes(b"host private PBKDF2 marker")
        try:
            data = assembly.read_bytes()
            runner = ManagedRunner(data, inspect_pe(data, assembly.name), persona,
                                   self.root, 750_000)
            result = runner.run(self.root)
            self.assertFalse(result["errors"], runner.events[-8:])
            recovered = [(item["guest_path"], (self.root / "artifacts" / item["file"]).read_bytes())
                         for item in result["artifacts"] if item.get("guest_path")]
            prefix = roaming + "\\" + tag
            self.assertEqual(recovered, [
                (prefix + "-payload.bin", b"PBKDF2 AES guest payload verified!"),
                (prefix + "-state.txt", b"pbkdf2-ok;sha1;sha256;reset;oneshot;catch"),
            ])
            self.assertEqual(host_marker.read_bytes(), b"host private PBKDF2 marker")
            report = json.loads((self.root / result["engine_report"]).read_text())
            self.assertEqual([event["type"] for event in report["events"]
                              if event.get("event") == "managed_catch"],
                             ["System.ArgumentOutOfRangeException"])
            self.assertFalse(any("blue-team-fixture" in str(event) for event in report["events"]
                                 if event.get("method", "").startswith(
                                     "System.Security.Cryptography.Rfc2898DeriveBytes.")))
            derive = runner._framework(
                "System.Security.Cryptography.Rfc2898DeriveBytes..ctor",
                ["blue-team-fixture", bytearray(range(1, 17)), 1000], None, True)
            expected_sha1 = bytes.fromhex(
                "7c4b200a28d6a8a9ee7c74e12808e8902cc1b46a"
                "c7406ea11944f0394f25b3d9ee8413f509997b09")
            self.assertEqual(runner._framework(
                "System.Security.Cryptography.Rfc2898DeriveBytes.GetBytes",
                [40], derive, False), expected_sha1)
            with self.assertRaisesRegex(UnsupportedManaged, "output exceeds limit"):
                runner._framework(
                    "System.Security.Cryptography.Rfc2898DeriveBytes.GetBytes",
                    [4097], derive, False)
            with self.assertRaisesRegex(UnsupportedManaged, "iteration count exceeds limit"):
                runner._framework(
                    "System.Security.Cryptography.Rfc2898DeriveBytes..ctor",
                    ["blue-team-fixture", bytearray(range(1, 17)), 1_000_001],
                    None, True)
            for algorithm in ("SHA384", "SHA512"):
                hash_name = runner._framework(
                    f"System.Security.Cryptography.HashAlgorithmName.get_{algorithm}",
                    [], None, False)
                state = runner._framework(
                    "System.Security.Cryptography.Rfc2898DeriveBytes..ctor",
                    ["blue-team-fixture", bytearray(range(1, 17)), 1000,
                     hash_name], None, True)
                self.assertEqual(runner._framework(
                    "System.Security.Cryptography.Rfc2898DeriveBytes.GetBytes",
                    [48], state, False), hashlib.pbkdf2_hmac(
                        algorithm.lower(), b"blue-team-fixture", bytes(range(1, 17)),
                        1000, 48))
            expensive = runner._framework(
                "System.Security.Cryptography.Rfc2898DeriveBytes..ctor",
                ["blue-team-fixture", bytearray(range(1, 17)), 1_000_000,
                 runner._framework(
                     "System.Security.Cryptography.HashAlgorithmName.get_SHA512",
                     [], None, False)], None, True)
            with self.assertRaisesRegex(UnsupportedManaged, "work exceeds limit"):
                runner._framework(
                    "System.Security.Cryptography.Rfc2898DeriveBytes.GetBytes",
                    [4096], expensive, False)
            md5 = runner._framework(
                "System.Security.Cryptography.HashAlgorithmName.get_MD5",
                [], None, False)
            with self.assertRaises(ManagedThrown):
                runner._framework(
                    "System.Security.Cryptography.Rfc2898DeriveBytes..ctor",
                    ["blue-team-fixture", bytearray(range(1, 17)), 1000, md5],
                    None, True)
        finally:
            host_marker.unlink()

    @unittest.skipUnless(shutil.which("dotnet"), ".NET SDK is unavailable")
    def test_managed_path_parts_use_guest_strings_and_leave_host_marker(self):
        project = FIXTURES / "ManagedPathParts" / "ManagedPathParts.csproj"
        subprocess.run(["dotnet", "build", str(project), "-c", "Release"],
                       check=True, stdout=subprocess.DEVNULL)
        assembly = (FIXTURES / "ManagedPathParts" / "bin" / "Release" /
                    "net8.0" / "ManagedPathParts.dll")
        persona = dict(self.persona)
        persona["user_name"] = Path.home().name
        persona["hostname"] = f"TEST-{random.getrandbits(64):016X}"
        roaming = rf"C:\Users\{persona['user_name']}\AppData\Roaming"
        tag = f"emumee-path-{persona['hostname']}"
        host_roaming = Path.home() / "AppData" / "Roaming"
        if not host_roaming.is_dir():
            self.skipTest("Host Roaming AppData directory is unavailable")
        host_marker = host_roaming / f"{tag}.dat"
        self.assertFalse(host_marker.exists())
        host_marker.write_bytes(b"host private path marker")
        try:
            data = assembly.read_bytes()
            runner = ManagedRunner(data, inspect_pe(data, assembly.name), persona,
                                   self.root, 500_000)
            result = runner.run(self.root)
            self.assertFalse(result["errors"], runner.events[-8:])
            recovered = {item["guest_path"]: (self.root / "artifacts" / item["file"]).read_bytes()
                         for item in result["artifacts"] if item.get("guest_path")}
            self.assertEqual(recovered, {
                roaming + "\\" + tag + ".dat": b"payload-path-parts",
                roaming + "\\" + tag + "-state.txt": b"parts-ok",
            })
            self.assertEqual(host_marker.read_bytes(), b"host private path marker")
            self.assertIsNone(runner._framework(
                "System.IO.Path.GetFileName", [None], None, False))
            self.assertIsNone(runner._framework(
                "System.IO.Path.GetDirectoryName", ["C:\\"], None, False))
            self.assertEqual(runner._framework(
                "System.IO.Path.ChangeExtension", [r"C:\stage\payload.bin", None],
                None, False), r"C:\stage\payload")
            self.assertEqual(runner._framework(
                "System.IO.Path.GetPathRoot", ["C:payload.bin"], None, False), "C:")
            with self.assertRaisesRegex(UnsupportedManaged, "UNC and device"):
                runner._framework("System.IO.Path.GetPathRoot",
                                  [r"\\server\share\file.bin"], None, False)
            with self.assertRaisesRegex(UnsupportedManaged, "argument exceeds limit"):
                runner._framework("System.IO.Path.GetFileName",
                                  ["x" * 4097], None, False)
            report = json.loads((self.root / result["engine_report"]).read_text())
            self.assertEqual(report["events"][-1]["event"], "file_write")
            self.assertEqual(result["cil_coverage"], report["cil_coverage"])
        finally:
            host_marker.unlink()

    @unittest.skipUnless(shutil.which("dotnet"), ".NET SDK is unavailable")
    def test_managed_environment_changes_stay_in_guest_process(self):
        project = FIXTURES / "ManagedEnvironment" / "ManagedEnvironment.csproj"
        subprocess.run(["dotnet", "build", str(project), "-c", "Release"],
                       check=True, stdout=subprocess.DEVNULL)
        assembly = (FIXTURES / "ManagedEnvironment" / "bin" / "Release" /
                    "net8.0" / "ManagedEnvironment.dll")
        persona = dict(self.persona)
        persona["user_name"] = Path.home().name
        persona["hostname"] = f"TEST-{random.getrandbits(64):016X}"
        roaming = rf"C:\Users\{persona['user_name']}\AppData\Roaming"
        tag = f"emumee-env-{persona['hostname']}"
        host_roaming = Path.home() / "AppData" / "Roaming"
        if not host_roaming.is_dir():
            self.skipTest("Host Roaming AppData directory is unavailable")
        host_marker = host_roaming / f"{tag}.txt"
        self.assertFalse(host_marker.exists())
        original_guest_var = os.environ.get("EMUMEE_GUEST_ONLY")
        original_user = os.environ.get("USERNAME")
        host_marker.write_bytes(b"host private environment marker")
        try:
            data = assembly.read_bytes()
            runner = ManagedRunner(data, inspect_pe(data, assembly.name), persona,
                                   self.root, 500_000)
            result = runner.run(self.root)
            self.assertFalse(result["errors"], runner.events[-8:])
            recovered = {item["guest_path"]: (self.root / "artifacts" / item["file"]).read_bytes()
                         for item in result["artifacts"] if item.get("guest_path")}
            self.assertEqual(recovered, {
                roaming + "\\" + tag + ".txt":
                    b"guest-value|%EMUMEE_MISSING%|guest-user",
                roaming + "\\" + tag + "-state.txt":
                    b"get-ok;path-ok;deleted;null-error;name-error",
            })
            self.assertEqual(host_marker.read_bytes(), b"host private environment marker")
            self.assertEqual(os.environ.get("EMUMEE_GUEST_ONLY"), original_guest_var)
            self.assertEqual(os.environ.get("USERNAME"), original_user)
            self.assertTrue(runner._framework("System.String.op_Equality",
                                              [None, None], None, False))
            self.assertTrue(runner._framework("System.String.op_Inequality",
                                              ["guest", "host"], None, False))
            self.assertIsNone(runner._framework(
                "System.Environment.GetEnvironmentVariable", ["EMUMEE_GUEST_ONLY"],
                None, False))
            with self.assertRaisesRegex(UnsupportedManaged, "Only process environment"):
                runner._framework("System.Environment.SetEnvironmentVariable",
                                  ["EMUMEE_GUEST_ONLY", "host", 1], None, False)
            with self.assertRaisesRegex(UnsupportedManaged, "value exceeds limit"):
                runner._framework("System.Environment.SetEnvironmentVariable",
                                  ["EMUMEE_GUEST_ONLY", "x" * 32_768], None, False)
            runner._framework("System.Environment.SetEnvironmentVariable",
                              ["EMUMEE_GUEST_ONLY", "x" * 16_384], None, False)
            with self.assertRaisesRegex(UnsupportedManaged, "expansion output exceeds limit"):
                runner._framework("System.Environment.ExpandEnvironmentVariables",
                                  ["%EMUMEE_GUEST_ONLY%" * 3], None, False)
            report = json.loads((self.root / result["engine_report"]).read_text())
            self.assertEqual([event["name"] for event in report["events"]
                              if event.get("event") == "environment_set"],
                             ["EMUMEE_GUEST_ONLY", "USERNAME", "EMUMEE_GUEST_ONLY"])
            self.assertEqual([event["type"] for event in report["events"]
                              if event.get("event") == "managed_catch"],
                             ["System.ArgumentNullException", "System.ArgumentException"])
        finally:
            host_marker.unlink()

    @unittest.skipUnless(shutil.which("dotnet"), ".NET SDK is unavailable")
    def test_managed_special_folders_use_persona_paths_without_host_writes(self):
        project = FIXTURES / "ManagedSpecialFolders" / "ManagedSpecialFolders.csproj"
        subprocess.run(["dotnet", "build", str(project), "-c", "Release"],
                       check=True, stdout=subprocess.DEVNULL)
        assembly = (FIXTURES / "ManagedSpecialFolders" / "bin" / "Release" /
                    "net8.0" / "ManagedSpecialFolders.dll")
        persona = dict(self.persona)
        persona["user_name"] = Path.home().name
        persona["hostname"] = f"TEST-{random.getrandbits(64):016X}"
        home = rf"C:\Users\{persona['user_name']}"
        roaming = home + r"\AppData\Roaming"
        local = home + r"\AppData\Local"
        startup = roaming + r"\Microsoft\Windows\Start Menu\Programs\Startup"
        tag = f"emumee-special-{persona['hostname']}"
        host_roaming = Path.home() / "AppData" / "Roaming"
        if not host_roaming.is_dir():
            self.skipTest("Host Roaming AppData directory is unavailable")
        host_marker = host_roaming / f"{tag}-roaming.txt"
        self.assertFalse(host_marker.exists())
        host_marker.write_bytes(b"host private marker")
        try:
            data = assembly.read_bytes()
            runner = ManagedRunner(data, inspect_pe(data, assembly.name), persona,
                                   self.root, 500_000)
            result = runner.run(self.root)
            self.assertFalse(result["errors"], runner.events[-8:])
            recovered = {item["guest_path"]: (self.root / "artifacts" / item["file"]).read_bytes()
                         for item in result["artifacts"] if item.get("guest_path")}
            self.assertEqual(recovered, {
                roaming + "\\" + tag + "-roaming.txt": b"roaming",
                local + "\\" + tag + "-local.txt": b"local",
                startup + "\\" + tag + "-startup.txt": b"startup",
                home + "\\Desktop\\" + tag + "-desktop.txt": b"desktop",
                home + "\\Documents\\" + tag + "-documents.txt": b"documents",
                home + "\\" + tag + "-profile.txt": b"profile",
                roaming + "\\" + tag + "-created.txt": roaming.encode(),
                roaming + "\\" + tag + "-unverified.txt": local.encode(),
                roaming + "\\" + tag + "-system.txt":
                    b"C:\\ProgramData|C:\\Windows|C:\\Windows\\System32|C:\\Program Files",
                roaming + "\\" + tag + "-state.txt":
                    b"folders-ok;invalid-folder;invalid-option",
            })
            self.assertEqual(host_marker.read_bytes(), b"host private marker")
            self.assertEqual(runner._framework("System.Environment.GetEnvironmentVariable",
                                               ["APPDATA"], None, False), roaming)
            with self.assertRaisesRegex(UnsupportedManaged, "Unsupported SpecialFolder"):
                runner._framework("System.Environment.GetFolderPath", [6], None, False)
            report = json.loads((self.root / result["engine_report"]).read_text())
            self.assertEqual(sum(event.get("event") == "special_folder"
                                 for event in report["events"]), 13)
            self.assertEqual([event["type"] for event in report["events"]
                              if event.get("event") == "managed_catch"],
                             ["System.ArgumentException"] * 2)
        finally:
            host_marker.unlink()

    @unittest.skipUnless(shutil.which("dotnet"), ".NET SDK is unavailable")
    def test_managed_file_streams_write_seek_read_and_share_guest_bytes(self):
        project = FIXTURES / "ManagedStreams" / "ManagedStreams.csproj"
        subprocess.run(["dotnet", "build", str(project), "-c", "Release"],
                       check=True, stdout=subprocess.DEVNULL)
        assembly = FIXTURES / "ManagedStreams" / "bin" / "Release" / "net8.0" / "ManagedStreams.dll"
        data = assembly.read_bytes()
        runner = ManagedRunner(data, inspect_pe(data, assembly.name), self.persona,
                               self.root, 500_000)
        result = runner.run(self.root)
        self.assertFalse(result["errors"])
        recovered = {item["guest_path"]: (self.root / "artifacts" / item["file"]).read_bytes()
                     for item in result["artifacts"]}
        base = r"C:\Users\Alex\Downloads\managed-stream-"
        self.assertEqual(recovered[base + "read.bin"], b"\0ABZD" + b"\0" * 5)
        self.assertEqual(recovered[base + "final.bin"], b"QBZDEF\0\0")
        self.assertEqual(recovered[base + "state.txt"], b"read-ok;share-denied;constructors-ok")
        self.assertEqual(runner.files[runner._file_key(base[:-1] + ".bin")], b"QBZDEF\0\0")
        report = json.loads((self.root / result["engine_report"]).read_text())
        self.assertEqual(sum(event.get("event") == "file_stream_open" for event in report["events"]), 5)
        self.assertEqual(sum(event.get("event") == "file_stream_close" for event in report["events"]), 5)
        self.assertTrue(all(stream["closed"] for stream in runner.file_streams))
        with self.assertRaises(ManagedThrown) as closed:
            runner._framework("System.IO.Stream.ReadByte", [], runner.file_streams[-1], False)
        self.assertEqual(closed.exception.value["__type"], "System.ObjectDisposedException")
        guest_file = base[:-1] + ".bin"
        reader = runner._framework("System.IO.File.OpenRead", [guest_file], None, False)
        self.assertEqual(runner._framework("System.IO.File.ReadAllBytes", [guest_file], None, False),
                         b"QBZDEF\0\0")
        for method, arguments in (("System.IO.File.Delete", [guest_file]),
                                  ("System.IO.File.WriteAllBytes", [guest_file, b"changed"])):
            with self.subTest(method=method), self.assertRaises(ManagedThrown) as denied:
                runner._framework(method, arguments, None, False)
            self.assertEqual(denied.exception.value["__type"], "System.IO.IOException")
        runner._framework("System.IO.Stream.Close", [], reader, False)
        writer = runner._framework("System.IO.File.OpenWrite", [guest_file], None, False)
        with self.assertRaises(ManagedThrown) as invalid_range:
            runner._framework("System.IO.Stream.Write", [bytearray(b"x"), -1, 1], writer, False)
        self.assertEqual(invalid_range.exception.value["__type"],
                         "System.ArgumentOutOfRangeException")
        runner._framework("System.IO.Stream.Close", [], writer, False)
        self.assertEqual(runner.files[runner._file_key(guest_file)], b"QBZDEF\0\0")
        appender = runner._framework("System.IO.FileStream..ctor", [guest_file, 6, 2, 0],
                                     None, True)
        with self.assertRaises(ManagedThrown) as before_append:
            runner._framework("System.IO.Stream.set_Position", [0], appender, False)
        self.assertEqual(before_append.exception.value["__type"], "System.IO.IOException")
        runner._framework("System.IO.Stream.WriteByte", [ord("!")], appender, False)
        runner._framework("System.IO.Stream.Close", [], appender, False)
        self.assertEqual(runner.files[runner._file_key(guest_file)], b"QBZDEF\0\0!")
        shared_delete = runner._framework("System.IO.FileStream..ctor", [guest_file, 3, 1, 5],
                                           None, True)
        with self.assertRaisesRegex(UnsupportedManaged, "Deleting an open managed FileStream"):
            runner._framework("System.IO.File.Delete", [guest_file], None, False)
        runner._framework("System.IO.Stream.Close", [], shared_delete, False)
        with patch("emumee.managed.MAX_FILE_STREAMS", 0):
            with self.assertRaisesRegex(UnsupportedManaged, "FileStream count exceeded"):
                runner._framework("System.IO.File.OpenRead", [guest_file], None, False)
        host_marker = self.root / "host-only-marker.bin"
        host_marker.write_bytes(b"host bytes stay private")
        with self.assertRaises(ManagedThrown):
            runner._framework("System.IO.File.OpenRead", [str(host_marker)], None, False)
        self.assertEqual(host_marker.read_bytes(), b"host bytes stay private")

    @unittest.skipUnless(shutil.which("dotnet"), ".NET SDK is unavailable")
    def test_managed_directories_enforce_parent_and_empty_delete(self):
        project = FIXTURES / "ManagedDirectories" / "ManagedDirectories.csproj"
        subprocess.run(["dotnet", "build", str(project), "-c", "Release"],
                       check=True, stdout=subprocess.DEVNULL)
        assembly = FIXTURES / "ManagedDirectories" / "bin" / "Release" / "net8.0" / "ManagedDirectories.dll"
        data = assembly.read_bytes()
        runner = ManagedRunner(data, inspect_pe(data, assembly.name), self.persona,
                               self.root, 100_000)
        result = runner.run(self.root)
        self.assertFalse(result["errors"])
        recovered = [(item["guest_path"], (self.root / "artifacts" / item["file"]).read_bytes())
                     for item in result["artifacts"]]
        self.assertEqual([payload for path, payload in recovered
                          if path.endswith("managed-dir-state.txt")],
                         [b"missing", b"missing parent", b"present", b"nonempty", b"deleted"])
        self.assertIn((r"C:\Users\Alex\Downloads\managed-dir\nested\payload.txt",
                       b"harmless managed directory marker"), recovered)
        self.assertFalse(any("managed-dir\\" in path for path in runner.files))
        self.assertNotIn(r"c:\users\alex\downloads\managed-dir", runner.directories)
        report = json.loads((self.root / result["engine_report"]).read_text())
        self.assertEqual([event["created"] for event in report["events"]
                          if event.get("event") == "directory_create"], [2])
        self.assertEqual(len([event for event in report["events"]
                              if event.get("event") == "directory_delete"]), 2)
        with self.assertRaises(ManagedThrown) as missing:
            runner._framework("System.IO.File.WriteAllText",
                              [r"C:\Users\Alex\Downloads\absent\out.txt", "x"], None, False)
        self.assertEqual(missing.exception.value["__type"], "System.IO.DirectoryNotFoundException")
        self.assertFalse(runner._framework("System.IO.File.Exists", [None], None, False))
        self.assertFalse(runner._framework("System.IO.File.Exists",
                                            [r"C:\Users\Alex\Downloads"], None, False))
        self.assertFalse(runner._framework("System.IO.Directory.Exists",
                                            [r"C:\Users\Alex\Documents\readme.txt"], None, False))
        with self.assertRaises(ManagedThrown) as collision:
            runner._framework("System.IO.Directory.CreateDirectory",
                              [r"C:\Users\Alex\Downloads\managed-dir-state.txt"], None, False)
        self.assertEqual(collision.exception.value["__type"], "System.IO.IOException")
        with patch("emumee.managed.MAX_GUEST_DIRECTORIES", len(runner.directories)):
            with self.assertRaisesRegex(UnsupportedManaged, "directory count exceeded"):
                runner._framework("System.IO.Directory.CreateDirectory",
                                  [r"C:\Users\Alex\Downloads\quota-dir"], None, False)
        with tempfile.TemporaryDirectory() as outside:
            marker = Path(outside) / "host-marker.txt"
            marker.write_text("private", encoding="utf-8")
            self.assertFalse(runner._framework("System.IO.Directory.Exists", [outside], None,
                                               False))
            runner._framework("System.IO.Directory.CreateDirectory", [outside], None, False)
            self.assertTrue(runner._framework("System.IO.Directory.Exists", [outside], None,
                                              False))
            self.assertEqual(marker.read_text(encoding="utf-8"), "private")

    @unittest.skipUnless(shutil.which("dotnet"), ".NET SDK is unavailable")
    def test_managed_recursive_delete_stays_in_guest_tree(self):
        project = FIXTURES / "ManagedRecursiveDelete" / "ManagedRecursiveDelete.csproj"
        subprocess.run(["dotnet", "build", str(project), "-c", "Release"],
                       check=True, stdout=subprocess.DEVNULL)
        assembly = (FIXTURES / "ManagedRecursiveDelete" / "bin" / "Release" /
                    "net8.0" / "ManagedRecursiveDelete.dll")
        data = assembly.read_bytes()
        runner = ManagedRunner(data, inspect_pe(data, assembly.name), self.persona,
                               self.root, 100_000)
        result = runner.run(self.root)
        self.assertFalse(result["errors"])
        recovered = [(item["guest_path"], (self.root / "artifacts" / item["file"]).read_bytes())
                     for item in result["artifacts"]]
        self.assertEqual([payload for path, payload in recovered
                          if path.endswith("managed-tree-state.txt")],
                         [b"created", b"nonrecursive denied", b"tree deleted",
                          b"missing denied", b"recreated"])
        self.assertIn((r"C:\Users\Alex\Downloads\managed-tree\nested\deeper\payload.txt",
                       b"harmless recursive payload"), recovered)
        self.assertNotIn(r"c:\users\alex\downloads\managed-tree\nested", runner.directories)
        self.assertNotIn(r"c:\users\alex\downloads\managed-tree\nested\deeper\payload.txt",
                         runner.files)
        self.assertEqual(runner.file_bytes, sum(map(len, runner.files.values())))
        report = json.loads((self.root / result["engine_report"]).read_text())
        deletes = [event for event in report["events"]
                   if event.get("event") == "directory_delete"]
        self.assertEqual(len(deletes), 1)
        self.assertEqual((deletes[0]["recursive"], deletes[0]["directories_removed"],
                          deletes[0]["files_removed"], deletes[0]["bytes_removed"]),
                         (True, 3, 1, len(b"harmless recursive payload")))

        host_dir = self.root / "host-target"
        host_dir.mkdir()
        marker = host_dir / "private.txt"
        marker.write_bytes(b"host private marker")
        guest_dir = str(host_dir)
        runner._framework("System.IO.Directory.CreateDirectory", [guest_dir], None, False)
        runner._framework("System.IO.File.WriteAllText",
                          [guest_dir + r"\guest.txt", "guest only"], None, False)
        runner._framework("System.IO.Directory.Delete", [guest_dir, True], None, False)
        self.assertEqual(marker.read_bytes(), b"host private marker")
        self.assertFalse(runner._framework("System.IO.Directory.Exists", [guest_dir], None,
                                            False))

        current_root = r"C:\Users\Alex\Downloads\current-tree"
        runner._framework("System.IO.Directory.CreateDirectory",
                          [current_root + r"\child"], None, False)
        runner._framework("System.IO.Directory.SetCurrentDirectory",
                          [current_root + r"\child"], None, False)
        with self.assertRaises(ManagedThrown) as current:
            runner._framework("System.IO.Directory.Delete", [current_root, True], None, False)
        self.assertEqual(current.exception.value["__type"], "System.IO.IOException")
        self.assertTrue(runner._framework("System.IO.Directory.Exists", [current_root], None,
                                           False))
        runner._framework("System.IO.Directory.SetCurrentDirectory",
                          [self.persona["current_dir"]], None, False)
        runner._framework("System.IO.Directory.Delete", [current_root, True], None, False)

    @unittest.skipUnless(shutil.which("dotnet"), ".NET SDK is unavailable")
    def test_managed_temp_and_current_directory_stay_virtual(self):
        project = FIXTURES / "ManagedPaths" / "ManagedPaths.csproj"
        subprocess.run(["dotnet", "build", str(project), "-c", "Release"],
                       check=True, stdout=subprocess.DEVNULL)
        assembly = FIXTURES / "ManagedPaths" / "bin" / "Release" / "net8.0" / "ManagedPaths.dll"
        data = assembly.read_bytes()
        host_cwd = Path.cwd()
        runner = ManagedRunner(data, inspect_pe(data, assembly.name), self.persona,
                               self.root, 100_000)
        result = runner.run(self.root)
        self.assertFalse(result["errors"])
        self.assertEqual(Path.cwd(), host_cwd)
        self.assertEqual(runner.current_dir, self.persona["current_dir"])
        recovered = {(item["guest_path"], (self.root / "artifacts" / item["file"]).read_bytes())
                     for item in result["artifacts"]}
        guest_temp = "C:\\Users\\Alex\\AppData\\Local\\Temp\\"
        stage = guest_temp + "emumee-stage"
        payload = b"harmless guest-relative marker"
        self.assertEqual(recovered, {
            ("relative.txt", payload),
            (r"C:\Users\Alex\Downloads\managed-temp-path.txt", guest_temp.encode()),
            (r"C:\Users\Alex\Downloads\managed-env-temp.txt", guest_temp.encode()),
            (r"C:\Users\Alex\Downloads\managed-current-dir.txt", stage.encode()),
            (r"C:\Users\Alex\Downloads\managed-relative-echo.txt", payload),
        })
        self.assertNotIn(stage.lower(), runner.directories)
        self.assertNotIn((stage + r"\relative.txt").lower(), runner.files)
        report = json.loads((self.root / result["engine_report"]).read_text())
        self.assertEqual([event["path"] for event in report["events"]
                          if event.get("event") == "current_directory"],
                         [stage, self.persona["current_dir"]])
        self.assertEqual(runner._framework("System.IO.Path.Combine",
                                           [r"C:\first", r"\rooted"], None, False),
                         r"\rooted")
        self.assertEqual(runner._framework("System.IO.Path.Combine",
                                           [r"C:\first", r"D:\second"], None, False),
                         r"D:\second")
        self.assertEqual(runner._framework("System.Environment.get_CurrentDirectory", [],
                                           None, False), self.persona["current_dir"])
        with self.assertRaises(ManagedThrown) as null_path:
            runner._framework("System.IO.Path.Combine", ["first", None], None, False)
        self.assertEqual(null_path.exception.value["__type"], "System.ArgumentNullException")
        with patch("emumee.managed.MAX_GUEST_PATH_CHARS", 10):
            with self.assertRaisesRegex(UnsupportedManaged, "combined path exceeds limit"):
                runner._framework("System.IO.Path.Combine", ["abcde", "fghij"], None,
                                  False)
        with self.assertRaises(ManagedThrown) as missing:
            runner._framework("System.IO.Directory.SetCurrentDirectory",
                              [r"C:\Users\Alex\Downloads\absent"], None, False)
        self.assertEqual(missing.exception.value["__type"], "System.IO.DirectoryNotFoundException")
        self.assertEqual(Path.cwd(), host_cwd)

    @unittest.skipUnless(shutil.which("dotnet"), ".NET SDK is unavailable")
    def test_managed_copy_move_capture_guest_bytes_and_collisions(self):
        project = FIXTURES / "ManagedTransfer" / "ManagedTransfer.csproj"
        subprocess.run(["dotnet", "build", str(project), "-c", "Release"],
                       check=True, stdout=subprocess.DEVNULL)
        assembly = FIXTURES / "ManagedTransfer" / "bin" / "Release" / "net8.0" / "ManagedTransfer.dll"
        data = assembly.read_bytes()
        runner = ManagedRunner(data, inspect_pe(data, assembly.name), self.persona,
                               self.root, 100_000)
        result = runner.run(self.root)
        self.assertFalse(result["errors"])
        source = r"C:\Users\Alex\Documents\readme.txt"
        target = r"C:\Users\Alex\Downloads\managed-target.txt"
        self.assertEqual(runner.files[source.lower()], b"Personal notes\n")
        self.assertEqual(runner.files[target.lower()], b"Personal notes\n")
        self.assertNotIn(r"c:\users\alex\downloads\managed-copy.txt", runner.files)
        self.assertNotIn(r"c:\users\alex\downloads\managed-moved.txt", runner.files)
        self.assertEqual(runner.file_bytes, sum(map(len, runner.files.values())))
        recovered = [(item["source"], item["guest_path"],
                      (self.root / "artifacts" / item["file"]).read_bytes())
                     for item in result["artifacts"]]
        self.assertIn(("managed_file_copy", r"C:\Users\Alex\Downloads\managed-copy.txt",
                       b"Personal notes\n"), recovered)
        self.assertIn(("managed_file_move", target, b"Personal notes\n"), recovered)
        self.assertIn(("managed_file_write", r"C:\Users\Alex\Downloads\managed-transfer-output.txt",
                       b"Personal notes\n"), recovered)
        self.assertEqual([payload for _, path, payload in recovered
                          if path.endswith("managed-transfer-state.txt")],
                         [b"copy collision", b"move collision", b"transferred"])
        report = json.loads((self.root / result["engine_report"]).read_text())
        self.assertEqual(len([event for event in report["events"]
                              if event.get("event") == "file_copy"]), 2)
        moves = [event for event in report["events"] if event.get("event") == "file_move"]
        self.assertEqual(len(moves), 3)
        self.assertTrue(moves[-1]["same_file"])
        with self.assertRaises(ManagedThrown) as same_copy:
            runner._framework("System.IO.File.Copy", [source, source, True], None, False)
        self.assertEqual(same_copy.exception.value["__type"], "System.IO.IOException")
        with self.assertRaises(ManagedThrown) as missing_parent:
            runner._framework("System.IO.File.Copy",
                              [source, r"C:\Users\Alex\Downloads\absent\payload.txt"],
                              None, False)
        self.assertEqual(missing_parent.exception.value["__type"],
                         "System.IO.DirectoryNotFoundException")
        with patch("emumee.managed.MAX_GUEST_FILE_BYTES", runner.file_bytes):
            with self.assertRaisesRegex(UnsupportedManaged, "storage exceeds"):
                runner._framework("System.IO.File.Copy",
                                  [source, r"C:\Users\Alex\Downloads\quota-copy.txt"],
                                  None, False)
        with tempfile.NamedTemporaryFile(delete=False) as outside:
            outside.write(b"host private marker")
            outside_path = Path(outside.name)
        try:
            with self.assertRaises(ManagedThrown):
                runner._framework("System.IO.File.Copy",
                                  [str(outside_path), r"C:\Users\Alex\Downloads\outside-copy.txt"],
                                  None, False)
            self.assertEqual(outside_path.read_bytes(), b"host private marker")
        finally:
            outside_path.unlink()

    @unittest.skipUnless(shutil.which("dotnet"), ".NET SDK is unavailable")
    def test_managed_file_attributes_block_guest_mutation_only(self):
        project = FIXTURES / "ManagedAttributes" / "ManagedAttributes.csproj"
        subprocess.run(["dotnet", "build", str(project), "-c", "Release"],
                       check=True, stdout=subprocess.DEVNULL)
        assembly = (FIXTURES / "ManagedAttributes" / "bin" / "Release" /
                    "net8.0" / "ManagedAttributes.dll")
        data = assembly.read_bytes()
        runner = ManagedRunner(data, inspect_pe(data, assembly.name), self.persona,
                               self.root, 100_000)
        result = runner.run(self.root)
        self.assertFalse(result["errors"])
        recovered = [(item["source"], item["guest_path"],
                      (self.root / "artifacts" / item["file"]).read_bytes())
                     for item in result["artifacts"]]
        self.assertEqual([payload for _, path, payload in recovered
                          if path.endswith("managed-attributes-state.txt")],
                         [b"source flags", b"append denied", b"delete denied",
                          b"copy flags", b"overwrite denied", b"directory hidden",
                          b"cleared"])
        self.assertIn(("managed_file_copy", r"C:\Users\Alex\Downloads\managed-attributes-copy.txt",
                       b"harmless attribute payload"), recovered)
        self.assertEqual(runner.file_bytes, sum(map(len, runner.files.values())))
        self.assertFalse(any("managed-attributes-source" in key or
                             "managed-attributes-copy" in key for key in runner.file_attributes))
        report = json.loads((self.root / result["engine_report"]).read_text())
        changes = [event for event in report["events"]
                   if event.get("event") == "file_attributes_set"]
        self.assertEqual([(event["attributes"], event["directory"]) for event in changes],
                         [(3, False), (128, False), (128, False), (18, True), (16, True)])

        marker = self.root / "host-private.txt"
        marker.write_bytes(b"host private marker")
        runner._framework("System.IO.Directory.CreateDirectory", [str(self.root)], None, False)
        runner._framework("System.IO.File.WriteAllText", [str(marker), "guest marker"], None, False)
        runner._framework("System.IO.File.SetAttributes", [str(marker), 1], None, False)
        with self.assertRaises(ManagedThrown) as denied:
            runner._framework("System.IO.File.Delete", [str(marker)], None, False)
        self.assertEqual(denied.exception.value["__type"], "System.UnauthorizedAccessException")
        self.assertEqual(marker.read_bytes(), b"host private marker")
        runner._framework("System.IO.File.SetAttributes", [str(marker), 128], None, False)
        runner._framework("System.IO.File.Delete", [str(marker)], None, False)
        self.assertEqual(marker.read_bytes(), b"host private marker")

        readonly = r"C:\Users\Alex\Downloads\managed-attributes-ro.txt"
        tree = r"C:\Users\Alex\Downloads\managed-attributes-tree"
        runner._framework("System.IO.Directory.CreateDirectory", [tree], None, False)
        runner._framework("System.IO.File.WriteAllText", [readonly, "source"], None, False)
        runner._framework("System.IO.File.WriteAllText", [tree + r"\child.txt", "child"], None, False)
        runner._framework("System.IO.File.SetAttributes", [tree + r"\child.txt", 1], None, False)
        with self.assertRaises(ManagedThrown) as recursive:
            runner._framework("System.IO.Directory.Delete", [tree, True], None, False)
        self.assertEqual(recursive.exception.value["__type"], "System.IO.IOException")
        self.assertTrue(runner._framework("System.IO.File.Exists", [tree + r"\child.txt"], None,
                                          False))
        runner._framework("System.IO.File.SetAttributes", [readonly, 1], None, False)
        with self.assertRaises(ManagedThrown) as copy_denied:
            runner._framework("System.IO.File.Copy", [tree + r"\child.txt", readonly, True],
                              None, False)
        self.assertEqual(copy_denied.exception.value["__type"],
                         "System.UnauthorizedAccessException")
        with self.assertRaisesRegex(UnsupportedManaged, "Unsupported managed file attributes"):
            runner._framework("System.IO.File.SetAttributes", [readonly, 0x40000000], None,
                              False)

    @unittest.skipUnless(shutil.which("dotnet"), ".NET SDK is unavailable")
    def test_managed_directory_enumeration_reads_guest_names_only(self):
        project = FIXTURES / "ManagedEnumeration" / "ManagedEnumeration.csproj"
        subprocess.run(["dotnet", "build", str(project), "-c", "Release"],
                       check=True, stdout=subprocess.DEVNULL)
        assembly = (FIXTURES / "ManagedEnumeration" / "bin" / "Release" /
                    "net8.0" / "ManagedEnumeration.dll")
        data = assembly.read_bytes()
        runner = ManagedRunner(data, inspect_pe(data, assembly.name), self.persona,
                               self.root, 100_000)
        result = runner.run(self.root)
        self.assertFalse(result["errors"])
        recovered = {item["guest_path"]: (self.root / "artifacts" / item["file"]).read_bytes()
                     for item in result["artifacts"]}
        prefix = r"C:\Users\Alex\Downloads\managed-enum-"
        root = r"C:\Users\Alex\Downloads\EnumStage"
        self.assertEqual(recovered[prefix + "top.txt"], (root + r"\beta.TXT").encode())
        self.assertEqual(recovered[prefix + "files.txt"].decode().splitlines(), [
            root + r"\beta.TXT", root + r"\Nested\Deep\delta.txt",
            root + r"\Nested\Gamma.txt"])
        self.assertEqual(recovered[prefix + "directories.txt"].decode().splitlines(), [
            root + r"\Nested", root + r"\Nested\Deep"])
        self.assertEqual(recovered[prefix + "all.txt"].decode().splitlines(), [
            root + r"\Alpha.bin", root + r"\beta.TXT", root + r"\Nested",
            root + r"\Nested\Deep", root + r"\Nested\Deep\delta.txt",
            root + r"\Nested\extensionless", root + r"\Nested\Gamma.txt"])
        self.assertEqual(recovered[prefix + "after.txt"], b"cleaned")
        self.assertEqual(runner._framework("System.IO.Directory.GetFiles",
                                            ["EnumStage", "*.bin"], None, False),
                         [r"EnumStage\Alpha.bin"])
        report = json.loads((self.root / result["engine_report"]).read_text())
        self.assertEqual([event["count"] for event in report["events"]
                          if event.get("event") == "directory_enumerate"], [1, 3, 2, 7, 1, 0])

        host_dir = self.root / "host-enum"
        host_dir.mkdir()
        marker = host_dir / "private.txt"
        marker.write_bytes(b"host private marker")
        with self.assertRaises(ManagedThrown) as missing:
            runner._framework("System.IO.Directory.GetFiles", [str(host_dir)], None, False)
        self.assertEqual(missing.exception.value["__type"],
                         "System.IO.DirectoryNotFoundException")
        runner._framework("System.IO.Directory.CreateDirectory", [str(host_dir)], None, False)
        runner._framework("System.IO.File.WriteAllText",
                          [str(host_dir / "guest.txt"), "guest only"], None, False)
        self.assertEqual(runner._framework("System.IO.Directory.GetFiles",
                                            [str(host_dir)], None, False),
                         [str(host_dir / "guest.txt")])
        self.assertEqual(marker.read_bytes(), b"host private marker")
        with self.assertRaisesRegex(UnsupportedManaged, "pattern path or syntax unsupported"):
            runner._framework("System.IO.Directory.GetFiles", [root, r"Nested\*.txt"],
                              None, False)
        with self.assertRaises(ManagedThrown) as invalid_option:
            runner._framework("System.IO.Directory.GetFiles", [root, "*", 2], None, False)
        self.assertEqual(invalid_option.exception.value["__type"],
                         "System.ArgumentOutOfRangeException")
        with patch("emumee.managed.MAX_DIRECTORY_ENUM_RESULTS", 0):
            with self.assertRaisesRegex(UnsupportedManaged, "enumeration exceeds limit"):
                runner._framework("System.IO.Directory.GetFiles", [root], None, False)

    @unittest.skipUnless(shutil.which("dotnet"), ".NET SDK is unavailable")
    def test_managed_loop_decodes_mutable_bytes(self):
        project = FIXTURES / "ManagedLoop" / "ManagedLoop.csproj"
        subprocess.run(["dotnet", "build", str(project), "-c", "Release"],
                       check=True, stdout=subprocess.DEVNULL)
        assembly = FIXTURES / "ManagedLoop" / "bin" / "Release" / "net8.0" / "ManagedLoop.dll"
        data = assembly.read_bytes()
        result = run_managed(data, inspect_pe(data, assembly.name), self.persona, self.root, 100_000)
        self.assertFalse(result["errors"])
        self.assertTrue(any((self.root / "artifacts" / item["file"]).read_bytes() == b"managed loop payload"
                            for item in result["artifacts"]))

    @unittest.skipUnless(shutil.which("dotnet"), ".NET SDK is unavailable")
    def test_managed_exceptions_follow_local_and_nested_catches(self):
        project = FIXTURES / "ManagedExceptions" / "ManagedExceptions.csproj"
        subprocess.run(["dotnet", "build", str(project), "-c", "Release"],
                       check=True, stdout=subprocess.DEVNULL)
        assembly = FIXTURES / "ManagedExceptions" / "bin" / "Release" / "net8.0" / "ManagedExceptions.dll"
        data = assembly.read_bytes()
        result = run_managed(data, inspect_pe(data, assembly.name), self.persona, self.root, 100_000)
        report = json.loads((self.root / result["engine_report"]).read_text())
        self.assertFalse(result["errors"])
        recovered = {(item["guest_path"], (self.root / "artifacts" / item["file"]).read_bytes())
                     for item in result["artifacts"]}
        self.assertEqual(recovered, {
            (r"C:\Users\Alex\Downloads\managed-caught.txt", b"managed catch marker"),
            (r"C:\Users\Alex\Downloads\managed-nested.txt", b"nested catch marker"),
            (r"C:\Users\Alex\Downloads\managed-format.txt", b"format catch marker"),
            (r"C:\Users\Alex\Downloads\managed-missing.txt", b"missing catch marker"),
            (r"C:\Users\Alex\Downloads\rethrow-inner.txt", b"inner rethrow marker"),
            (r"C:\Users\Alex\Downloads\rethrow-finally.txt", b"rethrow finally marker"),
            (r"C:\Users\Alex\Downloads\rethrow-outer.txt", b"outer rethrow marker")})
        self.assertEqual([event["type"] for event in report["events"]
                          if event.get("event") == "managed_catch"],
                         ["System.InvalidOperationException", "System.ArgumentException",
                          "System.FormatException", "System.IO.FileNotFoundException",
                          "System.InvalidOperationException", "System.InvalidOperationException"])
        self.assertEqual([event["event"] for event in report["events"]
                          if event.get("event") in {"managed_rethrow", "managed_finally"}],
                         ["managed_rethrow", "managed_finally"])

    @unittest.skipUnless(shutil.which("dotnet"), ".NET SDK is unavailable")
    def test_unhandled_managed_exception_is_reported_as_incomplete(self):
        project = FIXTURES / "ManagedUnhandled" / "ManagedUnhandled.csproj"
        subprocess.run(["dotnet", "build", str(project), "-c", "Release"],
                       check=True, stdout=subprocess.DEVNULL)
        assembly = FIXTURES / "ManagedUnhandled" / "bin" / "Release" / "net8.0" / "ManagedUnhandled.dll"
        data = assembly.read_bytes()
        result = run_managed(data, inspect_pe(data, assembly.name), self.persona, self.root, 100_000)
        self.assertEqual(result["errors"], [
            "Unhandled managed exception: System.InvalidOperationException"])
        self.assertEqual(len(result["artifacts"]), 1)
        self.assertEqual((self.root / "artifacts" / result["artifacts"][0]["file"]).read_bytes(),
                         b"unhandled finally marker")
        report = json.loads((self.root / result["engine_report"]).read_text())
        self.assertTrue(any(event.get("event") == "managed_finally" and
                            event.get("reason") == "exception" for event in report["events"]))

    @unittest.skipUnless(shutil.which("dotnet"), ".NET SDK is unavailable")
    def test_managed_finally_runs_on_leave_and_exception_unwind(self):
        project = FIXTURES / "ManagedFinally" / "ManagedFinally.csproj"
        subprocess.run(["dotnet", "build", str(project), "-c", "Release"],
                       check=True, stdout=subprocess.DEVNULL)
        assembly = FIXTURES / "ManagedFinally" / "bin" / "Release" / "net8.0" / "ManagedFinally.dll"
        data = assembly.read_bytes()
        result = run_managed(data, inspect_pe(data, assembly.name), self.persona, self.root, 100_000)
        report = json.loads((self.root / result["engine_report"]).read_text())
        self.assertFalse(result["errors"])
        recovered = {(item["guest_path"], (self.root / "artifacts" / item["file"]).read_bytes())
                     for item in result["artifacts"]}
        self.assertEqual(recovered, {
            (r"C:\Users\Alex\Downloads\before-finally.txt", b"before finally marker"),
            (r"C:\Users\Alex\Downloads\exception-finally.txt", b"exception finally marker"),
            (r"C:\Users\Alex\Downloads\after-finally.txt", b"outer catch marker"),
            (r"C:\Users\Alex\Downloads\cross-method-finally.txt", b"cross method finally marker"),
            (r"C:\Users\Alex\Downloads\cross-method-catch.txt", b"cross method catch marker"),
            (r"C:\Users\Alex\Downloads\inner-finally.txt", b"inner finally marker"),
            (r"C:\Users\Alex\Downloads\outer-finally.txt", b"outer finally marker"),
            (r"C:\Users\Alex\Downloads\after-nested-finally.txt", b"nested finally catch marker"),
            (r"C:\Users\Alex\Downloads\normal-inner-finally.txt", b"normal inner marker"),
            (r"C:\Users\Alex\Downloads\normal-outer-finally.txt", b"normal outer marker")})
        self.assertEqual(report["stdout"], ["finally marker", "normal nested marker"])
        self.assertEqual([e["reason"] for e in report["events"]
                          if e.get("event") == "managed_finally"],
                         ["leave", "exception", "exception", "exception", "nested",
                          "leave", "nested"])
        self.assertEqual([e["type"] for e in report["events"]
                          if e.get("event") == "managed_catch"],
                         ["System.InvalidOperationException", "System.ArgumentException",
                          "System.ApplicationException"])

    @unittest.skipUnless(shutil.which("dotnet"), ".NET SDK is unavailable")
    def test_invalid_managed_exception_region_is_rejected(self):
        project = FIXTURES / "ManagedFinally" / "ManagedFinally.csproj"
        subprocess.run(["dotnet", "build", str(project), "-c", "Release"],
                       check=True, stdout=subprocess.DEVNULL)
        assembly = FIXTURES / "ManagedFinally" / "bin" / "Release" / "net8.0" / "ManagedFinally.dll"
        data = assembly.read_bytes()

        def corrupt_handler(raw):
            body = read_method_body_from_bytes(raw)
            if body.exception_handlers:
                body.exception_handlers[0].handler_start = body.code_size + 1
            return body

        with patch("emumee.managed.read_method_body_from_bytes", side_effect=corrupt_handler):
            result = run_managed(data, inspect_pe(data, assembly.name), self.persona,
                                 self.root, 100_000)
        self.assertEqual(len(result["errors"]), 1)
        self.assertIn("Invalid managed exception region", result["errors"][0])
        self.assertEqual(result["artifacts"], [])

    @unittest.skipUnless(shutil.which("dotnet"), ".NET SDK is unavailable")
    def test_rethrow_outside_catch_is_rejected(self):
        project = FIXTURES / "ManagedHello" / "ManagedHello.csproj"
        subprocess.run(["dotnet", "build", str(project), "-c", "Release"],
                       check=True, stdout=subprocess.DEVNULL)
        assembly = FIXTURES / "ManagedHello" / "bin" / "Release" / "net8.0" / "ManagedHello.dll"
        data = assembly.read_bytes()

        def corrupt_instruction(raw):
            body = read_method_body_from_bytes(raw)
            body.instructions[0].opcode = OpCodes.Rethrow
            return body

        with patch("emumee.managed.read_method_body_from_bytes", side_effect=corrupt_instruction):
            result = run_managed(data, inspect_pe(data, assembly.name), self.persona,
                                 self.root, 100_000)
        self.assertEqual(result["errors"], ["Managed rethrow outside a catch handler"])
        self.assertEqual(result["artifacts"], [])

    @unittest.skipUnless(shutil.which("dotnet"), ".NET SDK is unavailable")
    def test_managed_instance_field_defaults_stay_in_guest(self):
        project = FIXTURES / "ManagedFieldDefaults" / "ManagedFieldDefaults.csproj"
        subprocess.run(["dotnet", "build", str(project), "-c", "Release"],
                       check=True, stdout=subprocess.DEVNULL)
        assembly = (FIXTURES / "ManagedFieldDefaults" / "bin" / "Release" /
                    "net8.0" / "ManagedFieldDefaults.dll")
        data = assembly.read_bytes()
        persona = dict(self.persona)
        persona["user_name"] = Path.home().name
        roaming = rf"C:\Users\{persona['user_name']}\AppData\Roaming"
        host_roaming = Path.home() / "AppData" / "Roaming"
        if not host_roaming.is_dir():
            self.skipTest("Host Roaming AppData directory is unavailable")
        host_marker = host_roaming / "managed-field-defaults.txt"
        self.assertFalse(host_marker.exists())
        host_marker.write_bytes(b"host defaults marker")
        self.addCleanup(host_marker.unlink)
        result = run_managed(data, inspect_pe(data, assembly.name), persona,
                             self.root, 100_000)
        self.assertFalse(result["errors"])
        self.assertEqual([(item["source"], item.get("guest_path"),
                           (self.root / "artifacts" / item["file"]).read_bytes())
                          for item in result["artifacts"]], [
            ("managed_file_write", roaming + r"\managed-field-defaults.txt",
             b"defaults-ok")])
        self.assertEqual(host_marker.read_bytes(), b"host defaults marker")
        field = lambda signature: SimpleNamespace(
            Signature=SimpleNamespace(value=signature))
        self.assertEqual(ManagedRunner._default_instance_field(field(b"\x06\x08")), 0)
        self.assertEqual(ManagedRunner._default_instance_field(field(b"\x06\x0d")), 0.0)
        self.assertIsNone(ManagedRunner._default_instance_field(field(b"\x06\x1d\x05")))
        self.assertIsNone(ManagedRunner._default_instance_field(field(b"\x06\x12\x05")))
        with self.assertRaisesRegex(UnsupportedManaged, "value-type"):
            ManagedRunner._default_instance_field(field(b"\x06\x11\x05"))
        with self.assertRaisesRegex(UnsupportedManaged, "Invalid managed field signature"):
            ManagedRunner._default_instance_field(field(b"\x06\x12"))
        with self.assertRaisesRegex(UnsupportedManaged, "Invalid managed field signature"):
            ManagedRunner._default_instance_field(field(b"\x06\x08\x00"))

    @unittest.skipUnless(shutil.which("dotnet"), ".NET SDK is unavailable")
    def test_managed_internal_virtual_methoddef_dispatch_and_null_receiver(self):
        project = FIXTURES / "ManagedInternalVirtual" / "ManagedInternalVirtual.csproj"
        subprocess.run(["dotnet", "build", str(project), "-c", "Release"],
                       check=True, stdout=subprocess.DEVNULL)
        assembly = (FIXTURES / "ManagedInternalVirtual" / "bin" / "Release" /
                    "net8.0" / "ManagedInternalVirtual.dll")
        data = assembly.read_bytes()
        persona = dict(self.persona)
        persona["user_name"] = Path.home().name
        roaming = rf"C:\Users\{persona['user_name']}\AppData\Roaming"
        host_roaming = Path.home() / "AppData" / "Roaming"
        if not host_roaming.is_dir():
            self.skipTest("Host Roaming AppData directory is unavailable")
        host_payload = host_roaming / "managed-internal-virtual-payload.txt"
        host_state = host_roaming / "managed-internal-virtual-state.txt"
        self.assertFalse(host_payload.exists())
        self.assertFalse(host_state.exists())
        host_payload.write_bytes(b"host internal payload marker")
        host_state.write_bytes(b"host internal state marker")
        self.addCleanup(host_payload.unlink)
        self.addCleanup(host_state.unlink)
        result = run_managed(data, inspect_pe(data, assembly.name), persona,
                             self.root, 100_000)
        self.assertFalse(result["errors"])
        recovered = [(item["source"], item.get("guest_path"),
                      (self.root / "artifacts" / item["file"]).read_bytes())
                     for item in result["artifacts"]]
        self.assertEqual(recovered, [
            ("managed_file_write", roaming + r"\managed-internal-virtual-payload.txt",
             b"derived"),
            ("managed_file_write", roaming + r"\managed-internal-virtual-state.txt",
             b"derived:base;base;fixed;base;null"),
        ])
        report = json.loads((self.root / result["engine_report"]).read_text())
        dispatches = [event for event in report["events"]
                      if event.get("event") == "managed_virtual_dispatch"]
        self.assertEqual(len(dispatches), 4)
        self.assertEqual(dispatches[0]["declared_method"], dispatches[1]["declared_method"])
        self.assertEqual(dispatches[0]["declared_method"], dispatches[3]["declared_method"])
        self.assertNotEqual(dispatches[0]["method"], dispatches[0]["declared_method"])
        self.assertTrue(all(event["method"] == event["declared_method"]
                            for event in dispatches[1:]))
        self.assertIn("System.NullReferenceException", [event.get("type")
            for event in report["events"] if event.get("event") == "managed_catch"])
        self.assertEqual(host_payload.read_bytes(), b"host internal payload marker")
        self.assertEqual(host_state.read_bytes(), b"host internal state marker")

    @unittest.skipUnless(shutil.which("dotnet"), ".NET SDK is unavailable")
    def test_managed_companion_virtual_dispatch_uses_guest_type_lineage(self):
        project = (FIXTURES / "ManagedVirtualCompanionLoader" /
                   "ManagedVirtualCompanionLoader.csproj")
        subprocess.run(["dotnet", "build", str(project), "-c", "Release"],
                       check=True, stdout=subprocess.DEVNULL)
        payload_path = (FIXTURES / "ManagedVirtualCompanionPayload" / "bin" / "Release" /
                        "net8.0" / "ManagedVirtualCompanionPayload.dll")
        loader_path = (FIXTURES / "ManagedVirtualCompanionLoader" / "bin" / "Release" /
                       "net8.0" / "ManagedVirtualCompanionLoader.dll")
        data, payload = loader_path.read_bytes(), payload_path.read_bytes()
        info = inspect_pe(data, loader_path.name)
        persona = dict(self.persona)
        persona["user_name"] = Path.home().name
        roaming = rf"C:\Users\{persona['user_name']}\AppData\Roaming"
        host_roaming = Path.home() / "AppData" / "Roaming"
        if not host_roaming.is_dir():
            self.skipTest("Host Roaming AppData directory is unavailable")
        host_payload = host_roaming / "managed-virtual-companion-payload.txt"
        host_state = host_roaming / "managed-virtual-companion-state.txt"
        self.assertFalse(host_payload.exists())
        self.assertFalse(host_state.exists())
        host_payload.write_bytes(b"host virtual payload marker")
        host_state.write_bytes(b"host virtual state marker")
        self.addCleanup(host_payload.unlink)
        self.addCleanup(host_state.unlink)
        result = run_managed(data, info, persona, self.root, 100_000,
                             companions=[(payload_path.name, payload)])
        self.assertFalse(result["errors"])
        recovered = [(item["source"], item.get("guest_path"),
                      (self.root / "artifacts" / item["file"]).read_bytes())
                     for item in result["artifacts"]]
        self.assertEqual(recovered, [
            ("managed_assembly_load", "", payload),
            ("managed_file_write", roaming + r"\managed-virtual-companion-payload.txt",
             b"derived"),
            ("managed_file_write", roaming + r"\managed-virtual-companion-state.txt",
             b"derived;base;fixed;base"),
        ])
        report = json.loads((self.root / result["engine_report"]).read_text())
        calls = [event for event in report["events"]
                 if event.get("event") == "managed_companion_call"]
        self.assertEqual([event["method"] for event in calls],
                         [".ctor", "Run", ".ctor", "Run", "Fixed", ".ctor", "Run"])
        self.assertNotEqual(calls[1]["dispatch_type_index"], calls[3]["dispatch_type_index"])
        self.assertEqual(calls[3]["dispatch_type_index"], calls[4]["dispatch_type_index"])
        self.assertEqual(calls[3]["dispatch_type_index"], calls[6]["dispatch_type_index"])
        self.assertEqual(host_payload.read_bytes(), b"host virtual payload marker")
        self.assertEqual(host_state.read_bytes(), b"host virtual state marker")
        with tempfile.TemporaryDirectory() as folder:
            absent = run_managed(data, info, persona, Path(folder), 100_000)
            self.assertEqual(absent["errors"], [
                "Unhandled managed exception: System.IO.FileNotFoundException"])
            self.assertEqual(absent["artifacts"], [])

    @unittest.skipUnless(shutil.which("dotnet"), ".NET SDK is unavailable")
    def test_managed_instance_companion_uses_guest_object_and_fields(self):
        project = (FIXTURES / "ManagedInstanceCompanionLoader" /
                   "ManagedInstanceCompanionLoader.csproj")
        subprocess.run(["dotnet", "build", str(project), "-c", "Release"],
                       check=True, stdout=subprocess.DEVNULL)
        payload_path = (FIXTURES / "ManagedInstanceCompanionPayload" / "bin" / "Release" /
                        "net8.0" / "ManagedInstanceCompanionPayload.dll")
        loader_path = (FIXTURES / "ManagedInstanceCompanionLoader" / "bin" / "Release" /
                       "net8.0" / "ManagedInstanceCompanionLoader.dll")
        data, payload = loader_path.read_bytes(), payload_path.read_bytes()
        info = inspect_pe(data, loader_path.name)
        persona = dict(self.persona)
        persona["user_name"] = Path.home().name
        roaming = rf"C:\Users\{persona['user_name']}\AppData\Roaming"
        host_roaming = Path.home() / "AppData" / "Roaming"
        if not host_roaming.is_dir():
            self.skipTest("Host Roaming AppData directory is unavailable")
        host_payload = host_roaming / "managed-instance-companion-payload.txt"
        host_state = host_roaming / "managed-instance-companion-state.txt"
        self.assertFalse(host_payload.exists())
        self.assertFalse(host_state.exists())
        host_payload.write_bytes(b"host instance payload marker")
        host_state.write_bytes(b"host instance state marker")
        self.addCleanup(host_payload.unlink)
        self.addCleanup(host_state.unlink)
        result = run_managed(data, info, persona, self.root, 100_000,
                             companions=[(payload_path.name, payload)])
        self.assertFalse(result["errors"])
        recovered = [(item["source"], item.get("guest_path"),
                      (self.root / "artifacts" / item["file"]).read_bytes())
                     for item in result["artifacts"]]
        self.assertEqual(recovered, [
            ("managed_assembly_load", "", payload),
            ("managed_file_write", roaming + r"\managed-instance-companion-payload.txt",
             b"guest instance ran"),
            ("managed_file_write", roaming + r"\managed-instance-companion-state.txt",
             b"guest instance ran;null"),
        ])
        report = json.loads((self.root / result["engine_report"]).read_text())
        self.assertEqual([event["method"] for event in report["events"]
                          if event.get("event") == "managed_companion_call"],
                         [".ctor", "Run"])
        self.assertIn("System.NullReferenceException", [event.get("type")
            for event in report["events"] if event.get("event") == "managed_catch"])
        self.assertTrue(any(event.get("event") == "managed_object_create" and
                            event.get("via") == "newobj" for event in report["events"]))
        self.assertEqual(host_payload.read_bytes(), b"host instance payload marker")
        self.assertEqual(host_state.read_bytes(), b"host instance state marker")
        with tempfile.TemporaryDirectory() as folder:
            absent = run_managed(data, info, persona, Path(folder), 100_000)
            self.assertEqual(absent["errors"], [
                "Unhandled managed exception: System.IO.FileNotFoundException"])
            self.assertEqual(absent["artifacts"], [])
        wrong_project = (FIXTURES / "ManagedWrongInstanceCompanion" /
                         "ManagedWrongInstanceCompanion.csproj")
        subprocess.run(["dotnet", "build", str(wrong_project), "-c", "Release"],
                       check=True, stdout=subprocess.DEVNULL)
        wrong_path = (FIXTURES / "ManagedWrongInstanceCompanion" / "bin" / "Release" /
                      "net8.0" / "ManagedInstanceCompanionPayload.dll")
        with tempfile.TemporaryDirectory() as folder:
            wrong = run_managed(data, info, persona, Path(folder), 100_000,
                                companions=[("wrong.dll", wrong_path.read_bytes())])
            self.assertEqual(wrong["errors"], [
                "Unhandled managed exception: System.MissingMethodException"])
            self.assertFalse(any(item["source"] == "managed_file_write"
                                 for item in wrong["artifacts"]))

    @unittest.skipUnless(shutil.which("dotnet"), ".NET SDK is unavailable")
    def test_managed_static_companion_reference_uses_only_supplied_bytes(self):
        project = (FIXTURES / "ManagedStaticCompanionLoader" /
                   "ManagedStaticCompanionLoader.csproj")
        subprocess.run(["dotnet", "build", str(project), "-c", "Release"],
                       check=True, stdout=subprocess.DEVNULL)
        payload_path = (FIXTURES / "ManagedCompanionPayload" / "bin" / "Release" /
                        "net8.0" / "ManagedCompanionPayload.dll")
        loader_path = (FIXTURES / "ManagedStaticCompanionLoader" / "bin" / "Release" /
                       "net8.0" / "ManagedStaticCompanionLoader.dll")
        data, payload = loader_path.read_bytes(), payload_path.read_bytes()
        info = inspect_pe(data, loader_path.name)
        persona = dict(self.persona)
        persona["user_name"] = Path.home().name
        roaming = rf"C:\Users\{persona['user_name']}\AppData\Roaming"
        host_roaming = Path.home() / "AppData" / "Roaming"
        if not host_roaming.is_dir():
            self.skipTest("Host Roaming AppData directory is unavailable")
        host_payload = host_roaming / "managed-companion-payload.txt"
        host_state = host_roaming / "managed-static-companion-state.txt"
        self.assertFalse(host_payload.exists())
        self.assertFalse(host_state.exists())
        host_payload.write_bytes(b"host payload marker")
        host_state.write_bytes(b"host static marker")
        self.addCleanup(host_payload.unlink)
        self.addCleanup(host_state.unlink)
        result = run_managed(data, info, persona, self.root, 100_000,
                             companions=[(payload_path.name, payload)])
        self.assertFalse(result["errors"])
        recovered = [(item["source"], item.get("guest_path"),
                      (self.root / "artifacts" / item["file"]).read_bytes())
                     for item in result["artifacts"]]
        self.assertEqual(recovered, [
            ("managed_assembly_load", "", payload),
            ("managed_file_write", roaming + r"\managed-companion-payload.txt",
             b"guest companion ran"),
            ("managed_file_write", roaming + r"\managed-static-companion-state.txt",
             b"static companion ran"),
        ])
        report = json.loads((self.root / result["engine_report"]).read_text())
        self.assertEqual([event["method"] for event in report["events"]
                          if event.get("event") == "managed_companion_call"], ["Run"])
        self.assertEqual(host_payload.read_bytes(), b"host payload marker")
        self.assertEqual(host_state.read_bytes(), b"host static marker")
        with tempfile.TemporaryDirectory() as folder:
            absent = run_managed(data, info, persona, Path(folder), 100_000)
            self.assertEqual(absent["errors"], [
                "Unhandled managed exception: System.IO.FileNotFoundException"])
            self.assertEqual(absent["artifacts"], [])
        wrong_project = FIXTURES / "ManagedWrongCompanion" / "ManagedWrongCompanion.csproj"
        subprocess.run(["dotnet", "build", str(wrong_project), "-c", "Release"],
                       check=True, stdout=subprocess.DEVNULL)
        wrong_path = (FIXTURES / "ManagedWrongCompanion" / "bin" / "Release" /
                      "net8.0" / "ManagedCompanionPayload.dll")
        with tempfile.TemporaryDirectory() as folder:
            wrong = run_managed(data, info, persona, Path(folder), 100_000,
                                companions=[("wrong.dll", wrong_path.read_bytes())])
            self.assertEqual(wrong["errors"], [
                "Unhandled managed exception: System.MissingMethodException"])
            self.assertFalse(any(item["source"] == "managed_file_write"
                                 for item in wrong["artifacts"]))

    @unittest.skipUnless(shutil.which("dotnet"), ".NET SDK is unavailable")
    def test_managed_named_companion_loads_only_supplied_guest_bytes(self):
        payload_project = FIXTURES / "ManagedCompanionPayload" / "ManagedCompanionPayload.csproj"
        loader_project = FIXTURES / "ManagedCompanionLoader" / "ManagedCompanionLoader.csproj"
        for project in (payload_project, loader_project):
            subprocess.run(["dotnet", "build", str(project), "-c", "Release"],
                           check=True, stdout=subprocess.DEVNULL)
        payload_path = (FIXTURES / "ManagedCompanionPayload" / "bin" / "Release" /
                        "net8.0" / "ManagedCompanionPayload.dll")
        loader_path = (FIXTURES / "ManagedCompanionLoader" / "bin" / "Release" /
                       "net8.0" / "ManagedCompanionLoader.dll")
        data = loader_path.read_bytes()
        payload = payload_path.read_bytes()
        persona = dict(self.persona)
        persona["user_name"] = Path.home().name
        roaming = rf"C:\Users\{persona['user_name']}\AppData\Roaming"
        host_roaming = Path.home() / "AppData" / "Roaming"
        if not host_roaming.is_dir():
            self.skipTest("Host Roaming AppData directory is unavailable")
        host_payload = host_roaming / "managed-companion-payload.txt"
        host_state = host_roaming / "managed-companion-state.txt"
        self.assertFalse(host_payload.exists())
        self.assertFalse(host_state.exists())
        host_payload.write_bytes(b"host payload marker")
        host_state.write_bytes(b"host state marker")
        self.addCleanup(host_payload.unlink)
        self.addCleanup(host_state.unlink)
        info = inspect_pe(data, loader_path.name)
        companions = [(payload_path.name, payload)]
        result = run_managed(data, info, persona, self.root, 100_000,
                             companions=companions)
        self.assertFalse(result["errors"])
        recovered = [(item["source"], item.get("guest_path"),
                      (self.root / "artifacts" / item["file"]).read_bytes())
                     for item in result["artifacts"]]
        self.assertEqual(recovered, [
            ("managed_assembly_load", "", payload),
            ("managed_file_write", roaming + r"\managed-companion-payload.txt",
             b"guest companion ran"),
            ("managed_file_write", roaming + r"\managed-companion-state.txt",
             b"loaded;missing"),
        ])
        self.assertEqual(host_payload.read_bytes(), b"host payload marker")
        self.assertEqual(host_state.read_bytes(), b"host state marker")
        report = json.loads((self.root / result["engine_report"]).read_text())
        self.assertEqual([(event["filename"], event["assembly"])
                          for event in report["events"]
                          if event.get("event") == "managed_companion_load"],
                         [(payload_path.name, "ManagedCompanionPayload")])
        self.assertIn("System.IO.FileNotFoundException", [event.get("type")
            for event in report["events"] if event.get("event") == "managed_catch"])

        runner = ManagedRunner(data, info, persona, self.root, 100_000,
                               companions=companions)
        first = runner._load_assembly(["ManagedCompanionPayload"])
        self.assertIs(first, runner._load_assembly(["managedcompanionpayload"]))
        with self.assertRaises(ManagedThrown) as absent:
            runner._load_assembly(["HostOnlyNeverLoad"])
        self.assertEqual(absent.exception.value["__type"],
                         "System.IO.FileNotFoundException")
        with self.assertRaisesRegex(UnsupportedManaged, "Qualified managed assembly"):
            runner._load_assembly(["ManagedCompanionPayload, Version=1.0.0.0"])
        with self.assertRaisesRegex(UnsupportedManaged, "Ambiguous"):
            ManagedRunner(data, info, persona, self.root, 100_000,
                          companions=[(payload_path.name, payload), ("duplicate.dll", payload)])
        with self.assertRaisesRegex(UnsupportedManaged, "Invalid managed companion"):
            ManagedRunner(data, info, persona, self.root, 100_000,
                          companions=[("broken.dll", b"not a PE")])

    @unittest.skipUnless(shutil.which("dotnet"), ".NET SDK is unavailable")
    def test_managed_reflection_loads_and_invokes_guest_assembly(self):
        builder = FIXTURES / "ManagedReflect" / "build_fixture.py"
        subprocess.run([shutil.which("python") or "python", str(builder)],
                       check=True, stdout=subprocess.DEVNULL)
        assembly = FIXTURES / "ManagedReflect" / "bin" / "Release" / "net8.0" / "ManagedReflect.dll"
        payload_path = FIXTURES / "ManagedPayload" / "bin" / "Release" / "net8.0" / "ManagedPayload.dll"
        executable_path = FIXTURES / "ManagedPayloadExe" / "bin" / "Release" / "net8.0" / "ManagedPayloadExe.dll"
        data = assembly.read_bytes()
        payload = payload_path.read_bytes()
        executable = executable_path.read_bytes()
        info = inspect_pe(data, assembly.name)
        result = run_managed(data, info, self.persona, self.root, 100_000)
        self.assertFalse(result["errors"])
        recovered = [(item["source"], (self.root / "artifacts" / item["file"]).read_bytes())
                     for item in result["artifacts"]]
        self.assertEqual([entry for entry in recovered
                          if not entry[0].startswith("managed_array:")], [
            ("managed_assembly_load", payload),
            ("managed_file_write", b"harmless reflected stage"),
            ("managed_file_write", b"harmless reflected internal"),
            ("managed_assembly_load", executable),
            ("managed_file_write", b"harmless reflected exe"),
        ])
        self.assertEqual({entry[1] for entry in recovered
                          if entry[0].startswith("managed_array:")},
                         {payload, executable})
        report = json.loads((self.root / result["engine_report"]).read_text())
        self.assertEqual(report["stdout"], ["instance returned", "instance returned"])
        self.assertEqual([e["event"] for e in report["events"]
                          if e["event"] in {"managed_assembly_load", "managed_reflect_invoke"}],
                         ["managed_assembly_load", "managed_reflect_invoke",
                          "managed_reflect_invoke", "managed_assembly_load", "managed_reflect_invoke"])
        self.assertEqual([e["via"] for e in report["events"]
                          if e["event"] == "managed_object_create"],
                         ["activator", "newobj"])

        runner = ManagedRunner(data, info, self.persona, self.root, 100_000)
        with self.assertRaises(ManagedThrown) as bad_image:
            runner._load_assembly([b"not a PE"])
        self.assertEqual(bad_image.exception.value["__type"], "System.BadImageFormatException")
        handle = runner._load_assembly([payload])
        self.assertIsNone(runner._reflect_entry_point(handle))
        self.assertIsNone(runner._reflect_type(handle, "Missing.Type"))
        typ = runner._reflect_type(handle, "Payload.Stage")
        self.assertIsNone(runner._reflect_method(typ, "Missing"))
        method = runner._reflect_method(typ, "Run")
        with self.assertRaisesRegex(UnsupportedManaged, "target does not match"):
            runner._invoke_reflected(method, [None, None])
        instance = runner._create_instance([typ])
        self.assertEqual(instance["fields"], {1: "harmless reflected"})
        with patch("emumee.managed.MAX_MANAGED_OBJECTS", runner.objects_created), self.assertRaisesRegex(
                UnsupportedManaged, "object allocation limit"):
            runner._create_instance([typ])
        with self.assertRaisesRegex(UnsupportedManaged, "arguments do not match"):
            runner._invoke_reflected(method, [instance, None])
        self.assertEqual(runner._invoke_reflected(method, [instance, [" stage"]]),
                         "instance returned")
        executable_handle = runner._load_assembly([executable])
        self.assertEqual(runner._reflect_entry_point(executable_handle)["module_id"], 2)
        with patch("emumee.managed.MAX_LOADED_ASSEMBLIES", 2), self.assertRaisesRegex(
                UnsupportedManaged, "load limit"):
            runner._load_assembly([payload])

    @unittest.skipUnless(shutil.which("dotnet"), ".NET SDK is unavailable")
    def test_managed_growth_stops_before_large_string_allocation(self):
        project = FIXTURES / "ManagedGrowth" / "ManagedGrowth.csproj"
        subprocess.run(["dotnet", "build", str(project), "-c", "Release"],
                       check=True, stdout=subprocess.DEVNULL)
        assembly = FIXTURES / "ManagedGrowth" / "bin" / "Release" / "net8.0" / "ManagedGrowth.dll"
        data = assembly.read_bytes()
        info = inspect_pe(data, assembly.name)
        with patch("emumee.managed.MAX_ARTIFACT", 256):
            result = run_managed(data, info, self.persona, self.root, 100_000)
        self.assertEqual(result["errors"], ["Managed string exceeds 32 MiB"])
        self.assertEqual(result["artifacts"], [])
        report = json.loads((self.root / result["engine_report"]).read_text())
        self.assertLess(report["instructions"], 100_000)
        self.assertLess((self.root / result["engine_report"]).stat().st_size, 32_000)

    @unittest.skipUnless(shutil.which("dotnet"), ".NET SDK is unavailable")
    def test_managed_trace_stdout_and_guest_file_budgets(self):
        project = FIXTURES / "ManagedStaticArray" / "ManagedStaticArray.csproj"
        subprocess.run(["dotnet", "build", str(project), "-c", "Release"],
                       check=True, stdout=subprocess.DEVNULL)
        assembly = FIXTURES / "ManagedStaticArray" / "bin" / "Release" / "net8.0" / "ManagedStaticArray.dll"
        data = assembly.read_bytes()
        runner = ManagedRunner(data, inspect_pe(data, assembly.name),
                               self.persona, self.root, 100_000)
        self.assertLess(len(runner._safe_repr("x" * 1_000_000)), 300)
        with patch("emumee.managed.MAX_ARTIFACT", 32):
            with self.assertRaisesRegex(UnsupportedManaged, "Managed string exceeds"):
                runner._framework("System.String.Concat", ["x" * 20, "y" * 20], None, False)
            with self.assertRaisesRegex(UnsupportedManaged, "Managed string exceeds"):
                runner._framework("System.String.Replace", ["x", "xx"], "x" * 20, False)
            with self.assertRaisesRegex(UnsupportedManaged, "Base64 output exceeds"):
                runner._framework("System.Convert.ToBase64String", [b"x" * 25], None, False)
            with self.assertRaisesRegex(UnsupportedManaged, "UTF-8 value exceeds"):
                runner._framework("System.Text.Encoding.GetBytes", ["\U0001F642" * 9],
                                  {"encoding": "utf-8"}, False)
        with patch("emumee.managed.MAX_STDOUT_CHARS", 10):
            runner._framework("System.Console.Write", ["123456"], None, False)
            with self.assertRaisesRegex(UnsupportedManaged, "stdout limit"):
                runner._framework("System.Console.Write", ["12345"], None, False)
        self.assertEqual(runner.stdout, ["123456"])
        with patch("emumee.managed.MAX_MANAGED_EVENTS", 1):
            runner._record_event({"event": "test"})
            with self.assertRaisesRegex(UnsupportedManaged, "event limit"):
                runner._record_event({"event": "test"})
        runner.files.clear()
        runner.file_bytes = 0
        with patch("emumee.managed.MAX_GUEST_FILE_BYTES", 10):
            runner._store_file("C:\\first.bin", b"123456")
            with self.assertRaisesRegex(UnsupportedManaged, "storage exceeds"):
                runner._store_file("C:\\second.bin", b"12345")
        self.assertEqual(runner.file_bytes, 6)
        self.assertNotIn("c:\\second.bin", runner.files)

    @unittest.skipUnless(shutil.which("dotnet"), ".NET SDK is unavailable")
    def test_managed_switch_jumps_to_guest_branch(self):
        project = FIXTURES / "ManagedSwitch" / "ManagedSwitch.csproj"
        subprocess.run(["dotnet", "build", str(project), "-c", "Release"],
                       check=True, stdout=subprocess.DEVNULL)
        assembly = FIXTURES / "ManagedSwitch" / "bin" / "Release" / "net8.0" / "ManagedSwitch.dll"
        data = assembly.read_bytes()
        info = inspect_pe(data, assembly.name)
        result = run_managed(data, info, self.persona, self.root, 100_000)
        self.assertFalse(result["errors"])
        self.assertEqual(len(result["artifacts"]), 1)
        item = result["artifacts"][0]
        self.assertEqual((self.root / "artifacts" / item["file"]).read_bytes(), b"five")

        original = read_method_body_from_bytes

        def corrupt_switch(raw):
            body = original(raw)
            for ins in body.instructions:
                if ins.mnemonic == "switch":
                    ins.operand[5] = 0x7FFFFFFF
            return body

        with tempfile.TemporaryDirectory() as bad_dir, patch(
                "emumee.managed.read_method_body_from_bytes", side_effect=corrupt_switch):
            bad = run_managed(data, info, self.persona, Path(bad_dir), 100_000)
        self.assertEqual(bad["errors"], ["Invalid managed switch target"])
        self.assertEqual(bad["artifacts"], [])

    @unittest.skipUnless(shutil.which("dotnet"), ".NET SDK is unavailable")
    def test_managed_static_array_is_initialized_from_assembly_and_bounded(self):
        project = FIXTURES / "ManagedStaticArray" / "ManagedStaticArray.csproj"
        subprocess.run(["dotnet", "build", str(project), "-c", "Release"],
                       check=True, stdout=subprocess.DEVNULL)
        assembly = FIXTURES / "ManagedStaticArray" / "bin" / "Release" / "net8.0" / "ManagedStaticArray.dll"
        data = assembly.read_bytes()
        info = inspect_pe(data, assembly.name)
        result = run_managed(data, info, self.persona, self.root, 100_000)
        self.assertFalse(result["errors"])
        self.assertEqual(len(result["artifacts"]), 1)
        item = result["artifacts"][0]
        payload = b"Managed static array payload marker.\n"
        self.assertEqual((self.root / "artifacts" / item["file"]).read_bytes(), payload)
        self.assertEqual(item["sha256"], hashlib.sha256(payload).hexdigest())
        report = json.loads((self.root / result["engine_report"]).read_text())
        self.assertIn({"event": "managed_array_init", "size": len(payload)}, report["events"])

        with tempfile.TemporaryDirectory() as limited_dir, patch("emumee.managed.MAX_ARTIFACT", 16):
            limited = run_managed(data, info, self.persona, Path(limited_dir), 100_000)
        self.assertEqual(limited["errors"], ["Managed array length exceeds limit for System.Byte"])
        self.assertEqual(limited["artifacts"], [])

    @unittest.skipUnless(shutil.which("dotnet"), ".NET SDK is unavailable")
    def test_managed_gzip_payload_is_bounded_and_recovered(self):
        project = FIXTURES / "ManagedGzip" / "ManagedGzip.csproj"
        subprocess.run(["dotnet", "build", str(project), "-c", "Release"],
                       check=True, stdout=subprocess.DEVNULL)
        assembly = FIXTURES / "ManagedGzip" / "bin" / "Release" / "net8.0" / "ManagedGzip.dll"
        data = assembly.read_bytes()
        info = inspect_pe(data, assembly.name)
        result = run_managed(data, info, self.persona, self.root, 100_000)
        self.assertFalse(result["errors"])
        payload = b"harmless managed gzip payload"
        self.assertTrue(any(item["source"] == "managed_gzip_decompress"
                            and (self.root / "artifacts" / item["file"]).read_bytes() == payload
                            for item in result["artifacts"]))
        self.assertTrue(any(item["source"] == "managed_file_write"
                            and (self.root / "artifacts" / item["file"]).read_bytes() == payload
                            for item in result["artifacts"]))
        deflate_payload = b"harmless managed deflate payload"
        self.assertTrue(any(item["source"] == "managed_deflate_decompress"
                            and (self.root / "artifacts" / item["file"]).read_bytes() == deflate_payload
                            for item in result["artifacts"]))
        runner = ManagedRunner(data, info, self.persona, self.root, 100_000)
        source = runner._framework("System.IO.MemoryStream..ctor",
                                   [bytearray(gzip.compress(b"x" * 33))], None, True)
        stream = runner._framework("System.IO.Compression.GZipStream..ctor",
                                   [source, 0], None, True)
        target = runner._framework("System.IO.MemoryStream..ctor", [], None, True)
        with patch("emumee.managed.MAX_ARTIFACT", 32), self.assertRaisesRegex(
                UnsupportedManaged, "exceeds"):
            runner._framework("System.IO.Stream.CopyTo", [target], stream, False)

    @unittest.skipUnless(shutil.which("dotnet"), ".NET SDK is unavailable")
    def test_managed_zip_extracts_guest_payloads_and_denies_traversal(self):
        project = FIXTURES / "ManagedZip" / "ManagedZip.csproj"
        subprocess.run(["dotnet", "build", str(project), "-c", "Release"],
                       check=True, stdout=subprocess.DEVNULL)
        assembly = (FIXTURES / "ManagedZip" / "bin" / "Release" /
                    "net8.0" / "ManagedZip.dll")
        persona = dict(self.persona)
        persona["user_name"] = Path.home().name
        persona["hostname"] = f"TEST-{random.getrandbits(64):016X}"
        roaming = rf"C:\Users\{persona['user_name']}\AppData\Roaming"
        tag = f"emumee-zip-{persona['hostname']}"
        host_roaming = Path.home() / "AppData" / "Roaming"
        if not host_roaming.is_dir():
            self.skipTest("Host Roaming AppData directory is unavailable")
        host_destination = host_roaming / tag
        self.assertFalse(host_destination.exists())
        host_destination.mkdir()
        host_marker = host_destination / "payload.bin"
        host_marker.write_bytes(b"host private ZIP marker")
        try:
            data = assembly.read_bytes()
            runner = ManagedRunner(data, inspect_pe(data, assembly.name), persona,
                                   self.root, 750_000)
            result = runner.run(self.root)
            self.assertFalse(result["errors"], runner.events[-8:])
            recovered = [(item["guest_path"], (self.root / "artifacts" / item["file"]).read_bytes())
                         for item in result["artifacts"] if item.get("guest_path")]
            prefix = roaming + "\\" + tag
            self.assertEqual([(path, payload) for path, payload in recovered
                              if path.endswith(("payload.bin", "readme.txt", "-state.txt"))], [
                (prefix + "\\payload.bin", b"zip guest payload verified!"),
                (prefix + "\\nested\\readme.txt", b"nested guest file"),
                (prefix + "-memory\\payload.bin", b"zip guest payload verified!"),
                (prefix + "-memory\\nested\\readme.txt", b"nested guest file"),
                (prefix + "-filestream\\payload.bin", b"zip guest payload verified!"),
                (prefix + "-filestream\\nested\\readme.txt", b"nested guest file"),
                (prefix + "-state.txt",
                 b"zip-ok;nested;overwrite;streams;traversal-denied;malformed-denied"),
            ])
            self.assertEqual(host_marker.read_bytes(), b"host private ZIP marker")
            self.assertFalse((host_roaming / "escape.bin").exists())
            report = json.loads((self.root / result["engine_report"]).read_text())
            self.assertEqual([event["files"] for event in report["events"]
                              if event.get("event") == "managed_zip_extract"], [2, 2, 2, 2])
            self.assertEqual([event["type"] for event in report["events"]
                              if event.get("event") == "managed_catch"],
                             ["System.IO.IOException", "System.IO.IOException",
                              "System.IO.InvalidDataException"])
            good = next(payload for path, payload in recovered if path.endswith("-source.zip"))
            with zipfile.ZipFile(BytesIO(good)) as archive:
                self.assertEqual(archive.namelist(), ["payload.bin", "nested/readme.txt"])
                self.assertEqual(archive.read("payload.bin"), b"zip guest payload verified!")

            pe_bytes = (FIXTURES / "native_x86.exe").read_bytes()
            packed = BytesIO()
            with zipfile.ZipFile(packed, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("nested/payload.exe", pe_bytes)
            guest_source = prefix + "-pe.zip"
            guest_target = prefix + "-pe"
            runner._framework("System.IO.File.WriteAllBytes",
                              [guest_source, bytearray(packed.getvalue())], None, False)
            before = len(runner.catalog.items)
            runner._framework("System.IO.Compression.ZipFile.ExtractToDirectory",
                              [guest_source, guest_target], None, False)
            self.assertTrue(any(item["kind"] == "pe" and
                                item["guest_path"] == guest_target + "\\nested\\payload.exe" and
                                (self.root / "artifacts" / item["file"]).read_bytes() == pe_bytes
                                for item in runner.catalog.items[before:]))
            with patch("emumee.managed.MAX_ZIP_ENTRIES", 1):
                with self.assertRaisesRegex(UnsupportedManaged, "entry count exceeds"):
                    runner._framework("System.IO.Compression.ZipFile.ExtractToDirectory",
                                      [prefix + "-source.zip", prefix + "-entry-limit"],
                                      None, False)
            with patch("emumee.managed.MAX_ZIP_OUTPUT", 8):
                with self.assertRaisesRegex(UnsupportedManaged, "output exceeds"):
                    runner._framework("System.IO.Compression.ZipFile.ExtractToDirectory",
                                      [guest_source, prefix + "-output-limit"], None, False)

            crowded = BytesIO()
            with zipfile.ZipFile(crowded, "w") as archive:
                for index in range(1025):
                    archive.writestr(f"entry-{index:04d}", b"")
            crowded_path = prefix + "-crowded.zip"
            runner._framework("System.IO.File.WriteAllBytes",
                              [crowded_path, bytearray(crowded.getvalue())], None, False)
            with patch("emumee.managed.zipfile.ZipFile",
                       side_effect=AssertionError("ZIP parser reached")):
                with self.assertRaisesRegex(UnsupportedManaged, "entry count exceeds"):
                    runner._framework("System.IO.Compression.ZipFile.ExtractToDirectory",
                                      [crowded_path, prefix + "-crowded"], None, False)
                with patch("emumee.managed.MAX_ZIP_CENTRAL_BYTES", 10):
                    with self.assertRaisesRegex(UnsupportedManaged, "central directory exceeds"):
                        runner._framework("System.IO.Compression.ZipFile.ExtractToDirectory",
                                          [prefix + "-source.zip", prefix + "-central-limit"],
                                          None, False)
                mismatched = bytearray(good)
                end = mismatched.rfind(b"PK\x05\x06")
                mismatched[end + 8:end + 12] = b"\x01\x00\x01\x00"
                mismatch_path = prefix + "-mismatch.zip"
                runner._framework("System.IO.File.WriteAllBytes",
                                  [mismatch_path, mismatched], None, False)
                with self.assertRaises(ManagedThrown) as malformed:
                    runner._framework("System.IO.Compression.ZipFile.ExtractToDirectory",
                                      [mismatch_path, prefix + "-mismatch"], None, False)
                self.assertEqual(malformed.exception.value["__type"],
                                 "System.IO.InvalidDataException")

            polyglot = BytesIO()
            with zipfile.ZipFile(polyglot, "w") as archive:
                archive.writestr("payload.bin", b"prefixed guest archive")
                archive.comment = b"comment " + b"PK\x05\x06" + b"\0" * 18 + b" tail"
            polyglot_path = prefix + "-prefixed.zip"
            runner._framework("System.IO.File.WriteAllBytes",
                              [polyglot_path, bytearray(b"MZ-stub" + polyglot.getvalue())],
                              None, False)
            runner._framework("System.IO.Compression.ZipFile.ExtractToDirectory",
                              [polyglot_path, prefix + "-prefixed"], None, False)
            self.assertEqual(runner.files[runner._file_key(prefix + "-prefixed\\payload.bin")],
                             b"prefixed guest archive")
        finally:
            host_marker.unlink()
            host_destination.rmdir()

    @unittest.skipUnless(shutil.which("dotnet"), ".NET SDK is unavailable")
    def test_managed_zip_entry_open_stays_in_guest_and_recovers_pe(self):
        project = FIXTURES / "ManagedZipEntry" / "ManagedZipEntry.csproj"
        subprocess.run(["dotnet", "build", str(project), "-c", "Release"],
                       check=True, stdout=subprocess.DEVNULL)
        assembly = (FIXTURES / "ManagedZipEntry" / "bin" / "Release" /
                    "net8.0" / "ManagedZipEntry.dll")
        data = assembly.read_bytes()
        persona = dict(self.persona)
        persona["user_name"] = Path.home().name
        persona["hostname"] = f"TEST-{random.getrandbits(64):016X}"
        host_roaming = Path.home() / "AppData" / "Roaming"
        if not host_roaming.is_dir():
            self.skipTest("Host Roaming AppData directory is unavailable")
        host_marker = host_roaming / f"emumee-zipentry-{persona['hostname']}.zip"
        self.assertFalse(host_marker.exists())
        host_marker.write_bytes(b"host private ZIP marker")
        self.addCleanup(host_marker.unlink)
        runner = ManagedRunner(data, inspect_pe(data, assembly.name), persona,
                               self.root, 750_000)
        result = runner.run(self.root)
        self.assertFalse(result["errors"], runner.events[-8:])
        self.assertEqual(host_marker.read_bytes(), b"host private ZIP marker")
        artifacts = [(item, (self.root / "artifacts" / item["file"]).read_bytes())
                     for item in result["artifacts"]]
        self.assertTrue(any(item["source"] == "managed_zip_entry_open" and
                            content == b"zip guest payload verified!"
                            for item, content in artifacts))
        self.assertTrue(any(item.get("guest_path", "").endswith("-state.txt") and
                            content == b"zip-entry-ok" for item, content in artifacts))
        self.assertEqual([event["name"] for event in runner.events
                          if event.get("event") == "managed_zip_entry_open"],
                         ["payload.bin", "nested/readme.txt"])
        for method in ("get_Entries", "get_Count", "get_Item", "GetEnumerator",
                       "MoveNext", "get_Current"):
            self.assertTrue(any(name.endswith(method) for name in runner.framework_call_counts),
                            method)
        self.assertGreaterEqual(runner.opcode_counts.get("cgt.un", 0), 2)

        pe_bytes = (FIXTURES / "native_x86.exe").read_bytes()
        packed = BytesIO()
        with zipfile.ZipFile(packed, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("nested/payload.exe", pe_bytes)
        memory = runner._framework("System.IO.MemoryStream..ctor",
                                   [bytearray(packed.getvalue())], None, True)
        opened = runner._framework("System.IO.Compression.ZipArchive..ctor",
                                   [memory, 0, True], None, True)
        entries = runner._framework("System.IO.Compression.ZipArchive.get_Entries",
                                    [], opened, False)
        self.assertEqual(runner._framework("get_Count", [], entries, False), 1)
        with self.assertRaises(ManagedThrown) as bad_index:
            runner._framework("get_Item", [1], entries, False)
        self.assertEqual(bad_index.exception.value["__type"],
                         "System.ArgumentOutOfRangeException")
        enumerator = runner._framework("GetEnumerator", [], entries, False)
        with self.assertRaises(ManagedThrown) as premature:
            runner._framework("get_Current", [], enumerator, False)
        self.assertEqual(premature.exception.value["__type"],
                         "System.InvalidOperationException")
        self.assertTrue(runner._framework("MoveNext", [], enumerator, False))
        self.assertFalse(runner._framework("MoveNext", [], enumerator, False))
        entry = runner._framework("System.IO.Compression.ZipArchive.GetEntry",
                                  ["nested/payload.exe"], opened, False)
        self.assertEqual(runner._framework("System.IO.Compression.ZipArchiveEntry.get_Length",
                                           [], entry, False), len(pe_bytes))
        before = len(runner.catalog.items)
        stream = runner._framework("System.IO.Compression.ZipArchiveEntry.Open",
                                   [], entry, False)
        self.assertTrue(any(item["kind"] == "pe" and item["source"] == "managed_zip_entry_open"
                            and (self.root / "artifacts" / item["file"]).read_bytes() == pe_bytes
                            for item in runner.catalog.items[before:]))
        self.assertEqual(bytes(runner._framework("System.IO.MemoryStream.ToArray",
                                                 [], stream, False)), pe_bytes)
        runner._framework("System.IO.Compression.ZipArchive.Dispose", [], opened, False)
        self.assertFalse(memory["closed"])
        with self.assertRaises(ManagedThrown) as closed:
            runner._framework("System.IO.Compression.ZipArchiveEntry.Open", [], entry, False)
        self.assertEqual(closed.exception.value["__type"], "System.ObjectDisposedException")
        runner._framework("System.IO.MemoryStream.set_Position", [0], memory, False)
        with patch("emumee.managed.MAX_ZIP_OUTPUT", 8), self.assertRaisesRegex(
                UnsupportedManaged, "output exceeds"):
            runner._framework("System.IO.Compression.ZipArchive..ctor",
                              [memory, 0, True], None, True)

    @unittest.skipUnless(shutil.which("dotnet"), ".NET SDK is unavailable")
    def test_managed_zip_stage_loads_and_invokes_only_in_guest(self):
        builder = FIXTURES / "ManagedZipStage" / "build_fixture.py"
        subprocess.run([shutil.which("python") or "python", str(builder)],
                       check=True, stdout=subprocess.DEVNULL)
        assembly = (FIXTURES / "ManagedZipStage" / "bin" / "Release" /
                    "net8.0" / "ManagedZipStage.dll")
        payload_path = (FIXTURES / "ManagedZipStagePayload" / "bin" / "Release" /
                        "net8.0" / "ManagedZipStagePayload.dll")
        persona = dict(self.persona)
        persona["user_name"] = Path.home().name
        persona["hostname"] = f"TEST-{random.getrandbits(64):016X}"
        roaming = rf"C:\Users\{persona['user_name']}\AppData\Roaming"
        host_roaming = Path.home() / "AppData" / "Roaming"
        if not host_roaming.is_dir():
            self.skipTest("Host Roaming AppData directory is unavailable")
        payload_name = f"zip-stage-payload-{persona['hostname']}.txt"
        state_name = f"zip-stage-state-{persona['hostname']}.txt"
        host_payload = host_roaming / payload_name
        host_state = host_roaming / state_name
        self.assertFalse(host_payload.exists())
        self.assertFalse(host_state.exists())
        host_payload.write_bytes(b"host payload marker")
        host_state.write_bytes(b"host state marker")
        self.addCleanup(host_payload.unlink)
        self.addCleanup(host_state.unlink)
        data = assembly.read_bytes()
        stage = payload_path.read_bytes()
        encoded = (FIXTURES / "ManagedZipStage" / "EmbeddedArchive.cs").read_text(
            encoding="utf-8").split('"')[1]
        with zipfile.ZipFile(BytesIO(base64.b64decode(encoded))) as embedded:
            self.assertEqual(embedded.namelist(), ["notes.txt",
                                                   "stage/ManagedZipStagePayload.dll"])
            self.assertEqual(embedded.read("stage/ManagedZipStagePayload.dll"), stage)
        result = run_managed(data, inspect_pe(data, assembly.name), persona,
                             self.root, 750_000)
        self.assertFalse(result["errors"])
        self.assertEqual(result["engine"], "emumee-cil")
        recovered = [(item["source"], item.get("guest_path", ""),
                      (self.root / "artifacts" / item["file"]).read_bytes())
                     for item in result["artifacts"]]
        self.assertEqual([entry for entry in recovered
                          if not entry[0].startswith("managed_array:")], [
            ("managed_zip_entry_open", "", stage),
            ("managed_assembly_load", "", stage),
            ("managed_file_write", roaming + "\\" + payload_name,
             b"harmless ZIP-loaded stage"),
            ("managed_file_write", roaming + "\\" + state_name,
             b"zip-stage-ok"),
        ])
        self.assertEqual({entry[2] for entry in recovered
                          if entry[0].startswith("managed_array:")}, {stage})
        self.assertEqual(host_payload.read_bytes(), b"host payload marker")
        self.assertEqual(host_state.read_bytes(), b"host state marker")
        report = json.loads((self.root / result["engine_report"]).read_text())
        self.assertEqual([event["event"] for event in report["events"]
                          if event["event"] in {"managed_zip_entry_open",
                                                "managed_assembly_load",
                                                "managed_reflect_invoke"}],
                         ["managed_zip_entry_open", "managed_assembly_load",
                          "managed_reflect_invoke"])

    @unittest.skipUnless(shutil.which("dotnet"), ".NET SDK is unavailable")
    def test_managed_zlib_reads_guest_file_incrementally(self):
        project = FIXTURES / "ManagedZlib" / "ManagedZlib.csproj"
        subprocess.run(["dotnet", "build", str(project), "-c", "Release"],
                       check=True, stdout=subprocess.DEVNULL)
        assembly = (FIXTURES / "ManagedZlib" / "bin" / "Release" /
                    "net8.0" / "ManagedZlib.dll")
        persona = dict(self.persona)
        persona["user_name"] = Path.home().name
        persona["hostname"] = f"TEST-{random.getrandbits(64):016X}"
        roaming = rf"C:\Users\{persona['user_name']}\AppData\Roaming"
        tag = f"emumee-zlib-{persona['hostname']}"
        host_roaming = Path.home() / "AppData" / "Roaming"
        if not host_roaming.is_dir():
            self.skipTest("Host Roaming AppData directory is unavailable")
        host_marker = host_roaming / f"{tag}-payload.bin"
        self.assertFalse(host_marker.exists())
        host_marker.write_bytes(b"host private zlib marker")
        try:
            data = assembly.read_bytes()
            runner = ManagedRunner(data, inspect_pe(data, assembly.name), persona,
                                   self.root, 750_000)
            result = runner.run(self.root)
            self.assertFalse(result["errors"], runner.events[-8:])
            plain = b"zlib guest payload verified!" + bytes(range(128))
            compressed = zlib.compress(plain)
            prefix = roaming + "\\" + tag
            recovered = [(item["guest_path"], (self.root / "artifacts" / item["file"]).read_bytes())
                         for item in result["artifacts"] if item.get("guest_path")]
            self.assertEqual(recovered, [
                (prefix + "-source.bin", compressed),
                (prefix + "-payload.bin", plain),
                (prefix + "-state.txt",
                 b"zlib-ok;partial-read;file;leave-open;invalid-catch"),
            ])
            self.assertTrue(any(item["source"] == "managed_zlib_decompress" and
                                (self.root / "artifacts" / item["file"]).read_bytes() == plain
                                for item in result["artifacts"]))
            self.assertEqual(host_marker.read_bytes(), b"host private zlib marker")
            report = json.loads((self.root / result["engine_report"]).read_text())
            self.assertEqual([event["format"] for event in report["events"]
                              if event.get("event") == "managed_decompress"], ["zlib"])
            self.assertEqual([event["type"] for event in report["events"]
                              if event.get("event") == "managed_catch"],
                             ["System.IO.InvalidDataException"])
        finally:
            host_marker.unlink()

    @unittest.skipUnless(shutil.which("dotnet"), ".NET SDK is unavailable")
    def test_managed_static_fields_initialize_once_and_stay_guest_only(self):
        project = FIXTURES / "ManagedStaticFields" / "ManagedStaticFields.csproj"
        subprocess.run(["dotnet", "build", str(project), "-c", "Release"],
                       check=True, stdout=subprocess.DEVNULL)
        assembly = project.parent / "bin" / "Release" / "net8.0" / "ManagedStaticFields.dll"
        data = assembly.read_bytes()
        persona = dict(self.persona)
        persona["user_name"] = Path.home().name
        roaming = rf"C:\Users\{persona['user_name']}\AppData\Roaming"
        host_roaming = Path.home() / "AppData" / "Roaming"
        if not host_roaming.is_dir():
            self.skipTest("Host Roaming AppData directory is unavailable")
        markers = [host_roaming / name for name in
                   ("managed-static-cctor.txt", "managed-static-state.txt")]
        for marker in markers:
            self.assertFalse(marker.exists())
            marker.write_bytes(b"host static marker")
            self.addCleanup(marker.unlink)
        result = run_managed(data, inspect_pe(data, assembly.name), persona,
                             self.root, 100_000)
        self.assertFalse(result["errors"], result["errors"])
        recovered = [(item["guest_path"], (self.root / "artifacts" / item["file"]).read_bytes())
                     for item in result["artifacts"]]
        self.assertEqual(recovered, [(roaming + "\\managed-static-cctor.txt", b"initialized"),
                                     (roaming + "\\managed-static-state.txt", b"static-ok")])
        for marker in markers:
            self.assertEqual(marker.read_bytes(), b"host static marker")
        report = json.loads((self.root / result["engine_report"]).read_text())
        events = [event for event in report["events"] if event.get("event") == "managed_type_init"]
        self.assertEqual([event["type"] for event in events], ["ExplicitStage", "InlineStage"])
        counts = {item["opcode"]: item["count"] for item in
                  report["cil_coverage"]["top_opcodes"]}
        self.assertGreaterEqual(counts.get("ldsfld", 0), 5)
        self.assertGreaterEqual(counts.get("stsfld", 0), 3)
        runner = ManagedRunner(data, inspect_pe(data, assembly.name), persona,
                               self.root, 100_000)
        with self.assertRaisesRegex(UnsupportedManaged, "Invalid managed static field token"):
            runner._static_field(0x040FFFFF)
        with self.assertRaisesRegex(UnsupportedManaged, "Invalid managed static field token"):
            runner._static_field(0x06000001)

    @unittest.skipUnless(shutil.which("dotnet"), ".NET SDK is unavailable")
    def test_managed_companion_static_fields_resolve_without_host_access(self):
        project = FIXTURES / "ManagedStaticFieldCompanionLoader" / "ManagedStaticFieldCompanionLoader.csproj"
        subprocess.run(["dotnet", "build", str(project), "-c", "Release"],
                       check=True, stdout=subprocess.DEVNULL)
        assembly = project.parent / "bin" / "Release" / "net8.0" / "ManagedStaticFieldCompanionLoader.dll"
        payload_path = (FIXTURES / "ManagedStaticFieldCompanionPayload" / "bin" /
                        "Release" / "net8.0" / "ManagedStaticFieldCompanionPayload.dll")
        data, payload = assembly.read_bytes(), payload_path.read_bytes()
        info = inspect_pe(data, assembly.name)
        persona = dict(self.persona)
        persona["user_name"] = Path.home().name
        roaming = rf"C:\Users\{persona['user_name']}\AppData\Roaming"
        host_roaming = Path.home() / "AppData" / "Roaming"
        if not host_roaming.is_dir():
            self.skipTest("Host Roaming AppData directory is unavailable")
        markers = [host_roaming / name for name in
                   ("managed-companion-static-init.txt", "managed-companion-static-state.txt")]
        for marker in markers:
            self.assertFalse(marker.exists())
            marker.write_bytes(b"host companion static marker")
            self.addCleanup(marker.unlink)
        result = run_managed(data, info, persona, self.root, 100_000,
                             companions=[(payload_path.name, payload)])
        self.assertFalse(result["errors"], result["errors"])
        recovered = [(item["source"], item.get("guest_path"),
                      (self.root / "artifacts" / item["file"]).read_bytes())
                     for item in result["artifacts"]]
        self.assertEqual(recovered, [
            ("managed_assembly_load", "", payload),
            ("managed_file_write", roaming + r"\managed-companion-static-init.txt", b"initialized"),
            ("managed_file_write", roaming + r"\managed-companion-static-state.txt",
             b"companion-static-ok"),
        ])
        report = json.loads((self.root / result["engine_report"]).read_text())
        self.assertEqual([(event["module_id"], event["type"]) for event in report["events"]
                          if event.get("event") == "managed_type_init"], [(1, "StaticFieldPayload.SharedStage")])
        for marker in markers:
            self.assertEqual(marker.read_bytes(), b"host companion static marker")
        with tempfile.TemporaryDirectory() as absent_root:
            absent = run_managed(data, info, persona, Path(absent_root), 100_000)
            self.assertEqual(absent["errors"],
                             ["Unhandled managed exception: System.IO.FileNotFoundException"])
            self.assertEqual(absent["artifacts"], [])
        wrong_project = FIXTURES / "ManagedStaticFieldCompanionWrong" / "ManagedStaticFieldCompanionWrong.csproj"
        subprocess.run(["dotnet", "build", str(wrong_project), "-c", "Release"],
                       check=True, stdout=subprocess.DEVNULL)
        wrong_path = wrong_project.parent / "bin" / "Release" / "net8.0" / payload_path.name
        with tempfile.TemporaryDirectory() as wrong_root:
            wrong = run_managed(data, info, persona, Path(wrong_root), 100_000,
                                companions=[(payload_path.name, wrong_path.read_bytes())])
            self.assertEqual(wrong["errors"],
                             ["Unhandled managed exception: System.MissingFieldException"])
            self.assertFalse(any(item["source"] == "managed_file_write"
                                 for item in wrong["artifacts"]))

    @unittest.skipUnless(shutil.which("dotnet"), ".NET SDK is unavailable")
    def test_managed_companion_instance_fields_resolve_without_host_access(self):
        project = FIXTURES / "ManagedInstanceFieldCompanionLoader" / "ManagedInstanceFieldCompanionLoader.csproj"
        subprocess.run(["dotnet", "build", str(project), "-c", "Release"],
                       check=True, stdout=subprocess.DEVNULL)
        assembly = project.parent / "bin" / "Release" / "net8.0" / "ManagedInstanceFieldCompanionLoader.dll"
        payload_path = (FIXTURES / "ManagedInstanceFieldCompanionPayload" / "bin" /
                        "Release" / "net8.0" / "ManagedInstanceFieldCompanionPayload.dll")
        data, payload = assembly.read_bytes(), payload_path.read_bytes()
        info = inspect_pe(data, assembly.name)
        persona = dict(self.persona)
        persona["user_name"] = Path.home().name
        roaming = rf"C:\Users\{persona['user_name']}\AppData\Roaming"
        host_marker = Path.home() / "AppData" / "Roaming" / "managed-companion-instance-field.txt"
        if not host_marker.parent.is_dir():
            self.skipTest("Host Roaming AppData directory is unavailable")
        self.assertFalse(host_marker.exists())
        host_marker.write_bytes(b"host instance field marker")
        self.addCleanup(host_marker.unlink)
        result = run_managed(data, info, persona, self.root, 100_000,
                             companions=[(payload_path.name, payload)])
        self.assertFalse(result["errors"], result["errors"])
        recovered = [(item["source"], item.get("guest_path"),
                      (self.root / "artifacts" / item["file"]).read_bytes())
                     for item in result["artifacts"]]
        self.assertEqual(recovered, [
            ("managed_assembly_load", "", payload),
            ("managed_file_write", roaming + r"\managed-companion-instance-field.txt",
             b"instance-field-ok"),
        ])
        report = json.loads((self.root / result["engine_report"]).read_text())
        self.assertIn("System.NullReferenceException", [event.get("type")
            for event in report["events"] if event.get("event") == "managed_catch"])
        self.assertEqual(host_marker.read_bytes(), b"host instance field marker")
        with tempfile.TemporaryDirectory() as absent_root:
            absent = run_managed(data, info, persona, Path(absent_root), 100_000)
            self.assertEqual(absent["errors"],
                             ["Unhandled managed exception: System.IO.FileNotFoundException"])
            self.assertEqual(absent["artifacts"], [])
        wrong_project = FIXTURES / "ManagedInstanceFieldCompanionWrong" / "ManagedInstanceFieldCompanionWrong.csproj"
        subprocess.run(["dotnet", "build", str(wrong_project), "-c", "Release"],
                       check=True, stdout=subprocess.DEVNULL)
        wrong_path = wrong_project.parent / "bin" / "Release" / "net8.0" / payload_path.name
        with tempfile.TemporaryDirectory() as wrong_root:
            wrong = run_managed(data, info, persona, Path(wrong_root), 100_000,
                                companions=[(payload_path.name, wrong_path.read_bytes())])
            self.assertEqual(wrong["errors"],
                             ["Unhandled managed exception: System.MissingFieldException"])
            self.assertFalse(any(item["source"] == "managed_file_write"
                                 for item in wrong["artifacts"]))

    @unittest.skipUnless(shutil.which("dotnet"), ".NET SDK is unavailable")
    def test_managed_embedded_resource_stream_is_guest_only_and_bounded(self):
        project = FIXTURES / "ManagedEmbeddedResource" / "ManagedEmbeddedResource.csproj"
        subprocess.run(["dotnet", "build", str(project), "-c", "Release"],
                       check=True, stdout=subprocess.DEVNULL)
        assembly = project.parent / "bin" / "Release" / "net8.0" / "ManagedEmbeddedResource.dll"
        payload = (project.parent / "payload.dat").read_bytes()
        data = assembly.read_bytes()
        persona = dict(self.persona)
        persona["user_name"] = Path.home().name
        roaming = rf"C:\Users\{persona['user_name']}\AppData\Roaming"
        host_roaming = Path.home() / "AppData" / "Roaming"
        if not host_roaming.is_dir():
            self.skipTest("Host Roaming AppData directory is unavailable")
        markers = [host_roaming / name for name in
                   ("managed-resource-payload.bin", "managed-resource-state.txt")]
        for marker in markers:
            self.assertFalse(marker.exists())
            marker.write_bytes(b"host resource marker")
            self.addCleanup(marker.unlink)
        result = run_managed(data, inspect_pe(data, assembly.name), persona,
                             self.root, 100_000)
        self.assertFalse(result["errors"], result["errors"])
        recovered = [(item["source"], item.get("guest_path"),
                      (self.root / "artifacts" / item["file"]).read_bytes())
                     for item in result["artifacts"]]
        self.assertEqual(recovered, [
            ("managed_manifest_resource", "", payload),
            ("managed_file_write", roaming + r"\managed-resource-payload.bin", payload),
            ("managed_file_write", roaming + r"\managed-resource-state.txt", b"resource-ok"),
        ])
        report = json.loads((self.root / result["engine_report"]).read_text())
        self.assertEqual([(event["module_id"], event["name"], event["size"])
                          for event in report["events"]
                          if event.get("event") == "managed_manifest_resource"],
                         [(0, "payload.dat", len(payload))])
        for marker in markers:
            self.assertEqual(marker.read_bytes(), b"host resource marker")
        runner = ManagedRunner(data, inspect_pe(data, assembly.name), persona,
                               self.root, 100_000)
        handle = {"__type": "System.Reflection.Assembly", "module_id": 0}
        self.assertIsNone(runner._manifest_resource_stream(handle, "absent.dat"))
        with self.assertRaises(ManagedThrown):
            runner._manifest_resource_stream(handle, None)
        with self.assertRaises(ManagedThrown):
            runner._manifest_resource_stream(handle, "")
        row = runner.pe.net.mdtables.ManifestResource.rows[0]
        original_offset = row.Offset
        row.Offset = runner.pe.net.struct.ResourcesSize
        with self.assertRaisesRegex(UnsupportedManaged, "resource range"):
            runner._manifest_resource_stream(handle, "payload.dat")
        row.Offset = original_offset
        get_data = runner.pe.get_data
        with patch.object(runner.pe, "get_data", side_effect=lambda rva, length:
                          b"\xff\xff\xff\x7f" if length == 4 else get_data(rva, length)):
            with self.assertRaisesRegex(UnsupportedManaged, "resource exceeds limit"):
                runner._manifest_resource_stream(handle, "payload.dat")
        with patch("emumee.managed.MAX_MANIFEST_RESOURCE_BYTES", len(payload) - 1):
            with self.assertRaisesRegex(UnsupportedManaged, "cumulative limit"):
                runner._manifest_resource_stream(handle, "payload.dat")
        row.Implementation = object()
        with self.assertRaisesRegex(UnsupportedManaged, "External managed manifest resource"):
            runner._manifest_resource_stream(handle, "payload.dat")
        row.Implementation = None
        stream = runner._manifest_resource_stream(handle, "payload.dat")
        with self.assertRaises(ManagedThrown) as read_only:
            runner._memory_stream_call("System.IO.Stream.Write", [b"x", 0, 1], stream)
        self.assertEqual(read_only.exception.value["__type"], "System.NotSupportedException")

    @unittest.skipUnless(shutil.which("dotnet"), ".NET SDK is unavailable")
    def test_managed_companion_manifest_resource_uses_supplied_bytes(self):
        project = FIXTURES / "ManagedResourceCompanionLoader" / "ManagedResourceCompanionLoader.csproj"
        subprocess.run(["dotnet", "build", str(project), "-c", "Release"],
                       check=True, stdout=subprocess.DEVNULL)
        assembly = project.parent / "bin" / "Release" / "net8.0" / "ManagedResourceCompanionLoader.dll"
        payload_path = (FIXTURES / "ManagedResourceCompanionPayload" / "bin" /
                        "Release" / "net8.0" / "ManagedResourceCompanionPayload.dll")
        resource = (payload_path.parent.parent.parent.parent / "companion.dat").read_bytes()
        data, payload = assembly.read_bytes(), payload_path.read_bytes()
        info = inspect_pe(data, assembly.name)
        persona = dict(self.persona)
        persona["user_name"] = Path.home().name
        roaming = rf"C:\Users\{persona['user_name']}\AppData\Roaming"
        host_roaming = Path.home() / "AppData" / "Roaming"
        if not host_roaming.is_dir():
            self.skipTest("Host Roaming AppData directory is unavailable")
        markers = [host_roaming / name for name in
                   ("managed-companion-resource.bin", "managed-companion-resource-state.txt")]
        for marker in markers:
            self.assertFalse(marker.exists())
            marker.write_bytes(b"host companion resource marker")
            self.addCleanup(marker.unlink)
        result = run_managed(data, info, persona, self.root, 100_000,
                             companions=[(payload_path.name, payload)])
        self.assertFalse(result["errors"], result["errors"])
        recovered = [(item["source"], item.get("guest_path"),
                      (self.root / "artifacts" / item["file"]).read_bytes())
                     for item in result["artifacts"]]
        self.assertEqual(recovered, [
            ("managed_assembly_load", "", payload),
            ("managed_manifest_resource", "", resource),
            ("managed_file_write", roaming + r"\managed-companion-resource.bin", resource),
            ("managed_file_write", roaming + r"\managed-companion-resource-state.txt",
             b"companion-resource-ok"),
        ])
        report = json.loads((self.root / result["engine_report"]).read_text())
        self.assertEqual([(event["module_id"], event["name"])
                          for event in report["events"]
                          if event.get("event") == "managed_manifest_resource"],
                         [(1, "companion.dat")])
        for marker in markers:
            self.assertEqual(marker.read_bytes(), b"host companion resource marker")
        with tempfile.TemporaryDirectory() as absent_root:
            absent = run_managed(data, info, persona, Path(absent_root), 100_000)
            self.assertEqual(absent["errors"],
                             ["Unhandled managed exception: System.IO.FileNotFoundException"])
            self.assertEqual(absent["artifacts"], [])

    @unittest.skipUnless(shutil.which("dotnet"), ".NET SDK is unavailable")
    def test_managed_manifest_resource_recovers_embedded_pe(self):
        project = FIXTURES / "ManagedResourcePe" / "ManagedResourcePe.csproj"
        subprocess.run(["dotnet", "build", str(project), "-c", "Release"],
                       check=True, stdout=subprocess.DEVNULL)
        assembly = project.parent / "bin" / "Release" / "net8.0" / "ManagedResourcePe.dll"
        payload = (FIXTURES / "native_x86.exe").read_bytes()
        data = assembly.read_bytes()
        persona = dict(self.persona)
        persona["user_name"] = Path.home().name
        roaming = rf"C:\Users\{persona['user_name']}\AppData\Roaming"
        host_roaming = Path.home() / "AppData" / "Roaming"
        if not host_roaming.is_dir():
            self.skipTest("Host Roaming AppData directory is unavailable")
        markers = [host_roaming / name for name in
                   ("managed-resource-native.exe", "managed-resource-native-state.txt")]
        for marker in markers:
            self.assertFalse(marker.exists())
            marker.write_bytes(b"host resource PE marker")
            self.addCleanup(marker.unlink)
        result = run_managed(data, inspect_pe(data, assembly.name), persona,
                             self.root, 100_000)
        self.assertFalse(result["errors"], result["errors"])
        resource = [item for item in result["artifacts"]
                    if item["source"] == "managed_manifest_resource"]
        self.assertEqual(len(resource), 1)
        self.assertEqual(resource[0]["kind"], "pe")
        self.assertEqual((self.root / "artifacts" / resource[0]["file"]).read_bytes(), payload)
        files = {item["guest_path"]: (self.root / "artifacts" / item["file"]).read_bytes()
                 for item in result["artifacts"] if item["source"] == "managed_file_write"}
        self.assertEqual(files, {roaming + r"\managed-resource-native.exe": payload,
                                 roaming + r"\managed-resource-native-state.txt":
                                     b"resource-pe-ok"})
        for marker in markers:
            self.assertEqual(marker.read_bytes(), b"host resource PE marker")

    def test_managed_coverage_counts_and_dashboard_are_bounded(self):
        assembly = FIXTURES / "ManagedGzip" / "bin" / "Release" / "net8.0" / "ManagedGzip.dll"
        if not assembly.is_file():
            self.skipTest("ManagedGzip fixture has not been built")
        data = assembly.read_bytes()
        result = run_managed(data, inspect_pe(data, assembly.name), self.persona,
                             self.root, 100_000)
        coverage = result["cil_coverage"]
        report = json.loads((self.root / result["engine_report"]).read_text())
        self.assertEqual(report["cil_coverage"], coverage)
        self.assertGreater(coverage["opcode_attempts"], 0)
        self.assertGreater(coverage["framework_calls"], 0)
        self.assertTrue(any(item["opcode"] == "call" for item in coverage["top_opcodes"]))
        self.assertEqual(sum(item["count"] for item in coverage["top_opcodes"])
                         + coverage["other_opcode_attempts"], coverage["opcode_attempts"])
        self.assertEqual(sum(item["count"] for item in coverage["top_framework_calls"])
                         + coverage["other_framework_calls"], coverage["framework_calls"])
        run_dir = self.root / "20261009T120000Z-abcdef12"
        run_dir.mkdir()
        summary = {"id": run_dir.name, "sample": {"name": assembly.name, "managed": True},
                   "status": "completed", "engine": "emumee-cil", "artifacts": [],
                   "cil_coverage": coverage}
        self.assertTrue(valid_summary(summary))
        (run_dir / "summary.json").write_text(json.dumps(summary), encoding="utf-8")
        page = create_app(self.root).test_client().get(f"/runs/{run_dir.name}").get_data(as_text=True)
        self.assertIn("Observed CIL opcodes", page)
        self.assertIn("Observed framework calls", page)
        self.assertIn("do not prove", page)
        hostile = json.loads(json.dumps(summary))
        hostile["cil_coverage"]["top_framework_calls"][0]["method"] = "<script>x</script>"
        self.assertTrue(valid_summary(hostile))
        (run_dir / "summary.json").write_text(json.dumps(hostile), encoding="utf-8")
        page = create_app(self.root).test_client().get(f"/runs/{run_dir.name}").get_data(as_text=True)
        self.assertIn("&lt;script&gt;x&lt;/script&gt;", page)
        self.assertNotIn("<script>x</script>", page)
        bad = json.loads(json.dumps(summary))
        bad["cil_coverage"]["other_framework_calls"] = -1
        self.assertFalse(valid_summary(bad))
        bad = json.loads(json.dumps(summary))
        bad["cil_coverage"]["top_opcodes"][0]["count"] += 1
        self.assertFalse(valid_summary(bad))
        with tempfile.TemporaryDirectory() as partial_dir:
            runner = ManagedRunner(data, inspect_pe(data, assembly.name), self.persona,
                                   Path(partial_dir), 100_000)
            with patch.object(runner, "_framework", side_effect=UnsupportedManaged("test stop")):
                partial = runner.run(Path(partial_dir))
            self.assertEqual(partial["errors"], ["test stop"])
            self.assertEqual(partial["cil_coverage"]["framework_calls"], 1)
            self.assertEqual(partial["cil_coverage"]["top_framework_calls"][0]["count"], 1)

    def test_dashboard_is_read_only_and_artifacts_are_allowlisted(self):
        app = create_app(self.root)
        client = app.test_client()
        self.assertEqual(client.get("/").status_code, 200)
        self.assertEqual(client.post("/").status_code, 405)
        self.assertEqual(client.get("/runs/not-a-run").status_code, 404)
        run_dir = self.root / "20261009T120000Z-abcdef12"
        (run_dir / "artifacts").mkdir(parents=True)
        (run_dir / "artifacts" / "manifest.json").write_text(
            json.dumps([{"file": "..\\..\\outside.txt"}]), encoding="utf-8")
        (self.root / "outside.txt").write_text("private", encoding="utf-8")
        self.assertEqual(client.get("/runs/20261009T120000Z-abcdef12/artifacts/..%5C..%5Coutside.txt").status_code, 404)
        (run_dir / "summary.json").write_text(json.dumps({"id": run_dir.name, "sample": {},
                                                            "status": "completed", "artifacts": "bad"}))
        self.assertIsNone(_worker_summary(run_dir / "summary.json"))
        self.assertEqual(client.get(f"/runs/{run_dir.name}").status_code, 404)
        self.assertEqual(client.get("/").status_code, 200)
        (run_dir / "summary.json").write_text(json.dumps({"id": run_dir.name, "sample": {},
                                                            "status": "completed", "artifacts": []}))
        (run_dir / "engine-report.json").write_text(json.dumps({
            "events": 17, "network_events": "bad", "entry_points": [17, {"events": [0]}]}))
        self.assertEqual(client.get(f"/runs/{run_dir.name}").status_code, 200)
        (run_dir / "artifacts" / "manifest.json").write_text(json.dumps([{"file": ["invalid"]}]))
        self.assertEqual(client.get(f"/runs/{run_dir.name}/artifacts/{'a' * 20}.bin").status_code, 404)

    def test_api_coverage_counts_are_bounded_and_dashboard_explains_trace(self):
        events = [{"event": "api", "api_name": "kernel32.ReadFile", "args": ["0x1"]}] * 3
        events += [{"event": "api", "api_name": "kernel32.StubW",
                    "args": ["Arg: 0x1"]}] * 2
        events += [{"event": "api", "api_name": f"demo.Api{index}", "args": []}
                   for index in range(101)]
        coverage = _api_coverage({"entry_points": [{"events": events}]})
        self.assertEqual(coverage["api_calls"], 106)
        self.assertEqual(coverage["observed_apis"], 103)
        self.assertEqual(len(coverage["observed_calls"]), 100)
        self.assertEqual(coverage["other_calls"], 3)
        self.assertEqual(coverage["observed_calls"][0],
                         {"api": "kernel32.ReadFile", "count": 3,
                          "signature_only_count": 0})
        self.assertEqual(coverage["observed_calls"][1],
                         {"api": "kernel32.StubW", "count": 2,
                          "signature_only_count": 2})
        self.assertEqual(coverage["signature_only_calls"],
                         [{"api": "kernel32.StubW", "count": 2}])
        run_dir = self.root / "20261009T120000Z-abcdef12"
        run_dir.mkdir()
        summary = {"id": run_dir.name, "sample": {"name": "harmless.exe"},
                   "status": "partial", "artifacts": [], "errors": [],
                   "api_coverage": coverage}
        self.assertTrue(valid_summary(summary))
        (run_dir / "summary.json").write_text(json.dumps(summary), encoding="utf-8")
        response = create_app(self.root).test_client().get(f"/runs/{run_dir.name}")
        self.assertEqual(response.status_code, 200)
        page = response.get_data(as_text=True)
        self.assertIn("Observed WinAPI calls", page)
        self.assertIn("kernel32.ReadFile", page)
        self.assertIn("kernel32.StubW", page)
        self.assertIn("3 additional calls", page)
        self.assertIn("does not prove", page)
        self.assertIn("Signature-only API calls", page)
        hostile = json.loads(json.dumps(summary))
        hostile["api_coverage"]["observed_calls"][0]["api"] = "<script>alert(1)</script>"
        self.assertTrue(valid_summary(hostile))
        (run_dir / "summary.json").write_text(json.dumps(hostile), encoding="utf-8")
        hostile_page = create_app(self.root).test_client().get(
            f"/runs/{run_dir.name}").get_data(as_text=True)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", hostile_page)
        self.assertNotIn("<script>alert(1)</script>", hostile_page)
        bad = json.loads(json.dumps(summary))
        bad["api_coverage"]["other_calls"] = -1
        self.assertFalse(valid_summary(bad))
        bad = json.loads(json.dumps(summary))
        bad["api_coverage"]["observed_calls"][0]["signature_only_count"] = 4
        self.assertFalse(valid_summary(bad))
        bad = json.loads(json.dumps(summary))
        bad["api_coverage"]["observed_calls"][0]["api"] = "x" * 300
        self.assertFalse(valid_summary(bad))

    def test_dashboard_shows_recovered_broker_attempt_and_incomplete_warning(self):
        run_dir = self.root / "20261009T120000Z-abcdef12"
        run_dir.mkdir()
        (run_dir / "summary.json").write_text(json.dumps({
            "id": run_dir.name, "sample": {}, "status": "failed", "errors": [],
            "network_broker_report": "network-broker.json",
            "network_broker_complete": False,
        }), encoding="utf-8")
        (run_dir / "network-broker.json").write_text(json.dumps([
            {"event": "http_request_attempt", "url": "http://127.0.0.1/"},
        ]), encoding="utf-8")
        response = create_app(self.root).test_client().get(f"/runs/{run_dir.name}")
        self.assertEqual(response.status_code, 200)
        page = response.get_data(as_text=True)
        self.assertIn("Network broker events", page)
        self.assertIn("http_request_attempt", page)
        self.assertIn("127.0.0.1", page)
        self.assertIn("may be incomplete", page)

    def test_artifact_hash_is_checked_at_collection_and_download(self):
        run_dir = self.root / "20261009T120000Z-abcdef12"
        artifact_dir = run_dir / "artifacts"
        artifact_dir.mkdir(parents=True)
        payload = b"harmless extracted bytes"
        digest = hashlib.sha256(payload).hexdigest()
        name = digest[:20] + ".bin"
        item = {"sha256": digest, "size": len(payload), "kind": "binary",
                "source": "fixture", "guest_path": "C:\\payload.bin", "file": name}
        (artifact_dir / name).write_bytes(payload)
        (artifact_dir / "manifest.json").write_text(json.dumps([item]))
        (run_dir / "summary.json").write_text(json.dumps({
            "id": run_dir.name, "sample": {}, "status": "completed", "artifacts": [item]}))
        client = create_app(self.root).test_client()
        url = f"/runs/{run_dir.name}/artifacts/{name}"
        self.assertTrue(verify_artifact_manifest(run_dir, [item]))
        response = client.get(url)
        self.assertEqual(response.data, payload)
        response.close()
        (artifact_dir / name).write_bytes(b"tampered extracted bytes")
        self.assertFalse(verify_artifact_manifest(run_dir, [item]))
        self.assertEqual(client.get(url).status_code, 404)

    def test_parent_and_dashboard_reject_hardlinked_report_files(self):
        run_dir = self.root / "20261009T120000Z-abcdef12"
        artifact_dir = run_dir / "artifacts"
        artifact_dir.mkdir(parents=True)
        outside_summary = self.root / "outside-summary.json"
        outside_summary.write_text(json.dumps({
            "id": run_dir.name, "sample": {}, "status": "completed", "artifacts": [],
        }), encoding="utf-8")
        summary_path = run_dir / "summary.json"
        try:
            summary_path.hardlink_to(outside_summary)
        except OSError:
            self.skipTest("Host does not permit hardlink creation")
        client = create_app(self.root).test_client()
        self.assertIsNone(_worker_summary(summary_path))
        self.assertEqual(client.get(f"/runs/{run_dir.name}").status_code, 404)
        summary_path.unlink()

        payload = b"harmless extracted bytes"
        digest = hashlib.sha256(payload).hexdigest()
        name = digest[:20] + ".bin"
        item = {"sha256": digest, "size": len(payload), "kind": "binary",
                "source": "fixture", "guest_path": "C:\\payload.bin", "file": name}
        summary_path.write_text(json.dumps({
            "id": run_dir.name, "sample": {}, "status": "completed", "artifacts": [item],
        }), encoding="utf-8")
        outside_engine = self.root / "outside-engine.json"
        outside_engine.write_text("{}", encoding="utf-8")
        engine_path = run_dir / "engine-report.json"
        engine_path.hardlink_to(outside_engine)
        self.assertEqual(client.get(f"/runs/{run_dir.name}").status_code, 404)
        engine_path.unlink()

        outside_artifact = self.root / "outside-artifact.bin"
        outside_artifact.write_bytes(payload)
        artifact_path = artifact_dir / name
        artifact_path.hardlink_to(outside_artifact)
        manifest_path = artifact_dir / "manifest.json"
        manifest_path.write_text(json.dumps([item]), encoding="utf-8")
        self.assertIsNone(read_verified_artifact(run_dir, item))
        self.assertFalse(verify_artifact_manifest(run_dir, [item]))
        self.assertEqual(client.get(f"/runs/{run_dir.name}/artifacts/{name}").status_code, 404)
        artifact_path.unlink()
        artifact_path.write_bytes(payload)

        outside_manifest = self.root / "outside-manifest.json"
        outside_manifest.write_text(json.dumps([item]), encoding="utf-8")
        manifest_path.unlink()
        manifest_path.hardlink_to(outside_manifest)
        self.assertFalse(verify_artifact_manifest(run_dir, [item]))
        self.assertEqual(client.get(f"/runs/{run_dir.name}/artifacts/{name}").status_code, 404)
        self.assertEqual(outside_artifact.read_bytes(), payload)

    def test_dashboard_serves_exact_bytes_that_passed_hash_check(self):
        run_dir = self.root / "20261009T120000Z-abcdef12"
        artifact_dir = run_dir / "artifacts"
        artifact_dir.mkdir(parents=True)
        payload = b"verified harmless bytes"
        digest = hashlib.sha256(payload).hexdigest()
        name = digest[:20] + ".bin"
        item = {"sha256": digest, "size": len(payload), "kind": "binary",
                "source": "fixture", "guest_path": "C:\\payload.bin", "file": name}
        artifact_path = artifact_dir / name
        artifact_path.write_bytes(payload)
        (artifact_dir / "manifest.json").write_text(json.dumps([item]))
        (run_dir / "summary.json").write_text(json.dumps({
            "id": run_dir.name, "sample": {}, "status": "completed", "artifacts": [item]}))

        def replace_after_read(root, record):
            verified = read_verified_artifact(root, record)
            artifact_path.write_bytes(b"changed after verification")
            return verified

        client = create_app(self.root).test_client()
        with patch("emumee.dashboard.read_verified_artifact", side_effect=replace_after_read):
            response = client.get(f"/runs/{run_dir.name}/artifacts/{name}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, payload)
        response.close()
        self.assertNotEqual(artifact_path.read_bytes(), payload)

    def test_dashboard_rejects_linked_run_directory(self):
        with tempfile.TemporaryDirectory() as outside:
            linked = self.root / "20261009T120000Z-abcdef12"
            try:
                linked.symlink_to(outside, target_is_directory=True)
            except OSError:
                self.skipTest("Host does not permit symlink creation")
            (Path(outside) / "summary.json").write_text(json.dumps({
                "id": linked.name, "sample": {}, "status": "completed"}))
            client = create_app(self.root).test_client()
            self.assertEqual(client.get(f"/runs/{linked.name}").status_code, 404)


if __name__ == "__main__":
    unittest.main()
