"""Focused regressions for analyst-observed extraction and request matching."""

from __future__ import annotations

import base64
import argparse
import contextlib
import hashlib
import io
import json
import os
import shutil
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch
from pathlib import Path
from types import SimpleNamespace

import pefile

from emumee.artifacts import ArtifactCatalog, groups_from_payloads
from emumee.bundle import collect_bundle, normalize_relative
from emumee.cli import (_managed_apphost_target, _network_attempts, _output_root,
                        _quarantine_unverified_artifacts, _staged_input_errors, batch)
from emumee.dashboard import create_app, _timeline_events, _compare_runs
from emumee.managed import run_managed
from emumee.job import OutputWatchdog
from emumee.native import _primary_entry_return, _primary_exit_code, run_native
from emumee.networkfixtures import matching_fixture, parse_network_fixtures
from emumee.networkipc import BROKER_JOURNAL, FileRPCClient, NetworkBroker, broker_ipc_dir
from emumee.network import NetworkDenied
from emumee.pe import InvalidSample, inspect_pe_header, inspect_pe
from emumee.persona import DEFAULT_PERSONA, make_speakeasy_config
from emumee.reports import (ENGINE_INTEGRITY, read_verified_engine_report,
                            read_verified_network_report,
                            recover_artifact_checkpoint, valid_summary,
                            verify_artifact_manifest)
from emumee.safeio import _FileInformation, _contained_handle_matches
from emumee.sandbox_probe import main as sandbox_probe_main
from emumee.worker import execute as execute_worker
from emumee.virtualprocess import VirtualProcessBridge


class PrivateEntryTests(unittest.TestCase):
    def test_direct_host_entry_rejected_before_file_write(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / "host-marker.txt"
            with self.assertRaisesRegex(RuntimeError, "containment missing"):
                sandbox_probe_main(root, root / "outside.txt", marker,
                                   os.getpid(), "Software\\EmumeePrivateTest",
                                   root / "bundle-marker.txt", 1)
            self.assertFalse(marker.exists())
            self.assertFalse((root / "bundle-marker.txt").exists())
            with self.assertRaisesRegex(RuntimeError, "containment missing"):
                execute_worker(root)
            self.assertFalse((root / "summary.json").exists())


class BundleInputTests(unittest.TestCase):
    def test_recursive_bundle_preserves_paths_and_rejects_ambiguity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app" / "data").mkdir(parents=True)
            (root / "app" / "main.exe").write_bytes(b"harmless main")
            (root / "app" / "data" / "config.bin").write_bytes(b"harmless data")
            selected = collect_bundle([root], [])
            self.assertEqual(selected, {"app/main.exe": b"harmless main",
                                        "app/data/config.bin": b"harmless data"})
            self.assertEqual(normalize_relative(r"app\main.exe"), "app/main.exe")
            with self.assertRaisesRegex(ValueError, "Duplicate guest bundle path"):
                collect_bundle([root], [(root / "app" / "main.exe", "APP/main.exe")])
            for unsafe in ("../other.exe", r"C:\other.exe", "/other.exe", "app//main.exe"):
                with self.subTest(unsafe=unsafe), self.assertRaises(ValueError):
                    normalize_relative(unsafe)

    def test_bundle_rejects_link_to_outside_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outside = root / "outside.txt"
            outside.write_bytes(b"host marker")
            package = root / "package"
            package.mkdir()
            linked = package / "linked.txt"
            try:
                linked.hardlink_to(outside)
            except OSError:
                self.skipTest("Host does not permit disposable hardlink creation")
            with self.assertRaisesRegex(ValueError, "single-linked"):
                collect_bundle([package], [])
            self.assertEqual(outside.read_bytes(), b"host marker")

    def test_parent_detects_changed_staged_bundle_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "inputs" / "nested").mkdir(parents=True)
            request = root / "request.json"
            main = root / "input.pe"
            extra = root / "inputs" / "nested" / "data.bin"
            request.write_bytes(b"{}")
            main.write_bytes(b"harmless main")
            extra.write_bytes(b"original")
            manifest = {"request_sha256": hashlib.sha256(request.read_bytes()).hexdigest(),
                        "execution_target": {"sha256": hashlib.sha256(main.read_bytes()).hexdigest()},
                        "companions": [], "bundle_files": [{
                            "path": "nested/data.bin",
                            "sha256": hashlib.sha256(extra.read_bytes()).hexdigest()}]}
            self.assertEqual(_staged_input_errors(root, manifest), [])
            extra.write_bytes(b"tampered")
            self.assertIn("inputs/nested/data.bin", " ".join(_staged_input_errors(root, manifest)))

    def test_native_guest_reads_bundled_file_instead_of_persona_text(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = Path(__file__).parent / "fixtures" / "copy_config_x86.exe"
            image = fixture.read_bytes()
            persona = json.loads(json.dumps(DEFAULT_PERSONA))
            persona["current_dir"] = r"C:\Users\Alex\Documents"
            staged = root / "inputs" / "readme.txt"
            staged.parent.mkdir()
            staged.write_bytes(b"bundled readme marker")
            result = run_native(image, inspect_pe(image, fixture.name), persona,
                                root, [], 10, 100_000,
                                bundle_files=[("readme.txt", staged, staged.read_bytes())],
                                bundle_guest_root=persona["current_dir"])
            self.assertFalse(result["errors"])
            self.assertTrue(any((root / "artifacts" / item["file"]).read_bytes()
                                == b"bundled readme marker"
                                for item in result["artifacts"]))

    @unittest.skipUnless(shutil.which("dotnet"), ".NET SDK is unavailable")
    def test_managed_guest_reads_nested_bundle_relative_to_launch_directory(self):
        project = Path(__file__).parent / "fixtures" / "ManagedBundle"
        subprocess.run(["dotnet", "build", str(project / "ManagedBundle.csproj"),
                        "-c", "Release"], check=True, stdout=subprocess.DEVNULL)
        assembly = project / "bin" / "Release" / "net8.0" / "ManagedBundle.dll"
        data = assembly.read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            persona = json.loads(json.dumps(DEFAULT_PERSONA))
            persona["current_dir"] = r"C:\Users\Alex\Downloads\app"
            result = run_managed(data, inspect_pe(data, assembly.name), persona,
                                 root, 100_000,
                                 bundle_files=[("app/data/message.txt", b"nested bundle marker")],
                                 bundle_guest_root=r"C:\Users\Alex\Downloads")
            self.assertFalse(result["errors"])
            self.assertTrue(any((root / "artifacts" / item["file"]).read_bytes()
                                == b"nested bundle marker" for item in result["artifacts"]))


class StagedInputIntegrityTests(unittest.TestCase):
    def test_contained_handle_fallback_checks_file_identity_and_links(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            file = root / "request.json"
            file.write_bytes(b"harmless")
            details = file.stat()
            info = _FileInformation()
            info.index_high = details.st_ino >> 32
            info.index_low = details.st_ino & 0xFFFFFFFF
            info.size_high = details.st_size >> 32
            info.size_low = details.st_size & 0xFFFFFFFF
            self.assertTrue(_contained_handle_matches(file, root, info))
            info.index_low ^= 1
            self.assertFalse(_contained_handle_matches(file, root, info))
            info.index_low ^= 1
            link = root / "linked.json"
            try:
                link.hardlink_to(file)
            except OSError:
                self.skipTest("Host does not permit disposable hardlink creation")
            self.assertFalse(_contained_handle_matches(file, root, info))

    def test_completed_report_rejects_conflicting_failure_flags(self):
        base = {"id": "20261010T000000Z-deadbeef", "sample": {},
                "status": "completed", "completion_reason": "entry_return"}
        self.assertTrue(valid_summary(base))
        for changed in ({"errors": ["guest crashed"]}, {"timeout_reached": True},
                        {"instruction_limit_reached": True}):
            with self.subTest(changed=changed):
                self.assertFalse(valid_summary({**base, **changed}))

    def test_parent_detects_changed_request_input_and_companion(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "inputs").mkdir()
            payloads = {"request.json": b"{}", "input.pe": b"MZ harmless",
                        "inputs/helper.dll": b"MZ companion"}
            for relative, payload in payloads.items():
                (root / relative).write_bytes(payload)
            manifest = {
                "request_sha256": hashlib.sha256(payloads["request.json"]).hexdigest(),
                "execution_target": {"sha256": hashlib.sha256(payloads["input.pe"]).hexdigest(),
                                     "via_managed_apphost": False},
                "sample": {"name": "input.exe", "sha256": ""},
                "companions": [{"name": "helper.dll",
                                "sha256": hashlib.sha256(payloads["inputs/helper.dll"]).hexdigest()}],
            }
            self.assertEqual(_staged_input_errors(root, manifest), [])
            for relative in payloads:
                with self.subTest(relative=relative):
                    path = root / relative
                    original = path.read_bytes()
                    path.write_bytes(original + b"changed")
                    self.assertEqual(_staged_input_errors(root, manifest), [
                        f"Staged execution input changed or is unsafe: {relative}"])
                    path.write_bytes(original)

    def test_worker_rejects_changed_request_and_input_before_guest_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = b"MZ harmless"
            (root / "input.pe").write_bytes(data)
            request = {"sample_name": "harmless.exe", "dlls": [],
                       "input_sha256": hashlib.sha256(data).hexdigest(),
                       "companions_sha256": {}}
            request_raw = json.dumps(request).encode("utf-8")
            (root / "request.json").write_bytes(request_raw)
            with patch("emumee.worker.verify_worker_containment", return_value={}):
                with self.assertRaisesRegex(InvalidSample, "Staged request changed"):
                    execute_worker(root, "0" * 64)
                (root / "input.pe").write_bytes(data + b"changed")
                with self.assertRaisesRegex(InvalidSample, "Staged execution input changed"):
                    execute_worker(root, hashlib.sha256(request_raw).hexdigest())
            self.assertFalse((root / "summary.json").exists())


class BatchIntakeTests(unittest.TestCase):
    def test_output_root_cannot_overlap_worker_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = root / "dist" / "Emumee"
            bundle.mkdir(parents=True)
            with self.assertRaisesRegex(ValueError, "outside the isolated worker bundle"):
                _output_root(str(bundle), worker_bundle=bundle)
            with self.assertRaisesRegex(ValueError, "outside the isolated worker bundle"):
                _output_root(str(bundle / "runs"), worker_bundle=bundle)
            self.assertEqual(_output_root(str(root / "output"), worker_bundle=bundle),
                             (root / "output").resolve())

    def test_over_limit_rejects_before_any_run(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "a.exe").write_bytes(b"a")
            (root / "b.exe").write_bytes(b"b")
            args = argparse.Namespace(directory=str(root), recursive=False,
                                      include_dll=False, max_samples=1)
            error = io.StringIO()
            with patch("emumee.cli.run") as execute, contextlib.redirect_stderr(error):
                self.assertEqual(batch(args), 2)
            execute.assert_not_called()
            self.assertIn("sample limit", error.getvalue())


class OutputLimitTests(unittest.TestCase):
    def test_private_broker_journal_counts_toward_output_limit(self):
        class FakeJob:
            def __init__(self):
                self.stopped = threading.Event()

            def terminate(self):
                self.stopped.set()

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_dir = root / "run"
            run_dir.mkdir()
            journal = root / "private.journal"
            journal.write_bytes(bytes(2 * 1024 * 1024))
            worker, broker = FakeJob(), FakeJob()
            with OutputWatchdog(run_dir, worker, 1, extra_files=(journal,),
                                extra_jobs=(broker,)) as watchdog:
                self.assertTrue(worker.stopped.wait(2))
                self.assertTrue(broker.stopped.is_set())
            self.assertIn("output size", watchdog.violation or "")

    @unittest.skipUnless(os.name == "nt", "alternate data streams require Windows")
    def test_named_streams_on_files_directories_and_journal_count_toward_limit(self):
        class FakeJob:
            def __init__(self):
                self.stopped = threading.Event()

            def terminate(self):
                self.stopped.set()

        for location in ("file", "directory", "journal"):
            with self.subTest(location=location), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                run_dir = root / "run"
                run_dir.mkdir()
                carrier = (run_dir if location == "directory" else
                           root / "private.journal" if location == "journal" else
                           run_dir / "carrier.bin")
                if location != "directory":
                    carrier.write_bytes(b"x")
                stream = Path(str(carrier) + ":quota_probe")
                try:
                    stream.write_bytes(bytes(1200 * 1024))
                except OSError as exc:
                    self.skipTest(f"volume does not support named streams: {exc}")
                worker, broker = FakeJob(), FakeJob()
                extras = (carrier,) if location == "journal" else ()
                with OutputWatchdog(run_dir, worker, 1, extra_files=extras,
                                    extra_jobs=(broker,)) as watchdog:
                    self.assertTrue(worker.stopped.wait(2))
                    self.assertTrue(broker.stopped.is_set())
                self.assertIn("output size", watchdog.violation or "")

    def test_output_watchdog_stops_job_when_run_data_cannot_be_inspected(self):
        class FakeJob:
            def __init__(self):
                self.stopped = threading.Event()

            def terminate(self):
                self.stopped.set()

        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            worker, broker = FakeJob(), FakeJob()
            with patch("emumee.job._named_stream_usage", side_effect=PermissionError):
                with OutputWatchdog(root, worker, 1,
                                    extra_jobs=(broker,)) as watchdog:
                    self.assertTrue(worker.stopped.wait(2))
                    self.assertTrue(broker.stopped.is_set())
            self.assertIn("could not inspect", watchdog.violation or "")


class NetworkFixtureTests(unittest.TestCase):
    def test_broker_ipc_rejects_non_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "broker-ipc").write_bytes(b"unsafe")
            with self.assertRaisesRegex(NetworkDenied, "not a regular directory"):
                broker_ipc_dir(root)

    def test_private_broker_ipc_keeps_streams_and_ready_state_out_of_run_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_dir = root / "run"
            ipc_dir = run_dir / "broker-ipc"
            ipc_dir.mkdir(parents=True)
            journal = root / "private.journal"
            journal.write_bytes(b"")
            with NetworkBroker(run_dir, network_mode="offline_replay",
                               local_hostname="guest-host", journal_path=journal):
                client = FileRPCClient(run_dir)
                try:
                    with self.assertRaisesRegex(NetworkDenied, "Offline replay denied"):
                        client.call("resolve", host="example.org")
                finally:
                    client.close()
            self.assertTrue((ipc_dir / "network-requests.bin").is_file())
            self.assertTrue((ipc_dir / "network-responses.bin").is_file())
            self.assertFalse((run_dir / "network-requests.bin").exists())
            self.assertFalse((run_dir / "network-responses.bin").exists())
            self.assertFalse((run_dir / "network-broker.json").exists())
            self.assertIn(b"broker_closed", journal.read_bytes())

    def test_broker_journal_can_live_outside_worker_run_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_dir = root / "worker"
            run_dir.mkdir()
            journal_path = root / "broker-private.journal"
            journal_path.write_bytes(b"")
            with NetworkBroker(run_dir, network_mode="offline_replay",
                               journal_path=journal_path) as broker:
                with self.assertRaisesRegex(NetworkDenied, "Offline replay denied"):
                    broker._fetch("https://example.org/miss", "GET", None, {})
            self.assertFalse((run_dir / BROKER_JOURNAL).exists())
            self.assertIn(b"network_replay_miss", journal_path.read_bytes())
            self.assertEqual(broker.journal_path, journal_path)

    def test_explicit_broker_mode_overrides_unreadable_request_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "request.json").write_text(json.dumps({
                "network_mode": "live", "persona": {"hostname": "other-host"}}),
                encoding="utf-8")
            with NetworkBroker(root, network_mode="offline_replay",
                               local_hostname="analyst-host") as broker:
                self.assertTrue(broker.offline_replay)
                self.assertIn("analyst-host", broker.local_hostnames)
                self.assertNotIn("other-host", broker.local_hostnames)
                with self.assertRaisesRegex(NetworkDenied, "Offline replay denied"):
                    broker._fetch("http://example.org/unlisted", "GET", None, {})

    def test_offline_replay_broker_rpc_never_uses_live_network(self):
        document = {"version": 1, "rules": [{"id": "known",
            "request": {"method": "GET", "url": "http://127.0.0.1/known",
                        "chunked": False, "headers": {}, "body_utf8": ""},
            "response": {"status": 200, "reason": "OK", "version": "HTTP/1.1",
                         "headers": [], "body_utf8": "replayed"}}]}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "request.json").write_text(json.dumps({"network_mode": "offline_replay"}),
                                               encoding="utf-8")
            (root / "network-fixtures.json").write_text(json.dumps(document),
                                                        encoding="utf-8")
            with NetworkBroker(root) as broker:
                self.assertTrue(broker.offline_replay)
                client = FileRPCClient(root)
                try:
                    reply = client.call("http_fetch_meta", url="http://127.0.0.1/known",
                                        method="GET", headers={}, body="", chunked=False)
                    self.assertEqual(base64.b64decode(reply["body"]), b"replayed")
                    with self.assertRaisesRegex(NetworkDenied, "Offline replay denied"):
                        client.call("http_fetch_meta", url="https://example.org/miss",
                                    method="GET", headers={}, body="", chunked=False)
                    with self.assertRaisesRegex(NetworkDenied, "Offline replay denied"):
                        client.call("resolve", host="example.org")
                    with self.assertRaisesRegex(NetworkDenied, "Offline replay denied"):
                        client.call("socket_open", af=2, type=1)
                finally:
                    client.close()
            attempts, denied, omitted = _network_attempts(root)
            self.assertEqual(denied, 3)
            self.assertEqual(omitted, 0)
            self.assertEqual(attempts[0]["fixture_id"], "known")
            self.assertEqual(attempts[0]["source"], "fixture")
            self.assertEqual([item["outcome"] for item in attempts[1:]],
                             ["replay_miss", "replay_miss", "replay_miss"])

    def test_offline_replay_uses_exact_http_fixture_and_denies_all_misses(self):
        document = {"version": 1, "rules": [{"id": "known-response",
            "request": {"method": "GET", "url": "https://example.org/known",
                        "chunked": False, "headers": {}, "body_utf8": ""},
            "response": {"status": 200, "reason": "OK", "version": "HTTP/1.1",
                         "headers": [], "body_utf8": "fixture bytes"}}]}
        broker = object.__new__(NetworkBroker)
        broker.fixtures = parse_network_fixtures(json.dumps(document).encode())
        broker.offline_replay = True
        broker.events = []
        broker._event = broker.events.append
        broker._public_address = lambda *_args: self.fail("offline replay reached host DNS")
        body, metadata = broker._fetch("https://example.org/known", "GET", None, {})
        self.assertEqual((body, metadata["status"]), (b"fixture bytes", 200))
        with self.assertRaisesRegex(NetworkDenied, "Offline replay denied"):
            broker._fetch("https://example.org/unlisted", "GET", None, {})
        with self.assertRaisesRegex(NetworkDenied, "Offline replay denied"):
            broker._handle({"op": "resolve", "host": "example.org"})
        with self.assertRaisesRegex(NetworkDenied, "Offline replay denied"):
            broker._handle({"op": "socket_open", "af": 2, "type": 1})
        misses = [event for event in broker.events
                  if event.get("event") == "network_replay_miss"]
        self.assertEqual([event["operation"] for event in misses],
                         ["http", "dns", "socket_open"])
        self.assertEqual(next(event["source"] for event in broker.events
                              if event.get("event") == "http_response"), "fixture")
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "network-broker.json").write_text(
                json.dumps(broker.events), encoding="utf-8")
            attempts, denied, omitted = _network_attempts(Path(directory))
        self.assertEqual(denied, 3)
        self.assertEqual(omitted, 0)
        self.assertEqual(attempts[0]["source"], "fixture")
        self.assertEqual(attempts[0]["fixture_id"], "known-response")
        self.assertEqual([attempt["outcome"] for attempt in attempts[1:]],
                         ["replay_miss", "replay_miss", "replay_miss"])

    def test_exact_request_and_response_including_body(self):
        document = {"version": 1, "rules": [{"id": "stage-one",
            "request": {"method": "POST", "url": "http://127.0.0.1/payload",
                        "chunked": False, "headers": {"X-Key": "alpha"},
                        "body_utf8": "ping"},
            "response": {"status": 201, "reason": "Created", "version": "HTTP/1.1",
                         "headers": [["Content-Type", "application/octet-stream"]],
                         "body_base64": base64.b64encode(b"payload").decode("ascii")}}]}
        rules = parse_network_fixtures(json.dumps(document).encode())
        self.assertIsNotNone(matching_fixture(rules, "POST", "http://127.0.0.1/payload",
                                              False, {"x-key": "alpha"}, b"ping"))
        self.assertIsNone(matching_fixture(rules, "POST", "http://127.0.0.1/payload",
                                           False, {"X-Key": "alpha"}, b"other"))
        self.assertIsNone(matching_fixture(rules, "POST", "http://127.0.0.1/payload",
                                           False, {"X-Key": "alpha", "X-Extra": "1"}, b"ping"))
        broker = object.__new__(NetworkBroker)
        broker.fixtures = rules
        broker.events = []
        broker._event = broker.events.append
        body, metadata = broker._fetch("http://127.0.0.1/payload", "POST", b"ping",
                                       {"X-Key": "alpha"})
        self.assertEqual(body, b"payload")
        self.assertEqual(metadata["status"], 201)
        self.assertTrue(any(event["event"] == "network_fixture_match"
                            for event in broker.events))
        with self.assertRaises(NetworkDenied):
            broker._fetch("http://127.0.0.1/payload", "POST", b"wrong",
                          {"X-Key": "alpha"})

    def test_duplicate_exact_request_rejected(self):
        rule = {"request": {"method": "GET", "url": "https://example.test/a",
                            "chunked": False, "headers": {}, "body_utf8": ""},
                "response": {"status": 200, "reason": "OK", "version": "HTTP/1.1",
                             "headers": [], "body_utf8": "x"}}
        with self.assertRaisesRegex(ValueError, "Duplicate exact"):
            parse_network_fixtures(json.dumps({"version": 1, "rules": [rule, rule]}).encode())


class ArtifactGroupTests(unittest.TestCase):
    def test_interrupted_artifact_checkpoint_is_verified_and_labeled(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_id = "20261013T120011Z-1234abcd"
            run_dir = root / run_id
            catalog = ArtifactCatalog(run_dir / "artifacts", checkpoint=True)
            item = catalog.add(b"harmless checkpoint payload", "virtual_file_write")
            self.assertIsNotNone(item)
            recovered = recover_artifact_checkpoint(run_dir)
            self.assertIsNotNone(recovered)
            self.assertEqual(recovered[0], [item])
            summary = {"id": run_id, "sample": {"name": "fixture.exe"},
                       "status": "timeout", "artifacts": recovered[0],
                       "artifact_groups": recovered[1], "errors": ["worker stopped"],
                       "guest_trace_complete": False,
                       "artifact_checkpoint_recovered": True}
            (run_dir / "summary.json").write_text(json.dumps(summary), encoding="utf-8")
            page = create_app(root).test_client().get(f"/runs/{run_id}")
            self.assertEqual(page.status_code, 200)
            self.assertIn("Artifacts below were recovered", page.get_data(as_text=True))
            self.assertIn("did not finish its guest trace", page.get_data(as_text=True))
            (run_dir / "artifacts" / item["file"]).write_bytes(b"tampered payload")
            self.assertIsNone(recover_artifact_checkpoint(run_dir))

    def test_artifact_observation_cap_omits_without_writing(self):
        with tempfile.TemporaryDirectory() as directory:
            catalog = ArtifactCatalog(Path(directory) / "artifacts")
            with patch("emumee.artifacts.MAX_ARTIFACT_OBSERVATIONS", 1):
                self.assertIsNotNone(catalog.add(b"first", "first"))
                self.assertIsNone(catalog.add(b"second", "second"))
            self.assertEqual(len(catalog.items), 1)
            self.assertEqual(catalog.capture_summary()["reasons"],
                             {"artifact_observation_limit": 1})
            self.assertEqual(len(list(catalog.root.glob("*.bin"))), 1)

    def test_artifact_capture_reports_size_and_scan_omissions(self):
        with tempfile.TemporaryDirectory() as directory:
            catalog = ArtifactCatalog(Path(directory) / "artifacts")
            with patch("emumee.artifacts.MAX_ARTIFACT", 8):
                self.assertIsNone(catalog.add(b"x" * 9, "oversized_stage"))
            with patch("emumee.artifacts.MAX_MEMORY_SCAN", 4):
                catalog.carve_pe(b"z" * 10, "memory_stage")
            self.assertEqual(catalog.items, [])
            self.assertEqual(catalog.capture_summary(), {
                "omitted_observations": 2, "omitted_bytes": 15,
                "reasons": {"artifact_size_limit": 1,
                            "memory_scan_input_limit": 1},
                "examples": [{"source": "oversized_stage", "bytes": 9,
                              "reason": "artifact_size_limit"},
                             {"source": "memory_stage", "bytes": 6,
                              "reason": "memory_scan_input_limit"}]})
            summary = {"id": "20261013T120004Z-1234abcd",
                       "sample": {"name": "fixture.exe"}, "status": "failed",
                       "artifacts": [], "errors": [],
                       "artifact_capture": catalog.capture_summary()}
            self.assertTrue(valid_summary(summary))
            run_dir = Path(directory) / summary["id"]
            run_dir.mkdir()
            (run_dir / "summary.json").write_text(json.dumps(summary), encoding="utf-8")
            page = create_app(Path(directory)).test_client().get(
                f"/runs/{summary['id']}")
            self.assertEqual(page.status_code, 200)
            self.assertIn("Artifact capture limits", page.get_data(as_text=True))
            self.assertIn("15 bytes", page.get_data(as_text=True))
            summary["artifact_capture"]["examples"][0]["source"] = "x" * 257
            self.assertFalse(valid_summary(summary))

    def test_dashboard_accepts_only_loopback_host_headers(self):
        with tempfile.TemporaryDirectory() as directory:
            client = create_app(Path(directory)).test_client()
            for host in ("localhost", "127.0.0.1:8765"):
                with self.subTest(host=host):
                    self.assertEqual(client.get("/", headers={"Host": host}).status_code, 200)
            for host in ("attacker.example", "127.0.0.1.attacker.example",
                         "192.0.2.1", "[::1]:8765"):
                with self.subTest(host=host):
                    self.assertEqual(client.get("/", headers={"Host": host}).status_code, 400)

    def test_dashboard_paginates_full_engine_and_broker_events(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_id = "20261013T120003Z-1234abcd"
            run_dir = root / run_id
            run_dir.mkdir()
            engine = json.dumps({"events": [
                {"event": "engine_marker", "number": number,
                 "marker": "ENGINE_LAST" if number == 2000 else "ordinary"}
                for number in range(2001)]}).encode()
            broker = json.dumps([
                {"event": "broker_marker", "number": number,
                 "marker": "BROKER_LAST" if number == 2000 else "ordinary"}
                for number in range(2001)]).encode()
            (run_dir / "engine-report.json").write_bytes(engine)
            (run_dir / "network-broker.json").write_bytes(broker)
            summary = {"id": run_id, "sample": {"name": "fixture.exe"},
                       "status": "completed", "artifacts": [], "errors": [],
                       "engine_report": "engine-report.json",
                       "engine_report_sha256": hashlib.sha256(engine).hexdigest(),
                       "engine_report_size": len(engine),
                       "network_broker_report": "network-broker.json",
                       "network_broker_report_sha256": hashlib.sha256(broker).hexdigest(),
                       "network_broker_report_size": len(broker),
                       "run_manifest": {"engine_report_integrity": ENGINE_INTEGRITY,
                                        "network_broker_report_integrity": ENGINE_INTEGRITY}}
            (run_dir / "summary.json").write_text(json.dumps(summary), encoding="utf-8")
            client = create_app(root).test_client()
            first = client.get(f"/runs/{run_id}")
            self.assertEqual(first.status_code, 200)
            self.assertIn("Showing 1–2000 of 2001", first.get_data(as_text=True))
            self.assertNotIn("ENGINE_LAST", first.get_data(as_text=True))
            self.assertNotIn("BROKER_LAST", first.get_data(as_text=True))
            last = client.get(f"/runs/{run_id}?events_page=2&broker_page=2")
            self.assertEqual(last.status_code, 200)
            self.assertIn("Showing 2001–2001 of 2001", last.get_data(as_text=True))
            self.assertIn("ENGINE_LAST", last.get_data(as_text=True))
            self.assertIn("BROKER_LAST", last.get_data(as_text=True))
            self.assertEqual(client.get(f"/runs/{run_id}?events_page=3").status_code, 404)
            self.assertEqual(client.get(f"/runs/{run_id}?events_page=-1").status_code, 400)

    def test_network_report_binding_rejects_post_run_change(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_id = "20261013T120002Z-1234abcd"
            run_dir = root / run_id
            run_dir.mkdir()
            broker = run_dir / "network-broker.json"
            raw = b'[{"event":"broker_closed"}]'
            broker.write_bytes(raw)
            summary = {"id": run_id, "sample": {"name": "fixture.exe"},
                       "status": "completed", "artifacts": [], "errors": [],
                       "network_broker_report": "network-broker.json",
                       "network_broker_report_sha256": hashlib.sha256(raw).hexdigest(),
                       "network_broker_report_size": len(raw),
                       "run_manifest": {"network_broker_report_integrity": ENGINE_INTEGRITY}}
            (run_dir / "summary.json").write_text(json.dumps(summary), encoding="utf-8")
            client = create_app(root).test_client()
            self.assertTrue(valid_summary(summary))
            self.assertEqual(read_verified_network_report(run_dir, summary), raw)
            self.assertEqual(client.get(f"/runs/{run_id}").status_code, 200)
            self.assertEqual(client.get(f"/compare?left={run_id}&right={run_id}").status_code,
                             200)
            broker.write_bytes(b'[{"event":"forged"}]')
            self.assertIsNone(read_verified_network_report(run_dir, summary))
            self.assertEqual(client.get(f"/runs/{run_id}").status_code, 404)
            self.assertEqual(client.get(f"/compare?left={run_id}&right={run_id}").status_code,
                             404)
            summary.pop("network_broker_report_sha256")
            self.assertFalse(valid_summary(summary))

    def test_host_group_verification_does_not_invoke_pefile(self):
        raw = (Path(__file__).parent / "fixtures" / "native_x64.exe").read_bytes()
        item = {"sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw),
                "kind": "pe", "source": "fixture", "guest_path": "", "file": "fixture.pe"}
        with patch("emumee.artifacts.pefile.PE", side_effect=AssertionError("host PE parser")):
            group = groups_from_payloads([(item, raw)])[0]
        self.assertEqual(group["kind"], "pe")
        self.assertEqual(group["pe_metadata"]["architecture"], "x64")
        self.assertIn("kernel32.dll", [name.lower() for name in
                                         group["pe_metadata"]["import_dlls"]])
        malformed = bytearray(512)
        malformed[:2] = b"MZ"
        malformed[0x3C:0x40] = (0xFFFFFFFF).to_bytes(4, "little")
        bad_item = dict(item, sha256=hashlib.sha256(malformed).hexdigest(),
                        size=len(malformed), kind="binary", file="malformed.bin")
        self.assertEqual(groups_from_payloads([(bad_item, bytes(malformed))])[0]["kind"],
                         "binary")

    def test_engine_trace_binding_rejects_post_run_change(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_id = "20261013T120001Z-1234abcd"
            run_dir = root / run_id
            run_dir.mkdir()
            engine = run_dir / "engine-report.json"
            raw = b'{"events":[]}'
            engine.write_bytes(raw)
            summary = {"id": run_id, "sample": {"name": "fixture.exe"},
                       "status": "completed", "artifacts": [], "errors": [],
                       "engine_report": "engine-report.json",
                       "engine_report_sha256": hashlib.sha256(raw).hexdigest(),
                       "engine_report_size": len(raw),
                       "run_manifest": {"engine_report_integrity": ENGINE_INTEGRITY}}
            (run_dir / "summary.json").write_text(json.dumps(summary), encoding="utf-8")
            client = create_app(root).test_client()
            self.assertTrue(valid_summary(summary))
            self.assertEqual(read_verified_engine_report(run_dir, summary), raw)
            detail = client.get(f"/runs/{run_id}")
            self.assertEqual(detail.status_code, 200)
            self.assertIn("SHA-256 verified", detail.get_data(as_text=True))
            self.assertEqual(client.get(f"/compare?left={run_id}&right={run_id}").status_code,
                             200)
            engine.write_bytes(b'{"events":[1]}')
            self.assertIsNone(read_verified_engine_report(run_dir, summary))
            self.assertEqual(client.get(f"/runs/{run_id}").status_code, 404)
            self.assertEqual(client.get(f"/compare?left={run_id}&right={run_id}").status_code,
                             404)
            summary["status"] = "failed"
            (run_dir / "summary.json").write_text(json.dumps(summary), encoding="utf-8")
            engine.unlink()
            self.assertEqual(client.get(f"/runs/{run_id}").status_code, 404)
            summary["status"] = "completed"
            summary.pop("engine_report_sha256")
            self.assertFalse(valid_summary(summary))
            summary.pop("engine_report_size")
            summary["status"] = "failed"
            (run_dir / "summary.json").write_text(json.dumps(summary), encoding="utf-8")
            self.assertTrue(valid_summary(summary))
            self.assertEqual(client.get(f"/runs/{run_id}").status_code, 200)

    def test_group_metadata_must_match_verified_artifact_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run_id = "20261013T120000Z-1234abcd"
            run_dir = root / run_id
            catalog = ArtifactCatalog(run_dir / "artifacts")
            catalog.add(b"harmless evidence", "file_write", guest_path=r"C:\Temp\evidence.bin")
            catalog.save_manifest()
            summary = {"id": run_id, "sample": {"name": "fixture.exe"},
                       "status": "completed", "artifacts": catalog.items,
                       "artifact_groups": catalog.groups(), "errors": []}
            (run_dir / "summary.json").write_text(json.dumps(summary), encoding="utf-8")
            client = create_app(root).test_client()
            self.assertTrue(valid_summary(summary))
            self.assertTrue(verify_artifact_manifest(run_dir, catalog.items,
                                                     summary["artifact_groups"]))
            self.assertEqual(client.get(f"/runs/{run_id}").status_code, 200)

            false_group = json.loads(json.dumps(summary))
            false_group["artifact_groups"][0]["preview"] = "fabricated evidence"
            self.assertTrue(valid_summary(false_group))
            self.assertFalse(verify_artifact_manifest(run_dir, catalog.items,
                                                      false_group["artifact_groups"]))
            (run_dir / "summary.json").write_text(json.dumps(false_group), encoding="utf-8")
            self.assertEqual(client.get(f"/runs/{run_id}").status_code, 404)
            false_group["artifact_groups"][0]["size"] = 999
            self.assertFalse(valid_summary(false_group))
            false_group["artifact_groups"][0]["sha256"] = []
            self.assertFalse(valid_summary(false_group))

            (run_dir / "summary.json").write_text(json.dumps(summary), encoding="utf-8")
            extra = catalog.add(b"unreported", "file_write")
            catalog.save_manifest()
            self.assertEqual(client.get(f"/runs/{run_id}/artifacts/{extra['file']}").status_code,
                             404)

    def test_failed_artifact_claims_are_quarantined_from_dashboard_and_compare(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            left_id = "20261013T120000Z-1234abcd"
            right_id = "20261013T120001Z-1234abcd"
            left = root / left_id
            left.mkdir()
            fake = {"sha256": "f" * 64, "size": 4, "kind": "pe",
                    "source": "file_write", "guest_path": r"C:\fake.exe",
                    "file": "f" * 20 + ".pe"}
            legacy = {"id": left_id, "sample": {"name": "fixture.exe"},
                      "status": "failed", "artifacts": [fake], "errors": []}
            (left / "summary.json").write_text(json.dumps(legacy), encoding="utf-8")
            right = root / right_id
            right.mkdir()
            (right / "summary.json").write_text(json.dumps({
                "id": right_id, "sample": {"name": "fixture.exe"},
                "status": "failed", "artifacts": [], "errors": []}), encoding="utf-8")
            client = create_app(root).test_client()
            detail = client.get(f"/runs/{left_id}")
            self.assertEqual(detail.status_code, 200)
            self.assertIn("Artifact claims could not be verified", detail.get_data(as_text=True))
            self.assertNotIn(fake["sha256"], detail.get_data(as_text=True))
            self.assertEqual(client.get(f"/runs/{left_id}/artifacts/{fake['file']}").status_code,
                             404)
            self.assertNotIn(left_id, client.get("/?kind=pe").get_data(as_text=True))
            comparison = client.get(
                f"/compare?left={left_id}&right={right_id}&format=json").get_json()
            self.assertEqual(comparison["artifact_changes"]["only_left"], [])
            self.assertEqual(comparison["artifact_evidence"]["left"], "unverified")

            summary = dict(legacy)
            _quarantine_unverified_artifacts(summary)
            self.assertEqual(summary["artifacts"], [])
            self.assertEqual(summary["artifact_groups"], [])
            self.assertEqual(summary["unverified_artifact_count"], 1)
            self.assertTrue(valid_summary(summary))
            summary["status"] = "completed"
            self.assertFalse(valid_summary(summary))

    def test_mapped_pe_reconstruction_keeps_image_and_section_bytes(self):
        source = Path(__file__).parent / "fixtures" / "native_x64.exe"
        file_bytes = source.read_bytes()
        pe = pefile.PE(data=file_bytes, fast_load=True)
        image = bytearray(pe.OPTIONAL_HEADER.SizeOfImage)
        headers = int(pe.OPTIONAL_HEADER.SizeOfHeaders)
        image[:headers] = file_bytes[:headers]
        for section in pe.sections:
            raw, virtual, size = (int(section.PointerToRawData),
                                  int(section.VirtualAddress),
                                  int(section.SizeOfRawData))
            image[virtual:virtual + size] = file_bytes[raw:raw + size]
        with tempfile.TemporaryDirectory() as directory:
            catalog = ArtifactCatalog(Path(directory))
            catalog.carve_pe(bytes(image), "mapped_fixture")
            kinds = {item["kind"] for item in catalog.items}
            self.assertEqual(kinds, {"memory", "pe"})
            recovered = next(item for item in catalog.items if item["kind"] == "pe")
            recovered_bytes = (Path(directory) / recovered["file"]).read_bytes()
            for section in pe.sections:
                raw, size = int(section.PointerToRawData), int(section.SizeOfRawData)
                self.assertEqual(recovered_bytes[raw:raw + size],
                                 file_bytes[raw:raw + size])
            self.assertEqual(recovered["context"]["layout"], "mapped_image")
            self.assertEqual({group["kind"] for group in catalog.groups()},
                             {"memory", "pe"})

    def test_remote_thread_captures_pe_assembled_across_writes(self):
        file_bytes = (Path(__file__).parent / "fixtures" / "native_x64.exe").read_bytes()
        pe = pefile.PE(data=file_bytes, fast_load=True)
        image = bytearray(pe.OPTIONAL_HEADER.SizeOfImage)
        headers = int(pe.OPTIONAL_HEADER.SizeOfHeaders)
        image[:headers] = file_bytes[:headers]
        for section in pe.sections:
            raw, virtual, size = (int(section.PointerToRawData),
                                  int(section.VirtualAddress),
                                  int(section.SizeOfRawData))
            image[virtual:virtual + size] = file_bytes[raw:raw + size]
        base = 0x50000000
        half = len(image) // 2
        process = SimpleNamespace(pid=4141, path=r"C:\Guest\target.exe", id=4141)
        mapping = SimpleNamespace(base=base, size=len(image), process=process, free=False)
        emu = SimpleNamespace(
            get_address_map=lambda address: mapping if base <= address < base + len(image) else None,
            mem_read=lambda address, size: bytes(image[address - base:address - base + size]),
            get_object_from_handle=lambda handle: SimpleNamespace(id=777),
            get_current_process=lambda: process,
            set_last_error=lambda value: None)
        with tempfile.TemporaryDirectory() as directory:
            catalog = ArtifactCatalog(Path(directory))
            bridge = VirtualProcessBridge(catalog)
            for order, (address, payload) in enumerate((
                    (base, bytes(image[:half])), (base + half, bytes(image[half:])))):
                bridge.events.append({"event": "virtual_process_memory_write",
                                      "success": True, "pid": process.pid,
                                      "address": address, "size": len(payload),
                                      "sha256": hashlib.sha256(payload).hexdigest()})
            with patch.object(bridge, "_process", return_value=process), \
                    patch.object(bridge, "_rights_allow", return_value=True), \
                    patch.object(bridge, "_owner_conflict", return_value=False), \
                    patch.object(bridge, "_released_range", return_value=False):
                handle = bridge._create_remote_thread(
                    emu, "kernel32.CreateRemoteThread", lambda params: 123,
                    [10, 0, 0, base + 0x1000, 0, 0, 0])
            self.assertEqual(handle, 123)
            recovered = [item for item in catalog.items if item["kind"] == "pe"]
            self.assertEqual(len(recovered), 1)
            self.assertEqual(recovered[0]["context"]["contributing_write_count"], 2)
            payload = (Path(directory) / recovered[0]["file"]).read_bytes()
            for section in pe.sections:
                raw, size = int(section.PointerToRawData), int(section.SizeOfRawData)
                self.assertEqual(payload[raw:raw + size], file_bytes[raw:raw + size])

    def test_duplicate_bytes_have_one_group_and_two_observations(self):
        with tempfile.TemporaryDirectory() as directory:
            catalog = ArtifactCatalog(Path(directory))
            catalog.add(b"safe payload", "decompress")
            catalog.add(b"safe payload", "file_write", guest_path=r"C:\\Temp\\safe.bin")
            groups = catalog.groups()
            self.assertEqual(len(groups), 1)
            self.assertEqual(len(groups[0]["observations"]), 2)
            self.assertEqual(groups[0]["sha256"], hashlib.sha256(b"safe payload").hexdigest())


class GuestInvocationTests(unittest.TestCase):
    def test_winexec_queues_only_a_guest_owned_executable(self):
        from tests.fixtures.build_native import build
        child_bytes = build(0x8664)
        guest_path = r"C:\Guest\child.exe"
        created = []
        errors = []
        child_queue = []
        process = SimpleNamespace(pid=1220, pe_data=child_bytes, path=guest_path)
        def create_process(*, path, cmdline, child):
            created.append((path, cmdline, child))
            child_queue.append(process)
            return process
        emu = SimpleNamespace(
            read_mem_string=lambda address, width: 'child.exe /test',
            get_cd=lambda: r"C:\Guest",
            get_file_manager=lambda: SimpleNamespace(files=[
                SimpleNamespace(path=guest_path, config=False, data=child_bytes)]),
            get_ptr_size=lambda: 8, set_last_error=errors.append,
            create_process=create_process, child_processes=child_queue)
        with tempfile.TemporaryDirectory() as directory:
            bridge = VirtualProcessBridge(ArtifactCatalog(Path(directory)))
            callbacks = []
            bridge.process_created_handler = lambda _emu, child, image: callbacks.append(
                (child, image))
            self.assertEqual(bridge._winexec(
                emu, "kernel32.WinExec", None, [1, 0]), 33)
            self.assertEqual(created, [(guest_path, 'child.exe /test', True)])
            self.assertEqual(callbacks, [(process, child_bytes)])
            self.assertEqual(child_queue, [process])
            self.assertEqual(errors[-1], 0)
            self.assertTrue(bridge.events[-1]["success"])

    def test_faulted_native_entry_is_not_reported_as_a_return(self):
        from tests.fixtures.build_native import build
        image = bytearray(build(0x8664))
        image[0x200:0x203] = b"\x0f\x0b\xc3"  # UD2 followed by an unreachable RET.
        with tempfile.TemporaryDirectory() as directory, \
                contextlib.redirect_stderr(io.StringIO()):
            root = Path(directory)
            result = run_native(bytes(image), inspect_pe(bytes(image), "ud2.exe"),
                                DEFAULT_PERSONA, root, [], 10, 100_000)
            entry = json.loads((root / "engine-report.json").read_text())["entry_points"][0]
            self.assertTrue(entry["error"])
            self.assertIsNotNone(entry["ret_val"])
            self.assertIsNone(_primary_entry_return([entry]))
            self.assertIsNone(result["guest_entry_return"])
            self.assertEqual(result["completion_reason"], "error")

    def test_native_config_uses_only_supplied_guest_values(self):
        config = make_speakeasy_config(DEFAULT_PERSONA, "fixture.exe", 10, 100,
                                       ["analysis", "two words"],
                                       {"EMUMEE_TEST": "virtual"})
        self.assertIn('"two words"', config["command_line"])
        self.assertEqual(config["env"]["emumee_test"], "virtual")

    def test_child_exit_does_not_replace_primary_guest_exit(self):
        entries = [{"guest_pid": 100}, {"guest_pid": 200}]
        events = [{"event": "virtual_process_exit", "pid": 100, "exit_code": 1},
                  {"event": "virtual_process_exit", "pid": 200, "exit_code": 7}]
        self.assertEqual(_primary_exit_code(entries, events), 1)


class DashboardComparisonTests(unittest.TestCase):
    def test_native_registry_side_effects_keep_capture_ticks(self):
        sample = Path(__file__).parent / "fixtures" / "registry_x64.exe"
        data = sample.read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            run_native(data, inspect_pe(data, sample.name), DEFAULT_PERSONA,
                       Path(directory), [], 10, 100_000)
            engine = json.loads((Path(directory) / "engine-report.json").read_text())
        effects = [event for event in engine["virtual_registry_events"]
                   if event.get("event") in {"virtual_registry_write", "virtual_registry_query"}]
        self.assertEqual(len(effects), 2)
        self.assertLess(effects[0]["pos"]["tick"], effects[1]["pos"]["tick"])
        self.assertLess(effects[0]["capture_sequence"], effects[1]["capture_sequence"])
        shown = [event for event in _timeline_events(engine)
                 if event.get("event") in {"virtual_registry_write", "virtual_registry_query"}]
        self.assertFalse(any(event.get("timeline_tick_inferred") for event in shown))

    def test_timeline_orders_virtual_file_effect_after_its_api(self):
        engine = {"virtual_file_events": [
            {"event": "virtual_file_seek", "api": "kernel32.SetFilePointer"},
            {"event": "virtual_file_rename_by_handle",
             "api": "kernel32.SetFileInformationByHandle"}],
            "entry_points": [{"events": [
                {"event": "api", "api_name": "kernel32.CreateFileW", "pos": {"tick": 9}},
                {"event": "file_write", "pos": {"tick": 18}},
                {"event": "api", "api_name": "kernel32.SetFilePointer", "pos": {"tick": 25}},
                {"event": "api", "api_name": "kernel32.SetFileInformationByHandle",
                 "pos": {"tick": 32}}]}]}
        events = _timeline_events(engine)
        self.assertEqual([event["event"] for event in events],
                         ["api", "file_write", "api", "virtual_file_seek", "api",
                          "virtual_file_rename_by_handle"])
        self.assertTrue(events[3]["timeline_tick_inferred"])

    def test_compare_exposes_outcome_and_persona_change(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            identifiers = ("20261012T200000Z-aaaaaaaa", "20261012T200001Z-bbbbbbbb")
            for index, identifier in enumerate(identifiers):
                run = root / identifier
                run.mkdir()
                (run / "summary.json").write_text(json.dumps({
                    "id": identifier, "sample": {"name": "test.exe", "sha256": "a" * 64},
                    "status": "completed", "persona": {"physical_memory_mb": 1024 * (index + 1)},
                    "guest_exit_code": index, "instruction_count": 12 + index,
                    "artifacts": [], "artifact_groups": [], "errors": [],
                    "run_manifest": {"limits": {"max_instructions": 1000}}}),
                    encoding="utf-8")
                (run / "engine-report.json").write_text(json.dumps({"entry_points": [{
                    "events": [{"event": "api", "api_name": "kernel32.Test", "ret_val": index}]
                }]}), encoding="utf-8")
            client = create_app(root).test_client()
            response = client.get(f"/compare?left={identifiers[0]}&right={identifiers[1]}&format=json")
            self.assertEqual(response.status_code, 200)
            result = response.get_json()
            self.assertEqual(result["outcomes"]["guest_exit_code"], {"left": 0, "right": 1})
            self.assertIn("physical_memory_mb", result["persona_changes"])
            self.assertIn("kernel32.Test", result["api_result_changes"])
            self.assertEqual(client.get("/?sha=" + "a" * 64).status_code, 200)

    def test_behavior_compare_detects_path_change_with_same_artifact_hash(self):
        summary = {"id": "20261012T200000Z-aaaaaaaa",
                   "sample": {"sha256": "a" * 64}, "artifacts": []}
        left = {"virtual_file_events": [{"event": "virtual_file_rename_by_handle",
                                         "new_path": r"C:\Temp\first.bin"}]}
        right = {"virtual_file_events": [{"event": "virtual_file_rename_by_handle",
                                          "new_path": r"C:\Temp\second.bin"}]}
        result = _compare_runs(summary, summary, left, right)
        self.assertEqual(len(result["behavior_changes"]["only_left"]), 1)
        self.assertEqual(len(result["behavior_changes"]["only_right"]), 1)

    def test_compare_keeps_repeated_behavior_and_changed_invocation(self):
        base = {"id": "20261012T200000Z-aaaaaaaa",
                "sample": {"sha256": "a" * 64}, "artifacts": []}
        left = {**base, "run_manifest": {"guest_env": {"MODE": "one"}}}
        right = {**base, "run_manifest": {"guest_env": {"MODE": "two"}}}
        beacon = {"event": "http_response_ready", "url": "https://example.test/a"}
        first = {"network_events": [beacon, beacon]}
        second = {"network_events": [beacon]}
        result = _compare_runs(left, right, first, second)
        self.assertFalse(result["comparable_context"]["same_invocation"])
        self.assertIn("guest_env", result["comparable_context"]["input_changes"])
        self.assertEqual(result["behavior_changes"]["only_left"][0]["count"], 1)
        self.assertEqual(result["behavior_changes"]["left_observations"], 2)



class NetworkSummaryTests(unittest.TestCase):
    def test_attempt_summary_reports_omitted_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            events = []
            for index in range(1001):
                host = f"node-{index}.example.org"
                events.extend(({"event": "dns_attempt", "host": host},
                               {"event": "dns", "host": host, "address": "8.8.8.8"}))
            (root / "network-broker.json").write_text(json.dumps(events), encoding="utf-8")
            attempts, denied, omitted = _network_attempts(root)
            self.assertEqual((len(attempts), denied, omitted), (1000, 0, 1))

    def test_broker_denial_becomes_summary_attempt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "network-broker.json").write_text(json.dumps([
                {"event": "http_request_attempt", "url": "http://127.0.0.1/a",
                 "method": "POST", "body_sha256": "a" * 64},
                {"event": "error", "error": "Private or host-local destination denied"}]))
            attempts, denied, omitted = _network_attempts(root)
            self.assertEqual(denied, 1)
            self.assertEqual(omitted, 0)
            self.assertEqual(attempts[0]["outcome"], "denied")


@unittest.skipUnless(shutil.which("dotnet"), ".NET SDK is unavailable")
class ManagedExtractionTests(unittest.TestCase):
    def test_async_task_main_writes_virtual_marker(self):
        project = Path(__file__).parent / "fixtures" / "ManagedAsync" / "ManagedAsync.csproj"
        subprocess.run(["dotnet", "build", str(project), "-c", "Release", "-v", "quiet"],
                       check=True, capture_output=True, text=True, timeout=120)
        assembly = project.parent / "bin" / "Release" / "net8.0" / "ManagedAsync.dll"
        data = assembly.read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            result = run_managed(data, inspect_pe(data, assembly.name), DEFAULT_PERSONA,
                                 Path(directory), 200_000)
            self.assertEqual(result["errors"], [])
            self.assertTrue(any(item["guest_path"] == "async-marker.txt"
                                for item in result["artifacts"]))

    def test_generic_json_deserialize_reaches_virtual_file_write(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "JsonProbe.csproj").write_text(
                '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup>'
                '<OutputType>Exe</OutputType><TargetFramework>net8.0</TargetFramework>'
                '</PropertyGroup></Project>', encoding="utf-8")
            (root / "Program.cs").write_text(
                'using System.IO; using System.Text.Json;'
                'class Program { static void Main() {'
                'var value=JsonSerializer.Deserialize<Payload>('
                '"{\\\"Path\\\":\\\"json-marker.txt\\\",'
                '\\\"Data\\\":\\\"json reached\\\"}");'
                'File.WriteAllText(value!.Path!,value.Data!); }'
                'class Payload { public string? Path {get;set;}'
                'public string? Data {get;set;} } }', encoding="utf-8")
            subprocess.run(["dotnet", "build", str(root / "JsonProbe.csproj"), "-c",
                            "Release", "-v", "quiet"], check=True, capture_output=True,
                           text=True, timeout=120)
            assembly = root / "bin" / "Release" / "net8.0" / "JsonProbe.dll"
            data = assembly.read_bytes()
            result = run_managed(data, inspect_pe(data, assembly.name), DEFAULT_PERSONA,
                                 root / "run", 200_000)
            self.assertEqual(result["errors"], [])
            self.assertTrue(any(item["guest_path"] == "json-marker.txt"
                                for item in result["artifacts"]))

    def test_pinvoke_tick_count_uses_persona_and_writes_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "PinvokeProbe.csproj").write_text(
                '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup>'
                '<OutputType>Exe</OutputType><TargetFramework>net8.0</TargetFramework>'
                '</PropertyGroup></Project>', encoding="utf-8")
            (root / "Program.cs").write_text(
                'using System; using System.IO; using System.Runtime.InteropServices;'
                'class Program { [DllImport("kernel32.dll", EntryPoint="GetTickCount64")]'
                'static extern ulong Tick(); static void Main() {'
                'File.WriteAllText("tick-marker.txt", Tick().ToString()); }}',
                encoding="utf-8")
            subprocess.run(["dotnet", "build", str(root / "PinvokeProbe.csproj"), "-c",
                            "Release", "-v", "quiet"], check=True, capture_output=True,
                           text=True, timeout=120)
            assembly = root / "bin" / "Release" / "net8.0" / "PinvokeProbe.dll"
            data = assembly.read_bytes()
            result = run_managed(data, inspect_pe(data, assembly.name), DEFAULT_PERSONA,
                                 root / "run", 200_000)
            self.assertEqual(result["errors"], [])
            self.assertTrue(any(item["guest_path"] == "tick-marker.txt"
                                for item in result["artifacts"]))

    def test_decoded_pe_survives_zeroing_and_common_hash_calls(self):
        payload = (Path(__file__).parent / "fixtures" / "console_output_x64.exe").read_bytes()
        encoded = base64.b64encode(bytes(byte ^ 0x5A for byte in payload)).decode("ascii")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "TransientPe.csproj"
            project.write_text('<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup>'
                               '<OutputType>Exe</OutputType><TargetFramework>net8.0</TargetFramework>'
                               '</PropertyGroup></Project>', encoding="utf-8")
            (root / "Program.cs").write_text(
                'using System; using System.Security.Cryptography; class Program {'
                'static int Main() {'
                f'byte[] encoded=Convert.FromBase64String("{encoded}");'
                'byte[] decoded=new byte[encoded.Length];'
                'for(int i=0;i<encoded.Length;i++) decoded[i]=(byte)(encoded[i]^0x5A);'
                'byte[] hash=SHA256.HashData(decoded);'
                'if(decoded[0]!=77 || decoded[1]!=90 || hash.Length!=32) return 2;'
                'Array.Clear(decoded,0,decoded.Length); return 0; } }', encoding="utf-8")
            subprocess.run(["dotnet", "build", str(project), "-c", "Release", "-v", "quiet"],
                           check=True, capture_output=True, text=True, timeout=120)
            assembly = root / "bin" / "Release" / "net8.0" / "TransientPe.dll"
            result = run_managed(assembly.read_bytes(), inspect_pe(assembly.read_bytes(),
                                 assembly.name), DEFAULT_PERSONA, root / "run", 200_000)
            self.assertEqual(result["errors"], [])
            self.assertEqual(result["guest_exit_code"], 0)
            self.assertTrue(any(item["sha256"] == hashlib.sha256(payload).hexdigest()
                                for item in result["artifacts"]))

    def test_memory_only_pe_ascii_encoding_and_apphost(self):
        sample = Path(__file__).parent / "fixtures" / "console_output_x64.exe"
        payload = sample.read_bytes()
        encoded = base64.b64encode(bytes(byte ^ 0x5A for byte in payload)).decode("ascii")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "MemoryPe.csproj"
            project.write_text('<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup>'
                               '<OutputType>Exe</OutputType><TargetFramework>net8.0</TargetFramework>'
                               '</PropertyGroup></Project>', encoding="utf-8")
            (root / "Program.cs").write_text(
                'using System; using System.Text; class Program { static int Main(string[] args) {'
                'byte[] mz = Encoding.ASCII.GetBytes("MZ");'
                f'byte[] encoded = Convert.FromBase64String("{encoded}");'
                'byte[] decoded = new byte[encoded.Length];'
                'for (int i=0; i<encoded.Length; i++) decoded[i]=(byte)(encoded[i]^0x5A);'
                'return decoded[0]==mz[0] && decoded[1]==mz[1] ? 0 : 2;'
                '} }', encoding="utf-8")
            subprocess.run(["dotnet", "build", str(project), "-c", "Release", "-v", "quiet"],
                           check=True, capture_output=True, text=True, timeout=120)
            output = root / "bin" / "Release" / "net8.0"
            assembly = output / "MemoryPe.dll"
            apphost = output / "MemoryPe.exe"
            apphost_data = apphost.read_bytes()
            target = _managed_apphost_target(apphost, apphost_data,
                                              inspect_pe_header(apphost_data, apphost.name))
            self.assertIsNotNone(target)
            self.assertEqual(target[0], assembly.read_bytes())
            result = run_managed(assembly.read_bytes(), inspect_pe(assembly.read_bytes(),
                                 assembly.name), DEFAULT_PERSONA, root / "run", 200_000)
            self.assertEqual(result["errors"], [])
            self.assertEqual(result["guest_exit_code"], 0)
            self.assertTrue(any(item["sha256"] == hashlib.sha256(payload).hexdigest()
                                for item in result["artifacts"]))
            limited = run_managed(assembly.read_bytes(), inspect_pe(assembly.read_bytes(),
                                  assembly.name), DEFAULT_PERSONA, root / "limited", 1)
            self.assertTrue(limited["instruction_limit_reached"])
            self.assertEqual(limited["instruction_count"], 1)


if __name__ == "__main__":
    unittest.main()
