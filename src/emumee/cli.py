"""Command-line entry points for isolated analysis and report browsing."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import ntpath
import os
import re
import sys
import subprocess
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .job import WorkerJob, OutputWatchdog, MAX_OUTPUT_FILES
from .appcontainer import AppContainer, BundleRunLock
from .networkipc import (BROKER_IPC_DIRECTORY, BROKER_JOURNAL, MAX_CALLS, MAX_OPEN_SOCKETS,
                         read_broker_journal)
from .networkfixtures import (MAX_FIXTURE_FILE, parse_network_fixtures,
                              public_fixture_document)
from .artifacts import MAX_ARTIFACT, MAX_MEMORY_SCAN
from .bundle import (MAX_BUNDLE_BYTES, MAX_BUNDLE_FILES, MAX_BUNDLE_FILE_BYTES,
                     collect_bundle, normalize_relative)
from .network import MAX_TRANSFER
from .console_output import MAX_CONSOLE_CHARS
from .pe import InvalidSample, inspect_pe_header
from .persona import DEFAULT_PERSONA, MAX_NATIVE_API_CALLS, load_persona
from .reports import (ENGINE_INTEGRITY, MAX_ENGINE_BYTES, MAX_NETWORK_REPORT_BYTES,
                      MAX_SUMMARY_BYTES, recover_artifact_checkpoint,
                      valid_summary, verify_artifact_manifest)
from .safeio import read_regular_file


MAX_INPUT_BYTES = 128 * 1024 * 1024
MAX_REQUEST_BYTES = 64 * 1024 * 1024
APPHOST_BINDING_MARKER = b"d38cc827-e34f-4453-9df4-1e796e9f1d07"
WORKER_STAGES = frozenset({
    "loading native module", "emulating native module", "collecting native report",
    "saving native manifest", "closing native engine", "native engine closed",
    "native runner returned",
})
MAX_WORKER_STAGE_BYTES = max(len(stage) for stage in WORKER_STAGES)


def _read_bounded(path: Path) -> bytes:
    with path.open("rb") as stream:
        data = stream.read(MAX_INPUT_BYTES + 1)
    if len(data) > MAX_INPUT_BYTES:
        raise InvalidSample(f"Input exceeds the 128 MiB limit: {path.name}")
    return data


def _atomic_text(path: Path, value: str) -> None:
    temporary = path.parent / f".{uuid.uuid4().hex}.tmp"
    with temporary.open("x", encoding="utf-8") as stream:
        stream.write(value)
    os.replace(temporary, path)


def _worker_summary(path: Path) -> dict | None:
    try:
        data = read_regular_file(path, MAX_SUMMARY_BYTES)
        if data is None:
            return None
        value = json.loads(data)
        return value if valid_summary(value) else None
    except (OSError, ValueError, RecursionError):
        return None


def _worker_stage(path: Path) -> str | None:
    """Accept only a short, fixed marker from the terminated worker."""
    try:
        data = read_regular_file(path, MAX_WORKER_STAGE_BYTES)
        if data is None:
            return None
        stage = data.decode("ascii")
        return stage if stage in WORKER_STAGES else None
    except (OSError, UnicodeError):
        return None


def _recover_network_report(run_dir: Path, journal_stream) -> str | None:
    try:
        events, complete, reason = read_broker_journal(journal_stream)
        _atomic_text(run_dir / "network-broker.json",
                     json.dumps(events, separators=(",", ":")))
        return None if complete else reason
    except (OSError, ValueError, RecursionError) as exc:
        return f"Network broker journal recovery failed: {exc}"


def _network_attempts(run_dir: Path, raw: bytes | None = None) -> tuple[list[dict], int, int]:
    """Summarize bounded broker evidence for native and managed runs alike."""
    if raw is None:
        raw = read_regular_file(run_dir / "network-broker.json", MAX_NETWORK_REPORT_BYTES)
    if raw is None:
        return [], 0, 0
    try:
        events = json.loads(raw)
    except (ValueError, RecursionError):
        return [], 0, 0
    if not isinstance(events, list):
        return [], 0, 0
    attempts: list[dict] = []
    denied = 0
    omitted = 0
    current = None
    for event in events:
        if not isinstance(event, dict):
            continue
        kind = event.get("event")
        if kind in {"http_request_attempt", "connect_attempt", "dns_attempt"}:
            current = {key: event[key] for key in
                       ("url", "method", "host", "port", "socket", "body_size", "body_sha256")
                       if key in event and isinstance(event[key], (str, int))}
            current["operation"] = ("http" if kind == "http_request_attempt" else
                                    "socket_connect" if kind == "connect_attempt" else "dns")
            current["outcome"] = "attempted"
            if len(attempts) < 1000:
                attempts.append(current)
            else:
                omitted += 1
        elif kind == "network_fixture_match" and current is not None:
            current["source"] = "fixture"
            if isinstance(event.get("id"), str):
                current["fixture_id"] = event["id"][:256]
        elif kind == "network_replay_miss":
            if current is None:
                current = {"operation": str(event.get("operation", "network"))[:64]}
                for key in ("url", "method", "host", "port"):
                    if key in event and isinstance(event[key], (str, int)):
                        current[key] = event[key]
                if len(attempts) < 1000:
                    attempts.append(current)
                else:
                    omitted += 1
            current["outcome"] = "replay_miss"
            current["source"] = "offline_replay"
            current["reason"] = "No exact replay rule or raw network access is unavailable"
            denied += 1
            current = None
        elif kind == "error" and current is not None:
            reason = str(event.get("error", ""))[:1024]
            current["outcome"] = "denied" if "denied" in reason.casefold() else "error"
            current["reason"] = reason
            denied += current["outcome"] == "denied"
            current = None
        elif kind == "http_request" and current is not None:
            current["source"] = "live"
            if isinstance(event.get("address"), str):
                current["address"] = event["address"]
        elif kind in {"http_response", "response", "connect", "dns"} and current is not None:
            current["outcome"] = ("response" if kind in {"http_response", "response"} else
                                  "connected" if kind == "connect" else "resolved")
            for key in ("status", "size", "sha256", "address"):
                if key in event and isinstance(event[key], (str, int)):
                    current[key] = event[key]
            if kind == "http_response" and event.get("source") in {"fixture", "live"}:
                current["source"] = event["source"]
            elif kind in {"connect", "dns"}:
                current["source"] = "live"
            current = None
    return attempts, denied, omitted


def _utc_timestamp(value: object, fallback: datetime) -> str:
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value)
            if parsed.tzinfo is not None:
                return parsed.astimezone(timezone.utc).isoformat()
        except ValueError:
            pass
    return fallback.isoformat()


def _output_root(value: str | None, *, worker_bundle: Path | None = None) -> Path:
    root = Path(value or "output").resolve()
    if worker_bundle is not None and root.is_relative_to(worker_bundle.resolve()):
        raise ValueError("Output directory must be outside the isolated worker bundle")
    return root


def _worker_bundle() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve()
    root = Path(__file__).resolve().parents[2]
    return root / "dist" / "Emumee" / "Emumee.exe"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _staged_input_errors(run_dir: Path, manifest: dict) -> list[str]:
    """Check every copied execution input against the parent-held run manifest."""
    expected = [("request.json", manifest.get("request_sha256"), MAX_REQUEST_BYTES),
                ("input.pe", manifest["execution_target"]["sha256"], MAX_INPUT_BYTES)]
    if manifest["execution_target"].get("via_managed_apphost"):
        expected.append(("inputs/" + manifest["sample"]["name"],
                         manifest["sample"]["sha256"], MAX_INPUT_BYTES))
    expected.extend(("inputs/" + item["name"], item["sha256"], MAX_INPUT_BYTES)
                    for item in manifest["companions"])
    expected.extend(("inputs/" + item["path"], item["sha256"], MAX_BUNDLE_FILE_BYTES)
                    for item in manifest.get("bundle_files", []))
    errors = []
    for relative, digest, limit in expected:
        payload = read_regular_file(run_dir / relative, limit)
        if payload is None or hashlib.sha256(payload).hexdigest() != digest:
            errors.append(f"Staged execution input changed or is unsafe: {relative}")
    return errors


def _bundle_tree_sha256(bundle_dir: Path) -> str:
    """Identify the complete one-directory worker bundle, not only its EXE."""
    root = bundle_dir.resolve()
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        if path.is_symlink() or not path.resolve().is_relative_to(root):
            raise RuntimeError("Worker bundle contains an unsafe file link")
        if path.is_dir():
            continue
        if not path.is_file():
            raise RuntimeError("Worker bundle contains an unsafe file link")
        relative = path.relative_to(root).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(4, "little"))
        digest.update(relative)
        digest.update(bytes.fromhex(_sha256_file(path)))
    return digest.hexdigest()


def _managed_apphost_target(sample: Path, data: bytes, info) -> tuple[bytes, object] | None:
    """Recognize a .NET apphost bound to one adjacent managed assembly."""
    if info.managed or info.kind != "exe" or sample.suffix.lower() != ".exe":
        return None
    marker = data.find(APPHOST_BINDING_MARKER)
    if marker < 0:
        return None
    binding = re.search(rb"([A-Za-z0-9_.-]{1,128}\.dll)\x00",
                        data[marker + len(APPHOST_BINDING_MARKER):marker + 256], re.I)
    if binding is None:
        return None
    candidate = sample.parent / binding.group(1).decode("ascii")
    if not candidate.is_file():
        raise InvalidSample(f".NET apphost's adjacent managed DLL is missing: {candidate.name}")
    sidecar = _read_bounded(candidate)
    sidecar_info = inspect_pe_header(sidecar, candidate.name)
    if not sidecar_info.managed:
        raise InvalidSample("Bound apphost sidecar is not a managed assembly")
    return sidecar, sidecar_info


def _quarantine_unverified_artifacts(summary: dict) -> None:
    """Keep failed worker claims out of trusted counts and comparisons."""
    artifacts = summary.get("artifacts", [])
    summary["unverified_artifact_count"] = len(artifacts) if isinstance(artifacts, list) else 0
    summary["artifact_integrity"] = "failed"
    summary["artifacts"] = []
    summary["artifact_groups"] = []


def run(args: argparse.Namespace) -> int:
    worker_exe = _worker_bundle()
    if not worker_exe.is_file():
        print("error: isolated worker bundle missing; run .\\build.ps1 first", file=sys.stderr)
        return 2
    from .worker_build import verify_receipt
    try:
        verify_receipt(worker_exe, None if getattr(sys, "frozen", False) else Path(__file__).resolve().parents[2])
    except (OSError, ValueError, RuntimeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    import pefile
    worker_pe = pefile.PE(str(worker_exe), fast_load=True)
    if worker_pe.OPTIONAL_HEADER.DllCharacteristics & 0x4000:
        print("error: worker bootloader is incompatible with Unicorn; run .\\build.ps1", file=sys.stderr)
        return 2
    try:
        supplied = Path(args.sample)
        persona = load_persona(Path(args.persona).resolve(strict=True) if args.persona else None)
        guest_root = persona["current_dir"]
        directory_input = supplied.is_dir()
        if directory_input:
            if not getattr(args, "launch", None):
                raise ValueError("A directory input requires --launch RELATIVE_EXE")
            launch_relative = normalize_relative(args.launch)
            bundle_dirs = [supplied, *(Path(value) for value in getattr(args, "files_dir", []))]
            bundle_files = [(Path(value), Path(value).name)
                            for value in getattr(args, "file", [])]
            bundled = collect_bundle(bundle_dirs, bundle_files)
            matching_launch = [name for name in bundled
                               if name.casefold() == launch_relative.casefold()]
            if not matching_launch:
                raise ValueError(f"Launch file is not in the selected directory: {launch_relative}")
            launch_relative = matching_launch[0]
            sample = supplied.joinpath(*launch_relative.split("/")).resolve(strict=True)
            data = bundled[launch_relative]
            launch_parent = ntpath.dirname(launch_relative.replace("/", "\\"))
            if launch_parent:
                persona["current_dir"] = ntpath.normpath(ntpath.join(guest_root, launch_parent))
        else:
            if getattr(args, "launch", None):
                raise ValueError("--launch is used when the run input is a directory")
            sample = supplied.resolve(strict=True)
            data = _read_bounded(sample)
            launch_relative = sample.name
            bundle_dirs = [Path(value) for value in getattr(args, "files_dir", [])]
            bundle_files = [(Path(value), Path(value).name)
                            for value in getattr(args, "file", [])]
            if bundle_dirs or bundle_files:
                if len(data) > MAX_BUNDLE_FILE_BYTES:
                    raise ValueError("Launch file exceeds the 32 MiB guest bundle file limit")
                bundled = collect_bundle(bundle_dirs, [*bundle_files, (sample, sample.name)])
            else:
                bundled = {}
        info = inspect_pe_header(data, sample.name)
        if info.kind == "msi" and (directory_input or getattr(args, "dll", []) or
                                    getattr(args, "launch", None)):
            raise ValueError("MSI inspection accepts a direct MSI input without --dll or --launch")
        apphost_target = _managed_apphost_target(sample, data, info)
        execution_data, execution_info = apphost_target or (data, info)
        emulate_exports = bool(getattr(args, "all_exports", False))
        if emulate_exports and (execution_info.kind != "dll" or execution_info.managed):
            raise ValueError("--all-exports requires a native DLL-style PE input")
        guest_args = list(getattr(args, "guest_arg", []) or [])
        quoted_arg_indices = list(getattr(args, "guest_quote_arg", []) or [])
        if (len(guest_args) > 64 or any(not isinstance(arg, str) or "\0" in arg
                                        for arg in guest_args) or
                sum(len(arg) for arg in guest_args) > 8192):
            raise ValueError("Guest arguments exceed the 64 argument / 8192 character limit")
        if (any(index < 0 or index >= len(guest_args) or '"' in guest_args[index]
                for index in quoted_arg_indices) or
                quoted_arg_indices and execution_info.managed):
            raise ValueError("--guest-quote-arg requires a valid native --guest-arg index without quote characters")
        guest_env: dict[str, str] = {}
        for assignment in getattr(args, "guest_env", []) or []:
            name, separator, value = assignment.partition("=")
            if (not separator or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_()]{0,127}", name)
                    or "\0" in value or len(value) > 4096):
                raise ValueError("Guest environment values must be KEY=VALUE")
            guest_env[name.upper()] = value
        if len(guest_env) > 64 or sum(len(k) + len(v) for k, v in guest_env.items()) > 8192:
            raise ValueError("Guest environment exceeds the 64 variable / 8192 character limit")
        fixture_document = None
        fixture_count = 0
        if getattr(args, "network_fixtures", None):
            fixture_path = Path(args.network_fixtures).resolve(strict=True)
            with fixture_path.open("rb") as stream:
                fixture_raw = stream.read(MAX_FIXTURE_FILE + 1)
            fixture_rules = parse_network_fixtures(fixture_raw)
            fixture_document = public_fixture_document(fixture_rules)
            fixture_count = len(fixture_rules)
    except (InvalidSample, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    companion_inputs: list[tuple[str, bytes, str, str]] = []
    offline_replay = bool(getattr(args, "offline_replay", False))
    network_mode = ("offline_replay" if offline_replay else
                    "live_with_exact_fixtures" if fixture_document is not None else "live")
    explicit_companion_limit = 16 if execution_info.managed else 32
    if len(args.dll) > explicit_companion_limit:
        print(f"error: explicit companion DLL count exceeds {explicit_companion_limit}",
              file=sys.stderr)
        return 2
    seen_companions: set[str] = set()
    for relative, dll_data in bundled.items():
        if Path(relative).suffix.casefold() != ".dll" or relative == launch_relative:
            continue
        try:
            dll_info = inspect_pe_header(dll_data, Path(relative).name)
        except InvalidSample:
            continue  # A non-PE .dll remains an ordinary guest file.
        if (dll_info.kind != "dll" or dll_info.architecture != execution_info.architecture or
                dll_info.managed != execution_info.managed or
                (apphost_target is not None and dll_data == execution_data)):
            continue
        name = Path(relative).name
        if name.casefold() in seen_companions:
            print(f"error: ambiguous matching DLL basename in bundle: {name}", file=sys.stderr)
            return 2
        seen_companions.add(name.casefold())
        companion_inputs.append((name, dll_data, hashlib.sha256(dll_data).hexdigest(),
                                 ntpath.normpath(ntpath.join(
                                     guest_root, relative.replace("/", "\\")))))
    for candidate in args.dll:
        try:
            path = Path(candidate).resolve(strict=True)
            dll_data = _read_bounded(path)
            dll_info = inspect_pe_header(dll_data, path.name)
        except (InvalidSample, OSError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        if (dll_info.kind != "dll" or dll_info.architecture != execution_info.architecture or
                dll_info.managed != execution_info.managed):
            flavor = "managed" if execution_info.managed else "native"
            print(f"error: companion is not a matching {execution_info.architecture} {flavor} DLL: {path}",
                  file=sys.stderr)
            return 2
        if path.name.casefold() in seen_companions:
            print(f"error: duplicate DLL filename: {path.name}", file=sys.stderr)
            return 2
        seen_companions.add(path.name.casefold())
        companion_inputs.append((path.name, dll_data, hashlib.sha256(dll_data).hexdigest(),
                                 ntpath.join(persona["current_dir"], path.name)))
    companion_limit = 16 if execution_info.managed else 32
    if len(companion_inputs) > companion_limit:
        print(f"error: companion DLL count exceeds {companion_limit}", file=sys.stderr)
        return 2
    try:
        root = _output_root(args.output, worker_bundle=worker_exe.parent)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    root.mkdir(parents=True, exist_ok=True)
    invocation_started = datetime.now(timezone.utc)
    run_id = invocation_started.strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    run_dir = root / run_id
    run_dir.mkdir(mode=0o700)
    ipc_dir = run_dir / BROKER_IPC_DIRECTORY
    ipc_dir.mkdir()
    (run_dir / "inputs").mkdir()
    (run_dir / "input.pe").write_bytes(execution_data)
    if apphost_target is not None:
        (run_dir / "inputs" / sample.name).write_bytes(data)
    if fixture_document is not None:
        (run_dir / "network-fixtures.json").write_bytes(fixture_document)
    bundle_hashes: list[dict] = []
    for relative, payload in sorted(bundled.items(), key=lambda item: item[0].casefold()):
        dest = (run_dir / "inputs").joinpath(*relative.split("/"))
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(payload)
        bundle_hashes.append({"path": relative, "sha256": hashlib.sha256(payload).hexdigest(),
                              "size": len(payload)})
    companions: list[str] = []
    companion_hashes: list[dict] = []
    companion_guest_paths: dict[str, str] = {}
    for name, dll_data, digest, guest_path in companion_inputs:
        dest = run_dir / "inputs" / name
        dest.write_bytes(dll_data)
        companions.append(name)
        companion_hashes.append({"name": name, "sha256": digest})
        companion_guest_paths[name] = guest_path
    request = {"sample_name": execution_info.name, "persona": persona, "dlls": companions,
               "timeout": args.timeout, "max_instructions": args.max_instructions,
               "guest_args": guest_args, "guest_env": guest_env,
               "quoted_arg_indices": quoted_arg_indices,
               "all_exports": emulate_exports,
               "network_mode": network_mode,
               "input_sha256": hashlib.sha256(execution_data).hexdigest(),
               "companions_sha256": {name: digest for name, _, digest, _ in companion_inputs},
               "companion_guest_paths": companion_guest_paths,
               "bundle_guest_root": guest_root,
               "bundle_files_sha256": {item["path"]: item["sha256"]
                                       for item in bundle_hashes}}
    request_raw = json.dumps(request, indent=2).encode("utf-8")
    run_manifest = {
        "emumee_version": __version__,
        "worker_bundle_sha256": _sha256_file(worker_exe),
        "bundle_tree_sha256": _bundle_tree_sha256(worker_exe.parent),
        "sample": {"name": sample.name, "sha256": hashlib.sha256(data).hexdigest()},
        "execution_target": {"name": execution_info.name,
                             "sha256": hashlib.sha256(execution_data).hexdigest(),
                             "via_managed_apphost": apphost_target is not None},
        "companions": companion_hashes,
        "bundle_files": bundle_hashes,
        "bundle_guest_root": guest_root,
        "bundle_launch": launch_relative if bundled else None,
        "request_sha256": hashlib.sha256(request_raw).hexdigest(),
        "guest_args": guest_args,
        "quoted_arg_indices": quoted_arg_indices,
        "guest_env": guest_env,
        "all_exports": emulate_exports,
        "network_mode": network_mode,
        "engine_report_integrity": ENGINE_INTEGRITY,
        "network_broker_report_integrity": ENGINE_INTEGRITY,
        "network_fixtures": {"file": "network-fixtures.json",
                             "sha256": hashlib.sha256(fixture_document).hexdigest(),
                             "rules": fixture_count} if fixture_document is not None else None,
        "persona_sha256": hashlib.sha256(json.dumps(persona, sort_keys=True,
                                                      separators=(",", ":")).encode("utf-8")).hexdigest(),
        "limits": {"timeout_seconds": args.timeout,
                   "timeout_scope": "guest_emulation; worker startup and reporting add time",
                   "max_instructions": args.max_instructions,
                   "max_native_api_calls": MAX_NATIVE_API_CALLS,
                   "worker_memory_mb": args.memory_mb,
                   "network_broker_memory_mb": 256,
                   "max_output_mb": args.max_output_mb,
                   "max_output_files": MAX_OUTPUT_FILES,
                   "max_input_bytes": MAX_INPUT_BYTES,
                   "max_bundle_files": MAX_BUNDLE_FILES,
                   "max_bundle_file_bytes": MAX_BUNDLE_FILE_BYTES,
                   "max_bundle_bytes": MAX_BUNDLE_BYTES,
                   "max_artifact_bytes": MAX_ARTIFACT,
                   "max_memory_scan_bytes": MAX_MEMORY_SCAN,
                   "max_http_transfer_bytes": MAX_TRANSFER,
                   "max_network_broker_calls": MAX_CALLS,
                   "max_network_sockets": MAX_OPEN_SOCKETS,
                   "max_console_chars_per_stream": MAX_CONSOLE_CHARS},
    }
    (run_dir / "request.json").write_bytes(request_raw)
    journal_path = root / f".{run_id}.{BROKER_JOURNAL}"
    journal_stream = journal_path.open("x+b", buffering=0)
    worker_exit = None
    worker_peak_memory_bytes = None
    failure = None
    timeout_reached = False
    try:
        with BundleRunLock(worker_exe), WorkerJob(args.memory_mb) as job, WorkerJob(256) as network_job, AppContainer(
                moniker=f"Emumee.AnalysisWorker.{uuid.uuid4().hex}", network=False,
                delete_on_close=True) as box, AppContainer(
                moniker=f"Emumee.NetworkBroker.{uuid.uuid4().hex}", network=not offline_replay,
                delete_on_close=True) as network_box:
            if _sha256_file(worker_exe) != run_manifest["worker_bundle_sha256"]:
                raise RuntimeError("Worker bundle changed after run manifest creation")
            if _bundle_tree_sha256(worker_exe.parent) != run_manifest["bundle_tree_sha256"]:
                raise RuntimeError("Worker bundle contents changed after run manifest creation")
            staged_errors = _staged_input_errors(run_dir, run_manifest)
            if staged_errors:
                raise RuntimeError("; ".join(staged_errors))
            network_thread = None
            network_result: dict = {}
            try:
                box.grant(worker_exe.parent, "RX")
                box.grant(run_dir, "M")
                network_box.grant(worker_exe.parent, "RX")
                network_box.grant(run_dir, "RX", recursive=False)
                network_box.grant(ipc_dir, "M")
                if fixture_document is not None:
                    network_box.grant(run_dir / "network-fixtures.json", "RX")
                network_box.grant(journal_path, "M")

                def run_network_broker() -> None:
                    try:
                        network_result["exit"] = network_box.launch(
                            [str(worker_exe), "_network_broker", str(run_dir),
                             network_mode, persona["hostname"], str(journal_path)],
                            run_dir, args.timeout + 30, job=network_job)
                    except (OSError, TimeoutError, RuntimeError) as exc:
                        network_result["error"] = str(exc)

                network_thread = threading.Thread(target=run_network_broker,
                                                  name="emumee-broker-launch", daemon=True)
                network_thread.start()
                ready = ipc_dir / "broker-ready"
                deadline = time.monotonic() + 10
                while not ready.is_file():
                    if not network_thread.is_alive():
                        raise RuntimeError(f"Network broker exited during startup: {network_result}")
                    if time.monotonic() >= deadline:
                        raise TimeoutError("Network broker startup exceeded 10 seconds")
                    time.sleep(0.05)
                with OutputWatchdog(run_dir, job, args.max_output_mb,
                                    extra_files=(journal_path,),
                                    extra_jobs=(network_job,)) as watchdog:
                    worker_exit = box.launch([str(worker_exe), "_worker", str(run_dir),
                                              run_manifest["request_sha256"]],
                                             run_dir, args.timeout + 15, job=job)
                if watchdog.violation:
                    failure = watchdog.violation
            finally:
                worker_peak_memory_bytes = job.peak_process_memory_bytes()
                try:
                    _atomic_text(ipc_dir / "broker-stop", "stop")
                except OSError as exc:
                    failure = f"Could not stop broker cleanly: {exc}"
                    network_job.terminate()
                if network_thread is not None:
                    network_thread.join(timeout=5)
                    if network_thread.is_alive():
                        network_job.terminate()
                        network_thread.join(timeout=2)
                        if network_thread.is_alive():
                            failure = "Network broker did not stop after job termination"
                    if network_result.get("exit") not in (None, 0):
                        failure = f"Network broker exited with code {network_result['exit']}"
                    if network_result.get("error"):
                        failure = f"Network broker failed: {network_result['error']}"
                for container in (box, network_box):
                    paths = ((journal_path,
                              *((run_dir / "network-fixtures.json",) if fixture_document is not None else ()),
                              ipc_dir, run_dir, worker_exe.parent)
                             if container is network_box else (run_dir, worker_exe.parent))
                    for path in paths:
                        try:
                            container.revoke(path)
                        except OSError as exc:
                            failure = f"Sandbox permission cleanup failed: {exc}"
    except TimeoutError as exc:
        timeout_reached = True
        failure = str(exc) or "Worker exceeded the wall-clock limit"
    except (OSError, RuntimeError) as exc:
        failure = f"Isolated worker failed: {exc}"
    journal_failure = _recover_network_report(run_dir, journal_stream)
    journal_stream.close()
    try:
        journal_path.unlink(missing_ok=True)
    except OSError as exc:
        failure = failure or f"Could not remove private broker journal: {exc}"
    if journal_failure:
        failure = failure or journal_failure
    report_path = run_dir / "summary.json"
    summary = _worker_summary(report_path) or {"id": run_id, "sample": info.to_dict()}
    summary["id"] = run_id
    summary["run_manifest"] = run_manifest
    summary["started_at"] = _utc_timestamp(summary.get("started_at"), invocation_started)
    summary["timeout_reached"] = bool(summary.get("timeout_reached")) or timeout_reached
    summary["network_broker_complete"] = journal_failure is None
    staged_errors = _staged_input_errors(run_dir, run_manifest)
    if staged_errors:
        summary["status"] = "failed"
        summary["completion_reason"] = "worker_failure"
        summary.setdefault("errors", []).extend(staged_errors)
    if failure or (summary.get("status") == "completed" and worker_exit != 0) or (
            summary.get("status") == "partial" and worker_exit not in (0, 1)):
        summary["status"] = "timeout" if timeout_reached else "failed"
        summary["completion_reason"] = "timeout" if timeout_reached else "worker_failure"
        summary.setdefault("errors", []).append(failure or f"Worker exit code was {worker_exit}")
    if summary.get("status") not in {"completed", "partial", "failed", "timeout"}:
        summary["status"] = "timeout" if timeout_reached else "failed"
        summary["completion_reason"] = "timeout" if timeout_reached else "worker_failure"
        stage = _worker_stage(run_dir / "worker-stage.txt") if not failure else None
        detail = f"; last recorded stage: {stage}" if stage else ""
        summary["errors"] = [failure or f"Worker exited before finishing (code {worker_exit}{detail})"]
    if journal_failure and journal_failure not in summary.get("errors", []):
        summary.setdefault("errors", []).append(journal_failure)
    if summary["status"] in {"failed", "timeout"} and "artifacts" not in summary:
        checkpoint = recover_artifact_checkpoint(run_dir)
        if checkpoint is not None and checkpoint[0]:
            summary["artifacts"], summary["artifact_groups"] = checkpoint
            summary["artifact_checkpoint_recovered"] = True
    if (summary["status"] in {"completed", "partial"} or
            (summary["status"] == "timeout" and "artifacts" in summary)) and not verify_artifact_manifest(
            run_dir, summary.get("artifacts", []), summary.get("artifact_groups")):
        summary["status"] = "failed"
        _quarantine_unverified_artifacts(summary)
        summary.setdefault("errors", []).append(
            "Worker artifact manifest, SHA-256, or group provenance verification failed")
    engine_raw = (read_regular_file(run_dir / "engine-report.json", MAX_ENGINE_BYTES)
                  if summary.get("engine_report") == "engine-report.json" else None)
    if engine_raw:
        summary["engine_report_sha256"] = hashlib.sha256(engine_raw).hexdigest()
        summary["engine_report_size"] = len(engine_raw)
    elif summary["status"] in {"completed", "partial"}:
        summary["status"] = "failed"
        summary.setdefault("errors", []).append(
            "Worker engine report missing, unsafe, empty, or exceeds 50 MiB")
    summary["guest_trace_complete"] = (bool(engine_raw) and
                                       summary.get("completion_reason") != "static_inspection")
    if fixture_document is not None:
        verified_fixture = read_regular_file(run_dir / "network-fixtures.json", MAX_FIXTURE_FILE)
        if verified_fixture != fixture_document:
            summary["status"] = "failed"
            summary.setdefault("errors", []).append("HTTP fixture file changed during analysis")
    broker_raw = read_regular_file(run_dir / "network-broker.json", MAX_NETWORK_REPORT_BYTES)
    if broker_raw:
        summary["network_broker_report"] = "network-broker.json"
        summary["network_broker_report_sha256"] = hashlib.sha256(broker_raw).hexdigest()
        summary["network_broker_report_size"] = len(broker_raw)
        (summary["network_attempts"], broker_denials,
         summary["network_attempts_omitted"]) = _network_attempts(run_dir, broker_raw)
        summary["denied_operations"] = max(summary.get("denied_operations", 0), broker_denials)
    elif summary["status"] in {"completed", "partial"}:
        summary["status"] = "failed"
        summary.setdefault("errors", []).append(
            "Network broker report missing, unsafe, empty, or exceeds 64 MiB")
    finished = datetime.now(timezone.utc)
    summary["finished_at"] = _utc_timestamp(summary.get("finished_at"), finished)
    summary["command_finished_at"] = finished.isoformat()
    summary["command_elapsed_seconds"] = round((finished - invocation_started).total_seconds(), 3)
    summary["worker_exit_code"] = worker_exit
    summary["worker_peak_memory_bytes"] = worker_peak_memory_bytes
    if summary["status"] == "failed" and worker_exit is not None:
        exit_hex = f"0x{worker_exit & 0xFFFFFFFF:08X}"
        if worker_peak_memory_bytes is not None and (
                worker_peak_memory_bytes >= args.memory_mb * 1024 * 1024 * 0.95):
            summary["worker_failure_reason"] = "memory_limit_likely"
            summary.setdefault("errors", []).append(
                f"Worker peak committed memory approached the {args.memory_mb} MiB limit "
                f"({worker_peak_memory_bytes} bytes); exit {exit_hex}")
        elif worker_exit == 0xC0000142:
            summary["worker_failure_reason"] = "dll_initialization_failed"
            summary.setdefault("errors", []).append(
                f"Worker DLL initialization failed ({exit_hex}); the configured "
                f"{args.memory_mb} MiB memory cap may be too low for startup")
        else:
            summary["worker_failure_reason"] = "worker_exited_before_report"
            summary.setdefault("errors", []).append(f"Worker exit status: {exit_hex}")
    _atomic_text(report_path, json.dumps(summary, indent=2))
    print(json.dumps({"run": run_id, "status": summary["status"], "report": str(run_dir / "summary.json"),
                      "guest_exit_code": summary.get("guest_exit_code"),
                      "guest_entry_return": summary.get("guest_entry_return"),
                      "completion_reason": summary.get("completion_reason"),
                      "worker_exit_code": worker_exit,
                      "worker_failure_reason": summary.get("worker_failure_reason"),
                      "worker_peak_memory_bytes": worker_peak_memory_bytes,
                      "command_elapsed_seconds": summary["command_elapsed_seconds"],
                      "instruction_count": summary.get("instruction_count"),
                      "instruction_limit_reached": summary.get("instruction_limit_reached", False),
                      "timeout_reached": summary.get("timeout_reached", False),
                      "guest_trace_complete": summary["guest_trace_complete"],
                      "artifact_checkpoint_recovered": summary.get("artifact_checkpoint_recovered", False),
                      "denied_operations": summary.get("denied_operations", 0),
                      "network_attempts": len(summary.get("network_attempts", [])),
                      "network_attempts_omitted": summary.get("network_attempts_omitted", 0),
                      "artifacts": len(summary.get("artifacts", [])),
                      "unique_artifacts": len(summary.get("artifact_groups", summary.get("artifacts", []))),
                      "errors": summary.get("errors", [])}, indent=2))
    return 0 if summary["status"] == "completed" else 1


def batch(args: argparse.Namespace) -> int:
    """Run a bounded directory of samples through the normal isolated path."""
    try:
        directory = Path(args.directory).resolve(strict=True)
        if not directory.is_dir():
            raise ValueError("Batch input must be a directory")
        extensions = ({".exe", ".scr", ".com", ".msi", ".msp", ".mst"} |
                      ({".dll", ".ocx", ".cpl", ".ax"} if args.include_dll else set()))
        pending = [directory]
        samples: list[Path] = []
        while pending:
            current = pending.pop()
            with os.scandir(current) as entries:
                for entry in entries:
                    if args.recursive and entry.is_dir(follow_symlinks=False):
                        pending.append(Path(entry.path))
                    elif (entry.is_file(follow_symlinks=False) and
                          (Path(entry.name).suffix.casefold() in extensions or
                           getattr(args, "all_pe", False))):
                        if getattr(args, "all_pe", False) and Path(entry.name).suffix.casefold() not in extensions:
                            try:
                                with open(entry.path, "rb") as stream:
                                    header = stream.read(1024 * 1024)
                                inspect_pe_header(header, entry.name)
                                if header[:2] != b"MZ":
                                    continue
                            except (OSError, InvalidSample):
                                continue
                        samples.append(Path(entry.path))
                        if len(samples) > args.max_samples:
                            raise ValueError(f"Batch exceeds the {args.max_samples} sample limit")
        if not samples:
            raise ValueError("Batch directory contains no matching PE or MSI inputs")
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    counts: dict[str, int] = {}
    for sample in sorted(samples, key=lambda path: str(path).casefold()):
        invocation = argparse.Namespace(**{**vars(args), "sample": str(sample)})
        captured_out, captured_error = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(captured_out), contextlib.redirect_stderr(captured_error):
            code = run(invocation)
        try:
            result = json.loads(captured_out.getvalue()) if captured_out.getvalue() else None
        except ValueError:
            result = None
        status = result.get("status", "failed") if isinstance(result, dict) else "rejected"
        counts[status] = counts.get(status, 0) + 1
        print(json.dumps({"type": "run", "sample": str(sample), "exit_code": code,
                          "status": status, "result": result,
                          "error": captured_error.getvalue().strip() or None}), flush=True)
    print(json.dumps({"type": "batch_summary", "total": len(samples),
                      "counts": counts, "sequential": True}), flush=True)
    return 0 if counts == {"completed": len(samples)} else 1


def _add_analysis_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--dll", action="append", default=[], help="Explicit guest DLL input; repeatable")
    parser.add_argument("--all-exports", action="store_true",
                        help="After native DLL attach, emulate up to ten exports with placeholder arguments")
    parser.add_argument("--file", action="append", default=[],
                        help="Additional guest file placed beside the launch file; repeatable")
    parser.add_argument("--files-dir", action="append", default=[],
                        help="Recursively include a directory as guest files; repeatable")
    parser.add_argument("--persona", help="JSON file overriding the default Windows persona")
    parser.add_argument("--network-fixtures", help="JSON file of exact HTTP request/response fixtures")
    parser.add_argument("--offline-replay", action="store_true",
                        help="Use exact HTTP fixtures only; deny and log every unmatched or raw network request")
    parser.add_argument("--guest-arg", action="append", default=[], help="Guest command-line argument; repeatable")
    parser.add_argument("--guest-quote-arg", action="append", type=int, default=[],
                        help="Quote a zero-based --guest-arg index in the raw native Windows command line")
    parser.add_argument("--guest-env", action="append", default=[], help="Guest process KEY=VALUE; repeatable")
    parser.add_argument("--output", help="Report directory (default: ./output)")
    parser.add_argument("--timeout", type=int, default=60,
                        help="Guest emulation limit in seconds; startup and reporting add time")
    parser.add_argument("--max-instructions", type=int, default=2_000_000)
    parser.add_argument("--memory-mb", type=int, default=1024, help="Worker memory cap in MiB")
    parser.add_argument("--max-output-mb", type=int, default=512, help="Run directory size cap in MiB")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="emumee", description="User-mode Windows PE emulation and payload extraction")
    parser.add_argument("--version", action="version", version=f"emumee {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    p_run = sub.add_parser("run", help="Emulate a PE or statically inspect an MSI")
    p_run.add_argument("sample", help="Native/managed PE, MSI, or a directory used with --launch")
    p_run.add_argument("--launch", help="Relative EXE or managed entry assembly inside a directory")
    _add_analysis_options(p_run)
    p_run.set_defaults(func=run)
    p_batch = sub.add_parser("batch", help="Analyze a bounded directory of PEs and MSIs sequentially")
    p_batch.add_argument("directory", help="Directory containing samples to analyze")
    p_batch.add_argument("--recursive", action="store_true", help="Include subdirectories without following links")
    p_batch.add_argument("--include-dll", action="store_true", help="Also analyze DLL files as primary inputs")
    p_batch.add_argument("--all-pe", action="store_true", help="Also inspect other filenames with a PE signature")
    p_batch.add_argument("--max-samples", type=int, default=1000, help="Reject batches larger than this count (maximum 1000)")
    _add_analysis_options(p_batch)
    p_batch.set_defaults(func=batch)
    p_dashboard = sub.add_parser("dashboard", help="Start read-only local report website")
    p_dashboard.add_argument("--output", help="Report directory (default: ./output)")
    p_dashboard.add_argument("--port", type=int, default=8765)
    p_dashboard.set_defaults(func=lambda args: _dashboard(args))
    p_persona = sub.add_parser("persona", help="Print a configurable default Windows identity")
    p_persona.set_defaults(func=lambda args: _persona())
    p_powershell = sub.add_parser("powershell", help="Experimental supplied-script execution in an offline Docker Desktop Linux VM")
    p_powershell.add_argument("sample", help="PowerShell .ps1 file (up to 1 MiB)")
    p_powershell.add_argument("--observer", required=True, help="Trusted Linux observer built with tools/build_powershell_exec_observer.ps1")
    p_powershell.add_argument("--instrumented-engine", required=True, help="Trusted pinned engine DLL with its .build.json evidence")
    p_powershell.add_argument("--guest-tools-build", required=True, help="Build JSON for guest Windows enumeration shims and CPU emulator")
    p_powershell.add_argument("--persona", help="Windows persona override JSON; requires --guest-tools-build")
    p_powershell.add_argument("--output", help="Dashboard report directory (default: ./output)")
    p_powershell.add_argument("--timeout", type=int, default=60, help="Container deadline in seconds (1..300)")
    p_powershell.set_defaults(func=_powershell)
    args = parser.parse_args(argv)
    if (getattr(args, "timeout", 1) <= 0 or getattr(args, "max_instructions", 1) <= 0
            or getattr(args, "memory_mb", 1) <= 0 or getattr(args, "max_output_mb", 1) <= 0):
        parser.error("limits must be positive")
    if args.command == "batch" and not 0 < args.max_samples <= 1000:
        parser.error("--max-samples must be between 1 and 1000")
    return args.func(args)


def _persona() -> int:
    print(json.dumps(DEFAULT_PERSONA, indent=2))
    return 0


def _powershell(args: argparse.Namespace) -> int:
    from .powershell import run_script, save_script_run
    try:
        report = run_script(Path(args.sample), Path(args.observer), Path(args.instrumented_engine),
                            timeout=args.timeout,
                            guest_tools_build=Path(args.guest_tools_build) if args.guest_tools_build else None,
                            persona_path=Path(args.persona) if args.persona else None)
        run_dir = save_script_run(report, _output_root(args.output))
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    print(json.dumps({"run_dir": str(run_dir), "status": "partial", "guest_exit_code": report["guest_exit_code"],
                      "commands": len(report["command_events"]), "errors": report["errors"]}, ensure_ascii=False))
    return 1 if report["errors"] else 0


def _dashboard(args: argparse.Namespace) -> int:
    from .dashboard import create_app
    app = create_app(_output_root(args.output))
    app.run(host="127.0.0.1", port=args.port, debug=False, use_reloader=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
