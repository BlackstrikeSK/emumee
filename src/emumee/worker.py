"""One analysis per process. Guest code is never started as a host process."""

from __future__ import annotations

import json
import hashlib
import traceback
from datetime import datetime, timezone
from pathlib import Path

from .appcontainer import verify_worker_containment
from .artifacts import MAX_ARTIFACT
from .bundle import (MAX_BUNDLE_BYTES, MAX_BUNDLE_FILES, MAX_BUNDLE_FILE_BYTES,
                     normalize_relative)
from .managed import run_managed
from .msi import inspect_msi
from .native import run_native
from .driver import run_driver
from .pe import InvalidSample, inspect_pe, inspect_pe_header
from .safeio import read_regular_file
from .kernel_code_reference import MAX_REFERENCE_BYTES
from .memory_strings import validate_options as validate_memory_strings


MAX_STAGED_INPUT_BYTES = 128 * 1024 * 1024
MAX_REQUEST_BYTES = 64 * 1024 * 1024


def _result_status(result: dict) -> tuple[str, str | None]:
    """An error-free trace is not evidence that guest execution completed."""
    if result.get("timeout_reached"):
        return "timeout", None
    if result.get("errors"):
        return "partial", None
    if result.get("completion_reason") in ("exit_process", "entry_return"):
        return "completed", None
    return "partial", "Guest completion path was not observed"


def _preflight_failure(run_dir: Path, message: str) -> None:
    (run_dir / "worker-error.txt").write_text(message, encoding="utf-8")
    raise InvalidSample(message)


def execute(run_dir: Path, expected_request_sha256: str | None = None) -> dict:
    containment = verify_worker_containment()
    request_diagnostics: list[str] = []
    request_raw = read_regular_file(run_dir / "request.json", MAX_REQUEST_BYTES,
                                    request_diagnostics, containment_root=run_dir)
    if request_raw is None:
        _preflight_failure(run_dir, "Staged request is unreadable or unsafe: " +
                           ", ".join(request_diagnostics))
    if (expected_request_sha256 is not None and
            hashlib.sha256(request_raw).hexdigest() != expected_request_sha256):
        _preflight_failure(run_dir, "Staged request changed")
    request = json.loads(request_raw)
    if not isinstance(request, dict):
        raise InvalidSample("Staged request must be a JSON object")
    memory_strings = validate_memory_strings(request.get("memory_strings"))
    data = read_regular_file(run_dir / "input.pe", MAX_STAGED_INPUT_BYTES,
                             containment_root=run_dir)
    if data is None:
        _preflight_failure(run_dir, "Staged execution input is unreadable or unsafe")
    if (expected_request_sha256 is not None and
            hashlib.sha256(data).hexdigest() != request.get("input_sha256")):
        _preflight_failure(run_dir, "Staged execution input changed")
    companion_hashes = request.get("companions_sha256")
    kernel_reference_data = None
    reference_hash = request.get('kernel_code_reference_sha256')
    reference_path = run_dir / 'kernel-code-reference.pe'
    if reference_hash is not None:
        if (not isinstance(reference_hash, str) or len(reference_hash) != 64 or
                any(c not in '0123456789abcdef' for c in reference_hash)):
            _preflight_failure(run_dir, 'Invalid staged kernel code reference digest')
        kernel_reference_data = read_regular_file(reference_path, MAX_REFERENCE_BYTES, containment_root=run_dir)
        if kernel_reference_data is None or hashlib.sha256(kernel_reference_data).hexdigest() != reference_hash:
            _preflight_failure(run_dir, 'Staged kernel code reference changed or is unsafe')
    elif reference_path.exists():
        _preflight_failure(run_dir, 'Unbound staged kernel code reference')
    if expected_request_sha256 is not None and not isinstance(companion_hashes, dict):
        raise InvalidSample("Staged companion hashes are missing")
    if isinstance(companion_hashes, dict):
        if set(companion_hashes) != set(request["dlls"]):
            raise InvalidSample("Staged companion list changed")
        for name in request["dlls"]:
            if not isinstance(name, str) or Path(name).name != name:
                raise InvalidSample("Invalid companion filename")
            companion = read_regular_file(run_dir / "inputs" / name, MAX_STAGED_INPUT_BYTES,
                                          containment_root=run_dir)
            if companion is None or hashlib.sha256(companion).hexdigest() != companion_hashes[name]:
                raise InvalidSample(f"Staged companion changed or is unsafe: {name}")
    bundle_hashes = request.get("bundle_files_sha256", {})
    if (not isinstance(bundle_hashes, dict) or len(bundle_hashes) > MAX_BUNDLE_FILES or
            (expected_request_sha256 is not None and "bundle_files_sha256" not in request)):
        raise InvalidSample("Staged bundle manifest is missing or exceeds limit")
    bundle_files: list[tuple[str, Path, bytes]] = []
    bundle_total = 0
    seen_bundle_paths: set[str] = set()
    guest_root = request.get("bundle_guest_root", request["persona"]["current_dir"])
    if not isinstance(guest_root, str) or not guest_root or len(guest_root) > 32767:
        raise InvalidSample("Invalid guest bundle root")
    for relative, digest in bundle_hashes.items():
        try:
            if normalize_relative(relative) != relative:
                raise ValueError("noncanonical path")
        except ValueError as exc:
            raise InvalidSample(f"Unsafe staged bundle path: {relative}") from exc
        if relative.casefold() in seen_bundle_paths:
            raise InvalidSample("Duplicate staged bundle path")
        seen_bundle_paths.add(relative.casefold())
        if not isinstance(digest, str) or len(digest) != 64:
            raise InvalidSample("Invalid staged bundle digest")
        source = (run_dir / "inputs").joinpath(*relative.split("/"))
        payload = read_regular_file(source, MAX_BUNDLE_FILE_BYTES,
                                    containment_root=run_dir)
        if payload is None or hashlib.sha256(payload).hexdigest() != digest:
            raise InvalidSample(f"Staged bundle file changed or is unsafe: {relative}")
        bundle_total += len(payload)
        if bundle_total > MAX_BUNDLE_BYTES:
            raise InvalidSample("Staged bundle exceeds 64 MiB")
        bundle_files.append((relative, source, payload))
    companion_guest_paths = request.get("companion_guest_paths", {})
    if not isinstance(companion_guest_paths, dict) or set(companion_guest_paths) not in (
            set(), set(request["dlls"])):
        raise InvalidSample("Staged companion guest paths changed")
    if any(not isinstance(value, str) or not value or len(value) > 32767
           for value in companion_guest_paths.values()):
        raise InvalidSample("Invalid companion guest path")
    header_info = inspect_pe_header(data, request["sample_name"])
    persona = request["persona"]
    if kernel_reference_data is not None and (header_info.kind != 'driver' or header_info.architecture != 'x64' or persona['windows_build'] != 22631):
        _preflight_failure(run_dir, 'Kernel code reference requires an x64 build22631 driver profile')
    started = datetime.now(timezone.utc).isoformat()
    summary = {"id": run_dir.name, "started_at": started, "sample": header_info.to_dict(),
               "persona": persona, "status": "running", "worker_containment": containment}
    (run_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    try:
        if header_info.kind == "msi":
            if request["dlls"] or request.get("all_exports"):
                raise InvalidSample("MSI inspection does not accept DLL loading options")
            result = inspect_msi(data, header_info, run_dir)
        else:
            info = inspect_pe(data, request["sample_name"])
            summary["sample"] = info.to_dict()
            if (type(request.get("driver_unload", False)) is not bool or
                    (request.get("driver_unload") and info.kind != "driver")):
                raise InvalidSample("Driver unload requires a driver input")
            if (type(request.get("all_exports", False)) is not bool or
                    (request.get("all_exports") and (info.kind != "dll" or info.managed))):
                raise InvalidSample("Export emulation requires a native DLL")
            if info.kind == "driver":
                if request["dlls"] or request.get("guest_args") or request.get("guest_env"):
                    raise InvalidSample("Driver inputs do not accept DLLs, process arguments, or environment overrides")
                result = run_driver(data, info, persona, run_dir, request["timeout"],
                                    request["max_instructions"],
                                    unload=request.get("driver_unload", False),
                                    kernel_code_reference=kernel_reference_data,
                                    memory_strings=memory_strings,
                                    bundle_files=bundle_files, bundle_guest_root=guest_root)
            elif info.managed:
                companions = []
                for name in request["dlls"]:
                    if not isinstance(name, str) or Path(name).name != name:
                        raise InvalidSample("Invalid companion filename")
                    source = run_dir / "inputs" / name
                    companion_data = read_regular_file(source, MAX_ARTIFACT,
                                                       containment_root=run_dir)
                    if companion_data is None or not companion_data:
                        raise InvalidSample("Managed companion is unsafe or exceeds limit")
                    companion_info = inspect_pe_header(companion_data, name)
                    if (companion_info.kind != "dll" or not companion_info.managed or
                            companion_info.architecture != info.architecture):
                        raise InvalidSample("Managed companion type or architecture mismatch")
                    companions.append((name, companion_data))
                result = run_managed(data, info, persona, run_dir,
                                     request["max_instructions"], companions=companions,
                                     memory_strings=memory_strings,
                                     guest_args=request.get("guest_args"),
                                     guest_env=request.get("guest_env"),
                                     bundle_files=[(name, payload) for name, _, payload in bundle_files],
                                     bundle_guest_root=guest_root)
            else:
                emulate_exports = request.get("all_exports", False)
                dlls = [run_dir / "inputs" / name for name in request["dlls"]]
                result = run_native(data, info, persona, run_dir, dlls,
                                    request["timeout"], request["max_instructions"],
                                    guest_args=request.get("guest_args"),
                                    guest_env=request.get("guest_env"),
                                    bundle_files=bundle_files,
                                    bundle_guest_root=guest_root,
                                    companion_guest_paths=companion_guest_paths,
                                    emulate_exports=emulate_exports,
                                    quoted_arg_indices=request.get("quoted_arg_indices"),
                                    memory_strings=memory_strings)
                (run_dir / "worker-stage.txt").write_text("native runner returned", encoding="utf-8")
        summary.update(result)
        summary["status"], completion_error = _result_status(result)
        if completion_error is not None:
            summary.setdefault("errors", []).append(completion_error)
    except Exception as exc:
        summary["status"] = "failed"
        summary["errors"] = [f"{type(exc).__name__}: {exc}"[:1024]]
        (run_dir / "worker-error.txt").write_text(traceback.format_exc()[:65536], encoding="utf-8")
    summary["finished_at"] = datetime.now(timezone.utc).isoformat()
    (run_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def main() -> None:
    import sys
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python -m emumee.worker RUN_DIRECTORY")
    result = execute(Path(sys.argv[1]).resolve())
    raise SystemExit(0 if result["status"] == "completed" else 1)


if __name__ == "__main__":
    main()
