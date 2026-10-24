"""Run and verify harmless drivers through the actual AppContainer worker."""

import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tests.fixtures.build_driver import build_driver, build_driver_file_probe
from emumee.reports import valid_summary, verify_artifact_manifest


def verify(root, worker=None):
    root.mkdir(parents=True, exist_ok=False)
    worker = worker or ROOT / "dist/Emumee/Emumee.exe"
    findings = []
    for machine, arch in ((0x14C, "x86"), (0x8664, "x64")):
        cases = [("success", False), ("success", True), ("failure", True),
                 ("loop", False), ("fault", False), ("unknown", False),
                 ("unload_loop", True), ("unload_fault", True)]
        for mode, unload in cases:
            case = f"{arch}-{mode}" + ("-unload" if unload else "")
            sample = root / f"{case}.sys"
            data = build_driver(machine, mode)
            sample.write_bytes(data)
            command = [str(worker), "run", str(sample), "--output", str(root / case),
                       "--timeout", "5", "--max-instructions", "100", "--offline-replay"]
            if unload:
                command.append("--driver-unload")
            process = subprocess.run(command, capture_output=True, text=True, timeout=45)
            result = json.loads(process.stdout)
            run = Path(result["report"]).parent
            summary = json.loads((run / "summary.json").read_text())
            expected = "completed" if mode in ("success", "failure") else "partial"
            assert summary["status"] == expected, (case, summary.get("errors"))
            assert process.returncode == (0 if expected == "completed" else 1), case
            assert valid_summary(summary), case
            assert summary["execution_mode"] == "kernel", case
            assert (run / "input.pe").read_bytes() == data, case
            assert summary["sample"]["sha256"] == hashlib.sha256(data).hexdigest(), case
            assert summary["guest_exit_code"] is None, case
            assert summary["driver"]["unload_completed"] == (mode == "success" and unload), case
            if mode == "success":
                assert summary["driver"]["entry_status"] == 0, case
                assert len(summary["driver"]["devices_created"]) == 1, case
                assert summary["driver"]["dispatch_routines"], case
                assert summary["api_coverage"]["api_calls"] == (3 if unload else 2), case
                pools = [item for item in summary["artifacts"] if item["source"].startswith("memory:api.pool.")]
                assert pools and any((run / "artifacts" / item["file"]).read_bytes().startswith(b"EMU!")
                                     for item in pools), case
            elif mode == "failure":
                assert summary["driver"]["entry_status"] == 0xC0000001, case
                assert not summary["driver"]["initialization_succeeded"], case
            elif mode.endswith("loop"):
                assert summary["instruction_limit_reached"] and summary["instruction_count"] <= 100, case
            if mode in ("loop", "fault", "unknown"):
                assert summary["driver"]["entry_status"] is None, case
            if mode == "unknown":
                assert any("ntoskrnl.MissingEmumeeKernelApi" in error for error in summary["errors"]), case
            assert verify_artifact_manifest(run, summary["artifacts"], summary["artifact_groups"]), case
            assert summary["worker_containment"], case
            assert summary["network_broker_complete"] is True, case
            assert summary["denied_operations"] == 0 and not summary["network_attempts"], case
            broker = json.loads((run / "network-broker.json").read_text())
            assert broker == [{"event": "broker_closed"}], (case, broker)
            raw = (run / "engine-report.json").read_bytes()
            assert hashlib.sha256(raw).hexdigest() == summary["engine_report_sha256"], case
            assert json.loads(raw)["driver"] == summary["driver"], case
            findings.append({"case": case, "report": str(run / "summary.json"), "verified": True})
            print(f"{case}: {expected}; lifecycle, artifacts, isolation and broker verified", flush=True)
    (root / "verification.json").write_text(json.dumps(findings, indent=2))


def verify_boundary(root, worker=None):
    root.mkdir(parents=True, exist_ok=False)
    worker = worker or ROOT / "dist/Emumee/Emumee.exe"
    findings = []
    for machine, arch in ((0x14C, "x86"), (0x8664, "x64")):
        marker = root / f"host-marker-{arch}.txt"
        data = build_driver_file_probe(machine, str(marker))
        sample = root / f"file-{arch}.sys"
        sample.write_bytes(data)
        process = subprocess.run([str(worker), "run", str(sample), "--output", str(root / arch),
                                  "--timeout", "5", "--max-instructions", "1000", "--offline-replay"],
                                 capture_output=True, text=True, timeout=45)
        result = json.loads(process.stdout)
        run = Path(result["report"]).parent
        summary = json.loads((run / "summary.json").read_text())
        assert process.returncode == 0 and summary["status"] == "completed", (arch, result)
        assert not marker.exists(), f"Kernel file API touched host marker: {marker}"
        assert (run / "input.pe").read_bytes() == data, arch
        assert summary["driver"]["entry_status"] == 0, arch
        assert valid_summary(summary), arch
        raw = (run / "engine-report.json").read_bytes()
        assert hashlib.sha256(raw).hexdigest() == summary["engine_report_sha256"], arch
        events = json.loads(raw)["entry_points"][0]["events"]
        assert any(event.get("event") == "file_open" and event.get("path") == str(marker)
                   for event in events), (arch, events)
        broker = json.loads((run / "network-broker.json").read_text())
        assert broker == [{"event": "broker_closed"}], arch
        assert summary["worker_containment"] and summary["network_broker_complete"], arch
        findings.append({"architecture": arch, "report": str(run / "summary.json"),
                         "host_marker_created": False, "guest_creation_observed": True})
        print(f"{arch}: kernel ZwCreateFile stayed in guest state; host marker absent", flush=True)
    (root / "verification.json").write_text(json.dumps(findings, indent=2))


def verify_context(root, worker=None):
    from tests.test_driver_image import relocated_probe
    from tests.test_kernel_api import pc_lookup_probe
    from tests.test_kernel_pool import pool_probe, zero_pool_probe
    from tests.test_kernel_callbacks import callback_probe
    from tests.test_kernel_sync import sync_probe
    from tests.test_kernel_environment import environment_probe
    worker = worker or ROOT / "dist/Emumee/Emumee.exe"
    root.mkdir(parents=True, exist_ok=False)
    cases = [("x86-relocated", bytes(relocated_probe(0x14C)), 42),
             ("x64-relocated", bytes(relocated_probe(0x8664)), 42)]
    for machine, arch in ((0x14C, "x86"), (0x8664, "x64")):
        for mode in ("register", "deregister"):
            cases.append((f"{arch}-callback-{mode}", callback_probe(machine, mode), 1))
        for kind, mode in (("guarded", "released"), ("push", "released"), ("rundown", "complete"), ("irql", "lowered")):
            cases.append((f"{arch}-sync-{kind}", sync_probe(machine, kind, mode), 0))
        for kind, expected in (("time", 0), ("counter", 0), ("processors", 1), ("number", 0)):
            cases.append((f"{arch}-env-{kind}", environment_probe(machine, kind), expected))
        cases.append((f"{arch}-execute-pool", pool_probe(machine, 0), 42))
        cases.append((f"{arch}-nx-pool", pool_probe(machine, 0x200), None))
        cases.append((f"{arch}-zero-nx-pool", pool_probe(machine, 0x600), None))
        cases.append((f"{arch}-zero-pool-bytes", zero_pool_probe(machine), 0))
        for found in (False, True):
            cases.append((f"{arch}-pc-lookup-{'found' if found else 'missing'}", pc_lookup_probe(machine, found), 1))
    for name, code, expected in (
        ("x64-pcr", "65488b04251800000048c1e83fc3", 1),
        ("x64-lock-queue", "65488b042528000000488b4068482500f0ffff6681384d5a7408482d00100000ebf10fb700c3", 0x5A4D),
    ):
        data = bytearray(build_driver(0x8664))
        code = bytes.fromhex(code)
        data[0x200:0x200 + len(code)] = code
        cases.append((name, bytes(data), expected))
    findings = []
    for name, data, expected in cases:
        sample = root / f"{name}.sys"
        sample.write_bytes(data)
        process = subprocess.run([str(worker), "run", str(sample),
            "--output", str(root / name), "--timeout", "5", "--max-instructions", "1000", "--offline-replay"],
            capture_output=True, text=True, timeout=45)
        result = json.loads(process.stdout)
        run = Path(result["report"]).parent
        summary = json.loads((run / "summary.json").read_text())
        raw = (run / "engine-report.json").read_bytes()
        report = json.loads(raw)
        assert process.returncode == (0 if expected is not None else 1), (name, result)
        assert summary["status"] == ("completed" if expected is not None else "partial"), (name, result)
        assert summary["driver"]["entry_status"] == expected, name
        assert (run / "input.pe").read_bytes() == data, name
        assert summary["sample"]["sha256"] == hashlib.sha256(data).hexdigest(), name
        assert hashlib.sha256(raw).hexdigest() == summary["engine_report_sha256"], name
        assert valid_summary(summary) and verify_artifact_manifest(run, summary["artifacts"], summary["artifact_groups"]), name
        assert summary["worker_containment"] and summary["network_broker_complete"], name
        assert not summary["network_attempts"] and not summary["denied_operations"], name
        assert not summary["api_coverage"]["signature_only_calls"], name
        assert json.loads((run / "network-broker.json").read_text()) == [{"event": "broker_closed"}], name
        if name.endswith("relocated"):
            assert report["image_placement"]["placement"] == "kernel_address_range", name
            assert report["driver_image_changes"]["changed_pages"] == 1, name
        if name.endswith("nx-pool"):
            assert any("non-executable" in error for error in summary["errors"]), name
        if name.endswith("zero-pool-bytes"):
            pool = next(item for item in summary["artifacts"] if item["source"].startswith("memory:api.pool."))
            assert (run / "artifacts" / pool["file"]).read_bytes() == bytes(4096), name
        if "-callback-" in name:
            callbacks = report["kernel_bugcheck_callbacks"]
            assert len(callbacks["registered"]) == (0 if name.endswith("deregister") else 1), name
            assert callbacks["callbacks_executed"] == 0, name
        if "-sync-" in name:
            state = report["kernel_synchronization"]
            assert state["irql"] == 0 and state["critical_region_depth"] == 0 and not state["held_guarded_mutexes"], name
        if name.endswith("env-counter"):
            import struct
            artifact = next(item for item in summary["artifacts"] if item["source"] == "modified_driver_image:0x2000")
            captured = (run / "artifacts" / artifact["file"]).read_bytes()
            assert struct.unpack_from("<Q", captured, 0x300)[0] == 10_000_000, name
            assert struct.unpack_from("<Q", captured, 0x310)[0] > 0xFFFFFFFF, name
        findings.append({"case": name, "report": str(run / "summary.json"), "verified": True})
        print(f"{name}: kernel CPU context, artifacts and isolation verified", flush=True)
    (root / "verification.json").write_text(json.dumps(findings, indent=2))


def verify_control(root, worker=None):
    root.mkdir(parents=True, exist_ok=False)
    worker = worker or ROOT / "dist/Emumee/Emumee.exe"
    data = build_driver(0x8664, "loop")
    sample = root / "controlled.sys"
    sample.write_bytes(data)
    process = subprocess.Popen([str(worker), "run", str(sample), "--output", str(root / "runs"),
        "--timeout", "20", "--max-instructions", "5000000", "--offline-replay"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    deadline = time.monotonic() + 35
    requested = False
    while process.poll() is None and time.monotonic() < deadline:
        progress = next((root / "runs").glob("*/driver-progress.json"), None)
        if progress is not None:
            (progress.parent / "driver-control.json").write_text('{"stop": true}', encoding="utf-8")
            requested = True
            break
        time.sleep(0.05)
    stdout, stderr = process.communicate(timeout=45)
    assert requested, (stdout, stderr)
    result = json.loads(stdout)
    run = Path(result["report"]).parent
    summary = json.loads((run / "summary.json").read_text())
    raw = (run / "engine-report.json").read_bytes()
    assert process.returncode == 1 and summary["status"] == "partial", result
    assert summary["completion_reason"] == "cancelled", result
    assert summary["guest_entry_return"] is None and summary["driver"]["entry_status"] is None, result
    assert 0 < summary["instruction_count"] < 5_000_000, result
    assert not summary["timeout_reached"] and not summary["instruction_limit_reached"], result
    assert (run / "input.pe").read_bytes() == data, result
    assert hashlib.sha256(raw).hexdigest() == summary["engine_report_sha256"], result
    assert valid_summary(summary) and verify_artifact_manifest(run, summary["artifacts"], summary["artifact_groups"]), result
    assert summary["worker_containment"] and summary["network_broker_complete"], result
    assert json.loads((run / "network-broker.json").read_text()) == [{"event": "broker_closed"}], result
    assert json.loads((run / "driver-progress.json").read_text())["status"] == "stopped", result
    (root / "verification.json").write_text(json.dumps([{"case": "analyst-control", "verified": True,
        "report": str(run / "summary.json"), "instruction_count": summary["instruction_count"]}], indent=2))
    print("analyst-control: partial trace, artifacts and normal sandbox cleanup preserved", flush=True)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--worker", type=Path, default=ROOT / "dist/Emumee/Emumee.exe")
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--boundary-only", action="store_true")
    selection.add_argument("--context-only", action="store_true")
    selection.add_argument("--control-only", action="store_true")
    arguments = parser.parse_args()
    destination, worker = arguments.destination.resolve(), arguments.worker.resolve()
    if arguments.boundary_only:
        verify_boundary(destination, worker)
    elif arguments.context_only:
        verify_context(destination, worker)
    elif arguments.control_only:
        verify_control(destination, worker)
    else:
        verify(destination, worker)
        verify_boundary(destination / "boundary", worker)
        verify_context(destination / "context", worker)
        verify_control(destination / "control", worker)
