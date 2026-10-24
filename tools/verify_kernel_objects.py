"""Verify kernel object state and coherent MDL aliases in the isolated worker."""

import argparse
import hashlib
import json
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tests.test_kernel_objects import cache_probe, mdl_probe, pending_dpc_probe, simple_timer_probe, readonly_api_probe
from tests.test_kernel_runtime import runtime_driver
from emumee.reports import valid_summary, verify_artifact_manifest


def cases(machine):
    x64 = machine == 0x8664
    base = 0x140000000 if x64 else 0x400000
    for mode in ("complete", "free", "blocked"):
        yield "rundown-" + mode, cache_probe(machine, mode), None if mode == "blocked" else 0, "kernel thread scheduling" if mode == "blocked" else None
    for mode in ("alias", "free", "readonly", "nx", "unmapped", "free-active"):
        expected = {"alias": int.from_bytes(b"API!", "little"), "free": int.from_bytes(b"EMU!", "little")}.get(mode)
        error = {"readonly": "write-protected", "nx": "non-executable", "unmapped": "read", "free-active": "MDL with active mappings"}.get(mode)
        yield "mdl-" + mode, mdl_probe(machine, mode), expected, error
    for kind in (0, 1):
        event = runtime_driver(machine, ["KeInitializeEvent", "KeSetEvent", "KeWaitForSingleObject"],
            [(0, [base + 0x2300, kind, 0], False), (1, [base + 0x2300, 0, 0], False),
             (2, [base + 0x2300, 0, 0, 0, base + 0x23F0], False),
             (2, [base + 0x2300, 0, 0, 0, base + 0x23F0], False)])
        yield "event-" + str(kind), event, 0 if kind == 0 else 0x102, None
        args = [base + 0x2300] + ([0] if x64 else [0, 0]) + [0, 0]
        timer = runtime_driver(machine, ["KeInitializeTimerEx", "KeSetTimerEx", "KeWaitForSingleObject"],
            [(0, [base + 0x2300, kind], False), (1, args, False),
             (2, [base + 0x2300, 0, 0, 0, base + 0x23F0], False),
             (2, [base + 0x2300, 0, 0, 0, base + 0x23F0], False)])
        yield "timer-" + str(kind), timer, 0 if kind == 0 else 0x102, None
    due = (1 << 64) - 100000
    args = [base + 0x2300] + ([due] if x64 else [due & 0xFFFFFFFF, due >> 32]) + [0, 0]
    timer_wait = runtime_driver(machine, ["KeInitializeTimerEx", "KeSetTimerEx", "KeWaitForSingleObject"],
        [(0, [base + 0x2300, 1], False), (1, args, False), (2, [base + 0x2300, 0, 0, 0, base + 0x23F0], False)],
        [(0x23F0, struct.pack("<q", -200000))])
    yield "timer-wait", timer_wait, 0, None
    yield "timer-aliases", simple_timer_probe(machine), 1, None
    yield "timer-pending-dpc", pending_dpc_probe(machine), 0, "kernel callback scheduling"
    yield "mdl-api-readonly", readonly_api_probe(machine), None, "read-only MDL alias"
    yield "mdl-api-empty-write", readonly_api_probe(machine, 0), 0, None


def verify(root, worker):
    root.mkdir(parents=True, exist_ok=False)
    findings = []
    for machine, architecture in ((0x14C, "x86"), (0x8664, "x64")):
        for mode, payload, expected, error in cases(machine):
            name = architecture + "-" + mode
            sample = root / (name + ".sys")
            sample.write_bytes(payload)
            process = subprocess.run([str(worker), "run", str(sample), "--output", str(root / name),
                "--offline-replay", "--timeout", "5", "--max-instructions", "4000"],
                text=True, capture_output=True, timeout=60)
            result = json.loads(process.stdout)
            run = Path(result["report"]).parent
            summary = json.loads((run / "summary.json").read_text())
            raw = (run / "engine-report.json").read_bytes()
            report = json.loads(raw)
            assert process.returncode == int(error is not None), (name, result)
            assert summary["status"] == ("partial" if error else "completed"), (name, result)
            assert summary["guest_entry_return"] == expected, (name, result)
            assert valid_summary(summary) and verify_artifact_manifest(run, summary["artifacts"], summary["artifact_groups"]), name
            assert summary["engine_report_sha256"] == hashlib.sha256(raw).hexdigest(), name
            assert (run / "input.pe").read_bytes() == payload and summary["sample"]["sha256"] == hashlib.sha256(payload).hexdigest(), name
            assert summary["worker_containment"] and summary["network_broker_complete"], name
            assert not summary["network_attempts"] and not summary["api_coverage"]["signature_only_calls"], name
            assert json.loads((run / "network-broker.json").read_text()) == [{"event": "broker_closed"}], name
            if error:
                assert any(error.lower() in item.lower() for item in summary["errors"]), (name, summary["errors"])
            else:
                assert not summary["errors"], (name, summary["errors"])
            if mode == "mdl-alias":
                artifact = next(item for item in summary["artifacts"] if item["source"] == "modified_driver_image:0x2000")
                captured = (run / "artifacts" / artifact["file"]).read_bytes()
                assert captured[0x350:0x354] == b"CPU!" and captured[0x358:0x35C] == b"API!", name
                assert not report["kernel_mdls"]["user_aliases"] and not report["kernel_mdls"]["descriptors"], name
            if mode == "mdl-readonly":
                pool = next(item for item in summary["artifacts"] if item["source"].startswith("memory:api.pool.NonPagedPoolNx.VgTr"))
                assert (run / "artifacts" / pool["file"]).read_bytes()[0x123:0x127] == b"EMU!", name
            if mode in ("mdl-api-readonly", "mdl-api-empty-write"):
                pool = next(item for item in summary["artifacts"] if item["source"].startswith("memory:api.pool.NonPagedPoolNx.VgTr"))
                assert (run / "artifacts" / pool["file"]).read_bytes()[:4] == bytes(4), name
            if mode == "rundown-free":
                assert not report["kernel_cache_aware_rundown"]["references"], name
            findings.append({"case": name, "verified": True, "report": str(run / "summary.json")})
            print(name + ": guest state, exact bytes, protections and report integrity verified", flush=True)
    (root / "verification.json").write_text(json.dumps(findings, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--worker", type=Path, default=ROOT / "dist/Emumee/Emumee.exe")
    args = parser.parse_args()
    verify(args.destination.resolve(), args.worker.resolve())
