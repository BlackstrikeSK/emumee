"""Verify guest-created kernel threads and DriverEntry resumption in AppContainer."""

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tests.test_kernel_threads import thread_probe, thread_chain_probe, thread_unload_probe
from emumee.reports import valid_summary, verify_artifact_manifest


def verify(root, worker, *, cases=None):
    root.mkdir(parents=True, exist_ok=False)
    findings = []
    for machine, architecture in ((0x14C, "x86"), (0x8664, "x64")):
        modes = cases or ("wait", "close", "attributes", "critical", "delay", "timeout", "poll", "return-first",
                     "deadlock", "budget", "fault", "unload", "many-any", "many-all", "priority", "chain", "priority-lookup", "shutdown-unload")
        for mode in modes:
            name = architecture + "-" + mode
            payload = (thread_chain_probe(machine) if mode == "chain" else
                       thread_unload_probe(machine) if mode == "shutdown-unload" else thread_probe(machine, mode))
            sample = root / (name + ".sys")
            sample.write_bytes(payload)
            budget = 300 if mode == "budget" else 4000
            command = [str(worker), "run", str(sample), "--output", str(root / name),
                       "--offline-replay", "--timeout", "5", "--max-instructions", str(budget)]
            if mode in ("unload", "shutdown-unload"): command.append("--driver-unload")
            process = subprocess.run(command, text=True, capture_output=True, timeout=60)
            result = json.loads(process.stdout)
            run = Path(result["report"]).parent
            summary = json.loads((run / "summary.json").read_text())
            raw = (run / "engine-report.json").read_bytes()
            report = json.loads(raw)
            partial = mode in ("deadlock", "budget", "fault")
            expected = None if partial else 0x102 if mode == "timeout" else 1 if mode == "many-any" else 0 if mode in ("many-all", "shutdown-unload") else 0x1234
            assert process.returncode == int(partial) and summary["status"] == ("partial" if partial else "completed"), (name, result)
            assert summary["guest_entry_return"] == expected, (name, result)
            assert valid_summary(summary) and verify_artifact_manifest(run, summary["artifacts"], summary["artifact_groups"]), name
            assert summary["engine_report_sha256"] == hashlib.sha256(raw).hexdigest(), name
            assert (run / "input.pe").read_bytes() == payload and summary["sample"]["sha256"] == hashlib.sha256(payload).hexdigest(), name
            assert summary["worker_containment"] and summary["network_broker_complete"], name
            assert not summary["network_attempts"] and not summary["api_coverage"]["signature_only_calls"], name
            assert json.loads((run / "network-broker.json").read_text()) == [{"event": "broker_closed"}], name
            threads = report["kernel_scheduling"]["threads"]
            assert len(threads) == (2 if mode == "chain" else 1), (name, threads)
            assert all(thread["started"] and thread["pid"] == 4 for thread in threads), (name, threads)
            if mode == "chain":
                assert len({thread["tid"] for thread in threads}) == 2 and all(thread["state"] == "done" for thread in threads), name
                waits = [event for entry in report["entry_points"] for event in entry["events"]
                         if event.get("api_name") == "ntoskrnl.KeWaitForSingleObject"]
                assert len(waits) == 3 and all(event["ret_val"] == "0x0" for event in waits), (name, waits)
            if not partial:
                assert not summary["errors"], (name, summary["errors"])
            else:
                assert summary["errors"], name
            if mode == "close": assert report["kernel_scheduling"]["open_thread_handles"] == 0, name
            if mode == "budget": assert summary["instruction_count"] == 300 and summary["instruction_limit_reached"], name
            if mode in ("unload", "shutdown-unload"): assert summary["driver"]["unload_completed"], name
            if mode == "shutdown-unload":
                assert threads[0]["state"] == "done", name
                waits = [event for entry in report["entry_points"] for event in entry["events"]
                         if event.get("api_name") == "ntoskrnl.KeWaitForSingleObject"]
                assert len(waits) == 2 and all(event["ret_val"] == "0x0" for event in waits), name
            if mode in ("priority", "priority-lookup"): assert threads[0]["recorded_priority"] == 15, name
            if mode == "priority-lookup":
                lookups = [event for entry in report["entry_points"] for event in entry["events"]
                           if event.get("api_name") == "ntoskrnl.MmGetSystemRoutineAddress"]
                assert len(lookups) == 1 and lookups[0]["args"] == ["KeSetActualBasePriorityThread"], name
                assert int(lookups[0]["ret_val"], 0) > 0, name
            if mode == "wait":
                artifact = next(item for item in summary["artifacts"] if item["source"] == "modified_driver_image:0x2000")
                data = (run / "artifacts" / artifact["file"]).read_bytes()
                width = 8 if machine == 0x8664 else 4
                assert data[0x340:0x340 + width] != data[0x348:0x348 + width], name
                assert int.from_bytes(data[0x350:0x350 + width], "little") == int(threads[0]["object"], 0), name
            findings.append({"case": name, "verified": True, "report": str(run / "summary.json")})
            print(name + ": native thread instructions, context, lifecycle and integrity verified", flush=True)
    (root / "verification.json").write_text(json.dumps(findings, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--worker", type=Path, default=ROOT / "dist/Emumee/Emumee.exe")
    parser.add_argument("--case", action="append", choices=("chain", "priority-lookup", "shutdown-unload"), help="Run only the selected additional cases")
    args = parser.parse_args()
    verify(args.destination.resolve(), args.worker.resolve(), cases=args.case)
