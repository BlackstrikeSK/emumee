"""Verify module queries and allocated-code reporting in an isolated worker."""

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tests.test_kernel_system_information import system_information_probe, image_range, verify_module_result
from tests.test_kernel_memory_report import allocated_code_probe, verify_memory_result
from emumee.reports import valid_summary, verify_artifact_manifest


def verify(root, worker):
    root.mkdir(parents=True, exist_ok=False)
    findings = []
    for machine, architecture in ((0x14C, "x86"), (0x8664, "x64")):
        cases = [(mode, alias, False) for mode in ("standard", "extended", "optional") for alias in (False, True)]
        cases += [("extended", False, True)]
        cases += [(mode, False, False) for mode in ("short", "null", "unmapped", "readonly", "return-readonly", "return-unmapped", "unknown")]
        for mode, alias, relocated in cases + [("pool-exec", False, False), ("pool-nx", False, False)]:
            name = f'{architecture}-{mode}{"-nt" if alias else ""}{"-relocated" if relocated else ""}'
            case = root / name
            case.mkdir()
            payload = (allocated_code_probe(machine, mode == "pool-exec") if mode.startswith("pool-") else
                       system_information_probe(machine, mode, alias, relocated))
            sample = case / "system-info.sys"
            sample.write_bytes(payload)
            process = subprocess.run([str(worker), "run", str(sample), "--output", str(case / "runs"),
                "--offline-replay", "--timeout", "5", "--max-instructions", "3000"],
                text=True, capture_output=True, timeout=60)
            assert process.returncode in (0, 1), (name, process.stdout, process.stderr)
            outcome = json.loads(process.stdout)
            run = Path(outcome["report"]).parent
            summary = json.loads((run / "summary.json").read_text())
            raw = (run / "engine-report.json").read_bytes()
            report = json.loads(raw)
            partial = mode not in ("standard", "extended", "optional", "short", "pool-exec")
            assert process.returncode == int(partial) and summary["status"] == ("partial" if partial else "completed"), name
            assert summary["guest_entry_return"] == (None if partial else 0), name
            assert valid_summary(summary) and verify_artifact_manifest(run, summary["artifacts"], summary["artifact_groups"]), name
            assert summary["sample"]["sha256"] == hashlib.sha256(payload).hexdigest() and (run / "input.pe").read_bytes() == payload, name
            assert summary["engine_report_sha256"] == hashlib.sha256(raw).hexdigest(), name
            assert all(summary["worker_containment"][key] for key in ("app_container", "job_object", "child_process_blocked")), name
            assert summary["network_broker_complete"] and json.loads((run / "network-broker.json").read_text()) == [{"event": "broker_closed"}], name
            if mode.startswith("pool-"):
                verify_memory_result(report, mode == "pool-exec")
            elif mode in ("standard", "extended", "optional"):
                verify_module_result(summary, run, machine, mode)
                if relocated:
                    assert report["image_base"] == (0xFFFFF80100000000 if machine == 0x8664 else 0x90000000), name
            else:
                data = image_range(summary, run, 0x2300, 0x100)
                assert data[0xF0:0xF4] == b"MARK", name
                assert (data[0xF8:0xFC] != b"DONE") == partial, name
                assert report["driver_image_changes"]["changed_pages"] == 1, name
                if mode == "short":
                    assert int.from_bytes(data[0x80:0x84], "little") == 0xC0000004 and int.from_bytes(data[:4], "little") > 300, name
                else:
                    assert report["entry_points"][0]["error"], name
            findings.append({"case": name, "verified": True, "report": str(run / "summary.json")})
            print(f'{name}: native query/reporting behavior and isolated trace verified', flush=True)
    (root / "verification.json").write_text(json.dumps(findings, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--worker", type=Path, default=ROOT / "dist/Emumee/Emumee.exe")
    args = parser.parse_args()
    verify(args.destination.resolve(), args.worker.resolve())
