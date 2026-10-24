"""Verify kernel file handles and host-path separation in the packaged worker."""

import hashlib
import json
import subprocess
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tests.test_kernel_files import file_probe
from emumee.reports import valid_summary, verify_artifact_manifest


def verify(root, worker=None):
    worker = worker or ROOT / "dist/Emumee/Emumee.exe"
    root.mkdir(parents=True, exist_ok=False)
    findings = []
    for machine, architecture in ((0x14C, "x86"), (0x8664, "x64")):
        for mode in ("write", "close", "duplicate"):
            name = f"{architecture}-{mode}"
            host_path = Path(r"C:\Windows\Temp") / ("emumee-kernel-" + uuid.uuid4().hex + ".bin")
            assert not host_path.exists(), host_path
            payload = file_probe(machine, str(host_path), mode, options=0x21 if mode == "duplicate" else 0x60)
            sample = root / (name + ".sys")
            sample.write_bytes(payload)
            process = subprocess.run([str(worker), "run", str(sample),
                "--output", str(root / name), "--offline-replay", "--timeout", "5", "--max-instructions", "2000"],
                text=True, capture_output=True, timeout=45)
            result = json.loads(process.stdout)
            run = Path(result["report"]).parent
            summary = json.loads((run / "summary.json").read_text())
            assert process.returncode == 0 and summary["status"] == "completed", (name, result)
            expected = {"write": 0, "close": 0xC0000008, "duplicate": 0xC0000035}[mode]
            assert summary["guest_entry_return"] == expected, (name, result)
            assert not host_path.exists(), host_path
            assert summary["errors"] == [] and not summary["api_coverage"]["signature_only_calls"], name
            assert valid_summary(summary) and verify_artifact_manifest(run, summary["artifacts"], summary["artifact_groups"]), name
            assert (run / "input.pe").read_bytes() == payload and summary["sample"]["sha256"] == hashlib.sha256(payload).hexdigest(), name
            assert summary["worker_containment"] and summary["network_broker_complete"], name
            assert json.loads((run / "network-broker.json").read_text()) == [{"event": "broker_closed"}], name
            assert hashlib.sha256((run / "engine-report.json").read_bytes()).hexdigest() == summary["engine_report_sha256"], name
            files = [item for item in summary["artifacts"] if item["source"] == "virtual_file_final"]
            if mode == "write":
                assert len(files) == 1 and (run / "artifacts" / files[0]["file"]).read_bytes() == b"EMU!", name
            else:
                assert not files, name
            findings.append({"case": name, "verified": True, "host_path_absent": str(host_path), "report": str(run / "summary.json")})
            print(f"{name}: status, exact bytes, host-path absence and isolation verified", flush=True)
    (root / "verification.json").write_text(json.dumps(findings, indent=2))


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--worker", type=Path, default=ROOT / "dist/Emumee/Emumee.exe")
    args = parser.parse_args()
    verify(args.destination.resolve(), args.worker.resolve())
