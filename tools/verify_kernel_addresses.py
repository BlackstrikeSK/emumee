"""Verify native kernel pointer and fault contracts inside the packaged worker."""

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tests.test_kernel_addresses import address_probe
from emumee.reports import valid_summary, verify_artifact_manifest


def verify(root, worker):
    root.mkdir(parents=True, exist_ok=False)
    findings = []
    for machine, architecture in ((0x14C, "x86"), (0x8664, "x64")):
        width = 8 if machine == 0x8664 else 4
        for mode in ("pointers", "stack-nx", "object-nx", "unmapped-read", "unmapped-write", "unmapped-fetch", "unresolved-read"):
            name = f"{architecture}-{mode}"
            payload = address_probe(machine, mode)
            sample = root / (name + ".sys")
            sample.write_bytes(payload)
            process = subprocess.run([str(worker), "run", str(sample), "--output", str(root / name),
                "--offline-replay", "--timeout", "5", "--max-instructions", "1000"],
                text=True, capture_output=True, timeout=60)
            assert process.returncode in (0, 1), (name, process.stdout, process.stderr)
            outcome = json.loads(process.stdout)
            run = Path(outcome["report"]).parent
            summary = json.loads((run / "summary.json").read_text())
            raw = (run / "engine-report.json").read_bytes()
            report = json.loads(raw)
            partial = mode != "pointers"
            assert process.returncode == int(partial) and summary["status"] == ("partial" if partial else "completed"), (name, outcome)
            assert summary["guest_entry_return"] == (None if partial else 0), name
            assert valid_summary(summary) and verify_artifact_manifest(run, summary["artifacts"], summary["artifact_groups"]), name
            assert (run / "input.pe").read_bytes() == payload and summary["sample"]["sha256"] == hashlib.sha256(payload).hexdigest(), name
            assert summary["worker_containment"] and summary["network_broker_complete"], name
            assert json.loads((run / "network-broker.json").read_text()) == [{"event": "broker_closed"}], name
            assert summary["engine_report_sha256"] == hashlib.sha256(raw).hexdigest(), name
            item = next(item for item in summary["artifacts"] if item["source"] == "modified_driver_image:0x2000")
            data = (run / "artifacts" / item["file"]).read_bytes()
            value = lambda offset: int.from_bytes(data[offset:offset + width], "little")
            minimum = 0xFFFF800000000000 if width == 8 else 0x80000000
            assert all(value(offset) >= minimum for offset in (0x380, 0x388, 0x390, 0x398)), name
            if partial:
                expected = {"unmapped-read": "invalid_read", "unmapped-write": "invalid_write", "unmapped-fetch": "invalid_fetch", "unresolved-read": "unresolved_kernel_import_read"}.get(mode, "invalid_execute")
                error = report["entry_points"][0]["error"]
                assert error["type"] == expected, name
                if mode.startswith("unmapped-"):
                    assert int(error["address"], 0) == 0x7FFF7000, name
                if mode == "unresolved-read":
                    assert error["api_name"] == "ntoskrnl.MissingEmumeeKernelData", name
                    assert int(error["address"], 0) == value(0x3C0), name
                assert data[0x3F8:0x3FC] != bytes.fromhex("efbeadde"), name
            else:
                assert summary["errors"] == [] and not summary["api_coverage"]["signature_only_calls"], name
                assert value(0x380) == value(0x3E0) and value(0x3D0) == value(0x3D8), name
                assert value(0x3D0) <= value(0x380) < value(0x3D0) + 0x10000, name
                assert value(0x3E8) == 0 and value(0x3F0) < 256, name
            findings.append({"case": name, "verified": True, "report": str(run / "summary.json")})
            print(f"{name}: native pointers, permissions, fault boundary and isolation verified", flush=True)
    (root / "verification.json").write_text(json.dumps(findings, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--worker", type=Path, default=ROOT / "dist/Emumee/Emumee.exe")
    args = parser.parse_args()
    verify(args.destination.resolve(), args.worker.resolve())
