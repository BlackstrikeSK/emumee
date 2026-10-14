"""Verify packaged managed byte-array mutation stays in the guest file map."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


def main(runs_root: Path) -> None:
    reports = list(runs_root.glob("*/summary.json"))
    assert len(reports) == 1, "expected one packaged ManagedByteArray run"
    run_dir = reports[0].parent
    summary = json.loads(reports[0].read_text(encoding="utf-8"))
    report = json.loads((run_dir / "engine-report.json").read_text(encoding="utf-8"))
    assert summary["status"] == "completed" and not summary.get("errors")
    assert summary["engine"] == "emumee-cil" and summary["network_broker_complete"] is True
    expected = {
        r"C:\Users\Alex\Downloads\managed-array-source.bin": b"ABC",
        r"C:\Users\Alex\Downloads\managed-array-edited.bin": b"AZC",
        r"C:\Users\Alex\Downloads\managed-array-state.txt":
            b"independent;negative-index;upper-bound;negative-ref;null-array",
    }
    recovered = {}
    for item in summary["artifacts"]:
        payload = (run_dir / "artifacts" / item["file"]).read_bytes()
        assert len(payload) == item["size"]
        assert hashlib.sha256(payload).hexdigest() == item["sha256"]
        recovered[item["guest_path"]] = payload
    assert recovered == expected
    assert [event["type"] for event in report["events"]
            if event.get("event") == "managed_catch"] == [
                "System.IndexOutOfRangeException",
                "System.IndexOutOfRangeException",
                "System.IndexOutOfRangeException",
                "System.NullReferenceException",
            ]
    assert summary["cil_coverage"] == report["cil_coverage"]
    print("packaged managed byte array: mutation, bounds exceptions, and artifact hashes verified")


if __name__ == "__main__":
    main(Path(sys.argv[1]).resolve())
