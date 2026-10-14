"""Verify packaged managed FileStream effects and recovered guest bytes."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
DEFAULT_RUNS = PROJECT / "output" / "managed-stream-package"


def main(runs_root: Path = DEFAULT_RUNS) -> None:
    reports = list(runs_root.glob("*/summary.json"))
    assert len(reports) == 1, "expected one packaged ManagedStreams run"
    run_dir = reports[0].parent
    summary = json.loads(reports[0].read_text(encoding="utf-8"))
    report = json.loads((run_dir / "engine-report.json").read_text(encoding="utf-8"))
    assert summary["status"] == "completed" and not summary.get("errors")
    assert summary["engine"] == "emumee-cil" and summary["network_broker_complete"] is True
    recovered = {}
    for item in summary["artifacts"]:
        payload = (run_dir / "artifacts" / item["file"]).read_bytes()
        assert len(payload) == item["size"]
        assert hashlib.sha256(payload).hexdigest() == item["sha256"]
        recovered[item["guest_path"]] = payload
    base = r"C:\Users\Alex\Downloads\managed-stream-"
    assert recovered[base + "read.bin"] == b"\0ABZD" + b"\0" * 5
    assert recovered[base + "final.bin"] == b"QBZDEF\0\0"
    assert recovered[base + "state.txt"] == b"read-ok;share-denied;constructors-ok"
    events = report["events"]
    assert sum(event.get("event") == "file_stream_open" for event in events) == 5
    assert sum(event.get("event") == "file_stream_close" for event in events) == 5
    assert any(event.get("event") == "file_stream_read" and event.get("size") == 4
               for event in events)
    assert any(event.get("event") == "file_stream_seek" and event.get("position") == 7
               for event in events)
    assert summary["cil_coverage"] == report["cil_coverage"]
    print("packaged managed streams: guest state, sharing, and artifact hashes verified")


if __name__ == "__main__":
    main(Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else DEFAULT_RUNS)
