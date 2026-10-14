"""Verify packaged guest-only MemoryStream and FileStream copies."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


def main(runs_root: Path) -> None:
    reports = list(runs_root.glob("*/summary.json"))
    assert len(reports) == 1, "expected one packaged ManagedMemoryCopy run"
    run_dir = reports[0].parent
    summary = json.loads(reports[0].read_text(encoding="utf-8"))
    report = json.loads((run_dir / "engine-report.json").read_text(encoding="utf-8"))
    assert summary["status"] == "completed" and not summary.get("errors")
    assert summary["engine"] == "emumee-cil" and summary["network_broker_complete"] is True
    prefix = r"C:\Users\Alex\Downloads\managed-memory-"
    expected = {
        prefix + "read.bin": b"\0BZD\0",
        prefix + "copy.bin": b"BZDEF\0\0",
        prefix + "roundtrip.bin": b"DEF\0\0",
        prefix + "backing.bin": b"QMN",
        prefix + "state.txt": b"copy-ok;fixed-ok",
    }
    recovered = {}
    for item in summary["artifacts"]:
        payload = (run_dir / "artifacts" / item["file"]).read_bytes()
        assert len(payload) == item["size"]
        assert hashlib.sha256(payload).hexdigest() == item["sha256"]
        if "guest_path" in item:
            recovered[item["guest_path"]] = payload
    assert recovered == expected
    assert [event["size"] for event in report["events"]
            if event.get("event") == "managed_stream_copy"] == [7, 5]
    assert [event["type"] for event in report["events"]
            if event.get("event") == "managed_catch"] == ["System.NotSupportedException"]
    assert summary["cil_coverage"] == report["cil_coverage"]
    print("packaged managed memory copy: positions, guest bytes, and artifact hashes verified")


if __name__ == "__main__":
    main(Path(sys.argv[1]).resolve())
