"""Verify packaged managed path-string operations and virtual writes."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


def main(runs_root: Path) -> None:
    summaries = list(runs_root.glob("*/summary.json"))
    assert len(summaries) == 1, "expected one packaged ManagedPathParts run"
    run_dir = summaries[0].parent
    summary = json.loads(summaries[0].read_text(encoding="utf-8"))
    report = json.loads((run_dir / "engine-report.json").read_text(encoding="utf-8"))
    assert summary["status"] == "completed" and not summary.get("errors")
    assert summary["engine"] == "emumee-cil" and summary["network_broker_complete"] is True
    roaming = r"C:\Users\Alex\AppData\Roaming"
    tag = "emumee-path-DESKTOP-7F4M2Q9"
    expected = {
        roaming + "\\" + tag + ".dat": b"payload-path-parts",
        roaming + "\\" + tag + "-state.txt": b"parts-ok",
    }
    recovered = {}
    for item in summary["artifacts"]:
        payload = (run_dir / "artifacts" / item["file"]).read_bytes()
        assert len(payload) == item["size"]
        assert hashlib.sha256(payload).hexdigest() == item["sha256"]
        recovered[item["guest_path"]] = payload
    assert recovered == expected
    calls = {event.get("method") for event in report["events"]
             if event.get("event") == "managed_call"}
    for method in ("GetFileName", "GetFileNameWithoutExtension", "GetExtension",
                   "HasExtension", "GetDirectoryName", "IsPathRooted", "GetPathRoot",
                   "ChangeExtension"):
        assert "System.IO.Path." + method in calls, method
    assert summary["cil_coverage"] == report["cil_coverage"]
    print("packaged managed path parts: guest bytes, path calls, and hashes verified")


if __name__ == "__main__":
    main(Path(sys.argv[1]).resolve())
