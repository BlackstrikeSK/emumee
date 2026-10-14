"""Verify packaged CIL directory state and guest-only file recovery."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
DEFAULT_RUNS = PROJECT / "output" / "managed-directory-package"


def main(runs_root: Path = DEFAULT_RUNS) -> None:
    summaries = list(runs_root.glob("*/summary.json"))
    assert len(summaries) == 1, "expected one packaged managed directory report"
    run_dir = summaries[0].parent
    summary = json.loads(summaries[0].read_text(encoding="utf-8"))
    report = json.loads((run_dir / "engine-report.json").read_text(encoding="utf-8"))
    assert summary["status"] == "completed"
    assert summary["engine"] == "emumee-cil"
    assert summary["network_broker_complete"] is True
    assert not summary["errors"]
    assert summary["cil_coverage"] == report["cil_coverage"]
    recovered = []
    for item in summary["artifacts"]:
        payload = (run_dir / "artifacts" / item["file"]).read_bytes()
        assert len(payload) == item["size"]
        assert hashlib.sha256(payload).hexdigest() == item["sha256"]
        recovered.append((item["guest_path"], payload))
    assert len(recovered) == 6
    assert [payload for path, payload in recovered if path.endswith("managed-dir-state.txt")] == [
        b"missing", b"missing parent", b"present", b"nonempty", b"deleted"]
    assert (r"C:\Users\Alex\Downloads\managed-dir\nested\payload.txt",
            b"harmless managed directory marker") in recovered
    assert [event["created"] for event in report["events"]
            if event.get("event") == "directory_create"] == [2]
    assert len([event for event in report["events"]
                if event.get("event") == "directory_delete"]) == 2
    print("packaged managed directories: parent, nonempty delete, and artifacts verified")


if __name__ == "__main__":
    main(Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else DEFAULT_RUNS)
