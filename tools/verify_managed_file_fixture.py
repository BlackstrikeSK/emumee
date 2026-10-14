"""Verify packaged CIL file lifecycle and extracted guest bytes."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
DEFAULT_RUNS = PROJECT / "output" / "managed-files-package"


def main(runs_root: Path = DEFAULT_RUNS) -> None:
    reports = list(runs_root.glob("*/summary.json"))
    assert len(reports) == 1, "expected one packaged ManagedFiles run"
    run_dir = reports[0].parent
    summary = json.loads(reports[0].read_text(encoding="utf-8"))
    report = json.loads((run_dir / "engine-report.json").read_text(encoding="utf-8"))
    assert summary["status"] == "completed"
    assert summary["engine"] == "emumee-cil"
    assert summary["network_broker_complete"] is True
    assert summary["cil_coverage"]["framework_calls"] >= 10
    assert summary["cil_coverage"] == report["cil_coverage"]
    recovered = []
    for item in summary["artifacts"]:
        payload = (run_dir / "artifacts" / item["file"]).read_bytes()
        assert len(payload) == item["size"]
        assert hashlib.sha256(payload).hexdigest() == item["sha256"]
        recovered.append((item["guest_path"], payload))
    assert (r"C:\Users\Alex\Downloads\managed-append.txt",
            b"harmless managed append marker") in recovered
    assert (r"C:\Users\Alex\Downloads\managed-content.txt",
            b"harmless managed append marker") in recovered
    assert (r"C:\Users\Alex\Downloads\managed-persona-copy.txt",
            b"Personal notes\n") in recovered
    assert [payload for path, payload in recovered if path.endswith("managed-state.txt")] == [
        b"missing", b"present", b"deleted"]
    assert [event["existed"] for event in report["events"]
            if event.get("event") == "file_delete"] == [False, True, True]
    assert not summary["errors"]
    print("packaged managed files: guest lifecycle and artifact hashes verified")


if __name__ == "__main__":
    main(Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else DEFAULT_RUNS)
