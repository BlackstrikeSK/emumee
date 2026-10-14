"""Verify packaged managed directory enumeration uses guest-only paths."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
DEFAULT_RUNS = PROJECT / "output" / "managed-enumeration-package"


def main(runs_root: Path = DEFAULT_RUNS) -> None:
    summaries = list(runs_root.glob("*/summary.json"))
    assert len(summaries) == 1, "expected one packaged enumeration report"
    run_dir = summaries[0].parent
    summary = json.loads(summaries[0].read_text(encoding="utf-8"))
    report = json.loads((run_dir / "engine-report.json").read_text(encoding="utf-8"))
    assert summary["status"] == "completed"
    assert summary["engine"] == "emumee-cil"
    assert summary["network_broker_complete"] is True
    assert not summary["errors"]
    recovered = {}
    for item in summary["artifacts"]:
        payload = (run_dir / "artifacts" / item["file"]).read_bytes()
        assert len(payload) == item["size"]
        assert hashlib.sha256(payload).hexdigest() == item["sha256"]
        recovered[item["guest_path"]] = payload
    assert len(summary["artifacts"]) == 10
    prefix = r"C:\Users\Alex\Downloads\managed-enum-"
    root = r"C:\Users\Alex\Downloads\EnumStage"
    assert recovered[prefix + "top.txt"] == (root + r"\beta.TXT").encode()
    assert recovered[prefix + "files.txt"].decode().splitlines() == [
        root + r"\beta.TXT", root + r"\Nested\Deep\delta.txt",
        root + r"\Nested\Gamma.txt"]
    assert recovered[prefix + "directories.txt"].decode().splitlines() == [
        root + r"\Nested", root + r"\Nested\Deep"]
    assert recovered[prefix + "all.txt"].decode().splitlines() == [
        root + r"\Alpha.bin", root + r"\beta.TXT", root + r"\Nested",
        root + r"\Nested\Deep", root + r"\Nested\Deep\delta.txt",
        root + r"\Nested\extensionless", root + r"\Nested\Gamma.txt"]
    assert recovered[prefix + "after.txt"] == b"cleaned"
    assert [event["count"] for event in report["events"]
            if event.get("event") == "directory_enumerate"] == [1, 3, 2, 7, 1, 0]
    print("packaged managed enumeration: guest paths, wildcard and recursion verified")


if __name__ == "__main__":
    main(Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else DEFAULT_RUNS)
