"""Verify packaged managed guest attributes and recovered file bytes."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
DEFAULT_RUNS = PROJECT / "output" / "managed-attributes-package"


def main(runs_root: Path = DEFAULT_RUNS) -> None:
    summaries = list(runs_root.glob("*/summary.json"))
    assert len(summaries) == 1, "expected one packaged managed-attributes report"
    run_dir = summaries[0].parent
    summary = json.loads(summaries[0].read_text(encoding="utf-8"))
    report = json.loads((run_dir / "engine-report.json").read_text(encoding="utf-8"))
    assert summary["status"] == "completed"
    assert summary["engine"] == "emumee-cil"
    assert summary["network_broker_complete"] is True
    assert not summary["errors"]
    recovered = []
    for item in summary["artifacts"]:
        payload = (run_dir / "artifacts" / item["file"]).read_bytes()
        assert len(payload) == item["size"]
        assert hashlib.sha256(payload).hexdigest() == item["sha256"]
        recovered.append((item["source"], item["guest_path"], payload))
    assert len(recovered) == 10
    assert [payload for _, path, payload in recovered
            if path.endswith("managed-attributes-state.txt")] == [
                b"source flags", b"append denied", b"delete denied", b"copy flags",
                b"overwrite denied", b"directory hidden", b"cleared"]
    assert ("managed_file_copy", r"C:\Users\Alex\Downloads\managed-attributes-copy.txt",
            b"harmless attribute payload") in recovered
    assert ("managed_file_write", r"C:\Users\Alex\Downloads\managed-attributes-copy.txt",
            b"writable copy") in recovered
    changes = [event for event in report["events"]
               if event.get("event") == "file_attributes_set"]
    assert [(event["attributes"], event["directory"]) for event in changes] == [
        (3, False), (128, False), (128, False), (18, True), (16, True)]
    print("packaged managed attributes: guest read-only and hidden state verified")


if __name__ == "__main__":
    main(Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else DEFAULT_RUNS)
