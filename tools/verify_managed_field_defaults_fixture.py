"""Verify packaged managed instance-field default reads remain guest-only."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from emumee.reports import verify_artifact_manifest


def verify(root: Path) -> None:
    summaries = list(root.glob("*/summary.json"))
    assert len(summaries) == 1, "expected exactly one packaged run"
    run = summaries[0].parent
    summary = json.loads(summaries[0].read_text(encoding="utf-8"))
    report = json.loads((run / "engine-report.json").read_text(encoding="utf-8"))
    broker = json.loads((run / "network-broker.json").read_text(encoding="utf-8"))
    assert summary["status"] == "completed" and not summary.get("errors")
    assert summary["engine"] == "emumee-cil" and summary["network_broker_complete"] is True
    assert verify_artifact_manifest(run, summary["artifacts"])
    assert broker[-1] == {"event": "broker_closed"}
    assert not any(event.get("event") == "http_request_attempt" for event in broker)
    opcodes = {item["opcode"]: item["count"]
               for item in report["cil_coverage"]["top_opcodes"]}
    assert opcodes.get("ldfld", 0) >= 10 and opcodes.get("stfld", 0) >= 1
    data = b"defaults-ok"
    assert len(summary["artifacts"]) == 1
    item = summary["artifacts"][0]
    assert (item["source"], item["guest_path"], item["size"], item["sha256"]) == (
        "managed_file_write", r"C:\Users\Alex\AppData\Roaming\managed-field-defaults.txt",
        len(data), hashlib.sha256(data).hexdigest())
    assert (run / "artifacts" / item["file"]).read_bytes() == data
    print("packaged managed field defaults: inherited and local field reads verified")


if __name__ == "__main__":
    verify(Path(sys.argv[1]).resolve())
