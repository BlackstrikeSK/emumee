"""Verify a packaged managed manifest resource remains guest-only."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from emumee.reports import verify_artifact_manifest


def verify(root: Path, payload_path: Path) -> None:
    summaries = list(root.glob("*/summary.json"))
    assert len(summaries) == 1
    run = summaries[0].parent
    summary = json.loads(summaries[0].read_text(encoding="utf-8"))
    report = json.loads((run / "engine-report.json").read_text(encoding="utf-8"))
    broker = json.loads((run / "network-broker.json").read_text(encoding="utf-8"))
    assert summary["status"] == "completed" and not summary.get("errors")
    assert summary["engine"] == "emumee-cil" and summary["network_broker_complete"] is True
    assert verify_artifact_manifest(run, summary["artifacts"])
    assert broker[-1] == {"event": "broker_closed"}
    data = payload_path.read_bytes()
    expected = [("managed_manifest_resource", "", data),
                ("managed_file_write", r"C:\Users\Alex\AppData\Roaming\managed-resource-payload.bin", data),
                ("managed_file_write", r"C:\Users\Alex\AppData\Roaming\managed-resource-state.txt",
                 b"resource-ok")]
    assert len(summary["artifacts"]) == len(expected)
    for item, (source, path, raw) in zip(summary["artifacts"], expected):
        assert (item["source"], item.get("guest_path", ""), item["size"], item["sha256"]) == (
            source, path, len(raw), hashlib.sha256(raw).hexdigest())
        assert (run / "artifacts" / item["file"]).read_bytes() == raw
    assert [(event["module_id"], event["name"], event["size"])
            for event in report["events"] if event.get("event") == "managed_manifest_resource"] == [
                (0, "payload.dat", len(data))]
    print("packaged managed resource: exact read-only embedded bytes and guest files verified")


if __name__ == "__main__":
    verify(Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve())
