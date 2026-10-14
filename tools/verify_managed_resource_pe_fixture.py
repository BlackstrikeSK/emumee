"""Verify a packaged managed resource yields exact harmless PE bytes."""

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
    payload = payload_path.read_bytes()
    resource = [item for item in summary["artifacts"]
                if item["source"] == "managed_manifest_resource"]
    assert len(resource) == 1 and resource[0]["kind"] == "pe"
    assert (resource[0]["size"], resource[0]["sha256"]) == (
        len(payload), hashlib.sha256(payload).hexdigest())
    assert (run / "artifacts" / resource[0]["file"]).read_bytes() == payload
    files = [item for item in summary["artifacts"] if item["source"] == "managed_file_write"]
    assert len(files) == 2
    expected = [(r"C:\Users\Alex\AppData\Roaming\managed-resource-native.exe", payload),
                (r"C:\Users\Alex\AppData\Roaming\managed-resource-native-state.txt",
                 b"resource-pe-ok")]
    for item, (path, raw) in zip(files, expected):
        assert (item["guest_path"], item["size"], item["sha256"]) == (
            path, len(raw), hashlib.sha256(raw).hexdigest())
        assert (run / "artifacts" / item["file"]).read_bytes() == raw
    assert [(event["module_id"], event["name"], event["size"])
            for event in report["events"] if event.get("event") == "managed_manifest_resource"] == [
                (0, "harmless-native.exe", len(payload))]
    print("packaged managed resource PE: exact hash-verified embedded and guest bytes")


if __name__ == "__main__":
    verify(Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve())
