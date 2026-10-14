"""Verify a packaged guest DLL reads only its supplied embedded resource."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from emumee.reports import verify_artifact_manifest


def verify(root: Path, payload_path: Path, resource_path: Path, missing_root: Path) -> None:
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
    resource = resource_path.read_bytes()
    expected = [("managed_assembly_load", "", payload_path.read_bytes()),
                ("managed_manifest_resource", "", resource),
                ("managed_file_write", r"C:\Users\Alex\AppData\Roaming\managed-companion-resource.bin",
                 resource),
                ("managed_file_write", r"C:\Users\Alex\AppData\Roaming\managed-companion-resource-state.txt",
                 b"companion-resource-ok")]
    assert len(summary["artifacts"]) == len(expected)
    for item, (source, path, raw) in zip(summary["artifacts"], expected):
        assert (item["source"], item.get("guest_path", ""), item["size"], item["sha256"]) == (
            source, path, len(raw), hashlib.sha256(raw).hexdigest())
        assert (run / "artifacts" / item["file"]).read_bytes() == raw
    assert [(event["module_id"], event["name"], event["size"])
            for event in report["events"] if event.get("event") == "managed_manifest_resource"] == [
                (1, "companion.dat", len(resource))]
    absent_summaries = list(missing_root.glob("*/summary.json"))
    assert len(absent_summaries) == 1
    absent = json.loads(absent_summaries[0].read_text(encoding="utf-8"))
    assert absent["status"] == "partial" and absent["artifacts"] == []
    assert absent["errors"] == ["Unhandled managed exception: System.IO.FileNotFoundException"]
    assert absent["network_broker_complete"] is True
    print("packaged companion resource: supplied bytes, guest files, and missing-DLL denial verified")


if __name__ == "__main__":
    verify(*(Path(arg).resolve() for arg in sys.argv[1:5]))
