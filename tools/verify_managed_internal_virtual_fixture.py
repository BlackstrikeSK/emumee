"""Verify local MethodDef virtual dispatch stays inside the guest CIL interpreter."""

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
    dispatches = [event for event in report["events"]
                  if event.get("event") == "managed_virtual_dispatch"]
    assert len(dispatches) == 4
    assert dispatches[0]["declared_method"] == dispatches[1]["declared_method"]
    assert dispatches[0]["declared_method"] == dispatches[3]["declared_method"]
    assert dispatches[0]["method"] != dispatches[0]["declared_method"]
    assert all(event["method"] == event["declared_method"] for event in dispatches[1:])
    assert "System.NullReferenceException" in [event.get("type") for event in report["events"]
                                               if event.get("event") == "managed_catch"]
    expected = [
        ("managed_file_write", r"C:\Users\Alex\AppData\Roaming\managed-internal-virtual-payload.txt",
         b"derived"),
        ("managed_file_write", r"C:\Users\Alex\AppData\Roaming\managed-internal-virtual-state.txt",
         b"derived:base;base;fixed;base;null"),
    ]
    assert len(summary["artifacts"]) == len(expected)
    for item, (source, guest_path, data) in zip(summary["artifacts"], expected):
        assert (item["source"], item["guest_path"], item["size"], item["sha256"]) == (
            source, guest_path, len(data), hashlib.sha256(data).hexdigest())
        assert (run / "artifacts" / item["file"]).read_bytes() == data
    print("packaged local managed virtual dispatch: override, base slot, and hashes verified")


if __name__ == "__main__":
    verify(Path(sys.argv[1]).resolve())
