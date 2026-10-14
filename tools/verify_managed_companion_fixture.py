"""Verify a packaged managed EXE loads only its supplied guest DLL."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from emumee.reports import verify_artifact_manifest


def verify(root: Path, payload: Path, missing_root: Path | None = None) -> None:
    summaries = list(root.glob("*/summary.json"))
    assert len(summaries) == 1, "expected one packaged managed companion run"
    run = summaries[0].parent
    summary = json.loads(summaries[0].read_text(encoding="utf-8"))
    report = json.loads((run / "engine-report.json").read_text(encoding="utf-8"))
    broker = json.loads((run / "network-broker.json").read_text(encoding="utf-8"))
    assert summary["status"] == "completed" and not summary.get("errors")
    assert summary["engine"] == "emumee-cil" and summary["network_broker_complete"] is True
    assert verify_artifact_manifest(run, summary["artifacts"])
    assert broker[-1] == {"event": "broker_closed"}
    assert not any(event.get("event") == "http_request_attempt" for event in broker)
    assert [(event["filename"], event["assembly"])
            for event in report["events"] if event.get("event") == "managed_companion_load"] == [
                ("ManagedCompanionPayload.dll", "ManagedCompanionPayload")]
    assert [event["type"] for event in report["events"]
            if event.get("event") == "managed_catch"] == ["System.IO.FileNotFoundException"]
    expected = [
        ("managed_assembly_load", "", payload.read_bytes()),
        ("managed_file_write", r"C:\Users\Alex\AppData\Roaming\managed-companion-payload.txt",
         b"guest companion ran"),
        ("managed_file_write", r"C:\Users\Alex\AppData\Roaming\managed-companion-state.txt",
         b"loaded;missing"),
    ]
    assert len(summary["artifacts"]) == len(expected)
    for item, (source, path, data) in zip(summary["artifacts"], expected):
        assert (item["source"], item["guest_path"], item["size"], item["sha256"]) == (
            source, path, len(data), hashlib.sha256(data).hexdigest())
        assert (run / "artifacts" / item["file"]).read_bytes() == data
    if missing_root is not None:
        missing_summaries = list(missing_root.glob("*/summary.json"))
        assert len(missing_summaries) == 1, "expected one missing-companion run"
        absent = json.loads(missing_summaries[0].read_text(encoding="utf-8"))
        assert absent["status"] == "partial"
        assert absent["artifacts"] == []
        assert absent["errors"] == [
            "Unhandled managed exception: System.IO.FileNotFoundException"]
        assert absent["network_broker_complete"] is True
    print("packaged managed companion: supplied DLL loaded and guest artifacts verified")


if __name__ == "__main__":
    verify(Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(strict=True),
           Path(sys.argv[3]).resolve() if len(sys.argv) > 3 else None)
