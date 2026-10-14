"""Verify packaged guest construction and call into a supplied managed DLL."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from emumee.reports import verify_artifact_manifest


def _single_run(root: Path) -> tuple[Path, dict]:
    summaries = list(root.glob("*/summary.json"))
    assert len(summaries) == 1, "expected exactly one run"
    return summaries[0].parent, json.loads(summaries[0].read_text(encoding="utf-8"))


def verify(root: Path, payload: Path, missing_root: Path) -> None:
    run, summary = _single_run(root)
    report = json.loads((run / "engine-report.json").read_text(encoding="utf-8"))
    broker = json.loads((run / "network-broker.json").read_text(encoding="utf-8"))
    assert summary["status"] == "completed" and not summary.get("errors")
    assert summary["engine"] == "emumee-cil" and summary["network_broker_complete"] is True
    assert verify_artifact_manifest(run, summary["artifacts"])
    assert broker[-1] == {"event": "broker_closed"}
    assert not any(event.get("event") == "http_request_attempt" for event in broker)
    assert [event["method"] for event in report["events"]
            if event.get("event") == "managed_companion_call"] == [".ctor", "Run"]
    assert [event["type"] for event in report["events"]
            if event.get("event") == "managed_catch"] == ["System.NullReferenceException"]
    assert any(event.get("event") == "managed_object_create" and event.get("via") == "newobj"
               for event in report["events"])
    assert [(event["filename"], event["assembly"])
            for event in report["events"] if event.get("event") == "managed_companion_load"] == [
                ("ManagedInstanceCompanionPayload.dll", "ManagedInstanceCompanionPayload")]
    expected = [
        ("managed_assembly_load", "", payload.read_bytes()),
        ("managed_file_write", r"C:\Users\Alex\AppData\Roaming\managed-instance-companion-payload.txt",
         b"guest instance ran"),
        ("managed_file_write", r"C:\Users\Alex\AppData\Roaming\managed-instance-companion-state.txt",
         b"guest instance ran;null"),
    ]
    assert len(summary["artifacts"]) == len(expected)
    for item, (source, guest_path, data) in zip(summary["artifacts"], expected):
        assert (item["source"], item["guest_path"], item["size"], item["sha256"]) == (
            source, guest_path, len(data), hashlib.sha256(data).hexdigest())
        assert (run / "artifacts" / item["file"]).read_bytes() == data
    missing_run, absent = _single_run(missing_root)
    assert absent["status"] == "partial" and absent["artifacts"] == []
    assert absent["errors"] == [
        "Unhandled managed exception: System.IO.FileNotFoundException"]
    assert absent["network_broker_complete"] is True
    missing_broker = json.loads((missing_run / "network-broker.json").read_text(encoding="utf-8"))
    assert missing_broker[-1] == {"event": "broker_closed"}
    print("packaged instance managed companion: guest object executed, missing DLL denied")


if __name__ == "__main__":
    verify(Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve(strict=True),
           Path(sys.argv[3]).resolve())
