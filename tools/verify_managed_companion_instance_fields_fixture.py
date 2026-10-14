"""Verify packaged cross-assembly instance field access stays guest-only."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from emumee.reports import verify_artifact_manifest


def verify(root: Path, payload_path: Path, missing_root: Path, wrong_root: Path) -> None:
    summaries = list(root.glob("*/summary.json"))
    assert len(summaries) == 1, "expected one completed packaged run"
    run = summaries[0].parent
    summary = json.loads(summaries[0].read_text(encoding="utf-8"))
    report = json.loads((run / "engine-report.json").read_text(encoding="utf-8"))
    broker = json.loads((run / "network-broker.json").read_text(encoding="utf-8"))
    assert summary["status"] == "completed" and not summary.get("errors")
    assert summary["engine"] == "emumee-cil" and summary["network_broker_complete"] is True
    assert verify_artifact_manifest(run, summary["artifacts"])
    assert broker[-1] == {"event": "broker_closed"}
    counts = {item["opcode"]: item["count"] for item in report["cil_coverage"]["top_opcodes"]}
    assert counts.get("ldfld", 0) >= 7 and counts.get("stfld", 0) >= 4
    assert len([event for event in report["events"]
                if event.get("event") == "managed_object_create" and
                event.get("module_id") == 1]) == 2
    assert [event.get("type") for event in report["events"]
            if event.get("event") == "managed_catch"] == ["System.NullReferenceException"]
    expected = [("managed_assembly_load", "", payload_path.read_bytes()),
                ("managed_file_write",
                 r"C:\Users\Alex\AppData\Roaming\managed-companion-instance-field.txt",
                 b"instance-field-ok")]
    assert len(summary["artifacts"]) == len(expected)
    for item, (source, guest_path, data) in zip(summary["artifacts"], expected):
        assert (item["source"], item.get("guest_path", ""), item["size"], item["sha256"]) == (
            source, guest_path, len(data), hashlib.sha256(data).hexdigest())
        assert (run / "artifacts" / item["file"]).read_bytes() == data
    missing_summaries = list(missing_root.glob("*/summary.json"))
    assert len(missing_summaries) == 1
    absent = json.loads(missing_summaries[0].read_text(encoding="utf-8"))
    assert absent["status"] == "partial" and absent["artifacts"] == []
    assert absent["errors"] == [
        "Unhandled managed exception: System.IO.FileNotFoundException"]
    assert absent["network_broker_complete"] is True
    wrong_summaries = list(wrong_root.glob("*/summary.json"))
    assert len(wrong_summaries) == 1
    wrong = json.loads(wrong_summaries[0].read_text(encoding="utf-8"))
    assert wrong["status"] == "partial" and wrong["network_broker_complete"] is True
    assert wrong["errors"] == ["Unhandled managed exception: System.MissingFieldException"]
    assert not any(item["source"] == "managed_file_write" for item in wrong["artifacts"])
    print("packaged companion instance fields: guest read/write, default, null, missing and mismatched DLL verified")


if __name__ == "__main__":
    verify(*(Path(arg).resolve() for arg in sys.argv[1:5]))
