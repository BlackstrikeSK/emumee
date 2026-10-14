"""Verify packaged managed static initialization and guest-only artifacts."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from emumee.reports import verify_artifact_manifest


def verify(root: Path) -> None:
    summaries = list(root.glob("*/summary.json"))
    assert len(summaries) == 1, "expected one packaged run"
    run = summaries[0].parent
    summary = json.loads(summaries[0].read_text(encoding="utf-8"))
    report = json.loads((run / "engine-report.json").read_text(encoding="utf-8"))
    broker = json.loads((run / "network-broker.json").read_text(encoding="utf-8"))
    assert summary["status"] == "completed" and not summary.get("errors")
    assert summary["engine"] == "emumee-cil" and summary["network_broker_complete"] is True
    assert verify_artifact_manifest(run, summary["artifacts"])
    assert broker[-1] == {"event": "broker_closed"}
    assert not any(event.get("event") == "http_request_attempt" for event in broker)
    assert [event["type"] for event in report["events"]
            if event.get("event") == "managed_type_init"] == ["ExplicitStage", "InlineStage"]
    counts = {item["opcode"]: item["count"] for item in report["cil_coverage"]["top_opcodes"]}
    assert counts.get("ldsfld", 0) >= 5 and counts.get("stsfld", 0) >= 3
    expected = [("managed-static-cctor.txt", b"initialized"),
                ("managed-static-state.txt", b"static-ok")]
    assert len(summary["artifacts"]) == len(expected)
    for item, (name, data) in zip(summary["artifacts"], expected):
        assert item["source"] == "managed_file_write"
        assert item["guest_path"] == rf"C:\Users\Alex\AppData\Roaming\{name}"
        assert item["size"] == len(data)
        assert item["sha256"] == hashlib.sha256(data).hexdigest()
        assert (run / "artifacts" / item["file"]).read_bytes() == data
    print("packaged managed static fields: explicit and inline initializers verified")


if __name__ == "__main__":
    verify(Path(sys.argv[1]).resolve())
