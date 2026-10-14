"""Verify packaged managed HttpClient tasks fail through the network broker."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


def main(runs_root: Path) -> None:
    summaries = list(runs_root.glob("*/summary.json"))
    assert len(summaries) == 1, "expected one packaged HttpClient run"
    run_dir = summaries[0].parent
    summary = json.loads(summaries[0].read_text(encoding="utf-8"))
    report = json.loads((run_dir / "engine-report.json").read_text(encoding="utf-8"))
    broker = json.loads((run_dir / "network-broker.json").read_text(encoding="utf-8"))
    assert summary["status"] == "completed" and not summary.get("errors")
    assert summary["engine"] == "emumee-cil" and summary["network_broker_complete"] is True
    assert len(summary["artifacts"]) == 1
    item = summary["artifacts"][0]
    content = (run_dir / "artifacts" / item["file"]).read_bytes()
    assert item["source"] == "managed_file_write"
    assert item["guest_path"] == r"C:\Users\Alex\AppData\Roaming\managed-http-state.txt"
    assert content == b"denied" and item["size"] == len(content)
    assert item["sha256"] == hashlib.sha256(content).hexdigest()
    assert [event["host"] for event in broker if event.get("event") == "http_request_attempt"] == [
        "127.0.0.1", "127.0.0.1"]
    assert not any(event.get("event") == "http_request" for event in broker)
    assert len([event for event in broker if event.get("event") == "error" and
                "Private or host-local destination denied" in event.get("error", "")]) == 2
    assert broker[-1] == {"event": "broker_closed"}
    assert [(event["method"], event["faulted"])
            for event in report["events"] if event.get("event") == "managed_http_task"] == [
                ("GetByteArrayAsync", True), ("GetStringAsync", True)]
    assert [event["type"] for event in report["events"]
            if event.get("event") == "managed_catch"] == [
                "System.Net.Http.HttpRequestException"] * 2
    assert summary["cil_coverage"] == report["cil_coverage"]
    print("packaged HttpClient: two logged localhost denials and catchable task failures verified")


if __name__ == "__main__":
    main(Path(sys.argv[1]).resolve())
