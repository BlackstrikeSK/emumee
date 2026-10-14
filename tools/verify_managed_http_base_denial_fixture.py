"""Verify packaged relative HttpClient requests stay brokered and guest-only."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from emumee.reports import verify_artifact_manifest


def verify(root: Path) -> None:
    summaries = list(root.glob("*/summary.json"))
    assert len(summaries) == 1, "expected one packaged BaseAddress run"
    run = summaries[0].parent
    summary = json.loads(summaries[0].read_text(encoding="utf-8"))
    report = json.loads((run / "engine-report.json").read_text(encoding="utf-8"))
    broker = json.loads((run / "network-broker.json").read_text(encoding="utf-8"))
    assert summary["status"] == "completed" and not summary.get("errors")
    assert summary["engine"] == "emumee-cil" and summary["network_broker_complete"] is True
    assert verify_artifact_manifest(run, summary["artifacts"])
    assert [(event["method"], event["url"], event["body_size"])
            for event in broker if event.get("event") == "http_request_attempt"] == [
                ("GET", "http://127.0.0.1:80/api/v1/first", 0),
                ("GET", "http://127.0.0.1:80/root", 0),
                ("POST", "http://127.0.0.1:80/api/upload", 4),
            ]
    assert not any(event.get("event") == "http_request" for event in broker)
    assert broker[-1] == {"event": "broker_closed"}
    assert [(event["method"], event["url"], event["faulted"])
            for event in report["events"] if event.get("event") == "managed_http_task"] == [
                ("GetStringAsync", "http://127.0.0.1:80/api/v1/first", True),
                ("GetStringAsync", "http://127.0.0.1:80/root", True),
                ("SendAsync", "http://127.0.0.1:80/api/upload", True),
            ]
    assert [event["type"] for event in report["events"]
            if event.get("event") == "managed_catch"].count(
                "System.Net.Http.HttpRequestException") == 3
    assert len(summary["artifacts"]) == 2
    request, state = summary["artifacts"]
    assert request["source"] == "network_request_body"
    assert request["guest_path"] == "http://127.0.0.1:80/api/upload"
    assert request["sha256"] == hashlib.sha256(b"PING").hexdigest()
    assert (run / "artifacts" / request["file"]).read_bytes() == b"PING"
    assert state["source"] == "managed_file_write"
    assert state["guest_path"] == r"C:\Users\Alex\AppData\Roaming\managed-http-base-state.txt"
    expected = b"denied;denied;denied;locked"
    assert state["sha256"] == hashlib.sha256(expected).hexdigest()
    assert (run / "artifacts" / state["file"]).read_bytes() == expected
    print("packaged BaseAddress: three relative requests denied and guest state verified")


if __name__ == "__main__":
    verify(Path(sys.argv[1]).resolve())
