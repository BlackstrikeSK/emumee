"""Verify packaged SendAsync headers, body extraction, and localhost denial."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


def verify(root: Path) -> None:
    summaries = list(root.glob("*/summary.json"))
    assert len(summaries) == 1, "expected one packaged SendAsync run"
    run = summaries[0].parent
    summary = json.loads(summaries[0].read_text(encoding="utf-8"))
    report = json.loads((run / "engine-report.json").read_text(encoding="utf-8"))
    broker = json.loads((run / "network-broker.json").read_text(encoding="utf-8"))
    assert summary["status"] == "completed" and not summary.get("errors")
    assert summary["engine"] == "emumee-cil" and summary["network_broker_complete"] is True
    assert len(summary["artifacts"]) == 2
    request, state = summary["artifacts"]
    assert request["source"] == "network_request_body" and request["kind"] == "network"
    assert request["guest_path"] == "http://127.0.0.1:80/send"
    assert request["size"] == 4 and request["sha256"] == hashlib.sha256(b"PING").hexdigest()
    assert (run / "artifacts" / request["file"]).read_bytes() == b"PING"
    assert state["source"] == "managed_file_write"
    assert state["guest_path"] == r"C:\Users\Alex\AppData\Roaming\managed-send-state.txt"
    assert state["size"] == 6 and state["sha256"] == hashlib.sha256(b"denied").hexdigest()
    assert (run / "artifacts" / state["file"]).read_bytes() == b"denied"
    attempts = [event for event in broker if event.get("event") == "http_request_attempt"]
    assert len(attempts) == 1
    attempt = attempts[0]
    assert (attempt["method"], attempt["host"], attempt["body_size"],
            attempt["body_sha256"]) == (
                "POST", "127.0.0.1", 4, hashlib.sha256(b"PING").hexdigest())
    assert attempt["headers"] == {
        "X-Client": "alpha", "X-Request": "beta", "X-Multi": "one, two",
        "Content-Type": "text/plain; charset=utf-8"}
    assert not any(event.get("event") == "http_request" for event in broker)
    assert broker[-1] == {"event": "broker_closed"}
    assert [(event["method"], event["verb"], event["request_size"], event["faulted"])
            for event in report["events"] if event.get("event") == "managed_http_task"] == [
                ("SendAsync", "POST", 4, True)]
    assert [event["type"] for event in report["events"]
            if event.get("event") == "managed_catch"] == [
                "System.Net.Http.HttpRequestException"]
    assert summary["cil_coverage"] == report["cil_coverage"]
    print("packaged SendAsync: exact headers/body, broker denial, and guest catch verified")


if __name__ == "__main__":
    verify(Path(sys.argv[1]).resolve())
