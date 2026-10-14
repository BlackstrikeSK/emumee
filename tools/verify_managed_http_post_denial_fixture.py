"""Verify packaged managed POST content reaches only the logged network broker."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


def main(runs_root: Path) -> None:
    summaries = list(runs_root.glob("*/summary.json"))
    assert len(summaries) == 1, "expected one packaged HttpPost run"
    run_dir = summaries[0].parent
    summary = json.loads(summaries[0].read_text(encoding="utf-8"))
    report = json.loads((run_dir / "engine-report.json").read_text(encoding="utf-8"))
    broker = json.loads((run_dir / "network-broker.json").read_text(encoding="utf-8"))
    assert summary["status"] == "completed" and not summary.get("errors")
    assert summary["engine"] == "emumee-cil" and summary["network_broker_complete"] is True
    assert len(summary["artifacts"]) == 2
    request, state = summary["artifacts"]
    json_body = '{"safe":"é"}'.encode("utf-8")
    assert request["source"] == "network_request_body"
    assert request["guest_path"] == "http://127.0.0.1:80/json"
    assert request["kind"] == "network"
    assert (run_dir / "artifacts" / request["file"]).read_bytes() == json_body
    assert request["size"] == len(json_body)
    assert request["sha256"] == hashlib.sha256(json_body).hexdigest()
    content = (run_dir / "artifacts" / state["file"]).read_bytes()
    assert state["source"] == "managed_file_write"
    assert state["guest_path"] == r"C:\Users\Alex\AppData\Roaming\managed-post-state.txt"
    assert content == b"denied" and state["size"] == len(content)
    assert state["sha256"] == hashlib.sha256(content).hexdigest()
    attempts = [event for event in broker if event.get("event") == "http_request_attempt"]
    assert [(event["method"], event["host"], event["body_size"],
             event["body_sha256"], event["headers"]) for event in attempts] == [
                 ("POST", "127.0.0.1", len(json_body),
                  hashlib.sha256(json_body).hexdigest(),
                  {"Content-Type": "application/json; charset=utf-8"})]
    assert not any(event.get("event") == "http_request" for event in broker)
    assert len([event for event in broker if event.get("event") == "error" and
                "Private or host-local destination denied" in event.get("error", "")]) == 1
    assert broker[-1] == {"event": "broker_closed"}
    assert [(event["method"], event["request_size"], event["faulted"])
            for event in report["events"] if event.get("event") == "managed_http_task"] == [
                ("PostAsync", len(json_body), True)]
    assert [event["type"] for event in report["events"]
            if event.get("event") == "managed_catch"] == [
                "System.Net.Http.HttpRequestException"]
    assert summary["cil_coverage"] == report["cil_coverage"]
    print("packaged managed POST: logged body hash, localhost denial, and catch verified")


if __name__ == "__main__":
    main(Path(sys.argv[1]).resolve())
