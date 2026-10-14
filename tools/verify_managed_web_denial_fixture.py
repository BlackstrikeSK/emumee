"""Verify packaged managed WebClient localhost attempts stay brokered and catchable."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


def main(runs_root: Path) -> None:
    reports = list(runs_root.glob("*/summary.json"))
    assert len(reports) == 1, "expected one packaged ManagedWebDownload run"
    run_dir = reports[0].parent
    summary = json.loads(reports[0].read_text(encoding="utf-8"))
    report = json.loads((run_dir / "engine-report.json").read_text(encoding="utf-8"))
    broker = json.loads((run_dir / "network-broker.json").read_text(encoding="utf-8"))
    assert summary["status"] == "completed" and not summary.get("errors")
    assert summary["engine"] == "emumee-cil" and summary["network_broker_complete"] is True
    recovered = {}
    for item in summary["artifacts"]:
        payload = (run_dir / "artifacts" / item["file"]).read_bytes()
        assert len(payload) == item["size"]
        assert hashlib.sha256(payload).hexdigest() == item["sha256"]
        recovered[item.get("guest_path")] = payload
    assert recovered == {r"C:\Users\Alex\Downloads\managed-web-state.txt": b"denied"}
    assert sum(event.get("event") == "http_request_attempt" and
               event.get("host") == "127.0.0.1" for event in broker) == 2
    assert sum(event.get("event") == "error" and
               "host-local destination denied" in event.get("error", "")
               for event in broker) == 2
    assert broker[-1] == {"event": "broker_closed"}
    assert [event["type"] for event in report["events"]
            if event.get("event") == "managed_catch"] == ["System.Net.WebException"] * 2
    assert not any(event.get("event") == "managed_download_file" for event in report["events"])
    assert summary["cil_coverage"] == report["cil_coverage"]
    print("packaged managed WebClient: two brokered localhost denials and guest catch verified")


if __name__ == "__main__":
    main(Path(sys.argv[1]).resolve())
