"""Check packaged invalid network API attempts remain visible and side-effect free."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "output" / "network-attempt-package"
EXPECTED = {
    "InternetOpenUrlA": "invalid session handle",
    "HttpSendRequestA": "invalid request handle",
    "WinHttpSendRequest": "invalid request handle",
    "gethostbyname": "missing hostname",
}


def verify(arch: str, api: str, reason: str) -> None:
    run = sorted((OUTPUT / f"{api.lower()}_{arch}").iterdir(), reverse=True)[0]
    summary = json.loads((run / "summary.json").read_text(encoding="utf-8"))
    report = json.loads((run / summary["engine_report"]).read_text(encoding="utf-8"))
    assert summary["status"] == "completed" and not summary["errors"], (arch, api, summary)
    assert [item["event"] for item in report["network_events"]] == [
        "network_attempt", "network_denied"], (arch, api, report["network_events"])
    assert report["network_events"][-1]["reason"] == reason, (arch, api)
    exits = [item for entry in report["entry_points"] for item in entry.get("events") or []
             if str(item.get("api_name", "")).endswith("ExitProcess")]
    assert exits and exits[-1]["args"] == ["0x0"], (arch, api, exits)
    broker = json.loads((run / "network-broker.json").read_text(encoding="utf-8"))
    assert not any(item.get("event") in ("connect", "send", "http", "dns")
                   for item in broker), (arch, api, broker)
    print(f"{api}_{arch}: logged {reason}; no broker network action")


if __name__ == "__main__":
    for architecture in ("x86", "x64"):
        for api_name, denial in EXPECTED.items():
            verify(architecture, api_name, denial)
