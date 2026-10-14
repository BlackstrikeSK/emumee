"""Verify packaged CPU reads of the virtual shared timing page."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from emumee.reports import verify_artifact_manifest


def verify(root: Path) -> None:
    fixtures = Path(__file__).resolve().parents[1] / "tests" / "fixtures"
    expected = {"kernel32.GetSystemTimeAsFileTime", "kernel32.GetTickCount",
                "kernel32.Sleep", "kernel32.ExitProcess"}
    for arch in ("x86", "x64"):
        case = f"shared_time_check_{arch}"
        summaries = list((root / case).glob("*/summary.json"))
        assert len(summaries) == 1, (case, summaries)
        run = summaries[0].parent
        summary = json.loads(summaries[0].read_text(encoding="utf-8"))
        submitted = (fixtures / f"{case}.exe").read_bytes()
        assert (run / "input.pe").read_bytes() == submitted, case
        assert summary["sample"]["sha256"] == hashlib.sha256(submitted).hexdigest(), case
        assert summary["status"] == "completed" and not summary["errors"], case
        assert not summary["api_coverage"]["signature_only_calls"], case
        assert verify_artifact_manifest(run, summary["artifacts"]), case
        assert summary["network_broker_complete"] is True, case
        journal = json.loads((run / "network-broker.json").read_text(encoding="utf-8"))
        assert journal[-1] == {"event": "broker_closed"}, case
        report = json.loads((run / summary["engine_report"]).read_text(encoding="utf-8"))
        entries = report["entry_points"]
        assert len(entries) == 1, case
        events = entries[0]["events"]
        names = {item.get("api_name") for item in events}
        assert expected <= names, (case, names)
        assert len([item for item in events
                    if item.get("api_name") == "kernel32.ExitProcess"]) == 1, case
        assert any(item.get("api_name") == "kernel32.ExitProcess"
                   and item.get("args") == ["0x1"] for item in events), case
        print(f"{case}: shared time branch, exact input, artifacts, and broker verified")


if __name__ == "__main__":
    verify(Path(sys.argv[1]))
