"""Verify live guest process exit status under packaged x86/x64 execution."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from emumee.reports import verify_artifact_manifest


def verify(root: Path) -> None:
    fixtures = Path(__file__).resolve().parents[1] / "tests" / "fixtures"
    for arch in ("x86", "x64"):
        case = f"process_exit_status_{arch}"
        summaries = list((root / case).glob("*/summary.json"))
        assert len(summaries) == 1, (case, summaries)
        run = summaries[0].parent
        summary = json.loads(summaries[0].read_text(encoding="utf-8"))
        submitted = (fixtures / f"{case}.exe").read_bytes()
        assert (run / "input.pe").read_bytes() == submitted, case
        assert summary["sample"]["sha256"] == hashlib.sha256(submitted).hexdigest(), case
        assert summary["status"] == "completed" and not summary["errors"], case
        assert summary["network_broker_complete"] is True, case
        assert json.loads((run / "network-broker.json").read_text(encoding="utf-8"))[-1] == {
            "event": "broker_closed"}, case
        assert verify_artifact_manifest(run, summary["artifacts"]), case
        assert not summary["api_coverage"]["signature_only_calls"], case
        report = json.loads((run / summary["engine_report"]).read_text(encoding="utf-8"))
        entries = report["entry_points"]
        assert len(entries) == 1 and not entries[0].get("error"), case
        events = report["virtual_process_events"]
        queries = [item for item in events if item["event"] == "virtual_process_exit_code"]
        exits = [item for item in events if item["event"] == "virtual_process_exit"]
        assert len(queries) == 1 and queries[0]["success"], case
        assert queries[0]["exit_code"] == 259, case
        assert len(exits) == 1 and exits[0]["exit_code"] == 1, case
        assert queries[0]["pid"] == exits[0]["pid"] == entries[0]["guest_pid"], case
        calls = [item for item in entries[0]["events"]
                 if item.get("api_name") == "kernel32.ExitProcess"]
        assert len(calls) == 1 and calls[0]["args"] == ["0x1"], case
        print(f"{case}: STILL_ACTIVE, exit code, artifacts, broker verified")


if __name__ == "__main__":
    verify(Path(sys.argv[1]).resolve())
