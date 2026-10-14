"""Verify packaged harmless PROCESS_DUP_HANDLE checks."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from emumee.reports import verify_artifact_manifest


def verify(root: Path) -> None:
    fixtures = Path(__file__).resolve().parents[1] / "tests" / "fixtures"
    for arch in ("x86", "x64"):
        case = f"process_duplicate_rights_{arch}"
        summaries = list((root / case).glob("*/summary.json"))
        assert len(summaries) == 1, (case, summaries)
        run = summaries[0].parent
        summary = json.loads(summaries[0].read_text(encoding="utf-8"))
        submitted = (fixtures / f"{case}.exe").read_bytes()
        assert (run / "input.pe").read_bytes() == submitted, case
        assert summary["sample"]["sha256"] == hashlib.sha256(submitted).hexdigest(), case
        assert summary["status"] == "completed" and not summary["errors"], case
        assert summary["network_broker_complete"] is True, case
        journal = json.loads((run / "network-broker.json").read_text(encoding="utf-8"))
        assert journal[-1] == {"event": "broker_closed"}, case
        assert verify_artifact_manifest(run, summary["artifacts"]), case
        assert not summary["api_coverage"]["signature_only_calls"], case
        report = json.loads((run / summary["engine_report"]).read_text(encoding="utf-8"))
        assert len(report["entry_points"]) == 1, case
        entry = report["entry_points"][0]
        assert entry["ret_val"] == "0x1" and not entry.get("error"), case
        calls = [item for item in entry["events"]
                 if item.get("api_name") == "kernel32.DuplicateHandle"]
        assert [item["ret_val"] for item in calls] == ["0x0", "0x0", "0x1", "0x1"], case
        assert any(item.get("api_name") == "kernel32.ExitProcess"
                   and item.get("args") == ["0x1"] for item in entry["events"]), case
        duplicates = [item for item in report["virtual_process_events"]
                      if item["event"] == "virtual_process_handle_duplicate"]
        assert [item["success"] for item in duplicates] == [False, False, True, True], case
        assert [item["reason"] for item in duplicates[:2]] == [
            "source process handle lacks duplicate right",
            "target process handle lacks duplicate right"], case
        assert any(item["source"] == "process_memory_read" and
                   (run / "artifacts" / item["file"]).read_bytes() == b"MZ"
                   for item in summary["artifacts"]), case
        print(f"{case}: both process-handle rights denied, valid duplicates and bytes verified")


if __name__ == "__main__":
    verify(Path(sys.argv[1]))
