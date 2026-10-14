"""Verify packaged harmless parent-to-child guest file duplication."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from emumee.reports import verify_artifact_manifest


def verify(root: Path) -> None:
    fixtures = Path(__file__).resolve().parents[1] / "tests" / "fixtures"
    for arch in ("x86", "x64"):
        case = f"child_parent_file_handle_duplicate_{arch}"
        summaries = list((root / case).glob("*/summary.json"))
        assert len(summaries) == 1, (case, summaries)
        run = summaries[0].parent
        summary = json.loads(summaries[0].read_text(encoding="utf-8"))
        submitted = (fixtures / f"{case}.exe").read_bytes()
        supplied = (fixtures / f"child_parent_module_{arch}" /
                    f"companion_{arch}.dll").read_bytes()
        assert (run / "input.pe").read_bytes() == submitted, case
        assert (run / "inputs" / f"companion_{arch}.dll").read_bytes() == supplied, case
        assert summary["sample"]["sha256"] == hashlib.sha256(submitted).hexdigest(), case
        assert summary["status"] == "completed" and not summary["errors"], case
        assert summary["network_broker_complete"] is True, case
        assert json.loads((run / "network-broker.json").read_text(encoding="utf-8"))[-1] == {
            "event": "broker_closed"}, case
        assert verify_artifact_manifest(run, summary["artifacts"]), case
        assert not summary["api_coverage"]["signature_only_calls"], case
        embedded = [item for item in summary["artifacts"]
                    if item["source"] == "embedded_input@0xa00"]
        assert len(embedded) == 1, case
        assert (run / "artifacts" / embedded[0]["file"]).read_bytes() == submitted[0xA00:0x1000], case
        report = json.loads((run / summary["engine_report"]).read_text(encoding="utf-8"))
        entries = report["entry_points"]
        assert len(entries) == 3 and entries[0]["pid"] == entries[1]["pid"], case
        assert entries[2]["pid"] != entries[1]["pid"], case
        assert entries[2]["ret_val"] == "0x1" and not entries[2].get("error"), case
        duplicates = [item for item in report["virtual_file_events"]
                      if item["event"] == "virtual_guest_handle_duplicate"]
        assert len(duplicates) == 1 and duplicates[0]["success"], case
        assert duplicates[0]["object_type"] == "file", case
        assert duplicates[0]["source_pid"] == entries[1]["pid"], case
        creates = [item for item in report["virtual_process_events"]
                   if item["event"] == "virtual_process_create"]
        assert len(creates) == 1 and creates[0]["success"], case
        assert duplicates[0]["target_pid"] == creates[0]["pid"], case
        assert entries[1]["guest_pid"] == duplicates[0]["source_pid"], case
        assert entries[2]["guest_pid"] == duplicates[0]["target_pid"], case
        assert any(item.get("api_name") == "kernel32.DuplicateHandle" and
                   item.get("ret_val") == "0x1" for item in entries[1]["events"]), case
        reads = [item for item in entries[2]["events"]
                 if item.get("api_name") == "kernel32.ReadFile"]
        assert [item["ret_val"] for item in reads] == ["0x0", "0x0", "0x1"], case
        assert [item["args"][0] for item in reads] == ["0x80", "0x84", "0x88"], case
        print(f"{case}: child-owned duplicate, guest bytes, artifacts, broker verified")


if __name__ == "__main__":
    verify(Path(sys.argv[1]).resolve())
