"""Verify packaged harmless guest file-handle duplication cases."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from emumee.reports import verify_artifact_manifest


def verify(root: Path) -> None:
    fixtures = Path(__file__).resolve().parents[1] / "tests" / "fixtures"
    for arch in ("x86", "x64"):
        case = f"duplicate_guest_file_{arch}"
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
        calls = report["entry_points"][0]["events"]
        for api, count in (("kernel32.WriteFile", 2),
                           ("kernel32.DuplicateHandle", 1),
                           ("kernel32.CloseHandle", 1)):
            assert sum(event.get("api_name") == api and event.get("ret_val") == "0x1"
                       for event in calls) == count, case
        assert any(event.get("api_name") == "kernel32.ExitProcess"
                   and event.get("args") == ["0x1"] for event in calls), case
        duplicated = [event for event in report["virtual_file_events"]
                      if event["event"] == "virtual_guest_handle_duplicate"]
        assert len(duplicated) == 1 and duplicated[0]["success"], case
        assert duplicated[0]["object_type"] == "file", case
        writes = [item for item in summary["artifacts"]
                  if item["source"] == "file_write" and
                  item.get("guest_path", "").endswith("duplicate-file.bin")]
        assert len(writes) == 1, case
        assert (run / "artifacts" / writes[0]["file"]).read_bytes() == b"ABCDEFGHQRST", case
        print(f"{case}: cursor, source close, artifact, and broker verified")


if __name__ == "__main__":
    verify(Path(sys.argv[1]))
