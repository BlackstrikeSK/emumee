"""Verify packaged guest bulk-memory APIs cannot copy a child-owned page."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from emumee.native import _report_blob
from emumee.reports import verify_artifact_manifest


def verify(root: Path) -> None:
    for arch in ("x86", "x64"):
        name = f"child_api_copy_{arch}"
        summaries = list((root / name).glob("*/summary.json"))
        assert len(summaries) == 1, (name, summaries)
        run = summaries[0].parent
        summary = json.loads(summaries[0].read_text(encoding="utf-8"))
        report = json.loads((run / summary["engine_report"]).read_text(encoding="utf-8"))
        broker = json.loads((run / "network-broker.json").read_text(encoding="utf-8"))
        assert summary["status"] == "partial", name
        assert len(report["entry_points"]) == 1, name
        assert any("RtlMoveMemory: source belongs to different guest process" in error
                   for error in summary["errors"]), name
        assert summary["network_broker_complete"] is True, name
        assert broker[-1] == {"event": "broker_closed"}, name
        assert verify_artifact_manifest(run, summary["artifacts"]), name
        assert not summary["api_coverage"]["signature_only_calls"], name
        events = report["virtual_process_events"]
        denied = [event for event in events
                  if event["event"] == "virtual_memory_api_denied"]
        assert len(denied) == 1, (name, denied)
        assert denied[0]["reason"] == "source belongs to different guest process", name
        assert not any(event["event"] == "virtual_cpu_memory_denied" for event in events), name
        writes = [event for event in events
                  if event["event"] == "virtual_process_memory_write"]
        assert len(writes) == 1 and writes[0]["success"], name
        if arch == "x64":
            destination = 0x140002400
            maps = [entry for entry in report["entry_points"][-1]["memory"]["layout"]
                    if int(entry["address"], 16) <= destination <
                    int(entry["address"], 16) + int(entry["size"], 16)]
            assert len(maps) == 1, name
            offset = destination - int(maps[0]["address"], 16)
            assert _report_blob(report["data"], maps[0]["data_ref"])[offset:offset + 16] == b"\0" * 16, name
        print(f"{name}: API copy denied; broker, artifacts, and guest events verified")


if __name__ == "__main__":
    verify(Path(sys.argv[1]).resolve())
