"""Verify packaged cross-process handler reads are denied before engine access."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from emumee.native import _report_blob
from emumee.reports import verify_artifact_manifest


def verify(root: Path) -> None:
    for arch in ("x86", "x64"):
        for cross_owner in (True, False):
            name = f"{'child' if cross_owner else 'local'}_api_env_{arch}"
            summaries = list((root / name).glob("*/summary.json"))
            assert len(summaries) == 1, (name, summaries)
            run = summaries[0].parent
            summary = json.loads(summaries[0].read_text(encoding="utf-8"))
            report = json.loads((run / summary["engine_report"]).read_text(encoding="utf-8"))
            broker = json.loads((run / "network-broker.json").read_text(encoding="utf-8"))
            assert summary["network_broker_complete"] is True, name
            assert broker[-1] == {"event": "broker_closed"}, name
            assert verify_artifact_manifest(run, summary["artifacts"]), name
            assert not summary["api_coverage"]["signature_only_calls"], name
            events = report["virtual_process_events"]
            writes = [event for event in events
                      if event["event"] == "virtual_process_memory_write"]
            assert len(writes) == 1 and writes[0]["success"], name
            denied = [event for event in events
                      if event["event"] == "virtual_handler_memory_denied"]
            assert not any(event["event"] == "virtual_cpu_memory_denied" for event in events), name
            if cross_owner:
                assert summary["status"] == "partial", name
                assert len(report["entry_points"]) == 1, name
                assert any("GetEnvironmentVariableA: guest API read denied: "
                           "different guest process" in error for error in summary["errors"]), name
                assert len(denied) == 1, name
                assert (denied[0]["api"], denied[0]["access"], denied[0]["address"],
                        denied[0]["size"], denied[0]["reason"]) == (
                    "kernel32.GetEnvironmentVariableA", "read", 0x50000, 1,
                    "different guest process"), name
            else:
                assert summary["status"] == "completed" and not summary["errors"], name
                assert not denied, name
                assert len(report["entry_points"]) == 2 and all(
                    not entry.get("error") for entry in report["entry_points"]), name
                calls = [event for event in report["entry_points"][0]["events"]
                         if event.get("api_name") == "kernel32.GetEnvironmentVariableA"]
                assert len(calls) == 1 and calls[0]["ret_val"] == "0x5", name
                if arch == "x64":
                    destination = 0x140002400
                    maps = [entry for entry in report["entry_points"][-1]["memory"]["layout"]
                            if int(entry["address"], 16) <= destination <
                            int(entry["address"], 16) + int(entry["size"], 16)]
                    assert len(maps) == 1, name
                    offset = destination - int(maps[0]["address"], 16)
                    assert _report_blob(report["data"], maps[0]["data_ref"])[offset:offset + 5] == b"Alex\0", name
            print(f"{name}: {'handler read denied' if cross_owner else 'local handler completed'}; "
                  "broker and artifacts verified")


if __name__ == "__main__":
    verify(Path(sys.argv[1]).resolve())
