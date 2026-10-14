"""Verify packaged CPU guards for known foreign and released guest pages."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from emumee.reports import verify_artifact_manifest
from emumee.native import _report_blob


def verify(root: Path, selected: set[str] | None = None) -> None:
    cases = [(f"child_direct_{access}_{arch}", access, "different guest process")
             for arch in ("x86", "x64") for access in ("read", "write", "write_rep", "execute")]
    cases += [(f"virtual_free_ex_direct_read_{arch}", "read", "released memory")
              for arch in ("x86", "x64")]
    for name, access, reason in cases:
        if selected is not None and name not in selected:
            continue
        operation = "write" if access == "write_rep" else access
        summaries = list((root / name).glob("*/summary.json"))
        assert len(summaries) == 1, (name, summaries)
        run = summaries[0].parent
        summary = json.loads(summaries[0].read_text(encoding="utf-8"))
        report = json.loads((run / summary["engine_report"]).read_text(encoding="utf-8"))
        broker = json.loads((run / "network-broker.json").read_text(encoding="utf-8"))
        assert summary["status"] == "partial", name
        assert len(report["entry_points"]) == 1, name
        assert any(f"guest {operation} denied: {reason}" in error
                   for error in summary["errors"]), name
        assert summary["network_broker_complete"] is True, name
        assert verify_artifact_manifest(run, summary["artifacts"]), name
        assert broker[-1] == {"event": "broker_closed"}, name
        assert not summary["api_coverage"]["signature_only_calls"], name
        denied = [event for event in report["virtual_process_events"]
                  if event["event"] == "virtual_cpu_memory_denied"]
        assert len(denied) == 1, (name, denied)
        assert (denied[0]["access"], denied[0]["reason"]) == (operation, reason), name
        assert not any(event["event"] == "virtual_process_memory_write"
                       for event in report["virtual_process_events"]), name
        if reason == "different guest process":
            assert denied[0]["pid"] != denied[0]["owner_pid"], name
            creates = [event for event in report["virtual_process_events"]
                       if event["event"] == "virtual_process_create"]
            assert len(creates) == 1 and creates[0]["success"], name
            if operation == "write":
                restored = [event for event in report["virtual_process_events"]
                            if event["event"] == "virtual_cpu_memory_restored"]
                assert len(restored) == 1 and restored[0]["success"], name
                maps = [mapping for mapping in report["entry_points"][-1]["memory"]["layout"]
                        if mapping["tag"].startswith("api.VirtualAllocEx.child-stage")]
                assert len(maps) == 1, name
                length = 16 if access == "write_rep" else 4
                assert _report_blob(report["data"], maps[0]["data_ref"])[:length] == b"\0" * length, name
        else:
            frees = [event for event in report["virtual_process_events"]
                     if event["event"] == "virtual_process_free"]
            assert [event["success"] for event in frees] == [False, True], name
        print(f"{name}: CPU {access} denied at {reason}; broker and artifacts verified")


def verify_controls(root: Path) -> None:
    for arch in ("x86", "x64"):
        name = f"child_process_{arch}"
        summaries = list((root / name).glob("*/summary.json"))
        assert len(summaries) == 1, (name, summaries)
        run = summaries[0].parent
        summary = json.loads(summaries[0].read_text(encoding="utf-8"))
        report = json.loads((run / summary["engine_report"]).read_text(encoding="utf-8"))
        broker = json.loads((run / "network-broker.json").read_text(encoding="utf-8"))
        assert summary["status"] == "completed" and not summary["errors"], name
        assert summary["network_broker_complete"] is True, name
        assert verify_artifact_manifest(run, summary["artifacts"]), name
        assert broker[-1] == {"event": "broker_closed"}, name
        assert not any(event["event"] == "virtual_cpu_memory_denied"
                       for event in report["virtual_process_events"]), name
        writes = [event for event in report["virtual_process_events"]
                  if event["event"] == "virtual_process_memory_write"]
        assert len(writes) == 1 and writes[0]["success"], name
        assert len(report["entry_points"]) == 2 and all(
            not entry.get("error") for entry in report["entry_points"]), name
        print(f"{name}: legitimate child write and execution verified")


if __name__ == "__main__":
    if len(sys.argv) > 2 and sys.argv[2] == "--case":
        verify(Path(sys.argv[1]).resolve(), set(sys.argv[3:]))
    else:
        verify(Path(sys.argv[1]).resolve())
    if len(sys.argv) > 2 and sys.argv[2] != "--case":
        verify_controls(Path(sys.argv[2]).resolve())
