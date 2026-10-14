"""Verify packaged PEB, process-parameter, and loader ownership probes."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from emumee.reports import verify_artifact_manifest


def verify(root: Path) -> None:
    for arch in ("x86", "x64"):
        for kind in ("peb", "parameters", "ldr", "parent_peb", "parent_ldr"):
            name = f"child_{kind}_read_{arch}"
            summaries = list((root / name).glob("*/summary.json"))
            assert len(summaries) == 1, (name, summaries)
            run = summaries[0].parent
            summary = json.loads(summaries[0].read_text(encoding="utf-8"))
            report = json.loads((run / summary["engine_report"]).read_text(encoding="utf-8"))
            broker = json.loads((run / "network-broker.json").read_text(encoding="utf-8"))
            assert summary["sample"]["sha256"] == hashlib.sha256(
                (run / "input.pe").read_bytes()).hexdigest(), name
            assert summary["network_broker_complete"] is True, name
            assert broker[-1] == {"event": "broker_closed"}, name
            assert verify_artifact_manifest(run, summary["artifacts"]), name
            assert not summary["api_coverage"]["signature_only_calls"], name
            events = report["virtual_process_events"]
            writes = [event for event in events
                      if event["event"] == "virtual_process_memory_write"]
            assert len(writes) == 1 and writes[0]["success"], name
            entries = report["entry_points"]
            assert len(entries) == 2 and not entries[0].get("error"), name
            denied = [event for event in events
                      if event["event"] == "virtual_cpu_memory_denied"]
            if kind.startswith("parent_"):
                assert summary["status"] == "partial" and summary["errors"], name
                assert len(denied) == 1, name
                assert denied[0]["access"] == "read", name
                assert denied[0]["reason"] == "different guest process", name
                assert denied[0]["pid"] != denied[0]["owner_pid"], name
                assert denied[0]["address"] == (
                    0x4040 if kind == "parent_peb" else
                    0x49F0 if arch == "x64" else 0x4650), name
                assert entries[1].get("error"), name
            else:
                assert summary["status"] == "completed" and not summary["errors"], name
                assert not denied and not entries[1].get("error"), name
                assert entries[1]["ret_val"] == (
                    "0x118" if kind == "parameters" and arch == "x64" else
                    "0xb8" if kind == "parameters" else "0x0"), name
            print(f"{name}: {'parent read denied' if kind.startswith('parent_') else 'child structure readable'}; "
                  "broker and artifacts verified")


if __name__ == "__main__":
    verify(Path(sys.argv[1]).resolve())
