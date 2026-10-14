"""Verify packaged API map rejection and valid CoCreateGuid controls."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from emumee.reports import verify_artifact_manifest


def verify(root: Path) -> None:
    for arch in ("x86", "x64"):
        for kind in ("child_read", "foreign_write", "local_read"):
            name = f"private_api_map_{kind}_{arch}"
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
            denied = [event for event in events
                      if event["event"] == "virtual_handler_memory_denied"]
            assert not any(event["event"] == "virtual_cpu_memory_denied" for event in events), name
            entries = report["entry_points"]
            if kind in ("child_read", "foreign_write"):
                assert summary["status"] == "partial" and summary["errors"], name
                assert len(entries) == 1, name
                assert len(denied) == 1, name
                expected = (("ole32.CoCreateGuid", "map", 0x1000, 0x30000000,
                             "API map size exceeds limit") if kind == "child_read" else
                            ("ole32.CoCreateGuid", "write", 0x50000, 16,
                             "different guest process"))
                assert (denied[0]["api"], denied[0]["access"], denied[0]["address"],
                        denied[0]["size"], denied[0]["reason"]) == expected, name
                if kind == "child_read":
                    assert not any(int(mapping["address"], 16) == 0x30000000
                                   for mapping in entries[0]["memory"]["layout"]), name
            else:
                assert summary["status"] == "completed" and not summary["errors"], name
                assert len(entries) == 2 and not denied, name
                assert all(not entry.get("error") for entry in entries), name
                assert entries[0]["ret_val"] == "0xdec0adde", name
                calls = [event for event in entries[0]["events"]
                         if event.get("api_name") == "ole32.CoCreateGuid"]
                assert len(calls) == 1 and calls[0]["ret_val"] == "0x0", name
            outcome = {"child_read": "map denied", "foreign_write": "foreign write denied",
                       "local_read": "local GUID completed"}[kind]
            print(f"{name}: {outcome}; broker and artifacts verified")


if __name__ == "__main__":
    verify(Path(sys.argv[1]).resolve())
