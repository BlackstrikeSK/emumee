"""Verify the harmless packaged named pagefile mapping matrix."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from emumee.native import _report_blob
from emumee.reports import verify_artifact_manifest


def verify(root: Path) -> None:
    fixtures = Path(__file__).resolve().parents[1] / "tests" / "fixtures"
    for arch in ("x86", "x64"):
        for kind in ("named_pagefile_mapping", "named_pagefile_coherent",
                     "named_pagefile_remap", "named_pagefile_duplicate",
                     "child_parent_named_mapping",
                     "child_parent_named_mapping_foreign_read"):
            case = f"{kind}_{arch}"
            summaries = list((root / case).glob("*/summary.json"))
            assert len(summaries) == 1, (case, summaries)
            run = summaries[0].parent
            summary = json.loads(summaries[0].read_text(encoding="utf-8"))
            submitted = (fixtures / f"{case}.exe").read_bytes()
            assert (run / "input.pe").read_bytes() == submitted, case
            assert summary["sample"]["sha256"] == hashlib.sha256(submitted).hexdigest(), case
            assert verify_artifact_manifest(run, summary["artifacts"]), case
            assert summary["network_broker_complete"] is True, case
            journal = json.loads((run / "network-broker.json").read_text(encoding="utf-8"))
            assert journal[-1] == {"event": "broker_closed"}, case
            assert not summary["api_coverage"]["signature_only_calls"], case
            if kind.startswith("child_parent"):
                supplied = fixtures / f"child_parent_module_{arch}" / f"companion_{arch}.dll"
                assert (run / "inputs" / supplied.name).read_bytes() == supplied.read_bytes(), case
                embedded = [item for item in summary["artifacts"]
                            if item["source"] == "embedded_input@0xa00"]
                assert len(embedded) == 1, case
                assert (run / "artifacts" / embedded[0]["file"]).read_bytes() == submitted[0xA00:0x1000], case
            report = json.loads((run / summary["engine_report"]).read_text(encoding="utf-8"))
            entries = report["entry_points"]
            child = kind.startswith("child_parent")
            assert len(entries) == (3 if child else 1), case
            calls = [event for entry in entries for event in entry.get("events") or []]
            opener = ("kernel32.DuplicateHandle" if kind == "named_pagefile_duplicate"
                      else "kernel32.OpenFileMappingW")
            opens = [event for event in calls if event.get("api_name") == opener]
            assert len(opens) == 1, case
            views = [event for event in report["virtual_file_events"]
                     if event["event"] == "virtual_mapping_view"
                     and event.get("path") == "<pagefile>"]
            if child:
                assert opens[0]["ret_val"] == "0x0", case
                assert entries[-1]["ret_val"] == "0x0", case
                assert len(views) == 1, case
                retired = [event for event in report["virtual_file_events"]
                           if event["event"] == "virtual_mapping_view_process_exit"
                           and event["base"] == views[0]["base"]]
                assert len(retired) == 1, case
                cleanup = [event for event in report["virtual_file_events"]
                           if event["event"] == "virtual_file_process_cleanup"
                           and event["views"] == 1 and event["mappings"] == 1]
                assert len(cleanup) == 1, case
                assert summary["status"] == "completed" and not summary["errors"], case
                print(f"{case}: parent section and view retired before child open")
                continue
            assert opens[0]["ret_val"] != "0x0", case
            assert len(views) == 2, case
            layout = entries[-1]["memory"]["layout"]
            maps = [item for item in layout if item["tag"].startswith("api.MapViewOfFile.")]
            assert len(maps) == 2, case
            expected_bytes = b"Cohr" if kind == "named_pagefile_coherent" else b"Pers"
            assert all(_report_blob(report["data"], item["data_ref"])[:4] == expected_bytes
                       for item in maps), case
            if kind == "named_pagefile_remap":
                assert any(event.get("api_name") == "kernel32.UnmapViewOfFile"
                           and event.get("ret_val") == "0x1" for event in calls), case
            assert all(item["is_free"] for item in maps), case
            denied = [event for event in report["virtual_process_events"]
                      if event["event"] == "virtual_cpu_memory_denied"]
            assert summary["status"] == "completed" and not summary["errors"], case
            assert not denied, case
            assert any(event.get("api_name") == "kernel32.ExitProcess"
                       and event.get("args") == ["0x1"] for event in calls), case
            print(f"{case}: named bytes, rights, artifacts, broker, and boundary verified")


if __name__ == "__main__":
    verify(Path(sys.argv[1]))
