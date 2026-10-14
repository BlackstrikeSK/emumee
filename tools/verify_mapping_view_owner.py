"""Verify packaged direct-child access to parent guest mapping views is denied."""

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
        for access in ("read", "write"):
            case = f"child_parent_mapping_view_{access}_{arch}"
            summaries = list((root / case).glob("*/summary.json"))
            assert len(summaries) == 1, (case, summaries)
            run = summaries[0].parent
            summary = json.loads(summaries[0].read_text(encoding="utf-8"))
            submitted = (fixtures / f"{case}.exe").read_bytes()
            supplied = fixtures / f"child_parent_module_{arch}" / f"companion_{arch}.dll"
            assert (run / "input.pe").read_bytes() == submitted, case
            assert (run / "inputs" / supplied.name).read_bytes() == supplied.read_bytes(), case
            assert summary["sample"]["sha256"] == hashlib.sha256(submitted).hexdigest(), case
            assert summary["status"] == "partial" and len(summary["errors"]) == 1, case
            assert f"guest {access} denied: different guest process" in summary["errors"][0], case
            assert summary["network_broker_complete"] is True, case
            journal = json.loads((run / "network-broker.json").read_text(encoding="utf-8"))
            assert journal[-1] == {"event": "broker_closed"}, case
            assert verify_artifact_manifest(run, summary["artifacts"]), case
            assert not summary["api_coverage"]["signature_only_calls"], case
            embedded = [item for item in summary["artifacts"]
                        if item["source"] == "embedded_input@0xa00"]
            assert len(embedded) == 1, case
            assert (run / "artifacts" / embedded[0]["file"]).read_bytes() == submitted[0xA00:0x1000], case
            guest_data = [item for item in summary["artifacts"]
                          if str(item.get("guest_path", "")).endswith("map-data.bin")]
            assert guest_data, case
            assert all((run / "artifacts" / item["file"]).read_bytes() == b"Pers"
                       for item in guest_data), case
            report = json.loads((run / summary["engine_report"]).read_text(encoding="utf-8"))
            entries = report["entry_points"]
            assert len(entries) == 3 and entries[0]["pid"] == entries[1]["pid"], case
            assert entries[2]["pid"] != entries[1]["pid"] and entries[2]["ret_val"] is None, case
            views = [item for item in report["virtual_file_events"]
                     if item["event"] == "virtual_mapping_view"]
            assert len(views) == 1 and views[0]["size"] == 4, case
            assert views[0]["writable"] == (access == "write"), case
            events = report["virtual_process_events"]
            denials = [item for item in events if item["event"] == "virtual_cpu_memory_denied"]
            assert len(denials) == 1, case
            assert (denials[0]["access"], denials[0]["address"], denials[0]["size"],
                    denials[0]["reason"]) == (
                        access, views[0]["base"], 4, "different guest process"), case
            assert denials[0]["pid"] != denials[0]["owner_pid"], case
            restored = [item for item in events if item["event"] == "virtual_cpu_memory_restored"]
            assert (len(restored), all(item["success"] for item in restored)) == (
                int(access == "write"), True), case
            print(f"{case}: parent view {access} denied; bytes, artifacts, broker verified")

    for arch in ("x86", "x64"):
        for access in ("read", "execute", "api_read", "api_write"):
            case = f"child_parent_pagefile_view_{access}_{arch}"
            summaries = list((root / case).glob("*/summary.json"))
            assert len(summaries) == 1, (case, summaries)
            run = summaries[0].parent
            summary = json.loads(summaries[0].read_text(encoding="utf-8"))
            submitted = (fixtures / f"{case}.exe").read_bytes()
            supplied = fixtures / f"child_parent_module_{arch}" / f"companion_{arch}.dll"
            assert (run / "input.pe").read_bytes() == submitted, case
            assert (run / "inputs" / supplied.name).read_bytes() == supplied.read_bytes(), case
            assert summary["sample"]["sha256"] == hashlib.sha256(submitted).hexdigest(), case
            assert summary["status"] == "partial" and len(summary["errors"]) == 1, case
            role = "source" if access == "api_read" else "destination"
            expected_error = (f"RtlMoveMemory: {role} belongs to different guest process"
                              if access.startswith("api_") else
                              f"guest {access} denied: different guest process")
            assert expected_error in summary["errors"][0], case
            assert summary["network_broker_complete"] is True, case
            journal = json.loads((run / "network-broker.json").read_text(encoding="utf-8"))
            assert journal[-1] == {"event": "broker_closed"}, case
            assert verify_artifact_manifest(run, summary["artifacts"]), case
            assert not summary["api_coverage"]["signature_only_calls"], case
            embedded = [item for item in summary["artifacts"]
                        if item["source"] == "embedded_input@0xa00"]
            assert len(embedded) == 1, case
            assert (run / "artifacts" / embedded[0]["file"]).read_bytes() == submitted[0xA00:0x1000], case
            report = json.loads((run / summary["engine_report"]).read_text(encoding="utf-8"))
            entries = report["entry_points"]
            assert len(entries) == 3 and entries[0]["pid"] == entries[1]["pid"], case
            assert entries[2]["pid"] != entries[1]["pid"] and entries[2]["ret_val"] is None, case
            cpu_denials = [item for item in report["virtual_process_events"]
                           if item["event"] == "virtual_cpu_memory_denied"]
            api_denials = [item for item in report["virtual_process_events"]
                           if item["event"] == "virtual_memory_api_denied"]
            if access.startswith("api_"):
                assert not cpu_denials and len(api_denials) == 1, case
                assert (api_denials[0]["api"], api_denials[0]["size"],
                        api_denials[0]["reason"]) == (
                            "kernel32.RtlMoveMemory", 4,
                            f"{role} belongs to different guest process"), case
                denied_address = api_denials[0]["pointers"][role]
            else:
                assert not api_denials and len(cpu_denials) == 1, case
                assert cpu_denials[0]["access"] == access, case
                assert cpu_denials[0]["reason"] == "different guest process", case
                assert cpu_denials[0]["pid"] != cpu_denials[0]["owner_pid"], case
                denied_address = cpu_denials[0]["address"]
            maps = [item for item in entries[-1]["memory"]["layout"]
                    if item["tag"].startswith("api.MapViewOfFile.")]
            assert len(maps) == 1 and int(maps[0]["address"], 16) == denied_address, case
            assert maps[0]["prot"] == ("rwx" if access == "execute" else "rw-"), case
            assert _report_blob(report["data"], maps[0]["data_ref"])[:4] == (
                b"\xc3\x90\x90\x90" if access == "execute" else b"Pers"), case
            print(f"{case}: pagefile view {access} denied; bytes, artifacts, broker verified")

    for arch in ("x86", "x64"):
        for operation in ("flush", "unmap", "unmap_interior"):
            case = f"child_parent_pagefile_view_{operation}_{arch}"
            summaries = list((root / case).glob("*/summary.json"))
            assert len(summaries) == 1, (case, summaries)
            run = summaries[0].parent
            summary = json.loads(summaries[0].read_text(encoding="utf-8"))
            submitted = (fixtures / f"{case}.exe").read_bytes()
            supplied = fixtures / f"child_parent_module_{arch}" / f"companion_{arch}.dll"
            assert (run / "input.pe").read_bytes() == submitted, case
            assert (run / "inputs" / supplied.name).read_bytes() == supplied.read_bytes(), case
            assert summary["sample"]["sha256"] == hashlib.sha256(submitted).hexdigest(), case
            assert summary["status"] == "completed" and not summary["errors"], case
            assert summary["network_broker_complete"] is True, case
            journal = json.loads((run / "network-broker.json").read_text(encoding="utf-8"))
            assert journal[-1] == {"event": "broker_closed"}, case
            assert verify_artifact_manifest(run, summary["artifacts"]), case
            assert not summary["api_coverage"]["signature_only_calls"], case
            embedded = [item for item in summary["artifacts"]
                        if item["source"] == "embedded_input@0xa00"]
            assert len(embedded) == 1, case
            assert (run / "artifacts" / embedded[0]["file"]).read_bytes() == submitted[0xA00:0x1000], case
            report = json.loads((run / summary["engine_report"]).read_text(encoding="utf-8"))
            entries = report["entry_points"]
            assert len(entries) == 3 and entries[0]["pid"] == entries[1]["pid"], case
            assert entries[2]["pid"] != entries[1]["pid"] and entries[2]["ret_val"] == "0x0", case
            denials = [item for item in report["virtual_file_events"]
                       if item["event"] == "virtual_mapping_view_denied"]
            expected_api = ("kernel32.FlushViewOfFile" if operation == "flush" else
                            "kernel32.UnmapViewOfFile")
            assert len(denials) == (0 if operation == "flush" else 1), case
            if denials:
                assert denials[0]["api"] == expected_api, case
                assert denials[0]["reason"] == "untracked view", case
            assert not any(item["event"] == "virtual_cpu_memory_denied"
                           for item in report["virtual_process_events"]), case
            maps = [item for item in entries[-1]["memory"]["layout"]
                    if item["tag"].startswith("api.MapViewOfFile.")]
            assert len(maps) == 1, case
            if denials:
                assert int(maps[0]["address"], 16) == denials[0]["base"], case
            assert maps[0]["is_free"] is True, case
            assert _report_blob(report["data"], maps[0]["data_ref"])[:4] == b"Pers", case
            print(f"{case}: retired view {operation} rejected; bytes, artifacts, broker verified")


if __name__ == "__main__":
    verify(Path(sys.argv[1]).resolve())
