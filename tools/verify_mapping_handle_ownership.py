"""Verify packaged guest file-mapping handle ownership and inheritance."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from emumee.reports import verify_artifact_manifest


def verify(root: Path) -> None:
    fixtures = Path(__file__).resolve().parents[1] / "tests" / "fixtures"
    for arch in ("x86", "x64"):
        supplied = fixtures / f"child_parent_module_{arch}" / f"companion_{arch}.dll"
        for mapped, created, parent_closed in (
                (False, False, False), (False, True, False),
                (True, False, False), (True, True, False),
                (True, True, True)):
            suffix = "closed" if parent_closed else f"{int(mapped)}{int(created)}"
            case = f"child_parent_mapping_handle_inherit_{suffix}_{arch}"
            summaries = list((root / case).glob("*/summary.json"))
            assert len(summaries) == 1, (case, summaries)
            run = summaries[0].parent
            summary = json.loads(summaries[0].read_text(encoding="utf-8"))
            submitted = (fixtures / f"{case}.exe").read_bytes()
            assert (run / "input.pe").read_bytes() == submitted, case
            assert (run / "inputs" / supplied.name).read_bytes() == supplied.read_bytes(), case
            assert summary["sample"]["sha256"] == hashlib.sha256(submitted).hexdigest(), case
            assert not summary["errors"] and summary["status"] == "completed", case
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
                          if item["source"] == "file_write" and
                          str(item.get("guest_path", "")).endswith("map-data.bin")]
            assert len(guest_data) == 1, case
            assert (run / "artifacts" / guest_data[0]["file"]).read_bytes() == b"Pers", case
            report = json.loads((run / summary["engine_report"]).read_text(encoding="utf-8"))
            entries = report["entry_points"]
            assert len(entries) == 3 and entries[0]["pid"] == entries[1]["pid"], case
            assert entries[2]["pid"] != entries[1]["pid"], case
            expected = mapped and created
            assert entries[2]["ret_val"] == ("0x1" if expected else "0x0"), case
            creates = [item for item in report["virtual_process_events"]
                       if item["event"] == "virtual_process_create"]
            assert len(creates) == 1 and creates[0]["inherited_mapping_handles"] == int(expected), case
            calls = [item for item in entries[2]["events"]
                     if str(item.get("api_name", "")).endswith(("MapViewOfFile", "CloseHandle"))]
            assert len(calls) == 2, case
            assert (calls[0]["ret_val"] != "0x0") == expected, case
            assert calls[1]["ret_val"] == ("0x1" if expected else "0x0"), case
            events = report["virtual_file_events"]
            mappings = [item for item in events if item["event"] == "virtual_mapping_create"]
            assert len(mappings) == 1 and mappings[0]["size"] == 4, case
            views = [item for item in events if item["event"] == "virtual_mapping_view"]
            assert len(views) == int(expected), case
            denials = [item for item in events if item["event"] == "virtual_mapping_handle_denied"]
            assert len(denials) == (0 if expected else 2), case
            closes = [item for item in events if item["event"] == "virtual_mapping_close"]
            assert len(closes) == (2 if parent_closed else int(expected)), case
            assert all(item["success"] for item in closes), case
            if parent_closed:
                assert closes[0]["remaining_owners"] == 1, case
            print(f"{case}: mapping ownership, guest bytes, artifacts, broker verified")


if __name__ == "__main__":
    verify(Path(sys.argv[1]).resolve())
