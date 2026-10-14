"""Verify packaged child memory APIs cannot read a parent guest-created DLL."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from emumee.reports import verify_artifact_manifest


def verify(root: Path) -> None:
    fixtures = Path(__file__).resolve().parents[1] / "tests" / "fixtures"
    for arch, base, access in ((arch, base, access)
                               for arch, base in (("x86", 0x50000000),
                                                  ("x64", 0x180000000))
                               for access in ("copy", "write")):
        case = f"child_parent_guest_dll_api_{access}_{arch}"
        summaries = list((root / case).glob("*/summary.json"))
        assert len(summaries) == 1, (case, summaries)
        run = summaries[0].parent
        summary = json.loads(summaries[0].read_text(encoding="utf-8"))
        submitted = (fixtures / f"{case}.exe").read_bytes()
        assert (run / "input.pe").read_bytes() == submitted, case
        assert not list((run / "inputs").glob("*.dll")), case
        assert summary["sample"]["sha256"] == hashlib.sha256(submitted).hexdigest(), case
        assert summary["network_broker_complete"] is True, case
        journal = json.loads((run / "network-broker.json").read_text(encoding="utf-8"))
        assert journal[-1] == {"event": "broker_closed"}, case
        assert verify_artifact_manifest(run, summary["artifacts"]), case
        assert not summary["api_coverage"]["signature_only_calls"], case
        for offset, size in ((0xA00, 0x600), (0x1000, 0x600)):
            payload = submitted[offset:offset + size]
            assert len(payload) == size, case
            assert any((run / "artifacts" / item["file"]).read_bytes() == payload
                       for item in summary["artifacts"]), case
        report = json.loads((run / summary["engine_report"]).read_text(encoding="utf-8"))
        entries = report["entry_points"]
        assert len(entries) == 2 and entries[0]["pid"] != entries[1]["pid"], case
        loads = [event for event in entries[0]["events"]
                 if str(event.get("api_name", "")).endswith("LoadLibraryW")]
        assert len(loads) == 1 and loads[0]["ret_val"] == hex(base), case
        loaded = [event for event in report["dll_initialization_events"]
                  if event["event"] == "virtual_dll_load" and event.get("mapped")]
        assert len(loaded) == 1 and loaded[0]["base"] == hex(base), case
        assert loaded[0]["sha256"] == hashlib.sha256(submitted[0x1000:0x1600]).hexdigest(), case
        denied = [event for event in report["virtual_process_events"]
                  if event["event"] == "virtual_memory_api_denied"]
        assert len(denied) == 1, case
        expected_pointer = "source" if access == "copy" else "destination"
        assert denied[0]["reason"] == f"{expected_pointer} belongs to different guest process", case
        assert not any(event["event"] == "virtual_cpu_memory_denied"
                       for event in report["virtual_process_events"]), case
        print(f"{case}: guest DLL API pointer denied; bytes, artifacts, broker verified")


if __name__ == "__main__":
    verify(Path(sys.argv[1]).resolve())
