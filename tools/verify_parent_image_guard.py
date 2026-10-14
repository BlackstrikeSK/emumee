"""Verify packaged child CPU probes cannot access a parent's supplied DLL."""

from __future__ import annotations

import hashlib
from itertools import product
import json
import sys
from pathlib import Path

from emumee.reports import verify_artifact_manifest


def verify(root: Path, modes: tuple[str, ...] = ("static", "dynamic", "guest")) -> None:
    fixtures = Path(__file__).resolve().parents[1] / "tests" / "fixtures"
    for arch, base in (("x86", 0x50000000), ("x64", 0x180000000)):
        supplied = fixtures / f"child_parent_module_{arch}" / f"companion_{arch}.dll"
        for load_mode, access in product(modes, ("read", "write", "execute")):
            prefix = "" if load_mode == "static" else f"{load_mode}_"
            case = f"child_parent_{prefix}dll_cpu_{access}_{arch}"
            summaries = list((root / case).glob("*/summary.json"))
            assert len(summaries) == 1, (case, summaries)
            run = summaries[0].parent
            summary = json.loads(summaries[0].read_text(encoding="utf-8"))
            submitted = (fixtures / f"{case}.exe").read_bytes()
            assert (run / "input.pe").read_bytes() == submitted, case
            if load_mode != "guest":
                assert (run / "inputs" / supplied.name).read_bytes() == supplied.read_bytes(), case
            else:
                assert not list((run / "inputs").glob("*.dll")), case
            assert summary["sample"]["sha256"] == hashlib.sha256(submitted).hexdigest(), case
            assert summary["network_broker_complete"] is True, case
            journal = json.loads((run / "network-broker.json").read_text(encoding="utf-8"))
            assert journal[-1] == {"event": "broker_closed"}, case
            assert verify_artifact_manifest(run, summary["artifacts"]), case
            assert not summary["api_coverage"]["signature_only_calls"], case
            embedded = [item for item in summary["artifacts"]
                        if item["source"] == "embedded_input@0xa00"]
            assert len(embedded) == 1, case
            assert (run / "artifacts" / embedded[0]["file"]).read_bytes() == submitted[0xA00:0x1000], case
            if load_mode == "guest":
                guest_dll = submitted[0x1000:0x1600]
                assert len(guest_dll) == 0x600, case
                assert any((run / "artifacts" / item["file"]).read_bytes() == guest_dll
                           for item in summary["artifacts"]), case
            report = json.loads((run / summary["engine_report"]).read_text(encoding="utf-8"))
            entries = report["entry_points"]
            if load_mode == "static":
                assert len(entries) == 3 and entries[0]["pid"] == entries[1]["pid"] != entries[2]["pid"], case
                assert entries[0]["ep_args"][0] == hex(base), case
            else:
                assert len(entries) == 2 and entries[0]["pid"] != entries[1]["pid"], case
                loads = [event for event in entries[0]["events"]
                         if str(event.get("api_name", "")).endswith("LoadLibraryW")]
                assert len(loads) == 1 and loads[0]["ret_val"] == hex(base), case
                attach = [event for event in report["dll_initialization_events"]
                          if event["event"] == "dll_process_attach"]
                assert len(attach) == 1 and attach[0]["success"], case
                if load_mode == "guest":
                    loaded = [event for event in report["dll_initialization_events"]
                              if event["event"] == "virtual_dll_load" and event.get("mapped")]
                    assert len(loaded) == 1 and loaded[0]["base"] == hex(base), case
                    assert loaded[0]["sha256"] == hashlib.sha256(guest_dll).hexdigest(), case
            denied = [event for event in report["virtual_process_events"]
                      if event["event"] == "virtual_cpu_memory_denied"]
            assert len(denied) == 1, case
            assert (denied[0]["access"], denied[0]["reason"]) == (
                access, "different guest process"), case
            assert denied[0]["pid"] != denied[0]["owner_pid"], case
            if access == "write":
                restored = [event for event in report["virtual_process_events"]
                            if event["event"] == "virtual_cpu_memory_restored"]
                assert len(restored) == 1 and restored[0]["success"], case
            print(f"{case}: packaged denial, exact bytes, artifacts, broker verified")


if __name__ == "__main__":
    verify(Path(sys.argv[1]).resolve(),
           tuple(sys.argv[2].split(",")) if len(sys.argv) > 2 else ("static", "dynamic", "guest"))
