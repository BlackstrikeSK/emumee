"""Verify packaged companion relocation and collision rejection fixtures."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from emumee.reports import verify_artifact_manifest


def verify(root: Path) -> None:
    fixtures = Path(__file__).resolve().parents[1] / "tests" / "fixtures"
    for arch in ("x86", "x64"):
        preferred = 0x1A0000000 if arch == "x64" else 0x52000000
        for variant in ("reloc_leaf", "no_reloc_collision", "bad_reloc_block"):
            name = f"{variant}_{arch}"
            summaries = list((root / name).glob("*/summary.json"))
            assert len(summaries) == 1, (name, summaries)
            run = summaries[0].parent
            summary = json.loads(summaries[0].read_text(encoding="utf-8"))
            broker = json.loads((run / "network-broker.json").read_text(
                encoding="utf-8"))
            assert summary["network_broker_complete"] is True, name
            assert broker[-1] == {"event": "broker_closed"}, name
            assert summary["sample"]["sha256"] == hashlib.sha256(
                (run / "input.pe").read_bytes()).hexdigest(), name
            for stem in ("companion", "leaf"):
                dll = f"{stem}_{arch}.dll"
                expected = (fixtures / "static_chain" / variant / dll).read_bytes()
                assert (run / "inputs" / dll).read_bytes() == expected, (name, dll)

            if variant != "reloc_leaf":
                assert summary["status"] == "failed", name
                assert any(f"Static companion relocation unavailable: leaf_{arch}"
                           in error for error in summary["errors"]), name
                assert not summary.get("engine_report") and not summary.get("artifacts"), name
                print(f"{name}: unusable relocation table rejected; broker closed")
                continue

            assert summary["status"] == "completed" and not summary["errors"], name
            assert verify_artifact_manifest(run, summary["artifacts"]), name
            assert not summary["api_coverage"]["signature_only_calls"], name
            report = json.loads((run / summary["engine_report"]).read_text(
                encoding="utf-8"))
            entries = report["entry_points"]
            assert [entry["ep_type"] for entry in entries] == [
                f"static_dll_entry_leaf_{arch}",
                f"static_dll_entry_companion_{arch}", "module_entry"], name
            assert not any(entry.get("error") for entry in entries), name
            assert [entry["ret_val"] for entry in entries] == [
                "0x1", "0x1", "0x2a"], name
            leaf_base = int(entries[0]["start_addr"], 16) - 0x1000
            middle_base = int(entries[1]["start_addr"], 16) - 0x1000
            assert middle_base == preferred and leaf_base != preferred, name
            assert int(entries[0]["ep_args"][0], 16) == leaf_base, name
            exits = [event for entry in entries for event in entry.get("events") or []
                     if str(event.get("api_name", "")).endswith("ExitProcess")]
            assert exits and exits[-1]["args"] == ["0x2a"], name
            print(f"{name}: leaf rebased to 0x{leaf_base:x}, export returned 42; "
                  "broker and inputs verified")


def verify_dynamic(root: Path) -> None:
    fixtures = Path(__file__).resolve().parents[1] / "tests" / "fixtures"
    for arch in ("x86", "x64"):
        preferred = 0x140000000 if arch == "x64" else 0x400000
        for variant in ("reloc_dynamic", "no_reloc_dynamic", "bad_reloc_dynamic"):
            name = f"{variant}_{arch}"
            summaries = list((root / name).glob("*/summary.json"))
            assert len(summaries) == 1, (name, summaries)
            run = summaries[0].parent
            summary = json.loads(summaries[0].read_text(encoding="utf-8"))
            broker = json.loads((run / "network-broker.json").read_text(
                encoding="utf-8"))
            assert summary["network_broker_complete"] is True, name
            assert broker[-1] == {"event": "broker_closed"}, name
            assert summary["sample"]["sha256"] == hashlib.sha256(
                (run / "input.pe").read_bytes()).hexdigest(), name
            dll = f"companion_{arch}.dll"
            assert (run / "inputs" / dll).read_bytes() == (
                fixtures / variant / dll).read_bytes(), name
            assert verify_artifact_manifest(run, summary["artifacts"]), name
            report = json.loads((run / summary["engine_report"]).read_text(
                encoding="utf-8"))
            entries = report["entry_points"]
            assert len(entries) == 1, name
            loads = [event for event in entries[0].get("events") or []
                     if str(event.get("api_name", "")).endswith("LoadLibraryA")]
            assert len(loads) == 1, name
            if variant != "reloc_dynamic":
                assert summary["status"] == "partial", name
                assert loads[0]["ret_val"] == "0x0", name
                assert any("companion relocation unavailable" in error
                           for error in summary["errors"]), name
                assert not report["dll_initialization_events"], name
                print(f"{name}: unusable dynamic relocation denied; broker closed")
                continue
            assert summary["status"] == "completed" and not summary["errors"], name
            assert not summary["api_coverage"]["signature_only_calls"], name
            base = int(loads[0]["ret_val"], 16)
            assert base and base != preferred, name
            assert entries[0]["ret_val"] == "0x2a" and not entries[0].get("error"), name
            assert report["dll_initialization_events"] == [
                {"event": "dll_process_attach", "module": f"companion_{arch}",
                 "base": hex(base), "success": True}], name
            print(f"{name}: dynamic DLL rebased to 0x{base:x}, export returned 42; "
                  "broker and input verified")


if __name__ == "__main__":
    verify(Path(sys.argv[1]).resolve())
    if len(sys.argv) > 2:
        verify_dynamic(Path(sys.argv[2]).resolve())
