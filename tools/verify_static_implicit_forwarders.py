"""Verify packaged static imports through unloaded supplied DLL forwarders."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from emumee.reports import verify_artifact_manifest


def verify(root: Path) -> None:
    fixtures = Path(__file__).resolve().parents[1] / "tests" / "fixtures"
    for arch in ("x86", "x64"):
        for mode in ("valid", "missing_reloc", "failed_attach", "chain"):
            case = f"{mode}_{arch}"
            summaries = list((root / case).glob("*/summary.json"))
            assert len(summaries) == 1, (case, summaries)
            run = summaries[0].parent
            summary = json.loads(summaries[0].read_text(encoding="utf-8"))
            sample = (fixtures / f"static_companion_{arch}.exe").read_bytes()
            assert (run / "input.pe").read_bytes() == sample, case
            assert summary["sample"]["sha256"] == hashlib.sha256(sample).hexdigest(), case
            stems = ("companion", "leaf", "terminal") if mode == "chain" else (
                "companion", "leaf")
            for stem in stems:
                name = f"{stem}_{arch}.dll"
                assert (run / "inputs" / name).read_bytes() == (
                    fixtures / f"forwarded_implicit_{mode}" / name).read_bytes(), (case, name)
            assert summary["network_broker_complete"] is True, case
            journal = json.loads((run / "network-broker.json").read_text(encoding="utf-8"))
            assert journal[-1] == {"event": "broker_closed"}, case
            assert not summary.get("api_coverage", {}).get("signature_only_calls"), case
            if mode == "missing_reloc":
                assert summary["status"] == "failed", case
                assert any("Static companion relocation unavailable" in error
                           for error in summary["errors"]), case
                assert not summary.get("engine_report"), case
                assert not summary.get("artifacts"), case
                print(f"{case}: failed before guest entry; inputs and broker verified")
                continue
            assert verify_artifact_manifest(run, summary["artifacts"]), case
            report = json.loads((run / summary["engine_report"]).read_text(encoding="utf-8"))
            entries = report["entry_points"]
            types = [entry["ep_type"] for entry in entries]
            if mode == "failed_attach":
                assert summary["status"] == "partial", case
                assert types == [f"static_dll_entry_leaf_{arch}",
                                 f"static_dll_detach_leaf_{arch}"], case
                assert any("Static companion initialization failed" in error
                           for error in summary["errors"]), case
            else:
                assert summary["status"] == "completed" and not summary["errors"], case
                prefix = [f"static_dll_entry_terminal_{arch}"] if mode == "chain" else []
                assert types == [*prefix, f"static_dll_entry_leaf_{arch}",
                                 f"static_dll_entry_companion_{arch}", "module_entry"], case
                assert entries[-1]["ret_val"] == "0x2a", case
            print(f"{case}: {summary['status']}; inputs, entry order, artifacts, broker verified")

    for arch in ("x86", "x64"):
        for mode in ("valid", "chain"):
            case = f"lifecycle_{mode}_{arch}"
            summaries = list((root / case).glob("*/summary.json"))
            assert len(summaries) == 1, (case, summaries)
            run = summaries[0].parent
            summary = json.loads(summaries[0].read_text(encoding="utf-8"))
            sample = (fixtures / f"static_companion_lifecycle_{arch}.exe").read_bytes()
            assert (run / "input.pe").read_bytes() == sample, case
            assert summary["sample"]["sha256"] == hashlib.sha256(sample).hexdigest(), case
            stems = ("companion", "leaf", "terminal") if mode == "chain" else (
                "companion", "leaf")
            for stem in stems:
                name = f"{stem}_{arch}.dll"
                assert (run / "inputs" / name).read_bytes() == (
                    fixtures / f"forwarded_implicit_{mode}" / name).read_bytes(), (case, name)
            assert summary["status"] == "completed" and not summary["errors"], case
            assert summary["network_broker_complete"] is True, case
            journal = json.loads((run / "network-broker.json").read_text(encoding="utf-8"))
            assert journal[-1] == {"event": "broker_closed"}, case
            assert verify_artifact_manifest(run, summary["artifacts"]), case
            assert not summary["api_coverage"]["signature_only_calls"], case
            report = json.loads((run / summary["engine_report"]).read_text(encoding="utf-8"))
            entries = report["entry_points"]
            prefix = [f"static_dll_entry_terminal_{arch}"] if mode == "chain" else []
            assert [entry["ep_type"] for entry in entries] == [
                *prefix, f"static_dll_entry_leaf_{arch}",
                f"static_dll_entry_companion_{arch}", "module_entry"], case
            assert entries[-1]["ret_val"] == "0x2a", case
            events = summary["dll_initialization_events"]
            assert [event["event"] for event in events] == [
                "companion_dll_retain", "companion_dll_release",
                "companion_dll_release", "dll_process_detach",
                "companion_dll_unload", "dll_process_attach"], case
            assert events[2]["references"] == 1, case
            assert events[3]["module"] == events[5]["module"] == f"companion_{arch}", case
            print(f"{case}: completed; inputs, release, reload, artifacts, broker verified")


if __name__ == "__main__":
    verify(Path(sys.argv[1]).resolve())
