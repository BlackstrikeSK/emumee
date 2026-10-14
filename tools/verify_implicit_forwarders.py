"""Verify packaged forwarders that load supplied DLL targets on demand."""

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
            for lifecycle in ((False, True) if mode in ("valid", "chain") else (False,)):
                case = f"{'lifecycle_' if lifecycle else ''}{mode}_{arch}"
                summaries = list((root / case).glob("*/summary.json"))
                assert len(summaries) == 1, (case, summaries)
                run = summaries[0].parent
                summary = json.loads(summaries[0].read_text(encoding="utf-8"))
                sample_name = (f"companion_lifecycle_{arch}.exe" if lifecycle else
                               f"checked_call_export_{arch}.exe")
                submitted = (fixtures / sample_name).read_bytes()
                assert (run / "input.pe").read_bytes() == submitted, case
                assert summary["sample"]["sha256"] == hashlib.sha256(submitted).hexdigest(), case
                stems = ("companion", "leaf", "terminal") if mode == "chain" else (
                    "companion", "leaf")
                source_dir = fixtures / f"forwarded_implicit_{mode}"
                for stem in stems:
                    dll = f"{stem}_{arch}.dll"
                    assert (run / "inputs" / dll).read_bytes() == (
                        source_dir / dll).read_bytes(), (case, dll)
                assert summary["network_broker_complete"] is True, case
                journal = json.loads((run / "network-broker.json").read_text(encoding="utf-8"))
                assert journal[-1] == {"event": "broker_closed"}, case
                assert verify_artifact_manifest(run, summary["artifacts"]), case
                assert not summary["api_coverage"]["signature_only_calls"], case
                report = json.loads((run / summary["engine_report"]).read_text(encoding="utf-8"))
                entries = report["entry_points"]
                assert len(entries) == 1 and not entries[0].get("error"), case
                events = summary["dll_initialization_events"]
                if mode in ("valid", "chain"):
                    assert summary["status"] == "completed" and not summary["errors"], case
                    assert entries[0]["ret_val"] == "0x2a", case
                    expected = ([f"leaf_{arch}"] if mode == "valid" else
                                [f"leaf_{arch}", f"terminal_{arch}"])
                    maps = [event for event in events if event["event"] == "dll_forwarder_map"]
                    attaches = [event for event in events if event["event"] == "dll_process_attach"]
                    multiplier = 2 if lifecycle else 1
                    assert [event["module"] for event in maps] == expected * multiplier, case
                    assert all(event["success"] for event in attaches), case
                    assert [event["module"] for event in attaches[:len(stems)]] == [
                        f"companion_{arch}", *reversed(expected)], case
                    assert len({event["base"] for event in attaches[:len(stems)]}) == len(stems), case
                    if lifecycle:
                        detached = [event["module"] for event in events
                                    if event["event"] == "dll_process_detach"]
                        assert detached == [f"{stem}_{arch}" for stem in stems], case
                elif mode == "missing_reloc":
                    assert summary["status"] == "partial", case
                    assert entries[0]["ret_val"] == "0x0", case
                    assert any("Forwarded DLL relocation unavailable" in error
                               for error in summary["errors"]), case
                    assert [event["event"] for event in events] == ["dll_process_attach"], case
                else:
                    assert summary["status"] == "completed" and not summary["errors"], case
                    assert entries[0]["ret_val"] == "0x0", case
                    assert [event["event"] for event in events] == [
                        "dll_process_attach", "dll_forwarder_map", "dll_process_attach",
                        "dll_process_detach", "dll_forwarder_load_failed"], case
                    assert events[2]["success"] is False, case
                print(f"{case}: {summary['status']}; inputs, artifacts, and broker verified")


if __name__ == "__main__":
    verify(Path(sys.argv[1]).resolve())
