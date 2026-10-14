"""Verify packaged guest-created DLL export-forwarder cases."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from emumee.reports import verify_artifact_manifest


def verify(root: Path) -> None:
    fixtures = Path(__file__).resolve().parents[1] / "tests" / "fixtures"
    for arch in ("x86", "x64"):
        for mode in ("valid", "missing_reloc", "failed_attach"):
            case = f"dropped_guest_forwarder_{mode}_{arch}"
            summaries = list((root / case).glob("*/summary.json"))
            assert len(summaries) == 1, (case, summaries)
            run = summaries[0].parent
            summary = json.loads(summaries[0].read_text(encoding="utf-8"))
            submitted = (fixtures / f"{case}.exe").read_bytes()
            assert (run / "input.pe").read_bytes() == submitted, case
            assert summary["sample"]["sha256"] == hashlib.sha256(submitted).hexdigest(), case
            assert summary["network_broker_complete"] is True, case
            journal = json.loads((run / "network-broker.json").read_text(encoding="utf-8"))
            assert journal[-1] == {"event": "broker_closed"}, case
            assert verify_artifact_manifest(run, summary["artifacts"]), case
            assert not summary["api_coverage"]["signature_only_calls"], case
            report = json.loads((run / summary["engine_report"]).read_text(encoding="utf-8"))
            entries = report["entry_points"]
            assert len(entries) == 1 and not entries[0].get("error"), case
            events = summary["dll_initialization_events"]
            assert [event["event"] for event in events[:2]] == [
                "virtual_dll_load", "dll_process_attach"], case
            assert events[0]["mapped"] and events[1]["success"], case

            def artifact_bytes(source: str) -> list[bytes]:
                return [(run / "artifacts" / item["file"]).read_bytes()
                        for item in summary["artifacts"] if item["source"] == source]

            stage, leaf = submitted[0xA00:0x1000], submitted[0x1000:0x1600]
            assert stage in artifact_bytes("embedded_input@0xa00"), case
            assert leaf in artifact_bytes("embedded_input@0x1000"), case
            assert stage in artifact_bytes("guest_dll_load"), case
            if mode == "missing_reloc":
                assert summary["status"] == "partial", case
                assert entries[0]["ret_val"] == "0x0", case
                assert len(events) == 2, case
                assert any("Forwarded guest DLL relocation unavailable" in error
                           for error in summary["errors"]), case
                assert leaf not in artifact_bytes("guest_dll_load"), case
            else:
                assert summary["status"] == "completed" and not summary["errors"], case
                assert leaf in artifact_bytes("guest_dll_load"), case
                assert events[2]["event"] == "dll_forwarder_map", case
                assert events[2]["required_by"] == "guest-stage", case
                assert events[0]["base"] != events[2]["base"], case
                if mode == "valid":
                    assert entries[0]["ret_val"] == "0x2a", case
                    assert [event["event"] for event in events[2:]] == [
                        "dll_forwarder_map", "dll_process_attach"], case
                    assert events[3]["success"], case
                else:
                    assert entries[0]["ret_val"] == "0x0", case
                    assert [event["event"] for event in events[2:]] == [
                        "dll_forwarder_map", "dll_process_attach", "dll_process_detach",
                        "dll_forwarder_load_failed"], case
                    assert events[3]["success"] is False, case
            print(f"{case}: {summary['status']}; inputs, artifacts, and broker verified")


if __name__ == "__main__":
    verify(Path(sys.argv[1]).resolve())
