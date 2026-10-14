"""Verify packaged guest-created DLL relocation and rejection fixtures."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from emumee.reports import verify_artifact_manifest


def verify(root: Path) -> None:
    fixtures = Path(__file__).resolve().parents[1] / "tests" / "fixtures"
    for arch in ("x86", "x64"):
        exe_base = 0x140000000 if arch == "x64" else 0x400000
        middle_base = 0x1A0000000 if arch == "x64" else 0x52000000
        for mode in ("valid", "missing", "bad_block"):
            for dependency in (False, True):
                stem = (f"dropped_guest_dependency_reloc_{mode}_{arch}" if dependency else
                        f"dropped_reloc_{mode}_{arch}")
                summaries = list((root / stem).glob("*/summary.json"))
                assert len(summaries) == 1, (stem, summaries)
                run = summaries[0].parent
                summary = json.loads(summaries[0].read_text(encoding="utf-8"))
                submitted = (fixtures / f"{stem}.exe").read_bytes()
                assert (run / "input.pe").read_bytes() == submitted, stem
                assert summary["sample"]["sha256"] == hashlib.sha256(submitted).hexdigest(), stem
                assert summary["network_broker_complete"] is True, stem
                journal = json.loads((run / "network-broker.json").read_text(encoding="utf-8"))
                assert journal[-1] == {"event": "broker_closed"}, stem
                assert verify_artifact_manifest(run, summary["artifacts"]), stem
                assert not summary["api_coverage"]["signature_only_calls"], stem
                report = json.loads((run / summary["engine_report"]).read_text(encoding="utf-8"))
                entries = report["entry_points"]
                assert len(entries) == 1 and not entries[0].get("error"), stem
                events = summary["dll_initialization_events"]
                assert events[0]["event"] == "virtual_dll_load", stem

                def artifact_bytes(source: str) -> list[bytes]:
                    return [(run / "artifacts" / item["file"]).read_bytes()
                            for item in summary["artifacts"] if item["source"] == source]

                primary = submitted[0xA00:0x1000]
                assert primary in artifact_bytes("embedded_input@0xa00"), stem
                if dependency:
                    leaf = submitted[0x1000:0x1600]
                    assert leaf in artifact_bytes("embedded_input@0x1000"), stem
                    assert events[0]["mapped"] and int(events[0]["base"], 16) == middle_base, stem
                else:
                    leaf = primary
                if mode == "valid":
                    assert summary["status"] == "completed" and not summary["errors"], stem
                    assert entries[0]["ret_val"] == "0x2a", stem
                    assert leaf in artifact_bytes("guest_dll_load"), stem
                    if dependency:
                        assert [event["event"] for event in events] == [
                            "virtual_dll_load", "dll_dependency_map",
                            "dll_process_attach", "dll_process_attach"], stem
                        assert int(events[1]["base"], 16) != middle_base, stem
                        assert events[2]["success"] and events[3]["success"], stem
                    else:
                        assert [event["event"] for event in events] == [
                            "virtual_dll_load", "dll_process_attach"], stem
                        assert events[0]["mapped"] and events[1]["success"], stem
                        assert int(events[0]["base"], 16) != exe_base, stem
                        assert events[0]["sha256"] == hashlib.sha256(leaf).hexdigest(), stem
                else:
                    assert entries[0]["ret_val"] == "0x0", stem
                    assert leaf not in artifact_bytes("guest_dll_load"), stem
                    if dependency:
                        assert summary["status"] == "partial", stem
                        assert [event["event"] for event in events] == [
                            "virtual_dll_load", "virtual_dll_load_failed"], stem
                        assert "cannot be mapped at preferred base" in events[1]["reason"], stem
                    else:
                        assert summary["status"] == "completed" and not summary["errors"], stem
                        assert len(events) == 1 and not events[0]["mapped"], stem
                        assert "cannot be mapped at preferred base" in events[0]["reason"], stem
                print(f"{stem}: {summary['status']}, ret {entries[0]['ret_val']}; "
                      "artifacts and broker verified")


if __name__ == "__main__":
    verify(Path(sys.argv[1]).resolve())
