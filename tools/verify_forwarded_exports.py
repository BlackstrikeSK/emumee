"""Check packaged x86/x64 companion export forwarding fixtures."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from emumee.reports import verify_artifact_manifest


def verify(root: Path) -> None:
    fixtures = Path(__file__).resolve().parents[1] / "tests" / "fixtures"
    for arch in ("x86", "x64"):
        for mode in ("name", "ordinal", "missing", "cycle"):
            for kind in ("static", "dynamic"):
                case = f"{kind}_{mode}_{arch}"
                summaries = list((root / case).glob("*/summary.json"))
                assert len(summaries) == 1, (case, summaries)
                run = summaries[0].parent
                summary = json.loads(summaries[0].read_text(encoding="utf-8"))
                source_dir = (fixtures / "static_chain" / f"forwarded_{mode}"
                              if kind == "static" else
                              fixtures / f"forwarded_dynamic_{mode}")
                sample_name = (f"static_companion_{arch}.exe" if kind == "static" else
                               f"checked_call_export_{arch}.exe")
                sample = (fixtures / sample_name).read_bytes()
                assert (run / "input.pe").read_bytes() == sample, case
                assert summary["sample"]["sha256"] == hashlib.sha256(sample).hexdigest(), case
                for stem in ("companion", "leaf"):
                    dll = f"{stem}_{arch}.dll"
                    assert (run / "inputs" / dll).read_bytes() == (source_dir / dll).read_bytes(), case
                assert summary["network_broker_complete"] is True, case
                journal = json.loads((run / "network-broker.json").read_text(encoding="utf-8"))
                assert journal[-1] == {"event": "broker_closed"}, case
                if summary["status"] != "failed":
                    assert verify_artifact_manifest(run, summary["artifacts"]), case
                else:
                    assert not summary.get("artifacts"), case
                assert not summary.get("api_coverage", {}).get("signature_only_calls"), case
                if kind == "static" and mode in ("missing", "cycle"):
                    assert summary["status"] == "failed", case
                    assert not summary.get("engine_report"), case
                else:
                    report = json.loads((run / summary["engine_report"]).read_text(
                        encoding="utf-8"))
                    entries = report["entry_points"]
                    assert entries and not any(entry.get("error") for entry in entries), case
                    if mode in ("name", "ordinal"):
                        assert summary["status"] == "completed" and not summary["errors"], case
                        assert entries[-1]["ret_val"] == "0x2a", case
                        if kind == "static":
                            assert [entry["ep_type"] for entry in entries] == [
                                f"static_dll_entry_leaf_{arch}",
                                f"static_dll_entry_companion_{arch}", "module_entry"], case
                        else:
                            assert [event["event"] for event in
                                    summary["dll_initialization_events"]] == [
                                "dll_dependency_map", "dll_process_attach",
                                "dll_process_attach"], case
                    else:
                        assert summary["status"] == "partial", case
                        assert len(entries) == 1 and entries[0]["ret_val"] == "0x0", case
                if mode in ("missing", "cycle"):
                    error = ("Forwarded DLL target not loaded" if mode == "missing" else
                             "Cyclic DLL export forwarder")
                    assert any(error in item for item in summary["errors"]), case
                print(f"{case}: {summary['status']}; submitted bytes, broker, "
                      "and artifacts verified")


if __name__ == "__main__":
    verify(Path(sys.argv[1]).resolve())
