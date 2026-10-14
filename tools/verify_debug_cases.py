"""Verify harmless packaged debugger-query consistency and handle checks."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from emumee.reports import verify_artifact_manifest


def verify(root: Path) -> None:
    fixtures = Path(__file__).resolve().parents[1] / "tests" / "fixtures"
    kinds = ("remote_debug_check", "is_debugger_present", "peb_debug_check", "nt_debug_port",
             "nt_debug_object", "nt_debug_flags")
    nt_classes = {"nt_debug_port": (7, 0),
                  "nt_debug_object": (30, 0xC0000353),
                  "nt_debug_flags": (31, 0)}
    for arch in ("x86", "x64"):
        for kind in kinds:
            case = f"{kind}_{arch}"
            summaries = list((root / case).glob("*/summary.json"))
            assert len(summaries) == 1, (case, summaries)
            run = summaries[0].parent
            summary = json.loads(summaries[0].read_text(encoding="utf-8"))
            submitted = (fixtures / f"{case}.exe").read_bytes()
            assert (run / "input.pe").read_bytes() == submitted, case
            assert summary["sample"]["sha256"] == hashlib.sha256(submitted).hexdigest(), case
            assert summary["status"] == "completed" and not summary["errors"], case
            assert not summary["api_coverage"]["signature_only_calls"], case
            assert verify_artifact_manifest(run, summary["artifacts"]), case
            assert summary["network_broker_complete"] is True, case
            journal = json.loads((run / "network-broker.json").read_text(encoding="utf-8"))
            assert journal[-1] == {"event": "broker_closed"}, case
            report = json.loads((run / summary["engine_report"]).read_text(encoding="utf-8"))
            entries = report["entry_points"]
            assert len(entries) == 1, case
            if kind in nt_classes:
                assert entries[0]["ret_val"] == "0x1", case
                information_class, status = nt_classes[kind]
                events = [item for item in report["virtual_process_events"]
                          if item["event"] == "virtual_nt_process_debug_query"]
                assert len(events) == 1, case
                assert events[0]["information_class"] == information_class, case
                assert events[0]["status"] == status, case
                assert events[0]["debugger_present"] is False, case
            else:
                exits = [item for item in entries[0]["events"]
                         if item.get("api_name") == "kernel32.ExitProcess"]
                assert len(exits) == 1 and exits[0]["args"] == ["0x1"], case
                if kind == "remote_debug_check":
                    checks = [item for item in report["virtual_process_events"]
                              if item["event"] == "virtual_debugger_check"]
                    assert [item["success"] for item in checks] == [True, False], case
                elif kind == "is_debugger_present":
                    checks = [item for item in report["virtual_process_events"]
                              if item["event"] == "virtual_debugger_check"]
                    assert len(checks) == 1 and checks[0]["debugger_present"] is False, case
            print(f"{case}: no-debugger branch, exact input, artifacts, and broker verified")


if __name__ == "__main__":
    verify(Path(sys.argv[1]))
