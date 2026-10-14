"""Verify packaged version-comparison branches and isolation artifacts."""

from __future__ import annotations

import hashlib
import json
import sys
from itertools import product
from pathlib import Path

from emumee.reports import verify_artifact_manifest


def verify(root: Path) -> None:
    fixtures = Path(__file__).resolve().parents[1] / "tests" / "fixtures"
    required = {"kernel32.VerSetConditionMask", "kernel32.VerifyVersionInfoW",
                "ntdll.RtlVerifyVersionInfo", "kernel32.ExitProcess"}
    for arch, compatibility in product(("x86", "x64"),
                                       ("none", "win81", "win10")):
        case = f"version_verify_{compatibility}_{arch}"
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
        events = entries[0]["events"]
        names = {event.get("api_name") for event in events}
        assert required <= names, (case, names)
        verify_events = [event for event in events if event.get("api_name") ==
                         "kernel32.VerifyVersionInfoW"]
        rtl_events = [event for event in events if event.get("api_name") ==
                      "ntdll.RtlVerifyVersionInfo"]
        assert len(verify_events) == len(rtl_events) == 2, case
        assert verify_events[0]["ret_val"] == (
            "0x1" if compatibility == "win10" else "0x0"), case
        assert verify_events[1]["ret_val"] == "0x0", case
        assert rtl_events[0]["ret_val"] == "0x0", case
        assert rtl_events[1]["ret_val"].lower() == "0xc0000059", case
        exits = [event for event in events if event.get("api_name") ==
                 "kernel32.ExitProcess"]
        assert len(exits) == 1 and exits[0].get("args") == ["0x1"], case
        print(f"{case}: comparison branches, exact input, artifacts, and broker verified")


if __name__ == "__main__":
    verify(Path(sys.argv[1]))
