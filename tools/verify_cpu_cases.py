"""Verify packaged x86/x64 CPU persona probes."""

from __future__ import annotations

import hashlib
import json
import sys
from itertools import product
from pathlib import Path

from emumee.reports import verify_artifact_manifest


def verify(root: Path) -> None:
    fixtures = Path(__file__).resolve().parents[1] / "tests" / "fixtures"
    for arch, family in product(("x86", "x64"),
                                ("cpuid_identity_check", "processor_feature_check",
                                 "tsc_sleep_check",
                                 "memory_persona_check")):
        case = f"{family}_{arch}"
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
        if family == "tsc_sleep_check":
            assert any(item.get("api_name") == "kernel32.Sleep"
                       for item in events), case
        if family == "memory_persona_check":
            assert any(item.get("api_name") == "kernel32.GlobalMemoryStatusEx"
                       for item in events), case
        if family == "processor_feature_check":
            queries = [item for item in events if item.get("api_name") ==
                       "kernel32.IsProcessorFeaturePresent"]
            assert len(queries) == 8, case
        assert len([item for item in events
                    if item.get("api_name") == "kernel32.ExitProcess"]) == 1, case
        assert any(item.get("api_name") == "kernel32.ExitProcess"
                   and item.get("args") == ["0x1"] for item in events), case
        print(f"{case}: CPU branch, exact input, artifacts, and broker verified")


if __name__ == "__main__":
    verify(Path(sys.argv[1]))
