"""Verify packaged harmless AVX store probes and isolation artifacts."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from emumee.reports import verify_artifact_manifest


def verify(root: Path) -> None:
    fixtures = Path(__file__).resolve().parents[1] / "tests" / "fixtures"
    expected = {"vinsertf128": 1, "vmovdqa": 1,
                "vmovdqu": 1, "vzeroupper": 1}
    for arch in ("x86", "x64"):
        case = f"avx_fallback_check_{arch}"
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
        assert report["avx_fallback_counts"] == expected, case
        entries = report["entry_points"]
        assert len(entries) == 1, case
        exits = [event for event in entries[0]["events"] if event.get("api_name") ==
                 "kernel32.ExitProcess"]
        assert len(exits) == 1 and exits[0].get("args") == ["0x1"], case
        print(f"{case}: AVX branch, exact input, artifacts, and broker verified")


if __name__ == "__main__":
    verify(Path(sys.argv[1]))
