"""Verify the harmless packaged guest-file concurrent-view matrix."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from emumee.native import _report_blob
from emumee.reports import verify_artifact_manifest


def verify(root: Path) -> None:
    fixtures = Path(__file__).resolve().parents[1] / "tests" / "fixtures"
    for arch, kind in ((arch, kind) for arch in ("x86", "x64")
                       for kind in ("mapped_file_coherent", "mapped_file_io_coherent")):
        case = f"{kind}_{arch}"
        expected = b"QRSTEFGH" if kind.endswith("io_coherent") else b"XYZ!EFGH"
        summaries = list((root / case).glob("*/summary.json"))
        assert len(summaries) == 1, (case, summaries)
        run = summaries[0].parent
        summary = json.loads(summaries[0].read_text(encoding="utf-8"))
        submitted = (fixtures / f"{case}.exe").read_bytes()
        assert (run / "input.pe").read_bytes() == submitted, case
        assert summary["sample"]["sha256"] == hashlib.sha256(submitted).hexdigest(), case
        assert summary["status"] == "completed" and not summary["errors"], case
        assert summary["network_broker_complete"] is True, case
        journal = json.loads((run / "network-broker.json").read_text(encoding="utf-8"))
        assert journal[-1] == {"event": "broker_closed"}, case
        assert verify_artifact_manifest(run, summary["artifacts"]), case
        assert not summary["api_coverage"]["signature_only_calls"], case
        report = json.loads((run / summary["engine_report"]).read_text(encoding="utf-8"))
        assert len(report["entry_points"]) == 1, case
        calls = report["entry_points"][0]["events"]
        maps = [event for event in calls
                if event.get("api_name") == "kernel32.MapViewOfFile"]
        assert len(maps) == 2 and all(event["ret_val"] != "0x0" for event in maps), case
        assert any(event.get("api_name") == "kernel32.ExitProcess"
                   and event.get("args") == ["0x1"] for event in calls), case
        if kind.endswith("io_coherent"):
            assert sum(event.get("api_name") == "kernel32.WriteFile"
                       and event.get("ret_val") == "0x1" for event in calls) == 2, case
        layout = report["entry_points"][0]["memory"]["layout"]
        views = [item for item in layout if item["tag"].startswith("api.MapViewOfFile.")]
        assert len(views) == 2 and all(item["is_free"] for item in views), case
        assert all(_report_blob(report["data"], item["data_ref"])[:8] == expected
                   for item in views), case
        artifacts = [item for item in summary["artifacts"]
                     if item["source"] == "virtual_file_final"
                     and item["guest_path"].endswith("mapped.bin")]
        assert len(artifacts) == 1, case
        assert (run / "artifacts" / artifacts[0]["file"]).read_bytes() == expected, case
        print(f"{case}: two coherent views, guest bytes, artifact, and broker verified")


if __name__ == "__main__":
    verify(Path(sys.argv[1]))
