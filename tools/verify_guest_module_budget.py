"""Verify the packaged 32-module guest DLL limit with harmless x86/x64 PEs."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from emumee.reports import verify_artifact_manifest


def verify(root: Path) -> None:
    fixtures = Path(__file__).resolve().parents[1] / "tests" / "fixtures"
    for arch in ("x86", "x64"):
        case = f"guest_module_budget_{arch}"
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
        assert not report["errors"], case
        entries = report["entry_points"]
        assert len(entries) == 1 and not entries[0].get("error"), case
        api = entries[0]["events"]
        assert sum(str(item.get("api_name", "")).endswith("CopyFileW") for item in api) == 32, case
        assert sum(str(item.get("api_name", "")).endswith("LoadLibraryW") for item in api) == 33, case
        exits = [item for item in api if str(item.get("api_name", "")).endswith("ExitProcess")]
        assert len(exits) == 1 and exits[0]["args"] == ["0x2a"], case

        loads = [item for item in report["dll_initialization_events"]
                 if item["event"] == "virtual_dll_load"]
        assert len(loads) == 33, case
        mapped = [item for item in loads if item["mapped"]]
        assert len(mapped) == 32, case
        assert len({item["path"].lower() for item in mapped}) == 32, case
        assert len({item["base"] for item in mapped}) == 32, case
        assert mapped[0]["path"].lower().endswith("guest-stage.dll"), case
        assert all(item["path"].lower().endswith(f"budget-{index:02d}.dll")
                   for index, item in enumerate(mapped[1:])), case
        assert loads[-1]["mapped"] is False, case
        assert loads[-1]["reason"] == "guest DLL load budget exceeded", case
        assert loads[-1]["path"].lower().endswith("budget-31.dll"), case

        stage = submitted[0xA00:0x1000]
        expected_sha = hashlib.sha256(stage).hexdigest()
        embedded = [item for item in summary["artifacts"]
                    if item["source"] == "embedded_input@0xa00"]
        assert len(embedded) == 1, case
        assert embedded[0]["sha256"] == expected_sha, case
        assert (run / "artifacts" / embedded[0]["file"]).read_bytes() == stage, case
        recovered = [item for item in summary["artifacts"]
                     if item["source"] == "guest_dll_load"]
        assert len(recovered) == 32, case
        assert all(item["sha256"] == expected_sha and
                   (run / "artifacts" / item["file"]).read_bytes() == stage
                   for item in recovered), case
        print(f"{case}: 32 mapped; 33rd refused; guest exit 42; artifacts and broker verified")


if __name__ == "__main__":
    verify(Path(sys.argv[1]).resolve())
