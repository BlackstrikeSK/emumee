"""Verify harmless packaged registry lifetime and payload cases."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from emumee.reports import verify_artifact_manifest


def verify(root: Path) -> None:
    fixtures = Path(__file__).resolve().parents[1] / "tests" / "fixtures"
    marker = b"BLUE_TEAM_REGISTRY_MARKER"
    for arch in ("x86", "x64"):
        for kind in ("registry", "registry_a", "registry_key",
                     "registry_key_a", "registry_key_exit"):
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
            assert any(event.get("api_name") == "kernel32.ExitProcess"
                       and event.get("args") == ["0x1"]
                       for event in entries[0]["events"]), case
            events = report["virtual_registry_events"]
            assert events[-1]["event"] == "virtual_registry_process_cleanup", case
            assert events[-1]["success"] is True, case
            assert events[-1]["handles"] == int(kind == "registry_key_exit"), case
            if kind.startswith("registry_key"):
                expected = [0, 0, 0, 0, 2]
                if kind != "registry_key_exit":
                    expected.append(0)
                assert [event["status"] for event in events[:-1]] == expected, case
            else:
                assert [event["status"] for event in events[:-1]] == [0, 0], case
                payloads = [item for item in summary["artifacts"]
                            if item["source"] == "registry_value"]
                assert len(payloads) == 1, case
                assert (run / "artifacts" / payloads[0]["file"]).read_bytes() == marker, case
            print(f"{case}: registry events, cleanup, artifacts, and broker verified")


if __name__ == "__main__":
    verify(Path(sys.argv[1]))
