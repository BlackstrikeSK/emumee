"""Verify harmless packaged x86/x64 VirtualFreeEx release probes."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from emumee.reports import verify_artifact_manifest


def verify(root: Path) -> None:
    for arch in ("x86", "x64"):
        summaries = list((root / arch).glob("*/summary.json"))
        assert len(summaries) == 1, (arch, summaries)
        run = summaries[0].parent
        summary = json.loads(summaries[0].read_text(encoding="utf-8"))
        report = json.loads((run / summary["engine_report"]).read_text(encoding="utf-8"))
        broker = json.loads((run / "network-broker.json").read_text(encoding="utf-8"))
        assert summary["status"] == "completed" and not summary.get("errors"), arch
        assert summary["network_broker_complete"] is True, arch
        assert verify_artifact_manifest(run, summary["artifacts"]), arch
        assert broker[-1] == {"event": "broker_closed"}, arch
        entries = report["entry_points"]
        assert len(entries) == 1 and not entries[0].get("error"), arch
        exits = [event for event in entries[0]["events"]
                 if event.get("api_name") == "kernel32.ExitProcess"]
        assert len(exits) == 1 and exits[0]["args"] == ["0x1"], arch
        allocations = [event for event in report["virtual_process_events"]
                       if event["event"] == "virtual_process_allocate"]
        assert len(allocations) == 1 and allocations[0]["success"], arch
        frees = [event for event in report["virtual_process_events"]
                 if event["event"] == "virtual_process_free"]
        assert [event["success"] for event in frees] == [False, True, False], arch
        assert [event["size"] for event in frees] == [1, 0, 0], arch
        assert all(event["address"] == allocations[0]["address"] for event in frees), arch
        assert frees[2]["reason"] == "address is not a live virtual allocation base", arch
        released_maps = [mapping for mapping in entries[0]["memory"]["layout"]
                         if mapping["address"] == f'0x{allocations[0]["address"]:x}']
        assert len(released_maps) == 1 and released_maps[0]["is_free"] is True, arch
        assert not summary["api_coverage"]["signature_only_calls"], arch
        print(f"{arch}: packaged allocation release, duplicate denial, and broker closure verified")


if __name__ == "__main__":
    verify(Path(sys.argv[1]).resolve())
