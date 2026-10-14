"""Verify packaged FileDispositionInfo mark and cancel guest behavior."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


DEFAULT_OUTPUT = Path(__file__).resolve().parents[1] / "output" / "file-disposition-package"


def main(output: Path = DEFAULT_OUTPUT) -> None:
    for arch in ("x86", "x64"):
        for mode in ("mark", "cancel", "exit"):
            cancel = mode == "cancel"
            name = f"file_disposition{'_' + mode if mode != 'mark' else ''}_{arch}"
            reports = list((output / name).glob("*/summary.json"))
            assert len(reports) == 1, f"{name}: expected one report"
            run_dir = reports[0].parent
            summary = json.loads(reports[0].read_text(encoding="utf-8"))
            engine = json.loads((run_dir / summary["engine_report"]).read_text(encoding="utf-8"))
            assert summary["status"] == "completed", name
            assert summary["network_broker_complete"] is True, name
            assert not summary["errors"], name
            assert not summary["api_coverage"]["signature_only_calls"], name
            assert any(event.get("api_name") == "kernel32.ExitProcess"
                       and event.get("args") == ["0x1"]
                       for entry in engine["entry_points"]
                       for event in entry["events"]), name
            marks = [event for event in engine["virtual_file_events"]
                     if event["event"] == "virtual_file_disposition"]
            assert [event["delete"] for event in marks] == ([True, False] if cancel else [True]), name
            deleted = [event for event in engine["virtual_file_events"]
                       if event["event"] == "virtual_file_disposition_delete"]
            assert len(deleted) == (0 if cancel else 1), name
            if deleted:
                assert deleted[0]["exists_after"] is False, name
                assert (deleted[0]["handle"] is None) == (mode == "exit"), name
            matching = [item for item in summary["artifacts"]
                        if item["source"] == "virtual_file_disposition_delete"]
            assert len(matching) == (0 if cancel else 1), name
            assert any((content := (run_dir / "artifacts" / item["file"]).read_bytes()) == b"OLD!"
                       and item["size"] == len(content)
                       and item["sha256"] == hashlib.sha256(content).hexdigest()
                       for item in summary["artifacts"]), name
            print(f"{name}: completed, guest exit 1, mark/cancel and payload verified")


if __name__ == "__main__":
    main(Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else DEFAULT_OUTPUT)
