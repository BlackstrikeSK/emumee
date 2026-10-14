"""Verify packaged handle-based guest rename and exact recovered bytes."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


DEFAULT_OUTPUT = Path(__file__).resolve().parents[1] / "output" / "file-rename-info-package"


def main(output: Path = DEFAULT_OUTPUT) -> None:
    for arch in ("x86", "x64"):
        for suffix in ("", "_a"):
            name = f"file_rename_info{suffix}_{arch}"
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
            renames = [event for event in engine["virtual_file_events"]
                       if event["event"] == "virtual_file_rename_by_handle"]
            assert len(renames) == 1, name
            event = renames[0]
            assert event["success"] and event["new_exists_after"], name
            assert not event["old_exists_after"], name
            assert event["old_path"].endswith("resized.bin"), name
            assert event["new_path"].endswith("renamed.bin"), name
            payloads = [item for item in summary["artifacts"]
                        if item["source"] == "virtual_file_rename_by_handle"
                        and item["guest_path"].endswith("renamed.bin")]
            assert any((content := (run_dir / "artifacts" / item["file"]).read_bytes())
                       == b"ABCDEFGH" and item["size"] == len(content)
                       and item["sha256"] == hashlib.sha256(content).hexdigest()
                       for item in payloads), name
            print(f"{name}: completed, guest exit 1, handle rename and payload verified")


if __name__ == "__main__":
    main(Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else DEFAULT_OUTPUT)
