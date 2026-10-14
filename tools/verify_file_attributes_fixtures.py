"""Verify packaged guest attribute mutation and exact extracted file bytes."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


DEFAULT_OUTPUT = Path(__file__).resolve().parents[1] / "output" / "file-attributes-package"


def main(output: Path = DEFAULT_OUTPUT) -> None:
    for arch in ("x86", "x64"):
        for suffix in ("", "_a"):
            for by_handle in (False, True):
                name = f"{'file_basic_info' if by_handle else 'file_attributes'}{suffix}_{arch}"
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
                changes = [event for event in engine["virtual_file_events"]
                           if event["event"] == ("virtual_file_basic_info" if by_handle else
                                                 "virtual_file_set_attributes")]
                assert len(changes) == 1 and changes[0]["attributes"] == 3, name
                if by_handle:
                    assert changes[0]["times"][0] == 0x12345678, name
                else:
                    assert changes[0]["success"], name
                attrs = [event for event in engine["virtual_file_events"]
                         if event["event"] == "virtual_file_attributes"]
                extended = [event for event in engine["virtual_file_events"]
                            if event["event"] == "virtual_file_attributes_ex"]
                assert len(attrs) == len(extended) == 1, name
                assert attrs[0]["attributes"] == 3, name
                assert (extended[0]["attributes"], extended[0]["size"]) == (3, 8), name
                payloads = [item for item in summary["artifacts"]
                            if item["guest_path"].endswith("metadata.bin")]
                assert any((content := (run_dir / "artifacts" / item["file"]).read_bytes())
                           == b"ABCDEFGH" and item["size"] == len(content)
                           and item["sha256"] == hashlib.sha256(content).hexdigest()
                           for item in payloads), name
                print(f"{name}: completed, attributes 3, size 8, payload verified")


if __name__ == "__main__":
    main(Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else DEFAULT_OUTPUT)
