"""Check packaged delete-on-close fixtures and recovered temporary bytes."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


DEFAULT_OUTPUT = Path(__file__).resolve().parents[1] / "output" / "delete-on-close-package"


def main(output: Path = DEFAULT_OUTPUT) -> None:
    names = [f"delete_on_close{suffix}_{arch}"
             for arch in ("x86", "x64") for suffix in ("", "_a")]
    names += [f"delete_on_{mode}_{arch}"
              for arch in ("x86", "x64") for mode in ("exit", "create")]
    for name in names:
        reports = list((output / name).glob("*/summary.json"))
        assert len(reports) == 1, f"{name}: expected one packaged report"
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
        deleted = [event for event in engine["virtual_file_events"]
                   if event["event"] == "virtual_file_delete_on_close"]
        assert len(deleted) == 1 and deleted[0]["exists_after"] is False, name
        assert (deleted[0]["handle"] is None) == ("_exit_" in name), name
        matches = [item for item in summary["artifacts"]
                   if item["source"] == "virtual_file_delete_on_close"]
        assert len(matches) == 1, name
        item = matches[0]
        content = (run_dir / "artifacts" / item["file"]).read_bytes()
        assert content == b"OLD!", name
        assert item["size"] == len(content), name
        assert item["sha256"] == hashlib.sha256(content).hexdigest(), name
        print(f"{name}: completed, guest exit 1, deleted name, extracted {content!r}")


if __name__ == "__main__":
    main(Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else DEFAULT_OUTPUT)
