"""Verify packaged Path.GetFullPath guest current-directory behavior."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


def main(runs_root: Path) -> None:
    summaries = list(runs_root.glob("*/summary.json"))
    assert len(summaries) == 1, "expected one packaged ManagedFullPath run"
    run_dir = summaries[0].parent
    summary = json.loads(summaries[0].read_text(encoding="utf-8"))
    report = json.loads((run_dir / "engine-report.json").read_text(encoding="utf-8"))
    assert summary["status"] == "completed" and not summary.get("errors")
    assert summary["engine"] == "emumee-cil" and summary["network_broker_complete"] is True
    roaming = r"C:\Users\Alex\AppData\Roaming"
    tag = "emumee-full-DESKTOP-7F4M2Q9"
    expected = {
        roaming + "\\" + tag + ".bin": b"guest-full-path-payload",
        roaming + "\\" + tag + "-state.txt": b"full-path-ok;null;empty;base",
    }
    recovered = {}
    for item in summary["artifacts"]:
        payload = (run_dir / "artifacts" / item["file"]).read_bytes()
        assert len(payload) == item["size"]
        assert hashlib.sha256(payload).hexdigest() == item["sha256"]
        recovered[item["guest_path"]] = payload
    assert recovered == expected
    assert sum(event.get("event") == "current_directory"
               for event in report["events"]) == 2
    assert [event["type"] for event in report["events"]
            if event.get("event") == "managed_catch"] == [
                "System.ArgumentNullException", "System.ArgumentException",
                "System.ArgumentException"]
    assert sum(event.get("event") == "managed_call" and
               event.get("method") == "System.IO.Path.GetFullPath"
               for event in report["events"]) >= 7
    assert summary["cil_coverage"] == report["cil_coverage"]
    print("packaged managed full path: guest cwd, catches, and hashes verified")


if __name__ == "__main__":
    main(Path(sys.argv[1]).resolve())
