"""Verify packaged managed temp path and current-directory isolation."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
DEFAULT_RUNS = PROJECT / "output" / "managed-paths-package"


def main(runs_root: Path = DEFAULT_RUNS) -> None:
    summaries = list(runs_root.glob("*/summary.json"))
    assert len(summaries) == 1, "expected one packaged managed paths report"
    run_dir = summaries[0].parent
    summary = json.loads(summaries[0].read_text(encoding="utf-8"))
    report = json.loads((run_dir / "engine-report.json").read_text(encoding="utf-8"))
    assert summary["status"] == "completed"
    assert summary["engine"] == "emumee-cil"
    assert summary["network_broker_complete"] is True
    assert not summary["errors"]
    assert summary["cil_coverage"] == report["cil_coverage"]
    recovered = set()
    for item in summary["artifacts"]:
        payload = (run_dir / "artifacts" / item["file"]).read_bytes()
        assert len(payload) == item["size"]
        assert hashlib.sha256(payload).hexdigest() == item["sha256"]
        recovered.add((item["guest_path"], payload))
    temp = "C:\\Users\\Alex\\AppData\\Local\\Temp\\"
    stage = temp + "emumee-stage"
    payload = b"harmless guest-relative marker"
    assert recovered == {
        ("relative.txt", payload),
        (r"C:\Users\Alex\Downloads\managed-temp-path.txt", temp.encode()),
        (r"C:\Users\Alex\Downloads\managed-env-temp.txt", temp.encode()),
        (r"C:\Users\Alex\Downloads\managed-current-dir.txt", stage.encode()),
        (r"C:\Users\Alex\Downloads\managed-relative-echo.txt", payload),
    }
    assert [event["path"] for event in report["events"]
            if event.get("event") == "current_directory"] == [
                stage, r"C:\Users\Alex\Downloads"]
    assert len([event for event in report["events"]
                if event.get("event") == "directory_delete"]) == 1
    print("packaged managed paths: guest temp, relative access, and artifacts verified")


if __name__ == "__main__":
    main(Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else DEFAULT_RUNS)
