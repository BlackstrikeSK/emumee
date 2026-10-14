"""Verify packaged CIL copy/move side effects and recovered guest bytes."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
DEFAULT_RUNS = PROJECT / "output" / "managed-transfer-package"


def main(runs_root: Path = DEFAULT_RUNS) -> None:
    summaries = list(runs_root.glob("*/summary.json"))
    assert len(summaries) == 1, "expected one packaged managed transfer report"
    run_dir = summaries[0].parent
    summary = json.loads(summaries[0].read_text(encoding="utf-8"))
    report = json.loads((run_dir / "engine-report.json").read_text(encoding="utf-8"))
    assert summary["status"] == "completed"
    assert summary["engine"] == "emumee-cil"
    assert summary["network_broker_complete"] is True
    assert not summary["errors"]
    assert summary["cil_coverage"] == report["cil_coverage"]
    recovered = []
    for item in summary["artifacts"]:
        payload = (run_dir / "artifacts" / item["file"]).read_bytes()
        assert len(payload) == item["size"]
        assert hashlib.sha256(payload).hexdigest() == item["sha256"]
        recovered.append((item["source"], item["guest_path"], payload))
    assert len(recovered) == 9
    assert ("managed_file_copy", r"C:\Users\Alex\Downloads\managed-copy.txt",
            b"Personal notes\n") in recovered
    assert ("managed_file_move", r"C:\Users\Alex\Downloads\managed-target.txt",
            b"Personal notes\n") in recovered
    assert ("managed_file_write", r"C:\Users\Alex\Downloads\managed-transfer-output.txt",
            b"Personal notes\n") in recovered
    assert [payload for _, path, payload in recovered
            if path.endswith("managed-transfer-state.txt")] == [
                b"copy collision", b"move collision", b"transferred"]
    copies = [event for event in report["events"] if event.get("event") == "file_copy"]
    moves = [event for event in report["events"] if event.get("event") == "file_move"]
    assert len(copies) == 2 and len(moves) == 3
    assert copies[1]["overwrite"] is True
    assert moves[1]["overwrite"] is True
    assert moves[2]["same_file"] is True
    print("packaged managed transfer: collisions, overwrite, move, and artifacts verified")


if __name__ == "__main__":
    main(Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else DEFAULT_RUNS)
