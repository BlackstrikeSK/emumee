"""Verify packaged managed recursive delete and retained payload evidence."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
DEFAULT_RUNS = PROJECT / "output" / "managed-recursive-delete-package"


def main(runs_root: Path = DEFAULT_RUNS) -> None:
    summaries = list(runs_root.glob("*/summary.json"))
    assert len(summaries) == 1, "expected one packaged recursive-delete report"
    run_dir = summaries[0].parent
    summary = json.loads(summaries[0].read_text(encoding="utf-8"))
    report = json.loads((run_dir / "engine-report.json").read_text(encoding="utf-8"))
    assert summary["status"] == "completed"
    assert summary["engine"] == "emumee-cil"
    assert summary["network_broker_complete"] is True
    assert not summary["errors"]
    recovered = []
    for item in summary["artifacts"]:
        payload = (run_dir / "artifacts" / item["file"]).read_bytes()
        assert len(payload) == item["size"]
        assert hashlib.sha256(payload).hexdigest() == item["sha256"]
        recovered.append((item["guest_path"], payload))
    assert len(recovered) == 7
    assert [payload for path, payload in recovered
            if path.endswith("managed-tree-state.txt")] == [
                b"created", b"nonrecursive denied", b"tree deleted",
                b"missing denied", b"recreated"]
    assert (r"C:\Users\Alex\Downloads\managed-tree\nested\deeper\payload.txt",
            b"harmless recursive payload") in recovered
    assert (r"C:\Users\Alex\Downloads\managed-tree\recreated.txt",
            b"recreated guest file") in recovered
    deletes = [item for item in report["events"] if item.get("event") == "directory_delete"]
    assert len(deletes) == 1
    assert (deletes[0]["recursive"], deletes[0]["directories_removed"],
            deletes[0]["files_removed"], deletes[0]["bytes_removed"]) == (
                True, 3, 1, len(b"harmless recursive payload"))
    print("packaged managed recursive delete: guest tree and seven artifacts verified")


if __name__ == "__main__":
    main(Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else DEFAULT_RUNS)
