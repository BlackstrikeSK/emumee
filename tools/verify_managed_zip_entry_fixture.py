"""Verify packaged ZipArchive entry reads remain in the guest model."""

from __future__ import annotations

import hashlib
import io
import json
import sys
import zipfile
from pathlib import Path


def main(runs_root: Path) -> None:
    summaries = list(runs_root.glob("*/summary.json"))
    assert len(summaries) == 1, "expected one packaged ManagedZipEntry run"
    run_dir = summaries[0].parent
    summary = json.loads(summaries[0].read_text(encoding="utf-8"))
    report = json.loads((run_dir / "engine-report.json").read_text(encoding="utf-8"))
    assert summary["status"] == "completed" and not summary.get("errors")
    assert summary["engine"] == "emumee-cil" and summary["network_broker_complete"] is True
    prefix = r"C:\Users\Alex\AppData\Roaming\emumee-zipentry-DESKTOP-7F4M2Q9"
    actual = []
    for item in summary["artifacts"]:
        payload = (run_dir / "artifacts" / item["file"]).read_bytes()
        assert len(payload) == item["size"]
        assert hashlib.sha256(payload).hexdigest() == item["sha256"]
        actual.append((item["source"], item.get("guest_path", ""), payload))
    assert len(actual) == 5
    assert actual[0][1] == prefix + ".zip"
    with zipfile.ZipFile(io.BytesIO(actual[0][2])) as archive:
        assert archive.namelist() == ["payload.bin", "nested/readme.txt"]
        assert archive.read("payload.bin") == b"zip guest payload verified!"
    assert [payload for source, _, payload in actual if source == "managed_zip_entry_open"] == [
        b"zip guest payload verified!", b"nested guest file"]
    assert any(path == prefix + "-selected.bin" and payload == b"zip guest payload verified!"
               for _, path, payload in actual)
    assert any(path == prefix + "-state.txt" and payload == b"zip-entry-ok"
               for _, path, payload in actual)
    events = report["events"]
    assert [event["entries"] for event in events
            if event.get("event") == "managed_zip_preflight"] == [2, 2]
    assert [event["name"] for event in events
            if event.get("event") == "managed_zip_entry_open"] == [
                "payload.bin", "nested/readme.txt"]
    called = [event["method"] for event in events if event.get("event") == "managed_call"]
    for method in ("get_Entries", "get_Count", "get_Item", "GetEnumerator",
                   "MoveNext", "get_Current"):
        assert any(name.endswith(method) for name in called), method
    assert summary["cil_coverage"] == report["cil_coverage"]
    print("packaged managed ZIP entries: guest streams and hashes verified")


if __name__ == "__main__":
    main(Path(sys.argv[1]).resolve())
