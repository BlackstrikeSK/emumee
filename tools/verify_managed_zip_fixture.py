"""Verify packaged managed ZIP extraction stays in the guest file map."""

from __future__ import annotations

import hashlib
import io
import json
import sys
import zipfile
from pathlib import Path


def main(runs_root: Path) -> None:
    summaries = list(runs_root.glob("*/summary.json"))
    assert len(summaries) == 1, "expected one packaged ManagedZip run"
    run_dir = summaries[0].parent
    summary = json.loads(summaries[0].read_text(encoding="utf-8"))
    report = json.loads((run_dir / "engine-report.json").read_text(encoding="utf-8"))
    assert summary["status"] == "completed" and not summary.get("errors")
    assert summary["engine"] == "emumee-cil" and summary["network_broker_complete"] is True
    prefix = r"C:\Users\Alex\AppData\Roaming\emumee-zip-DESKTOP-7F4M2Q9"
    recovered = []
    for item in summary["artifacts"]:
        payload = (run_dir / "artifacts" / item["file"]).read_bytes()
        assert len(payload) == item["size"]
        assert hashlib.sha256(payload).hexdigest() == item["sha256"]
        recovered.append((item["guest_path"], payload))
    assert [path for path, _ in recovered] == [
        prefix + "-source.zip", prefix + r"\payload.bin",
        prefix + r"\nested\readme.txt",
        prefix + r"-memory\payload.bin", prefix + r"-memory\nested\readme.txt",
        prefix + r"-filestream\payload.bin", prefix + r"-filestream\nested\readme.txt",
        prefix + "-bad.zip", prefix + "-malformed.zip",
        prefix + "-state.txt"]
    assert recovered[1][1] == b"zip guest payload verified!"
    assert recovered[2][1] == b"nested guest file"
    assert recovered[3][1] == recovered[5][1] == recovered[1][1]
    assert recovered[4][1] == recovered[6][1] == recovered[2][1]
    assert recovered[9][1] == b"zip-ok;nested;overwrite;streams;traversal-denied;malformed-denied"
    with zipfile.ZipFile(io.BytesIO(recovered[0][1])) as archive:
        assert archive.namelist() == ["payload.bin", "nested/readme.txt"]
        assert archive.read("payload.bin") == recovered[1][1]
        assert archive.read("nested/readme.txt") == recovered[2][1]
    with zipfile.ZipFile(io.BytesIO(recovered[7][1])) as archive:
        assert archive.namelist() == ["../escape.bin"]
    malformed = bytearray(recovered[0][1])
    end = malformed.rfind(b"PK\x05\x06")
    malformed[end + 8:end + 12] = b"\x01\x00\x01\x00"
    assert recovered[8][1] == malformed
    events = report["events"]
    assert [event["entries"] for event in events
            if event.get("event") == "managed_zip_preflight"] == [2, 2, 2, 2, 2, 1]
    assert [event["files"] for event in events if event.get("event") == "managed_zip_extract"] == [2, 2, 2, 2]
    assert [event["type"] for event in events if event.get("event") == "managed_catch"] == [
        "System.IO.IOException", "System.IO.IOException",
        "System.IO.InvalidDataException"]
    assert summary["cil_coverage"] == report["cil_coverage"]
    print("packaged managed ZIP: guest paths, overwrite, traversal denial, and hashes verified")


if __name__ == "__main__":
    main(Path(sys.argv[1]).resolve())
