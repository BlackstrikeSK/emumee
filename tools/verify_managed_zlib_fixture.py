"""Verify packaged bounded zlib reads from a guest-only file."""

from __future__ import annotations

import hashlib
import json
import sys
import zlib
from pathlib import Path


def main(runs_root: Path) -> None:
    summaries = list(runs_root.glob("*/summary.json"))
    assert len(summaries) == 1, "expected one packaged ManagedZlib run"
    run_dir = summaries[0].parent
    summary = json.loads(summaries[0].read_text(encoding="utf-8"))
    report = json.loads((run_dir / "engine-report.json").read_text(encoding="utf-8"))
    assert summary["status"] == "completed" and not summary.get("errors")
    assert summary["engine"] == "emumee-cil" and summary["network_broker_complete"] is True
    plain = b"zlib guest payload verified!" + bytes(range(128))
    prefix = r"C:\Users\Alex\AppData\Roaming\emumee-zlib-DESKTOP-7F4M2Q9"
    expected = [
        (prefix + "-source.bin", zlib.compress(plain)),
        ("", plain),
        (prefix + "-payload.bin", plain),
        (prefix + "-state.txt", b"zlib-ok;partial-read;file;leave-open;invalid-catch"),
    ]
    recovered = []
    for item in summary["artifacts"]:
        payload = (run_dir / "artifacts" / item["file"]).read_bytes()
        assert len(payload) == item["size"]
        assert hashlib.sha256(payload).hexdigest() == item["sha256"]
        recovered.append((item["guest_path"], payload))
    assert recovered == expected
    assert summary["artifacts"][1]["source"] == "managed_zlib_decompress"
    events = report["events"]
    assert [event["format"] for event in events if event.get("event") == "managed_decompress"] == ["zlib"]
    assert sum(event.get("event") == "managed_compressed_stream_open" for event in events) == 2
    assert [event["type"] for event in events if event.get("event") == "managed_catch"] == [
        "System.IO.InvalidDataException"]
    assert summary["cil_coverage"] == report["cil_coverage"]
    print("packaged managed zlib: guest file, partial read, invalid catch, and hashes verified")


if __name__ == "__main__":
    main(Path(sys.argv[1]).resolve())
