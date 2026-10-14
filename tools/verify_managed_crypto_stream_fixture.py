"""Verify packaged guest-only CryptoStream read/write behavior."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


def main(runs_root: Path) -> None:
    summaries = list(runs_root.glob("*/summary.json"))
    assert len(summaries) == 1, "expected one packaged ManagedCryptoStream run"
    run_dir = summaries[0].parent
    summary = json.loads(summaries[0].read_text(encoding="utf-8"))
    report = json.loads((run_dir / "engine-report.json").read_text(encoding="utf-8"))
    assert summary["status"] == "completed" and not summary.get("errors")
    assert summary["engine"] == "emumee-cil" and summary["network_broker_complete"] is True
    prefix = r"C:\Users\Alex\AppData\Roaming\emumee-cryptostream-DESKTOP-7F4M2Q9"
    plain = b"managed aes streaming payload verified!"
    cipher = bytes.fromhex(
        "d6d020609ad1bee66948a5a8ad2b7a122feba8a998d05e66"
        "c9452bd7d449c923b0b713abbcbb146cf3a7ab917e1d0637")
    expected = [
        (prefix + "-read.bin", plain),
        (prefix + "-write.bin", cipher),
        (prefix + "-write-decrypt.bin", plain),
        (prefix + "-file.bin", plain[:32]),
        (prefix + "-file.bin", plain),
        (prefix + "-state.txt", b"cryptostream-ok;read;write;file;flush;leave-open"),
    ]
    recovered = []
    for item in summary["artifacts"]:
        payload = (run_dir / "artifacts" / item["file"]).read_bytes()
        assert len(payload) == item["size"]
        assert hashlib.sha256(payload).hexdigest() == item["sha256"]
        recovered.append((item["guest_path"], payload))
    assert recovered == expected
    events = report["events"]
    assert sum(event.get("event") == "managed_crypto_stream_open" for event in events) == 4
    assert sum(event.get("event") == "managed_crypto_stream_flush_final" for event in events) == 3
    assert sum(event.get("event") == "managed_crypto_stream_read_transform"
               for event in events) == 1
    assert [event["type"] for event in events if event.get("event") == "managed_catch"] == [
        "System.NotSupportedException"]
    assert summary["cil_coverage"] == report["cil_coverage"]
    print("packaged managed CryptoStream: read/write, guest file, catches, and hashes verified")


if __name__ == "__main__":
    main(Path(sys.argv[1]).resolve())
