"""Verify packaged PBKDF2 and AES payload recovery through guest-only storage."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


def main(runs_root: Path) -> None:
    summaries = list(runs_root.glob("*/summary.json"))
    assert len(summaries) == 1, "expected one packaged ManagedPbkdf2 run"
    run_dir = summaries[0].parent
    summary = json.loads(summaries[0].read_text(encoding="utf-8"))
    report = json.loads((run_dir / "engine-report.json").read_text(encoding="utf-8"))
    assert summary["status"] == "completed" and not summary.get("errors")
    assert summary["engine"] == "emumee-cil" and summary["network_broker_complete"] is True
    prefix = r"C:\Users\Alex\AppData\Roaming\emumee-pbkdf2-DESKTOP-7F4M2Q9"
    expected = [
        (prefix + "-payload.bin", b"PBKDF2 AES guest payload verified!"),
        (prefix + "-state.txt", b"pbkdf2-ok;sha1;sha256;reset;oneshot;catch"),
    ]
    recovered = []
    for item in summary["artifacts"]:
        payload = (run_dir / "artifacts" / item["file"]).read_bytes()
        assert len(payload) == item["size"]
        assert hashlib.sha256(payload).hexdigest() == item["sha256"]
        recovered.append((item["guest_path"], payload))
    assert recovered == expected
    events = report["events"]
    derivations = [event for event in events if event.get("event") == "managed_pbkdf2"]
    assert [event["hash"] for event in derivations] == [
        "SHA256", "SHA256", "SHA1", "SHA1", "SHA1", "SHA256"]
    assert [event["type"] for event in events if event.get("event") == "managed_catch"] == [
        "System.ArgumentOutOfRangeException"]
    assert not any("blue-team-fixture" in str(event) for event in events
                   if event.get("method", "").startswith(
                       "System.Security.Cryptography.Rfc2898DeriveBytes."))
    assert summary["cil_coverage"] == report["cil_coverage"]
    print("packaged managed PBKDF2: AES payload, continuation, reset, catch, and hashes verified")


if __name__ == "__main__":
    main(Path(sys.argv[1]).resolve())
