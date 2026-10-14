"""Check exact outputs of the packaged harmless managed AES fixture."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


def main(runs_root: Path) -> None:
    summaries = list(runs_root.glob("*/summary.json"))
    assert len(summaries) == 1, "expected one packaged ManagedAes run"
    run_dir = summaries[0].parent
    summary = json.loads(summaries[0].read_text(encoding="utf-8"))
    report = json.loads((run_dir / "engine-report.json").read_text(encoding="utf-8"))
    assert summary["status"] == "completed" and not summary.get("errors")
    assert summary["engine"] == "emumee-cil" and summary["network_broker_complete"] is True
    prefix = r"C:\Users\Alex\AppData\Roaming\emumee-aes-DESKTOP-7F4M2Q9"
    expected = {
        prefix + "-plain.bin": bytes.fromhex("6bc1bee22e409f96e93d7e117393172a"),
        prefix + "-cipher.bin": bytes.fromhex("7649abac8119b246cee98e9b12e9197d"),
        prefix + "-unpadded.bin": b"hello managed aes payload",
        prefix + "-state.txt": b"aes-ok;bad-input;bad-key",
    }
    recovered = {}
    for item in summary["artifacts"]:
        payload = (run_dir / "artifacts" / item["file"]).read_bytes()
        assert len(payload) == item["size"]
        assert hashlib.sha256(payload).hexdigest() == item["sha256"]
        recovered[item["guest_path"]] = payload
    assert recovered == expected
    transforms = [event for event in report["events"]
                  if event.get("event") == "managed_aes_transform"]
    assert [(event["direction"], event["output_size"]) for event in transforms] == [
        ("decrypt", 16), ("encrypt", 16), ("decrypt", 25)]
    assert [event["type"] for event in report["events"]
            if event.get("event") == "managed_catch"] == [
                "System.Security.Cryptography.CryptographicException"] * 2
    assert summary["cil_coverage"] == report["cil_coverage"]
    print("packaged managed AES: NIST vector, padding, catches, and hashes verified")


if __name__ == "__main__":
    main(Path(sys.argv[1]).resolve())
