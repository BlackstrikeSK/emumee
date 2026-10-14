"""Verify the packaged harmless managed block-transform fixture."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


def main(runs_root: Path) -> None:
    summaries = list(runs_root.glob("*/summary.json"))
    assert len(summaries) == 1, "expected one packaged ManagedAesBlocks run"
    run_dir = summaries[0].parent
    summary = json.loads(summaries[0].read_text(encoding="utf-8"))
    report = json.loads((run_dir / "engine-report.json").read_text(encoding="utf-8"))
    assert summary["status"] == "completed" and not summary.get("errors")
    assert summary["engine"] == "emumee-cil" and summary["network_broker_complete"] is True
    prefix = r"C:\Users\Alex\AppData\Roaming\emumee-aes-blocks-DESKTOP-7F4M2Q9"
    expected = {
        prefix + "-cipher.bin": bytes.fromhex(
            "d6d020609ad1bee66948a5a8ad2b7a122feba8a998d05e66"
            "c9452bd7d449c923b0b713abbcbb146cf3a7ab917e1d0637"),
        prefix + "-plain.bin": b"managed aes streaming payload verified!",
        prefix + "-state.txt": b"aes-blocks-ok;hold-final;reuse;bounds",
    }
    recovered = {}
    for item in summary["artifacts"]:
        payload = (run_dir / "artifacts" / item["file"]).read_bytes()
        assert len(payload) == item["size"]
        assert hashlib.sha256(payload).hexdigest() == item["sha256"]
        recovered[item["guest_path"]] = payload
    assert recovered == expected
    blocks = [event for event in report["events"]
              if event.get("event") == "managed_aes_block"]
    assert [(event["direction"], event["input_size"], event["output_size"])
            for event in blocks] == [
                ("encrypt", 16, 16), ("encrypt", 16, 16), ("decrypt", 48, 32)]
    assert [event["type"] for event in report["events"]
            if event.get("event") == "managed_catch"] == [
                "System.ArgumentOutOfRangeException"] * 2
    assert summary["cil_coverage"] == report["cil_coverage"]
    print("packaged managed AES blocks: output windows, held padding, reuse, and hashes verified")


if __name__ == "__main__":
    main(Path(sys.argv[1]).resolve())
