"""Check packaged append-only CPU fixtures and their extracted guest bytes."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "output" / "append-package"


def main(output: Path = OUTPUT) -> None:
    for arch in ("x86", "x64"):
        for suffix in ("", "_a"):
            name = f"append_only{suffix}_{arch}"
            reports = list((output / name).glob("*/summary.json"))
            if len(reports) != 1:
                raise AssertionError(f"{name}: expected one packaged report")
            run_dir = reports[0].parent
            summary = json.loads(reports[0].read_text(encoding="utf-8"))
            engine = json.loads((run_dir / summary["engine_report"]).read_text(encoding="utf-8"))
            assert summary["status"] == "completed", name
            assert summary["network_broker_complete"] is True, name
            assert not summary["errors"], name
            assert not summary["api_coverage"]["signature_only_calls"], name
            assert any(event.get("api_name") == "kernel32.ExitProcess"
                       and event.get("args") == ["0x1"]
                       for entry in engine["entry_points"]
                       for event in entry["events"]), name
            matches = [item for item in summary["artifacts"]
                       if item.get("guest_path", "").lower().endswith("reopened.bin")]
            assert len(matches) == 1, name
            item = matches[0]
            content = (run_dir / "artifacts" / item["file"]).read_bytes()
            assert content == b"OLD!NEW!", name
            assert item["size"] == len(content), name
            assert item["sha256"] == hashlib.sha256(content).hexdigest(), name
            print(f"{name}: completed, guest exit 1, extracted {content!r}")


if __name__ == "__main__":
    main(Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else OUTPUT)
