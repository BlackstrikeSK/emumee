"""Verify a packaged ZIP member is loaded and invoked only inside guest CIL."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
PAYLOAD = (PROJECT / "tests" / "fixtures" / "ManagedZipStagePayload" /
           "bin" / "Release" / "net8.0" / "ManagedZipStagePayload.dll")


def main(runs_root: Path) -> None:
    summaries = list(runs_root.glob("*/summary.json"))
    assert len(summaries) == 1, "expected one packaged ZIP stage run"
    run_dir = summaries[0].parent
    summary = json.loads(summaries[0].read_text(encoding="utf-8"))
    report = json.loads((run_dir / "engine-report.json").read_text(encoding="utf-8"))
    assert summary["status"] == "completed" and not summary.get("errors")
    assert summary["engine"] == "emumee-cil" and summary["network_broker_complete"] is True
    stage = PAYLOAD.read_bytes()
    prefix = r"C:\Users\Alex\AppData\Roaming"
    expected = [
        ("managed_zip_entry_open", "", stage),
        ("managed_assembly_load", "", stage),
        ("managed_file_write", prefix + r"\zip-stage-payload-DESKTOP-7F4M2Q9.txt",
         b"harmless ZIP-loaded stage"),
        ("managed_file_write", prefix + r"\zip-stage-state-DESKTOP-7F4M2Q9.txt",
         b"zip-stage-ok"),
    ]
    actual = []
    for item in summary["artifacts"]:
        payload = (run_dir / "artifacts" / item["file"]).read_bytes()
        assert len(payload) == item["size"]
        assert hashlib.sha256(payload).hexdigest() == item["sha256"]
        actual.append((item["source"], item.get("guest_path", ""), payload))
    assert actual == expected
    assert [item["kind"] for item in summary["artifacts"]] == [
        "pe", "pe", "binary", "binary"]
    events = report["events"]
    assert [event["event"] for event in events
            if event["event"] in {"managed_zip_entry_open", "managed_assembly_load",
                                  "managed_reflect_invoke"}] == [
                                      "managed_zip_entry_open", "managed_assembly_load",
                                      "managed_reflect_invoke"]
    assert [event["name"] for event in events
            if event.get("event") == "managed_zip_entry_open"] == [
                "stage/ManagedZipStagePayload.dll"]
    assert summary["cil_coverage"] == report["cil_coverage"]
    print("packaged ZIP stage: extracted DLL, CIL invocation, guest files, and hashes verified")


if __name__ == "__main__":
    main(Path(sys.argv[1]).resolve())
