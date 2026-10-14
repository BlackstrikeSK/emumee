"""Verify packaged managed SpecialFolder paths and guest-only writes."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


def main(runs_root: Path) -> None:
    reports = list(runs_root.glob("*/summary.json"))
    assert len(reports) == 1, "expected one packaged ManagedSpecialFolders run"
    run_dir = reports[0].parent
    summary = json.loads(reports[0].read_text(encoding="utf-8"))
    report = json.loads((run_dir / "engine-report.json").read_text(encoding="utf-8"))
    assert summary["status"] == "completed" and not summary.get("errors")
    assert summary["engine"] == "emumee-cil" and summary["network_broker_complete"] is True
    home = r"C:\Users\Alex"
    roaming = home + r"\AppData\Roaming"
    local = home + r"\AppData\Local"
    startup = roaming + r"\Microsoft\Windows\Start Menu\Programs\Startup"
    tag = "emumee-special-DESKTOP-7F4M2Q9"
    expected = {
        roaming + "\\" + tag + "-roaming.txt": b"roaming",
        local + "\\" + tag + "-local.txt": b"local",
        startup + "\\" + tag + "-startup.txt": b"startup",
        home + "\\Desktop\\" + tag + "-desktop.txt": b"desktop",
        home + "\\Documents\\" + tag + "-documents.txt": b"documents",
        home + "\\" + tag + "-profile.txt": b"profile",
        roaming + "\\" + tag + "-created.txt": roaming.encode(),
        roaming + "\\" + tag + "-unverified.txt": local.encode(),
        roaming + "\\" + tag + "-system.txt":
            b"C:\\ProgramData|C:\\Windows|C:\\Windows\\System32|C:\\Program Files",
        roaming + "\\" + tag + "-state.txt":
            b"folders-ok;invalid-folder;invalid-option",
    }
    recovered = {}
    for item in summary["artifacts"]:
        payload = (run_dir / "artifacts" / item["file"]).read_bytes()
        assert len(payload) == item["size"]
        assert hashlib.sha256(payload).hexdigest() == item["sha256"]
        recovered[item["guest_path"]] = payload
    assert recovered == expected
    assert sum(event.get("event") == "special_folder" for event in report["events"]) == 13
    assert [event["type"] for event in report["events"]
            if event.get("event") == "managed_catch"] == ["System.ArgumentException"] * 2
    assert summary["cil_coverage"] == report["cil_coverage"]
    print("packaged managed special folders: persona paths, guest bytes, and hashes verified")


if __name__ == "__main__":
    main(Path(sys.argv[1]).resolve())
