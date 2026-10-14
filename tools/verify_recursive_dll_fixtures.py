"""Check packaged recursive DLL execution, lifetime, and extracted guest bytes."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNS = ROOT / "output" / "recursive-package"


def verify(arch: str, variant: str) -> None:
    fixture = ROOT / "tests" / "fixtures" / f"dropped_{variant}_dll_{arch}.exe"
    matches = []
    for run in RUNS.iterdir():
        if not run.is_dir() or not (run / "summary.json").is_file():
            continue
        summary = json.loads((run / "summary.json").read_text(encoding="utf-8"))
        if summary["sample"]["sha256"] == hashlib.sha256(fixture.read_bytes()).hexdigest():
            matches.append((run, summary))
    assert matches, fixture.name
    run, summary = sorted(matches, key=lambda pair: pair[0].name)[-1]
    assert summary["status"] == "completed" and not summary["errors"], fixture.name
    report = json.loads((run / summary["engine_report"]).read_text(encoding="utf-8"))
    assert not report.get("errors"), fixture.name
    events = report["dll_initialization_events"]
    companion = f"companion_{arch}"
    expected_attach = ([companion] if variant == "guest_nested" else []) + [
        "guest-leaf", "guest-stage"]
    assert [item["module"] for item in events if item["event"] == "dll_process_attach"] == expected_attach, fixture.name
    assert all(item["success"] for item in events if item["event"] == "dll_process_attach"), fixture.name
    expected_detach = (list(reversed(expected_attach)) if variant != "guest_dependency"
                       else [])
    assert [item["module"] for item in events if item["event"] == "dll_process_detach"] == expected_detach, fixture.name
    api = [item for entry in report["entry_points"] for item in entry.get("events", [])]
    exits = [item for item in api if str(item.get("api_name", "")).endswith("ExitProcess")]
    assert exits[-1]["args"] == ["0x2a"], fixture.name
    if variant != "guest_dependency":
        frees = [item for item in api if str(item.get("api_name", "")).endswith("FreeLibrary")]
        assert [item["ret_val"] for item in frees] == ["0x1"], fixture.name
    for name, start, end in (("guest-stage.dll", 0xA00, 0x1000),
                             ("guest-leaf.dll", 0x1000, 0x1600)):
        expected = fixture.read_bytes()[start:end]
        artifacts = [item for item in summary["artifacts"]
                     if item["source"] == "guest_dll_load" and
                     item.get("guest_path", "").endswith(name)]
        assert len(artifacts) == 1, (fixture.name, name)
        assert artifacts[0]["sha256"] == hashlib.sha256(expected).hexdigest(), name
        assert (run / "artifacts" / artifacts[0]["file"]).read_bytes() == expected, name
    print(f"{fixture.name}: packaged attach, detach, and guest bytes verified")


def verify_cycle(arch: str) -> None:
    fixture = ROOT / "tests" / "fixtures" / f"dropped_guest_cycle_dll_{arch}.exe"
    digest = hashlib.sha256(fixture.read_bytes()).hexdigest()
    matches = []
    for run in RUNS.iterdir():
        if (run / "summary.json").is_file():
            summary = json.loads((run / "summary.json").read_text(encoding="utf-8"))
            if summary["sample"]["sha256"] == digest:
                matches.append((run, summary))
    assert matches, fixture.name
    run, summary = sorted(matches, key=lambda pair: pair[0].name)[-1]
    assert summary["status"] == "partial", fixture.name
    assert len([item for item in summary["errors"]
                if "cyclic guest DLL dependency" in item]) == 2, fixture.name
    report = json.loads((run / summary["engine_report"]).read_text(encoding="utf-8"))
    events = report["dll_initialization_events"]
    loads = [item for item in events if item["event"] == "virtual_dll_load"]
    assert len(loads) == 2 and loads[0]["base"] == loads[1]["base"], fixture.name
    assert not any(item["event"] == "dll_process_attach" for item in events), fixture.name
    print(f"{fixture.name}: packaged cycle fails visibly and retry remaps")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        RUNS = Path(sys.argv[1]).resolve()
    for architecture in ("x86", "x64"):
        for kind in ("guest_dependency", "guest_dependency_release", "guest_nested"):
            verify(architecture, kind)
        verify_cycle(architecture)
