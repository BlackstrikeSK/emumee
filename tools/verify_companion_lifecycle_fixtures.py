"""Check packaged companion reference counts, detach, and guest DLL bytes."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def report_for(name: str):
    run = sorted((ROOT / "output" / name).iterdir(), reverse=True)[0]
    summary = json.loads((run / "summary.json").read_text(encoding="utf-8"))
    report = json.loads((run / summary["engine_report"]).read_text(encoding="utf-8"))
    assert summary["status"] == "completed" and not summary["errors"], name
    assert not report.get("errors"), name
    events = [event for entry in report["entry_points"]
              for event in (entry.get("events") or [])]
    exits = [event for event in events
             if str(event.get("api_name", "")).endswith("ExitProcess")]
    assert exits[-1]["args"] == ["0x2a"], name
    return run, summary, report, events


def free_returns(events):
    return [event["ret_val"] for event in events
            if str(event.get("api_name", "")).endswith("FreeLibrary")]


def verify_companion(arch: str, *, tls: bool, static: bool) -> None:
    name = f"{'static_' if static else ''}companion_{'tls_' if tls else ''}lifecycle_{arch}"
    _run, _summary, report, api = report_for(name)
    expected = [] if static else (["dll_tls_callback"] if tls else []) + ["dll_process_attach"]
    expected += ["companion_dll_retain", "companion_dll_release"]
    if tls:
        expected.append("dll_tls_detach")
    expected += ["dll_process_detach", "companion_dll_unload"]
    if tls:
        expected.append("dll_tls_callback")
    expected.append("dll_process_attach")
    actual = report["dll_initialization_events"]
    assert [item["event"] for item in actual] == expected, name
    assert free_returns(api) == (["0x1", "0x1"] if static else ["0x1", "0x1", "0x0"]), name
    assert next(item for item in actual if item["event"] == "companion_dll_retain")["references"] == 2, name
    assert next(item for item in actual if item["event"] == "companion_dll_release")["references"] == 1, name
    print(f"{name}: retained, detached, and reloaded")


def verify_dependency(arch: str, *, preloaded: bool, tls: bool = False) -> None:
    name = (f"dropped_dependency_preload_{'tls_' if tls else ''}dll_{arch}"
            if preloaded else f"dropped_dependency_lifecycle_dll_{arch}")
    run, summary, report, api = report_for(name)
    events = report["dll_initialization_events"]
    detached = [item["module"] for item in events if item["event"] == "dll_process_detach"]
    companion_name = f"companion_{arch}"
    assert detached == (["guest-stage", "guest-stage", companion_name]
                        if preloaded else ["guest-stage", companion_name]), name
    assert sum(item["event"] == "companion_dll_unload" for item in events) == 1, name
    assert free_returns(api) == (["0x1", "0x1", "0x0", "0x1", "0x1"]
                                 if preloaded else ["0x1", "0x1", "0x0"]), name
    if preloaded:
        assert [item["references"] for item in events
                if item["event"] == "companion_dll_release"] == [1, 1], name
        assert not any(item["event"] == "dll_dependency_map" for item in events), name
    else:
        assert sum(item["event"] == "dll_dependency_map" for item in events) == 2, name
    fixture = (f"dropped_dependency_preload_dll_{arch}.exe" if preloaded
               else f"{name}.exe")
    data = (ROOT / "tests" / "fixtures" / fixture).read_bytes()[0xA00:0x1000]
    digest = hashlib.sha256(data).hexdigest()
    artifacts = [item for item in summary["artifacts"]
                 if item["source"] == "guest_dll_load" and item["sha256"] == digest]
    assert len(artifacts) == 1, name
    assert (run / "artifacts" / artifacts[0]["file"]).read_bytes() == data, name
    print(f"{name}: dependency reference lifetime and exact DLL bytes verified")


if __name__ == "__main__":
    for architecture in ("x86", "x64"):
        for uses_tls in (False, True):
            verify_companion(architecture, tls=uses_tls, static=False)
            verify_companion(architecture, tls=uses_tls, static=True)
            verify_dependency(architecture, preloaded=True, tls=uses_tls)
        verify_dependency(architecture, preloaded=False)
