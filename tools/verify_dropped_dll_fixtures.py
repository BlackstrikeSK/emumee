"""Verify packaged guest-created DLL loads and invalid-image rejection."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def latest_run(name: str) -> Path:
    return sorted((ROOT / "output" / name).iterdir(), reverse=True)[0]


def verify(name: str, valid: bool) -> None:
    run = latest_run(name)
    summary = json.loads((run / "summary.json").read_text(encoding="utf-8"))
    report = json.loads((run / summary["engine_report"]).read_text(encoding="utf-8"))
    assert summary["status"] == "completed" and not summary["errors"], name
    entries = report["entry_points"]
    assert len(entries) == 1 and not entries[0].get("error"), name
    events = report["dll_initialization_events"]
    assert events[0]["event"] == "virtual_dll_load", name
    if valid:
        assert entries[0]["ret_val"] == "0x2a", name
        if "_shadow_" in name:
            assert "Documents" in events[0]["path"], name
        expected = (["virtual_dll_load", "dll_tls_callback", "dll_process_attach"]
                    if "_tls_" in name else ["virtual_dll_load", "dll_process_attach"])
        assert [event["event"] for event in events] == expected, name
        assert events[0]["mapped"] and events[-1]["success"], name
        if "_import_" in name:
            imported = [event for event in entries[0]["events"]
                        if str(event.get("api_name", "")).endswith("GetCurrentProcessId")]
            assert len(imported) == 1 and imported[0]["ret_val"] != "0x0", name
        data = (ROOT / "tests" / "fixtures" / f"{name}.exe").read_bytes()[0xA00:0x1000]
        digest = hashlib.sha256(data).hexdigest()
        assert events[0]["sha256"] == digest, name
        artifacts = [item for item in summary["artifacts"]
                     if item["source"] == "guest_dll_load" and item["sha256"] == digest]
        assert len(artifacts) == 1, name
        assert (run / "artifacts" / artifacts[0]["file"]).read_bytes() == data, name
    else:
        assert len(events) == 1 and not events[0]["mapped"], name
        assert "not a PE" in events[0]["reason"], name
        assert not any(item["source"] == "guest_dll_load" for item in summary["artifacts"]), name
        exits = [event for event in entries[0]["events"]
                 if str(event.get("api_name", "")).endswith("ExitProcess")]
        assert exits[-1]["args"] == ["0x1"], name
    print(f"{name}: {'guest DLL executed and extracted' if valid else 'invalid DLL rejected'}")


def verify_missing(name: str) -> None:
    run = latest_run(name)
    summary = json.loads((run / "summary.json").read_text(encoding="utf-8"))
    report = json.loads((run / summary["engine_report"]).read_text(encoding="utf-8"))
    assert summary["status"] == "completed" and not summary["errors"], name
    assert report["entry_points"][0]["ret_val"] == "0x0", name
    events = report["dll_initialization_events"]
    assert len(events) == 1 and not events[0]["mapped"], name
    assert "absent" in events[0]["reason"], name
    print(f"{name}: missing full path did not load a same-name companion")


def verify_dependency(arch: str, failing: bool) -> None:
    name = f"dropped_dependency_{'fail_' if failing else ''}{arch}"
    run = latest_run(name)
    summary = json.loads((run / "summary.json").read_text(encoding="utf-8"))
    report = json.loads((run / summary["engine_report"]).read_text(encoding="utf-8"))
    assert summary["status"] == "completed" and not summary["errors"], name
    entries = report["entry_points"]
    assert len(entries) == 1 and not entries[0].get("error"), name
    events = report["dll_initialization_events"]
    assert [item["event"] for item in events[:3]] == [
        "virtual_dll_load", "dll_dependency_map", "dll_process_attach"], name
    assert events[2]["module"] == f"companion_{arch}", name
    assert events[2]["success"] is not failing, name
    if failing:
        assert [item["event"] for item in events[3:]] == [
            "dll_process_detach", "virtual_dll_load_failed"], name
        assert events[3]["module"] == f"companion_{arch}" and entries[0]["ret_val"] == "0x0", name
    else:
        assert len(events) == 4 and events[3]["module"] == "guest-stage", name
        assert events[3]["success"] and entries[0]["ret_val"] == "0x2a", name
    data = (ROOT / "tests" / "fixtures" / f"dropped_dependency_dll_{arch}.exe").read_bytes()[0xA00:0x1000]
    digest = hashlib.sha256(data).hexdigest()
    artifacts = [item for item in summary["artifacts"]
                 if item["source"] == "guest_dll_load" and item["sha256"] == digest]
    assert len(artifacts) == 1, name
    assert (run / "artifacts" / artifacts[0]["file"]).read_bytes() == data, name
    print(f"{name}: {'dependency failure stopped the chain' if failing else 'dependency initialized before guest DLL'}")


def verify_lifecycle(arch: str, tls: bool) -> None:
    name = f"dropped_{'tls_' if tls else ''}lifecycle_dll_{arch}"
    run = latest_run(name)
    summary = json.loads((run / "summary.json").read_text(encoding="utf-8"))
    report = json.loads((run / summary["engine_report"]).read_text(encoding="utf-8"))
    assert summary["status"] == "completed" and not summary["errors"], name
    entry = report["entry_points"][0]
    assert entry["ret_val"] == "0x2a" and not entry.get("error"), name
    events = report["dll_initialization_events"]
    expected = (["virtual_dll_load", "dll_tls_callback", "dll_process_attach"]
                if tls else ["virtual_dll_load", "dll_process_attach"])
    expected += ["virtual_dll_load", "virtual_dll_release"]
    if tls:
        expected.append("dll_tls_detach")
    expected += ["dll_process_detach", "virtual_dll_unload", "virtual_dll_load"]
    if tls:
        expected.append("dll_tls_callback")
    expected.append("dll_process_attach")
    assert [event["event"] for event in events] == expected, name
    assert next(event for event in events if event["event"] == "virtual_dll_release")["references"] == 1, name
    calls = [event for event in entry["events"] if str(event.get("api_name", "")).endswith("FreeLibrary")]
    assert [event["ret_val"] for event in calls] == ["0x1", "0x1", "0x0"], name
    exported = [event for event in entry["events"]
                if str(event.get("api_name", "")).endswith("GetProcAddress")]
    assert [event["ret_val"] != "0x0" for event in exported] == [True, True, False, True], name
    data = (ROOT / "tests" / "fixtures" / f"{name}.exe").read_bytes()[0xA00:0x1000]
    digest = hashlib.sha256(data).hexdigest()
    artifacts = [item for item in summary["artifacts"]
                 if item["source"] == "guest_dll_load" and item["sha256"] == digest]
    assert len(artifacts) == 1, name
    assert (run / "artifacts" / artifacts[0]["file"]).read_bytes() == data, name
    print(f"{name}: reference count, detach, stale handle, reload, and DLL bytes verified")


def verify_failed_attach(arch: str, tls: bool, dependency: bool) -> None:
    qualifier = "dependency_" if dependency else "tls_" if tls else ""
    name = f"dropped_{qualifier}failed_attach_dll_{arch}"
    run = latest_run(name)
    summary = json.loads((run / "summary.json").read_text(encoding="utf-8"))
    report = json.loads((run / summary["engine_report"]).read_text(encoding="utf-8"))
    assert summary["status"] == "completed" and not summary["errors"], name
    entry = report["entry_points"][0]
    exits = [event for event in entry["events"]
             if str(event.get("api_name", "")).endswith("ExitProcess")]
    loads = [event for event in entry["events"]
             if str(event.get("api_name", "")).endswith("LoadLibraryW")]
    assert exits[-1]["args"] == ["0x2a"] and len(loads) == 2, name
    assert all(event["ret_val"] == "0x0" for event in loads), name
    sequence = ["virtual_dll_load"]
    if dependency:
        sequence += ["dll_dependency_map", "dll_process_attach"]
    if tls:
        sequence.append("dll_tls_callback")
    sequence.append("dll_process_attach")
    if tls:
        sequence.append("dll_tls_detach")
    sequence.append("dll_process_detach")
    if dependency:
        sequence.append("dll_process_detach")
    sequence.append("virtual_dll_load_failed")
    events = report["dll_initialization_events"]
    assert [event["event"] for event in events] == sequence * 2, name
    assert all(not event["success"] for event in events
               if event["event"] == "dll_process_attach" and event["module"] == "guest-stage"), name
    data = (ROOT / "tests" / "fixtures" / f"{name}.exe").read_bytes()[0xA00:0x1000]
    digest = hashlib.sha256(data).hexdigest()
    artifacts = [item for item in summary["artifacts"]
                 if item["source"] == "guest_dll_load" and item["sha256"] == digest]
    assert len(artifacts) == 1, name
    assert (run / "artifacts" / artifacts[0]["file"]).read_bytes() == data, name
    print(f"{name}: failed attach detached, unloaded, retried, and exact DLL bytes verified")


if __name__ == "__main__":
    for arch in ("x86", "x64"):
        verify(f"dropped_dll_{arch}", True)
        verify(f"dropped_tls_dll_{arch}", True)
        verify(f"dropped_import_dll_{arch}", True)
        verify(f"dropped_shadow_dll_{arch}", True)
        verify(f"dropped_invalid_dll_{arch}", False)
        verify_missing(f"missing_companion_path_{arch}")
        verify_dependency(arch, False)
        verify_dependency(arch, True)
        verify_lifecycle(arch, False)
        verify_lifecycle(arch, True)
        verify_failed_attach(arch, False, False)
        verify_failed_attach(arch, True, False)
        verify_failed_attach(arch, False, True)
