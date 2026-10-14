"""Check packaged process fixtures after running them with Emumee.exe."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SHELLCODE = b"\x31\xc0\xc3"


def latest_run(name: str) -> Path:
    runs = sorted((ROOT / "output" / name).iterdir(), reverse=True)
    if not runs:
        raise AssertionError(f"no packaged run: {name}")
    return runs[0]


def artifact_matches(run: Path, summary: dict, source: str, data: bytes) -> bool:
    digest = hashlib.sha256(data).hexdigest()
    for item in summary["artifacts"]:
        if item["source"] != source or item["sha256"] != digest:
            continue
        name = item["file"]
        if Path(name).name != name:
            continue
        if (run / "artifacts" / name).read_bytes() == data:
            return True
    return False


def verify(name: str, entry_count: int) -> None:
    run = latest_run(name)
    summary = json.loads((run / "summary.json").read_text(encoding="utf-8"))
    report = json.loads((run / summary["engine_report"]).read_text(encoding="utf-8"))
    assert summary["status"] == "completed" and not summary["errors"], name
    entries = report["entry_points"]
    assert len(entries) == entry_count and all(not item.get("error") for item in entries), name
    events = report["virtual_process_events"]
    if "memory_read" in name:
        arch = name.rsplit("_", 1)[-1]
        fixture = (ROOT / "tests" / "fixtures" / f"{name}.exe").read_bytes()
        nested = fixture[0xA00:0xA10]
        reads = [item for item in events if item["event"] == "virtual_process_memory_read"]
        assert [item["success"] for item in reads] == [False, True], (name, reads)
        assert reads[0]["reason"] == "invalid process handle", name
        assert reads[1]["sha256"] == hashlib.sha256(nested).hexdigest(), name
        assert artifact_matches(run, summary, "process_memory_read", nested), name
        assert arch in ("x86", "x64")
    else:
        mode = "resumed" if "_resumed_" in name else "suspended" if "_suspended_" in name else "immediate"
        threads = [item for item in events if item["event"] == "virtual_remote_thread_create"]
        assert len(threads) == 1 and threads[0]["success"], name
        assert threads[0]["flags"] == (0 if mode == "immediate" else 4), name
        injected = [item for item in entries if str(item.get("ep_type", "")).startswith("injected_thread_")]
        assert len(injected) == (0 if mode == "suspended" else 1), name
        assert all(item["ret_val"] == "0x0" for item in injected), name
        writes = [item for item in events if item["event"] == "virtual_process_memory_write"]
        assert len(writes) == 2 and all(item["success"] for item in writes), name
        assert writes[1]["sha256"] == hashlib.sha256(SHELLCODE).hexdigest(), name
        assert artifact_matches(run, summary, "process_memory_write", SHELLCODE), name
        resumes = [item for item in events if item["event"] == "virtual_thread_resume"]
        assert len(resumes) == (1 if mode == "resumed" else 0), name
        if resumes:
            assert (resumes[0]["previous_suspend_count"], resumes[0]["suspend_count"]) == (1, 0), name
    print(f"{name}: {len(entries)} clean entry points, verified guest bytes")


def verify_cross_owner(name: str, operation: str) -> None:
    run = latest_run(name)
    summary = json.loads((run / "summary.json").read_text(encoding="utf-8"))
    report = json.loads((run / summary["engine_report"]).read_text(encoding="utf-8"))
    assert summary["status"] == "completed" and not summary["errors"], name
    assert len(report["entry_points"]) == 2, name
    assert all(not item.get("error") for item in report["entry_points"]), name
    event_type = {"write": "virtual_process_memory_write",
                  "alloc": "virtual_process_allocate",
                  "protect": "virtual_process_protect"}[operation]
    events = [item for item in report["virtual_process_events"]
              if item["event"] == event_type]
    assert [item["success"] for item in events] == [False, True], (name, events)
    assert "different guest process" in events[0]["reason"], name
    fixture = (ROOT / "tests" / "fixtures" / f"{name}.exe").read_bytes()
    nested = fixture[0xA00:0x1000]
    assert artifact_matches(run, summary, "process_memory_write", nested), name
    print(f"{name}: foreign mapping denied, valid child operation and bytes verified")


def verify_access(name: str) -> None:
    run = latest_run(name)
    summary = json.loads((run / "summary.json").read_text(encoding="utf-8"))
    report = json.loads((run / summary["engine_report"]).read_text(encoding="utf-8"))
    assert summary["status"] == "completed" and not summary["errors"], name
    assert len(report["entry_points"]) == 1 and report["entry_points"][0]["ret_val"] == "0x1", name
    events = report["virtual_process_events"]
    opens = [item for item in events if item["event"] == "virtual_process_open"]
    assert [item["requested_access"] for item in opens] == [0x10, 0x08], name
    assert all(item["success"] for item in opens) and opens[0]["handle"] != opens[1]["handle"], name
    denied = [item["reason"] for item in events if not item["success"]]
    assert denied == ["process handle lacks write rights",
                      "process handle lacks VM operation rights",
                      "process handle lacks read rights",
                      "invalid process handle"], (name, denied)
    assert len([item for item in events if item["event"] == "virtual_process_allocate"
                and item["success"]]) == 1, name
    assert len([item for item in events if item["event"] == "virtual_process_close"
                and item["success"]]) == 2, name
    print(f"{name}: per-handle rights, close, and surviving handle verified")


def verify_duplicate(name: str) -> None:
    run = latest_run(name)
    summary = json.loads((run / "summary.json").read_text(encoding="utf-8"))
    report = json.loads((run / summary["engine_report"]).read_text(encoding="utf-8"))
    assert summary["status"] == "completed" and not summary["errors"], name
    assert len(report["entry_points"]) == 1 and report["entry_points"][0]["ret_val"] == "0x1", name
    events = report["virtual_process_events"]
    duplicates = [item for item in events if item["event"] == "virtual_process_handle_duplicate"]
    assert [item["success"] for item in duplicates] == [True, True], name
    assert duplicates[0]["granted_access"] == 0x38, name
    assert duplicates[1]["granted_access"] == 0x10, name
    assert len([item for item in events if item["event"] == "virtual_process_close" and item["success"]]) == 3, name
    assert artifact_matches(run, summary, "process_memory_write", b"MZ"), name
    assert artifact_matches(run, summary, "process_memory_read", b"MZ"), name
    print(f"{name}: own-process duplicate rights, write, and read verified")


def verify_thread_handles(name: str) -> None:
    run = latest_run(name)
    summary = json.loads((run / "summary.json").read_text(encoding="utf-8"))
    report = json.loads((run / summary["engine_report"]).read_text(encoding="utf-8"))
    assert summary["status"] == "completed" and not summary["errors"], name
    entries = report["entry_points"]
    assert len(entries) == 2 and all(not entry.get("error") for entry in entries), name
    assert entries[0]["ret_val"] == "0x1" and entries[1]["ret_val"] == "0x0", name
    events = report["virtual_process_events"]
    created = [event for event in events if event["event"] == "virtual_thread_create"]
    assert len(created) == 1 and created[0]["suspend_count"] == 1, name
    opened = [event for event in events if event["event"] == "virtual_thread_open"]
    assert len(opened) == 1 and opened[0]["requested_access"] == 0x40, name
    duplicates = [event for event in events
                  if event["event"] == "virtual_process_handle_duplicate"]
    assert len(duplicates) == 1 and duplicates[0]["success"], name
    assert duplicates[0]["object_type"] == "thread" and duplicates[0]["granted_access"] == 2, name
    resumes = [event for event in events if event["event"] == "virtual_thread_resume"]
    assert [event["success"] for event in resumes] == [False, False, False, True], name
    assert (resumes[-1]["previous_suspend_count"], resumes[-1]["suspend_count"]) == (1, 0), name
    closes = [event for event in events if event["event"] == "virtual_thread_close"]
    assert len(closes) == 3 and all(event["success"] for event in closes), name
    print(f"{name}: thread rights, duplicate, closure, and suspended execution verified")


if __name__ == "__main__":
    for machine in ("x86", "x64"):
        verify(f"child_memory_read_{machine}", 2)
        verify(f"child_remote_thread_{machine}", 3)
        verify(f"child_remote_thread_suspended_{machine}", 2)
        verify(f"child_remote_thread_resumed_{machine}", 3)
        for operation in ("write", "alloc", "protect"):
            verify_cross_owner(f"child_cross_owner_{operation}_{machine}", operation)
        verify_access(f"process_access_{machine}")
        verify_duplicate(f"process_duplicate_{machine}")
        verify_thread_handles(f"thread_handles_{machine}")
