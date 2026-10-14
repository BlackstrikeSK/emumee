"""Check packaged native WinINet/WinHTTP calls reach the broker's deny policy."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "output" / "native-http-package"


def verify(arch: str, stack: str) -> None:
    run = sorted((OUTPUT / f"{stack}_{arch}").iterdir(), reverse=True)[0]
    summary = json.loads((run / "summary.json").read_text(encoding="utf-8"))
    report = json.loads((run / summary["engine_report"]).read_text(encoding="utf-8"))
    broker = json.loads((run / "network-broker.json").read_text(encoding="utf-8"))
    assert summary["status"] == "completed" and not summary["errors"], (arch, stack, summary)
    events = report["network_events"]
    assert [item["event"] for item in events] == [
        "network_attempt", "http_request", "network_error"], (arch, stack, events)
    request = events[1]
    assert request["url"].startswith("http://127.0.0.1") and request["method"] == (
        "POST" if stack == "winhttp" else "GET"), (arch, stack, request)
    if stack == "winhttp":
        assert request["headers"] == {"X-Test": "emumee"}, (arch, stack, request)
        assert request["size"] == len(b"harmless WinHTTP body"), (arch, stack, request)
    assert any("Private or host-local destination denied: 127.0.0.1" in
               str(item.get("error", "")) for item in broker), (arch, stack, broker)
    assert not any(item.get("event") == "http_response" for item in broker), (arch, stack)
    exits = [item for entry in report["entry_points"] for item in entry.get("events") or []
             if str(item.get("api_name", "")).endswith("ExitProcess")]
    assert exits and exits[-1]["args"] == ["0x0"], (arch, stack, exits)
    print(f"{stack}_{arch}: native request logged; localhost denied by broker")


def verify_response_denial(arch: str, stack: str, variant: str) -> None:
    run = sorted((OUTPUT / f"{stack}_{variant}_{arch}").iterdir(), reverse=True)[0]
    summary = json.loads((run / "summary.json").read_text(encoding="utf-8"))
    report = json.loads((run / summary["engine_report"]).read_text(encoding="utf-8"))
    broker = json.loads((run / "network-broker.json").read_text(encoding="utf-8"))
    assert summary["status"] == "completed" and not summary["errors"], (arch, stack, summary)
    expected = []
    if variant == "post":
        expected += ["http_connect_attempt", "http_connect",
                     "http_open_request_attempt", "http_request_opened"]
    expected += ["network_attempt", "http_request", "network_error"]
    if stack == "winhttp":
        expected += ["http_receive_attempt", "network_denied"]
    if variant in ("query", "post") or (variant == "available" and stack == "winhttp"):
        expected += ["http_query_attempt", "network_denied"]
    expected += ["http_read_attempt", "network_denied"]
    if variant in ("available", "post"):
        expected += ["http_available_attempt", "network_denied"]
    assert [item["event"] for item in report["network_events"]] == expected, (
        arch, stack, report["network_events"])
    assert report["network_events"][-1]["reason"] == (
        "response not ready or invalid request handle"), (arch, stack)
    assert any("Private or host-local destination denied: 127.0.0.1" in
               str(item.get("error", "")) for item in broker), (arch, stack, broker)
    if variant == "post":
        request = report["network_events"][5]
        assert request["method"] == "POST" and request["size"] == len(
            b"harmless WinINet body") and request["headers"] == {
                "X-Test": "emumee"}, (arch, stack, request)
    assert not any(item.get("event") == "http_response" for item in broker), (arch, stack)
    exits = [item for entry in report["entry_points"] for item in entry.get("events") or []
             if str(item.get("api_name", "")).endswith("ExitProcess")]
    assert exits and exits[-1]["args"] == ["0x0"], (arch, stack, exits)
    print(f"{stack}_{variant}_{arch}: denied response access failed cleanly")


def verify_stream_denial(arch: str, variant: str = "stream") -> None:
    label = f"winhttp_{variant}_{arch}"
    chunked = variant == "chunked"
    run = sorted((OUTPUT / label).iterdir(), reverse=True)[0]
    summary = json.loads((run / "summary.json").read_text(encoding="utf-8"))
    report = json.loads((run / summary["engine_report"]).read_text(encoding="utf-8"))
    broker = json.loads((run / "network-broker.json").read_text(encoding="utf-8"))
    assert summary["status"] == "completed" and not summary["errors"], (arch, summary)
    events = report["network_events"]
    expected = ["network_attempt", "http_request_staged", "http_write_attempt", "http_write"]
    if chunked:
        expected += ["http_write_attempt", "http_write"]
    expected += [
        "http_receive_attempt", "http_request", "network_error",
        "http_query_attempt", "network_denied", "http_read_attempt", "network_denied",
    ]
    assert [item["event"] for item in events] == expected, (label, events)
    assert events[1]["chunked"] is chunked, (label, events[1])
    assert events[3]["accumulated"] == len(b"harmless WinHTTP body"), (label, events[3])
    if chunked:
        assert events[5]["chunk_terminated"] and events[5]["size"] == 0, (label, events[5])
        assert events[7]["chunked"] and events[7]["headers"] == {
            "Transfer-Encoding": "chunked", "X-Test": "emumee"}, (label, events[7])
    assert any("Private or host-local destination denied: 127.0.0.1" in
               str(item.get("error", "")) for item in broker), (arch, broker)
    assert not any(item.get("event") == "http_response" for item in broker), arch
    exits = [item for entry in report["entry_points"] for item in entry.get("events") or []
             if str(item.get("api_name", "")).endswith("ExitProcess")]
    assert exits and int(exits[-1]["args"][0], 16) == (
        len(b"harmless WinHTTP body") if chunked else len(b"WinHTTP body")), (label, exits)
    print(f"{label}: guest write staged; broker denied localhost at receive")


def verify_wininet_stream_denial(arch: str, variant: str = "stream") -> None:
    label = f"wininet_{variant}_{arch}"
    run = sorted((OUTPUT / label).iterdir(), reverse=True)[0]
    summary = json.loads((run / "summary.json").read_text(encoding="utf-8"))
    report = json.loads((run / summary["engine_report"]).read_text(encoding="utf-8"))
    broker = json.loads((run / "network-broker.json").read_text(encoding="utf-8"))
    assert summary["status"] == "completed" and not summary["errors"], (label, summary)
    events = report["network_events"]
    assert [item["event"] for item in events] == [
        "http_connect_attempt", "http_connect", "http_open_request_attempt",
        "http_request_opened", "network_attempt", "http_request_staged",
        "http_write_attempt", "http_write", "http_end_attempt", "http_request",
        "network_error", "http_read_attempt", "network_denied",
    ], (label, events)
    assert events[7]["accumulated"] == len(b"harmless WinINet body"), (label, events)
    assert events[5]["linked_buffer_ignored"] is (variant == "linked"), (label, events[5])
    assert events[9]["method"] == "POST" and events[9]["size"] == len(
        b"harmless WinINet body") and events[9]["headers"] == {
            "X-Test": "emumee"}, (label, events[9])
    assert any("Private or host-local destination denied: 127.0.0.1" in
               str(item.get("error", "")) for item in broker), (label, broker)
    assert not any(item.get("event") == "http_response" for item in broker), label
    exits = [item for entry in report["entry_points"] for item in entry.get("events") or []
             if str(item.get("api_name", "")).endswith("ExitProcess")]
    assert exits and int(exits[-1]["args"][0], 16) == (
        len(b"WinINet body") ^ 1), (label, exits)
    print(f"{label}: guest write staged; broker denied localhost at end")


def verify_invalid_staging(arch: str, stage: str) -> None:
    label = f"wininet_bad_{stage}_{arch}"
    run = sorted((OUTPUT / label).iterdir(), reverse=True)[0]
    summary = json.loads((run / "summary.json").read_text(encoding="utf-8"))
    report = json.loads((run / summary["engine_report"]).read_text(encoding="utf-8"))
    broker = json.loads((run / "network-broker.json").read_text(encoding="utf-8"))
    assert summary["status"] == "completed" and not summary["errors"], (label, summary)
    expected = ["http_connect_attempt"]
    expected += ["http_connect"] if stage == "request" else ["network_denied"]
    expected += ["http_open_request_attempt", "network_denied",
                 "network_attempt", "network_denied", "http_query_attempt",
                 "network_denied", "http_read_attempt", "network_denied",
                 "http_available_attempt", "network_denied"]
    assert [item["event"] for item in report["network_events"]] == expected, (
        label, report["network_events"])
    assert not any(item.get("event") in {"http_request", "http_response"}
                   for item in broker), (label, broker)
    exits = [item for entry in report["entry_points"] for item in entry.get("events") or []
             if str(item.get("api_name", "")).endswith("ExitProcess")]
    assert exits and exits[-1]["args"] == ["0x0"], (label, exits)
    print(f"{label}: invalid handle denied before broker action")


if __name__ == "__main__":
    for architecture in ("x86", "x64"):
        for api_stack in ("wininet", "winhttp"):
            verify(architecture, api_stack)
            for response_variant in ("read", "query", "available"):
                verify_response_denial(architecture, api_stack, response_variant)
            if api_stack == "wininet":
                verify_response_denial(architecture, api_stack, "post")
        verify_stream_denial(architecture)
        verify_stream_denial(architecture, "chunked")
        verify_wininet_stream_denial(architecture)
        verify_wininet_stream_denial(architecture, "linked")
        for invalid_stage in ("connect", "request"):
            verify_invalid_staging(architecture, invalid_stage)
