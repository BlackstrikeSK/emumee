"""Verify packaged guest children cannot reuse a parent's companion DLL handle."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from emumee.reports import verify_artifact_manifest


def verify(root: Path) -> None:
    fixtures = Path(__file__).resolve().parents[1] / "tests" / "fixtures"
    for arch, parent_base in (("x86", 0x50000000), ("x64", 0x180000000)):
        companion = fixtures / f"child_parent_module_{arch}" / f"companion_{arch}.dll"
        companion_bytes = companion.read_bytes()
        for kind in ("lookup", "handle", "handle_ex", "free", "proc",
                     "filename", "peb", "psapi_name", "psapi_path",
                     "psapi_self", "psapi_enum", "psapi_name_valid",
                     "psapi_path_valid", "toolhelp_self", "toolhelp_parent",
                     "toolhelp_next", "toolhelp_foreign"):
            case = f"child_parent_module_{kind}_{arch}"
            summaries = list((root / case).glob("*/summary.json"))
            assert len(summaries) == 1, (case, summaries)
            run = summaries[0].parent
            summary = json.loads(summaries[0].read_text(encoding="utf-8"))
            submitted = (fixtures / f"{case}.exe").read_bytes()
            assert (run / "input.pe").read_bytes() == submitted, case
            assert (run / "inputs" / companion.name).read_bytes() == companion_bytes, case
            assert summary["sample"]["sha256"] == hashlib.sha256(submitted).hexdigest(), case
            assert summary["network_broker_complete"] is True, case
            journal = json.loads((run / "network-broker.json").read_text(encoding="utf-8"))
            assert journal[-1] == {"event": "broker_closed"}, case
            assert verify_artifact_manifest(run, summary["artifacts"]), case
            assert not summary["api_coverage"]["signature_only_calls"], case
            child_bytes = submitted[0xA00:0x1000]
            embedded = [item for item in summary["artifacts"]
                        if item["source"] == "embedded_input@0xa00"]
            assert len(embedded) == 1, case
            assert (run / "artifacts" / embedded[0]["file"]).read_bytes() == child_bytes, case

            report = json.loads((run / summary["engine_report"]).read_text(encoding="utf-8"))
            entries = report["entry_points"]
            assert len(entries) == 3 and all(not item.get("error") for item in entries), case
            assert entries[0]["pid"] == entries[1]["pid"] != entries[2]["pid"], case
            assert entries[0]["ep_args"][0] == hex(parent_base), case
            expected_api = {
                "lookup": "LoadLibraryW", "handle": "GetModuleHandleW",
                "handle_ex": "GetModuleHandleExW", "free": "FreeLibrary",
                "proc": "GetProcAddress", "filename": "GetModuleFileNameW",
                "peb": None, "psapi_name": "GetModuleBaseNameW",
                "psapi_path": "GetModuleFileNameExW",
                "psapi_self": "GetModuleBaseNameW",
                "psapi_enum": "EnumProcessModules",
                "psapi_name_valid": "GetModuleBaseNameW",
                "psapi_path_valid": "GetModuleFileNameExW",
                "toolhelp_self": "Module32FirstW",
                "toolhelp_parent": "Module32FirstW",
                "toolhelp_next": "Module32NextW",
                "toolhelp_foreign": "Module32FirstW"}[kind]
            if expected_api is not None:
                child_api = [item for item in entries[2]["events"]
                             if str(item.get("api_name", "")).endswith(expected_api)]
                assert len(child_api) == 1, case
            if kind.endswith("_valid"):
                opened = [item for item in report["virtual_process_events"]
                          if item["event"] == "virtual_process_open"]
                assert len(opened) == 1 and opened[0]["success"], case
                pid_calls = [item for item in entries[2]["events"]
                             if str(item.get("api_name", "")).endswith(
                                 "GetCurrentProcessId")]
                assert len(pid_calls) == 1, case
                assert int(pid_calls[0]["ret_val"], 16) == opened[0]["pid"], case
            if kind == "lookup":
                assert summary["status"] == "completed" and not summary["errors"], case
                child_base = int(entries[2]["ret_val"], 16)
                assert child_base not in (0, parent_base), case
                attach = [item for item in report["dll_initialization_events"]
                          if item["event"] == "dll_process_attach"]
                assert len(attach) == 1 and attach[0]["success"], case
                assert attach[0]["base"] == hex(child_base), case
            elif kind == "psapi_self":
                assert summary["status"] == "completed" and not summary["errors"], case
                assert int(entries[2]["ret_val"], 16) > 0, case
                assert not any(item["event"] == "dll_process_attach"
                               for item in report["dll_initialization_events"]), case
            elif kind == "toolhelp_foreign":
                assert summary["status"] == "completed" and not summary["errors"], case
                parent_snapshots = [item for item in entries[1]["events"]
                                    if str(item.get("api_name", "")).endswith(
                                        "CreateToolhelp32Snapshot")]
                assert len(parent_snapshots) == 1, case
                handle = parent_snapshots[0]["ret_val"]
                assert handle not in ("0x0", "0xffffffff", "0xffffffffffffffff"), case
                assert entries[2]["ret_val"] == "0x0", case
                for operation in ("Module32FirstW", "CloseHandle"):
                    calls = [item for item in entries[2]["events"]
                             if str(item.get("api_name", "")).endswith(operation)]
                    assert len(calls) == 1, case
                    assert calls[0]["ret_val"] == "0x0", case
                    assert calls[0]["args"][0] == handle, case
            elif kind.startswith("toolhelp_"):
                assert summary["status"] == "completed" and not summary["errors"], case
                own_base = 0x1A0000000 if arch == "x64" else 0x500000
                parent_image = 0x140000000 if arch == "x64" else 0x400000
                if kind == "toolhelp_next":
                    assert int(entries[2]["ret_val"], 16) not in (
                        0, own_base, parent_image), case
                else:
                    expected_base = parent_image if kind == "toolhelp_parent" else own_base
                    assert entries[2]["ret_val"] == hex(expected_base), case
                operation = ("Module32NextW" if kind == "toolhelp_next"
                             else "CloseHandle")
                for operation in ("CreateToolhelp32Snapshot", operation):
                    calls = [item for item in entries[2]["events"]
                             if str(item.get("api_name", "")).endswith(operation)]
                    assert len(calls) == 1 and calls[0]["ret_val"] != "0x0", case
            else:
                assert entries[2]["ret_val"] == "0x0", case
                assert not any(item["event"] == "dll_process_attach"
                               for item in report["dll_initialization_events"]), case
                if kind in ("free", "proc"):
                    assert summary["status"] == "partial", case
                    assert len(summary["errors"]) == 1, case
                    assert "DLL handle belongs to different guest process" in summary["errors"][0], case
                else:
                    assert summary["status"] == "completed" and not summary["errors"], case
            print(f"{case}: {summary['status']}; child handle boundary and bytes verified")


if __name__ == "__main__":
    verify(Path(sys.argv[1]).resolve())
