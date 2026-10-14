"""Check packaged guest parent/child process-handle isolation."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from emumee.reports import verify_artifact_manifest


def verify(root: Path) -> None:
    fixtures = Path(__file__).resolve().parents[1] / "tests" / "fixtures"
    for arch in ("x86", "x64"):
        supplied = fixtures / f"child_parent_module_{arch}" / f"companion_{arch}.dll"
        for kind in ("foreign", "open", "closed"):
            case = f"child_parent_process_handle_{kind}_{arch}"
            summaries = list((root / case).glob("*/summary.json"))
            assert len(summaries) == 1, (case, summaries)
            run = summaries[0].parent
            summary = json.loads(summaries[0].read_text(encoding="utf-8"))
            submitted = (fixtures / f"{case}.exe").read_bytes()
            assert (run / "input.pe").read_bytes() == submitted, case
            assert (run / "inputs" / supplied.name).read_bytes() == supplied.read_bytes(), case
            assert summary["sample"]["sha256"] == hashlib.sha256(submitted).hexdigest(), case
            assert summary["network_broker_complete"] is True, case
            journal = json.loads((run / "network-broker.json").read_text(encoding="utf-8"))
            assert journal[-1] == {"event": "broker_closed"}, case
            assert verify_artifact_manifest(run, summary["artifacts"]), case
            assert not summary["api_coverage"]["signature_only_calls"], case
            child = submitted[0xA00:0x1000]
            embedded = [item for item in summary["artifacts"]
                        if item["source"] == "embedded_input@0xa00"]
            assert len(embedded) == 1, case
            assert (run / "artifacts" / embedded[0]["file"]).read_bytes() == child, case

            report = json.loads((run / summary["engine_report"]).read_text(encoding="utf-8"))
            entries = report["entry_points"]
            assert len(entries) == 3 and entries[0]["pid"] == entries[1]["pid"], case
            assert entries[2]["pid"] != entries[1]["pid"], case
            events = report["virtual_process_events"]
            opens = [event for event in events if event["event"] == "virtual_process_open"]
            reads = [event for event in events if event["event"] == "virtual_process_memory_read"]
            assert len(reads) == (2 if kind == "closed" else 1), case
            assert len(opens) == (1 if kind == "foreign" else 2), case
            assert all(event["success"] and not event["inherit"] for event in opens), case
            assert entries[2]["ret_val"] == ("0x1" if kind == "open" else "0x0"), case
            if kind == "foreign":
                assert not summary["errors"] and summary["status"] == "completed", case
                assert not reads[0]["success"] and reads[0]["reason"] == "invalid process handle", case
                assert reads[0]["handle"] == opens[0]["handle"], case
                denied_close = [event for event in events
                                if event["event"] == "virtual_process_handle_close"]
                assert len(denied_close) == 1, case
                assert denied_close[0]["handle"] == opens[0]["handle"], case
                assert denied_close[0]["reason"] == "different guest process", case
            else:
                assert summary["errors"] == [
                    "kernel32.OpenProcess: guest parent process access control not modeled"], case
                assert opens[0]["handle"] != opens[1]["handle"], case
                assert reads[0]["success"] and reads[0]["handle"] == opens[1]["handle"], case
                closed = [event for event in events if event["event"] == "virtual_process_close"]
                assert len(closed) == 1 and closed[0]["success"], case
                assert closed[0]["handle"] == opens[1]["handle"], case
                if kind == "closed":
                    assert not reads[1]["success"], case
                    assert reads[1]["reason"] == "invalid process handle", case
                    assert reads[1]["handle"] == opens[1]["handle"], case
            print(f"{case}: modeled handle ownership, bytes, artifacts, broker verified")

        for opened, created, parent_closed in (
                (False, False, False), (False, True, False),
                (True, False, False), (True, True, False),
                (True, True, True)):
            stem = ("child_parent_process_handle_inherit_closed" if parent_closed else
                    f"child_parent_process_handle_inherit_{int(opened)}{int(created)}")
            case = f"{stem}_{arch}"
            summaries = list((root / case).glob("*/summary.json"))
            assert len(summaries) == 1, (case, summaries)
            run = summaries[0].parent
            summary = json.loads(summaries[0].read_text(encoding="utf-8"))
            submitted = (fixtures / f"{case}.exe").read_bytes()
            assert (run / "input.pe").read_bytes() == submitted, case
            assert (run / "inputs" / supplied.name).read_bytes() == supplied.read_bytes(), case
            assert summary["sample"]["sha256"] == hashlib.sha256(submitted).hexdigest(), case
            assert summary["network_broker_complete"] is True, case
            journal = json.loads((run / "network-broker.json").read_text(encoding="utf-8"))
            assert journal[-1] == {"event": "broker_closed"}, case
            assert verify_artifact_manifest(run, summary["artifacts"]), case
            assert not summary["api_coverage"]["signature_only_calls"], case
            assert not summary["errors"] and summary["status"] == "completed", case
            embedded = [item for item in summary["artifacts"]
                        if item["source"] == "embedded_input@0xa00"]
            assert len(embedded) == 1, case
            assert (run / "artifacts" / embedded[0]["file"]).read_bytes() == submitted[0xA00:0x1000], case
            report = json.loads((run / summary["engine_report"]).read_text(encoding="utf-8"))
            entries = report["entry_points"]
            assert len(entries) == 3 and entries[0]["pid"] == entries[1]["pid"], case
            assert entries[2]["pid"] != entries[1]["pid"], case
            assert entries[2]["ret_val"] == ("0x1" if opened and created else "0x0"), case
            events = report["virtual_process_events"]
            opens = [item for item in events if item["event"] == "virtual_process_open"]
            creates = [item for item in events if item["event"] == "virtual_process_create"]
            reads = [item for item in events if item["event"] == "virtual_process_memory_read"]
            closes = [item for item in events if item["event"] == "virtual_process_close"]
            assert len(opens) == len(creates) == len(reads) == 1, case
            assert opens[0]["inherit"] == opened, case
            assert creates[0]["inherited_process_handles"] == int(opened and created), case
            assert reads[0]["handle"] == opens[0]["handle"], case
            assert reads[0]["success"] == (opened and created), case
            assert len(closes) == (2 if parent_closed else int(opened and created)), case
            assert all(item["success"] and item["handle"] == opens[0]["handle"]
                       for item in closes), case
            print(f"{case}: inheritance flags, lifetime, artifacts, broker verified")

        for inheritable in (False, True):
            case = f"child_parent_process_handle_set_inherit_{int(inheritable)}_{arch}"
            summaries = list((root / case).glob("*/summary.json"))
            assert len(summaries) == 1, (case, summaries)
            run = summaries[0].parent
            summary = json.loads(summaries[0].read_text(encoding="utf-8"))
            submitted = (fixtures / f"{case}.exe").read_bytes()
            assert (run / "input.pe").read_bytes() == submitted, case
            assert (run / "inputs" / supplied.name).read_bytes() == supplied.read_bytes(), case
            assert summary["sample"]["sha256"] == hashlib.sha256(submitted).hexdigest(), case
            assert not summary["errors"] and summary["status"] == "completed", case
            assert summary["network_broker_complete"] is True, case
            journal = json.loads((run / "network-broker.json").read_text(encoding="utf-8"))
            assert journal[-1] == {"event": "broker_closed"}, case
            assert verify_artifact_manifest(run, summary["artifacts"]), case
            assert not summary["api_coverage"]["signature_only_calls"], case
            embedded = [item for item in summary["artifacts"]
                        if item["source"] == "embedded_input@0xa00"]
            assert len(embedded) == 1, case
            assert (run / "artifacts" / embedded[0]["file"]).read_bytes() == submitted[0xA00:0x1000], case
            report = json.loads((run / summary["engine_report"]).read_text(encoding="utf-8"))
            entries = report["entry_points"]
            assert len(entries) == 3 and entries[0]["pid"] == entries[1]["pid"], case
            assert entries[2]["pid"] != entries[1]["pid"], case
            assert entries[2]["ret_val"] == ("0x1" if inheritable else "0x0"), case
            events = report["virtual_process_events"]
            opens = [item for item in events if item["event"] == "virtual_process_open"]
            changed = [item for item in events if item["event"] == "virtual_handle_information_set"]
            creates = [item for item in events if item["event"] == "virtual_process_create"]
            reads = [item for item in events if item["event"] == "virtual_process_memory_read"]
            assert len(opens) == len(changed) == len(creates) == len(reads) == 1, case
            assert opens[0]["inherit"] is not inheritable, case
            assert changed[0]["success"] and changed[0]["result_flags"] == int(inheritable), case
            assert creates[0]["inherited_process_handles"] == int(inheritable), case
            assert reads[0]["handle"] == opens[0]["handle"], case
            assert reads[0]["success"] == inheritable, case
            print(f"{case}: flag mutation, child outcome, artifacts, broker verified")


if __name__ == "__main__":
    verify(Path(sys.argv[1]).resolve())
