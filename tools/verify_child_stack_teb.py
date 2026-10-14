"""Verify packaged child stack separation and TEB segment reset probes."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from emumee.reports import verify_artifact_manifest


def verify(root: Path) -> None:
    for arch in ("x86", "x64"):
        for kind in ("stack", "parent_stack", "teb_leak"):
            name = f"child_{kind}_read_{arch}" if kind != "teb_leak" else (
                f"child_teb_leak_{arch}")
            summaries = list((root / name).glob("*/summary.json"))
            assert len(summaries) == 1, (name, summaries)
            run = summaries[0].parent
            summary = json.loads(summaries[0].read_text(encoding="utf-8"))
            report = json.loads((run / summary["engine_report"]).read_text(encoding="utf-8"))
            broker = json.loads((run / "network-broker.json").read_text(encoding="utf-8"))
            assert summary["sample"]["sha256"] == hashlib.sha256(
                (run / "input.pe").read_bytes()).hexdigest(), name
            assert summary["network_broker_complete"] is True, name
            assert broker[-1] == {"event": "broker_closed"}, name
            assert verify_artifact_manifest(run, summary["artifacts"]), name
            assert not summary["api_coverage"]["signature_only_calls"], name
            entries = report["entry_points"]
            assert len(entries) == 2 and not entries[0].get("error"), name
            events = report["virtual_process_events"]
            writes = [event for event in events
                      if event["event"] == "virtual_process_memory_write"]
            assert len(writes) == 1 and writes[0]["success"], name
            stacks = [event for event in events
                      if event["event"] == "virtual_process_stack"]
            resets = [event for event in events
                      if event["event"] == "virtual_process_segment_reset"]
            assert len(stacks) == len(resets) == 1, name
            assert (stacks[0]["address"], stacks[0]["size"]) == (
                0x1400000, 0x100000), name
            assert (resets[0]["address"], resets[0]["size"]) == (
                0x3000, 0x1000), name
            denied = [event for event in events
                      if event["event"] == "virtual_cpu_memory_denied"]
            if kind == "parent_stack":
                assert summary["status"] == "partial" and summary["errors"], name
                assert len(denied) == 1, name
                assert (denied[0]["access"], denied[0]["address"],
                        denied[0]["reason"]) == (
                    "read", 0x12FFF00, "different guest process"), name
                assert denied[0]["pid"] != denied[0]["owner_pid"], name
            else:
                assert summary["status"] == "completed" and not summary["errors"], name
                assert not denied and not entries[1].get("error"), name
                assert entries[1]["ret_val"] == (
                    "0x0" if kind == "teb_leak" else "0xfeedf000"), name
            print(f"{name}: {'parent stack denied' if kind == 'parent_stack' else 'child completed'}; "
                  "broker and artifacts verified")

        name = f"child_remote_thread_{arch}"
        summaries = list((root / name).glob("*/summary.json"))
        assert len(summaries) == 1, (name, summaries)
        run = summaries[0].parent
        summary = json.loads(summaries[0].read_text(encoding="utf-8"))
        report = json.loads((run / summary["engine_report"]).read_text(encoding="utf-8"))
        broker = json.loads((run / "network-broker.json").read_text(encoding="utf-8"))
        assert summary["status"] == "completed" and not summary["errors"], name
        assert summary["sample"]["sha256"] == hashlib.sha256(
            (run / "input.pe").read_bytes()).hexdigest(), name
        assert summary["network_broker_complete"] is True, name
        assert broker[-1] == {"event": "broker_closed"}, name
        assert verify_artifact_manifest(run, summary["artifacts"]), name
        assert not summary["api_coverage"]["signature_only_calls"], name
        entries = report["entry_points"]
        assert len(entries) == 3 and not any(entry.get("error") for entry in entries), name
        assert entries[1]["ret_val"] == "0x0" and entries[2]["ret_val"] == "0x0", name
        events = report["virtual_process_events"]
        stacks = [event for event in events if event["event"] == "virtual_process_stack"]
        resets = [event for event in events
                  if event["event"] == "virtual_process_segment_reset"]
        assert len(stacks) == len(resets) == 2, name
        assert len({event["address"] for event in stacks}) == 2, name
        assert all(event["address"] != 0x1200000 and event["size"] == 0x100000
                   for event in stacks), name
        assert not any(event["event"] == "virtual_cpu_memory_denied"
                       for event in events), name
        print(f"{name}: remote and primary child threads completed on separate stacks; "
              "broker and artifacts verified")

        for mode in ("read", "write"):
            name = f"child_remote_teb_{mode}_{arch}"
            summaries = list((root / name).glob("*/summary.json"))
            assert len(summaries) == 1, (name, summaries)
            run = summaries[0].parent
            summary = json.loads(summaries[0].read_text(encoding="utf-8"))
            report = json.loads((run / summary["engine_report"]).read_text(
                encoding="utf-8"))
            broker = json.loads((run / "network-broker.json").read_text(
                encoding="utf-8"))
            assert summary["status"] == "completed" and not summary["errors"], name
            assert summary["sample"]["sha256"] == hashlib.sha256(
                (run / "input.pe").read_bytes()).hexdigest(), name
            assert summary["network_broker_complete"] is True, name
            assert broker[-1] == {"event": "broker_closed"}, name
            assert verify_artifact_manifest(run, summary["artifacts"]), name
            assert not summary["api_coverage"]["signature_only_calls"], name
            entries = report["entry_points"]
            assert len(entries) == 3 and not any(entry.get("error") for entry in entries), name
            assert [entry["ret_val"] for entry in entries[1:]] == ["0x0", "0x0"], name
            events = report["virtual_process_events"]
            stacks = [event for event in events
                      if event["event"] == "virtual_process_stack"]
            resets = [event for event in events
                      if event["event"] == "virtual_process_segment_reset"]
            assert len(stacks) == len(resets) == 2, name
            assert len({event["address"] for event in stacks}) == 2, name
            assert len({event["tid"] for event in stacks}) == 2, name
            assert not any(event["event"] == "virtual_cpu_memory_denied"
                           for event in events), name
            remote_code = (
                (b"\x65\x8b\x04\x25\0\x02\0\0\xc3" if arch == "x64" else
                 b"\x64\xa1\0\x02\0\0\xc3") if mode == "read" else
                (b"\x65\xc7\x04\x25\0\x02\0\0\x44\x33\x22\x11\x31\xc0\xc3"
                 if arch == "x64" else
                 b"\x64\xc7\x05\0\x02\0\0\x44\x33\x22\x11\x31\xc0\xc3"))
            writes = [event for event in events
                      if event["event"] == "virtual_process_memory_write"]
            assert writes[-1]["sha256"] == hashlib.sha256(remote_code).hexdigest(), name
            print(f"{name}: remote and primary thread TEB bytes isolated; "
                  "broker and artifacts verified")


if __name__ == "__main__":
    verify(Path(sys.argv[1]).resolve())
