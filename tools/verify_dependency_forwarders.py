"""Verify packaged dynamic DLL import tables that follow unloaded forwarders."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from emumee.reports import verify_artifact_manifest


def verify(root: Path) -> None:
    fixtures = Path(__file__).resolve().parents[1] / "tests" / "fixtures"
    for arch in ("x86", "x64"):
        cases: list[tuple[str, str, list[Path], list[str], str]] = []
        for mode in ("valid", "missing_reloc", "failed_attach", "chain"):
            folder = fixtures / f"forwarded_implicit_{mode}"
            stems = ("companion", "leaf", "terminal") if mode == "chain" else (
                "companion", "leaf")
            cases.append((f"supplied_{mode}_{arch}", f"dropped_dependency_dll_{arch}",
                          [folder / f"{stem}_{arch}.dll" for stem in stems],
                          [f"{stem}_{arch}" for stem in stems], mode))
        terminal = fixtures / "forwarded_implicit_chain" / f"terminal_{arch}.dll"
        companion = fixtures / "forwarded_dependency_guest" / f"companion_{arch}.dll"
        cases.append((f"guest_import_{arch}", f"dropped_guest_import_forwarder_{arch}",
                      [terminal], ["guest-leaf", f"terminal_{arch}"], "valid"))
        for mode in ("valid", "missing_reloc", "failed_attach"):
            cases.append((f"import_guest_{mode}_{arch}",
                          f"dropped_import_guest_forwarder_{mode}_{arch}",
                          [companion], [f"companion_{arch}", "guest-leaf"], mode))
        cases.append((f"guest_import_release_{arch}",
                      f"dropped_guest_import_forwarder_release_{arch}",
                      [terminal], ["guest-leaf", f"terminal_{arch}"], "release"))
        cases.append((f"import_guest_release_{arch}",
                      f"dropped_import_guest_forwarder_release_{arch}",
                      [companion], [f"companion_{arch}", "guest-leaf"], "release"))

        for case, sample_stem, dlls, expected_maps, mode in cases:
            summaries = list((root / case).glob("*/summary.json"))
            assert len(summaries) == 1, (case, summaries)
            run = summaries[0].parent
            summary = json.loads(summaries[0].read_text(encoding="utf-8"))
            submitted = (fixtures / f"{sample_stem}.exe").read_bytes()
            assert (run / "input.pe").read_bytes() == submitted, case
            assert summary["sample"]["sha256"] == hashlib.sha256(submitted).hexdigest(), case
            for dll in dlls:
                assert (run / "inputs" / dll.name).read_bytes() == dll.read_bytes(), (case, dll)
            assert summary["network_broker_complete"] is True, case
            journal = json.loads((run / "network-broker.json").read_text(encoding="utf-8"))
            assert journal[-1] == {"event": "broker_closed"}, case
            assert verify_artifact_manifest(run, summary["artifacts"]), case
            assert not summary["api_coverage"]["signature_only_calls"], case
            report = json.loads((run / summary["engine_report"]).read_text(encoding="utf-8"))
            entries = report["entry_points"]
            assert len(entries) == 1 and not entries[0].get("error"), case
            events = summary["dll_initialization_events"]
            assert events[0]["event"] == "virtual_dll_load" and events[0]["mapped"], case

            def artifact_bytes(source: str) -> list[bytes]:
                return [(run / "artifacts" / item["file"]).read_bytes()
                        for item in summary["artifacts"] if item["source"] == source]

            stage = submitted[0xA00:0x1000]
            assert stage in artifact_bytes("embedded_input@0xa00"), case
            assert stage in artifact_bytes("guest_dll_load"), case
            guest_leaf = submitted[0x1000:0x1600] if "guest-leaf" in expected_maps else None
            if guest_leaf is not None:
                assert guest_leaf in artifact_bytes("embedded_input@0x1000"), case
            maps = [event["module"] for event in events if event["event"] == "dll_dependency_map"]
            mapped_bases = [int(event["base"], 16) for event in events
                            if event["event"] == "dll_dependency_map"]
            assert len(mapped_bases) == len(set(mapped_bases)), case
            attaches = [event["module"] for event in events
                        if event["event"] == "dll_process_attach"]
            if mode == "missing_reloc":
                assert summary["status"] == "partial", case
                assert entries[0]["ret_val"] == "0x0", case
                assert maps == expected_maps[:1] and not attaches, case
                assert any("dependency" in error and ("relocation" in error or
                           "cannot be mapped" in error) for error in summary["errors"]), case
                if guest_leaf is not None:
                    assert guest_leaf not in artifact_bytes("guest_dll_load"), case
            elif mode == "failed_attach":
                assert summary["status"] == "completed" and not summary["errors"], case
                assert entries[0]["ret_val"] == "0x0", case
                assert maps == expected_maps, case
                assert attaches == [expected_maps[-1]], case
                assert any(event["event"] == "dll_process_detach" for event in events), case
            else:
                assert summary["status"] == "completed" and not summary["errors"], case
                assert entries[0]["ret_val"] == ("0x1" if mode == "release" else "0x2a"), case
                assert maps == expected_maps, case
                assert attaches == [*reversed(expected_maps), "guest-stage"], case
                if guest_leaf is not None:
                    assert guest_leaf in artifact_bytes("guest_dll_load"), case
                if mode == "release":
                    detached = [event["module"] for event in events
                                if event["event"] == "dll_process_detach"]
                    assert detached == ["guest-stage", *expected_maps], case
            print(f"{case}: {summary['status']}; inputs, events, artifacts, broker verified")


if __name__ == "__main__":
    verify(Path(sys.argv[1]).resolve())
