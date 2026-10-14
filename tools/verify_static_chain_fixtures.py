"""Verify packaged x86/x64 static companion dependency runs."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "output" / "static-chain-package"


def verify(arch: str, variant: str) -> None:
    label = variant or "plain"
    folder = OUTPUT / f"{label}_{arch}"
    run = sorted(folder.iterdir(), reverse=True)[0]
    summary = json.loads((run / "summary.json").read_text(encoding="utf-8"))
    report = json.loads((run / summary["engine_report"]).read_text(encoding="utf-8"))
    entries = report["entry_points"]
    types = [entry["ep_type"] for entry in entries]
    leaf = f"static_dll_entry_leaf_{arch}"
    middle = f"static_dll_entry_companion_{arch}"
    expected = ([f"static_dll_tls_leaf_{arch}_0"] if "tls_leaf" in variant else [])
    if "no_entry_tls_leaf" not in variant:
        expected.append(leaf)
    if variant not in ("failing_leaf", "failing_tls_leaf"):
        expected.append(middle)
    failed = variant.startswith("failing")
    if failed:
        failed_stem = (f"leaf_{arch}" if variant in ("failing_leaf", "failing_tls_leaf")
                       else f"companion_{arch}")
        if variant == "failing_tls_leaf":
            expected.append(f"static_dll_tls_detach_leaf_{arch}_0")
        expected.append(f"static_dll_detach_{failed_stem}")
        if variant in ("failing_middle_tls_leaf", "failing_middle_no_entry_tls_leaf"):
            expected.append(f"static_dll_tls_detach_leaf_{arch}_0")
        if variant.startswith("failing_middle") and "no_entry" not in variant:
            expected.append(f"static_dll_detach_leaf_{arch}")
    else:
        expected.append("module_entry")
    assert types == expected, (arch, variant, types)
    assert not report.get("errors") and not any(entry.get("error") for entry in entries), (arch, variant)
    assert summary["status"] == ("partial" if failed else "completed"), (arch, variant, summary)
    assert ("module_entry" in types) != failed, (arch, variant, types)
    if failed:
        assert any("Static companion initialization failed" in str(error)
                   for error in summary["errors"]), (arch, variant, summary["errors"])
        assert not any(str(event.get("api_name", "")).endswith("ExitProcess")
                       for entry in entries for event in entry.get("events") or []), (arch, variant)
        detached = [event["module"] for event in report["dll_initialization_events"]
                    if event["event"] == "dll_process_detach"]
        assert detached == [failed_stem] + ([f"leaf_{arch}"]
                                            if variant.startswith("failing_middle")
                                            and "no_entry" not in variant else []), (arch, variant)
        if variant == "failing_middle_no_entry_tls_leaf":
            assert [event["module"] for event in report["dll_initialization_events"]
                    if event["event"] == "dll_tls_detach"] == [f"leaf_{arch}"], (arch, variant)
        if variant in ("failing_leaf", "failing_middle"):
            probed = [entry["ret_val"] for entry in entries
                      if entry["ep_type"].startswith("static_dll_detach_")]
            assert probed == ["0x4d"] * len(detached), (arch, variant, probed)
    else:
        exits = [event for entry in entries for event in entry.get("events") or []
                 if str(event.get("api_name", "")).endswith("ExitProcess")]
        assert exits and exits[-1]["args"] == ["0x2a"], (arch, variant, exits)
        assert not summary["errors"], (arch, variant, summary["errors"])
    print(f"{label}_{arch}: {summary['status']}, {types}")


if __name__ == "__main__":
    for architecture in ("x86", "x64"):
        for fixture_variant in ("", "tls_leaf", "failing_leaf", "failing_middle",
                                "failing_tls_leaf", "failing_middle_tls_leaf",
                                "no_entry_tls_leaf", "failing_middle_no_entry_tls_leaf"):
            verify(architecture, fixture_variant)
