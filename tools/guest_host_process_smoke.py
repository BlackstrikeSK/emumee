"""Attempt harmless host cmd execution from x86/x64 guest CreateProcessW."""

from __future__ import annotations

import json
import subprocess
import sys
import uuid
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))
from tests.fixtures.build_native import build_host_process_probe  # noqa: E402


EXE = PROJECT / "dist" / "Emumee" / "Emumee.exe"


def main() -> None:
    root = PROJECT / "output" / "host-process-package" / uuid.uuid4().hex
    root.mkdir(parents=True)
    marker = root / "host-marker.txt"
    try:
        for arch, machine in (("x86", 0x14C), ("x64", 0x8664)):
            fixture = root / f"host_process_probe_{arch}.exe"
            fixture.write_bytes(build_host_process_probe(machine, str(marker)))
            output = root / arch
            result = subprocess.run(
                [str(EXE), "run", str(fixture), "--output", str(output), "--timeout", "30"],
                cwd=PROJECT, capture_output=True, text=True, timeout=50,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            assert result.returncode == 1, f"{arch} returned {result.returncode}: {result.stderr}"
            summaries = list(output.glob("*/summary.json"))
            assert len(summaries) == 1, f"{arch} did not write one summary"
            run_dir = summaries[0].parent
            summary = json.loads(summaries[0].read_text(encoding="utf-8"))
            report = json.loads((run_dir / "engine-report.json").read_text(encoding="utf-8"))
            assert summary["status"] == "partial", f"{arch}: {summary['status']}"
            assert summary["network_broker_complete"] is True
            assert summary["artifacts"] == []
            creates = [event for event in report["virtual_process_events"]
                       if event.get("event") == "virtual_process_create"]
            assert len(creates) == 1
            assert creates[0]["success"] is False
            assert creates[0]["application"] == r"C:\Windows\System32\cmd.exe"
            assert creates[0]["reason"] == "executable absent from guest filesystem"
            assert str(marker) in creates[0]["command_line"]
            assert any("executable unavailable in guest" in error
                       for error in summary["errors"])
            assert not marker.exists(), f"guest {arch} created a host marker"
        print(f"packaged guest host-process probe: x86/x64 denied; evidence in {root}")
    finally:
        marker.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
