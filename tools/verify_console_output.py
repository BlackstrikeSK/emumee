"""Verify packaged guest console capture and read-only dashboard rendering."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from emumee.dashboard import create_app
from emumee.reports import valid_summary


EXPECTED = {
    "console_output_x86.exe": ("native stdout\nwide console ✓\n", "native stderr\n"),
    "console_output_x64.exe": ("native stdout\nwide console ✓\n", "native stderr\n"),
    "ManagedHello.dll": ("emumee managed fixture\n", ""),
    "ManagedConsole.dll": ("managed stdout\n", "managed stderr\n"),
}


def verify(root: Path) -> str:
    summaries = list(root.glob("*/summary.json"))
    if len(summaries) != 1:
        raise AssertionError(f"expected exactly one run under {root}")
    path = summaries[0]
    summary = json.loads(path.read_text(encoding="utf-8"))
    name = summary["sample"]["name"]
    expected_stdout, expected_stderr = EXPECTED[name]
    expected = {"stdout": expected_stdout, "stderr": expected_stderr,
                "stdout_truncated": False, "stderr_truncated": False}
    if not valid_summary(summary) or summary["status"] != "completed" or summary["errors"]:
        raise AssertionError(f"invalid or incomplete run: {name}")
    if summary["console_output"] != expected:
        raise AssertionError(f"summary console output mismatch: {name}")
    report = json.loads((path.parent / "engine-report.json").read_text(encoding="utf-8"))
    if report["console_output"] != expected:
        raise AssertionError(f"engine console output mismatch: {name}")
    if summary.get("network_broker_complete") is not True:
        raise AssertionError(f"broker log incomplete: {name}")
    response = create_app(root).test_client().get(f"/runs/{summary['id']}")
    page = response.get_data(as_text=True)
    if response.status_code != 200 or expected_stdout.strip() not in page:
        raise AssertionError(f"dashboard stdout missing: {name}")
    if expected_stderr and expected_stderr.strip() not in page:
        raise AssertionError(f"dashboard stderr missing: {name}")
    return name


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit("Usage: verify_console_output.py OUTPUT_ROOT [OUTPUT_ROOT ...]")
    for argument in sys.argv[1:]:
        print(f"{verify(Path(argument).resolve())}: console summary, report, dashboard, broker verified")
