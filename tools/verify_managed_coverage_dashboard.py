"""Check packaged managed coverage counts, extraction, and loopback display."""

from __future__ import annotations

import hashlib
import json
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
EXE = PROJECT / "dist" / "Emumee" / "Emumee.exe"
DEFAULT_RUNS = PROJECT / "output" / "managed-coverage-package"


def main(runs_root: Path = DEFAULT_RUNS) -> None:
    reports = list(runs_root.glob("*/summary.json"))
    assert len(reports) == 1, "expected one packaged managed report"
    run_dir = reports[0].parent
    summary = json.loads(reports[0].read_text(encoding="utf-8"))
    engine = json.loads((run_dir / "engine-report.json").read_text(encoding="utf-8"))
    coverage = summary["cil_coverage"]
    assert summary["status"] == "completed"
    assert summary["engine"] == "emumee-cil"
    assert summary["network_broker_complete"] is True
    assert engine["cil_coverage"] == coverage
    assert coverage["opcode_attempts"] > 0
    assert coverage["framework_calls"] > 0
    assert coverage["untracked_framework_calls"] == 0
    assert sum(item["count"] for item in coverage["top_opcodes"]) + coverage[
        "other_opcode_attempts"] == coverage["opcode_attempts"]
    assert sum(item["count"] for item in coverage["top_framework_calls"]) + coverage[
        "other_framework_calls"] == coverage["framework_calls"]
    assert any(item["opcode"] == "call" for item in coverage["top_opcodes"])
    assert len(summary["artifacts"]) == 4
    for item in summary["artifacts"]:
        payload = (run_dir / "artifacts" / item["file"]).read_bytes()
        assert len(payload) == item["size"]
        assert hashlib.sha256(payload).hexdigest() == item["sha256"]
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    process = subprocess.Popen(
        [str(EXE), "dashboard", "--output", str(runs_root), "--port", str(port)],
        cwd=PROJECT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    try:
        deadline = time.monotonic() + 10
        url = f"http://127.0.0.1:{port}/runs/{run_dir.name}"
        while True:
            if process.poll() is not None:
                raise AssertionError("packaged dashboard exited before serving")
            try:
                with urllib.request.urlopen(url, timeout=1) as response:
                    page = response.read(2 * 1024 * 1024).decode("utf-8")
                break
            except (urllib.error.URLError, TimeoutError):
                if time.monotonic() >= deadline:
                    raise AssertionError("packaged dashboard did not become ready")
                time.sleep(0.05)
        for expected in ("Observed CIL opcodes", "Observed framework calls",
                         "do not prove", "CIL opcode attempts"):
            assert expected in page, f"missing dashboard text: {expected}"
        assert "Observed WinAPI calls" not in page
        print("packaged managed coverage: counts, four artifacts, and dashboard verified")
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


if __name__ == "__main__":
    main(Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else DEFAULT_RUNS)
