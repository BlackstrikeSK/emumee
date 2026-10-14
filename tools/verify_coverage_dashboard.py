"""Check the packaged loopback dashboard's observed API coverage display."""

from __future__ import annotations

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
DEFAULT_RUNS = PROJECT / "output" / "coverage-package" / "signature_stub_x86"


def main(runs_root: Path = DEFAULT_RUNS) -> None:
    reports = list(runs_root.glob("*/summary.json"))
    assert len(reports) == 1, "expected one packaged signature-only report"
    run_dir = reports[0].parent
    summary = json.loads(reports[0].read_text(encoding="utf-8"))
    coverage = summary["api_coverage"]
    assert summary["status"] == "partial"
    assert summary["network_broker_complete"] is True
    assert coverage["api_calls"] > 0
    assert coverage["observed_apis"] >= 1
    assert any(item["api"] == "kernel32.MoveFileWithProgressW" and item["count"] == 1
               and item["signature_only_count"] == 1
               for item in coverage["observed_calls"])
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
        for expected in ("Observed WinAPI calls", "kernel32.MoveFileWithProgressW",
                         "Signature-only API calls", "does not prove"):
            assert expected in page, f"missing dashboard text: {expected}"
        print("packaged dashboard: observed API and signature-only coverage visible")
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


if __name__ == "__main__":
    main(Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else DEFAULT_RUNS)
