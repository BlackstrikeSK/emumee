"""Check that the packaged local dashboard shows broker audit events."""

from __future__ import annotations

import socket
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path


root = Path(__file__).resolve().parents[1]
exe = root / "dist" / "Emumee" / "Emumee.exe"
runs_root = root / "output" / "journal-dashboard-package" / "winhttp_chunked_x86"
run_dir = sorted((path for path in runs_root.iterdir() if path.is_dir()), reverse=True)[0]
with socket.socket() as listener:
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
process = subprocess.Popen(
    [str(exe), "dashboard", "--output", str(runs_root), "--port", str(port)],
    cwd=root, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
)
try:
    deadline = time.monotonic() + 10
    url = f"http://127.0.0.1:{port}/runs/{run_dir.name}"
    while True:
        if process.poll() is not None:
            raise AssertionError("Packaged dashboard exited before serving")
        try:
            with urllib.request.urlopen(url, timeout=1) as response:
                page = response.read(2 * 1024 * 1024).decode("utf-8")
            break
        except (urllib.error.URLError, TimeoutError):
            if time.monotonic() >= deadline:
                raise AssertionError("Packaged dashboard did not become ready")
            time.sleep(0.05)
    if "Network broker events" not in page or "http_request_attempt" not in page:
        raise AssertionError("Packaged dashboard omitted broker audit events")
    print("packaged dashboard: broker attempt visible over loopback")
finally:
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
