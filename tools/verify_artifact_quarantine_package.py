"""Exercise failed-run artifact quarantine through the packaged dashboard."""

from __future__ import annotations

import json
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXE = ROOT / "dist" / "Emumee" / "Emumee.exe"
LEFT = "20261013T120000Z-1234abcd"
RIGHT = "20261013T120001Z-1234abcd"


def fetch(url: str) -> tuple[int, str]:
    try:
        with urllib.request.urlopen(url, timeout=2) as response:
            return response.status, response.read(2 * 1024 * 1024).decode("utf-8")
    except urllib.error.HTTPError as exc:
        return exc.code, ""


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="emumee-artifact-view-") as folder:
        root = Path(folder)
        fake = {"sha256": "f" * 64, "size": 4, "kind": "pe",
                "source": "file_write", "guest_path": r"C:\fake.exe",
                "file": "f" * 20 + ".pe"}
        for run_id, artifacts in ((LEFT, [fake]), (RIGHT, [])):
            run = root / run_id
            run.mkdir()
            (run / "summary.json").write_text(json.dumps({
                "id": run_id, "sample": {"name": "fixture.exe"},
                "status": "failed", "artifacts": artifacts, "errors": []}),
                encoding="utf-8")
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        server = subprocess.Popen(
            [str(EXE), "dashboard", "--output", str(root), "--port", str(port)],
            cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        try:
            base = f"http://127.0.0.1:{port}"
            deadline = time.monotonic() + 15
            while True:
                if server.poll() is not None:
                    raise AssertionError("packaged dashboard exited before serving")
                try:
                    status, detail = fetch(f"{base}/runs/{LEFT}")
                    break
                except (urllib.error.URLError, TimeoutError):
                    if time.monotonic() >= deadline:
                        raise AssertionError("packaged dashboard did not become ready")
                    time.sleep(0.05)
            assert status == 200
            assert "Artifact claims could not be verified" in detail
            assert fake["sha256"] not in detail
            status, filtered = fetch(f"{base}/?kind=pe")
            assert status == 200 and LEFT not in filtered
            status, comparison = fetch(
                f"{base}/compare?left={LEFT}&right={RIGHT}&format=json")
            assert status == 200
            diff = json.loads(comparison)
            assert diff["artifact_changes"]["only_left"] == []
            assert diff["artifact_evidence"]["left"] == "unverified"
            status, _ = fetch(f"{base}/runs/{LEFT}/artifacts/{fake['file']}")
            assert status == 404
            print("packaged dashboard quarantined fabricated failed-run artifact claims")
        finally:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=5)


if __name__ == "__main__":
    main()
