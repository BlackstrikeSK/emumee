"""Kill a harmless packaged broker after a denied request and recover its log."""

from __future__ import annotations

import json
import tempfile
import threading
import time
import uuid
from pathlib import Path

from emumee.appcontainer import AppContainer
from emumee.cli import _recover_network_report
from emumee.job import WorkerJob
from emumee.network import NetworkDenied
from emumee.networkipc import BROKER_JOURNAL, FileRPCClient


root = Path(__file__).resolve().parents[1]
exe = root / "dist" / "Emumee" / "Emumee.exe"
with tempfile.TemporaryDirectory(dir=root / "output") as folder:
    run_dir = Path(folder)
    with (run_dir / BROKER_JOURNAL).open("x+b", buffering=0) as journal:
        with AppContainer(moniker=f"Emumee.BrokerCrashProbe.{uuid.uuid4().hex}",
                          network=True, delete_on_close=True) as box, WorkerJob(256) as job:
            box.grant(exe.parent, "RX")
            box.grant(run_dir, "M")
            result = {}

            def launch() -> None:
                try:
                    result["exit"] = box.launch(
                        [str(exe), "_network_broker", str(run_dir)], run_dir, 20, job=job)
                except (OSError, RuntimeError, TimeoutError) as exc:
                    result["error"] = str(exc)

            thread = threading.Thread(target=launch, daemon=True)
            try:
                thread.start()
                deadline = time.monotonic() + 10
                while not (run_dir / "broker-ready").is_file():
                    if not thread.is_alive():
                        raise AssertionError(f"Broker exited before ready: {result}")
                    if time.monotonic() >= deadline:
                        raise AssertionError("Broker did not become ready")
                    time.sleep(0.02)
                client = FileRPCClient(run_dir)
                try:
                    try:
                        client.call("http_fetch", url="http://127.0.0.1/",
                                    method="GET", body="", headers={})
                    except NetworkDenied:
                        pass
                    else:
                        raise AssertionError("Broker allowed localhost")
                finally:
                    client.close()
                job.terminate()
                thread.join(timeout=5)
                if thread.is_alive():
                    raise AssertionError("Broker process survived job termination")
            finally:
                job.terminate()
                thread.join(timeout=5)
                box.revoke(run_dir)
                box.revoke(exe.parent)
        reason = _recover_network_report(run_dir, journal)
        if not reason or "no close marker" not in reason:
            raise AssertionError(f"Expected incomplete journal: {reason}")
        events = json.loads((run_dir / "network-broker.json").read_text(encoding="utf-8"))
        if not any(item.get("event") == "http_request_attempt" and
                   item.get("url") == "http://127.0.0.1/" for item in events):
            raise AssertionError("Denied destination was not recovered")
        if any(item.get("event") == "http_request" for item in events):
            raise AssertionError("Broker unexpectedly connected to localhost")
        print("packaged broker termination: denied destination recovered; log marked incomplete")
