"""Probe whether the packaged worker runs inside a less-privileged AppContainer."""

from __future__ import annotations

import json
import shutil
import tempfile
import uuid
from pathlib import Path

from emumee.appcontainer import AppContainer, BundleRunLock
from emumee.job import WorkerJob
from emumee.persona import DEFAULT_PERSONA


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    bundle = root / "dist" / "Emumee"
    exe = bundle / "Emumee.exe"
    with tempfile.TemporaryDirectory(dir=root / "output") as folder:
        run_dir = Path(folder)
        shutil.copyfile(root / "tests" / "fixtures" / "native_x86.exe", run_dir / "input.pe")
        (run_dir / "inputs").mkdir()
        (run_dir / "request.json").write_text(json.dumps({
            "sample_name": "native_x86.exe", "persona": DEFAULT_PERSONA, "dlls": [],
            "timeout": 10, "max_instructions": 100_000,
        }), encoding="utf-8")
        with BundleRunLock(exe), WorkerJob(256) as job, AppContainer(
                moniker=f"Emumee.LpacProbe.{uuid.uuid4().hex}", network=False,
                delete_on_close=True, lpac=True) as box:
            box.grant(bundle, "RX")
            box.grant(run_dir, "M")
            try:
                code = box.launch([str(exe), "_worker", str(run_dir)], run_dir, 20,
                                  job=job)
                summary_path = run_dir / "summary.json"
                if not summary_path.is_file():
                    stage_path = run_dir / "worker-stage.txt"
                    stage = stage_path.read_text(encoding="utf-8") if stage_path.is_file() else None
                    files = sorted(item.name for item in run_dir.iterdir())
                    raise RuntimeError(f"LPAC worker exited {code} before summary; "
                                       f"stage={stage!r}; files={files}")
                summary = json.loads(summary_path.read_text(encoding="utf-8"))
                if code != 0 or summary["status"] != "completed":
                    raise AssertionError(f"LPAC worker failed: {code}, {summary['status']}")
                print("LPAC native worker: completed")
            finally:
                box.revoke(run_dir)
                box.revoke(bundle)


if __name__ == "__main__":
    main()
