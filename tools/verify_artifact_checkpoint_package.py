"""Exercise artifact recovery when a harmless managed guest is forcibly stopped."""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROJECT = ROOT / "tests" / "fixtures" / "ManagedCheckpointTimeout"
OUTPUT = (ROOT / "output").resolve()
subprocess.run(["dotnet", "build", str(PROJECT / "ManagedCheckpointTimeout.csproj"),
                "-c", "Release"], cwd=ROOT, check=True,
               capture_output=True, text=True, timeout=120)
sample = PROJECT / "bin" / "Release" / "net8.0" / "ManagedCheckpointTimeout.dll"
with tempfile.TemporaryDirectory(dir=OUTPUT, prefix="checkpoint-package-") as folder:
    work = Path(folder).resolve()
    if not work.is_relative_to(OUTPUT):
        raise RuntimeError("Temporary checkpoint test escaped the output directory")
    result = subprocess.run([str(ROOT / "dist" / "Emumee" / "Emumee.exe"),
                             "run", str(sample), "--timeout", "1",
                             "--max-instructions", "1000000000", "--offline-replay",
                             "--output", str(work / "runs")],
                            cwd=ROOT, capture_output=True, text=True, timeout=60)
    envelope = json.loads(result.stdout)
    summary = json.loads(Path(envelope["report"]).read_text(encoding="utf-8"))
    print(json.dumps({"status": summary["status"],
                      "guest_trace_complete": summary.get("guest_trace_complete"),
                      "artifact_checkpoint_recovered": summary.get("artifact_checkpoint_recovered"),
                      "artifacts": summary.get("artifacts", []),
                      "errors": summary.get("errors", [])}, indent=2))
    assert summary["status"] == "timeout", summary
    assert summary.get("guest_trace_complete") is False, summary
    assert summary.get("artifact_checkpoint_recovered") is True, summary
    assert any((Path(envelope["report"]).parent / "artifacts" / item["file"]).read_bytes()
               == b"harmless checkpoint payload" for item in summary["artifacts"]), summary
