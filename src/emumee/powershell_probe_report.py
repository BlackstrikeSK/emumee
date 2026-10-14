"""Save fixed PowerShell feasibility evidence in the normal dashboard envelope."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import uuid
from pathlib import Path

from .reports import ENGINE_INTEGRITY, MAX_ENGINE_BYTES, valid_summary


def save_probe_run(report: dict, root: Path, source: str) -> Path:
    if report.get("passed") is not True:
        raise ValueError("Only a verified fixed probe can be saved as a dashboard run")
    probe = report["probe"]
    now = dt.datetime.now(dt.timezone.utc)
    run_id = now.strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:8]
    limitations = report["limitations"]
    engine = {"command_events": probe["command_events"],
              "command_capture": {"complete": False,
                                  "source": "engine_debugger_command_processor",
                                  "dropped_events": probe["dropped_command_events"],
                                  "limitations": limitations},
              "fixed_probe_source": source, "probe_evidence": report}
    payload = json.dumps(engine, indent=2).encode("utf-8")
    if len(payload) > MAX_ENGINE_BYTES:
        raise ValueError("PowerShell probe evidence exceeds the engine report limit")
    summary = {"id": run_id, "status": "partial", "engine": "powershell-container-probe",
               "sample": {"name": "Fixed PowerShell command-capture probe", "kind": "powershell-probe",
                          "managed": True, "architecture": "x64",
                          "sha256": hashlib.sha256(source.encode("utf-8")).hexdigest()},
               "started_at": report.get("execution_started_at", now.isoformat()),
               "finished_at": report.get("execution_finished_at", now.isoformat()),
               "guest_exit_code": 0, "completion_reason": "entry_return",
               "guest_trace_complete": False, "errors": [], "artifacts": [],
               "engine_report": "engine-report.json", "engine_report_size": len(payload),
               "engine_report_sha256": hashlib.sha256(payload).hexdigest(),
               "console_output": {"stdout": "\n".join(probe["values"]), "stderr": "",
                                  "stdout_truncated": False, "stderr_truncated": False},
               "run_manifest": {"probe_only": True, "execution_boundary": "docker-linux-vm",
                                "image": report["image"],
                                "engine_report_integrity": ENGINE_INTEGRITY}}
    if not valid_summary(summary):
        raise ValueError("Invalid PowerShell probe report envelope")
    root.mkdir(parents=True, exist_ok=True)
    run = root / run_id
    run.mkdir()
    (run / "engine-report.json").write_bytes(payload)
    (run / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return run
