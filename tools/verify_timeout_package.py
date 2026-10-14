"""Bounded harmless guest loop to verify timeout reporting in the packaged CLI."""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

import pefile


root = Path(__file__).resolve().parents[1]
output_root = (root / "output").resolve()
template = (root / "tests" / "fixtures" / "console_output_x64.exe").read_bytes()
pe = pefile.PE(data=template, fast_load=True)
offset = pe.get_offset_from_rva(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
loop = bytearray(template)
loop[offset:offset + 2] = b"\xeb\xfe"  # jmp $; guest CPU only

with tempfile.TemporaryDirectory(dir=output_root, prefix="timeout-package-") as folder:
    work = Path(folder).resolve()
    if not work.is_relative_to(output_root):
        raise RuntimeError("Temporary timeout test escaped the output directory")
    sample = work / "guest-loop.exe"
    sample.write_bytes(loop)
    result = subprocess.run([str(root / ".venv" / "Scripts" / "emumee.exe"),
                             "run", str(sample), "--timeout", "1",
                             "--max-instructions", "100000000",
                             "--output", str(work / "runs")],
                            capture_output=True, text=True, timeout=30)
    envelope = json.loads(result.stdout)
    summary = json.loads(Path(envelope["report"]).read_text(encoding="utf-8"))
    engine = json.loads((Path(envelope["report"]).parent / "engine-report.json").read_text(encoding="utf-8"))
    print(json.dumps({"status": summary["status"],
                      "timeout_reached": summary.get("timeout_reached"),
                      "instruction_limit_reached": summary.get("instruction_limit_reached"),
                      "instruction_count": summary.get("instruction_count"),
                      "engine_runtime": engine.get("emulation_total_runtime"),
                      "entry_return_values": [entry.get("ret_val") for entry in engine.get("entry_points", [])],
                      "errors": summary.get("errors")}, indent=2))
    if (summary["status"] != "timeout" or
            summary.get("timeout_reached") is not True or
            summary.get("instruction_limit_reached") is not False or
            not summary.get("instruction_count", 0)):
        raise AssertionError("The infinite guest loop was not classified as a wall-clock timeout")
