"""Run a harmless memory-only PE decoder through the isolated CLI bundle."""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path


root = Path(__file__).resolve().parents[1]
output_root = (root / "output").resolve()
payload = (root / "tests" / "fixtures" / "console_output_x64.exe").read_bytes()
encoded = base64.b64encode(bytes(byte ^ 0x5A for byte in payload)).decode("ascii")

with tempfile.TemporaryDirectory(dir=output_root, prefix="analyst-package-") as folder:
    work = Path(folder).resolve()
    if not work.is_relative_to(output_root):
        raise RuntimeError("Temporary package test escaped the output directory")
    project = work / "MemoryPe.csproj"
    project.write_text('<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup>'
                       '<OutputType>Exe</OutputType><TargetFramework>net8.0</TargetFramework>'
                       '</PropertyGroup></Project>', encoding="utf-8")
    (work / "Program.cs").write_text(
        'using System; using System.Text; class Program { static int Main(string[] args) {'
        'byte[] mz = Encoding.ASCII.GetBytes("MZ");'
        f'byte[] encoded = Convert.FromBase64String("{encoded}");'
        'byte[] decoded = new byte[encoded.Length];'
        'for (int i=0; i<encoded.Length; i++) decoded[i]=(byte)(encoded[i]^0x5A);'
        'return decoded[0]==mz[0] && decoded[1]==mz[1] ? 0 : 2;'
        '} }', encoding="utf-8")
    subprocess.run(["dotnet", "build", str(project), "-c", "Release", "-v", "quiet"],
                   check=True, capture_output=True, text=True, timeout=120)
    apphost = work / "bin" / "Release" / "net8.0" / "MemoryPe.exe"
    result = subprocess.run([str(root / ".venv" / "Scripts" / "emumee.exe"), "run",
                             str(apphost), "--timeout", "25", "--output", str(work / "runs")],
                            capture_output=True, text=True, timeout=60)
    if result.returncode != 0:
        raise AssertionError(f"Packaged memory PE run failed: {result.stdout} {result.stderr}")
    envelope = json.loads(result.stdout)
    summary = json.loads(Path(envelope["report"]).read_text(encoding="utf-8"))
    expected = hashlib.sha256(payload).hexdigest()
    if (summary["status"] != "completed" or
            not summary["run_manifest"]["execution_target"]["via_managed_apphost"] or
            not any(group["sha256"] == expected and
                    any(observation["source"].startswith("managed_array:")
                        for observation in group["observations"])
                    for group in summary.get("artifact_groups", []))):
        raise AssertionError(f"Memory-only PE was not recovered: {envelope}")
    print(f"packaged memory-only PE: recovered {expected}; apphost routed to CIL")
