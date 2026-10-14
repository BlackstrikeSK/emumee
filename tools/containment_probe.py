"""Harmless packaged-run checks for guest-to-host command and file escape.

This is an operator-invoked regression probe. Guest commands only write unique
temporary markers, which are checked and removed before the script exits.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import uuid
import winreg
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tests.fixtures.build_native import (build_host_process_probe,
                                         build_host_winexec_probe,
                                         build_host_winexec_via_ldr_probe)  # noqa: E402


EXE = ROOT / "dist" / "Emumee" / "Emumee.exe"
OUTPUT = ROOT / "output" / "containment-probe"


def _run(sample: Path, *guest_args: str) -> dict:
    command = [str(EXE), "run", str(sample), "--output", str(OUTPUT),
               "--timeout", "10"]
    for value in guest_args:
        command.extend(["--guest-arg", value])
    process = subprocess.run(command, cwd=ROOT, capture_output=True, text=True,
                             timeout=45, check=False)
    try:
        result = json.loads(process.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Emumee did not return a run report: {process.stderr}") from exc
    result["cli_exit_code"] = process.returncode
    return result


def main() -> int:
    OUTPUT.mkdir(parents=True, exist_ok=True)
    findings = []
    with tempfile.TemporaryDirectory(prefix="emumee-host-probe-") as directory:
        temporary = Path(directory)
        for name, machine in (("x86", 0x14C), ("x64", 0x8664)):
            marker = temporary / f"native-{name}-host-command.txt"
            sample = temporary / f"native-{name}.exe"
            sample.write_bytes(build_host_process_probe(machine, str(marker)))
            result = _run(sample)
            created = marker.exists()
            findings.append({"probe": f"native-createprocess-{name}",
                             "host_marker_created": created, "run": result})
            marker.unlink(missing_ok=True)
            winexec_marker = temporary / f"native-{name}-winexec-host-command.txt"
            winexec_sample = temporary / f"native-winexec-{name}.exe"
            winexec_sample.write_bytes(build_host_winexec_probe(machine, str(winexec_marker)))
            result = _run(winexec_sample)
            findings.append({"probe": f"native-winexec-{name}",
                             "host_marker_created": winexec_marker.exists(), "run": result})
            winexec_marker.unlink(missing_ok=True)
            ldr_marker = temporary / f"native-{name}-ldr-host-command.txt"
            ldr_sample = temporary / f"native-ldr-{name}.exe"
            ldr_sample.write_bytes(build_host_winexec_via_ldr_probe(
                machine, str(ldr_marker)))
            result = _run(ldr_sample)
            findings.append({"probe": f"native-ldr-winexec-{name}",
                             "host_marker_created": ldr_marker.exists(), "run": result})
            ldr_marker.unlink(missing_ok=True)

        project = temporary / "ManagedHostProbe.csproj"
        project.write_text('<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup>'
                           '<OutputType>Exe</OutputType><TargetFramework>net8.0</TargetFramework>'
                           '</PropertyGroup></Project>', encoding="utf-8")
        (temporary / "Program.cs").write_text(
            'using System; using System.IO; using System.Diagnostics;'
            'using System.Runtime.InteropServices;'
            'class Program { [DllImport("kernel32.dll", EntryPoint="WinExec")]'
            'static extern uint WinExec(string command, uint show);'
            'static void Main(string[] args) {'
            'if(args[0]=="process") {'
            'Process.Start("cmd.exe", "/c echo emumee-host-probe > \\"" + args[1] + "\\"");'
            '} else if(args[0]=="pinvoke") {'
            'WinExec("cmd.exe /c echo emumee-host-probe > \\"" + args[1] + "\\"", 0);'
            '} else { Directory.CreateDirectory(Path.GetDirectoryName(args[1])!);'
            'File.WriteAllText(args[1], "guest virtual file"); }'
            '} }', encoding="utf-8")
        subprocess.run(["dotnet", "build", str(project), "-c", "Release", "-v", "quiet"],
                       cwd=temporary, check=True, capture_output=True, text=True, timeout=120)
        apphost = temporary / "bin" / "Release" / "net8.0" / "ManagedHostProbe.exe"
        file_marker = temporary / "managed-host-file.txt"
        command_marker = temporary / "managed-host-command.txt"
        result = _run(apphost, "process", str(command_marker))
        findings.append({"probe": "managed-process", "run": result,
                         "host_command_marker_created": command_marker.exists()})
        result = _run(apphost, "pinvoke", str(command_marker))
        findings.append({"probe": "managed-pinvoke-winexec", "run": result,
                         "host_command_marker_created": command_marker.exists()})
        result = _run(apphost, "file", str(file_marker))
        findings.append({"probe": "managed-file", "run": result,
                         "host_file_created": file_marker.exists()})
        file_marker.unlink(missing_ok=True)
        command_marker.unlink(missing_ok=True)
        private_dir = temporary / "private-entry"
        private_dir.mkdir()
        outside_marker = temporary / "private-host-file.txt"
        bundle_marker = temporary / "private-bundle-file.txt"
        registry_key = f"Software\\EmumeePrivateProbe\\{uuid.uuid4().hex}"
        try:
            for mode, extra in (
                    ("_worker", ["0" * 64]), ("_network_broker", []),
                    ("_sandbox_probe", [str(ROOT / "README.md"),
                                         str(outside_marker), str(os.getpid()),
                                         registry_key, str(bundle_marker), "1"])):
                process = subprocess.run([str(EXE), mode, str(private_dir), *extra],
                                         cwd=ROOT, capture_output=True, text=True,
                                         timeout=15, check=False)
                rejected = (process.returncode != 0 and
                            "containment missing" in process.stderr.lower())
                findings.append({"probe": f"direct-{mode[1:]}",
                                 "containment_rejected": rejected,
                                 "host_marker_created": outside_marker.exists() or
                                 bundle_marker.exists(),
                                 "worker_report_created": (private_dir / "summary.json").exists(),
                                 "broker_ready_created": (private_dir / "broker-ready").exists()})
        finally:
            outside_marker.unlink(missing_ok=True)
            bundle_marker.unlink(missing_ok=True)
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, registry_key)
            except FileNotFoundError:
                pass
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, r"Software\EmumeePrivateProbe")
            except (FileNotFoundError, PermissionError):
                pass
    report = OUTPUT / "containment-results.json"
    report.write_text(json.dumps(findings, indent=2), encoding="utf-8")
    print(json.dumps({"report": str(report), "findings": [
        {key: value for key, value in finding.items() if key != "run"}
        for finding in findings]}, indent=2))
    return 1 if any(finding.get("containment_rejected") is False or
                    finding.get("worker_report_created") or
                    finding.get("broker_ready_created") or
                    finding.get("host_marker_created") or
                    finding.get("host_file_created") or
                    finding.get("host_command_marker_created") for finding in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
