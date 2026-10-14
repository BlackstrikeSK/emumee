"""Run only a fixed harmless PowerShell confinement/trace probe in a Linux container.

This is a feasibility tool, not a submitted-script execution mode. It requires
an already pulled official SDK image pinned by repository digest.
"""

from __future__ import annotations

import argparse
import base64
import json
import re
import subprocess
import uuid
from pathlib import Path


PROBE = r"""
$ErrorActionPreference = 'Stop'
$values = @(Trace-Command -Name CommandDiscovery,ParameterBinding -FilePath /work/trace.log -Expression {
    $name = 'Write-' + 'Output'
    & $name ('runtime-' + 'resolved-argument')
    Invoke-Expression ('Write-Output ' + "'nested-resolved-argument'")
    & /bin/echo ('native-' + 'resolved-argument')
})
$client = [System.Net.Sockets.TcpClient]::new()
$connected = $false
try {
    $task = $client.ConnectAsync('198.51.100.1', 80)
    if ($task.Wait(1500)) { $connected = $client.Connected }
} catch {} finally { $client.Dispose() }
$rootWrite = $false
try { [IO.File]::WriteAllText('/emumee-probe-marker', 'harmless'); $rootWrite = $true } catch {}
$status = [IO.File]::ReadAllText('/proc/self/status')
[ordered]@{
    powershell_version = $PSVersionTable.PSVersion.ToString()
    platform = $PSVersionTable.Platform
    values = $values
    network_connected = $connected
    root_write_succeeded = $rootWrite
    host_drive_visible = [IO.Directory]::Exists('/mnt/c')
    docker_socket_visible = [IO.File]::Exists('/var/run/docker.sock')
    no_new_privileges = [bool]($status -match '(?m)^NoNewPrivs:\s+1$')
    effective_capabilities_zero = [bool]($status -match '(?m)^CapEff:\s+0+$')
    trace = [IO.File]::ReadAllText('/work/trace.log')
} | ConvertTo-Json -Depth 5 -Compress
"""


def docker(*args: str, timeout: int = 30) -> str:
    try:
        result = subprocess.run(["docker", *args], capture_output=True, text=True,
                                encoding="utf-8", errors="replace", timeout=timeout)
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"docker {args[0]} observation timed out; inspect daemon state before retrying") from None
    if result.returncode:
        raise RuntimeError(f"docker {args[0]} failed: {result.stderr[:2000]}")
    return result.stdout


def probe(image: str, resume_container: str | None = None) -> dict:
    if not re.fullmatch(r"mcr\.microsoft\.com/dotnet/sdk@sha256:[0-9a-f]{64}", image):
        raise ValueError("Use an already pulled official SDK repository digest")
    image_info = json.loads(docker("image", "inspect", image))[0]
    if image_info.get("Os") != "linux":
        raise ValueError("The feasibility probe requires a Linux guest image")
    if resume_container and not re.fullmatch(r"emumee-pwsh-probe-[0-9a-f]{32}", resume_container):
        raise ValueError("Invalid probe container name")
    name = resume_container or "emumee-pwsh-probe-" + uuid.uuid4().hex
    print(json.dumps({"probe_container": name}), flush=True)
    encoded = base64.b64encode(PROBE.encode("utf-16le")).decode("ascii")
    created = False
    try:
        if resume_container:
            previous = json.loads(docker("inspect", name))[0]
            expected_command = ["pwsh", "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded]
            if (previous["Image"] != image_info["Id"] or
                    previous["Config"]["Cmd"] != expected_command or
                    previous["State"]["Status"] != "created"):
                raise ValueError("Resume target is not this fixed probe in created state")
        else:
            docker("create", "--name", name, "--pull=never", "--network=none",
               "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges=true",
               "--user=65534:65534", "--pids-limit=64", "--memory=512m", "--cpus=1",
               "--hostname=emumee-pwsh-probe", "--workdir=/work", "--log-driver=none",
               "--tmpfs=/work:rw,nosuid,nodev,noexec,size=16m,mode=1777",
               "--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=16m,mode=1777",
               "--env=HOME=/work", "--env=POWERSHELL_TELEMETRY_OPTOUT=1",
               "--env=DOTNET_CLI_TELEMETRY_OPTOUT=1", image,
               "pwsh", "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded,
               timeout=90)
        created = True
        info = json.loads(docker("inspect", name))[0]
        config = info["HostConfig"]
        checks = {
            "network_none": config["NetworkMode"] == "none",
            "read_only_root": config["ReadonlyRootfs"] is True,
            "no_binds": not config.get("Binds"),
            "no_host_mounts": all(mount.get("Type") == "tmpfs"
                                  for mount in info.get("Mounts", [])),
            "no_privileged": config["Privileged"] is False,
            "capabilities_dropped": config["CapDrop"] == ["ALL"],
            "no_new_privileges": "no-new-privileges=true" in config["SecurityOpt"],
            "unprivileged_user": info["Config"]["User"] == "65534:65534",
            "memory_limited": config["Memory"] == 512 * 1024 * 1024,
            "pids_limited": config["PidsLimit"] == 64,
        }
        if not all(checks.values()):
            raise RuntimeError("Container configuration verification failed: " + str(checks))
        raw = docker("start", "--attach", name, timeout=90)
        if len(raw.encode("utf-8")) > 1024 * 1024:
            raise RuntimeError("Fixed probe output exceeded its expected bound")
        final = json.loads(docker("inspect", name))[0]["State"]
        if final["Running"] or final["ExitCode"] != 0 or final.get("OOMKilled"):
            raise RuntimeError("Fixed PowerShell probe did not complete successfully")
        result = json.loads(raw)
        expected = ["runtime-resolved-argument", "nested-resolved-argument", "native-resolved-argument"]
        observed_checks = {
            "runtime_values": result["values"] == expected,
            "network_denied": result["network_connected"] is False,
            "root_write_denied": result["root_write_succeeded"] is False,
            "host_drive_absent": result["host_drive_visible"] is False,
            "docker_socket_absent": result["docker_socket_visible"] is False,
            "no_new_privileges": result["no_new_privileges"] is True,
            "capabilities_zero": result["effective_capabilities_zero"] is True,
            "expanded_trace_values": all(line in result["trace"] for line in (
                "BIND arg [runtime-resolved-argument] to param [InputObject] SUCCESSFUL",
                "BIND arg [nested-resolved-argument] to param [InputObject] SUCCESSFUL",
                "BIND cmd line arg [native-resolved-argument] to position [0]")),
        }
        return {"image": image, "image_id": image_info["Id"],
                "configuration_checks": checks, "observed_checks": observed_checks,
                "passed": all(observed_checks.values()), "probe": result,
                "limitations": ["Fixed harmless probe only; no submitted scripts are accepted",
                                "Linux PowerShell does not reproduce a Windows persona",
                                "Trace-Command is script-controllable and is not a complete audit boundary",
                                "The probe does not establish resistance to container escape"]}
    finally:
        if created:
            docker("rm", "--force", name)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--resume-container", help="Resume this fixed probe after a create observation timeout")
    args = parser.parse_args()
    report = probe(args.image, args.resume_container)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({"passed": report["passed"], "output": str(args.output),
                      "checks": report["observed_checks"]}))
    if not report["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
