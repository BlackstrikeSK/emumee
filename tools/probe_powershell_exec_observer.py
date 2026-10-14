"""Fixed benign PowerShell probe with a separate Linux native-exec observer.

Requires the statically built tools/powershell_exec_observer.c. Runs only in an
unprivileged no-network Linux container, never host PowerShell. No submitted
script argument or analysis mode is provided.
"""

import argparse
import base64
import datetime as dt
import hashlib
import hmac
import io
import json
import re
import secrets
import subprocess
import tarfile
import uuid
from pathlib import Path

from tools.probe_powershell_container import docker


PROBE = r"""
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.OS -notmatch 'Linux') { throw 'Expected Linux guest' }
$name = '/bin/' + 'echo'
& $name @('space value', 'quote"value', '', 'café-✓')
Set-PSBreakpoint -Command 'Write-Output' -Action {} | Out-Null
Get-PSBreakpoint | Disable-PSBreakpoint
Get-PSBreakpoint | Remove-PSBreakpoint
& $name ('after-' + 'breakpoint-removal')
try {
    $stream = [System.IO.File]::OpenRead('/proc/1/mem')
    $stream.Dispose()
    & $name 'observer-memory-readable'
} catch [System.UnauthorizedAccessException] { & $name 'observer-memory-denied' }
catch { & $name 'observer-memory-other-error' }
try {
    $socket = [System.Net.Sockets.Socket]::new(
        [System.Net.Sockets.AddressFamily]::InterNetwork,
        [System.Net.Sockets.SocketType]::Stream,
        [System.Net.Sockets.ProtocolType]::Tcp)
    $socket.Dispose()
    & $name 'network-socket-created'
} catch { & $name 'network-socket-denied' }
"""


def verified_events(raw: bytes, key: bytes) -> list[dict]:
    """Reject forged, reordered, missing, or malformed observer records."""
    if len(raw) > 4 * 1024 * 1024:
        raise ValueError("Observer output exceeds fixed-probe limit")
    result = []
    for line in raw.splitlines():
        signature, separator, body = line.partition(b" ")
        if (not separator or not re.fullmatch(b"[a-f0-9]{64}", signature) or
                not hmac.compare_digest(signature.decode("ascii"),
                                        hmac.new(key, body, hashlib.sha256).hexdigest())):
            raise ValueError("Unauthenticated observer output")
        event = json.loads(body)
        if (not isinstance(event, dict) or type(event.get("sequence")) is not int or
                event["sequence"] != len(result) + 1):
            raise ValueError("Observer record sequence is invalid")
        result.append(event)
    if (not result or result[0].get("event") != "observer_ready" or
            result[-1].get("event") != "observer_finished"):
        raise ValueError("Observer did not report a complete trace lifecycle")
    return result


def command_events(events: list[dict]) -> list[dict]:
    """Project only kernel-confirmed execs; preserve exact native argv bytes."""
    pending = {}
    result = []
    for event in events:
        if event["event"] == "native_exec_attempt":
            pending[event["pid"]] = event
        elif event["event"] == "native_exec_committed":
            attempt = pending.pop(event["pid"], None)
            if attempt is None:
                raise ValueError("Exec confirmation has no observed argument array")
            path_bytes = bytes.fromhex(attempt["path_hex"])
            argv_bytes = [bytes.fromhex(value) for value in attempt["argv_hex"]]
            path = path_bytes.decode("utf-8", errors="backslashreplace")
            result.append({"event": "powershell_command_invocation", "sequence": len(result) + 1,
                "capture": "external_linux_ptrace", "phase": "kernel_exec_committed",
                "scope": "native-process-observer", "command_type": "Application",
                "command": path.rsplit("/", 1)[-1], "path": path, "guest_pid": event["pid"],
                "native_arguments": [value.decode("utf-8", errors="backslashreplace") for value in argv_bytes[1:]],
                "argv_hex": attempt["argv_hex"], "path_hex": attempt["path_hex"],
                "observer_sequence": event["sequence"], "argv_includes_executable": True,
                "bound_parameters": {}, "unbound_arguments": []})
    return result


def observer_image(image: str, payload: bytes) -> str:
    """Bake the trusted observer into a layer; runtime root stays read-only."""
    digest = hashlib.sha256(image.encode("ascii") + payload).hexdigest()
    tag = "emumee-pwsh-exec-observer:" + digest[:32]
    archive = io.BytesIO()
    dockerfile = (f"FROM {image}\nCOPY --chmod=0555 observer /observer\n"
                  f"LABEL org.emumee.observer.build={digest}\n").encode("ascii")
    with tarfile.open(fileobj=archive, mode="w") as tar:
        for filename, content in (("Dockerfile", dockerfile), ("observer", payload)):
            member = tarfile.TarInfo(filename)
            member.size, member.mode = len(content), 0o555
            tar.addfile(member, io.BytesIO(content))
    completed = subprocess.run(["docker", "build", "--pull=false", "--network=none", "--tag", tag, "-"],
                               input=archive.getvalue(), capture_output=True, timeout=90)
    if completed.returncode:
        raise RuntimeError("Observer image build failed: " + completed.stderr.decode("utf-8", errors="replace")[-2000:])
    info = json.loads(docker("image", "inspect", tag))[0]
    if info["Config"].get("Labels", {}).get("org.emumee.observer.build") != digest:
        raise RuntimeError("Observer image label verification failed")
    return info["Id"]


def probe(image: str, observer: Path) -> dict:
    if not re.fullmatch(r"mcr\.microsoft\.com/dotnet/sdk@sha256:[a-f0-9]{64}", image):
        raise ValueError("An already pulled official SDK image pinned by digest is required")
    image_info = json.loads(docker("image", "inspect", image))[0]
    if image_info["Os"] != "linux" or image_info["Architecture"] != "amd64":
        raise ValueError("This observer prototype requires Linux amd64")
    payload = observer.read_bytes()
    if payload[:6] != b"\x7fELF\x02\x01":
        raise ValueError("Observer must be a built Linux x86-64 ELF")
    runtime_image = observer_image(image, payload)
    encoded = base64.b64encode(PROBE.encode("utf-16le")).decode("ascii")
    name = "emumee-exec-observer-" + uuid.uuid4().hex
    created = False
    try:
        docker("create", "--name", name, "--interactive", "--pull=never", "--network=none",
               "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges=true",
               "--user=65534:65534", "--pids-limit=64", "--memory=512m", "--cpus=1",
               "--hostname=emumee-pwsh-observer", "--workdir=/work", "--log-driver=none",
               "--tmpfs=/work:rw,nosuid,nodev,noexec,size=16m,mode=1777",
               "--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=16m,mode=1777",
               "--env=HOME=/work", "--env=POWERSHELL_TELEMETRY_OPTOUT=1",
               "--env=DOTNET_CLI_TELEMETRY_OPTOUT=1", "--env=DOTNET_EnableDiagnostics=0",
               "--env=OPENSSL_CONF=/dev/null", runtime_image, "/observer", "pwsh", "-NoLogo",
               "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded, timeout=90)
        created = True
        info = json.loads(docker("inspect", name))[0]
        config = info["HostConfig"]
        checks = {"network_none": config["NetworkMode"] == "none",
            "read_only_root": config["ReadonlyRootfs"] is True,
            "no_binds": not config.get("Binds"),
            "no_host_mounts": all(m.get("Type") == "tmpfs" for m in info.get("Mounts", [])),
            "no_privileged": config["Privileged"] is False,
            "capabilities_dropped": config["CapDrop"] == ["ALL"],
            "no_new_privileges": config["SecurityOpt"] == ["no-new-privileges=true"],
            "unprivileged_user": info["Config"]["User"] == "65534:65534",
            "memory_limited": config["Memory"] == 512 * 1024 * 1024,
            "pids_limited": config["PidsLimit"] == 64,
            "cpu_limited": config["NanoCpus"] == 1_000_000_000}
        if not all(checks.values()):
            raise RuntimeError("Container configuration verification failed")
        key = secrets.token_bytes(32)
        started = dt.datetime.now(dt.timezone.utc).isoformat()
        completed = subprocess.run(["docker", "start", "--attach", "--interactive", name], input=key,
                                   capture_output=True, timeout=90)
        final = json.loads(docker("inspect", name))[0]["State"]
        if completed.returncode or final["Running"] or final["ExitCode"] or final.get("OOMKilled"):
            raise RuntimeError("Fixed observer probe failed: " + completed.stdout.decode("utf-8", errors="replace")[:2000]
                               + completed.stderr.decode("utf-8", errors="replace")[:1000])
        events = verified_events(completed.stdout, key)
        commands = command_events(events)
        echo = [c["native_arguments"] for c in commands if c["path"] == "/bin/echo"]
        observed = {"exact_native_argv": ["space value", 'quote"value', "", "café-✓"] in echo,
                    "after_breakpoint_removal": ["after-breakpoint-removal"] in echo,
                    "observer_memory_denied": ["observer-memory-denied"] in echo,
                    "observer_memory_not_readable": ["observer-memory-readable"] not in echo,
                    "network_socket_denied": ["network-socket-denied"] in echo,
                    "no_network_socket_created": ["network-socket-created"] not in echo,
                    "socket_denial_observed": any(e["event"] == "native_syscall_denied" and
                                                  e["syscall_number"] == 41 for e in events),
                    "observer_non_dumpable": events[0]["dumpable"] == 0,
                    "tracer_exitkill_enabled": events[0]["exitkill"] is True,
                    "root_exited_successfully": events[-1]["root_exit_code"] == 0}
        network = [{**event, "event": "network_denied", "api": "linux.socket",
                    "capture": "external_linux_ptrace", "network_used": False,
                    "reason": "Network socket creation denied before execution"}
                   for event in events if event["event"] == "native_syscall_denied" and event["syscall_number"] == 41]
        return {"image": image, "image_id": runtime_image, "base_image_id": image_info["Id"],
            "capture_source": "external_linux_ptrace",
            "observer_sha256": hashlib.sha256(payload).hexdigest(),
            "execution_started_at": started, "execution_finished_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "configuration_checks": checks, "observed_checks": observed, "passed": all(observed.values()),
            "probe": {"command_events": commands, "observer_events": events, "network_events": network,
                      "dropped_command_events": 0, "capture_integrity_events": []},
            "limitations": ["Fixed harmless probe only; no submitted scripts are accepted",
                "Only Linux native execs and selected syscall denials are observed; PowerShell cmdlets are not covered",
                "Linux guest identity is not the Windows persona",
                "The prototype does not establish resistance to container escape or all observer tampering",
                "Exec confirmation does not establish successful program completion",
                "Linux x86-64 only; execveat descriptor paths are not resolved"]}
    finally:
        if created:
            docker("rm", "--force", name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--observer", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--dashboard-root", type=Path)
    args = parser.parse_args()
    report = probe(args.image, args.observer)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    if args.dashboard_root and report["passed"]:
        from emumee.powershell_probe_report import save_probe_run
        print(json.dumps({"dashboard_run": str(save_probe_run(report, args.dashboard_root, PROBE))}))
    print(json.dumps({"passed": report["passed"], "checks": report["observed_checks"]}))
    if not report["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
