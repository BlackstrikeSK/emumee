"""Shared authenticated PowerShell capture protocol and immutable runtime image."""

import hashlib
import hmac
import io
import json
import re
import subprocess
import tarfile

SDK_IMAGE = "mcr.microsoft.com/dotnet/sdk@sha256:2f5eb32870b4c0074a3d5b5191a03553bcab7b74463a76a7c0a5f3ef65c90fe5"
SOURCE_COMMIT = "3ad470239de5c9c52d470917b071831f16b02fc3"
ENGINE_HOME = "/usr/share/powershell/.store/powershell.linux.x64/7.5.12/powershell.linux.x64/7.5.12/tools/net9.0/any"


def docker(*args: str, timeout=30) -> str:
    result = subprocess.run(["docker", *args], capture_output=True, text=True,
                            encoding="utf-8", errors="replace", timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"docker {args[0]} failed: {result.stderr[:2000]}")
    return result.stdout


def verified_events(raw: bytes, key: bytes, *, require_finished=True) -> list[dict]:
    """Reject forged, reordered, missing, or malformed observer records."""
    if len(raw) > 4 * 1024 * 1024:
        raise ValueError("Observer output exceeds trace limit")
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
            (require_finished and result[-1].get("event") != "observer_finished")):
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


def engine_command_events(events: list[dict]) -> list[dict]:
    """Label instrumented-engine payloads as guest-generated, even after MAC verification."""
    result = []
    for event in events:
        if event["event"] != "guest_engine_record":
            continue
        raw = bytes.fromhex(event["data_hex"])
        if len(raw) > 65536:
            raise ValueError("Guest engine record exceeds limit")
        record = json.loads(raw)
        if (not isinstance(record, dict) or record.get("event") != "powershell_command_invocation" or
                not isinstance(record.get("command"), str) or
                not isinstance(record.get("bound_parameters"), dict) or
                type(record.get("sequence")) is not int or
                not 1 <= record["sequence"] <= 2000 or record.get("phase") not in
                {"command_line_bound", "process_record_bound", "script_arguments_bound"}):
            raise ValueError("Guest engine invocation record is malformed")
        record.update(capture="guest_engine_instrumentation", provenance="in_process_data",
                      guest_pid=event["pid"], observer_sequence=event["sequence"],
                      engine_sequence=record["sequence"])
        record["command"] = record["command"] or "<scriptblock>"
        for field in ("native_arguments", "argv_hex", "path_hex", "argv_includes_executable"):
            record.pop(field, None)
        result.append(record)
    return result


def observer_image(image: str, payload: bytes, engine_payload: bytes | None = None) -> str:
    """Bake the trusted observer into a layer; runtime root stays read-only."""
    digest = hashlib.sha256(image.encode("ascii") + payload + (engine_payload or b"")).hexdigest()
    tag = "emumee-pwsh-exec-observer:" + digest[:32]
    archive = io.BytesIO()
    dockerfile = (f"FROM {image}\nCOPY --chmod=0555 observer /observer\n" +
                  (f"COPY --chmod=0444 engine.dll {ENGINE_HOME}/System.Management.Automation.dll\n" if engine_payload else "") +
                  f"LABEL org.emumee.observer.build={digest}\n").encode("ascii")
    with tarfile.open(fileobj=archive, mode="w") as tar:
        for filename, content in (("Dockerfile", dockerfile), ("observer", payload)):
            member = tarfile.TarInfo(filename)
            member.size, member.mode = len(content), 0o555
            tar.addfile(member, io.BytesIO(content))
        if engine_payload:
            member = tarfile.TarInfo("engine.dll")
            member.size, member.mode = len(engine_payload), 0o444
            tar.addfile(member, io.BytesIO(engine_payload))
    completed = subprocess.run(["docker", "build", "--pull=false", "--network=none", "--tag", tag, "-"],
                               input=archive.getvalue(), capture_output=True, timeout=90)
    if completed.returncode:
        raise RuntimeError("Observer image build failed: " + completed.stderr.decode("utf-8", errors="replace")[-2000:])
    info = json.loads(docker("image", "inspect", tag))[0]
    if info["Config"].get("Labels", {}).get("org.emumee.observer.build") != digest:
        raise RuntimeError("Observer image label verification failed")
    return info["Id"]


