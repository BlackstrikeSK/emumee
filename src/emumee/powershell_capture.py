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
MAX_OBSERVER_BYTES = 8 * 1024 * 1024
ENGINE_HOME = "/usr/share/powershell/.store/powershell.linux.x64/7.5.12/powershell.linux.x64/7.5.12/tools/net9.0/any"


def docker(*args: str, timeout=30) -> str:
    result = subprocess.run(["docker", *args], capture_output=True, text=True,
                            encoding="utf-8", errors="replace", timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"docker {args[0]} failed: {result.stderr[:2000]}")
    return result.stdout


def verified_events(raw: bytes, key: bytes, *, require_finished=True) -> list[dict]:
    """Reject forged, reordered, missing, or malformed observer records."""
    if len(raw) > MAX_OBSERVER_BYTES:
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
                {"command_line_bound", "process_record_bound", "script_arguments_bound",
                 "method_arguments_bound", "reflection_arguments_supplied",
                 "property_get_started", "property_get_completed", "property_get_failed",
                 "property_set_started", "property_set_completed", "property_set_failed"}):
            raise ValueError("Guest engine invocation record is malformed")
        if record['phase'].startswith('property_') or record.get('command_type') == 'DotNetProperty':
            if (record.get('command_type') != 'DotNetProperty' or record.get('operation') not in {'get','set'} or
                    record.get('access_status') not in {'started','completed','failed'} or
                    record['phase'] != 'property_'+record['operation']+'_'+record['access_status'] or
                    any(not isinstance(record.get(key),str) for key in ('property_name','declaring_type','property_type','accessor_signature','dispatch_route','selected_property')) or
                    any(type(record.get(key)) is not bool for key in ('is_static','value_available')) or
                    type(record.get('access_id')) is not int or not 1 <= record['access_id'] <= 2000 or
                    record.get('target_type') is not None and not isinstance(record['target_type'],str) or
                    record.get('error_type') is not None and not isinstance(record['error_type'],str) or
                    record.get('value_stage') not in {'returned','converted','supplied_before_clr_conversion'} or
                    'property_value' not in record or not isinstance(record.get('index_arguments'),list) or
                    record['value_available'] != (record['operation'] == 'set' or record['access_status'] == 'completed')):
                raise ValueError('Guest engine property record is malformed')
        if record['phase'] in {'method_arguments_bound', 'reflection_arguments_supplied'} or record.get('command_type') == 'DotNetMethod':
            arguments = record.get('method_arguments')
            if (record.get('command_type') != 'DotNetMethod' or record['phase'] not in {'method_arguments_bound','reflection_arguments_supplied'} or
                    any(not isinstance(record.get(key), str) for key in ('method_name', 'declaring_type', 'method_signature', 'dispatch_route')) or
                    any(type(record.get(flag)) is not bool for flag in ('is_static','is_constructor','metadata_captured')) or
                    record.get('target_type') is not None and not isinstance(record['target_type'],str) or
                    not isinstance(record.get('generic_arguments'),list) or any(not isinstance(item,str) for item in record['generic_arguments']) or
                    not isinstance(arguments, list) or len(arguments) > 32 or
                    type(record.get('arguments_truncated')) is not bool or
                    any(not isinstance(arg, dict) or arg.get('position') != index or
                        type(arg.get('position')) is not int or not isinstance(arg.get('name'), str) or
                        arg.get('parameter_type') is not None and not isinstance(arg['parameter_type'], str) or
                        'value' not in arg or any(type(arg.get(flag)) is not bool for flag in ('by_ref','is_out','is_optional'))
                        for index, arg in enumerate(arguments))):
                raise ValueError('Guest engine method record is malformed')
        record.update(capture="guest_engine_instrumentation", provenance="in_process_data",
                      guest_pid=event["pid"], observer_sequence=event["sequence"],
                      engine_sequence=record["sequence"])
        record["command"] = record["command"] or "<scriptblock>"
        for field in ("native_arguments", "argv_hex", "path_hex", "argv_includes_executable"):
            record.pop(field, None)
        result.append(record)
    return result


def guest_tool_event(event: dict, program_names: list[str], persona_sha256: str) -> tuple[dict, list[dict]]:
    """Guest model payloads cannot claim external provenance or kernel argv."""
    raw = bytes.fromhex(event['data_hex'])
    if len(raw) > 65536:
        raise ValueError('Guest utility record exceeds limit')
    record = json.loads(raw)
    if (not isinstance(record, dict) or record.get('event') != 'guest_windows_enumeration' or
            record.get('program') not in program_names or not isinstance(record.get('arguments'), list) or
            len(record['arguments']) > 64 or any(not isinstance(a, str) or len(a) > 16000 for a in record['arguments']) or
            any(not isinstance(record.get(k), str) or not re.fullmatch('[a-f0-9]{64}', record[k]) for k in ('persona_sha256', 'pe_sha256')) or
            type(record.get('guest_exit_code')) is not int or not 0 <= record['guest_exit_code'] <= 0xffffffff or
            record.get('network_broker_available') is not False or record.get('architecture') != 'x64' or
            not isinstance(record.get('network_events'), list) or len(record['network_events']) > 16 or
            any(not isinstance(e, dict) or not isinstance(e.get('event'), str) for e in record['network_events']) or
            not isinstance(record.get('errors'), list) or len(record['errors']) > 8 or
            any(not isinstance(e, str) or len(e) > 2048 for e in record['errors'])):
        raise ValueError('Guest utility record is malformed')
    chunks = record.get('network_chunk_count', 0)
    count = record.get('network_event_count', len(record['network_events']))
    index = record.get('network_chunk_index')
    if (type(chunks) is not int or not 0 <= chunks <= 2048 or type(count) is not int or not 0 <= count <= 2048 or
            index is not None and (type(index) is not int or not 0 <= index < chunks)):
        raise ValueError('Guest utility network chunk metadata is malformed')
    command = {'event': 'powershell_command_invocation', 'command': record['program'],
               'command_type': 'EmulatedWindowsApplication', 'phase': 'emulation_finished',
               'capture': 'guest_windows_emulation', 'provenance': 'in_process_data',
               'guest_pid': event['pid'], 'observer_sequence': event['sequence'],
               'bound_parameters': {}, 'unbound_arguments': record['arguments'],
               'persona_sha256': record['persona_sha256'], 'pe_sha256': record['pe_sha256'],
               'persona_matches_baseline': record['persona_sha256'] == persona_sha256,
               'reported_guest_exit_code': record['guest_exit_code'], 'errors': record['errors'],
               'network_chunk_count': chunks, 'network_event_count': count,
               'network_chunk_index': index, 'network_events_truncated': record.get('network_events_truncated') is True}
    network = [{**e, 'capture': 'guest_windows_emulation', 'provenance': 'in_process_data',
                'network_used': False, 'guest_tool_program': record['program'],
                'observer_sequence': event['sequence'], 'guest_pid': event['pid']}
               for e in record['network_events']]
    return command, network


def observer_image(image: str, payload: bytes, engine_payload: bytes | None = None) -> str:
    """Bake the trusted observer into a layer; runtime root stays read-only."""
    base = json.loads(docker('image', 'inspect', image))[0]
    reference = image
    if re.fullmatch(r'sha256:[a-f0-9]{64}', image):
        # BuildKit treats a raw image ID in FROM as a registry repository name.
        # A private content-derived tag plus layer verification keeps this local.
        reference = 'emumee-pwsh-runtime-base:' + image[7:]
        docker('image', 'tag', image, reference)
        if json.loads(docker('image', 'inspect', reference))[0]['Id'] != image:
            raise ValueError('Runtime base image tag does not match its immutable ID')
    digest = hashlib.sha256(image.encode("ascii") + payload + (engine_payload or b"")).hexdigest()
    tag = "emumee-pwsh-exec-observer:" + digest[:32]

    def checked_id(info):
        if info["Config"].get("Labels", {}).get("org.emumee.observer.build") != digest:
            raise RuntimeError("Observer image label verification failed")
        if info['RootFS']['Layers'][:len(base['RootFS']['Layers'])] != base['RootFS']['Layers']:
            raise RuntimeError('Observer runtime does not extend the verified base layers')
        return info['Id']

    # Rebuilding an existing tag can replace its image ID between inspect and
    # container creation in another run. Reuse the verified content-derived image.
    try:
        cached = json.loads(docker('image', 'inspect', tag))[0]
    except RuntimeError:
        pass
    else:
        return checked_id(cached)
    archive = io.BytesIO()
    dockerfile = (f"FROM {reference}\nCOPY --chmod=0555 observer /observer\n" +
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
    return checked_id(info)


