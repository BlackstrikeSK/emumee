"""Run supplied PowerShell only inside a verified, offline Docker Desktop Linux VM."""

from __future__ import annotations

import datetime as dt
import base64
import hashlib
import json
import re
import secrets
import subprocess
import threading
import time
import uuid
from pathlib import Path

from .powershell_capture import (SDK_IMAGE, SOURCE_COMMIT, MAX_OBSERVER_BYTES, command_events, docker,
                                engine_command_events, guest_tool_event, observer_image, verified_events)
from .reports import ENGINE_INTEGRITY, valid_summary

MAX_SCRIPT = 1024 * 1024
MAX_TRACE = MAX_OBSERVER_BYTES
LIMITATIONS = [
    "Experimental Linux PowerShell runtime; Windows commands, APIs, and persona integration are incomplete",
    "Engine invocation values are guest-generated and can be forged or bypassed with arbitrary .NET/native access",
    "Native argv bytes are observed at syscall entry and confirmed on exec; concurrent argument mutation can race observation",
    "PowerShell-bound .NET methods and reflection targets are observed before invocation; CLR-internal calls, dynamic method bodies, property access, and arbitrary object values remain incomplete",
    "Console capture covers successful write/writev calls to guest stdout/stderr backing files, including duplicated descriptors, up to 64 KiB per stream and 4096 bytes per syscall; other redirections are not captured",
    "The container boundary depends on Docker Desktop's Linux VM and kernel; container escape resistance is not established",
]


def _read_bounded(path: Path, limit: int) -> bytes:
    with path.open('rb') as stream:
        content = stream.read(limit + 1)
    if not content or len(content) > limit:
        raise ValueError(f'{path.name} must contain 1..{limit} bytes')
    return content


def configuration_checks(info: dict, *, persona_mode=False) -> dict:
    host, config = info['HostConfig'], info['Config']
    return {
        'network_none': host['NetworkMode'] == 'none',
        'read_only_root': host['ReadonlyRootfs'] is True,
        'no_binds': not host.get('Binds'),
        'no_host_mounts': all(m.get('Type') == 'tmpfs' for m in info.get('Mounts', [])),
        'no_devices': not host.get('Devices') and not host.get('DeviceRequests'),
        'no_privileged': host['Privileged'] is False,
        'capabilities_dropped': host['CapDrop'] == ['ALL'] and not host.get('CapAdd'),
        'no_new_privileges': host['SecurityOpt'] == ['no-new-privileges=true'],
        'private_pid_namespace': not host.get('PidMode'),
        'private_ipc_namespace': host.get('IpcMode') == 'private',
        'unprivileged_user': config['User'] == '65534:65534',
        'memory_limited': host['Memory'] == 512 * 1024 * 1024,
        'swap_limited': host['MemorySwap'] == 512 * 1024 * 1024,
        'pids_limited': host['PidsLimit'] == 64,
        'cpu_limited': host['NanoCpus'] == 1_000_000_000,
        'temporary_files_only': host.get('Tmpfs') == {
            '/work': 'rw,nosuid,nodev,noexec,size=16m,mode=1777',
            '/tmp': 'rw,nosuid,nodev,noexec,size=16m,mode=1777'},
        'logging_disabled': host['LogConfig']['Type'] == 'none',
        'trusted_entrypoint': config.get('Entrypoint') is None,
        'expected_command': config['Cmd'] == ['/observer', '--script-persona' if persona_mode else '--script'],
    }


def _attach(name: str, input_bytes: bytes, timeout: int) -> tuple[bytes, bytes, str | None]:
    """Drain both pipes with hard memory caps; terminate the container on excess or timeout."""
    process = subprocess.Popen(['docker', 'start', '--attach', '--interactive', name],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    buffers = [bytearray(), bytearray()]
    excess = threading.Event()
    failures = []

    def drain(stream, index, limit):
        try:
            while True:
                block = stream.read(8192)
                if not block:
                    break
                available = limit - len(buffers[index])
                buffers[index].extend(block[:available])
                if len(block) > available:
                    excess.set()
        except OSError as error:
            failures.append(str(error))
            excess.set()
        finally:
            stream.close()

    def feed():
        try:
            process.stdin.write(input_bytes)
            process.stdin.close()
        except (BrokenPipeError, OSError):
            pass

    threads = [threading.Thread(target=drain, args=(process.stdout, 0, MAX_TRACE), daemon=True),
               threading.Thread(target=drain, args=(process.stderr, 1, 65536), daemon=True),
               threading.Thread(target=feed, daemon=True)]
    for thread in threads:
        thread.start()
    deadline = time.monotonic() + timeout
    reason = None
    try:
        while process.poll() is None:
            if excess.wait(0.05):
                reason = 'observer_output_limit'
                break
            if time.monotonic() >= deadline:
                reason = 'timeout'
                break
        if reason:
            # Inspect even if kill reports an already-stopped container.
            try:
                docker('kill', name, timeout=10)
            except RuntimeError:
                pass
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
            reason = reason or 'docker_attach_failure'
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        for thread in threads:
            thread.join(timeout=2)
    if any(t.is_alive() for t in threads) or failures:
        raise RuntimeError('Docker attach streams did not close cleanly')
    return bytes(buffers[0]), bytes(buffers[1]), reason


def project_trace(events: list[dict], *, guest_tools=None, persona_sha256='') -> tuple[list[dict], list[dict], dict, list[str]]:
    commands = command_events(events)
    errors = []
    model_network = []
    network_chunks = {}
    model_results = {}
    for event in events:
        if event['event'] == 'guest_tool_record':
            try:
                command, network = guest_tool_event(event, guest_tools or [], persona_sha256)
                key = command['guest_pid'], command['command']
                if command['network_chunk_index'] is not None:
                    chunks = network_chunks.setdefault(key, {})
                    index = command['network_chunk_index']
                    if index in chunks:
                        errors.append(f"Duplicate guest utility network chunk at observer sequence {event['sequence']}")
                    else:
                        chunks[index] = command, network
                    continue
                commands.append(command)
                model_results[key] = command, len(network)
                model_network.extend(network)
                if not command['persona_matches_baseline']:
                    errors.append(f"Guest Windows persona changed before invocation at observer sequence {event['sequence']}")
                errors.extend(command['errors'])
                if command['network_events_truncated']:
                    errors.append(f"Guest Windows utility network observations truncated: {command['command']}")
            except (ValueError, TypeError, KeyError, RecursionError, UnicodeError):
                errors.append(f"Rejected malformed guest utility record at observer sequence {event['sequence']}")
            continue
        if event['event'] != 'guest_engine_record':
            continue
        try:
            commands.extend(engine_command_events([event]))
        except (ValueError, TypeError, KeyError, RecursionError, UnicodeError):
            errors.append(f"Rejected malformed engine record at observer sequence {event['sequence']}")
    for key, chunks in network_chunks.items():
        if key not in model_results:
            errors.append(f'Orphaned guest utility network chunks: {key[1]}')
    for key, (result, initial_count) in model_results.items():
        chunks = network_chunks.get(key, {})
        valid = (set(chunks) == set(range(result['network_chunk_count'])) and all(
            c['persona_sha256'] == result['persona_sha256'] and c['pe_sha256'] == result['pe_sha256'] and
            c['network_chunk_count'] == result['network_chunk_count'] and c['network_event_count'] == result['network_event_count']
            for c, _ in chunks.values()) and initial_count + sum(len(n) for _, n in chunks.values()) == result['network_event_count'])
        if not valid:
            errors.append(f'Missing or inconsistent guest utility network chunks: {key[1]}')
        for index in sorted(chunks):
            model_network.extend(chunks[index][1])
    commands.sort(key=lambda c: c['observer_sequence'])
    if guest_tools:
        reported = {c['guest_pid'] for c in commands if c['capture'] == 'guest_windows_emulation'}
        for command in commands:
            if (command['capture'] == 'external_linux_ptrace' and command.get('path', '').startswith(
                    ('/opt/emumee/bin/', '/opt/emumee/windows/Windows/System32/')) and
                    command['guest_pid'] not in reported):
                errors.append(f"Guest Windows utility did not return a valid emulation record: {command['command']}")
    for number, command in enumerate(commands, 1):
        command['sequence'] = number
    network = [{**event, 'event': 'network_denied', 'api': 'linux.syscall',
                'capture': 'external_linux_ptrace', 'network_used': False,
                'reason': 'Network syscall denied before execution'}
               for event in events if event['event'] == 'native_syscall_denied' and
               event['syscall_number'] in {41, 42, 43, 44, 45, 46, 47, 49, 50, 53, 288, 299, 307}]
    network.extend(model_network)
    console = {'stdout': '', 'stderr': '', 'stdout_truncated': False, 'stderr_truncated': False}
    for fd, field in ((1, 'stdout'), (2, 'stderr')):
        writes = [event for event in events if event['event'] == 'native_console_write' and event['fd'] == fd]
        data = b''.join(bytes.fromhex(event['data_hex']) for event in writes)
        console[field] = data.decode('utf-8', errors='backslashreplace')
        console[field + '_truncated'] = any(event['truncated'] for event in writes)
    return commands, network, console, errors


def run_script(sample: Path, observer: Path, instrumented_engine: Path, *, timeout=60,
               guest_tools_build: Path | None = None, persona_path: Path | None = None) -> dict:
    if type(timeout) is not int or not 1 <= timeout <= 300:
        raise ValueError('PowerShell timeout must be 1..300 seconds')
    if sample.suffix.lower() != '.ps1':
        raise ValueError('PowerShell input must be a .ps1 file')
    source = _read_bounded(sample, MAX_SCRIPT)
    if persona_path and not guest_tools_build:
        raise ValueError('A Windows persona requires --guest-tools-build')
    guest_tools = None
    persona = None
    persona_bytes = b''
    persona_sha256 = ''
    if guest_tools_build:
        from .persona import load_persona
        guest_tools = json.loads(_read_bounded(guest_tools_build, 65536))
        if (not isinstance(guest_tools, dict) or guest_tools.get('schema') != 1 or guest_tools.get('sdk_image') != SDK_IMAGE or
                not isinstance(guest_tools.get('image_id'), str) or not re.fullmatch(r'sha256:[a-f0-9]{64}', guest_tools['image_id']) or
                any(not isinstance(guest_tools.get(k), str) or not re.fullmatch('[a-f0-9]{64}', guest_tools[k])
                    for k in ('build_sha256', 'wheel_sha256')) or
                not isinstance(guest_tools.get('program_names'), list) or not 1 <= len(guest_tools['program_names']) <= 128 or
                any(not isinstance(n, str) or not re.fullmatch('[a-z0-9-]+[.]exe', n) for n in guest_tools['program_names'])):
            raise ValueError('Invalid guest tools build evidence')
        persona = load_persona(persona_path)
        persona_bytes = json.dumps(persona, ensure_ascii=True, separators=(',', ':')).encode('ascii')
        if len(persona_bytes) > 4 * 1024 * 1024:
            raise ValueError('Windows persona exceeds the guest transfer limit')
        persona_sha256 = hashlib.sha256(persona_bytes).hexdigest()
    payload = _read_bounded(observer, 16 * 1024 * 1024)
    if payload[:6] != b'\x7fELF\x02\x01':
        raise ValueError('Observer must be a trusted built Linux x86-64 ELF')
    engine_payload = _read_bounded(instrumented_engine, 32 * 1024 * 1024)
    build = json.loads(_read_bounded(instrumented_engine.with_suffix('.build.json'), 65536))
    if (build.get('source_commit') != SOURCE_COMMIT or build.get('sdk_image') != SDK_IMAGE or
            build.get('assembly_sha256') != hashlib.sha256(engine_payload).hexdigest()):
        raise ValueError('Instrumented engine does not match its pinned build evidence')
    daemon = json.loads(docker('info', '--format', '{{json .}}'))
    if daemon.get('OSType') != 'linux' or daemon.get('OperatingSystem') != 'Docker Desktop':
        raise ValueError('This execution mode requires Docker Desktop with its Linux VM')
    base = json.loads(docker('image', 'inspect', SDK_IMAGE))[0]
    if base['Os'] != 'linux' or base['Architecture'] != 'amd64':
        raise ValueError('Pinned Linux amd64 SDK image is required')
    runtime_base = SDK_IMAGE
    if guest_tools:
        tool_info = json.loads(docker('image', 'inspect', guest_tools['image_id']))[0]
        labels = tool_info['Config'].get('Labels', {})
        if (tool_info['Id'] != guest_tools['image_id'] or tool_info['Os'] != 'linux' or tool_info['Architecture'] != 'amd64' or
                labels.get('org.emumee.guest-tools.schema') != '1' or
                labels.get('org.emumee.guest-tools.build') != guest_tools['build_sha256'] or
                labels.get('org.emumee.guest-tools.wheel') != guest_tools['wheel_sha256']):
            raise ValueError('Guest tools image does not match build evidence')
        runtime_base = guest_tools['image_id']
    image = observer_image(runtime_base, payload, engine_payload)
    name = 'emumee-powershell-' + uuid.uuid4().hex
    # The script travels through observer stdin into tmpfs; never a bind mount or image layer.
    created = False
    try:
        docker('create', '--name', name, '--interactive', '--pull=never', '--network=none',
               '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges=true',
               '--user=65534:65534', '--pids-limit=64', '--memory=512m', '--memory-swap=512m', '--cpus=1',
               '--ipc=private', '--hostname=emumee-powershell', '--workdir=/work', '--log-driver=none',
               '--tmpfs=/work:rw,nosuid,nodev,noexec,size=16m,mode=1777',
               '--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=16m,mode=1777',
               '--env=HOME=/work', '--env=POWERSHELL_TELEMETRY_OPTOUT=1',
               '--env=DOTNET_CLI_TELEMETRY_OPTOUT=1', '--env=DOTNET_EnableDiagnostics=0',
               '--env=OPENSSL_CONF=/dev/null', '--entrypoint=', image, '/observer',
               '--script-persona' if guest_tools else '--script', timeout=90)
        created = True
        info = json.loads(docker('inspect', name))[0]
        checks = configuration_checks(info, persona_mode=bool(guest_tools))
        if not all(checks.values()):
            raise RuntimeError('Container configuration failed checks: ' + ', '.join(k for k, v in checks.items() if not v))
        key = secrets.token_bytes(32)
        started = dt.datetime.now(dt.timezone.utc).isoformat()
        input_bytes = key + len(source).to_bytes(4, 'big') + source
        if guest_tools:
            input_bytes += len(persona_bytes).to_bytes(4, 'big') + persona_bytes
        raw, stderr, stop_reason = _attach(name, input_bytes, timeout)
        state = json.loads(docker('inspect', name))[0]['State']
        if state['Running']:
            raise RuntimeError('Container still running after attach ended')
        errors = []
        # A killed observer can leave its last write incomplete. Authenticate every retained whole line.
        if raw and not raw.endswith(b'\n'):
            raw = raw[:raw.rfind(b'\n') + 1]
            errors.append('Observer output ended with an incomplete record')
        try:
            events = verified_events(raw, key, require_finished=False)
        except (ValueError, TypeError, KeyError, RecursionError, UnicodeError) as error:
            events = []
            errors.append('Observer trace rejected: ' + str(error))
        complete = bool(events and events[-1]['event'] == 'observer_finished')
        commands, network, console, parse_errors = project_trace(events,
            guest_tools=guest_tools['program_names'] if guest_tools else None, persona_sha256=persona_sha256)
        errors.extend(parse_errors)
        if not complete:
            errors.append('Observer lifecycle did not finish; retained records are incomplete')
        errors.extend(e.get('reason', 'Observer error') for e in events if e['event'] == 'observer_error')
        if state.get('OOMKilled'):
            errors.append('Container memory limit reached')
        if stop_reason:
            errors.append('Container stopped: ' + stop_reason)
        if stderr:
            errors.append('Docker attach diagnostics: ' + stderr.decode('utf-8', errors='replace')[:2000])
        root_exit = events[-1].get('root_exit_code') if complete else None
        if root_exit is not None and root_exit != 0:
            errors.append(f'PowerShell exited with code {root_exit}')
        limitations = list(LIMITATIONS)
        if guest_tools:
            limitations[0] = 'Bundled Windows utilities use per-invocation x64 CPU emulation and persona snapshots; full Windows APIs and persistent shared state remain incomplete'
            limitations.append('Utility records are guest-generated; persona hash comparisons are diagnostic, not tamper-resistant attestation')
            limitations.append('Linux native exit status exposes the low eight bits; the model record retains the full Windows utility exit code')
        return {'source': source.decode('utf-16' if source[:2] in (b'\xff\xfe', b'\xfe\xff') else 'utf-8-sig', errors='replace'),
                'sample_name': sample.name, 'sample_sha256': hashlib.sha256(source).hexdigest(),
                'input_bytes_base64': base64.b64encode(source).decode('ascii'),
                'execution_started_at': started, 'execution_finished_at': dt.datetime.now(dt.timezone.utc).isoformat(),
                'image': SDK_IMAGE, 'image_id': image, 'base_image_id': base['Id'],
                'observer_sha256': hashlib.sha256(payload).hexdigest(), 'instrumented_engine_build': build,
                'guest_tools_build': guest_tools, 'windows_persona': persona, 'persona_sha256': persona_sha256,
                'configuration_checks': checks, 'observer_events': events, 'observer_trace_complete': complete,
                'command_events': commands, 'network_events': network, 'console_output': console,
                'errors': errors, 'guest_exit_code': root_exit, 'timeout_reached': stop_reason == 'timeout',
                'completion_reason': 'timeout' if stop_reason == 'timeout' else ('error' if errors else 'exit_process'),
                'limitations': limitations}
    finally:
        if created:
            docker('rm', '--force', name)


def save_script_run(report: dict, root: Path) -> Path:
    now = dt.datetime.now(dt.timezone.utc)
    run_id = now.strftime('%Y%m%dT%H%M%SZ-') + uuid.uuid4().hex[:8]
    engine = {'command_events': report['command_events'], 'network_events': report['network_events'],
              'command_capture': {'complete': False, 'source': 'engine_instrumentation_and_external_native',
                                  'dropped_events': None,
                                  'event_loss_unknown': not report['observer_trace_complete'],
                                  'observer_state': 'no_interruption_observed' if report['observer_trace_complete'] else 'terminated',
                                  'limitations': report['limitations']},
              'submitted_script_source': report['source'], 'execution_evidence': report}
    payload = json.dumps(engine, indent=2, ensure_ascii=False).encode('utf-8')
    summary = {'id': run_id, 'status': 'partial', 'engine': 'powershell-container',
               'sample': {'name': report['sample_name'], 'kind': 'powershell', 'managed': True,
                          'architecture': 'x64', 'sha256': report['sample_sha256']},
               'started_at': report['execution_started_at'], 'finished_at': report['execution_finished_at'],
               'guest_exit_code': report['guest_exit_code'], 'completion_reason': report['completion_reason'],
               'guest_trace_complete': False, 'timeout_reached': report['timeout_reached'],
               'errors': report['errors'], 'artifacts': [], 'console_output': report['console_output'],
               'engine_report': 'engine-report.json', 'engine_report_size': len(payload),
               'engine_report_sha256': hashlib.sha256(payload).hexdigest(),
               'network_attempts': report['network_events'][:1000],
               'network_attempts_omitted': max(0, len(report['network_events']) - 1000),
               'run_manifest': {'probe_only': False, 'execution_boundary': 'docker-desktop-linux-vm',
                                'network_mode': 'none', 'image': report['image'], 'image_id': report['image_id'],
                                'configuration_checks': report['configuration_checks'],
                                'guest_tools_build': report.get('guest_tools_build'),
                                'persona_sha256': report.get('persona_sha256'),
                                'engine_report_integrity': ENGINE_INTEGRITY}}
    if not valid_summary(summary):
        raise ValueError('Invalid PowerShell report envelope')
    root.mkdir(parents=True, exist_ok=True)
    run = root / run_id
    run.mkdir()
    (run / 'engine-report.json').write_bytes(payload)
    (run / 'summary.json').write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding='utf-8')
    return run
