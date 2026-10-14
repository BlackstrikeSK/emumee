"""Guest-only bridge from Linux native shims to generated Windows PE emulation."""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

from .enumeration_programs import enumeration_programs
from .guest_programs import hostname_exe
from .persona import load_persona


def programs(persona):
    return {"hostname.exe": hostname_exe(True), **enumeration_programs(True, persona)}


def program_names():
    return sorted(programs(load_persona(None)))


def emulate(program: str, arguments: list[str], persona_path: Path) -> tuple[dict, dict]:
    """No external process, network broker, arbitrary PE, or host path fallback."""
    from .native import run_native
    from .pe import inspect_pe

    if len(arguments) > 64 or any(not isinstance(a, str) or len(a.encode('utf-8')) > 16000 for a in arguments):
        raise ValueError("Guest utility arguments exceed bounds")
    with persona_path.open('rb') as stream:
        raw_persona = stream.read(4 * 1024 * 1024 + 1)
    if not raw_persona or len(raw_persona) > 4 * 1024 * 1024:
        raise ValueError("Guest persona exceeds bounds")
    persona = load_persona(None, document=json.loads(raw_persona))
    name = program.lower()
    if not name.endswith('.exe'):
        name += '.exe'
    images = programs(persona)
    if name not in images:
        raise ValueError("Unknown guest enumeration program")
    image = images[name]
    with tempfile.TemporaryDirectory(prefix='emumee-tool-', dir='/tmp') as directory:
        with open(os.devnull, 'w') as silent, contextlib.redirect_stdout(silent), contextlib.redirect_stderr(silent):
            result = run_native(image, inspect_pe(image, name), persona, Path(directory), [],
                                10, 500_000, guest_args=arguments)
        with (Path(directory) / result['engine_report']).open('rb') as stream:
            raw_report = stream.read(16 * 1024 * 1024 + 1)
        if len(raw_report) > 16 * 1024 * 1024:
            raise ValueError("Guest utility report exceeds bounds")
        report = json.loads(raw_report)
    exit_code = result['guest_exit_code']
    if exit_code is None:
        exit_code = result.get('guest_entry_return')
    if exit_code is None or result['errors']:
        exit_code = 1
    event = {'event': 'guest_windows_enumeration', 'program': name, 'arguments': arguments,
             'persona_sha256': hashlib.sha256(raw_persona).hexdigest(),
             'pe_sha256': hashlib.sha256(image).hexdigest(),
             'guest_exit_code': exit_code, 'completion_reason': result['completion_reason'],
             'errors': [str(e)[:2048] for e in result['errors'][:8]],
             'network_events': report.get('network_events', [])[:16],
             'network_events_truncated': len(report.get('network_events', [])) > 16,
             'network_broker_available': False, 'architecture': 'x64',
             'console_truncated': any(result['console_output'][s + '_truncated'] for s in ('stdout', 'stderr'))}
    return result['console_output'], event


def main():
    try:
        output, event = emulate(sys.argv[1], sys.argv[2:], Path('/work/persona.json'))
        raw = json.dumps(event, ensure_ascii=True, separators=(',', ':')).encode('ascii')
        if len(raw) > 65536:
            event.update(network_events=[], network_events_truncated=True)
            raw = json.dumps(event, ensure_ascii=True, separators=(',', ':')).encode('ascii')
        if len(raw) > 65536 or os.write(197, raw) != len(raw):
            raise ValueError('Guest utility record transport failed')
        for stream, fd in (('stdout', 1), ('stderr', 2)):
            data = output[stream].encode('utf-8')
            while data:
                written = os.write(fd, data[:4096])
                if written <= 0:
                    raise ValueError('Guest utility console transport failed')
                data = data[written:]
        return event['guest_exit_code'] & 255
    except Exception as error:
        print('Guest Windows utility failed: ' + str(error)[:1024], file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
