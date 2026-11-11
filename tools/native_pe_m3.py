"""Qualify the first M3 bootstrap checkbox; not the complete M3 lifecycle."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from native_pe_m2 import seal as m2_seal
from native_pe_staging_seal import binding
from native_pe_worklist import atomic_write, fingerprint

ROOT = Path(__file__).resolve().parents[1]
SIZE = 0x125000


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def cases():
    for architecture in ('X86', 'X64'):
        for extension in ('exe', 'dll'):
            for kind in ('Basic', 'Mutation', 'Protect', 'Free'):
                for persona in ('default', 'configured'):
                    yield architecture, extension, kind, persona
        yield architecture, 'exe', 'Boundary', 'default'


def check_bootstrap(execution, architecture, kind):
    bootstrap = execution['user_bootstrap']
    assert bootstrap['process_id'] == 1024 and bootstrap['thread_id'] == 1
    assert bootstrap['mapped_bytes'] == SIZE
    assert bootstrap['image_base'] == (0x400000 if architecture == 'X86' else 0x140000000)
    assert bootstrap['stack_limit'] == 0x70000000 and bootstrap['stack_base'] == 0x70100000
    assert 0 < bootstrap['teb'] < 2**32 and bootstrap['teb'] % 4096 == 0
    assert bootstrap['peb'] == bootstrap['teb'] + 0x2000
    assert bootstrap['process_parameters'] == bootstrap['teb'] + 0x3000
    assert bootstrap['environment'] == bootstrap['teb'] + 0x25000
    assert 0 < bootstrap['command_line'] < 2**32 and bootstrap['command_line'] != bootstrap['teb']
    assert execution['max_instructions'] == 500000
    assert 0 < execution['instruction_count'] <= execution['max_instructions']
    if kind in ('Protect', 'Free'):
        assert isinstance(execution['error'], str) and 'owned user bootstrap' in execution['error']
        assert execution['guest_entry_return'] is None
        assert execution['completion_reason'] != 'entry_return'
    else:
        assert execution['error'] is None and execution['guest_entry_return'] == 1
        assert execution['completion_reason'] == 'entry_return'
    assert all(event['thread_id'] == 1 for event in execution['api_events'])


def reference(root):
    program = '''import hashlib,json,pathlib
from speakeasy.winenv.defs.nt.ntoskrnl import PEB,TEB,RTL_USER_PROCESS_PARAMETERS
import speakeasy.winenv.defs.nt.ntoskrnl as definitions
result={"definitions_sha256":hashlib.sha256(pathlib.Path(definitions.__file__).read_bytes()).hexdigest(),"layouts":{},"parameter_sizes":{}}
for width in (4,8):
 rows={}
 for kind,fields in [(TEB,["NtTib","ClientId","ThreadLocalStoragePointer","ProcessEnvironmentBlock","LastErrorValue"]),(PEB,["ImageBaseAddress","ProcessParameters","NumberOfProcessors","OSMajorVersion","OSBuildNumber"]),(RTL_USER_PROCESS_PARAMETERS,["StandardInput","CurrentDirectory","ImagePathName","CommandLine","Environment","DesktopInfo"])]:
  value=kind(width);rows[kind.__name__]={name:getattr(value.__struct__.__class__,name).offset for name in fields}
 result["layouts"][str(width)]=rows
 result["parameter_sizes"][str(width)]=RTL_USER_PROCESS_PARAMETERS(width).sizeof()
print(json.dumps(result))
'''
    completed = subprocess.run([str(ROOT / '.venv/Scripts/python.exe'), '-c', program], capture_output=True, check=True, timeout=30)
    document = json.loads(completed.stdout)
    verify_reference(document)
    atomic_write(root / 'bootstrap-reference.json', json.dumps(document, indent=2) + '\n')


def verify_reference(document):
    source = ROOT / '.venv/Lib/site-packages/speakeasy/winenv/defs/nt/ntoskrnl.py'
    assert sha(source.read_bytes()) == document['definitions_sha256']
    assert document['parameter_sizes'] == {'4': 144, '8': 240}
    for width, expected in [('4', [(0,32,44,48,52), (8,16,100,164,172), (24,36,56,64,72,120)]),
                            ('8', [(0,64,88,96,104), (16,32,184,280,288), (32,56,96,112,128,192)])]:
        for kind, fields, offsets in zip(('TEB','PEB','RTL_USER_PROCESS_PARAMETERS'),
            (('NtTib','ClientId','ThreadLocalStoragePointer','ProcessEnvironmentBlock','LastErrorValue'),
             ('ImageBaseAddress','ProcessParameters','NumberOfProcessors','OSMajorVersion','OSBuildNumber'),
             ('StandardInput','CurrentDirectory','ImagePathName','CommandLine','Environment','DesktopInfo')), expected):
            assert document['layouts'][width][kind] == dict(zip(fields, offsets))


def verify(root, architecture, extension, kind, persona):
    label = f'{architecture}-bootstrap-{kind}-{extension}-{persona}'
    fixture = root / 'fixtures-final' / label
    directory = root / 'bootstrap' / label
    manifest = binding(directory, fixture / f'bootstrap.{extension}')
    receipt = json.loads((root / 'bundle/rust-worker-build.json').read_bytes())
    assert manifest['source_tree_sha256'] == receipt['source_tree_sha256']
    assert manifest['bundle_receipt'] == receipt
    execution = manifest['result']['execution']
    assert execution['architecture'] == architecture.lower()
    check_bootstrap(execution, architecture, kind)
    request = manifest['result']['input_receipt']
    assert request['module_name'] == f'bootstrap.{extension}'
    assert request['max_instructions'] == execution['max_instructions'] == 500000
    assert request['timeout_us'] == 30000000
    spec = json.loads((fixture / 'inputs.json').read_bytes())
    assert request['invocation'] == spec['invocation']
    assert request['arguments'] == json.loads((fixture / 'arguments.json').read_bytes())
    assert request['staged'] == spec['files'] == []
    assert (request['persona_sha256'] is not None) == (persona == 'configured')
    if persona == 'configured':
        assert (directory / 'persona.json').read_bytes() == (fixture / 'persona.json').read_bytes()
    job = json.loads((directory / 'general-job-profile.json').read_bytes())
    assert job['profile'] == 'submitted_user_1024_v1' and job['cleanup'] == 'restored'
    assert 0 < job['peak_process_memory_bytes'] <= job['process_memory_bytes'] == 1024**3
    assert job['active_process_limit'] == 1 and job['network_capabilities'] == 0
    stop = json.loads((directory / 'worker-stop.json').read_bytes())
    assert stop['cleanup'] == 'restored' and stop['worker']['reason'] == 'exited' and stop['worker']['exit_code'] == 0
    return dict(case=label, verified=True, expected_guest_refusal=kind in ('Protect', 'Free'))


def run(root):
    output = root / 'bootstrap'
    output.mkdir()
    reference(root)
    executable = (root / 'bundle/emumee-rs.exe').resolve()
    records = []
    for architecture, extension, kind, persona in cases():
        label = f'{architecture}-bootstrap-{kind}-{extension}-{persona}'
        fixture = root / 'fixtures-final' / label
        command = [str(executable), 'run', str(fixture / f'bootstrap.{extension}'), '--output', str(output / label),
                   '--inputs', str(fixture / 'inputs.json'), '--max-instructions', '500000', '--timeout-us', '30000000']
        if persona == 'configured':
            command += ['--persona', str(fixture / 'persona.json')]
        if kind == 'Boundary':
            command = [str(executable), 'user-bootstrap-boundary-fixture', str(fixture / 'bootstrap.exe'),
                       str(output / label), architecture.lower()]
        else:
            command += ['--', *json.loads((fixture / 'arguments.json').read_bytes())]
        completed = subprocess.run(command, capture_output=True, timeout=60)
        (output / f'{label}.stdout').write_bytes(completed.stdout)
        (output / f'{label}.stderr').write_bytes(completed.stderr)
        assert completed.returncode == (1 if kind in ('Protect', 'Free') else 0), (label, completed.returncode, completed.stderr.decode(errors='replace'))
        records.append(verify(root, architecture, extension, kind, persona))
    atomic_write(output / 'verification.json', json.dumps(records, indent=2) + '\n')


def seal(root, check=False):
    m2_seal(root, check=True)
    verify_reference(json.loads((root / 'bootstrap-reference.json').read_bytes()))
    records = [verify(root, *case) for case in cases()]
    assert json.loads((root / 'bootstrap/verification.json').read_bytes()) == records
    paths = [root / 'bootstrap-reference.json', *(path for path in sorted((root / 'bootstrap').rglob('*')) if path.is_file())]
    artifacts = [dict(path=path.relative_to(ROOT).as_posix(), size=path.stat().st_size, sha256=sha(path.read_bytes())) for path in paths]
    document = dict(schema=1, scope='First M3 bootstrap checkbox only; not loader-list/static-TLS/lifecycle closure',
                    prior_m2_sha256=sha((root / 'qualified-m2.json').read_bytes()), controls=records, artifacts=artifacts)
    document['fingerprint'] = fingerprint(document)
    destination = root / 'qualified-bootstrap.json'
    if check:
        assert json.loads(destination.read_bytes()) == document
    else:
        assert not destination.exists(), 'Preserve sealed evidence'
        atomic_write(destination, json.dumps(document, indent=2) + '\n')
    print(json.dumps(dict(controls=len(records), files=len(artifacts), fingerprint=document['fingerprint']), indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--seal', action='store_true')
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    if args.seal or args.check:
        seal(args.root.resolve(), check=args.check)
    else:
        run(args.root.resolve())
