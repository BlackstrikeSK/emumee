"""Execute and independently seal the bounded M2 binding/rollback/import exit."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from native_pe_staging_seal import binding, seal as staging_seal
from native_pe_worklist import atomic_write, fingerprint

ROOT = Path(__file__).resolve().parents[1]
CASES = ('normal', 'request', 'primary', 'slot', 'swap', 'missing', 'extra',
         'persona', 'persona-missing', 'persona-unexpected', 'schema', 'options',
         'size', 'hash', 'path', 'quota', 'architecture', 'partial-load',
         'parent-options', 'parent-artifact')
EXITS = dict(Named=17, Ordinal=17, DataNamed=43, DataOrdinal=43,
             DelayNamed=17, DllStartup=1)
EXITS.update({f'Dll{case}': value for case, value in tuple(EXITS.items()) if case != 'DllStartup'})
ERRORS = dict(request='request changed', primary='input hash/size changed',
              slot='hash/size changed', swap='hash/size changed', missing='slot inventory differs',
              extra='slot inventory differs', persona='persona changed',
              schema='identity/profile', options='argument quoting', size='file type, links or size',
              hash='hash/size changed', path='Invalid or duplicate submitted guest file',
              quota='staged byte/module quota', architecture='same-architecture native DLL')
ERRORS.update({'persona-missing': 'os error 2', 'persona-unexpected': 'Unexpected submitted persona',
               'partial-load': 'overlapping'})


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def verify_control(directory, case, architecture):
    receipt = json.loads((directory / 'binding-verification.json').read_bytes())
    assert receipt == dict(schema=1, case=case, architecture=architecture.lower(), verified=True,
                           worker_exit=0 if case in ('normal', 'parent-options', 'parent-artifact') else 2,
                           cleanup='restored', request_sha256=receipt['request_sha256'])
    assert not (directory / 'manifest.json').exists()
    actual_hash = sha((directory / 'request.json').read_bytes())
    assert (actual_hash == receipt['request_sha256']) is (case != 'request')
    job = json.loads((directory / 'general-job-profile.json').read_bytes())
    assert job['profile'] == 'submitted_user_1024_v1' and job['cleanup'] == 'restored'
    assert 0 < job['peak_process_memory_bytes'] <= job['process_memory_bytes'] == 1024 * 1024 * 1024
    assert job['active_process_limit'] == 1 and job['network_capabilities'] == 0
    assert job['output_limits'] == dict(max_bytes=512 * 1024 * 1024, max_entries=4200,
                                        max_directories=8, max_depth=4)
    stop = json.loads((directory / 'worker-stop.json').read_bytes())
    assert stop['cleanup'] == 'restored'
    assert stop['worker']['reason'] == 'exited' and stop['worker']['exit_code'] == receipt['worker_exit']
    containment = json.loads((directory / 'worker/containment.json').read_bytes())
    assert all(containment[key] is True for key in ('app_container', 'job_object', 'child_process_blocked'))
    assert containment['network_capabilities'] == 0
    if receipt['worker_exit'] == 2:
        assert not (directory / 'worker/result.json').exists()
        assert ERRORS[case] in (directory / 'worker/error.txt').read_text(encoding='utf-8')
    else:
        result = json.loads((directory / 'worker/result.json').read_bytes())
        request = json.loads((directory / 'request.json').read_bytes())
        assert result['input_receipt'] == request
        assert result['request_sha256'] == receipt['request_sha256'] == sha((directory / 'request.json').read_bytes())
        assert sha((directory / 'input.pe').read_bytes()) == request['input_sha256']
        assert sha((directory / 'persona.json').read_bytes()) == request['persona_sha256']
        for index, item in enumerate(request['staged']):
            raw = (directory / f'inputs/{index:04}.bin').read_bytes()
            assert len(raw) == item['size'] and sha(raw) == item['sha256']
        assert result['execution']['max_instructions'] == request['max_instructions']
        assert result['execution']['architecture'] == architecture.lower()
        assert 0 < result['execution']['instruction_count'] <= request['max_instructions']
        assert result['execution']['guest_entry_return'] == 42 and result['execution']['error'] is None
        if case.startswith('parent-'):
            rejected = json.loads((directory / 'parent-rejected.json').read_bytes())
            if case == 'parent-options':
                assert rejected['input_receipt'] != request
            else:
                artifact = rejected['execution']['artifacts'][0]
                assert artifact['filename'] != artifact['sha256'] + '.bin'
    return receipt


def run(root):
    output = root / 'binding'
    output.mkdir()
    executable = root / 'bundle/emumee-rs.exe'
    records = []
    for architecture in ('X86', 'X64'):
        for case in CASES:
            label = f'{architecture}-{case}'
            command = [str(executable), 'user-binding-fixture', case, str(output / label), architecture.lower()]
            completed = subprocess.run(command, capture_output=True, timeout=60)
            (output / f'{label}.stdout').write_bytes(completed.stdout)
            (output / f'{label}.stderr').write_bytes(completed.stderr)
            assert completed.returncode == 0, (label, completed.returncode, completed.stderr.decode(errors='replace'))
            records.append(verify_control(output / label, case, architecture))
        for case, expected in EXITS.items():
            label = f'{architecture}-exit-{case}'
            fixture = root / 'fixtures-final' / label
            source = fixture / ('imports.dll' if case.startswith('Dll') else 'imports.exe')
            directory = output / label
            command = [str(executable), 'run', str(source), '--inputs', str(fixture / 'inputs.json'), '--output', str(directory), '--max-instructions', '2000']
            completed = subprocess.run(command, capture_output=True, timeout=60)
            (output / f'{label}.stdout').write_bytes(completed.stdout)
            (output / f'{label}.stderr').write_bytes(completed.stderr)
            assert completed.returncode == 0, (label, completed.stderr.decode(errors='replace'))
            manifest = binding(directory, source)
            assert manifest['result']['execution']['guest_entry_return'] == expected
            assert manifest['result']['execution']['error'] is None
            records.append(dict(case=label, verified=True, return_value=expected))
        label = f'{architecture}-after-refusals'
        completed = subprocess.run([str(executable), 'user-binding-fixture', 'normal', str(output / label), architecture.lower()], capture_output=True, timeout=60)
        (output / f'{label}.stdout').write_bytes(completed.stdout)
        (output / f'{label}.stderr').write_bytes(completed.stderr)
        assert completed.returncode == 0, completed.stderr.decode(errors='replace')
        records.append(verify_control(output / label, 'normal', architecture))
    atomic_write(output / 'verification.json', json.dumps(records, indent=2) + '\n')


def seal(root, check=False):
    staging_seal(root, check=True)
    records = []
    for architecture in ('X86', 'X64'):
        for case in CASES:
            records.append(verify_control(root / 'binding' / f'{architecture}-{case}', case, architecture))
        for case, expected in EXITS.items():
            directory = root / 'binding' / f'{architecture}-exit-{case}'
            fixture = root / 'fixtures-final' / f'{architecture}-exit-{case}'
            source = fixture / ('imports.dll' if case.startswith('Dll') else 'imports.exe')
            manifest = binding(directory, source)
            execution = manifest['result']['execution']
            assert execution['guest_entry_return'] == expected and execution['error'] is None
            request = json.loads((directory / 'request.json').read_bytes())
            spec = json.loads((fixture / 'inputs.json').read_bytes())
            assert len(request['staged']) == len(spec['files'])
            assert spec['files'] or case == 'DllStartup'
            for index, item in enumerate(spec['files']):
                raw = (fixture / item['source']).read_bytes()
                assert (directory / f'inputs/{index:04}.bin').read_bytes() == raw
                assert request['staged'][index] == dict(kind=item['kind'], guest_path=item['guest_path'], size=len(raw), sha256=sha(raw))
            if 'Delay' in case:
                assert len(execution['delay_imports']) == 1 and execution['delay_imports'][0]['error'] is None
            records.append(dict(case=f'{architecture}-exit-{case}', verified=True, return_value=expected))
        records.append(verify_control(root / 'binding' / f'{architecture}-after-refusals', 'normal', architecture))
    assert json.loads((root / 'binding/verification.json').read_bytes()) == records
    artifacts = []
    for path in sorted((root / 'binding').rglob('*')):
        if path.is_file():
            artifacts.append(dict(path=path.relative_to(ROOT).as_posix(), size=path.stat().st_size, sha256=sha(path.read_bytes())))
    document = dict(schema=1, scope='M2 complete bounded PE input/import/ABI foundations; not M3/M10 or API semantic parity',
                    prior_matrix_sha256=sha((root / 'qualified-smoke.json').read_bytes()), controls=records, artifacts=artifacts)
    document['fingerprint'] = fingerprint(document)
    destination = root / 'qualified-m2.json'
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
