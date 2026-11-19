"""Replay source-tested M4 guests in containment and seal their exact evidence."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from native_pe_m3_lifecycle import seal as lifecycle_seal
from native_pe_staging_seal import binding, source_fingerprint
from native_pe_validation import load_policy, source_snapshot, verify_index
from native_pe_worklist import atomic_write, fingerprint

ROOT = Path(__file__).resolve().parents[1]
FIELDS = (
    'architecture', 'completion_reason', 'guest_entry_return', 'process_exit_code',
    'instruction_count', 'max_instructions', 'maximum_continuation_depth', 'final_pc',
    'error', 'native_memory_fault', 'api_calls', 'api_events', 'api_events_omitted',
    'user_bootstrap', 'user_threads', 'user_lifecycle', 'user_processes', 'native_exceptions',
    'dynamic_loader', 'user_loader', 'crt_startup', 'provider_denials',
    'provider_denials_omitted', 'virtual_uptime_ms', 'artifacts', 'console', 'file_storage',
)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def required_cases():
    common = (
        'beginthread', 'beginthreadex', 'dispatcher', 'halt', 'apc',
        'thread-authority', 'thread-context', 'root-forced-exit', 'root-thread-exit',
        'root-foreign-terminate', 'root-handle', 'handle-namespaces', 'dispatcher-authority',
        'fls-callback-deadlock', 'fls-callback-wait', 'fls-retirement-deadlock',
        'fls-retirement-wait', 'apc-callback-deadlock', 'apc-callback-wait',
        'root-retirement-deadlock', 'root-retirement-wait', 'fls-retirement-pass-bound',
        'fls-retirement-repopulate', 'nested-alertable-apcs', 'veh-wait-deadlock',
        'veh-wait', 'veh-nesting-bound', 'veh-nested-context', 'unhandled-filter-continue',
        'vectored-continue-phase', 'raise-noncontinuable', 'raise-continue',
        'notification-wait-deadlock', 'notification-attach-detach-waits',
        'exit-inside-veh', 'exit-inside-apc', 'worker-process-detach-owner',
    )
    common += tuple(f'fls-{mode}' for mode in range(5))
    common += tuple(f'veh-fault-{mode}' for mode in range(5))
    common += tuple(f'actual-{kind}' for kind in ('Signal', 'Quantum', 'Deadlock', 'Timeout'))
    names = {f'{arch}-m4-{name}' for arch in ('X86', 'X64') for name in common}
    names.update(f'X86-m4-x86-seh-chain-{mode}' for mode in range(3))
    names.update(f'X64-m4-runtime-function-table-{mode}' for mode in range(3))
    names.update(f'X64-m4-{name}' for name in (
        'worker-runtime-function-table', 'fls-nested-exception', 'fls-exception-continuation'))
    return names


def projection(execution):
    return {key: execution.get(key) for key in FIELDS}


def required_eh4_cases():
    names = ('continue-negative', 'filter-search', 'accept-positive', 'gs-cookie',
             'topmost-search', 'local-finally', 'global-local-unwind')
    negatives = ('cycle', 'level', 'table', 'filter-address', 'handler-address',
                 'cookie-offset', 'cookie', 'gs-cookie', 'revalidation',
                 'finally-revalidation', 'filter-abi', 'checker-abi',
                 'noncontinuable', 'global-disposition')
    return {f'X86-m4-eh4-{name}' for name in names + tuple(f'reject-{name}' for name in negatives)}


def required_process_cases():
    names = ('isolation', 'suspended-isolation', 'terminate', 'fault', 'budget',
             'missing', 'bad-output', 'CreateProcessW', 'CreateProcessInternalA',
             'CreateProcessInternalW', 'WinExec', 'extension', 'remote-thread-context-protect',
             'state-isolation', 'inherit-handles', 'no-inherit-handles', 'quota',
             'wrong-arch', 'deadlines', 'deadlock')
    return {f'{architecture}-m4-process-{name}' for architecture in ('X86', 'X64') for name in names}


def check_execution(execution, expected, limits, architecture):
    assert architecture in ('x86', 'x64')
    assert execution['architecture'] == expected['architecture'] == architecture
    assert execution['max_instructions'] == limits['max_instructions']
    assert type(execution['instruction_count']) is int
    assert 0 <= execution['instruction_count'] <= limits['max_instructions']
    assert execution['completion_reason'] in ('entry_return', 'process_exit', 'instruction_budget', 'error')
    assert projection(execution) == projection(expected), 'Contained M4 outcome differs from its source-tested execution'
    if execution['completion_reason'] == 'entry_return':
        assert execution['guest_entry_return'] == 1 and execution['error'] is None
    if execution['completion_reason'] in ('entry_return', 'process_exit'):
        assert all(not event['pending'] for event in execution['api_events'])
    if execution['completion_reason'] == 'instruction_budget':
        assert execution['instruction_count'] == limits['max_instructions']
    if execution['completion_reason'] == 'error':
        assert isinstance(execution['error'], str) and execution['error']


def cases(root):
    fixtures = root / 'fixtures-final'
    selected = sorted(path for path in fixtures.iterdir() if path.is_dir() and '-m4-' in path.name)
    names = {path.name for path in selected}
    assert required_cases() <= names, f'Missing M4 source controls: {sorted(required_cases() - names)}'
    assert required_eh4_cases() <= names, f'Missing EH4 source controls: {sorted(required_eh4_cases() - names)}'
    assert required_process_cases() <= names, f'Missing isolated process source controls: {sorted(required_process_cases() - names)}'
    for fixture in selected:
        assert (fixture / 'source-execution.json').is_file(), f'Missing source-tested outcome: {fixture.name}'
    return selected


def verify(root, fixture):
    run = root / 'm4' / fixture.name
    spec = json.loads((fixture / 'inputs.json').read_bytes())
    sources = [path for path in fixture.iterdir() if path.suffix.lower() in ('.exe', '.dll')]
    assert len(sources) == 1
    manifest = binding(run, sources[0])
    receipt = json.loads((root / 'bundle/rust-worker-build.json').read_bytes())
    assert manifest['source_tree_sha256'] == receipt['source_tree_sha256']
    assert manifest['bundle_receipt'] == receipt
    request = manifest['result']['input_receipt']
    assert request['module_name'] == sources[0].name
    assert request['arguments'] == json.loads((fixture / 'arguments.json').read_bytes())
    assert request['invocation'] == spec['invocation']
    assert len(spec['files']) == len(request['staged'])
    for index, (file, staged) in enumerate(zip(spec['files'], request['staged'])):
        raw = (fixture / file['source']).read_bytes()
        assert raw == (run / 'inputs' / f'{index:04}.bin').read_bytes()
        assert staged == dict(kind=file['kind'], guest_path=file['guest_path'], size=len(raw),
                              sha256=hashlib.sha256(raw).hexdigest())
    limits = json.loads((fixture / 'limits.json').read_bytes())
    assert limits == dict(max_instructions=request['max_instructions'], timeout_us=request['timeout_us'])
    expected = json.loads((fixture / 'source-execution.json').read_bytes())
    execution = manifest['result']['execution']
    check_execution(execution, expected, limits, fixture.name.split('-')[0].lower())
    job = json.loads((run / 'general-job-profile.json').read_bytes())
    assert job['profile'] == 'submitted_user_1024_v1' and job['cleanup'] == 'restored'
    assert 0 < job['peak_process_memory_bytes'] <= job['process_memory_bytes'] == 1024**3
    assert job['active_process_limit'] == 1 and job['network_capabilities'] == 0
    stop = json.loads((run / 'worker-stop.json').read_bytes())
    assert stop['cleanup'] == 'restored' and stop['worker']['reason'] == 'exited'
    assert stop['worker']['exit_code'] == 0
    return dict(case=fixture.name, verified=True, completion=execution['completion_reason'],
                instructions=execution['instruction_count'], source_execution_sha256=sha(fixture / 'source-execution.json'))


def source_gate(root, index_path=None):
    policy = load_policy(ROOT)
    index_path = (index_path or root / 'source-validation/index.json').resolve()
    assert index_path.resolve().is_relative_to(root.resolve()), 'Source index must remain within this qualification root'
    index = json.loads(index_path.read_bytes())
    verify_index(ROOT, index, policy)
    assert index['full_baseline'] and index['source_hashes'] == source_snapshot(ROOT)
    assert index['policy_fingerprint'] == fingerprint(policy)
    fixture_root = str((root / 'fixtures-final').resolve())
    assert index['environment']['build_environment_hashes'].get('EMUMEE_USER_TEST_FIXTURES') == hashlib.sha256(fixture_root.encode()).hexdigest(), 'Source validation did not emit these M4 fixtures'
    receipt = json.loads((root / 'bundle/rust-worker-build.json').read_bytes())
    current = source_fingerprint(ROOT)
    assert receipt['source_tree_sha256'] == current['source_tree_sha256']
    assert receipt['source_files'] == current['source_files']
    return index


def run(root, index_path=None):
    source_gate(root, index_path)
    fixtures = cases(root)
    output = root / 'm4'
    output.mkdir()
    executable = (root / 'bundle/emumee-rs.exe').resolve()
    records = []
    for fixture in fixtures:
        limits = json.loads((fixture / 'limits.json').read_bytes())
        expected = json.loads((fixture / 'source-execution.json').read_bytes())
        source, = [path for path in fixture.iterdir() if path.suffix.lower() in ('.exe', '.dll')]
        command = [str(executable), 'run', str(source), '--output', str(output / fixture.name),
                   '--inputs', str(fixture / 'inputs.json'), '--max-instructions', str(limits['max_instructions']),
                   '--timeout-us', str(limits['timeout_us'])]
        if (fixture / 'persona.json').exists():
            command += ['--persona', str(fixture / 'persona.json')]
        command += ['--', *json.loads((fixture / 'arguments.json').read_bytes())]
        completed = subprocess.run(command, capture_output=True, timeout=90)
        (output / f'{fixture.name}.stdout').write_bytes(completed.stdout)
        (output / f'{fixture.name}.stderr').write_bytes(completed.stderr)
        successful = expected['completion_reason'] in ('entry_return', 'process_exit')
        assert completed.returncode == (0 if successful else 1), (fixture.name, completed.returncode, completed.stderr)
        records.append(verify(root, fixture))
        print(fixture.name, 'verified', flush=True)
    atomic_write(output / 'verification.json', json.dumps(records, indent=2) + '\n')


def seal(root, check=False, index_path=None, receipt_path=None):
    index_path = (index_path or root / 'source-validation/index.json').resolve()
    source_gate(root, index_path)
    lifecycle_seal(root, check=True)
    fixtures = cases(root)
    records = [verify(root, fixture) for fixture in fixtures]
    assert json.loads((root / 'm4/verification.json').read_bytes()) == records
    paths = set(path for path in (root / 'm4').rglob('*') if path.is_file())
    paths.update(path for fixture in fixtures for path in fixture.rglob('*') if path.is_file())
    paths.update(path for path in index_path.parent.rglob('*') if path.is_file())
    paths.add(root / 'qualified-m3.json')
    artifacts = [dict(path=path.relative_to(ROOT).as_posix(), size=path.stat().st_size, sha256=sha(path))
                 for path in sorted(paths)]
    document = dict(schema=1, scope='Bounded M4 source-tested guest runtime and contained replay; not API semantic parity or global M10',
                    controls=records, artifacts=artifacts)
    document['fingerprint'] = fingerprint(document)
    destination = (receipt_path or root / 'qualified-m4.json').resolve()
    assert destination.resolve().is_relative_to(root.resolve()), 'M4 receipt must remain within this qualification root'
    if check:
        assert json.loads(destination.read_bytes()) == document
    else:
        assert not destination.exists(), 'Preserve sealed evidence'
        atomic_write(destination, json.dumps(document, indent=2) + '\n')
    print(json.dumps(dict(controls=len(records), files=len(artifacts), fingerprint=document['fingerprint']), indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--source-index', type=Path)
    parser.add_argument('--receipt', type=Path)
    action = parser.add_mutually_exclusive_group()
    action.add_argument('--seal', action='store_true')
    action.add_argument('--check', action='store_true')
    args = parser.parse_args()
    if args.seal or args.check:
        seal(args.root.resolve(), check=args.check, index_path=args.source_index, receipt_path=args.receipt)
    else:
        run(args.root.resolve(), index_path=args.source_index)
