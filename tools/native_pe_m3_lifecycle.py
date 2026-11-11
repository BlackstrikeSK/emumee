"""Execute and independently seal the bounded submitted-user M3 lifecycle matrix."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from native_pe_m3 import seal as bootstrap_seal
from native_pe_staging_seal import binding
from native_pe_worklist import atomic_write, fingerprint

ROOT = Path(__file__).resolve().parents[1]


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def cases():
    for architecture in ('X86', 'X64'):
        for kind in ('normal', 'refusal'):
            yield architecture, 'storage', kind, 'bootstrap.exe'
        for kind in ('existing', 'recursive', 'forwarder'):
            yield architecture, 'graph', kind, 'graph.exe'
        yield architecture, 'provider', '', 'bootstrap.exe'
        for kind in ('MissingModule', 'MissingExport', 'Cycle'):
            yield architecture, 'forwarder', kind, 'graph.exe'
        for forced in ('false', 'true'):
            for loops in ('false', 'true'):
                yield architecture, 'process', f'{forced}-{loops}', 'exit.exe'
        for kind in ('Return', 'Exit', 'Terminate', 'Suspended', 'Budget', 'Fault'):
            yield architecture, 'thread', kind, 'threads.exe'
        for kind in ('Normal', 'Fault', 'Budget', 'BadStack', 'Nonvolatile', 'InvalidTarget'):
            yield architecture, 'callback', kind, 'callbacks.exe'
        for kind in ('Return', 'Exit', 'Terminate', 'Suspended'):
            yield architecture, 'companion-thread', kind, 'threads.exe'
        for kind in ('false', 'true'):
            yield architecture, 'companion-process', kind, 'exit.exe'
        yield architecture, 'tls-quota', '', 'quota.exe'
        for kind in ('false', 'true'):
            yield architecture, 'nested-loader', kind, 'nested.exe'
        yield architecture, 'unresolved-static', '', 'unresolved.exe'


def label(case):
    architecture, family, kind, _ = case
    return f'{architecture}-m3-{family}' + (f'-{kind}' if kind else '')


def expected(case):
    _, family, kind, _ = case
    if family == 'storage' and kind == 'refusal' or family == 'unresolved-static':
        return 'error', None
    if family == 'process':
        return ('error', None) if kind == 'false-true' else ('process_exit', None)
    if family == 'companion-process':
        return 'process_exit', None
    if family in ('thread', 'callback'):
        if kind == 'Budget':
            return 'instruction_budget', None
        if kind in ('Fault', 'BadStack', 'Nonvolatile', 'InvalidTarget'):
            return 'error', None
    return 'entry_return', 1 if family in ('storage', 'provider', 'callback') else 42


def check_execution(execution, case):
    architecture, family, kind, filename = case
    reason, value = expected(case)
    budget = 512 if family == 'process' or kind == 'Budget' else 500000
    assert execution['architecture'] == architecture.lower()
    assert execution['completion_reason'] == reason
    assert execution['guest_entry_return'] == value
    assert execution['max_instructions'] == budget
    assert 0 <= execution['instruction_count'] <= budget
    bootstrap = execution['user_bootstrap']
    assert bootstrap['process_id'] == 1024 and bootstrap['thread_id'] == 1
    assert 0 < bootstrap['teb'] < 2**32 and bootstrap['teb'] % 4096 == 0
    assert bootstrap['peb'] == bootstrap['teb'] + 0x2000
    assert bootstrap['image_base'] == (0x400000 if architecture == 'X86' else 0x140000000)
    assert bootstrap['stack_limit'] == 0x70000000 and bootstrap['stack_base'] == 0x70100000
    if reason == 'error':
        assert isinstance(execution['error'], str) and execution['error']
    else:
        assert execution['error'] is None
    if reason == 'instruction_budget' or family == 'process' and kind == 'false-true':
        assert execution['instruction_count'] == budget
    if family in ('storage', 'unresolved-static') and reason == 'error':
        assert execution['instruction_count'] == 0
        assert ('lacks permission2' if family == 'storage' else 'not an actually modeled binding') in execution['error']
    loader = execution.get('user_loader')
    if not (family == 'unresolved-static' or family == 'storage' and kind == 'refusal'):
        assert isinstance(loader, dict)
    if loader:
        assert loader['entries'][0]['name'] == filename
        assert [entry['name'] for entry in loader['entries'][1:4]] == ['ntdll.dll', 'kernel32.dll', 'kernelbase.dll']
    if family in ('graph', 'forwarder', 'nested-loader'):
        dynamic = execution['dynamic_loader']
        assert dynamic['profile'] == 'bounded-vfs-dll-graph-v2'
        assert dynamic['state']['active'] is None and dynamic['state']['suspended'] == []
        assert dynamic['suspended_callers'] == 0 and dynamic['requests'] == dynamic['resumed']
        assert all(entry['name'] not in ('guest.dll', 'other.dll') for entry in loader['entries'])
        if family == 'nested-loader':
            assert dynamic['requests'] == 3
            assert execution['maximum_continuation_depth'] >= 2
        if family == 'forwarder':
            code = {'MissingModule': 126, 'MissingExport': 127, 'Cycle': 50}[kind]
            assert any(event['api'].endswith('.GetProcAddress') and event['result'] == 0 and event['last_error'] == code and not event['pending'] for event in execution['api_events'])
    if family == 'callback':
        crt = execution['crt_startup']
        assert not crt['initializer_pending'] and crt['suspended_initializers'] == 0
        assert len(crt['interrupted_initializers']) == (0 if kind == 'Normal' else 2)
        if kind == 'Normal':
            assert len(crt['initializers']) == 3 and execution['maximum_continuation_depth'] >= 3
        elif kind == 'BadStack':
            assert 'return frame' in execution['error']
        elif kind == 'Nonvolatile':
            assert 'nonvolatile register' in execution['error']
        elif kind == 'InvalidTarget':
            assert 'lacks permission4' in execution['error']
    if family in ('process', 'companion-process'):
        lifecycle = execution['user_lifecycle']
        forced = kind.startswith('true')
        interrupted = family == 'process' and kind == 'false-true'
        assert execution['process_exit_code'] == 73 and lifecycle['forced'] == forced
        assert lifecycle['complete'] == (not interrupted)
        assert len(lifecycle['events']) == (0 if forced else 3 if family == 'companion-process' else 1)
        if not interrupted:
            assert all(event['returned'] and event['reason'] == 0 for event in lifecycle['events'])
            assert loader['tls_bytes'] == 0 and loader['threads'] == {}
        else:
            assert 'Process detach' in execution['error'] and not lifecycle['events'][0]['returned']
    if family in ('thread', 'companion-thread', 'tls-quota'):
        threads = execution['user_threads']
        interrupted = kind in ('Budget', 'Fault')
        assert threads['current'] == 1 and len(threads['threads']) == (2 if family == 'tls-quota' else 1)
        assert threads['pending'] == int(interrupted)
        if interrupted:
            assert threads['threads'][0]['state'] == 'interrupted'
        else:
            assert all(thread['backing_released'] and thread['handle_closed'] for thread in threads['threads'])
            assert all(thread['exit_code'] == (73 if kind == 'Exit' else 74 if kind == 'Terminate' else 42) for thread in threads['threads'])
            assert len(loader['threads']) == 1
            assert len(loader['threads']['1']['blocks']) == (17 if family == 'tls-quota' else 2 if family == 'companion-thread' else 1)
            assert all(event['returned'] for event in execution['user_lifecycle']['events'])
        if family == 'tls-quota':
            assert loader['tls_bytes'] < 64 * 1024 * 1024
            events = execution['user_lifecycle']['events']
            assert len(events) == 132 and {event['thread'] for event in events} == {2, 3}
            assert sum(event['reason'] == 2 for event in events) == sum(event['reason'] == 3 for event in events) == 66
            assert any(event['api'].endswith('.CreateThread') and event['result'] == 0 and event['last_error'] == 8 and not event['pending'] for event in execution['api_events'])
        else:
            reasons = [event['reason'] for event in execution['user_lifecycle']['events']]
            multiplier = 3 if family == 'companion-thread' else 1
            assert reasons == [2] * multiplier + ([] if kind in ('Terminate', 'Budget', 'Fault') else [3] * multiplier)
            assert any(event['thread_id'] == 2 for event in execution['api_events'])


def verify(root, case):
    name = label(case)
    fixture = root / 'fixtures-final' / name
    run = root / 'lifecycle' / name
    source = fixture / case[3]
    manifest = binding(run, source)
    receipt = json.loads((root / 'bundle/rust-worker-build.json').read_bytes())
    assert manifest['source_tree_sha256'] == receipt['source_tree_sha256'] and manifest['bundle_receipt'] == receipt
    request = manifest['result']['input_receipt']
    assert request['module_name'] == case[3] and request['persona_sha256'] is None
    assert request['arguments'] == json.loads((fixture / 'arguments.json').read_bytes())
    assert request['timeout_us'] == 30000000
    spec = json.loads((fixture / 'inputs.json').read_bytes())
    assert request['invocation'] == spec['invocation'] == dict(all_exports=False, environment=[], force_quotes=[])
    assert len(spec['files']) == len(request['staged'])
    for index, (file, staged) in enumerate(zip(spec['files'], request['staged'])):
        assert file['source'] == f'input-{index:04}.bin'
        raw = (fixture / file['source']).read_bytes()
        assert raw == (run / 'inputs' / f'{index:04}.bin').read_bytes()
        assert staged == dict(kind=file['kind'], guest_path=file['guest_path'], size=len(raw), sha256=sha(raw))
    execution = manifest['result']['execution']
    check_execution(execution, case)
    assert request['max_instructions'] == execution['max_instructions']
    assert json.loads((fixture / 'limits.json').read_bytes()) == dict(max_instructions=request['max_instructions'], timeout_us=request['timeout_us'])
    job = json.loads((run / 'general-job-profile.json').read_bytes())
    assert job['profile'] == 'submitted_user_1024_v1' and job['cleanup'] == 'restored'
    assert 0 < job['peak_process_memory_bytes'] <= job['process_memory_bytes'] == 1024**3
    assert job['active_process_limit'] == 1 and job['network_capabilities'] == 0
    stop = json.loads((run / 'worker-stop.json').read_bytes())
    assert stop['cleanup'] == 'restored' and stop['worker']['reason'] == 'exited' and stop['worker']['exit_code'] == 0
    return dict(case=name, verified=True, completion=execution['completion_reason'], instructions=execution['instruction_count'])


def run(root):
    output = root / 'lifecycle'
    output.mkdir()
    executable = (root / 'bundle/emumee-rs.exe').resolve()
    records = []
    for case in cases():
        name = label(case)
        fixture = root / 'fixtures-final' / name
        limits = json.loads((fixture / 'limits.json').read_bytes())
        command = [str(executable), 'run', str(fixture / case[3]), '--output', str(output / name),
                   '--inputs', str(fixture / 'inputs.json'), '--max-instructions', str(limits['max_instructions']),
                   '--timeout-us', str(limits['timeout_us']), '--', *json.loads((fixture / 'arguments.json').read_bytes())]
        completed = subprocess.run(command, capture_output=True, timeout=90)
        (output / f'{name}.stdout').write_bytes(completed.stdout)
        (output / f'{name}.stderr').write_bytes(completed.stderr)
        assert completed.returncode == (0 if expected(case)[0] in ('entry_return', 'process_exit') else 1), (name, completed.returncode, completed.stderr.decode(errors='replace'))
        records.append(verify(root, case))
        print(name, 'verified', flush=True)
    atomic_write(output / 'verification.json', json.dumps(records, indent=2) + '\n')


def seal(root, check=False):
    bootstrap_seal(root, check=True)
    records = [verify(root, case) for case in cases()]
    assert json.loads((root / 'lifecycle/verification.json').read_bytes()) == records
    paths = [path for path in sorted((root / 'lifecycle').rglob('*')) if path.is_file()]
    for case in cases():
        paths.extend(path for path in sorted((root / 'fixtures-final' / label(case)).rglob('*')) if path.is_file())
    artifacts = [dict(path=path.relative_to(ROOT).as_posix(), size=path.stat().st_size, sha256=sha(path.read_bytes())) for path in paths]
    document = dict(schema=1, scope='Bounded M3 submitted-user loader/static TLS/thread/process/callback lifecycle; not M4 scheduling, API semantic parity or M10',
                    prior_bootstrap_sha256=sha((root / 'qualified-bootstrap.json').read_bytes()), controls=records, artifacts=artifacts)
    document['fingerprint'] = fingerprint(document)
    destination = root / 'qualified-m3.json'
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
