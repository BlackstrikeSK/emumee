"""Qualify trusted submitted-input fixtures through a frozen offline Rust bundle."""
from __future__ import annotations

import argparse
import copy
import ctypes
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def verify_run(directory, source, expected_code, *, exports=False, fault=False):
    manifest = json.loads((directory / 'manifest.json').read_bytes())
    request_raw = (directory / 'request.json').read_bytes()
    request = json.loads(request_raw)
    result_raw = (directory / 'worker/result.json').read_bytes()
    result = json.loads(result_raw)
    assert request['schema'] == 2 and result['schema'] == 1
    assert request['profile'] == result['profile'] == 'submitted_user_pe_v1'
    assert manifest['result'] == result
    assert manifest['request_sha256'] == result['request_sha256'] == digest(request_raw)
    assert manifest['result_sha256'] == digest(result_raw)
    assert request['input_sha256'] == result['input_sha256'] == digest(source.read_bytes())
    assert (directory / 'input.pe').read_bytes() == source.read_bytes()
    assert request['input_size'] == source.stat().st_size
    assert manifest['cleanup'] == 'restored'
    assert result['run_id'] == request['run_id']
    assert result['input_receipt'] == request
    persona = directory / 'persona.json'
    assert (digest(persona.read_bytes()) if persona.exists() else None) == request.get('persona_sha256')
    containment = result['containment']
    assert all(containment[key] is True for key in ('app_container', 'job_object', 'child_process_blocked'))
    assert containment['network_capabilities'] == 0
    for index, file in enumerate(request.get('staged', [])):
        raw = (directory / 'inputs' / f'{index:04}.bin').read_bytes()
        assert len(raw) == file['size'] and digest(raw) == file['sha256']
    execution = result['execution']
    if expected_code == 0:
        assert execution['error'] is None and execution['completion_reason'] == 'entry_return'
        assert execution['guest_entry_return'] == (1 if exports else 42)
        if exports:
            entries = execution['native_loader']['export_entries']
            assert len(entries) == int(exports) and all(entry['returned_value'] == 42 for entry in entries)
            assert all(entry['stopped_instructions'] > entry['started_instructions'] for entry in entries)
            if 'staging-ordering' in str(source.parent):
                assert [entry['ordinal'] for entry in entries] == [1, 3, 2, 4]
                assert [entry['names'] for entry in entries] == [['Export1'], ['Export2'], [], []]
    elif fault:
        assert execution['error'] is not None and execution['guest_entry_return'] is None
        entries = execution['native_loader']['export_entries']
        assert len(entries) == 1 and entries[0]['error'] is not None
    else:
        assert execution['instruction_count'] == 1
        assert execution['guest_entry_return'] is None
        assert execution['completion_reason'] == 'instruction_budget'
    return manifest


def run(bundle, fixtures, output):
    output.mkdir()
    executable = bundle / 'emumee-rs.exe'
    records = []

    def invoke(label, source, specification, expected_code, *, exports=False, budget=None, fault=False, reason=None):
        directory = output / label
        command = [str(executable), 'run', str(source), '--output', str(directory), '--inputs', str(specification)]
        if budget is not None:
            command += ['--max-instructions', str(budget)]
        command += ['--', 'two words', 'tail\\']
        completed = subprocess.run(command, capture_output=True, timeout=60)
        (output / f'{label}.stdout').write_bytes(completed.stdout)
        (output / f'{label}.stderr').write_bytes(completed.stderr)
        assert completed.returncode == expected_code, (label, completed.returncode, completed.stderr.decode(errors='replace'))
        if expected_code == 2:
            assert not directory.exists(), label
            if reason is not None:
                assert reason in completed.stderr.decode(errors='replace'), (label, completed.stderr)
        else:
            verify_run(directory, source, expected_code, exports=exports, fault=fault)
            requested = json.loads(specification.read_bytes())
            admitted = json.loads((directory / 'request.json').read_bytes())
            assert admitted['invocation'] == requested['invocation']
            assert len(admitted['staged']) == len(requested['files'])
            for actual, original in zip(admitted['staged'], requested['files']):
                host = Path(original['source'])
                if not host.is_absolute():
                    host = specification.parent / host
                raw = host.read_bytes()
                assert actual == dict(kind=original['kind'], guest_path=original['guest_path'],
                                      size=len(raw), sha256=digest(raw))
        records.append(dict(case=label, exit_code=completed.returncode, verified=True))

    for architecture in ('X86', 'X64'):
        for case in ('file', 'environment', 'quoting', 'companion', 'forwarded', 'exports',
                     'ServiceMainA', 'ServiceMainW', 'ServiceMain', 'selection', 'ordering', 'forwarder', 'fault'):
            fixture = fixtures / f'{architecture}-staging-{case}'
            is_export = case in ('exports', 'ServiceMainA', 'ServiceMainW', 'ServiceMain', 'selection', 'ordering', 'forwarder', 'fault')
            source = fixture / ('sample.dll' if is_export else 'sample.exe')
            fault = case in ('fault', 'forwarder')
            invoke(f'{architecture}-{case}', source, fixture / 'inputs.json', 1 if fault else 0,
                   exports=9 if case == 'selection' else 4 if case == 'ordering' else is_export, fault=fault)
            invoke(f'{architecture}-{case}-budget', source, fixture / 'inputs.json', 1, budget=1)

    specification = json.loads((fixtures / 'X64-staging-file/inputs.json').read_bytes())
    for index, file in enumerate(specification['files']):
        file['source'] = str((fixtures / 'X64-staging-file' / file['source']).resolve())
    source = fixtures / 'X64-staging-file/sample.exe'
    failures = {}
    for label, path in (('parent', r'C:\..\escape'), ('dot', r'C:\a\.\b'),
                        ('unc', r'\\host\share\file'), ('device', r'\\?\C:\file'),
                        ('ads', r'C:\file:stream'), ('reserved', r'C:\con.txt'),
                        ('slash', 'C:/file'), ('trailing', 'C:\\file.'),
                        ('empty-component', r'C:\a\\b')):
        candidate = copy.deepcopy(specification)
        candidate['files'][0]['guest_path'] = path
        failures['path-' + label] = candidate
    candidate = copy.deepcopy(specification)
    candidate['files'][1]['guest_path'] = candidate['files'][0]['guest_path'].upper()
    failures['case-collision'] = candidate
    candidate = copy.deepcopy(specification)
    candidate['files'][1]['guest_path'] = candidate['files'][0]['guest_path'] + r'\child'
    failures['file-directory-collision'] = candidate
    candidate = copy.deepcopy(specification)
    candidate['invocation']['environment'].append(['token', 'duplicate'])
    failures['environment-collision'] = candidate
    for label, quotes in (('quote-negative', [-1]), ('quote-range', [2]), ('quote-duplicate', [1, 1])):
        candidate = copy.deepcopy(specification)
        candidate['invocation']['force_quotes'] = quotes
        failures[label] = candidate
    for label, value in (('schema', 2), ('unknown', 1)):
        candidate = copy.deepcopy(specification)
        candidate['schema' if label == 'schema' else 'host_search'] = value
        failures[label] = candidate
    companion = fixtures / 'X64-staging-companion/payload0.bin'
    foreign = fixtures / 'X86-staging-companion/payload0.bin'
    for label, payload in (('architecture', foreign), ('non-dll', source)):
        candidate = copy.deepcopy(specification)
        candidate['files'] = [dict(kind='companion', guest_path=r'C:\lib\guest.dll', source=str(payload))]
        failures[label] = candidate
    candidate = copy.deepcopy(specification)
    candidate['files'] = [dict(kind='companion', guest_path=path, source=str(companion))
                          for path in (r'C:\lib\guest.dll', r'C:\other\GUEST.dll')]
    failures['module-collision'] = candidate
    oversized = output / 'oversized.bin'
    with oversized.open('wb') as stream:
        stream.truncate(32 * 1024 * 1024 + 1)
    candidate = copy.deepcopy(specification)
    candidate['files'][0]['source'] = str(oversized)
    failures['file-quota'] = candidate
    candidate = copy.deepcopy(specification)
    candidate['files'] = [dict(kind='file', guest_path=f'C:\\file{index}', source=str(companion)) for index in range(129)]
    failures['count-quota'] = candidate
    full = output / 'quota.bin'
    with full.open('wb') as stream:
        stream.truncate(32 * 1024 * 1024)
    candidate = copy.deepcopy(specification)
    candidate['files'] = [dict(kind='file', guest_path=f'C:\\file{index}', source=str(full)) for index in range(5)]
    failures['total-quota'] = candidate
    for label, host in (('directory', fixtures), ('missing', output / 'absent.bin')):
        candidate = copy.deepcopy(specification)
        candidate['files'][0]['source'] = str(host)
        failures['source-' + label] = candidate
    original = output / 'link-source.bin'
    original.write_bytes(b'RUST')
    hardlink = output / 'hardlink.bin'
    os.link(original, hardlink)
    candidate = copy.deepcopy(specification)
    candidate['files'][0]['source'] = str(hardlink)
    failures['source-hardlink'] = candidate
    junction = output / 'junction'
    completed = subprocess.run(['cmd', '/c', 'mklink', '/J', str(junction), str(fixtures / 'X64-staging-file')], capture_output=True, check=True)
    (output / 'junction-create.log').write_bytes(completed.stdout + completed.stderr)
    candidate = copy.deepcopy(specification)
    candidate['files'][0]['source'] = str(junction / 'payload0.bin')
    failures['source-junction'] = candidate
    try:
        for label, candidate in failures.items():
            path = output / f'{label}.json'
            path.write_text(json.dumps(candidate), encoding='utf-8')
            reasons = {
                'case-collision': 'Invalid or duplicate submitted guest file',
                'file-directory-collision': 'Submitted guest file/directory collision',
                'environment-collision': 'Invalid or duplicate submitted environment override',
                'quote-negative': 'expected usize', 'quote-range': 'Invalid submitted argument quoting',
                'quote-duplicate': 'Invalid submitted argument quoting',
                'schema': 'Invalid submitted input specification schema/count',
                'unknown': 'unknown field', 'architecture': 'same-architecture native DLL',
                'non-dll': 'same-architecture native DLL',
                'module-collision': 'Invalid or duplicate submitted companion module',
                'file-quota': 'Worker file type, links or size rejected',
                'count-quota': 'Invalid submitted input specification schema/count',
                'total-quota': 'Worker file type, links or size rejected',
                'source-directory': 'os error 5',
                'source-missing': 'os error 2',
                'source-hardlink': 'Worker file type, links or size rejected',
                'source-junction': 'Worker handle resolves to another path',
            }
            invoke('refuse-' + label, source, path, 2,
                   reason='Invalid submitted guest path' if label.startswith('path-') else reasons[label])
    finally:
        os.rmdir(junction)
    writer_path = output / 'writer.bin'
    writer_path.write_bytes(b'RUST')
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateFileW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
                                  ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p]
    kernel.CreateFileW.restype = ctypes.c_void_p
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    handle = kernel.CreateFileW(str(writer_path), 0x40000000, 7, None, 3, 0, None)
    assert handle not in (None, ctypes.c_void_p(-1).value)
    try:
        candidate = copy.deepcopy(specification)
        candidate['files'][0]['source'] = str(writer_path)
        path = output / 'writer.json'
        path.write_text(json.dumps(candidate), encoding='utf-8')
        invoke('refuse-source-writer', source, path, 2, reason='os error 32')
    finally:
        assert kernel.CloseHandle(handle)
    for label, raw in (('duplicate-field', b'{"schema":1,"schema":1}'),
                       ('large-specification', b' ' * (65536 + 1))):
        path = output / f'{label}.json'
        path.write_bytes(raw)
        invoke('refuse-' + label, source, path, 2,
               reason='duplicate field' if label == 'duplicate-field' else 'Worker file type, links or size rejected')
    (output / 'verification.json').write_text(json.dumps(records, indent=2) + '\n', encoding='utf-8')
    print(f'Verified {len(records)} staging guest/refusal controls')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', required=True, type=Path)
    parser.add_argument('--fixtures', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    run(args.bundle.resolve(), args.fixtures.resolve(), args.output.resolve())


if __name__ == '__main__':
    main()
