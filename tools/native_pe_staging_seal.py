"""Independently bind M2 staging captures to exact build sources and frozen bytes."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tests'))
from test_native_pe_package import source_fingerprint
from native_pe_worklist import atomic_write, fingerprint
from native_pe_staging import verify_run


def binding(run, source):
    manifest = json.loads((run / 'manifest.json').read_bytes())
    request_raw = (run / 'request.json').read_bytes()
    result_raw = (run / 'worker/result.json').read_bytes()
    request = json.loads(request_raw)
    result = json.loads(result_raw)
    sha = lambda raw: hashlib.sha256(raw).hexdigest()
    assert manifest['result'] == result
    assert manifest['request_sha256'] == result['request_sha256'] == sha(request_raw)
    assert manifest['result_sha256'] == sha(result_raw)
    assert manifest['cleanup'] == 'restored'
    assert request['schema'] == 2 and request['profile'] == result['profile'] == 'submitted_user_pe_v1'
    assert request['run_id'] == result['run_id'] and result['schema'] == 1
    assert result['input_receipt'] == request
    raw = source.read_bytes()
    assert (run / 'input.pe').read_bytes() == raw
    assert request['input_sha256'] == result['input_sha256'] == sha(raw)
    assert request['input_size'] == len(raw)
    persona = run / 'persona.json'
    assert (sha(persona.read_bytes()) if persona.exists() else None) == request.get('persona_sha256')
    assert result['containment']['network_capabilities'] == 0
    assert all(result['containment'][key] is True for key in ('app_container', 'job_object', 'child_process_blocked'))
    for index, file in enumerate(request['staged']):
        raw = (run / f'inputs/{index:04}.bin').read_bytes()
        assert len(raw) == file['size'] and sha(raw) == file['sha256']
    for artifact in result['execution']['artifacts']:
        assert artifact['filename'] == artifact['sha256'] + '.bin'
        raw = (run / 'worker/artifacts' / artifact['filename']).read_bytes()
        assert len(raw) == artifact['size'] and sha(raw) == artifact['sha256']
    return manifest


def seal(directory, *, check=False):
    bundle = directory / 'bundle'
    fixtures = directory / 'fixtures-final'
    regression = directory / 'qualification'
    staging = directory / 'staging'
    expected = source_fingerprint(ROOT)
    receipt = json.loads((bundle / 'rust-worker-build.json').read_bytes())
    assert receipt['schema'] == 2
    assert receipt['source_files'] == expected['source_files']
    assert receipt['source_tree_sha256'] == expected['source_tree_sha256']
    builds = {}
    for name, option, key in (('emumee-rs.exe', 'build-info', 'controller_sha256'),
                              ('emumee-worker.exe', '--build-info', 'worker_sha256')):
        completed = subprocess.run([str(bundle / name), option], capture_output=True, check=True, timeout=30)
        builds[name] = json.loads(completed.stdout)
        assert builds[name]['source_tree_sha256'] == expected['source_tree_sha256']
        assert hashlib.sha256((bundle / name).read_bytes()).hexdigest() == receipt[key]
        assert (bundle / name).read_bytes() == (ROOT / 'target/release' / name).read_bytes()
    assert hashlib.sha256((bundle / 'unicorn.dll').read_bytes()).hexdigest() == receipt['unicorn_sha256']
    assert (bundle / 'unicorn.dll').read_bytes() == (ROOT / 'target/release/unicorn.dll').read_bytes()
    records = json.loads((regression / 'verification.json').read_bytes())
    refusals = json.loads((regression / 'refusal-verification.json').read_bytes())
    assert len(records) == 120 and len(refusals) == 28
    assert all(row['verified'] is True for row in records + refusals)
    assert all(row['exit_code'] == 2 for row in refusals)
    assert len({(row['architecture'], row['case']) for row in records}) == 120
    for row in records:
        case = row['case']
        architecture = row['architecture']
        filename = 'sample.dll' if case == 'dll' else 'sample.exe'
        if case.startswith(('layout-', 'imports-', 'abi-')):
            filename = case.split('-')[0] + '.exe'
        fixture_case = 'exe' if case in ('budget', 'persona') else case
        manifest = binding(regression / f'{architecture}-{case}', fixtures / f'{architecture}-{fixture_case}' / filename)
        execution = manifest['result']['execution']
        assert execution['configuration']['generated_only'] is False
        assert execution['configuration']['initialized'] is True
    staging_records = json.loads((staging / 'verification.json').read_bytes())
    cases = ('file', 'environment', 'quoting', 'companion', 'forwarded', 'exports',
             'ServiceMainA', 'ServiceMainW', 'ServiceMain', 'selection', 'ordering', 'forwarder', 'fault')
    positive = {f'{arch}-{case}{suffix}' for arch in ('X86', 'X64') for case in cases for suffix in ('', '-budget')}
    names = {row['case'] for row in staging_records}
    assert len(staging_records) == len(names) == 82
    assert {name for name in names if not name.startswith('refuse-')} == positive
    for row in staging_records:
        assert row['verified'] is True
        name = row['case']
        if name.startswith('refuse-'):
            assert row['exit_code'] == 2 and not (staging / name).exists()
            continue
        architecture, case = name.split('-', 1)
        budget = case.endswith('-budget')
        case = case.removesuffix('-budget')
        is_export = case in ('exports', 'ServiceMainA', 'ServiceMainW', 'ServiceMain', 'selection', 'ordering', 'forwarder', 'fault')
        source = fixtures / f'{architecture}-staging-{case}' / ('sample.dll' if is_export else 'sample.exe')
        fault = case in ('fault', 'forwarder')
        expected_code = 1 if budget or fault else 0
        assert row['exit_code'] == expected_code
        verify_run(staging / name, source, expected_code, exports=9 if case == 'selection' else 4 if case == 'ordering' else is_export,
                   fault=not budget and fault)
        binding(staging / name, source)
        requested = json.loads((source.parent / 'inputs.json').read_bytes())
        admitted = json.loads((staging / name / 'request.json').read_bytes())
        assert requested['invocation'] == admitted['invocation']
        for original, actual in zip(requested['files'], admitted['staged'], strict=True):
            raw = (source.parent / original['source']).read_bytes()
            assert actual == dict(kind=original['kind'], guest_path=original['guest_path'],
                                  size=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    artifacts = []
    for subdirectory in (bundle, fixtures, regression, staging):
        for path in sorted(subdirectory.rglob('*')):
            if path.is_file():
                artifacts.append(dict(path=path.relative_to(ROOT).as_posix(), size=path.stat().st_size,
                                      sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
    document = dict(schema=1, scope='M2 fourth-checkbox staging with layout/import/ABI regressions; not full M2/M10/API parity',
                    source_tree_sha256=expected['source_tree_sha256'], package_receipt=receipt,
                    build_info=builds, regression_cases=records, regression_refusals=refusals,
                    staging_cases=staging_records, artifacts=artifacts)
    document['fingerprint'] = fingerprint(document)
    destination = directory / 'qualified-smoke.json'
    if check:
        assert json.loads(destination.read_bytes()) == document
    else:
        assert not destination.exists(), 'Preserve sealed evidence'
        atomic_write(destination, json.dumps(document, indent=2) + '\n')
    print(json.dumps(dict(files=len(artifacts), regression_guests=len(records),
                          regression_refusals=len(refusals), staging_controls=len(staging_records),
                          source_tree_sha256=expected['source_tree_sha256'], fingerprint=document['fingerprint']), indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    seal(args.root.resolve(), check=args.check)
