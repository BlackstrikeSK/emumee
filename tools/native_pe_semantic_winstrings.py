"""Qualify the expanded Windows-string contracts on the contained user route."""
import argparse
from collections import defaultdict
import json
from pathlib import Path
import subprocess

from native_pe_m6 import build_gate
from native_pe_semantic_strlen import load, record
from native_pe_staging_seal import binding
from native_pe_winstrings_guest import MEMORY_PATH, program
from native_pe_winstrings_reference import SIZE, SOURCE, observe
from native_pe_worklist import atomic_write, contract_key, fingerprint, runtime_snapshot, validate_evidence


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / 'rust/emumee-engine/src/api/winstrings_semantic_reference.json'
OUTPUT = 'expanded-candidate/candidate-all-contained'
PROFILE = 'emumee.native-semantic.winstrings.v1'
DIRECT_TEST = (
    'api::winstrings::tests::'
    'frozen_windows_string_expanded_memory_and_null_controls_match_all_module_identities'
)
BUDGET = 10000
TIMEOUT_US = 30000000
POINTER_EXPORTS = {'CharUpperW', '_wcslwr'}

# Legacy reports include the import name. Rust uses operation names and, for
# combined legacy diagnostics, a more specific read or encoding failure.
FIXED_DIAGNOSTICS = {
    'CompareStringA': {'non-ASCII collation unavailable': 'CompareString: non-ASCII collation unavailable'},
    'CompareStringW': {'non-ASCII collation unavailable': 'CompareString: non-ASCII collation unavailable'},
    'FindStringOrdinal': {'non-ASCII case fold unavailable': 'FindStringOrdinal: non-ASCII case fold unavailable'},
    'WideCharToMultiByte': {
        'unsupported code page 999': 'Character conversion: unsupported code page',
        'unsupported conversion flags 0x1': 'Character conversion: unsupported conversion flags',
    },
    'RtlOemToUnicodeN': {'non-ASCII OEM code page unavailable': 'RtlOemToUnicodeN: non-ASCII OEM unavailable'},
    'RtlIsTextUnicode': {
        'invalid or oversized text buffer': 'RtlIsTextUnicode: inaccessible buffer',
        'inaccessible result flags': 'RtlIsTextUnicode: inaccessible buffer',
    },
    'StrTrimW': {
        'inaccessible or unterminated guest string': 'StrTrimW: inaccessible string',
        'guest destination is not writable': 'StrTrimW: destination not writable',
    },
    'ApiSetQueryApiSetPresence': {
        'namespace api-ms-win-missing-l1-1-0 unavailable':
            'ApiSetQueryApiSetPresence: namespace api-ms-win-missing-l1-1-0 unavailable',
    },
}


def diagnostic(case, message):
    export = case['export']
    readable = case['protection'] & 1 and case['arguments'][0] != 0
    if export in POINTER_EXPORTS:
        if message == 'inaccessible or non-ASCII string':
            return ('Case mapping: inaccessible string' if not readable
                    else 'Case mapping: non-ASCII mapping unavailable')
        if message == 'guest string is not writable':
            return 'Case mapping: destination not writable'
        if export == 'CharUpperW' and message == 'non-ASCII character mapping unavailable':
            return 'CharUpperW: non-ASCII mapping unavailable'
    if export == 'CharToOemA':
        if message == 'non-ASCII or inaccessible source':
            return ('CharToOemA: inaccessible source' if not readable
                    else 'CharToOemA: non-ASCII source unavailable')
        if message == 'guest destination is not writable':
            return 'CharToOemA: destination not writable'
    return FIXED_DIAGNOSTICS[export][message]


def identity(case):
    return case['module'], case['export'], 'function', 'x64' if case['width'] == 8 else 'x86'


def reference():
    frozen = load(CORPUS)
    details = observe(include_diagnostics=True)
    diagnostics = defaultdict(list)
    for case in details['cases']:
        name = f'{case["module"]}.{case["export"]}: '
        for message in case.pop('legacy_diagnostics'):
            assert message.startswith(name), message
            diagnostics[identity(case), case['label']].append(
                diagnostic(case, message[len(name):])
            )
    assert details == frozen, 'Independent Windows-string reference drifted'
    assert len(frozen['cases']) == 1004 and len(frozen['contracts']) == 42
    for case in frozen['cases']:
        assert bool(diagnostics.get((identity(case), case['label']))) == case['unsupported']
    return frozen, diagnostics


def controls(frozen):
    selected = [case for case in frozen['cases'] if case['protection'] != 2]
    assert len(selected) == 962
    assert {identity(case) for case in selected} == {tuple(row) for row in frozen['contracts']}
    return {f'{index:03}': case for index, case in enumerate(selected)}


def templates(root):
    return {width: fixture.read_bytes() for width, fixture in template_paths(root).items()}


def template_paths(root):
    return {width: root / 'fixtures-final' / f'{arch}-semantic-interlocked-dynamic/sample.exe'
            for width, arch in ((4, 'X86'), (8, 'X64'))}


def source_test(index):
    test_run, = [run for run in load(index)['runs'] if run['suite'] == 'rust-tests']
    assert test_run['exit_code'] == 0
    assert f'test {DIRECT_TEST} ... ok' in (ROOT / test_run['log']).read_text(encoding='utf-8')


def check_diagnostics(execution, expected):
    assert execution.get('string_api_unsupported', []) == expected, 'String diagnostic differs'


def check_case(directory, case, template, receipt, diagnostics):
    assert load(directory / 'specification.json') == case
    source = directory / 'sample.exe'
    assert source.read_bytes() == program(case, template), 'Synthetic PE differs from recipe'
    output = directory / 'run'
    manifest = binding(output, source)
    assert manifest['bundle_receipt'] == receipt
    assert manifest['source_tree_sha256'] == receipt['source_tree_sha256']

    result = manifest['result']
    request = result['input_receipt']
    assert request['module_name'] == source.name and not request['staged'] and not request['arguments']
    assert request['max_instructions'] == BUDGET and request['timeout_us'] == TIMEOUT_US
    execution = result['execution']
    module, export, _, arch = identity(case)
    assert execution['architecture'] == arch and execution['api_events_omitted'] == 0
    assert execution['configuration']['initialized'] and not execution['configuration']['generated_only']
    assert execution['error'] is None and execution['completion_reason'] == 'entry_return'
    assert execution['guest_entry_return'] == 1 and 0 < execution['instruction_count'] <= BUDGET

    event, = [event for event in execution['api_events'] if event['api'] == f'{module}.{export}']
    assert event['arguments'] == case['arguments'] and not event['pending'] and event['error'] is None
    bits = 8 * case['width'] if export in POINTER_EXPORTS else 32
    mask = (1 << bits) - 1
    assert event['result'] & mask == case['result'] & mask and event['last_error'] == case['last_error']
    check_diagnostics(execution, diagnostics)

    arena, = [artifact for artifact in execution['artifacts'] if any(
        origin['kind'] == 'guest_file' and origin['guest_path'].lower() == MEMORY_PATH.lower()
        for origin in artifact['observations']
    )]
    assert arena['size'] == SIZE and arena['sha256'] == case['memory_sha256']
    job = load(output / 'general-job-profile.json')
    assert job['profile'] == 'submitted_user_1024_v1' and job['cleanup'] == 'restored'
    assert job['active_process_limit'] == 1 and job['network_capabilities'] == 0
    assert 0 < job['peak_process_memory_bytes'] <= job['process_memory_bytes'] == 1024**3
    stop = load(output / 'worker-stop.json')
    assert stop['cleanup'] == 'restored' and stop['worker']['reason'] == 'exited'
    assert stop['worker']['exit_code'] == 0
    return dict(case=directory.name, identity=list(identity(case)), label=case['label'],
                arena_sha256=arena['sha256'], diagnostics=diagnostics)


def run(root, index):
    build_gate(root, index)
    source_test(index)
    frozen, diagnostics = reference()
    headers = templates(root)
    receipt = load(root / 'bundle/rust-worker-build.json')
    output = root / OUTPUT
    output.mkdir(parents=True)
    for name, case in controls(frozen).items():
        directory = output / name
        directory.mkdir()
        sample = directory / 'sample.exe'
        sample.write_bytes(program(case, headers[case['width']]))
        (directory / 'specification.json').write_text(json.dumps(case, indent=2) + '\n', encoding='utf-8')
        process = subprocess.run(
            [str(root / 'bundle/emumee-rs.exe'), 'run', str(sample),
             '--output', str(directory / 'run'), '--max-instructions', str(BUDGET),
             '--timeout-us', str(TIMEOUT_US)], capture_output=True, timeout=120,
        )
        (directory / 'stdout').write_bytes(process.stdout)
        (directory / 'stderr').write_bytes(process.stderr)
        assert process.returncode == 0, (name, process.stderr)
        check_case(directory, case, headers[case['width']], receipt,
                   diagnostics.get((identity(case), case['label']), []))
        print(f'{name} independently verified', flush=True)


def proof_path(root):
    return root / f'qualified-semantic-winstrings-{fingerprint(runtime_snapshot(ROOT))}.json'


def seal(root, index, *, check=False):
    build_gate(root, index)
    source_test(index)
    frozen, diagnostics = reference()
    expected = controls(frozen)
    output = root / OUTPUT
    assert {path.name for path in output.iterdir() if path.is_dir()} == set(expected)
    headers = templates(root)
    receipt = load(root / 'bundle/rust-worker-build.json')
    observed = [
        check_case(output / name, case, headers[case['width']], receipt,
                   diagnostics.get((identity(case), case['label']), []))
        for name, case in expected.items()
    ]
    paths = {CORPUS, ROOT / SOURCE, *template_paths(root).values()}
    for directory in (root / 'bundle', *(output / name for name in expected)):
        paths.update(path for path in directory.rglob('*') if path.is_file())
    document = dict(
        schema=1, profile=PROFILE, runtime_fingerprint=fingerprint(runtime_snapshot(ROOT)),
        source_tree_sha256=receipt['source_tree_sha256'], contract_identities=frozen['contracts'],
        oracle_observations=len(frozen['cases']), source_only_observations=len(frozen['cases']) - len(observed),
        tests=[DIRECT_TEST], controls=observed, artifacts=[record(path) for path in sorted(paths)],
    )
    document['fingerprint'] = fingerprint(document)
    path = proof_path(root)
    if check:
        assert load(path) == document, 'Expanded Windows-string proof differs'
    else:
        assert not path.exists(), 'Preserve sealed evidence'
        atomic_write(path, json.dumps(document, indent=2) + '\n')
    print(json.dumps(dict(contracts=len(frozen['contracts']), controls=len(observed),
                          fingerprint=document['fingerprint'])))


def require_dispatch(row, related):
    dispatch = row['rust_dispatch']
    export = row['export']
    convention = 'cdecl' if export == '_wcslwr' else 'stdcall'
    assert dispatch['dispatch'] == 'model' and dispatch['callable'] is True
    assert dispatch['return_type'] == ('pointer' if export in POINTER_EXPORTS else 'u32')
    assert {len(case['arguments']) for _, case in related} == {dispatch['argc']}
    assert dispatch['convention'] == convention
    assert any(ref['source'] == SOURCE and ref['module'] == row['module']
               and ref['export'] == export and ref['argc'] == dispatch['argc']
               and (ref['convention'] or 'stdcall') == convention for ref in row['reference_sources'])


def publish_evidence(root, index, ledger_path, *, collect_only=False):
    assert collect_only, 'Publish Windows strings through the atomic family publisher'
    seal(root, index, check=True)
    ledger = load(ledger_path)
    assert ledger['runtime_source_hashes'] == runtime_snapshot(ROOT)
    frozen = load(CORPUS)
    groups = defaultdict(list)
    for name, case in controls(frozen).items():
        groups[identity(case)].append((name, case))
    claims = []
    artifacts = [record(path) for path in (proof_path(root), CORPUS, ROOT / SOURCE)]
    for row in ledger['entries']:
        key = contract_key(row)
        if key not in groups:
            continue
        related = groups[key]
        require_dispatch(row, related)
        negatives = [name for name, case in related if case['label'].startswith(('null-', 'permission-'))]
        assert negatives
        claim = {field: row[field] for field in ('module', 'export', 'kind', 'architecture', 'source_fingerprint')}
        claim.update(semantic_status='verified_model', submitted_route='verified', behavioral_evidence=[dict(
            id=f'winstrings-{row["module"]}-{row["export"]}-{row["architecture"]}-v1',
            architecture=row['architecture'], source_fingerprint=row['source_fingerprint'],
            oracle='Frozen string handler, default persona; returns, last error, full arena and reviewed diagnostic equivalents',
            baseline=record(CORPUS), limits=dict(arena_bytes=SIZE, max_instructions=BUDGET),
            tests=[DIRECT_TEST, *(f'winstrings-contained-{name}' for name, _ in related)],
            negative_controls=[f'winstrings-contained-{name}' for name in negatives],
            artifacts=artifacts,
        )])
        validate_evidence(claim)
        claims.append(claim)
    assert {contract_key(claim) for claim in claims} == set(groups) and len(claims) == len(groups)
    return claims


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', required=True, type=Path)
    parser.add_argument('--source-index', required=True, type=Path)
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument('--seal', action='store_true')
    actions.add_argument('--check', action='store_true')
    options = parser.parse_args()
    root, index = options.root.resolve(), options.source_index.resolve()
    if options.seal or options.check:
        seal(root, index, check=options.check)
    else:
        run(root, index)
