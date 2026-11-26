"""Qualify lstrlenA/W against frozen oracles and the contained submitted route."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from native_pe_m4 import verify
from native_pe_m6 import build_gate
from native_pe_staging_seal import binding
from native_pe_strlen_reference import observe
from native_pe_semantic_proofs import contract_identities as proof_contracts
from native_pe_worklist import atomic_write, fingerprint, runtime_snapshot, validate_evidence

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / 'rust/emumee-engine/src/api/winstrings_reference.json'
BOUNDARIES = ROOT / 'rust/emumee-engine/src/api/lstrlen_semantic_reference.json'
DIRECT_TEST = 'api::winstrings::tests::lstrlen_matches_independent_frozen_boundaries_encoding_and_read_permissions'
GUEST_TEST = 'semantic_strings_tests::semantic_lstrlen_submitted_calls_match_frozen_returns_errors_and_all_memory'
OUTPUT = 'semantic-lstrlen'


def load(path):
    return json.loads(Path(path).read_bytes())


def record(path):
    data = path.read_bytes()
    return dict(path=path.resolve().relative_to(ROOT).as_posix(), size=len(data),
                sha256=hashlib.sha256(data).hexdigest())


def proof_path(root):
    # Each tool/model revision keeps its own immutable receipt. A requalification
    # must not overwrite evidence referenced by an archived ledger claim.
    revision = fingerprint(runtime_snapshot(ROOT))
    return root / f'qualified-semantic-lstrlen-{revision}.json'


def required_cases():
    return {f'{arch}-semantic-{export}-{index:03}' for arch in ('X86', 'X64')
            for export in ('lstrlenA', 'lstrlenW') for index in range(3)}


def cases(root):
    selected = sorted(p for p in (root / 'fixtures-final').iterdir()
                      if p.is_dir() and '-semantic-lstrlen' in p.name)
    assert {p.name for p in selected} == required_cases(), 'Semantic strlen fixture set differs'
    return selected


def source_tests(index):
    run, = [r for r in load(index)['runs'] if r['suite'] == 'rust-tests']
    assert run['exit_code'] == 0
    log = (ROOT / run['log']).read_text(encoding='utf-8')
    for test in (DIRECT_TEST, GUEST_TEST):
        assert f'test {test} ... ok' in log, f'Missing successful semantic test: {test}'
    assert load(BOUNDARIES) == observe(), 'Independent frozen-handler observations drifted'


def oracle_for(name):
    arch, _, export, number = name.split('-')
    selected = [c for c in load(CORPUS)['cases']
                if c['module'] == 'kernel32' and c['export'] == export
                and c['width'] == (4 if arch == 'X86' else 8)]
    assert len(selected) == 3
    return selected[int(number)]


def observations(root, fixture):
    source = fixture / 'sample.exe'
    manifest = binding(root / OUTPUT / fixture.name, source)
    result = manifest['result']['execution']
    oracle = oracle_for(fixture.name)
    event, = [e for e in result['api_events'] if e['api'] == 'kernel32.' + oracle['export']]
    assert not event['pending'] and event['error'] is None
    assert (event['result'], event['last_error']) == (oracle['result'], oracle['last_error'])
    address = oracle['arguments'][0]
    assert event['arguments'] == [0 if address == 0 else 0x26000000 + address - 0x1000]
    arena, = [a for a in result['artifacts'] if any(
        o['kind'] == 'guest_file' and o['guest_path'].lower().endswith('strlen-memory.bin')
        for o in a['observations'])]
    assert arena['size'] == 0x10000 and arena['sha256'] == oracle['memory_sha256']
    assert result['error'] is None and result['guest_entry_return'] == 1
    return dict(case=fixture.name, module='kernel32', export=oracle['export'],
                architecture='x86' if oracle['width'] == 4 else 'x64',
                result=event['result'], last_error=event['last_error'],
                arena_sha256=arena['sha256'], oracle=oracle)


def run(root, index):
    build_gate(root, index)
    source_tests(index)
    output = root / OUTPUT
    output.mkdir()
    for fixture in cases(root):
        limits = load(fixture / 'limits.json')
        command = [str(root / 'bundle/emumee-rs.exe'), 'run', str(fixture / 'sample.exe'),
                   '--output', str(output / fixture.name), '--inputs', str(fixture / 'inputs.json'),
                   '--max-instructions', str(limits['max_instructions']),
                   '--timeout-us', str(limits['timeout_us'])]
        result = subprocess.run(command, capture_output=True, timeout=120)
        (output / f'{fixture.name}.stdout').write_bytes(result.stdout)
        (output / f'{fixture.name}.stderr').write_bytes(result.stderr)
        assert result.returncode == 0, (fixture.name, result.stderr)
        verify(root, fixture, output_directory=OUTPUT)
        observations(root, fixture)
        print(f'{fixture.name} independently verified', flush=True)


def seal(root, index, *, check=False):
    build_gate(root, index)
    source_tests(index)
    selected = cases(root)
    controls = []
    for fixture in selected:
        verify(root, fixture, output_directory=OUTPUT)
        controls.append(observations(root, fixture))
    paths = {CORPUS, BOUNDARIES}
    for directory in (root / 'bundle', root / OUTPUT, *selected):
        paths.update(p for p in directory.rglob('*') if p.is_file())
    document = dict(schema=1, profile='emumee.native-semantic.lstrlen.v1',
                    runtime_fingerprint=fingerprint(runtime_snapshot(ROOT)),
                    source_tree_sha256=load(root / 'bundle/rust-worker-build.json')['source_tree_sha256'],
                    contract_identities=proof_contracts([dict(module='kernel32',export=name,architecture=arch) for arch in ('x86','x64') for name in ('lstrlenA','lstrlenW')]),
                    oracle_observations=len(load(BOUNDARIES)['cases']),
                    tests=[DIRECT_TEST, GUEST_TEST], controls=controls,
                    artifacts=[record(p) for p in sorted(paths)])
    # The current source gate is checked above. Its index is deliberately not
    # hashed into this semantic proof: maintained evidence points to this proof,
    # and must itself be validated by the final source index without a hash cycle.
    document['fingerprint'] = fingerprint(document)
    path = proof_path(root)
    if check:
        assert load(path) == document, 'Semantic strlen proof differs'
    else:
        assert not path.exists(), 'Preserve sealed semantic evidence'
        atomic_write(path, json.dumps(document, indent=2) + '\n')
    print(json.dumps(dict(contracts=4, controls=len(controls), fingerprint=document['fingerprint'])))


def publish_evidence(root, index, ledger_path, *, collect_only=False):
    seal(root, index, check=True)
    ledger = load(ledger_path)
    assert ledger['runtime_source_hashes'] == runtime_snapshot(ROOT), 'Ledger is stale'
    maintained_path = ROOT / 'docs/native-pe/evidence.json'
    maintained = load(maintained_path)
    identities = {('kernel32', name, 'function', arch)
                  for name in ('lstrlenA', 'lstrlenW') for arch in ('x86', 'x64')}
    selected = [r for r in ledger['entries'] if tuple(r[k] for k in ('module', 'export', 'kind', 'architecture')) in identities]
    assert len(selected) == 4
    records = []
    for row in selected:
        identity = {k: row[k] for k in ('module', 'export', 'kind', 'architecture', 'source_fingerprint')}
        architecture = row['architecture']
        names = [f'{architecture.upper()}-semantic-{row["export"]}-{i:03}' for i in range(3)]
        claim = dict(**identity, semantic_status='verified_model', submitted_route='verified',
            behavioral_evidence=[dict(id=f'legacy-{row["export"]}-{architecture}-v1',
                architecture=architecture, source_fingerprint=row['source_fingerprint'],
                oracle='Frozen handler observations: return, preserved error, complete synthetic memory; bounded charset/permission/length properties',
                baseline=record(CORPUS), limits=dict(chars=32767, arena_bytes=65536, max_instructions=10000),
                tests=[DIRECT_TEST, GUEST_TEST, *names], negative_controls=[names[0], names[2], 'unreadable/encoding/overflow/length-limit oracle cases'],
                artifacts=[record(proof_path(root)), record(CORPUS), record(BOUNDARIES)])])
        validate_evidence(claim)
        records.append(claim)
    if collect_only:
        return records
    maintained['entries'] = [r for r in maintained['entries']
        if tuple(r[k] for k in ('module', 'export', 'kind', 'architecture')) not in identities] + records
    atomic_write(maintained_path, json.dumps(maintained, indent=2) + '\n')
    print('Published four source-bound semantic contracts; regenerate the ledger and final source index.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', required=True, type=Path)
    parser.add_argument('--source-index', required=True, type=Path)
    action = parser.add_mutually_exclusive_group()
    action.add_argument('--seal', action='store_true')
    action.add_argument('--check', action='store_true')
    action.add_argument('--record-evidence', type=Path, metavar='LEDGER')
    args = parser.parse_args()
    root, index = args.root.resolve(), args.source_index.resolve()
    if args.record_evidence:
        publish_evidence(root, index, args.record_evidence.resolve())
    elif args.seal or args.check:
        seal(root, index, check=args.check)
    else:
        run(root, index)
