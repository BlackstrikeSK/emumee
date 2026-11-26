"""Qualify explicit frozen void placeholders without inventing scalar returns."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from native_pe_legacy_voids import MANIFEST, RETURN_SOURCE, review
from native_pe_legacy_literals import NORMALIZER, groups
from native_pe_m4 import verify
from native_pe_m6 import build_gate
from native_pe_semantic_strlen import load, record
from native_pe_staging_seal import binding
from native_pe_semantic_proofs import contract_identities as proof_contracts
from native_pe_worklist import atomic_write, fingerprint, runtime_snapshot, validate_evidence

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = 'semantic-voids'
TESTS = [
    'semantic_voids_tests::frozen_void_calls_preserve_seeded_registers_errors_and_the_complete_arena',
    'semantic_voids_tests::frozen_void_width_aliases_resolve_dynamically_and_preserve_full_return_registers',
    'api::legacy_voids::tests::reviewed_voids_and_frozen_width_aliases_remain_void_and_finite',
]
ARENA_HASH = hashlib.sha256(bytes([0xa5]) * 0x10000).hexdigest()


def controls(reviewed=None):
    reviewed = reviewed or review()
    result = {}
    for architecture in ('x86', 'x64'):
        result.update({name.replace('-semantic-literal-', '-semantic-void-'): members
                       for name, members in groups(architecture, reviewed).items()})
        result[f'{architecture.upper()}-semantic-void-dynamic'] = None
    return result


def fixtures(root, expected):
    selected = sorted(p for p in (root / 'fixtures-final').iterdir()
                      if p.is_dir() and '-semantic-void-' in p.name)
    assert {p.name for p in selected} == set(expected), 'Void control set differs'
    return selected


def source_tests(index):
    run, = [r for r in load(index)['runs'] if r['suite'] == 'rust-tests']
    assert run['exit_code'] == 0
    text = (ROOT / run['log']).read_text(encoding='utf-8')
    for name in TESTS:
        assert f'test {name} ... ok' in text, f'Missing successful void test: {name}'


def observations(root, fixture, expected):
    execution = binding(root / OUTPUT / fixture.name, fixture / 'sample.exe')['result']['execution']
    assert execution['error'] is None and execution['guest_entry_return'] == 1
    assert execution['api_events_omitted'] == 0
    events = [e for e in execution['api_events'] if e.get('effect') == 'frozen_legacy_placeholder']
    if expected is None:
        assert [e['api'] for e in events] == ['comctl32.InitCommonControls', 'comctl32.InitCommonControlsA', 'comctl32.InitCommonControlsW']
        assert all(e['result'] is None and not e['pending'] and e['error'] is None for e in events)
        assert all(e['last_error'] == 0x12345678 for e in events[1:])
        assert not execution['artifacts']
        return dict(case=fixture.name, dynamic_aliases=['InitCommonControlsA', 'InitCommonControlsW'])
    names = [(entry['module'] + '.' + name, entry) for entry in expected for name in entry['call_names']]
    assert [e['api'] for e in events] == [name for name, _ in names], 'Void API route/order differs'
    argument = 0
    if fixture.name.endswith('-Poison'):
        argument = (1 << (32 if fixture.name.startswith('X86-') else 64)) - 1
    elif fixture.name.endswith('-Arena'):
        argument = 0x26000000
    for event, (_, oracle) in zip(events, names):
        assert event['result'] is None, (fixture.name, event['api'], 'return')
        assert event['last_error'] == 0x12345678 and not event['pending'] and event['error'] is None
        assert event['arguments'] == [argument] * oracle['argc'], (fixture.name, 'ABI arguments')
    arena, = [a for a in execution['artifacts'] if any(
        o['kind'] == 'guest_file' and o['guest_path'].lower().endswith('void-memory.bin')
        for o in a['observations'])]
    assert arena['size'] == 0x10000 and arena['sha256'] == ARENA_HASH, 'Void handler changed the guest arena'
    return dict(case=fixture.name, calls=[dict(api=e['api'], result=e['result'],
        last_error=e['last_error'], arguments=e['arguments']) for e in events], arena_sha256=arena['sha256'])


def run(root, index):
    build_gate(root, index)
    source_tests(index)
    expected = controls()
    output = root / OUTPUT
    output.mkdir()
    for fixture in fixtures(root, expected):
        limits = load(fixture / 'limits.json')
        command = [str(root / 'bundle/emumee-rs.exe'), 'run', str(fixture / 'sample.exe'),
                   '--output', str(output / fixture.name), '--inputs', str(fixture / 'inputs.json'),
                   '--max-instructions', str(limits['max_instructions']), '--timeout-us', str(limits['timeout_us'])]
        result = subprocess.run(command, capture_output=True, timeout=120)
        (output / f'{fixture.name}.stdout').write_bytes(result.stdout)
        (output / f'{fixture.name}.stderr').write_bytes(result.stderr)
        assert result.returncode == 0, (fixture.name, result.stderr)
        verify(root, fixture, output_directory=OUTPUT)
        observations(root, fixture, expected[fixture.name])
        print(f'{fixture.name} independently verified', flush=True)


def proof_path(root):
    return root / f'qualified-semantic-voids-{fingerprint(runtime_snapshot(ROOT))}.json'


def seal(root, index, *, check=False):
    build_gate(root, index)
    source_tests(index)
    reviewed = review()
    expected = controls(reviewed)
    selected = fixtures(root, expected)
    observed = []
    for fixture in selected:
        verify(root, fixture, output_directory=OUTPUT)
        observed.append(observations(root, fixture, expected[fixture.name]))
    paths = {MANIFEST, ROOT / NORMALIZER, ROOT / RETURN_SOURCE}
    paths.update(ROOT / p for p in load(MANIFEST)['sources'])
    for directory in (root / 'bundle', root / OUTPUT, *selected):
        paths.update(p for p in directory.rglob('*') if p.is_file())
    document = dict(schema=1, profile='emumee.native-semantic.legacy-voids.v1',
                    runtime_fingerprint=fingerprint(runtime_snapshot(ROOT)),
                    source_tree_sha256=load(root / 'bundle/rust-worker-build.json')['source_tree_sha256'],
                    contract_identities=proof_contracts(reviewed['contracts']),
                    oracle=reviewed, tests=TESTS, controls=observed,
                    artifacts=[record(p) for p in sorted(paths)])
    document['fingerprint'] = fingerprint(document)
    path = proof_path(root)
    if check:
        assert load(path) == document, 'Legacy void proof differs'
    else:
        assert not path.exists(), 'Preserve sealed void evidence'
        atomic_write(path, json.dumps(document, indent=2) + '\n')
    print(json.dumps(dict(contracts=len(reviewed['contracts']), controls=len(observed), fingerprint=document['fingerprint'])))


def publish_evidence(root, index, ledger_path, *, collect_only=False):
    seal(root, index, check=True)
    ledger = load(ledger_path)
    assert ledger['runtime_source_hashes'] == runtime_snapshot(ROOT), 'Ledger is stale'
    reviewed = review()
    selected = {(r['module'], r['export'], 'function', r['architecture']): r for r in reviewed['contracts']}
    claims = []
    for row in ledger['entries']:
        key = tuple(row[k] for k in ('module', 'export', 'kind', 'architecture'))
        if key not in selected:
            continue
        oracle = selected[key]
        assert row['rust_dispatch']['legacy_void_placeholder'] is True
        assert row['rust_dispatch']['return_type'] == 'void'
        assert row['rust_dispatch']['argc'] == oracle['argc']
        related = [name for name, members in controls(reviewed).items()
                   if members and any(e['module'] == row['module'] and e['export'] == row['export']
                       and e['architecture'] == row['architecture'] for e in members)]
        assert len(related) == 3
        claim = {k: row[k] for k in ('module', 'export', 'kind', 'architecture', 'source_fingerprint')}
        claim.update(semantic_status='verified_legacy_placeholder', submitted_route='verified',
            behavioral_evidence=[dict(id=f'legacy-void-{row["module"]}-{row["export"]}-{row["architecture"]}-v1',
                architecture=row['architecture'], source_fingerprint=row['source_fingerprint'],
                oracle='Independently parsed frozen void body, original A/W miss normalization and extracted original call-return bookkeeping; no native Windows behavior claimed',
                baseline=oracle['reference_sources'], limits=dict(arena_bytes=65536, max_instructions=100000, args=12),
                tests=[*TESTS, *related], negative_controls=['Zero arguments', 'Poisoned arguments', 'Valid arena pointers',
                    'Unknown-name refusal', 'Kernel authority refusal', 'Existing explicit-refusal precedence', 'Scalar zero is not a void result', 'Full-width return-register seed preservation'],
                artifacts=[record(proof_path(root)), record(MANIFEST), record(ROOT / NORMALIZER), record(ROOT / RETURN_SOURCE)])])
        validate_evidence(claim)
        claims.append(claim)
    assert len(claims) == 18
    if collect_only:
        return claims
    path = ROOT / 'docs/native-pe/evidence.json'
    maintained = load(path)
    maintained['entries'] = [r for r in maintained['entries']
        if tuple(r[k] for k in ('module', 'export', 'kind', 'architecture')) not in selected] + claims
    atomic_write(path, json.dumps(maintained, indent=2) + '\n')
    print('Published 18 source-bound legacy-placeholder contracts; regenerate ledger and final source validation.')


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
