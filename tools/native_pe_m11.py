"""Independently audit native API closure against the frozen full denominator.

Recompute completion without the ledger's completion algorithm, verify every
closed claim's source-bound evidence artifacts, and check the same-build release
matrix and source index. Partial semantic progress is valid; completion requires
zero open contracts, no unresolved inventory, and every required gate verified.
The audit never creates semantic evidence or silently seals missing milestones.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
from collections import Counter
import subprocess
import sys

from native_pe_worklist import (
    CLOSED_STATES, OPEN_STATES, ROUTES, REQUIRED_GATES, atomic_write, fingerprint,
    validate_evidence,
    runtime_snapshot,
)
from native_pe_m6 import build_gate
from native_pe_m10 import matrix as check_matrix, stages

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / 'tools'
BASELINE = ROOT / 'rust/api-parity/legacy-inventory.json'
PARTITION = ROOT / 'docs/native-pe/api-batches.json'


def _sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _python(script, *args):
    completed = subprocess.run([sys.executable, str(TOOLS / script), *[str(a) for a in args]],
                               cwd=ROOT, capture_output=True, text=True)
    assert completed.returncode == 0, (script, completed.returncode, completed.stderr)
    return completed.stdout


def _load(path):
    return json.loads(Path(path).read_text(encoding='utf-8-sig'))


def falsely_closed_count(entries):
    """Count closed semantic claims whose declared evidence is invalid."""
    invalid = 0
    for row in entries:
        if row['semantic_status'] in CLOSED_STATES:
            try:
                validate_evidence(row)
            except (ValueError, KeyError, TypeError):
                invalid += 1
    return invalid


def independent_completion(entries, unresolved, gates):
    """Recompute the gate without calling the ledger's completion algorithm."""
    identities = [(r['module'], r['export'], r['kind'], r['architecture']) for r in entries]
    assert len(set(identities)) == len(identities), 'Duplicate denominator contract'
    for row in entries:
        assert row['semantic_status'] in CLOSED_STATES | OPEN_STATES, 'Unknown semantic status'
        assert row['submitted_route'] in ROUTES, 'Unknown submitted route'
        validate_evidence(row)
    opened = [r for r in entries if not (
        r['semantic_status'] in CLOSED_STATES
        and (r['status'] != 'missing_binding' or r['semantic_status'] == 'not_applicable_with_proof')
        and r['submitted_route'] in ('verified', 'not_applicable_with_proof'))]
    scope = fingerprint(sorted(r['source_fingerprint'] for r in entries))
    qualified_gates = set(gates) == set(REQUIRED_GATES) and all(
        isinstance(g, dict) and g.get('status') == 'verified' and g.get('evidence')
        and g.get('scope_fingerprint') == scope for g in gates.values())
    return dict(complete=bool(entries) and not unresolved and not opened and bool(qualified_gates),
                open_contracts=len(opened),
                semantic_counts=dict(Counter(r['semantic_status'] for r in entries)),
                submitted_route_counts=dict(Counter(r['submitted_route'] for r in entries)),
                scope_fingerprint=scope)


def verify_semantic_artifacts(entries, root=ROOT, *, bundle=None, runtime_fingerprint=None, source_index=None):
    from native_pe_semantic_proofs import verify_artifacts
    return verify_artifacts(entries, root, bundle=bundle, runtime_fingerprint=runtime_fingerprint,
                            source_index=source_index)


def build_ledger(root, bundle):
    """Reproduce the denominator inputs and the parity ledger under `root`."""
    audit = root / 'audit'
    audit.mkdir(parents=True, exist_ok=True)
    inventory = audit / 'legacy-inventory.json'
    _python('inventory_native_api.py', '--output', inventory)
    # The frozen inventory must regenerate exactly to the committed baseline.
    assert _load(inventory) == _load(BASELINE), 'Regenerated inventory differs from the frozen baseline'
    queries = inventory.with_name('queries.json')
    dispatch = audit / 'dispatch.json'
    completed = subprocess.run([str((bundle / 'emumee-rs.exe').resolve()), 'inspect-api-surface', str(queries)],
                               cwd=ROOT, capture_output=True)
    assert completed.returncode == 0, ('inspect-api-surface', completed.returncode, completed.stderr)
    dispatch.write_bytes(completed.stdout)
    ledger = audit / 'ledger.json'
    _python('native_api_parity_ledger.py', '--inventory', inventory, '--dispatch', dispatch, '--output', ledger)
    return ledger


def verify_release_anchor(bundle, matrix_path, index_path):
    release_root = bundle.resolve().parent
    assert bundle.resolve() == release_root / 'bundle', 'Expected the frozen release bundle directory'
    assert matrix_path.resolve() == release_root / 'qualified-m10.json', 'Matrix belongs to another release root'
    build_gate(release_root, index_path.resolve())
    # Check existing evidence only: an audit must not create a missing milestone
    # seal or run controls as a side effect of checking a release claim.
    for _, produced, _, _, check_step in stages(release_root, index_path.resolve()):
        assert (release_root / produced).is_file(), f'Missing release milestone: {produced}'
        check_step()
    check_matrix(release_root, index_path.resolve(), check=True)


def audit_document(root, bundle, matrix_path, index_path):
    verify_release_anchor(bundle, matrix_path, index_path)
    ledger_path = root / 'audit/ledger.json'
    ledger = _load(ledger_path)
    assert ledger['runtime_source_hashes'] == runtime_snapshot(ROOT), 'Ledger runtime dependencies are stale'
    assert ledger['source_hashes'] == _load(BASELINE)['sources'], 'Ledger baseline dependencies differ'
    assert ledger['maintained_evidence_fingerprint'] == fingerprint(
        _load(ROOT / 'docs/native-pe/evidence.json')), 'Ledger maintained evidence is stale'
    partition = _load(PARTITION)
    entries = ledger['entries']

    # Independent recomputation of the completion status from the ledger's own
    # entries and gates: a second opinion that must match the ledger's report.
    independent = independent_completion(entries, ledger['inventory_unresolved'], ledger['required_gates'])
    for field in ('complete', 'open_contracts', 'semantic_counts', 'submitted_route_counts', 'scope_fingerprint'):
        assert independent[field] == ledger[field], ('ledger self-report disagrees with the audit', field)

    # The denominator's shape is exactly the frozen partition.
    assert len(entries) == partition['contract_count'] == 2590, 'Denominator size is not the frozen contract count'
    assert ledger['inventory_fingerprint'] == partition['inventory_fingerprint'], 'Inventory is not the one the partition was cut against'
    assert ledger['partition_fingerprint'] == fingerprint(partition), 'Partition fingerprint drifted'
    assert not ledger['inventory_changes']['added'] and not ledger['inventory_changes']['removed'], 'Unreviewed inventory drift'
    assert sum(ledger['counts'].values()) == 2590, 'Binding counts do not cover the denominator'
    expected_contracts = {tuple(key) for batch in partition['batches'] for key in batch['contracts']}
    actual_contracts = {(r['module'], r['export'], r['kind'], r['architecture']) for r in entries}
    assert actual_contracts == expected_contracts, 'Ledger contracts differ from the frozen partition'
    assert ledger['counts'] == dict(Counter(r['status'] for r in entries)), 'Binding counts differ from entries'

    # Legitimate partial closure is allowed; invalid or stale evidence cannot be
    # credited. Open contracts and gates still prevent global completion.
    falsely_closed = falsely_closed_count(entries)
    stale_evidence = sum(row['semantic_status'] == 'stale' for row in entries)
    assert falsely_closed == 0, f'{falsely_closed} contracts credited as closed without the evidence to support it'
    open_contracts = independent['open_contracts']
    # An honest global gate over this evidence reports the denominator open, not closed.
    semantic_artifacts = verify_semantic_artifacts(entries, bundle=bundle,
        runtime_fingerprint=fingerprint(runtime_snapshot(ROOT)), source_index=index_path)

    gate_states = {name: ledger['required_gates'].get(name, {}).get('status', 'unreviewed') for name in REQUIRED_GATES}
    matrix = _load(matrix_path)
    index = _load(index_path)

    document = dict(
        schema=2,
        scope='M11 independent closure audit of the full native API denominator; '
              'completion requires source-bound semantic evidence, submitted routes and every required gate',
        complete=independent['complete'],
        denominator=dict(
            contracts=len(entries),
            open_contracts=open_contracts,
            closed_contracts=len(entries) - open_contracts,
            semantic_artifacts=semantic_artifacts,
            falsely_closed=falsely_closed,
            stale_evidence=stale_evidence,
            binding_counts=ledger['counts'],
            semantic_counts=ledger['semantic_counts'],
            inventory_unresolved=ledger['inventory_unresolved'],
        ),
        required_gates=gate_states,
        ledger=dict(
            inventory_fingerprint=ledger['inventory_fingerprint'],
            partition_fingerprint=ledger['partition_fingerprint'],
            scope_fingerprint=ledger['scope_fingerprint'],
            sha256=_sha(ledger_path),
        ),
        release_matrix=dict(path=Path(matrix_path).resolve().relative_to(ROOT).as_posix(),
                            fingerprint=matrix['fingerprint'],
                            source_tree_sha256=matrix['source_tree_sha256']),
        source_index=dict(path=Path(index_path).resolve().relative_to(ROOT).as_posix(),
                          sha256=_sha(index_path),
                          source_fingerprint=index.get('source_fingerprint')),
        honest_scope=[
            'The audit validates declared closure evidence and never creates semantic evidence.',
            f'{open_contracts} of {len(entries)} contracts remain open, including unverified submitted routes.',
            'The required gates are reported in their true state (verified, stale or unreviewed), not forced to verified.',
            'What is certified is that the accounting is reproducible from frozen inventory and same-build dispatch, '
            'internally consistent, tamper-evident, and credits nothing it has not earned.',
        ],
    )
    document['fingerprint'] = fingerprint(document)
    return document


def seal(root, bundle, matrix_path, index_path, *, check=False):
    document = audit_document(root, bundle, matrix_path, index_path)
    destination = root / 'qualified-m11.json'
    if check:
        assert _load(destination) == document, 'M11 audit differs from its sealed form'
    else:
        assert not destination.exists(), 'Preserve sealed evidence'
        atomic_write(destination, json.dumps(document, indent=2) + '\n')
    print(json.dumps(dict(complete=document['complete'],
                          open_contracts=document['denominator']['open_contracts'],
                          falsely_closed=document['denominator']['falsely_closed'],
                          gates=document['required_gates'],
                          fingerprint=document['fingerprint']), indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--bundle', type=Path, required=True, help='Same-build bundle dir (the M10 release bundle).')
    parser.add_argument('--matrix', type=Path, required=True, help='The M10 release-matrix seal (qualified-m10.json).')
    parser.add_argument('--source-index', type=Path, required=True)
    action = parser.add_mutually_exclusive_group()
    action.add_argument('--seal', action='store_true')
    action.add_argument('--check', action='store_true')
    args = parser.parse_args()
    root = args.root.resolve()
    bundle, matrix, index = args.bundle.resolve(), args.matrix.resolve(), args.source_index.resolve()
    if args.seal or args.check:
        seal(root, bundle, matrix, index, check=args.check)
    else:
        build_ledger(root, bundle)
        print('ledger reproduced', flush=True)
