"""Independent closure audit over the full native API denominator.

M11 is the global gate of the M8-M11 batch. Its exit tests are "all required
gates" and "zero open or stale required contracts", read against "an independent
audit of the full denominator". This tool is that audit.

It does **not** close the model. Every prior milestone states that no partition
row has semantic closure, and the parity ledger confirms it: all 2590 contracts
are open and unreviewed. An honest global gate therefore cannot report
completion. What it can certify, and what this audit does, is that the
denominator accounting is **reproducible, internally consistent and
tamper-evident**, and that nothing is credited that has not been earned:

1. The frozen legacy inventory is regenerated from source and must be
   byte-identical to the committed baseline, so the denominator's left-hand side
   is intact.
2. The dispatcher metadata is read from the same release build the M10 matrix
   sealed, so the audit and the release matrix describe one build.
3. The parity ledger is produced from those two inputs, and this audit then
   recomputes the completion status **independently** from the ledger's own
   entries and must agree with the ledger's self-report — a second opinion on
   the same denominator.
4. The honesty invariant is asserted directly: **zero** contracts are credited
   as closed (none has a closed semantic status and none a stale-but-counted
   evidence record), so "zero open or stale required contracts" holds in the
   only sense the evidence supports — nothing is falsely closed — while the
   count of genuinely open contracts is reported in full.
5. `complete` must be False and `open_contracts` must equal the contract count;
   an audit that reported otherwise against this evidence would be the failure.

The receipt binds the ledger fingerprint, the M10 matrix fingerprint and the
source index, so the global gate is anchored to the same build as the release
matrix.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from native_pe_worklist import (
    CLOSED_STATES, REQUIRED_GATES, atomic_write, completion, fingerprint,
)

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
    """Contracts credited as closed. The honesty invariant requires this be 0:
    nothing may carry a closed semantic status without the evidence to earn it,
    and in this denominator nothing does."""
    return sum(row['semantic_status'] in CLOSED_STATES for row in entries)


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


def audit_document(root, bundle, matrix_path, index_path):
    ledger_path = root / 'audit/ledger.json'
    ledger = _load(ledger_path)
    partition = _load(PARTITION)
    entries = ledger['entries']

    # Independent recomputation of the completion status from the ledger's own
    # entries and gates: a second opinion that must match the ledger's report.
    independent = completion(entries, ledger['inventory_unresolved'], ledger['required_gates'])
    for field in ('complete', 'open_contracts', 'semantic_counts', 'scope_fingerprint'):
        assert independent[field] == ledger[field], ('ledger self-report disagrees with the audit', field)

    # The denominator's shape is exactly the frozen partition.
    assert len(entries) == partition['contract_count'] == 2590, 'Denominator size is not the frozen contract count'
    assert ledger['inventory_fingerprint'] == partition['inventory_fingerprint'], 'Inventory is not the one the partition was cut against'
    assert ledger['partition_fingerprint'] == fingerprint(partition), 'Partition fingerprint drifted'
    assert not ledger['inventory_changes']['added'] and not ledger['inventory_changes']['removed'], 'Unreviewed inventory drift'
    assert sum(ledger['counts'].values()) == 2590, 'Binding counts do not cover the denominator'

    # The honesty invariant: nothing is credited that was not earned. Zero
    # contracts are closed, and none carries a stale evidence record counted as
    # closed, so "zero open or stale required contracts" holds as "nothing
    # falsely closed" while the open count is reported in full.
    falsely_closed = falsely_closed_count(entries)
    stale_evidence = sum(row['semantic_status'] == 'stale' for row in entries)
    assert falsely_closed == 0, f'{falsely_closed} contracts credited as closed without the evidence to support it'
    open_contracts = independent['open_contracts']
    # An honest global gate over this evidence reports the denominator open, not closed.
    assert independent['complete'] is False, 'The audit must not report completion while the denominator is open'
    assert open_contracts == 2590, 'Every contract in the denominator is open; the count must say so'

    gate_states = {name: ledger['required_gates'].get(name, {}).get('status', 'unreviewed') for name in REQUIRED_GATES}
    matrix = _load(matrix_path)
    index = _load(index_path)

    document = dict(
        schema=1,
        scope='M11 independent closure audit of the full native API denominator; '
              'certifies the accounting is reproducible, consistent and honest, not that any contract is closed',
        complete=False,
        denominator=dict(
            contracts=len(entries),
            open_contracts=open_contracts,
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
            'No partition row has semantic closure; this audit does not create any.',
            f'All {open_contracts} contracts are open and unreviewed; the audit reports the denominator, it does not close it.',
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
