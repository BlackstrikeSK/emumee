"""Fail-closed, source-bound accounting for native PE migration contracts."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
from collections import Counter


OPEN_STATES = {'unreviewed', 'missing', 'implemented_unverified', 'blocked', 'stale'}
CLOSED_STATES = {
    'verified_model', 'verified_legacy_placeholder',
    'verified_intentional_change', 'not_applicable_with_proof',
}
ROUTES = {'unreviewed', 'missing', 'implemented_unverified', 'verified', 'not_applicable_with_proof'}
REQUIRED_GATES = (
    'effective_registration_review', 'non_api_scope', 'source_regression',
    'contained_execution', 'safety', 'package', 'operations', 'closure_audit',
)


def fingerprint(value):
    raw = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)
    return hashlib.sha256(raw.encode()).hexdigest()


def atomic_write(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=path.parent,
                                         prefix=path.name + '.', suffix='.tmp', delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def runtime_snapshot(root):
    paths = [root / 'Cargo.lock', root / 'Cargo.toml']
    paths += sorted(path for path in (root / 'rust').rglob('*')
                    if path.is_file() and path.suffix in ('.rs', '.toml', '.cmake', '.json'))
    paths += [root / 'tools' / name for name in
              ('build_rust.ps1', 'package_rust.ps1', 'package_rust_linux.sh',
               'native_api_parity_ledger.py', 'native_pe_worklist.py', 'native_pe_status.py',
               'inventory_native_api.py', 'audit_native_surface.py', 'native_pe_batches.py', 'native_pe_validation.py',
               'native_pe_baseline.py', 'native_pe_registration.py', 'native_pe_staging.py',
                'native_pe_staging_seal.py', 'native_pe_m2.py', 'native_pe_m3.py', 'verify_rust_user_pe.ps1')]
    paths += sorted((root / 'tests').glob('test_native_pe_*.py'))
    paths += [root / 'tests/test_native_api_inventory.py']
    paths += [root / 'docs/native-pe/validation-policy.json']
    paths += [root / relative for relative in registration_dependencies(root)]
    return {path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in paths}


def registration_dependencies(root):
    policy = root / 'docs/native-pe/registration-policy.json'
    if not policy.is_file():
        return []
    document = json.loads(policy.read_text(encoding='utf-8-sig'))
    sources = document.get('reviewed_sources')
    if document.get('schema') != 1 or not isinstance(sources, dict) or not sources:
        raise ValueError('Malformed effective registration dependency policy')
    relatives = ['docs/native-pe/registration-policy.json', *sources]
    for relative in relatives:
        if (not isinstance(relative, str) or not relative or '\\' in relative or ':' in relative
                or Path(relative).is_absolute() or '..' in Path(relative).parts
                or not (root / relative).resolve().is_relative_to(root.resolve())):
            raise ValueError('Effective registration dependency escapes repository')
    return relatives


def changed_sources(root, sources):
    changed = []
    for relative, expected in sources.items():
        path = root / relative
        if (not path.resolve().is_relative_to(root.resolve()) or not path.is_file()
                or hashlib.sha256(path.read_bytes()).hexdigest() != expected):
            changed.append(relative)
    return changed


def contract_key(row):
    fields = ('module', 'export', 'kind', 'architecture')
    if any(not isinstance(row.get(field), str) or not row[field] for field in fields):
        raise ValueError('Contract identity requires module/export/kind/architecture')
    if row['architecture'] not in ('x86', 'x64') or row['kind'] not in ('function', 'data'):
        raise ValueError('Unknown contract architecture/kind')
    return tuple(row[field] for field in fields)


def indexed(rows):
    result = {}
    for row in rows:
        key = contract_key(row)
        if key in result:
            raise ValueError(f'Duplicate contract: {key}')
        result[key] = row
    return result


def validate_batch_graph(worklist):
    batches = {batch['id']: batch for batch in worklist['batches']}
    if len(batches) != len(worklist['batches']):
        raise ValueError('Duplicate batch ID')
    for batch in batches.values():
        if batch['status'] not in ('pending', 'in_progress', 'blocked', 'closed'):
            raise ValueError('Unknown batch status')
        if not isinstance(batch['depends_on'], list) or any(not isinstance(item, str) for item in batch['depends_on']):
            raise ValueError('Batch dependencies must be a list of IDs')
        if len(batch['depends_on']) != len(set(batch['depends_on'])):
            raise ValueError('Duplicate batch dependency')
        if any(dependency not in batches for dependency in batch['depends_on']):
            raise ValueError('Unknown batch dependency')
    visiting, visited = set(), set()

    def visit(batch_id):
        if batch_id in visiting:
            raise ValueError('Cyclic batch dependency')
        if batch_id in visited:
            return
        visiting.add(batch_id)
        for dependency in batches[batch_id]['depends_on']:
            visit(dependency)
        visiting.remove(batch_id)
        visited.add(batch_id)

    for batch_id in batches:
        visit(batch_id)
    return batches


def validate_evidence(row):
    state = row.get('semantic_status', 'unreviewed')
    if state not in OPEN_STATES | CLOSED_STATES:
        raise ValueError(f'Unknown semantic state: {state}')
    route = row.get('submitted_route', 'unreviewed')
    if route not in ROUTES:
        raise ValueError(f'Unknown submitted route: {route}')
    if route == 'not_applicable_with_proof' and state != 'not_applicable_with_proof':
        raise ValueError('An applicable contract cannot waive its submitted route')
    if state not in CLOSED_STATES:
        return
    evidence = row.get('behavioral_evidence')
    if not isinstance(evidence, list) or not evidence:
        raise ValueError('Closed contract requires behavioral evidence')
    for item in evidence:
        if not isinstance(item, dict):
            raise ValueError('Evidence must be an object')
        for field in ('id', 'oracle', 'baseline', 'limits', 'negative_controls', 'tests'):
            if not item.get(field):
                raise ValueError(f'Closed evidence requires {field}')
        for field in ('tests', 'negative_controls'):
            if not isinstance(item[field], list) or not all(isinstance(value, str) and value for value in item[field]):
                raise ValueError(f'Closed evidence requires a list of {field}')
        if not isinstance(item['limits'], dict):
            raise ValueError('Closed evidence requires structured limits')
        if item.get('architecture') != row['architecture']:
            raise ValueError('Evidence architecture differs from contract')
        if item.get('source_fingerprint') != row['source_fingerprint']:
            raise ValueError('Evidence source fingerprint differs from contract')
    if state == 'verified_intentional_change' and not row.get('accepted_deviation'):
        raise ValueError('Intentional change requires an accepted deviation')


def merge_contracts(current, previous=None, *, allow_inventory_change=False):
    fresh = indexed(current)
    prior = indexed(previous or [])
    added = sorted(set(fresh) - set(prior)) if previous is not None else []
    removed = sorted(set(prior) - set(fresh))
    if previous is not None and (added or removed) and not allow_inventory_change:
        raise ValueError(f'Inventory drift requires review: {len(added)} added, {len(removed)} removed')
    for key, row in fresh.items():
        row.setdefault('semantic_status', 'unreviewed')
        row.setdefault('submitted_route', 'unreviewed')
        row.setdefault('behavioral_evidence', [])
        row.setdefault('history', [])
        old = prior.get(key)
        if old is None:
            validate_evidence(row)
            continue
        validate_evidence(old)
        for field in ('semantic_status', 'submitted_route', 'behavioral_evidence',
                      'history', 'accepted_deviation', 'next_action', 'blocker', 'batch'):
            if field in old:
                row[field] = old[field]
        had_claim = (old.get('semantic_status', 'unreviewed') not in ('unreviewed', 'missing', 'blocked')
                     or old.get('behavioral_evidence') or old.get('submitted_route') == 'verified')
        if old.get('source_fingerprint') != row['source_fingerprint'] and had_claim:
            row['history'] = [*row['history'], {
                'source_fingerprint': old.get('source_fingerprint'),
                'semantic_status': old.get('semantic_status', 'unreviewed'),
                'submitted_route': old.get('submitted_route', 'unreviewed'),
                'behavioral_evidence': old.get('behavioral_evidence', []),
            }]
            row['semantic_status'] = 'stale'
            row['submitted_route'] = 'unreviewed'
            row['behavioral_evidence'] = []
        validate_evidence(row)
    return list(fresh.values()), {
        'added': added, 'removed': removed,
        'retired_contracts': [prior[key] for key in removed],
    }


def apply_evidence(rows, document):
    if document.get('schema') != 1:
        raise ValueError('Unknown maintained evidence schema')
    contracts = indexed(rows)
    records = indexed(document['entries'])
    if set(records) - set(contracts):
        raise ValueError('Orphan maintained evidence requires inventory review')
    for key, record in records.items():
        validate_evidence(record)
        row = contracts[key]
        if record['source_fingerprint'] != row['source_fingerprint']:
            if record not in row['history']:
                row['history'] = [*row['history'], record]
            row['semantic_status'] = 'stale'
            row['submitted_route'] = 'unreviewed'
            row['behavioral_evidence'] = []
            continue
        for field in ('semantic_status', 'submitted_route', 'behavioral_evidence', 'accepted_deviation'):
            if field in record:
                row[field] = record[field]
        validate_evidence(row)
    unknown = set(document.get('required_gates', {})) - set(REQUIRED_GATES)
    if unknown:
        raise ValueError(f'Unknown maintained qualification gates: {sorted(unknown)}')
    return document.get('required_gates', {})


def completion(entries, unresolved, required_gates):
    indexed(entries)
    for row in entries:
        validate_evidence(row)
    semantics = Counter(row['semantic_status'] for row in entries)
    routes = Counter(row['submitted_route'] for row in entries)
    open_contracts = sum(row['semantic_status'] not in CLOSED_STATES or
                         (row.get('status') == 'missing_binding' and
                          row['semantic_status'] != 'not_applicable_with_proof') or
                         row['submitted_route'] not in ('verified', 'not_applicable_with_proof')
                         for row in entries)
    scope_fingerprint = fingerprint(sorted(row['source_fingerprint'] for row in entries))
    gates_pass = set(required_gates) == set(REQUIRED_GATES) and all(
        isinstance(gate, dict) and gate.get('status') == 'verified' and gate.get('evidence')
        and gate.get('scope_fingerprint') == scope_fingerprint
        for gate in required_gates.values()
    )
    return {
        'complete': bool(entries) and not unresolved and not open_contracts and bool(gates_pass),
        'open_contracts': open_contracts,
        'semantic_counts': dict(semantics), 'submitted_route_counts': dict(routes),
        'required_gates': required_gates,
        'scope_fingerprint': scope_fingerprint,
    }
