"""Combine a frozen legacy AST inventory with exact Rust dispatcher metadata."""
import argparse
import json
from collections import Counter
from pathlib import Path

from native_pe_batches import validate_partition, variants
from native_pe_worklist import (
    REQUIRED_GATES, apply_evidence, atomic_write, changed_sources, completion, fingerprint, merge_contracts, runtime_snapshot,
)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--inventory', type=Path, required=True)
    p.add_argument('--dispatch', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--previous', type=Path, help='Preserve evidence from this ledger; defaults to output when present.')
    p.add_argument('--allow-inventory-change', action='store_true', help='Record reviewed additions/removals without discarding retired rows.')
    p.add_argument('--evidence', type=Path, default=Path(__file__).resolve().parents[1] / 'docs/native-pe/evidence.json',
                   help='Maintained sparse behavioral evidence, separate from generated output.')
    p.add_argument('--partition', type=Path, default=Path(__file__).resolve().parents[1] / 'docs/native-pe/api-batches.json',
                   help='Frozen exact contract partition; mismatches fail before writing.')
    a = p.parse_args()
    legacy = json.loads(a.inventory.read_text(encoding='utf-8-sig'))
    rust = json.loads(a.dispatch.read_text(encoding='utf-8-sig'))
    previous_path = a.previous or a.output
    previous = json.loads(previous_path.read_text(encoding='utf-8-sig')) if previous_path.exists() else None
    if a.previous and not a.previous.is_file():
        p.error('Requested previous ledger does not exist')
    dispatch = {}
    for row in rust['entries']:
        key = (row['module'], row['export'], row['architecture'])
        if key in dispatch:
            p.error(f'Duplicate dispatcher contract: {key}')
        dispatch[key] = row
    root = Path(__file__).resolve().parents[1]
    changed = changed_sources(root, legacy['sources'])
    if changed:
        p.error(f'Frozen legacy source missing or changed: {changed}')
    runtime_hashes = runtime_snapshot(root)
    dependency_fingerprint = fingerprint({'legacy': legacy['sources'], 'runtime': runtime_hashes})
    declarations = {}
    for row in legacy['entries']:
        for name in variants(row):
            key = (row['module'], name, row['kind'])
            declarations.setdefault(key, []).append(row)
    rows = []
    for (module, name, kind), sources in sorted(declarations.items()):
        for arch in ('x86', 'x64'):
            binding = dispatch.get((module, name, arch)) if kind == 'function' else None
            status = 'missing_binding' if binding is None or binding['dispatch'] in ('unmodeled', 'explicit_unsupported') else 'unverified_binding'
            rows.append({'module': module, 'export': name, 'kind': kind, 'architecture': arch,
                         'status': status, 'rust_dispatch': binding,
                         'reference_sources': sources, 'behavioral_evidence': [],
                         'source_fingerprint': fingerprint({'dependencies': dependency_fingerprint,
                                                            'declarations': sources, 'binding': binding})})
    try:
        partition_document = json.loads(a.partition.read_text(encoding='utf-8-sig'))
        assignment = validate_partition(partition_document, rows, fingerprint(legacy), legacy)
        rows, drift = merge_contracts(rows, previous['entries'] if previous else None,
                                     allow_inventory_change=a.allow_inventory_change)
        for row in rows:
            row['batch'] = assignment[tuple(row[field] for field in ('module', 'export', 'kind', 'architecture'))]
        maintained = json.loads(a.evidence.read_text(encoding='utf-8-sig'))
        maintained_gates = apply_evidence(rows, maintained)
        gates = previous.get('required_gates', {}) if previous else {}
        gates = {name: gates.get(name, {'status': 'unreviewed', 'evidence': []}) for name in REQUIRED_GATES}
        gates.update(maintained_gates)
        scope_fingerprint = fingerprint(sorted(row['source_fingerprint'] for row in rows))
        for gate in gates.values():
            if gate.get('status') == 'verified' and gate.get('scope_fingerprint') != scope_fingerprint:
                gate['history'] = [*gate.get('history', []), {
                    key: value for key, value in gate.items() if key != 'history'
                }]
                gate['status'] = 'stale'
                gate['evidence'] = []
        result_status = completion(rows, legacy['unresolved'], gates)
    except ValueError as error:
        p.error(str(error))
    counts = Counter(r['status'] for r in rows)
    families = {}
    for row in rows:
        families.setdefault(row['module'], Counter())[row['status']] += 1
    result = {'schema': 2, **result_status, 'scope': legacy['scope'],
              'inventory_unresolved': legacy['unresolved'], 'source_hashes': legacy['sources'],
              'runtime_source_hashes': runtime_hashes,
              'maintained_evidence_fingerprint': fingerprint(maintained),
              'inventory_fingerprint': fingerprint(legacy),
              'partition_fingerprint': fingerprint(partition_document),
              'inventory_changes': drift,
              'inventory_history': [*(previous.get('inventory_history', []) if previous else []),
                                    *([drift] if drift['added'] or drift['removed'] else [])],
              'counts': dict(counts), 'families': {k: dict(v) for k,v in sorted(families.items())},
              'entries': rows,
              'completion_rule': 'Every legacy behavioral contract, alias/data/ABI dependency and required regression must have verified Rust evidence. Dispatcher presence alone never closes a row.'}
    a.output.parent.mkdir(parents=True, exist_ok=True)
    atomic_write(a.output, json.dumps(result, indent=2)+'\n')
    atomic_write(a.output.with_suffix('.md'), '# Native API parity ledger\n\nComplete: **'
        + ('yes' if result['complete'] else 'no') + '**. Model bindings are not semantic qualification.\n\n'
        + '| Module | Missing bindings | Unverified bindings |\n| --- | ---: | ---: |\n'
        + ''.join(f"| {m} | {c.get('missing_binding',0)} | {c.get('unverified_binding',0)} |\n" for m,c in sorted(families.items()))
        + '\nThe JSON ledger retains source hashes, exact registrations and per-architecture unresolved contracts.\n')
    print(json.dumps({'complete': result['complete'], 'contracts': len(rows), **dict(counts),
                      'semantic_counts': result['semantic_counts'],
                      'open_contracts': result['open_contracts'],
                      'inventory_added': len(drift['added']), 'inventory_removed': len(drift['removed'])}))


if __name__ == '__main__':
    main()
