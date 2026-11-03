"""Combine a frozen legacy AST inventory with exact Rust dispatcher metadata."""
import argparse
import json
from collections import Counter
from pathlib import Path


def variants(row):
    name = row['export']
    if name.endswith('*'):
        names = [name[:-1]+'A', name[:-1]+'W']
    elif row.get('character_width_dispatch'):
        names = [name+'A', name+'W']
    else:
        names = [name]
    if row.get('ordinal'):
        names.append('#'+str(row['ordinal']))
    return names


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--inventory', type=Path, required=True)
    p.add_argument('--dispatch', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    legacy = json.loads(a.inventory.read_text(encoding='utf-8-sig'))
    rust = json.loads(a.dispatch.read_text(encoding='utf-8-sig'))
    dispatch = {(r['module'], r['export'], r['architecture']): r for r in rust['entries']}
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
                         'reference_sources': sources, 'behavioral_evidence': []})
    counts = Counter(r['status'] for r in rows)
    families = {}
    for row in rows:
        families.setdefault(row['module'], Counter())[row['status']] += 1
    result = {'schema': 1, 'complete': False, 'scope': legacy['scope'],
              'inventory_unresolved': legacy['unresolved'], 'source_hashes': legacy['sources'],
              'counts': dict(counts), 'families': {k: dict(v) for k,v in sorted(families.items())},
              'entries': rows,
              'completion_rule': 'Every legacy behavioral contract, alias/data/ABI dependency and required regression must have verified Rust evidence. Dispatcher presence alone never closes a row.'}
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8')
    a.output.with_suffix('.md').write_text('# Native API parity ledger\n\nComplete: **no**. Model bindings are not semantic qualification.\n\n'
        + '| Module | Missing bindings | Unverified bindings |\n| --- | ---: | ---: |\n'
        + ''.join(f"| {m} | {c.get('missing_binding',0)} | {c.get('unverified_binding',0)} |\n" for m,c in sorted(families.items()))
        + '\nThe JSON ledger retains source hashes, exact registrations and per-architecture unresolved contracts.\n', encoding='utf-8')
    print(json.dumps({'complete': False, 'contracts': len(rows), **dict(counts)}))


if __name__ == '__main__':
    main()
