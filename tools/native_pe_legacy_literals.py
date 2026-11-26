"""Review explicit frozen return-only handlers and their original alias rule.

No legacy imports, PE execution or native Windows exports run. Handler bodies
are AST-checked literals; the one extracted normalization method uses fake API
lookups and cannot reach an emulator or the host.
"""
from __future__ import annotations

import argparse
import ast
import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

from native_pe_batches import inventory_contracts, variants
from native_pe_worklist import fingerprint

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / 'rust/emumee-engine/src/api/legacy_literals.json'
NORMALIZER = '.venv/Lib/site-packages/speakeasy/windows/winemu.py'


def load(path):
    return json.loads(Path(path).read_bytes())


def normalizer_factory():
    data = (ROOT / NORMALIZER).read_bytes()
    expected = load(ROOT / 'docs/native-pe/registration-policy.json')['reviewed_sources'][NORMALIZER]
    assert hashlib.sha256(data).hexdigest() == expected, 'Reviewed normalizer changed'
    tree = ast.parse(data)
    method, = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == 'normalize_import_miss']
    cls = ast.ClassDef(name='Normalizer', bases=[], keywords=[], body=[copy.deepcopy(method)],
                       decorator_list=[], type_params=[])
    module = ast.fix_missing_locations(ast.Module(body=[cls], type_ignores=[]))
    namespace = {'winemu': SimpleNamespace(normalize_dll_name=lambda name: name)}
    exec(compile(module, NORMALIZER, 'exec'), namespace)
    return namespace['Normalizer'], expected


def review(manifest=None):
    manifest = manifest or load(MANIFEST)
    frozen = load(ROOT / 'rust/api-parity/legacy-inventory.json')
    assert manifest['schema'] == 1
    contracts = inventory_contracts(frozen)
    expected_paths = {s['source'] for r in manifest['entries'] for s in r['reference_sources']}
    assert set(manifest['sources']) == expected_paths, 'Literal reference dependency set differs'
    trees = {}
    for name, digest in manifest['sources'].items():
        assert name in frozen['sources'] and digest == frozen['sources'][name], 'Unreviewed literal source'
        data = (ROOT / name).read_bytes()
        assert digest == frozen['sources'][name] == hashlib.sha256(data).hexdigest(), 'Frozen literal source changed'
        trees[name] = ast.parse(data)
    normalizer, normalizer_hash = normalizer_factory()
    identities = set()
    results = []
    all_names = {(r['module'], n) for r in frozen['entries'] if r['kind'] == 'function' for n in variants(r)}
    for entry in manifest['entries']:
        module, export, architecture = (entry[k] for k in ('module', 'export', 'architecture'))
        key = module, export, 'function', architecture
        assert key not in identities and architecture in ('x86', 'x64')
        identities.add(key)
        assert not export.startswith('#'), 'Ordinal evidence needs an actual ordinal import route'
        assert entry['reference_sources'] == contracts[key], 'Literal declaration identity differs'
        assert entry['convention'] == 'stdcall' and 0 <= entry['argc'] <= 12
        assert type(entry['value']) is int and 0 <= entry['value'] <= 0xffffffff
        values = []
        for ref in entry['reference_sources']:
            function, = [n for n in ast.walk(trees[ref['source']])
                         if isinstance(n, ast.FunctionDef) and n.lineno == ref['line']]
            assert function.end_lineno == ref['end_line']
            body = [n for n in function.body if not (isinstance(n, ast.Expr)
                    and isinstance(n.value, ast.Constant) and isinstance(n.value.value, str))]
            assert len(body) == 1 and isinstance(body[0], ast.Return), 'Handler is not return-only'
            value = ast.literal_eval(body[0].value)
            assert isinstance(value, (bool, int)) and value is not None and value >= 0
            assert value == ref['literal_result'] and ref['literal_return_only']
            body_text = ast.unparse(ast.Module(body=body, type_ignores=[]))
            assert hashlib.sha256(body_text.encode()).hexdigest() == ref['body_sha256']
            decorators = [d for d in function.decorator_list if isinstance(d, ast.Call)]
            matching = [d for d in decorators if d.args and isinstance(d.args[0], ast.Constant)
                        and d.args[0].value == ref['export']]
            assert len(matching) == 1, 'Literal decorator identity differs'
            keywords = {k.arg: k.value for k in matching[0].keywords}
            argc = ast.literal_eval(keywords['argc']) if 'argc' in keywords else 0
            assert argc == ref['argc'] == entry['argc']
            values.append(int(value))
        assert set(values) == {entry['value']}, 'Manifest value differs from independently parsed body'
        names = [export]
        if module != 'ntdll':
            for suffix in ('A', 'W'):
                alias = export + suffix
                assert (module, alias) not in all_names, 'An exact baseline declaration must win over a miss alias'
                instance = normalizer()
                instance.api = SimpleNamespace(get_export_func_handler=lambda dll, name:
                    (dll, (export, entry['argc'], entry['value'])) if (dll, name) == (module, export) else (None, None))
                result = instance.normalize_import_miss(module, alias)
                assert result == (module, (export, entry['argc'], entry['value'])), 'Frozen alias normalization differs'
                names.append(alias)
        results.append({**entry, 'call_names': names, 'oracle_value': values[0]})
    assert len(results) == 156, 'Review a changed literal contract denominator explicitly'
    return dict(schema=1, contracts=results, normalizer_sha256=normalizer_hash,
                manifest_fingerprint=fingerprint(manifest))


def groups(architecture, reviewed=None):
    modules = {}
    for entry in (reviewed or review())['contracts']:
        if entry['architecture'] == architecture:
            modules.setdefault(entry['module'], []).append(entry)
    result = {}
    arch = architecture.upper()
    for module, entries in sorted(modules.items()):
        entries.sort(key=lambda e: e['export'])
        for start in range(0, len(entries), 4):
            for arguments in ('Zero', 'Poison', 'Arena'):
                name = f'{arch}-semantic-literal-{module}-{start // 4:03}-{arguments}'
                result[name] = entries[start:start + 4]
    return result


if __name__ == '__main__':
    argparse.ArgumentParser(description=__doc__).parse_args()
    result = review()
    print(json.dumps(dict(contracts=len(result['contracts']), exports=len({(r['module'], r['export']) for r in result['contracts']}),
                          manifest_fingerprint=result['manifest_fingerprint'], normalizer_sha256=result['normalizer_sha256'])))
