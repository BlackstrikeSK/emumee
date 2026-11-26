"""Review explicit handlers that only unpack args, assign constants and return."""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

from native_pe_batches import inventory_contracts, variants
from native_pe_legacy_literals import normalizer_factory

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / 'rust/emumee-engine/src/api/legacy_locals.json'


def load(path):
    return json.loads(Path(path).read_bytes())


def constant_result(function, argc):
    """A finite AST proof; no source execution or general expression evaluator."""
    body = [n for n in function.body if not (isinstance(n, ast.Expr)
            and isinstance(n.value, ast.Constant) and isinstance(n.value.value, str))]
    assert len(body) >= 2 and isinstance(body[-1], ast.Return)
    names = {}
    for statement in body[:-1]:
        assert isinstance(statement, ast.Assign) and len(statement.targets) == 1
        target = statement.targets[0]
        value = statement.value
        if isinstance(target, (ast.Tuple, ast.List)):
            assert isinstance(value, ast.Name) and value.id == 'argv'
            assert len(target.elts) == argc
            assert all(isinstance(n, ast.Name) and n.id != 'argv' for n in target.elts)
            names.update({n.id: None for n in target.elts})
        else:
            assert isinstance(target, ast.Name) and target.id != 'argv'
            assert isinstance(value, ast.Constant) and type(value.value) in (int, bool)
            names[target.id] = int(value.value)
    result = body[-1].value
    if isinstance(result, ast.Name):
        result = names.get(result.id)
    else:
        assert isinstance(result, ast.Constant) and type(result.value) in (int, bool)
        result = int(result.value)
    assert type(result) is int and 0 <= result <= 0xffffffff
    return result


def review(manifest=None):
    manifest = manifest or load(MANIFEST)
    frozen = load(ROOT / 'rust/api-parity/legacy-inventory.json')
    assert manifest['schema'] == 1
    contracts = inventory_contracts(frozen)
    paths = {r['source'] for e in manifest['entries'] for r in e['reference_sources']}
    assert set(manifest['sources']) == paths
    trees = {}
    for path, digest in manifest['sources'].items():
        assert path in frozen['sources'] and digest == frozen['sources'][path]
        raw = (ROOT / path).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == digest
        trees[path] = ast.parse(raw)
    normalizer, normalizer_hash = normalizer_factory()
    all_names = {(r['module'], n) for r in frozen['entries'] if r['kind'] == 'function' for n in variants(r)}
    identities = set()
    rows = []
    for entry in manifest['entries']:
        module, export, architecture = (entry[k] for k in ('module', 'export', 'architecture'))
        key = module, export, 'function', architecture
        assert key not in identities and architecture in ('x86', 'x64')
        identities.add(key)
        assert not export.startswith(('#', 'ordinal_'))
        assert entry['reference_sources'] == contracts[key]
        assert entry['convention'] == 'stdcall' and 0 <= entry['argc'] <= 12
        assert type(entry['value']) is int and 0 <= entry['value'] <= 0xffffffff
        for ref in entry['reference_sources']:
            function, = [n for n in ast.walk(trees[ref['source']])
                         if isinstance(n, ast.FunctionDef) and n.lineno == ref['line']]
            assert function.end_lineno == ref['end_line']
            assert constant_result(function, entry['argc']) == entry['value']
            body = [n for n in function.body if not (isinstance(n, ast.Expr)
                    and isinstance(n.value, ast.Constant) and isinstance(n.value.value, str))]
            assert hashlib.sha256(ast.unparse(ast.Module(body=body, type_ignores=[])).encode()).hexdigest() == ref['body_sha256']
            matching = [d for d in function.decorator_list if isinstance(d, ast.Call)
                        and d.args and isinstance(d.args[0], ast.Constant) and d.args[0].value == ref['export']]
            decorator, = matching
            keywords = {k.arg: k.value for k in decorator.keywords}
            assert ast.literal_eval(keywords['argc']) == ref['argc'] == entry['argc']
        names = [export]
        assert module != 'ntdll', 'Review NTDLL kernel bridging separately'
        for suffix in ('A', 'W'):
            alias = export + suffix
            assert (module, alias) not in all_names
            instance = normalizer()
            instance.api = SimpleNamespace(get_export_func_handler=lambda dll, name:
                (dll, (export, entry['argc'], entry['value'])) if (dll, name) == (module, export) else (None, None))
            assert instance.normalize_import_miss(module, alias) == (module, (export, entry['argc'], entry['value']))
            names.append(alias)
        rows.append({**entry, 'call_names': names, 'oracle_value': entry['value']})
    assert len(rows) == 36, 'Review a changed local-constant denominator explicitly'
    return dict(contracts=rows, normalizer_sha256=normalizer_hash)
