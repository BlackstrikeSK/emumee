"""Independently review frozen void placeholders and their return-register rule."""
from __future__ import annotations

import ast
import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

from native_pe_batches import inventory_contracts, variants
from native_pe_legacy_literals import normalizer_factory

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / 'rust/emumee-engine/src/api/legacy_voids.json'
RETURN_SOURCE = '.venv/Lib/site-packages/speakeasy/binemu.py'


def load(path):
    return json.loads(Path(path).read_bytes())


def return_observations():
    """Extract only two pinned CPU bookkeeping methods, with fake registers."""
    raw = (ROOT / RETURN_SOURCE).read_bytes()
    expected = load(ROOT / 'docs/native-pe/registration-policy.json')['reviewed_sources'][RETURN_SOURCE]
    assert hashlib.sha256(raw).hexdigest() == expected, 'Frozen call-return source changed'
    tree = ast.parse(raw)
    methods = []
    for name in ('do_call_return', 'clean_stack_args'):
        method, = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == name]
        methods.append(copy.deepcopy(method))
    cls = ast.ClassDef(name='ReturnOracle', bases=[], keywords=[], body=methods,
                      decorator_list=[], type_params=[])
    registers = SimpleNamespace(ARCH_X86=1, ARCH_AMD64=2, X86_REG_ESP='esp',
        X86_REG_EIP='eip', X86_REG_EAX='eax', AMD64_REG_RSP='rsp', AMD64_REG_RIP='rip',
        AMD64_REG_RAX='rax', X86_REG_XMM0='xmm0', CALL_CONV_FLOAT=3,
        CALL_CONV_CDECL=4, CALL_CONV_FASTCALL=5)
    namespace = dict(e_arch=registers, EmuException=RuntimeError)
    exec(compile(ast.fix_missing_locations(ast.Module(body=[cls], type_ignores=[])),
                 RETURN_SOURCE, 'exec'), namespace)
    results = []
    for arch, size, names in (('x86', 4, ('esp', 'eip', 'eax')),
                              ('x64', 8, ('rsp', 'rip', 'rax'))):
        for argc in (0, 1, 4):
            for seed in (0, 0x12345678, (1 << (size * 8)) - 1):
                for value in (None, 0, 1):
                    instance = namespace['ReturnOracle']()
                    state = dict(zip(names, (0x20000, 0x40000, seed)))
                    writes = []
                    def write(register, new):
                        assert register in state
                        state[register] = new
                        writes.append([register, new])
                    instance.get_arch = lambda: 1 if arch == 'x86' else 2
                    instance.get_ptr_size = lambda: size
                    instance.ptr_size = size
                    instance.reg_read = state.__getitem__
                    instance.reg_write = write
                    instance.do_call_return(argc, ret_addr=0x60000, ret_value=value, conv=0)
                    assert state[names[0]] == 0x20000 + size + (argc * size if arch == 'x86' else 0)
                    assert state[names[1]] == 0x60000
                    assert state[names[2]] == (seed if value is None else value)
                    assert (any(r == names[2] for r, _ in writes)) == (value is not None)
                    results.append(dict(architecture=arch, argc=argc, seed=seed, handler_return=value,
                                        registers=state, writes=writes))
    return dict(source=RETURN_SOURCE, sha256=expected, cases=results)


def review(manifest=None):
    manifest = manifest or load(MANIFEST)
    frozen = load(ROOT / 'rust/api-parity/legacy-inventory.json')
    assert manifest['schema'] == 1
    contracts = inventory_contracts(frozen)
    paths = {r['source'] for e in manifest['entries'] for r in e['reference_sources']}
    assert set(manifest['sources']) == paths
    trees = {}
    for path, digest in manifest['sources'].items():
        assert path in frozen['sources'] and digest == frozen['sources'][path], 'Unreviewed void source'
        raw = (ROOT / path).read_bytes()
        assert digest == frozen['sources'][path] == hashlib.sha256(raw).hexdigest()
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
        for ref in entry['reference_sources']:
            function, = [n for n in ast.walk(trees[ref['source']])
                         if isinstance(n, ast.FunctionDef) and n.lineno == ref['line']]
            assert function.end_lineno == ref['end_line']
            body = [n for n in function.body if not (isinstance(n, ast.Expr)
                    and isinstance(n.value, ast.Constant) and isinstance(n.value.value, str))]
            assert len(body) == 1 and isinstance(body[0], ast.Return)
            assert body[0].value is None or ast.literal_eval(body[0].value) is None
            assert ref['literal_return_only'] and ref['literal_result'] is None
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
                (dll, (export, entry['argc'])) if (dll, name) == (module, export) else (None, None))
            assert instance.normalize_import_miss(module, alias) == (module, (export, entry['argc']))
            names.append(alias)
        rows.append({**entry, 'call_names': names})
    assert len(rows) == 18, 'Review a changed void denominator explicitly'
    return dict(contracts=rows, normalizer_sha256=normalizer_hash, call_return=return_observations())
