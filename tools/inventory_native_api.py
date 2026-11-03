"""Read-only AST inventory of legacy API handlers and native extension hooks.

No legacy module is imported and no guest code is executed. Unresolved dynamic
registrations remain explicit inventory gaps, never inferred coverage.
"""
from __future__ import annotations
import argparse
import ast
import hashlib
import json
from pathlib import Path


class Unknown(Exception):
    pass


class Symbol:
    def __init__(self, name):
        self.name = name


def value(node, env):
    if node is None:
        raise Unknown('dynamic dictionary expansion')
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name) and node.id in env:
        return env[node.id]
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        return [value(item, env) for item in node.elts]
    if isinstance(node, ast.Dict):
        return {value(k, env): value(v, env) for k, v in zip(node.keys, node.values)}
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return value(node.left, env) + value(node.right, env)
    if isinstance(node, ast.JoinedStr):
        return ''.join(str(value(item.value, env)) if isinstance(item, ast.FormattedValue) else str(item.value) for item in node.values)
    if isinstance(node, ast.Subscript):
        return value(node.value, env)[value(node.slice, env)]
    if isinstance(node, ast.Attribute):
        key = ast.unparse(node)
        if key in env:
            return env[key]
        if node.attr == 'CALL_CONV_CDECL':
            return 'cdecl'
        if node.attr == 'CALL_CONV_STDCALL':
            return 'stdcall'
        if node.attr == 'CALL_CONV_FASTCALL':
            return 'fastcall'
        if node.attr == 'CALL_CONV_FLOAT':
            return 'float'
        if node.attr == 'VAR_ARGS':
            return 'variadic'
        if isinstance(node.value, ast.Name) and node.value.id == 'self':
            return Symbol(key)
    if isinstance(node, ast.Lambda):
        return Symbol('lambda')
    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name) and node.func.id in ('tuple', 'list', 'sorted', 'enumerate', 'range', 'str', 'int'):
            functions = {'tuple': tuple, 'list': list, 'sorted': sorted, 'enumerate': lambda x: list(enumerate(x)), 'range': lambda *a: list(range(*a)), 'str': str, 'int': int}
            return functions[node.func.id](*(value(a, env) for a in node.args))
        if isinstance(node.func, ast.Attribute) and node.func.attr in ('items', 'keys', 'values'):
            return list(getattr(value(node.func.value, env), node.func.attr)())
    raise Unknown(ast.unparse(node))


def bind(target, item, env):
    if isinstance(target, ast.Name):
        env[target.id] = item
    elif isinstance(target, ast.Attribute):
        env[ast.unparse(target)] = item
    elif isinstance(target, (ast.Tuple, ast.List)):
        for name, part in zip(target.elts, item):
            bind(name, part, env)


class Inventory:
    def __init__(self, root):
        self.root = root
        self.entries = []
        self.unresolved = []
        self.sources = {}

    def source(self, path):
        raw = path.read_bytes()
        name = path.relative_to(self.root).as_posix()
        self.sources[name] = hashlib.sha256(raw).hexdigest()
        return name, ast.parse(raw.decode('utf-8-sig'), filename=name)

    def extension(self, path):
        name, tree = self.source(path)
        self.walk(tree.body, {}, name)

    def walk(self, nodes, env, source):
        for node in nodes:
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                if node.value is not None:
                    try:
                        item = value(node.value, env)
                        for target in node.targets if isinstance(node, ast.Assign) else [node.target]:
                            bind(target, item, env)
                    except (Unknown, TypeError, ValueError, KeyError, IndexError, AttributeError, OverflowError):
                        pass
            elif isinstance(node, ast.For):
                try:
                    sequence = value(node.iter, env)
                    if len(sequence) > 4096:
                        raise Unknown('loop bound')
                except (Unknown, TypeError, ValueError, KeyError, IndexError, AttributeError, OverflowError):
                    self.walk(node.body, dict(env), source)
                else:
                    for item in sequence:
                        local = dict(env)
                        bind(node.target, item, local)
                        self.walk(node.body, local, source)
                self.walk(node.orelse, dict(env), source)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                env[node.name] = Symbol(node.name)
                local = dict(env)
                self.walk(node.body, local, source)
            elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                call = node.value
                if isinstance(call.func, ast.Attribute) and call.func.attr == 'add_api_hook':
                    try:
                        module = value(call.args[1], env)
                        export = value(call.args[2], env)
                        keywords = {k.arg: k.value for k in call.keywords}
                        argc = value(keywords['argc'], env) if 'argc' in keywords else None
                        convention = value(keywords['call_conv'], env) if 'call_conv' in keywords else None
                        if not isinstance(module, str) or not isinstance(export, str):
                            raise Unknown('non-string registration')
                        self.entries.append({'module': module, 'export': export, 'kind': 'function', 'argc': argc, 'convention': convention, 'source': source, 'line': node.lineno, 'origin': 'emumee_extension'})
                    except (Unknown, TypeError, ValueError, KeyError, IndexError, AttributeError, OverflowError) as error:
                        self.unresolved.append({'source': source, 'line': node.lineno, 'call': ast.unparse(call), 'reason': str(error)})
            else:
                # Both branches are potential registrations; admission conditions
                # are retained in the source rather than assumed universally true.
                for field in ('body', 'orelse', 'finalbody'):
                    body = getattr(node, field, None)
                    if isinstance(body, list):
                        self.walk(body, dict(env), source)
                for handler in getattr(node, 'handlers', []):
                    self.walk(handler.body, dict(env), source)

    def speakeasy(self, path):
        source, tree = self.source(path)
        for cls in (n for n in tree.body if isinstance(n, ast.ClassDef)):
            module = path.stem
            for statement in cls.body:
                if isinstance(statement, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'name' for t in statement.targets):
                    try:
                        module = value(statement.value, {})
                    except Unknown:
                        pass
            for function in (n for n in cls.body if isinstance(n, ast.FunctionDef)):
                for decorator in function.decorator_list:
                    if not isinstance(decorator, ast.Call):
                        continue
                    decorator_name = ast.unparse(decorator.func).split('.')[-1]
                    if decorator_name not in ('apihook', 'impdata'):
                        continue
                    keywords = {k.arg: k.value for k in decorator.keywords}
                    try:
                        export = value(decorator.args[0], {}) if decorator.args else function.name
                        argc = value(keywords['argc'], {}) if 'argc' in keywords else 0
                        convention = value(keywords['conv'], {}) if 'conv' in keywords else 'stdcall'
                        ordinal = value(keywords['ordinal'], {}) if 'ordinal' in keywords else None
                    except Unknown as error:
                        self.unresolved.append({'source': source, 'line': decorator.lineno, 'call': ast.unparse(decorator), 'reason': str(error)})
                        continue
                    body = ast.Module(body=[n for n in function.body if not (isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant) and isinstance(n.value.value, str))], type_ignores=[])
                    body_text = ast.unparse(body)
                    literal = None
                    literal_valid = False
                    if len(body.body) == 1 and isinstance(body.body[0], (ast.Return, ast.Pass)):
                        expression = getattr(body.body[0], 'value', None)
                        if expression is None:
                            literal_valid = True
                        else:
                            try:
                                literal = ast.literal_eval(expression)
                                literal_valid = literal is None or isinstance(literal, (bool, int))
                            except (ValueError, TypeError):
                                pass
                    self.entries.append({'module': module, 'export': export, 'kind': 'data' if decorator_name == 'impdata' else 'function', 'argc': argc, 'convention': convention, 'ordinal': ordinal, 'source': source, 'line': function.lineno, 'end_line': function.end_lineno, 'body_sha256': hashlib.sha256(body_text.encode()).hexdigest(), 'literal_return_only': literal_valid, 'literal_result': literal if literal_valid else None, 'origin': 'speakeasy_baseline', 'character_width_dispatch': 'get_char_width(' in body_text})


def native_closure(root):
    files, pending = set(), ['native']
    while pending:
        module = pending.pop()
        path = root / 'src/emumee' / (module + '.py')
        if not path.is_file() or path in files:
            continue
        files.add(path)
        tree = ast.parse(path.read_text(encoding='utf-8-sig'))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.level == 1 and node.module:
                pending.append(node.module)
    return sorted(files)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--refresh-baseline', action='store_true', help='Deliberately replace a changed frozen baseline after reviewing its source changes.')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    inventory = Inventory(root)
    for path in sorted((root / '.venv/Lib/site-packages/speakeasy/winenv/api/usermode').glob('*.py')):
        inventory.speakeasy(path)
    for path in native_closure(root):
        inventory.extension(path)
    unique = {(r['source'], r['line'], r['call']): r for r in inventory.unresolved}
    unresolved = sorted(unique.values(), key=lambda r: (r['source'], r['line']))
    inventory.entries.sort(key=lambda r: (r['module'], str(r['export']), r['origin'], r['line']))
    result = {'schema': 1, 'scope': 'Installed Speakeasy user-mode handlers plus the static native.py import closure. Conditional/unresolved registrations require review; this inventory is not a parity claim.', 'entries': inventory.entries, 'unresolved': unresolved, 'sources': inventory.sources}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps(result, indent=2) + '\n'
    if args.output.exists() and args.output.read_text(encoding='utf-8-sig') != content and not args.refresh_baseline:
        parser.error('Frozen inventory differs from the current legacy sources; review the changes before --refresh-baseline.')
    args.output.write_text(content, encoding='utf-8')
    queries = set()
    for entry in inventory.entries:
        name = entry['export']
        if not isinstance(name, str) or entry['kind'] != 'function':
            continue
        variants = [name]
        if name.endswith('*'):
            variants = [name[:-1]+'A', name[:-1]+'W']
        elif entry.get('character_width_dispatch'):
            # The generic handler itself throws without an A/W suffix; only its
            # character-width variants are successful legacy entrypoints.
            variants = [name+'A', name+'W']
        if entry.get('ordinal'):
            variants.append('#'+str(entry['ordinal']))
        for name in variants:
            queries.add((entry['module'], name))
    args.output.with_name('queries.json').write_text(json.dumps([{'module':m,'export':n} for m,n in sorted(queries)], indent=2)+'\n', encoding='utf-8')
    counts = {}
    for entry in inventory.entries:
        counts[entry['origin']] = counts.get(entry['origin'], 0) + 1
    print(json.dumps({'entries': counts, 'unresolved_sites': len(unresolved), 'source_files': len(inventory.sources)}))


if __name__ == '__main__':
    main()
