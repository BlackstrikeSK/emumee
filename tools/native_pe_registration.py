"""Review effective legacy registration paths without importing legacy modules."""
from __future__ import annotations

import argparse
import ast
from collections import Counter
import copy
import fnmatch
import hashlib
import json
from pathlib import Path

from inventory_native_api import Inventory, Symbol, Unknown, bind, value
from native_pe_batches import inventory_contracts
from native_pe_validation import local_path
from native_pe_worklist import atomic_write, fingerprint, runtime_snapshot


POLICY = 'docs/native-pe/registration-policy.json'
SCOPE = ('Static effective registration review on successful run_native initialization; '
         'not constructor execution, guest reachability, API semantics or package qualification')


class RegistrationReturn(Exception):
    pass


def body_hash(node):
    return hashlib.sha256(ast.dump(node, include_attributes=False).encode()).hexdigest()


def callback_info(node, source, bound=False):
    arguments = [argument.arg for argument in node.args.posonlyargs + node.args.args]
    arguments = arguments[1:] if bound else arguments
    original = arguments[2] if len(arguments) >= 3 else None
    references = [part.lineno for part in ast.walk(node)
                  if isinstance(part, ast.Name) and part.id == original and isinstance(part.ctx, ast.Load)]
    calls = [part for part in ast.walk(node) if isinstance(part, ast.Call)]
    return {'id': f'{source}:{node.lineno}', 'source': source, 'line': node.lineno,
            'name': getattr(node, 'name', '<lambda>'), 'body_fingerprint': body_hash(node),
            'original_parameter': original, 'original_references': sorted(set(references)),
            'original_calls': [ast.unparse(call) for call in calls
                               if isinstance(call.func, ast.Name) and call.func.id == original],
            'original_forwarding': [ast.unparse(call) for call in calls
                                   if not (isinstance(call.func, ast.Name) and call.func.id == original)
                                   and any(isinstance(part, ast.Name) and part.id == original
                                           for argument in [*call.args, *(item.value for item in call.keywords)]
                                           for part in ast.walk(argument))],
            'original_guards': [ast.unparse(part.test) for part in ast.walk(node)
                                if isinstance(part, (ast.If, ast.IfExp))
                                and any(isinstance(item, ast.Name) and item.id == original
                                        for item in ast.walk(part.test))],
            'disposition': 'may_call_or_forward_baseline_original' if references else 'does_not_reference_original'}


def scoped_nodes(node):
    yield node
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
        return
    for child in ast.iter_child_nodes(node):
        yield from scoped_nodes(child)


def registration_call(node):
    return (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr in ('install', 'add_api_hook'))


def relevant(node):
    return any(registration_call(part) for part in scoped_nodes(node))


def resolve(node, environment):
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'range':
        bounds = [value(argument, environment) for argument in node.args]
        if len(range(*bounds)) > 4096:
            raise ValueError('Registration loop exceeds finite review bound')
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr == 'get_ptr_size' and not node.args:
            return environment['pointer_size']
    if isinstance(node, ast.Compare) and len(node.ops) == 1:
        left, right = resolve(node.left, environment), resolve(node.comparators[0], environment)
        if isinstance(left, Symbol) or isinstance(right, Symbol):
            raise Unknown('Unresolved registration comparison')
        if isinstance(node.ops[0], ast.Eq):
            return left == right
        if isinstance(node.ops[0], ast.NotEq):
            return left != right
        if isinstance(node.ops[0], ast.In):
            return left in right
        if isinstance(node.ops[0], ast.NotIn):
            return left not in right
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        operand = resolve(node.operand, environment)
        if isinstance(operand, Symbol):
            raise Unknown('Unresolved registration predicate')
        return not operand
    if isinstance(node, ast.BoolOp):
        items = [resolve(item, environment) for item in node.values]
        if any(isinstance(item, Symbol) for item in items):
            raise Unknown('Unresolved registration predicate')
        return all(items) if isinstance(node.op, ast.And) else any(items)
    result = value(node, environment)
    if isinstance(result, Symbol) and isinstance(node, ast.Attribute) and ast.unparse(node) in environment:
        return environment[ast.unparse(node)]
    return result


class Review:
    def __init__(self, root):
        self.root = root
        self.sources = {}
        self.trees = {}
        self.callbacks = {}
        self.installations = []

    def read(self, relative):
        path = local_path(self.root, relative)
        raw = path.read_bytes()
        self.sources[relative] = hashlib.sha256(raw).hexdigest()
        if relative not in self.trees:
            self.trees[relative] = ast.parse(raw.decode('utf-8-sig'), filename=relative)
        return self.trees[relative]

    def callback(self, expression, environment, functions, source, methods):
        if isinstance(expression, ast.Lambda):
            node, bound = expression, False
        else:
            symbol = resolve(expression, environment)
            if not isinstance(symbol, Symbol):
                raise ValueError('Non-symbol registration callback requires review')
            bound = symbol.name.startswith('self.')
            name = symbol.name.split('.', 1)[1] if bound else symbol.name
            node = (methods if bound else functions).get(name)
            if node is None:
                raise ValueError(f'Unresolved registration callback: {symbol.name}')
        information = callback_info(node, source, bound)
        self.callbacks[information['id']] = information
        return information['id']

    def walk(self, nodes, environment, source, functions, methods, hooks, install, phase='queued-before-load', guards=(), strict=False):
        for node in nodes:
            if isinstance(node, ast.FunctionDef):
                environment[node.name] = Symbol(node.name)
                if any(relevant(statement) for statement in node.body):
                    raise ValueError(f'Nested dynamic registration requires review: {source}:{node.lineno}')
                continue
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                try:
                    result = resolve(node.value, environment)
                    for target in node.targets if isinstance(node, ast.Assign) else [node.target]:
                        bind(target, result, environment)
                except (Unknown, TypeError, ValueError, KeyError, IndexError, AttributeError, OverflowError):
                    pass
                if isinstance(node.value, ast.Call) and ast.unparse(node.value.func) == 'se.load_module':
                    phase = 'active-after-load'
                continue
            barrier = strict and any(isinstance(part, (ast.Return, ast.Raise, ast.Break, ast.Continue)) for part in scoped_nodes(node))
            if not relevant(node) and not barrier:
                continue
            if isinstance(node, ast.For):
                sequence = resolve(node.iter, environment)
                if not isinstance(sequence, (list, tuple, range)) or len(sequence) > 4096:
                    raise ValueError('Unresolved or unbounded registration loop')
                for item in sequence:
                    bind(node.target, item, environment)
                    phase = self.walk(node.body, environment, source, functions, methods, hooks, install, phase, guards, strict)
                phase = self.walk(node.orelse, environment, source, functions, methods, hooks, install, phase, guards, strict)
            elif isinstance(node, ast.If):
                condition = resolve(node.test, environment)
                if type(condition) is not bool:
                    raise ValueError('Registration condition is not statically Boolean')
                phase = self.walk(node.body if condition else node.orelse, environment, source, functions,
                                  methods, hooks, install, phase, (*guards, {'test': ast.unparse(node.test), 'value': condition}), strict)
            elif isinstance(node, ast.Try):
                if any(relevant(item) for handler in node.handlers for item in handler.body):
                    raise ValueError('Exception-path registrations require explicit review')
                phase = self.walk(node.body + node.orelse + node.finalbody, environment, source,
                                  functions, methods, hooks, install, phase, guards, strict)
            elif isinstance(node, ast.Expr) and registration_call(node.value):
                call = node.value
                if call.func.attr == 'install':
                    instance = ast.unparse(call.func.value)
                    if instance not in install:
                        raise ValueError(f'Unknown installer: {instance}')
                    installer_source, class_node, constructor_call = install[instance]
                    class_methods = {part.name: part for part in class_node.body if isinstance(part, ast.FunctionDef)}
                    installer = class_methods.get('install')
                    if installer is None:
                        raise ValueError(f'Missing install method: {instance}')
                    self.installations.append({'instance': instance, 'class': class_node.name, 'source': installer_source,
                                               'line': installer.lineno, 'call_line': node.lineno,
                                               'constructor': constructor_info(class_methods.get('__init__'), installer_source),
                                               'constructor_call': constructor_call,
                                               'phase': phase, 'guards': list(guards)})
                    try:
                        self.walk(installer.body, dict(environment), installer_source, {}, class_methods,
                                  hooks, {}, phase, guards, True)
                    except RegistrationReturn:
                        pass
                else:
                    if len(call.args) != 3 or any(keyword.arg is None for keyword in call.keywords):
                        raise ValueError('Unreviewed hook argument shape')
                    module, export = (resolve(argument, environment) for argument in call.args[1:])
                    keywords = {keyword.arg: resolve(keyword.value, environment) for keyword in call.keywords}
                    if set(keywords) - {'argc', 'call_conv'} or not isinstance(module, str) or not isinstance(export, str):
                        raise ValueError('Unresolved hook identity or keyword')
                    hooks.append({'sequence': len(hooks), 'module': module.lower(), 'export': export.lower(),
                                  'declared_export': export, 'argc': keywords.get('argc', 0),
                                  'convention': keywords.get('call_conv'), 'source': source, 'line': node.lineno,
                                  'callback': self.callback(call.args[0], environment, functions, source, methods),
                                  'phase': phase, 'guards': list(guards)})
            elif isinstance(node, ast.Return):
                raise RegistrationReturn()
            else:
                raise ValueError(f'Unreviewed registration control flow: {source}:{node.lineno}')
        return phase

    def extensions(self, architecture):
        tree = self.read('src/emumee/native.py')
        runner = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'run_native')
        imports = {alias.asname or alias.name: (node.module, alias.name) for node in tree.body
                   if isinstance(node, ast.ImportFrom) and node.level == 1 for alias in node.names}
        installers = {}
        for statement in runner.body:
            for node in scoped_nodes(statement):
                if (isinstance(node, ast.Assign) and isinstance(node.value, ast.Call)
                        and isinstance(node.value.func, ast.Name) and node.value.func.id in imports):
                    module, class_name = imports[node.value.func.id]
                    relative = f'src/emumee/{module}.py'
                    classes = [part for part in self.read(relative).body if isinstance(part, ast.ClassDef) and part.name == class_name]
                    if classes:
                        for target in node.targets:
                            if isinstance(target, ast.Name):
                                installers[target.id] = (relative, classes[-1], ast.unparse(node.value))
        functions = {node.name: node for statement in runner.body for node in ast.walk(statement)
                     if isinstance(node, ast.FunctionDef)}
        environment = {name: Symbol(name) for name in functions}
        environment.update({'info.architecture': architecture, 'self.ptr_size': 8 if architecture == 'x64' else 4,
                            'pointer_size': 8 if architecture == 'x64' else 4})
        hooks = []
        self.walk(runner.body, environment, 'src/emumee/native.py', functions, {}, hooks, installers)
        return hooks


def constructor_info(node, source):
    if node is None:
        return {'source': source, 'disposition': 'inherits_base_constructor'}
    return {'source': source, 'line': node.lineno, 'body_fingerprint': body_hash(node),
            'arguments': [argument.arg for argument in node.args.posonlyargs + node.args.args],
            'state_assignments': [ast.unparse(part) for statement in node.body for part in scoped_nodes(statement)
                                  if isinstance(part, (ast.Assign, ast.AnnAssign))
                                  and any(isinstance(target, ast.Attribute) and ast.unparse(target.value) == 'self'
                                          for target in (part.targets if isinstance(part, ast.Assign) else [part.target]))],
            'guards': [ast.unparse(part.test) for part in ast.walk(node) if isinstance(part, ast.If)],
            'table_operations': [ast.unparse(part) for part in ast.walk(node)
                                 if isinstance(part, (ast.Assign, ast.AnnAssign, ast.Expr))
                                 and any(token in ast.unparse(part) for token in ('self.funcs', 'self.data', '__get_hook_attrs__'))],
            'disposition': 'source_reviewed_not_executed'}


def declaration_id(row):
    return f'{row["source"]}:{row["line"]}:{row["kind"]}:{row["export"]}'


def selected_decorator(node):
    decorators = {}
    for decorator in node.decorator_list:
        if not isinstance(decorator, ast.Call):
            raise ValueError('Unreviewed handler decorator')
        name = getattr(decorator.func, 'id', getattr(decorator.func, 'attr', None))
        if name not in ('apihook', 'impdata'):
            raise ValueError('Unreviewed handler decorator')
        decorators.setdefault(name, value(decorator.args[0], {}) if decorator.args else node.name)
    if 'apihook' in decorators:
        return 'function', decorators['apihook']
    return 'data', decorators.get('impdata')


def baseline_tables(review, inventory):
    tables = {}
    declarations = []
    constructors = []
    for source in sorted({row['source'] for row in inventory['entries'] if row['origin'] == 'speakeasy_baseline'}):
        tree = review.read(source)
        for class_node in (part for part in tree.body if isinstance(part, ast.ClassDef)):
            methods = {part.name: part for part in class_node.body if isinstance(part, ast.FunctionDef)}
            matching = [row for row in inventory['entries'] if row['source'] == source
                        and any(isinstance(part, ast.FunctionDef) and part.lineno == row['line'] for part in class_node.body)]
            if not matching:
                continue
            if [ast.unparse(base) for base in class_node.bases] != ['api.ApiHandler']:
                raise ValueError('Unreviewed baseline handler inheritance')
            modules = {row['module'] for row in matching}
            if len(modules) != 1 or next(iter(modules)) in tables:
                raise ValueError('Ambiguous baseline autoload module identity')
            module = next(iter(modules))
            table = {'function': {}, 'data': {}}
            tables[module] = table
            constructors.append(dict(module=module, **constructor_info(methods.get('__init__'), source)))
            for row in matching:
                node = next(part for part in class_node.body if isinstance(part, ast.FunctionDef) and part.lineno == row['line'])
                selected_kind, selected_export = selected_decorator(node)
                state = ('python_method_shadowed' if methods[node.name] is not node else
                         'decorator_metadata_shadowed' if (row['kind'], row['export']) != (selected_kind, selected_export)
                         else 'registered')
                declarations.append({'id': declaration_id(row), 'module': module, 'export': row['export'],
                                     'kind': row['kind'], 'method': node.name,
                                     'disposition': state})
            for method_name, node in sorted(methods.items()):
                candidates = [row for row in matching if row['line'] == node.lineno]
                selected_kind, selected_export = selected_decorator(node) if candidates else (None, None)
                row = next((row for row in candidates if (row['kind'], row['export']) == (selected_kind, selected_export)), None)
                if row is not None:
                    handler = {**row, 'id': declaration_id(row), 'method': method_name}
                    table[row['kind']][row['export']] = handler
                    if row.get('ordinal'):
                        table[row['kind']][f'ordinal_{row["ordinal"]}'] = handler
            for row in declarations:
                if row['module'] == module and row['disposition'] == 'registered':
                    selected = table[row['kind']].get(row['export'])
                    if selected['id'] != row['id']:
                        row['disposition'] = 'export_slot_overwritten_in_dir_order'
    return tables, declarations, constructors


def normalized_module(module):
    lower = module.lower()
    if lower.startswith(('api-ms-win-crt', 'vcruntime', 'ucrtbased', 'ucrtbase', 'msvcr', 'msvcp')):
        return 'msvcrt'
    if lower.startswith(('winsock', 'wsock32')):
        return 'ws2_32'
    if lower.startswith('api-ms-win-core'):
        return 'kernel32'
    return module


def baseline_handler(tables, module, export):
    def lookup(target_module, target_export):
        return tables.get(target_module.lower(), {}).get('function', {}).get(target_export)
    export = 'ordinal_' + export[1:] if export.startswith('#') else export
    direct = lookup(module, export)
    if direct:
        return direct, 'exact'
    alternate = export[:-1] if export.endswith(('A', 'W')) else ''
    folded = normalized_module(module)
    if module.lower().startswith('ntdll'):
        direct = lookup('ntoskrnl', export)
        if direct:
            return direct, 'ntdll_kernel_fallback'
        if export.startswith('Zw'):
            alternate = 'Nt' + export[2:]
        elif export.startswith('Nt'):
            alternate = 'Zw' + export[2:]
        return lookup('ntoskrnl', alternate), 'ntdll_kernel_fallback'
    for target_module, target_export in ((module, alternate), (folded, export), (folded, alternate)):
        handler = lookup(target_module, target_export) if target_export else None
        if handler:
            return handler, 'normalized_import_miss'
    return None, 'no_baseline_handler'


def matching_hooks(hooks, module, export):
    buckets = {}
    for hook in hooks:
        buckets.setdefault(hook['module'], {}).setdefault(hook['export'], []).append(hook)
    module, export = module.lower(), export.lower()
    modules = ([module] if module in buckets else []) + [name for name in buckets if name != module and fnmatch.fnmatchcase(module, name)]
    result = []
    for name in modules:
        functions = buckets[name]
        exports = ([export] if export in functions else []) + [name for name in functions if name != export and fnmatch.fnmatchcase(export, name)]
        for name in exports:
            result.extend(functions[name])
    return result


def disposition(tables, hooks, key):
    module, export, kind, architecture = key
    row = dict(module=module, export=export, kind=kind, architecture=architecture)
    if kind == 'data':
        handler = tables.get(module.lower(), {}).get('data', {}).get(export)
        return dict(row, disposition='registered_data_handler' if handler else 'no_data_handler',
                    baseline=handler['id'] if handler else None, hooks=[], invoked_hooks=[])
    handler, resolution = baseline_handler(tables, module, export)
    requested = 'ordinal_' + export[1:] if export.startswith('#') else export
    lookup_export = handler['export'] if handler and requested.startswith('ordinal_') else requested
    chain = matching_hooks(hooks, module, lookup_export)
    invoked = chain if handler else chain[-1:]
    return dict(row, disposition='baseline_with_hooks' if handler and chain else 'baseline_only' if handler
                else 'last_hook_only' if chain else 'no_registered_handler_or_hook',
                resolution=resolution, baseline=handler['id'] if handler else None,
                baseline_module=handler['module'] if handler else None,
                baseline_literal_return_only=handler.get('literal_return_only') if handler else None,
                baseline_literal_result=handler.get('literal_result') if handler else None,
                hook_lookup_export=lookup_export, hooks=[hook['sequence'] for hook in chain],
                invoked_hooks=[hook['sequence'] for hook in invoked],
                return_hook=chain[-1]['sequence'] if chain else None,
                original_target=handler['id'] if handler and chain else None,
                argc=handler['argc'] if handler else chain[-1]['argc'] if chain else None,
                convention=handler['convention'] if handler else (chain[-1]['convention'] or 'stdcall') if chain else None)


def collect(root):
    initial = runtime_snapshot(root)
    policy = json.loads(local_path(root, POLICY).read_text(encoding='utf-8-sig'))
    inventory = json.loads((root / 'rust/api-parity/legacy-inventory.json').read_text(encoding='utf-8-sig'))
    if policy.get('schema') != 1 or policy.get('inventory_fingerprint') != fingerprint(inventory) or inventory.get('unresolved'):
        raise ValueError('Registration policy/inventory drift requires explicit review')
    review = Review(root)
    expected_sources = {**inventory['sources'], **policy['reviewed_sources']}
    for relative, expected in expected_sources.items():
        review.read(relative)
        if review.sources[relative] != expected:
            raise ValueError(f'Reviewed registration source drift: {relative}')
    tables, declarations, constructors = baseline_tables(review, inventory)
    kernel_inventory = Inventory(root)
    kernel_inventory.speakeasy(local_path(root, policy['kernel_normalization_source']))
    if kernel_inventory.unresolved:
        raise ValueError('Unresolved kernel normalization declarations require review')
    kernel_tables, _, _ = baseline_tables(review, {'entries': kernel_inventory.entries})
    tables.update(kernel_tables)
    module_load_tables = copy.deepcopy(tables)
    runner_tree = review.read('src/emumee/native.py')
    patches = [node for node in ast.walk(runner_tree) if isinstance(node, ast.Assign)
               and any(isinstance(target, ast.Subscript) and isinstance(target.value, ast.Attribute)
                       and target.value.attr == 'funcs' for target in node.targets)]
    if len(patches) != 1 or ast.unparse(patches[0]) != policy['conditional_table_patch']:
        raise ValueError('Unreviewed dynamic API-table mutation')
    patch_node = patches[0]
    fallback = {'id': f'src/emumee/native.py:{patch_node.lineno}', 'module': 'ntdll', 'export': 'LdrUnloadDll',
                'argc': 1, 'convention': 'stdcall', 'literal_return_only': True, 'literal_result': 0xC00000BB}
    applied = 'LdrUnloadDll' not in tables.get('ntdll', {}).get('function', {})
    if applied:
        tables['ntdll']['function']['LdrUnloadDll'] = fallback
    architectures = {}
    for architecture in ('x86', 'x64'):
        review.installations = []
        hooks = review.extensions(architecture)
        architectures[architecture] = {'installations': review.installations, 'hooks': hooks}
    extension_sites = {(row['source'], row['line'], row['module'].lower(), row['export'].lower())
                       for row in inventory['entries'] if row['origin'] == 'emumee_extension'}
    for result in architectures.values():
        observed = {(row['source'], row['line'], row['module'], row['declared_export'].lower()) for row in result['hooks']}
        if observed != extension_sites or len(result['hooks']) != sum(row['origin'] == 'emumee_extension' for row in inventory['entries']):
            raise ValueError('Effective hook activation does not exactly cover frozen extension declarations')
    contracts = []
    module_load_contracts = []
    for key, members in inventory_contracts(inventory).items():
        row = disposition(tables, architectures[key[3]]['hooks'], key)
        row['declaration_ids'] = sorted({declaration_id(member) for member in members})
        row['reference_exports'] = sorted({member['export'] for member in members})
        contracts.append(row)
        module_load_contracts.append(disposition(module_load_tables, [hook for hook in architectures[key[3]]['hooks']
                                                if hook['phase'] == 'queued-before-load'], key))
    if set(review.sources) - set(expected_sources):
        raise ValueError('Additional registration dependency requires source review')
    if review.sources != expected_sources:
        raise ValueError('Reviewed source hashes changed after parsing')
    for relative, expected in expected_sources.items():
        if hashlib.sha256(local_path(root, relative).read_bytes()).hexdigest() != expected:
            raise ValueError(f'Reviewed source changed during collection: {relative}')
    if runtime_snapshot(root) != initial:
        raise ValueError('Source changed during effective registration review')
    payload = {'inventory_fingerprint': fingerprint(inventory), 'policy_fingerprint': fingerprint(policy),
               'source_hashes': review.sources, 'runtime_source_hashes': initial,
               'baseline_declarations': declarations, 'baseline_constructors': constructors,
               'conditional_table_patch': {'source': 'src/emumee/native.py', 'line': patch_node.lineno,
                                           'guard': 'ntdll is not None and LdrUnloadDll absent',
                                           'phase': 'active-after-load', 'applied': applied, 'handler': fallback},
               'architectures': architectures, 'callbacks': review.callbacks, 'contracts': contracts,
               'module_load_contracts': module_load_contracts,
               'phase_scope': 'Queued hooks are flushed by lazy engine initialization; module_load_contracts precede the post-load table patch and 21 later hooks. Exceptions expose only the completed prefix, never the final map.',
               'native_bridges': [row for row in contracts if row['module'] in ('mscoree', 'msi32')],
               'counts': dict(Counter(row['disposition'] for row in contracts))}
    return {'schema': 1, 'scope': SCOPE, 'review_complete': True, 'payload': payload, 'review_fingerprint': fingerprint(payload)}


def verify_report(previous, current):
    if (not isinstance(previous, dict) or previous.get('schema') != 1 or previous.get('scope') != SCOPE
            or previous.get('review_complete') is not True
            or previous.get('review_fingerprint') != fingerprint(previous.get('payload'))
            or previous['review_fingerprint'] != current['review_fingerprint']):
        raise ValueError('Effective registration report is corrupt or stale')


def main():
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('audit', 'check'))
    parser.add_argument('--output', type=Path)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    try:
        if args.action == 'audit' and (args.output is None or args.output.exists()
                or not args.output.resolve().is_relative_to((root / 'output').resolve())):
            raise ValueError('audit requires a new --output inside repository output/')
        if args.action == 'check' and args.report is None:
            raise ValueError('check requires --report')
        report = collect(root)
        if args.action == 'audit':
            atomic_write(args.output, json.dumps(report, indent=2) + '\n')
        else:
            verify_report(json.loads(args.report.read_text(encoding='utf-8-sig')), report)
        print(json.dumps({'review_complete': True, 'contracts': len(report['payload']['contracts']),
                          'counts': report['payload']['counts'], 'review_fingerprint': report['review_fingerprint']}, indent=2))
    except (ValueError, KeyError, TypeError, OSError, Unknown, StopIteration) as error:
        parser.error(str(error))


if __name__ == '__main__':
    main()
