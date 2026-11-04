"""Static native runner surface snapshot; never import or execute legacy code."""
import argparse
import ast
import hashlib
import json
from pathlib import Path


def audit_source(source):
    tree = ast.parse(source)
    runner = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                  and node.name == 'run_native')
    installs = []
    hooks = []
    reports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            name = node.func.attr
            if name == 'install':
                installs.append({'line': node.lineno, 'call': ast.unparse(node)})
            if name.startswith('add_') and name.endswith('_hook'):
                hooks.append({'line': node.lineno, 'call': ast.unparse(node)})
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if (isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name)
                        and target.value.id == 'report' and isinstance(target.slice, ast.Constant)
                        and isinstance(target.slice.value, str)):
                    reports.add(target.slice.value)
    returns = []
    for node in ast.walk(runner):
        if isinstance(node, ast.Return) and isinstance(node.value, ast.Dict):
            keys = [key.value for key in node.value.keys
                    if isinstance(key, ast.Constant) and isinstance(key.value, str)]
            if 'engine' in keys:
                returns.extend(keys)
    return {
        'runner_parameters': [argument.arg for argument in runner.args.args],
        'install_call_sites': sorted(installs, key=lambda row: row['line']),
        'hook_call_sites': sorted(hooks, key=lambda row: row['line']),
        'report_mutation_keys': sorted(reports), 'summary_keys': sorted(set(returns)),
        'effective_registration_review': 'unreviewed',
        'limitation': 'Lexical call sites include conditional/nested registrations; order is not runtime activation proof.',
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    paths = ['src/emumee/native.py', 'src/emumee/cli.py',
             'rust/emumee-core/src/user_input.rs', 'rust/emumee-engine/src/user.rs',
             'rust/emumee-cli/src/user_controller.rs', 'rust/emumee-worker/src/user_worker.rs']
    result = {'schema': 1, **audit_source((root / paths[0]).read_text(encoding='utf-8-sig')),
              'sources': {path: hashlib.sha256((root / path).read_bytes()).hexdigest() for path in paths}}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({name: len(result[name]) for name in
                      ('runner_parameters', 'install_call_sites', 'hook_call_sites', 'summary_keys')}))


if __name__ == '__main__':
    main()
