"""Index native source validation and select affected safe suites conservatively."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import fnmatch
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import signal
import subprocess
import sys
import time

from native_pe_worklist import atomic_write, fingerprint, registration_dependencies


SUITES = ('partition', 'accounting', 'inventory', 'syntax', 'rust-tests', 'rust-lint', 'whitespace')
POLICY = 'docs/native-pe/validation-policy.json'
HEX_HASH = re.compile(r'^[0-9a-f]{64}$')


def local_path(root, relative):
    if (not isinstance(relative, str) or not relative or '\\' in relative or ':' in relative
            or PurePosixPath(relative).is_absolute() or '..' in PurePosixPath(relative).parts):
        raise ValueError(f'Expected a repository-relative path: {relative}')
    path = root / relative
    if not path.resolve().is_relative_to(root.resolve()):
        raise ValueError(f'Path escapes repository: {relative}')
    return path


def file_record(root, relative):
    path = local_path(root, relative)
    digest = hashlib.sha256()
    size = 0
    with path.open('rb') as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
    return {'path': relative, 'sha256': digest.hexdigest(), 'size': size}


def source_snapshot(root, paths=None):
    if paths is None:
        result = subprocess.run(['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard'],
                                cwd=root, capture_output=True, check=True)
        paths = set(os.fsdecode(name) for name in result.stdout.split(b'\0') if name)
        inventory = root / 'rust/api-parity/legacy-inventory.json'
        if inventory.is_file():
            paths.update(json.loads(inventory.read_text(encoding='utf-8-sig'))['sources'])
        paths.update(registration_dependencies(root))
    result = {}
    for relative in sorted(set(paths)):
        path = local_path(root, relative)
        result[relative] = file_record(root, relative)['sha256'] if path.is_file() else None
    return result


def environment_snapshot():
    versions = {}
    for name, command in (
        ('cargo', ['cargo', '--version']), ('rustc', ['rustc', '-Vv']),
        ('powershell', ['powershell', '-NoProfile', '-Command', '$PSVersionTable.PSVersion.ToString()']),
    ):
        result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=30)
        versions[name] = result.stdout.strip()
    return {'platform': platform.platform(), 'machine': platform.machine(),
            'python': sys.version, 'python_executable': sys.executable, 'tools': versions,
            'test_environment': {'RUST_TEST_THREADS': '1', 'CARGO_BUILD_JOBS': '1'},
            'build_environment_hashes': {
                name: hashlib.sha256(value.encode('utf-8')).hexdigest()
                for name, value in sorted(os.environ.items())
                if name.startswith(('CARGO_', 'RUST', 'CMAKE_', 'BINDGEN_', 'LIBCLANG', 'VSCMD_'))
                or name in ('PATH', 'PATHEXT', 'PSModulePath', 'PSMODULEPATH', 'CC', 'CXX', 'AR', 'INCLUDE', 'LIB', 'LIBPATH',
                            'CL', '_CL_', 'LINK', '_LINK_', 'MAKE', 'NINJA', 'CFLAGS', 'CXXFLAGS', 'LDFLAGS')}}


def load_policy(root):
    policy = json.loads(local_path(root, POLICY).read_text(encoding='utf-8-sig'))
    if (not isinstance(policy, dict) or policy.get('schema') != 1 or policy.get('suites') != list(SUITES)
            or policy.get('unknown_change') != 'all' or not isinstance(policy.get('rules'), list)
            or not policy.get('scope')):
        raise ValueError('Unknown validation policy or unsafe unknown-change fallback')
    for rule in policy['rules']:
        if (not isinstance(rule, dict) or not isinstance(rule.get('patterns'), list) or not rule['patterns']
                or not all(isinstance(item, str) and item for item in rule['patterns'])
                or not rule.get('reason') or (rule['suites'] != 'all'
                and (not rule['suites'] or not set(rule['suites']) <= set(SUITES)))):
            raise ValueError('Malformed validation impact rule')
    return policy


def affected_suites(changed, policy):
    selected = set()
    reasons = {}
    for relative in changed:
        rule = next((rule for rule in policy['rules']
                     if any(fnmatch.fnmatchcase(relative, pattern) for pattern in rule['patterns'])), None)
        suites = SUITES if rule is None or rule['suites'] == 'all' else rule['suites']
        selected.update(suites)
        reasons[relative] = rule['reason'] if rule else 'Unclassified dependency: full safe source validation'
    return [suite for suite in SUITES if suite in selected], reasons


def make_plan(current, environment, policy, baseline=None, full=False):
    previous = baseline['source_hashes'] if baseline else {}
    changed = [name for name in sorted(set(current) | set(previous)) if current.get(name) != previous.get(name)]
    selected, reasons = affected_suites(changed, policy)
    fallback = None
    if full:
        fallback = 'Explicit full validation'
    elif baseline is None:
        fallback = 'No verified baseline'
    elif not baseline.get('full_baseline'):
        fallback = 'Selected-only receipt is not a full baseline'
    elif baseline['policy_fingerprint'] != fingerprint(policy):
        fallback = 'Validation policy changed'
    elif baseline['environment'] != environment:
        fallback = 'Toolchain or execution environment changed'
    if fallback:
        selected = list(SUITES)
    return {'changed_sources': changed, 'selected_suites': selected, 'reasons': reasons,
            'fallback': fallback, 'baseline_fingerprint': baseline['index_fingerprint'] if baseline else None}


def suite_commands(root, python=None, sources=None):
    python = python or sys.executable
    syntax_paths = sorted({*(relative for relative in (sources if sources is not None else source_snapshot(root))
                            if fnmatch.fnmatchcase(relative, 'tools/native_pe_*.py')
                            or fnmatch.fnmatchcase(relative, 'tests/test_native_pe_*.py')),
                           'tools/native_api_parity_ledger.py', 'tools/inventory_native_api.py',
                           'tools/audit_native_surface.py', 'tests/test_native_api_inventory.py'})
    shell = ['powershell', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'tools/build_rust.ps1']
    return {
        'partition': [python, 'tools/native_pe_batches.py', '--check'],
        'accounting': [python, '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_native_pe_*.py', '-v'],
        'inventory': [python, '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_native_api_inventory.py', '-v'],
        'syntax': [python, '-m', 'py_compile', *syntax_paths],
        'rust-tests': [*shell, '-Test', '-Validation', '-Jobs', '1'],
        'rust-lint': [*shell, '-Lint', '-Jobs', '1'],
        'whitespace': ['git', 'diff', '--check'],
    }


def save_index(path, document):
    document['index_fingerprint'] = fingerprint({key: value for key, value in document.items() if key != 'index_fingerprint'})
    atomic_write(path, json.dumps(document, indent=2) + '\n')


def run_command(command, *, cwd, stdout, stderr, env, timeout):
    options = {'creationflags': subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == 'nt' else {'start_new_session': True}
    process = subprocess.Popen(command, cwd=cwd, stdout=stdout, stderr=stderr, env=env, **options)
    try:
        return subprocess.CompletedProcess(command, process.wait(timeout=timeout))
    except BaseException:
        try:
            if os.name == 'nt':
                subprocess.run(['taskkill', '/PID', str(process.pid), '/T', '/F'],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
            else:
                os.killpg(process.pid, signal.SIGKILL)
        finally:
            if process.poll() is None:
                process.kill()
            process.wait()
        raise


def verify_index(root, document, policy):
    if not isinstance(document, dict) or document.get('schema') != 1 or document.get('index_fingerprint') != fingerprint(
            {key: value for key, value in document.items() if key != 'index_fingerprint'}):
        raise ValueError('Invalid validation index schema/fingerprint')
    if not isinstance(document['source_hashes'], dict):
        raise ValueError('Malformed source snapshot')
    for relative, digest in document['source_hashes'].items():
        local_path(root, relative)
        if digest is not None and (not isinstance(digest, str) or not HEX_HASH.fullmatch(digest)):
            raise ValueError('Malformed source hash')
    if not document['source_hashes'] or document['source_fingerprint'] != fingerprint(document['source_hashes']):
        raise ValueError('Invalid source snapshot fingerprint')
    if document['status'] != 'passed' or not document['stable_sources']:
        raise ValueError('Validation failed, was interrupted, or sources changed while running')
    artifacts = {}
    for artifact in document['artifacts']:
        if artifact['path'] in artifacts or file_record(root, artifact['path']) != {key: artifact[key] for key in ('path', 'sha256', 'size')}:
            raise ValueError('Duplicate or changed validation artifact')
        artifacts[artifact['path']] = artifact
    selected = document['selection']['selected_suites']
    if (not selected or len(selected) != len(set(selected)) or not set(selected) <= set(policy['suites'])
            or [run['suite'] for run in document['runs']] != selected):
        raise ValueError('Incomplete or duplicate command receipts')
    commands = suite_commands(root, document['environment']['python_executable'], document['source_hashes'])
    for run in document['runs']:
        if (type(run['exit_code']) is not int or run['exit_code'] != 0
                or not isinstance(run['seconds'], (int, float)) or not 0 <= run['seconds'] < 86400
                or run['source_fingerprint'] != document['source_fingerprint']
                or run['log'] not in artifacts or artifacts[run['log']]['role'] != 'command-log'
                or run['command'] != commands[run['suite']]):
            raise ValueError('Invalid or unsuccessful command receipt')
    if document['full_baseline'] != (selected == list(SUITES)):
        raise ValueError('Selected-only receipt mislabeled as full baseline')
    return document


def execute_plan(root, output, selection, sources, environment, policy, timeout=600, artifacts=()):
    relative_output = output.resolve().relative_to(root.resolve()).as_posix()
    if not relative_output.startswith('output/') or output.exists():
        raise ValueError('Use a new directory inside repository output/; existing evidence is never overwritten')
    commands = suite_commands(root, sources=sources)
    references = [{**file_record(root, relative), 'role': 'reference-only'} for relative in artifacts]
    if not selection['selected_suites']:
        raise ValueError('No affected suites; nothing to execute')
    output.mkdir(parents=True)
    document = {'schema': 1, 'created_utc': datetime.now(timezone.utc).isoformat(),
                'scope': policy['scope'], 'source_hashes': sources, 'source_fingerprint': fingerprint(sources),
                'environment': environment, 'policy_fingerprint': fingerprint(policy), 'selection': selection,
                'runs': [], 'artifacts': references, 'stable_sources': False, 'status': 'running',
                'full_baseline': False}
    index_path = output / 'index.json'
    save_index(index_path, document)
    try:
        for suite in selection['selected_suites']:
            log_path = output / (suite + '.log')
            start = time.monotonic()
            exit_code = None
            try:
                with log_path.open('w', encoding='utf-8') as log:
                    result = run_command(commands[suite], cwd=root, stdout=log, stderr=subprocess.STDOUT,
                                         env={**os.environ, **environment['test_environment']}, timeout=timeout)
                    exit_code = result.returncode
            finally:
                relative_log = log_path.relative_to(root).as_posix()
                document['artifacts'].append({**file_record(root, relative_log), 'role': 'command-log'})
                document['runs'].append({'suite': suite, 'command': commands[suite], 'exit_code': exit_code,
                                         'seconds': round(time.monotonic() - start, 6), 'log': relative_log,
                                         'source_fingerprint': document['source_fingerprint']})
                save_index(index_path, document)
            if exit_code != 0:
                raise ValueError(f'Validation suite failed: {suite} (exit {exit_code})')
        document['stable_sources'] = sources == source_snapshot(root) and environment == environment_snapshot()
        if not document['stable_sources']:
            raise ValueError('Sources or execution environment changed during validation; evidence is not current')
        for artifact in document['artifacts']:
            if file_record(root, artifact['path']) != {key: artifact[key] for key in ('path', 'sha256', 'size')}:
                raise ValueError('Artifact changed during validation; evidence is not current')
        document['full_baseline'] = selection['selected_suites'] == list(SUITES)
        document['status'] = 'passed'
    except BaseException:
        document['status'] = 'failed-or-interrupted'
        raise
    finally:
        save_index(index_path, document)
    return document


def main():
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('plan', 'run', 'check'))
    parser.add_argument('--baseline', type=Path)
    parser.add_argument('--index', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--full', action='store_true')
    parser.add_argument('--details', action='store_true', help='Print all changed sources and selection reasons')
    parser.add_argument('--artifact', action='append', default=[], help='Repository-relative reference-only artifact; never imported as qualification')
    parser.add_argument('--timeout', type=int, default=600)
    args = parser.parse_args()
    try:
        if not 1 <= args.timeout <= 86400:
            raise ValueError('Timeout must be 1..86400 seconds per command')
        policy = load_policy(root)
        sources = source_snapshot(root)
        environment = environment_snapshot()
        if args.action == 'check':
            if args.index is None:
                raise ValueError('check requires --index')
            document = verify_index(root, json.loads(args.index.read_text(encoding='utf-8-sig')), policy)
            if (document['source_hashes'] != sources or document['environment'] != environment
                    or document['policy_fingerprint'] != fingerprint(policy)):
                raise ValueError('Validation index is stale for current sources, policy or environment')
            result = {'verified': True, 'full_baseline': document['full_baseline'], 'source_fingerprint': document['source_fingerprint'],
                      'timings': {run['suite']: run['seconds'] for run in document['runs']}}
        else:
            baseline = None
            if args.baseline and args.baseline.exists():
                baseline = verify_index(root, json.loads(args.baseline.read_text(encoding='utf-8-sig')), policy)
            selection = make_plan(sources, environment, policy, baseline, args.full)
            if args.action == 'plan':
                result = selection if args.details else {
                    'changed_source_count': len(selection['changed_sources']),
                    'selected_suites': selection['selected_suites'], 'fallback': selection['fallback'],
                    'changed_sources_preview': selection['changed_sources'][:20]}
            else:
                if args.output is None:
                    raise ValueError('run requires --output')
                document = execute_plan(root, args.output.resolve(), selection, sources, environment, policy,
                                        args.timeout, args.artifact)
                result = {'index': str(args.output / 'index.json'), 'status': document['status'],
                          'full_baseline': document['full_baseline'], 'source_fingerprint': document['source_fingerprint']}
        print(json.dumps(result, indent=2))
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as error:
        parser.error(str(error))


if __name__ == '__main__':
    main()
