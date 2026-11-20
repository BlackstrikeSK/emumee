"""Replay and independently check the M6 registry/persona/filesystem controls contained.

This is a milestone receipt for the M6 obligations and their exit criterion, not
API semantic parity for any partition row and not M10 qualification. It uses the
existing M4 verifier for request/result/input, ABI effects and cleanup.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from native_pe_m4 import source_gate, verify
from native_pe_staging_seal import binding
from native_pe_worklist import atomic_write, fingerprint

ROOT = Path(__file__).resolve().parents[1]

# Every family whose controls select narrow or wide exports emits both widths.
_WIDTH_FAMILIES = {
    'registry': ['DeleteValue', 'EnumKey', 'KeyInfo', 'ServiceHandler', 'DeleteDenied'],
    'version': ['Identity', 'Condition', 'Verify', 'BadArguments'],
    'locale': ['Defaults', 'Validity', 'Session', 'Firmware'],
    'file': ['Size', 'Times', 'Information', 'Legacy', 'Denied'],
    'path': ['ShortPath', 'FindExStandard', 'FindExBasic', 'TempName', 'BinaryType',
             'ShortNameUnsupported', 'SearchLevelUnsupported'],
    'volume': ['Identity', 'Space', 'Enumerate', 'MountPaths', 'DosDevice', 'Redirection'],
    'console': ['Title', 'Window', 'Handlers', 'History'],
}
# These two families have no A/W selection: the forced section unmap is one
# ntdll contract, and the compiled programs are whole programs.
_PLAIN_FAMILIES = {
    'unmap': ['SelfImage', 'NotMapped', 'Hollow'],
    'observation': ['ImageWrite', 'WrittenCode'],
    'compiled': ['m6_program', 'm6_refusal'],
}


def required_cases():
    names = {f'{arch}-m6-{family}-{case}{width}'
             for arch in ('X86', 'X64')
             for family, cases in _WIDTH_FAMILIES.items()
             for case in cases
             for width in ('A', 'W')}
    names.update(f'{arch}-m6-{family}-{case}'
                 for arch in ('X86', 'X64')
                 for family, cases in _PLAIN_FAMILIES.items()
                 for case in cases)
    return names


def cases(root):
    selected = sorted(path for path in (root / 'fixtures-final').iterdir()
                      if path.is_dir() and '-m6-' in path.name)
    names = {path.name for path in selected}
    assert names == required_cases(), f'M6 control set differs: {sorted(names ^ required_cases())}'
    return selected


# The shared M4 projection does not cover the observation families M6 owns, so
# the replay compares them itself: every contained run must report the same
# forced section unmaps, image writes, console session and search state as the
# source-tested execution it replays.
_OBSERVED = ('forced_unmaps', 'image_writes', 'console_session', 'file_enumeration',
             'user_processes', 'loaded_modules')


def observations(root, fixture, *, output_directory='m6'):
    run = root / output_directory / fixture.name
    source, = [p for p in fixture.iterdir() if p.suffix.lower() in ('.exe', '.dll')]
    execution = binding(run, source)['result']['execution']
    expected = json.loads((fixture / 'source-execution.json').read_bytes())
    for field in _OBSERVED:
        assert execution.get(field) == expected.get(field), (fixture.name, field)
    return {field: execution.get(field) for field in ('forced_unmaps', 'image_writes')}


def build_gate(root, index):
    source_gate(root, index)
    bundle = root / 'bundle'
    receipt = json.loads((bundle / 'rust-worker-build.json').read_bytes())
    for name, field, option in [('emumee-rs.exe', 'controller_sha256', 'build-info'),
                                ('emumee-worker.exe', 'worker_sha256', '--build-info'),
                                ('unicorn.dll', 'unicorn_sha256', None)]:
        assert hashlib.sha256((bundle / name).read_bytes()).hexdigest() == receipt[field]
        if option:
            result = subprocess.run([str(bundle / name), option], capture_output=True,
                                    check=True, timeout=30)
            assert json.loads(result.stdout)['source_tree_sha256'] == receipt['source_tree_sha256']


def run(root, index):
    build_gate(root, index)
    selected = cases(root)
    output = root / 'm6'
    output.mkdir()  # Preserve existing successful and failed runs.
    executable = root / 'bundle/emumee-rs.exe'
    records = []
    for fixture in selected:
        limits = json.loads((fixture / 'limits.json').read_bytes())
        expected = json.loads((fixture / 'source-execution.json').read_bytes())
        source, = [p for p in fixture.iterdir() if p.suffix.lower() in ('.exe', '.dll')]
        command = [str(executable), 'run', str(source), '--output', str(output / fixture.name),
                   '--inputs', str(fixture / 'inputs.json'),
                   '--max-instructions', str(limits['max_instructions']),
                   '--timeout-us', str(limits['timeout_us']), '--',
                   *json.loads((fixture / 'arguments.json').read_bytes())]
        result = subprocess.run(command, capture_output=True, timeout=120)
        (output / f'{fixture.name}.stdout').write_bytes(result.stdout)
        (output / f'{fixture.name}.stderr').write_bytes(result.stderr)
        successful = expected['completion_reason'] in ('entry_return', 'process_exit')
        assert result.returncode == (0 if successful else 1), (fixture.name, result.returncode, result.stderr)
        record = verify(root, fixture, output_directory='m6')
        observations(root, fixture)
        records.append(record)
        print(f'{fixture.name} verified', flush=True)
    atomic_write(output / 'verification.json', json.dumps(records, indent=2) + '\n')


def seal(root, index, *, check=False):
    build_gate(root, index)
    selected = cases(root)
    records = [verify(root, fixture, output_directory='m6') for fixture in selected]
    for fixture in selected:
        observations(root, fixture)
    assert records == json.loads((root / 'm6/verification.json').read_bytes())
    paths = set()
    for directory in (root / 'bundle', root / 'm6', index.parent, *selected):
        paths.update(path for path in directory.rglob('*') if path.is_file())
    artifacts = [dict(path=path.relative_to(ROOT).as_posix(), size=path.stat().st_size,
                      sha256=hashlib.sha256(path.read_bytes()).hexdigest()) for path in sorted(paths)]
    document = dict(schema=2, scope='M6 registry/persona/filesystem source and contained replay, including the compiler-produced exit criterion; per-row semantic API parity and M10 remain open',
                    controls=records, artifacts=artifacts)
    document['fingerprint'] = fingerprint(document)
    destination = root / 'qualified-m6.json'
    if check:
        assert json.loads(destination.read_bytes()) == document
    else:
        assert not destination.exists(), 'Preserve sealed evidence'
        atomic_write(destination, json.dumps(document, indent=2) + '\n')
    print(json.dumps(dict(controls=len(records), files=len(artifacts), fingerprint=document['fingerprint'])))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--source-index', type=Path, required=True)
    action = parser.add_mutually_exclusive_group()
    action.add_argument('--seal', action='store_true')
    action.add_argument('--check', action='store_true')
    args = parser.parse_args()
    root, index = args.root.resolve(), args.source_index.resolve()
    if args.seal or args.check:
        seal(root, index, check=args.check)
    else:
        run(root, index)
