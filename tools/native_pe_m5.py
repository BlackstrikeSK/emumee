"""Replay and independently check the M5 CRT/allocation/string controls contained.

This is a milestone receipt for the M5 obligations and their exit criterion, not
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
from native_pe_worklist import atomic_write, fingerprint

ROOT = Path(__file__).resolve().parents[1]


# One entry per emitted control family: the family label and its kinds.
_FAMILIES = {
    'crt-data': [f'{kind}-20000' for kind in ('Alias', 'Thread', 'Long', 'Parent',
                                              'Release', 'Protect', 'Free', 'Nx')] +
                [f'Alias-{budget}' for budget in (1, 10, 50, 100)],
    'win-alloc': ['Global', 'Local', 'Probe', 'RtlSize', 'ForeignFree',
                  'InteriorFree', 'OwnedFree', 'BadFlags'],
    'crt-runtime': ['Globals', 'Atexit', 'ExitImmediate', 'CleanExit', 'Terminate',
                    'UnbalancedUnlock', 'ExitReentrant', 'NewMode', 'ThreadLocale',
                    'AppType'],
    'crt-text': ['Text', 'Fold', 'Convert', 'Clock', 'BadLocale', 'NullString'],
    'win-text': ['Copy', 'Map', 'Message', 'BadType', 'BadFlags', 'MessageModule'],
    'crt-service': ['Format', 'Scan', 'Services', 'ThrowUnsupported',
                    'FloatUnsupported', 'ControlUnsupported'],
    'crt-file': ['Streams', 'Output', 'BadMode', 'BadClose', 'WriteOnlyRead'],
    'compiled': ['crt_program', 'crt_refusal'],
}


def required_cases():
    return {f'{arch}-m5-{family}-{case}'
            for arch in ('X86', 'X64')
            for family, kinds in _FAMILIES.items()
            for case in kinds}


def cases(root):
    selected = sorted(path for path in (root / 'fixtures-final').iterdir()
                      if path.is_dir() and '-m5-' in path.name)
    names = {path.name for path in selected}
    assert names == required_cases(), f'M5 control set differs: {sorted(names ^ required_cases())}'
    return selected


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
    output = root / 'm5'
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
        result = subprocess.run(command, capture_output=True, timeout=90)
        (output / f'{fixture.name}.stdout').write_bytes(result.stdout)
        (output / f'{fixture.name}.stderr').write_bytes(result.stderr)
        successful = expected['completion_reason'] in ('entry_return', 'process_exit')
        assert result.returncode == (0 if successful else 1), (fixture.name, result.returncode, result.stderr)
        records.append(verify(root, fixture, output_directory='m5'))
        print(f'{fixture.name} verified', flush=True)
    atomic_write(output / 'verification.json', json.dumps(records, indent=2) + '\n')


def seal(root, index, *, check=False):
    build_gate(root, index)
    selected = cases(root)
    records = [verify(root, fixture, output_directory='m5') for fixture in selected]
    assert records == json.loads((root / 'm5/verification.json').read_bytes())
    paths = set()
    for directory in (root / 'bundle', root / 'm5', index.parent, *selected):
        paths.update(path for path in directory.rglob('*') if path.is_file())
    artifacts = [dict(path=path.relative_to(ROOT).as_posix(), size=path.stat().st_size,
                      sha256=hashlib.sha256(path.read_bytes()).hexdigest()) for path in sorted(paths)]
    document = dict(schema=2, scope='M5 CRT/allocation/string source and contained replay, including the compiler-produced exit criterion; per-row semantic API parity and M10 remain open',
                    controls=records, artifacts=artifacts)
    document['fingerprint'] = fingerprint(document)
    destination = root / 'qualified-m5.json'
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
