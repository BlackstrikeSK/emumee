"""Replay and independently check the M8 submitted-sample capture controls contained.

This is a milestone receipt for the M8 capture obligations (N14 memory-string
indicators and N15 executable-region/dropped-PE carving), not API semantic
parity for any partition row and not M10 qualification. It uses the existing M4
verifier for request/result/input, ABI effects and cleanup, and additionally
compares every capture report these controls own between the source-tested
execution and its contained replay.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from native_pe_m4 import verify
from native_pe_m6 import build_gate
from native_pe_staging_seal import binding
from native_pe_worklist import atomic_write, fingerprint

ROOT = Path(__file__).resolve().parents[1]

# The M8 control families. Each control's outcome is decided by the request's
# capture configuration, not the guest: the guest embeds indicator strings (or
# drops an executable payload) and returns 1, and the configured submitted-sample
# capture recovers them.
_FAMILIES = {
    'strings': ['Builtin', 'Custom'],
    'carve': ['Shellcode'],
}

# The submitted-sample capture reports these controls own. The shared M4
# projection does not cover them, so the replay compares them itself: every
# contained run must report the same memory-string capture, its bound receipt,
# and the same carved artifacts as the source-tested execution it replays.
_OBSERVED = ('user_memory_strings', 'user_memory_capture', 'artifacts')


def required_cases():
    return {f'{arch}-m8-{family}-{case}'
            for arch in ('X86', 'X64')
            for family, cases in _FAMILIES.items()
            for case in cases}


def cases(root):
    selected = sorted(path for path in (root / 'fixtures-final').iterdir()
                      if path.is_dir() and '-m8-' in path.name)
    names = {path.name for path in selected}
    assert names == required_cases(), f'M8 control set differs: {sorted(names ^ required_cases())}'
    for fixture in selected:
        assert (fixture / 'source-execution.json').is_file(), f'Missing source-tested outcome: {fixture.name}'
    return selected


def observations(root, fixture, *, output_directory='m8'):
    run = root / output_directory / fixture.name
    source, = [p for p in fixture.iterdir() if p.suffix.lower() in ('.exe', '.dll')]
    execution = binding(run, source)['result']['execution']
    expected = json.loads((fixture / 'source-execution.json').read_bytes())
    for field in _OBSERVED:
        assert execution.get(field) == expected.get(field), (fixture.name, field)
    # Every M8 control decides nothing beyond returning 1 from its entry.
    assert execution['completion_reason'] == 'entry_return', fixture.name
    assert execution['guest_entry_return'] == 1, fixture.name
    return {field: execution.get(field) for field in _OBSERVED if execution.get(field)}


def run(root, index):
    build_gate(root, index)
    selected = cases(root)
    output = root / 'm8'
    output.mkdir()  # Preserve existing successful and failed runs.
    executable = root / 'bundle/emumee-rs.exe'
    records = []
    for fixture in selected:
        limits = json.loads((fixture / 'limits.json').read_bytes())
        source, = [p for p in fixture.iterdir() if p.suffix.lower() in ('.exe', '.dll')]
        command = [str(executable), 'run', str(source), '--output', str(output / fixture.name),
                   '--inputs', str(fixture / 'inputs.json'),
                   '--max-instructions', str(limits['max_instructions']),
                   '--timeout-us', str(limits['timeout_us']), '--',
                   *json.loads((fixture / 'arguments.json').read_bytes())]
        result = subprocess.run(command, capture_output=True, timeout=120)
        (output / f'{fixture.name}.stdout').write_bytes(result.stdout)
        (output / f'{fixture.name}.stderr').write_bytes(result.stderr)
        assert result.returncode == 0, (fixture.name, result.returncode, result.stderr)
        record = verify(root, fixture, output_directory='m8')
        observations(root, fixture)
        records.append(record)
        print(f'{fixture.name} verified', flush=True)
    atomic_write(output / 'verification.json', json.dumps(records, indent=2) + '\n')


def seal(root, index, *, check=False):
    build_gate(root, index)
    selected = cases(root)
    records = [verify(root, fixture, output_directory='m8') for fixture in selected]
    for fixture in selected:
        observations(root, fixture)
    assert records == json.loads((root / 'm8/verification.json').read_bytes())
    paths = set()
    for directory in (root / 'bundle', root / 'm8', index.parent, *selected):
        paths.update(path for path in directory.rglob('*') if path.is_file())
    artifacts = [dict(path=path.relative_to(ROOT).as_posix(), size=path.stat().st_size,
                      sha256=hashlib.sha256(path.read_bytes()).hexdigest()) for path in sorted(paths)]
    document = dict(schema=2, scope='M8 submitted-sample memory-string and executable-region capture source and contained replay; per-row semantic API parity and M10 remain open',
                    controls=records, artifacts=artifacts)
    document['fingerprint'] = fingerprint(document)
    destination = root / 'qualified-m8.json'
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
