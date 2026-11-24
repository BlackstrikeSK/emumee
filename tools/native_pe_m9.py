"""Replay and independently check the M9 cross-family operational controls contained.

This is a milestone receipt for the M9 operational gate: single generated
x86/x64 programs that chain several modeled API families (allocation, the owned
virtual filesystem, the registry, cryptography and the network address model)
in one contained execution and decide their own outcome. It is not API semantic
parity for any partition row and not M10 qualification. It reuses the M4 verifier
for request/result/input, ABI effects and cleanup, and additionally enforces the
N17 report-field audit: every serialized report field an M9 control produces is
reviewed, and the contained replay must reproduce the same field set as the
source-tested run it replays.

Unlike the M8 capture controls, an M9 control configures no submitted-sample
capture: it produces no memory-string report, capture receipt or carved
artifact, and that absence is checked so an operational control can never
quietly depend on the capture path.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from native_pe_m4 import verify
from native_pe_m6 import build_gate
from native_pe_m8 import _NONDETERMINISTIC_REPORT_FIELDS, _REVIEWED_REPORT_FIELDS
from native_pe_staging_seal import binding
from native_pe_worklist import atomic_write, fingerprint

ROOT = Path(__file__).resolve().parents[1]

# The M9 operational controls. Each case is one generated program that chains
# several modeled families together; the guest decides its own outcome inline
# and returns 1.
_FAMILIES = {
    'operational': ['Provisioning', 'Integrity', 'Networking'],
}

# An operational control produces no submitted-sample capture, so these report
# fields must be absent from its execution report.
_CAPTURE_FIELDS = ('user_memory_strings', 'user_memory_capture')


def required_cases():
    return {f'{arch}-m9-{family}-{case}'
            for arch in ('X86', 'X64')
            for family, cases in _FAMILIES.items()
            for case in cases}


def cases(root):
    selected = sorted(path for path in (root / 'fixtures-final').iterdir()
                      if path.is_dir() and '-m9-' in path.name)
    names = {path.name for path in selected}
    assert names == required_cases(), f'M9 control set differs: {sorted(names ^ required_cases())}'
    for fixture in selected:
        assert (fixture / 'source-execution.json').is_file(), f'Missing source-tested outcome: {fixture.name}'
    return selected


def observations(root, fixture, *, output_directory='m9'):
    run = root / output_directory / fixture.name
    source, = [p for p in fixture.iterdir() if p.suffix.lower() in ('.exe', '.dll')]
    execution = binding(run, source)['result']['execution']
    expected = json.loads((fixture / 'source-execution.json').read_bytes())
    # N17 report audit: no field is invented, dropped or left unreviewed.
    unreviewed = sorted(set(execution) - _REVIEWED_REPORT_FIELDS)
    assert not unreviewed, (fixture.name, 'unreviewed execution report fields', unreviewed)
    compared = set(execution) - _NONDETERMINISTIC_REPORT_FIELDS
    assert compared == set(expected) - _NONDETERMINISTIC_REPORT_FIELDS, (
        fixture.name, 'replay report fields differ',
        sorted(compared ^ (set(expected) - _NONDETERMINISTIC_REPORT_FIELDS)))
    # An operational control never configures submitted-sample capture, so no
    # memory-string report, capture receipt or carved artifact exists.
    for field in _CAPTURE_FIELDS:
        assert execution.get(field) is None, (fixture.name, 'unexpected capture report', field)
    assert not execution.get('artifacts'), (fixture.name, 'unexpected artifacts', execution.get('artifacts'))
    # Every M9 control decides nothing beyond returning 1 from its entry.
    assert execution['completion_reason'] == 'entry_return', fixture.name
    assert execution['guest_entry_return'] == 1, fixture.name
    return {}


def run(root, index):
    build_gate(root, index)
    selected = cases(root)
    output = root / 'm9'
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
        record = verify(root, fixture, output_directory='m9')
        observations(root, fixture)
        records.append(record)
        print(f'{fixture.name} verified', flush=True)
    atomic_write(output / 'verification.json', json.dumps(records, indent=2) + '\n')


def seal(root, index, *, check=False):
    build_gate(root, index)
    selected = cases(root)
    records = [verify(root, fixture, output_directory='m9') for fixture in selected]
    for fixture in selected:
        observations(root, fixture)
    assert records == json.loads((root / 'm9/verification.json').read_bytes())
    paths = set()
    for directory in (root / 'bundle', root / 'm9', index.parent, *selected):
        paths.update(path for path in directory.rglob('*') if path.is_file())
    artifacts = [dict(path=path.relative_to(ROOT).as_posix(), size=path.stat().st_size,
                      sha256=hashlib.sha256(path.read_bytes()).hexdigest()) for path in sorted(paths)]
    document = dict(schema=2, scope='M9 cross-family operational source and contained replay; per-row semantic API parity and M10 remain open',
                    controls=records, artifacts=artifacts)
    document['fingerprint'] = fingerprint(document)
    destination = root / 'qualified-m9.json'
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
