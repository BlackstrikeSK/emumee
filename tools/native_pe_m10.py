"""Reproduce every milestone's chained seal against one release build and bind them.

M10 is the same-build release matrix gate of the M8-M11 batch. Each milestone
from the bounded smoke through M9 already has its own independent replay-and-seal
tool, and each binds its controls to a packaged worker. This driver runs that
whole chain against **one** shared qualification root — one release build, one
package, one full source-validation index, one emitted fixture corpus — and then
seals a matrix that records every milestone seal's fingerprint together with the
single bundle and source index they were all produced from.

The matrix proves a release property no single milestone seal states on its own:
that one current build reproduces the source-tested outcome of every contained
control across every milestone, with the per-milestone seals chained exactly as
each tool requires (the smoke under the staging seal, M2 under the smoke, the
bootstrap under M2, M3 under the bootstrap, M4 under M3, and M5-M9 each bound to
the shared source index). It is not API semantic parity for any partition row,
and the global gates with an independent audit of the full denominator remain
M11.

Reproducing the chain is deterministic but not cheap: it replays the entire
contained corpus through the packaged worker, so each stage is skipped when its
seal is already present under the root, which makes a long run resumable.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from native_pe_worklist import atomic_write, fingerprint

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / 'tools'

# Each milestone seal this matrix binds, in chain order, and the file each tool
# writes. The smoke seal underlies M2, which underlies the bootstrap, which
# underlies M3; M4 chains to M3; and M5-M9 each bind to the shared source index.
MILESTONES = [
    ('smoke', 'qualified-smoke.json'),
    ('m2', 'qualified-m2.json'),
    ('bootstrap', 'qualified-bootstrap.json'),
    ('m3', 'qualified-m3.json'),
    ('m4', 'qualified-m4.json'),
    ('m5', 'qualified-m5.json'),
    ('m6', 'qualified-m6.json'),
    ('m7', 'qualified-m7.json'),
    ('m8', 'qualified-m8.json'),
    ('m9', 'qualified-m9.json'),
]


def _sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _run(command, **kwargs):
    print('  $', ' '.join(str(part) for part in command), flush=True)
    completed = subprocess.run(command, cwd=ROOT, **kwargs)
    assert completed.returncode == 0, (command, completed.returncode)


def _python(script, *args):
    _run([sys.executable, str(TOOLS / script), *[str(a) for a in args]])


def _pwsh(*args):
    _run(['pwsh', '-NoProfile', '-Command',
          ' '.join([str(TOOLS / 'verify_rust_user_pe.ps1'), *[str(a) for a in args]])])


def _rel(root, *parts):
    return (root / Path(*parts)).resolve().relative_to(ROOT).as_posix()


def _regression(root):
    """Produce the bounded regression evidence under `root/qualification`.

    This is the one stage that runs a PowerShell script (`verify_rust_user_pe.ps1`),
    and it is also the one whose pass depends on PowerShell observing the
    deliberately uncontained worker's native refusal exit code. A PowerShell
    launched as a child of this Python process does not always see that native
    exit code, so if the regression has already been produced from a shell —
    120 contained cases and the direct-worker refusal — this reuses it rather
    than running the script again. A fresh root therefore expects the operator
    to run `verify_rust_user_pe.ps1 -Bundle <root>/bundle -Fixtures
    <root>/fixtures-final -OutputRoot <root>/qualification -Layout -Imports -Abi`
    from a shell first; the staging seal below re-verifies its full content.
    """
    verification = root / 'qualification/verification.json'
    if verification.exists() and len(json.loads(verification.read_bytes())) == 120:
        print('  regression already produced; reusing', flush=True)
        return
    _pwsh('-Bundle', _rel(root, 'bundle'), '-Fixtures', _rel(root, 'fixtures-final'),
          '-OutputRoot', _rel(root, 'qualification'), '-Layout', '-Imports', '-Abi')


def _staging(root):
    if (root / 'staging/verification.json').exists():
        print('  staging already produced; reusing', flush=True)
        return
    _python('native_pe_staging.py', '--bundle', root / 'bundle',
            '--fixtures', root / 'fixtures-final', '--output', root / 'staging')


def stages(root, index):
    """The chain as (name, produced-seal, build-steps, seal-step, check-step).

    A build step replays a milestone's controls; the seal step writes its
    `qualified-*.json`; the check step re-verifies it. The smoke stage has no
    single tool: the regression and staging replays precede its seal.
    """
    smoke_build = [lambda: _regression(root), lambda: _staging(root)]
    return [
        ('smoke', 'qualified-smoke.json', smoke_build,
         lambda: _python('native_pe_staging_seal.py', '--root', root),
         lambda: _python('native_pe_staging_seal.py', '--root', root, '--check')),
        ('m2', 'qualified-m2.json', [lambda: _python('native_pe_m2.py', '--root', root)],
         lambda: _python('native_pe_m2.py', '--root', root, '--seal'),
         lambda: _python('native_pe_m2.py', '--root', root, '--check')),
        ('bootstrap', 'qualified-bootstrap.json', [lambda: _python('native_pe_m3.py', '--root', root)],
         lambda: _python('native_pe_m3.py', '--root', root, '--seal'),
         lambda: _python('native_pe_m3.py', '--root', root, '--check')),
        ('m3', 'qualified-m3.json', [lambda: _python('native_pe_m3_lifecycle.py', '--root', root)],
         lambda: _python('native_pe_m3_lifecycle.py', '--root', root, '--seal'),
         lambda: _python('native_pe_m3_lifecycle.py', '--root', root, '--check')),
        ('m4', 'qualified-m4.json', [lambda: _python('native_pe_m4.py', '--root', root, '--source-index', index)],
         lambda: _python('native_pe_m4.py', '--root', root, '--source-index', index, '--seal'),
         lambda: _python('native_pe_m4.py', '--root', root, '--source-index', index, '--check')),
    ] + [
        (name, f'qualified-{name}.json',
         [lambda name=name: _python(f'native_pe_{name}.py', '--root', root, '--source-index', index)],
         lambda name=name: _python(f'native_pe_{name}.py', '--root', root, '--source-index', index, '--seal'),
         lambda name=name: _python(f'native_pe_{name}.py', '--root', root, '--source-index', index, '--check'))
        for name in ('m5', 'm6', 'm7', 'm8', 'm9')
    ]


def run(root, index):
    for name, produced, build, seal_step, check_step in stages(root, index):
        if (root / produced).exists():
            print(f'[{name}] already sealed; rechecking', flush=True)
            check_step()
            continue
        print(f'[{name}] replaying and sealing', flush=True)
        for step in build:
            step()
        seal_step()
    print('chain reproduced', flush=True)


def matrix(root, index, *, check=False):
    seals = {}
    for name, produced in MILESTONES:
        document = json.loads((root / produced).read_bytes())
        seals[name] = dict(file=produced, fingerprint=document['fingerprint'])
    bundle = sorted((root / 'bundle').rglob('*'))
    bundle_files = [dict(path=path.relative_to(ROOT).as_posix(), size=path.stat().st_size, sha256=_sha(path))
                    for path in bundle if path.is_file()]
    index_document = json.loads(index.read_bytes())
    receipt = json.loads((root / 'bundle/rust-worker-build.json').read_bytes())
    document = dict(
        schema=1,
        scope='M10 same-build release matrix: every milestone seal reproduced against one release build; '
              'not API semantic parity and not the M11 global gates',
        source_tree_sha256=receipt['source_tree_sha256'],
        source_index=dict(path=index.relative_to(ROOT).as_posix(), sha256=_sha(index),
                          source_fingerprint=index_document.get('source_fingerprint')),
        bundle=bundle_files,
        milestones=seals,
    )
    document['fingerprint'] = fingerprint(document)
    destination = root / 'qualified-m10.json'
    if check:
        assert json.loads(destination.read_bytes()) == document, 'M10 matrix differs from its sealed form'
    else:
        assert not destination.exists(), 'Preserve sealed evidence'
        atomic_write(destination, json.dumps(document, indent=2) + '\n')
    print(json.dumps(dict(milestones=len(seals), bundle_files=len(bundle_files),
                          source_tree_sha256=document['source_tree_sha256'],
                          fingerprint=document['fingerprint']), indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--source-index', type=Path, required=True)
    action = parser.add_mutually_exclusive_group()
    action.add_argument('--seal', action='store_true')
    action.add_argument('--check', action='store_true')
    args = parser.parse_args()
    root, index = args.root.resolve(), args.source_index.resolve()
    if args.check:
        run(root, index)  # Re-verify every milestone seal, then the matrix.
        matrix(root, index, check=True)
    elif args.seal:
        matrix(root, index, check=False)
    else:
        run(root, index)
