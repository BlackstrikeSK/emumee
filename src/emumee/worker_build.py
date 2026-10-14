"""Build receipts detect stale source workers and missing generated guest assets."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import sys
from pathlib import Path

from .safeio import read_regular_file


RECEIPT = 'worker-build.json'
MAX_RECEIPT = 128 * 1024


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def source_files(root: Path) -> dict[str, str]:
    root = root.resolve()
    selected = [root / n for n in ('Emumee.spec', 'launcher.py', 'pyproject.toml', 'build.ps1', 'tools/patch_bootloader_cfg.py')]
    selected.extend((root / 'src/emumee').rglob('*.py'))
    selected.extend((root / 'src/emumee/guest_native').glob('*.exe'))
    result = {}
    for path in sorted(selected):
        if path.is_symlink() or not path.resolve().is_relative_to(root):
            raise ValueError('Worker source includes an unsafe file link')
        result[path.relative_to(root).as_posix()] = sha256(path)
    return result


def source_digest(files: dict[str, str]) -> str:
    return hashlib.sha256(json.dumps(files, sort_keys=True, separators=(',', ':')).encode('utf-8')).hexdigest()


def asset_files(directory: Path) -> dict[str, dict]:
    result = {}
    for path in sorted(directory.glob('*.exe')):
        if (not re.fullmatch(r'[a-z0-9_]+_(x86|x64)[.]exe', path.name) or path.is_symlink() or
                not path.resolve().is_relative_to(directory.resolve()) or not 0 < path.stat().st_size <= 1024 * 1024):
            raise ValueError('Invalid generated guest utility asset')
        result[path.name] = {'sha256': sha256(path), 'size': path.stat().st_size}
    if not result:
        raise ValueError('Generated guest utility assets are missing')
    return result


def write_receipt(worker: Path, root: Path) -> dict:
    source = source_files(root)
    expected = asset_files(root / 'src/emumee/guest_native')
    actual = asset_files(worker.parent / '_internal/emumee/guest_native')
    if actual != expected:
        raise ValueError('Packaged guest utilities differ from source assets')
    receipt = {'schema': 1, 'built_at': dt.datetime.now(dt.timezone.utc).isoformat(),
               'python_version': sys.version, 'worker_sha256': sha256(worker),
               'source_tree_sha256': source_digest(source), 'source_files': source,
               'guest_native_assets': actual}
    raw = json.dumps(receipt, indent=2).encode('utf-8')
    if len(raw) > MAX_RECEIPT:
        raise ValueError('Worker build receipt exceeds limit')
    (worker.parent / RECEIPT).write_bytes(raw)
    return receipt


def verify_receipt(worker: Path, source_root: Path | None = None) -> dict:
    raw = read_regular_file(worker.parent / RECEIPT, MAX_RECEIPT)
    if raw is None:
        raise ValueError('worker build receipt missing or unsafe; run .\\build.ps1')
    receipt = json.loads(raw)
    if (not isinstance(receipt, dict) or receipt.get('schema') != 1 or
            receipt.get('worker_sha256') != sha256(worker)):
        raise ValueError('worker executable does not match its build receipt; run .\\build.ps1')
    if receipt.get('guest_native_assets') != asset_files(worker.parent / '_internal/emumee/guest_native'):
        raise ValueError('packaged guest utilities differ from build receipt; run .\\build.ps1')
    if source_root is not None:
        current = source_files(source_root)
        if receipt.get('source_tree_sha256') != source_digest(current) or receipt.get('source_files') != current:
            raise ValueError('isolated worker is stale relative to current source; run .\\build.ps1')
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('worker', type=Path)
    parser.add_argument('--source', type=Path, required=True)
    args = parser.parse_args()
    result = write_receipt(args.worker, args.source)
    print(json.dumps({'worker_sha256': result['worker_sha256'],
                      'source_tree_sha256': result['source_tree_sha256'],
                      'guest_native_assets': len(result['guest_native_assets'])}))


if __name__ == '__main__':
    main()
