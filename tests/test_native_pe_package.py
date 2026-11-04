"""Packaging source fingerprints and refusal controls never execute release binaries."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SELECTED = ('Cargo.toml', 'Cargo.lock', 'tools/build_rust.ps1',
            'tools/package_rust.ps1', 'tools/package_rust_linux.sh')


def source_fingerprint(root):
    selected = set(SELECTED)
    selected.update(path.relative_to(root).as_posix() for path in (root / 'rust').rglob('*')
                    if path.is_file() and path.suffix in ('.rs', '.toml', '.cmake', '.json'))
    sources = {name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in sorted(selected)}
    text = ''.join(f'{name}\0{digest}\n' for name, digest in sources.items())
    return dict(source_tree_sha256=hashlib.sha256(text.encode()).hexdigest(), source_files=sources)


@unittest.skipUnless(shutil.which('powershell'), 'Windows PowerShell is required')
class PackageFingerprintTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='native package ')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for name in SELECTED:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('fixture\n', encoding='utf-8')
        shutil.copyfile(ROOT / 'tools/package_rust.ps1', self.root / 'tools/package_rust.ps1')
        (self.root / 'rust/example').mkdir(parents=True)
        for name in ('lib.rs', 'Cargo.toml', 'config.json', 'build.cmake', 'ignored.txt'):
            (self.root / 'rust/example' / name).write_text(name, encoding='utf-8')

    def run_helper(self, *arguments, root=None):
        return subprocess.run(['powershell', '-NoProfile', '-NonInteractive', '-File',
                               str((root or self.root) / 'tools/package_rust.ps1'), *arguments],
                              capture_output=True, text=True, encoding='utf-8', timeout=30)

    def test_independent_synthetic_fingerprint_without_binaries(self):
        result = self.run_helper('-SourceFingerprintOnly')
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(source_fingerprint(self.root), json.loads(result.stdout))
        self.assertFalse((self.root / 'target').exists())

    def test_current_repository_fingerprint_matches_build_algorithm(self):
        result = self.run_helper('-SourceFingerprintOnly', root=ROOT)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(source_fingerprint(ROOT), json.loads(result.stdout))

    def test_selected_mutation_changes_fingerprint_but_ignored_file_does_not(self):
        before = json.loads(self.run_helper('-SourceFingerprintOnly').stdout)
        (self.root / 'rust/example/ignored.txt').write_text('changed')
        self.assertEqual(before, json.loads(self.run_helper('-SourceFingerprintOnly').stdout))
        (self.root / 'rust/example/lib.rs').write_text('changed')
        after = json.loads(self.run_helper('-SourceFingerprintOnly').stdout)
        self.assertNotEqual(before['source_tree_sha256'], after['source_tree_sha256'])
        self.assertEqual(source_fingerprint(self.root), after)

    def test_existing_destination_refused_without_touching_contents(self):
        destination = self.root / 'frozen'
        destination.mkdir()
        (destination / 'sentinel').write_bytes(b'preserve')
        result = self.run_helper('-Destination', str(destination))
        self.assertNotEqual(0, result.returncode)
        self.assertIn('Preserve the existing frozen Rust bundle', result.stderr)
        self.assertEqual(b'preserve', (destination / 'sentinel').read_bytes())

    def test_missing_source_refused_before_creating_destination(self):
        (self.root / 'Cargo.lock').unlink()
        result = self.run_helper('-Destination', 'new-bundle')
        self.assertNotEqual(0, result.returncode)
        self.assertFalse((self.root / 'new-bundle').exists())

    def test_modes_are_mutually_exclusive(self):
        result = self.run_helper('-SourceFingerprintOnly', '-Destination', 'new-bundle')
        self.assertNotEqual(0, result.returncode)
        self.assertFalse((self.root / 'new-bundle').exists())


if __name__ == '__main__':
    unittest.main()
