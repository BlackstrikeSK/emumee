"""Coverage controls for the M10 same-build release matrix; no guest execution."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import native_pe_m10
from native_pe_m10 import MILESTONES, ROOT, matrix

_SANDBOX = ROOT / 'output'


def _fake_root(directory, *, omit=()):
    root = Path(directory)
    (root / 'bundle').mkdir(parents=True)
    (root / 'bundle/rust-worker-build.json').write_text(
        json.dumps({'source_tree_sha256': 'a' * 64}), encoding='utf-8')
    (root / 'bundle/emumee-rs.exe').write_bytes(b'bundle-bytes')
    for order, (name, produced) in enumerate(MILESTONES):
        if name in omit:
            continue
        (root / produced).write_text(
            json.dumps({'fingerprint': f'{name}-fingerprint', 'order': order}), encoding='utf-8')
    index = root / 'source-validation-final' / 'index.json'
    index.parent.mkdir(parents=True)
    index.write_text(json.dumps({'source_fingerprint': 'c' * 64}), encoding='utf-8')
    return root, index


class M10MatrixTests(unittest.TestCase):
    def test_matrix_binds_every_milestone_in_chain_order(self):
        expected = ['smoke', 'm2', 'bootstrap', 'm3', 'm4', 'm5', 'm6', 'm7', 'm8', 'm9']
        self.assertEqual(expected, [name for name, _ in MILESTONES])

    def test_matrix_seals_and_rechecks_every_fingerprint(self):
        with tempfile.TemporaryDirectory(dir=_SANDBOX) as directory:
            root, index = _fake_root(directory)
            matrix(root, index, check=False)
            document = json.loads((root / 'qualified-m10.json').read_bytes())
            self.assertEqual(set(document['milestones']), {name for name, _ in MILESTONES})
            for name, produced in MILESTONES:
                self.assertEqual(document['milestones'][name]['fingerprint'], f'{name}-fingerprint')
                self.assertEqual(document['milestones'][name]['file'], produced)
            self.assertTrue(document['fingerprint'])
            # The sealed matrix rechecks byte-for-byte.
            matrix(root, index, check=True)

    def test_a_missing_milestone_seal_is_refused(self):
        with tempfile.TemporaryDirectory(dir=_SANDBOX) as directory:
            root, index = _fake_root(directory, omit=('m7',))
            with self.assertRaises(FileNotFoundError):
                matrix(root, index, check=False)

    def test_an_altered_milestone_fingerprint_breaks_the_recheck(self):
        with tempfile.TemporaryDirectory(dir=_SANDBOX) as directory:
            root, index = _fake_root(directory)
            matrix(root, index, check=False)
            (root / 'qualified-m8.json').write_text(
                json.dumps({'fingerprint': 'tampered'}), encoding='utf-8')
            with self.assertRaises(AssertionError):
                matrix(root, index, check=True)


if __name__ == '__main__':
    unittest.main()
