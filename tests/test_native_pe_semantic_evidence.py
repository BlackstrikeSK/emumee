"""Atomic family publication must never leave a partial semantic update."""
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import native_pe_semantic_evidence as evidence


def claim(name):
    return dict(module='kernel32', export=name, kind='function', architecture='x64',
        source_fingerprint='a' * 64, semantic_status='verified_legacy_placeholder', submitted_route='verified',
        behavioral_evidence=[dict(id=name, architecture='x64', source_fingerprint='a' * 64,
            oracle='unit test oracle', baseline='frozen test', limits=dict(bytes=4),
            tests=['positive'], negative_controls=['negative'])])


class AtomicSemanticEvidenceTests(unittest.TestCase):
    def fixture(self, directory):
        path = Path(directory) / 'evidence.json'
        path.write_text(json.dumps(dict(schema=1, entries=[claim('Existing')])))
        return path, path.read_bytes()

    def test_later_proof_failure_leaves_maintained_evidence_byte_identical(self):
        with tempfile.TemporaryDirectory() as directory:
            path, before = self.fixture(directory)
            def checked(*args, collect_only):
                self.assertTrue(collect_only)
                self.assertEqual(before, path.read_bytes())
                return [claim('First')]
            def refused(*args, collect_only):
                self.assertTrue(collect_only)
                self.assertEqual(before, path.read_bytes())
                raise AssertionError('second proof failed')
            with self.assertRaisesRegex(AssertionError, 'second proof'):
                evidence.publish(None,None,None,qualifiers=[SimpleNamespace(publish_evidence=checked),
                    SimpleNamespace(publish_evidence=refused)],evidence_path=path)
            self.assertEqual(before,path.read_bytes())

    def test_overlapping_or_unverified_claims_cannot_partially_publish(self):
        with tempfile.TemporaryDirectory() as directory:
            path,before = self.fixture(directory)
            duplicate=SimpleNamespace(publish_evidence=lambda *a, **k: [claim('Same')])
            with self.assertRaisesRegex(AssertionError,'Overlapping'):
                evidence.publish(None,None,None,qualifiers=[duplicate,duplicate],evidence_path=path)
            self.assertEqual(before,path.read_bytes())
            open_claim=claim('Open');open_claim['semantic_status']='unreviewed'
            with self.assertRaises(AssertionError):
                evidence.publish(None,None,None,qualifiers=[SimpleNamespace(publish_evidence=lambda *a,**k: [open_claim])],evidence_path=path)
            self.assertEqual(before,path.read_bytes())

    def test_all_checked_families_publish_together_and_preserve_unrelated_claims(self):
        with tempfile.TemporaryDirectory() as directory:
            path,_=self.fixture(directory)
            one=SimpleNamespace(publish_evidence=lambda *a,**k: [claim('One')])
            two=SimpleNamespace(publish_evidence=lambda *a,**k: [claim('Two')])
            self.assertEqual(2,evidence.publish(None,None,None,qualifiers=[one,two],evidence_path=path))
            self.assertEqual(['Existing','One','Two'],[r['export'] for r in json.loads(path.read_bytes())['entries']])


if __name__ == '__main__':
    unittest.main()
