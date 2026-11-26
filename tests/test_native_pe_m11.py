"""Coverage controls for the M11 closure audit; no guest execution."""
from pathlib import Path
import sys
import unittest
import tempfile
import hashlib
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import native_pe_m11
from native_pe_m11 import falsely_closed_count, independent_completion, verify_semantic_artifacts
from native_pe_worklist import REQUIRED_GATES, CLOSED_STATES, completion, fingerprint


def _rows(*statuses):
    return [{'module': 'm', 'export': f'E{i}', 'kind': 'function', 'architecture': 'x64',
             'semantic_status': s, 'submitted_route': 'unreviewed',
             'status': 'unverified_binding', 'source_fingerprint': f'fp{i}',
             'history': [], 'behavioral_evidence': []}
            for i, s in enumerate(statuses)]


def _closed(status='verified_model'):
    row, = _rows(status)
    row.update(submitted_route='verified', accepted_deviation='reviewed synthetic deviation',
               behavioral_evidence=[dict(id='synthetic-control', oracle='independent properties',
                   baseline='frozen synthetic baseline', architecture='x64', source_fingerprint='fp0',
                   tests=['positive-control'], negative_controls=['invalid-input'], limits={'bytes': 16})])
    return row


def _gates(rows):
    scope = fingerprint(sorted(r['source_fingerprint'] for r in rows))
    return {name: dict(status='verified', evidence=['synthetic-gate'], scope_fingerprint=scope)
            for name in REQUIRED_GATES}


class M11ClosureAuditTests(unittest.TestCase):
    def test_closure_audit_is_the_gate_m11_owns(self):
        self.assertIn('closure_audit', REQUIRED_GATES)

    def test_an_all_open_denominator_credits_nothing(self):
        rows = _rows('unreviewed', 'unreviewed', 'unreviewed')
        self.assertEqual(0, falsely_closed_count(rows))

    def test_closed_status_without_evidence_is_falsely_credited(self):
        rows = _rows('unreviewed', 'verified_model', 'not_applicable_with_proof')
        self.assertEqual(2, falsely_closed_count(rows))

    def test_evidence_backed_partial_closure_is_not_falsely_credited(self):
        closed = _closed()
        opened, = _rows('unreviewed')
        opened['export'] = 'Open'
        rows = [closed, opened]
        self.assertEqual(0, falsely_closed_count(rows))
        result = independent_completion(rows, [], _gates(rows))
        self.assertFalse(result['complete'])
        self.assertEqual(1, result['open_contracts'])

    def test_independent_algorithm_allows_complete_evidence_and_all_gates(self):
        for semantic in CLOSED_STATES:
            rows = [_closed(semantic)]
            if semantic == 'not_applicable_with_proof':
                rows[0].update(status='missing_binding', submitted_route='not_applicable_with_proof')
            expected = completion(rows, [], _gates(rows))
            with patch('native_pe_worklist.completion', side_effect=AssertionError('Must be independent')):
                actual = independent_completion(rows, [], _gates(rows))
            self.assertTrue(actual['complete'])
            for key in actual:
                self.assertEqual(expected[key], actual[key])

    def test_open_route_missing_binding_inventory_or_stale_gate_blocks_completion(self):
        for change in ('route', 'binding', 'inventory', 'gate', 'missing_gate'):
            rows = [_closed()]
            gates = _gates(rows)
            unresolved = []
            if change == 'route':
                rows[0]['submitted_route'] = 'unreviewed'
            elif change == 'binding':
                rows[0]['status'] = 'missing_binding'
            elif change == 'inventory':
                unresolved = ['unresolved registration']
            elif change == 'gate':
                gates['package']['scope_fingerprint'] = 'stale'
            else:
                gates.pop('package')
            actual = independent_completion(rows, unresolved, gates)
            self.assertFalse(actual['complete'], change)
            self.assertEqual(completion(rows, unresolved, gates)['open_contracts'], actual['open_contracts'])

    def test_duplicate_contract_or_stale_evidence_is_rejected(self):
        row = _closed()
        with self.assertRaisesRegex(AssertionError, 'Duplicate'):
            independent_completion([row, row], [], {})
        row['behavioral_evidence'][0]['source_fingerprint'] = 'stale'
        with self.assertRaisesRegex(ValueError, 'fingerprint'):
            independent_completion([row], [], {})

    def test_closed_evidence_artifacts_are_required_and_hash_checked(self):
        row = _closed()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(AssertionError, 'bound artifacts'):
                verify_semantic_artifacts([row], root)
            data = b'qualified synthetic oracle result'
            (root / 'proof.json').write_bytes(data)
            row['behavioral_evidence'][0]['artifacts'] = [dict(
                path='proof.json', size=len(data), sha256=hashlib.sha256(data).hexdigest())]
            self.assertEqual(1, verify_semantic_artifacts([row], root))
            (root / 'proof.json').write_bytes(b'x' * len(data))
            with self.assertRaisesRegex(AssertionError, 'hash mismatch'):
                verify_semantic_artifacts([row], root)
            row['behavioral_evidence'][0]['artifacts'][0]['path'] = '../proof.json'
            with self.assertRaises(AssertionError):
                verify_semantic_artifacts([row], root)

    def test_audit_refuses_a_matrix_from_another_release_root(self):
        with self.assertRaisesRegex(AssertionError, 'another release root'):
            native_pe_m11.verify_release_anchor(Path('/release/bundle'), Path('/other/qualified-m10.json'), Path('/release/index.json'))

    def test_audit_rejects_a_ledger_from_old_runtime_sources(self):
        with patch.object(native_pe_m11, 'verify_release_anchor'), \
             patch.object(native_pe_m11, '_load', return_value={'runtime_source_hashes': {'old': 'hash'}}), \
             patch.object(native_pe_m11, 'runtime_snapshot', return_value={'current': 'hash'}):
            with self.assertRaisesRegex(AssertionError, 'runtime dependencies are stale'):
                native_pe_m11.audit_document(Path('/root'), Path('/root/bundle'), Path('/root/matrix'), Path('/root/index'))

    def test_audit_rejects_a_ledger_from_old_maintained_evidence(self):
        ledger = dict(runtime_source_hashes={}, source_hashes={}, maintained_evidence_fingerprint='stale')
        with patch.object(native_pe_m11, 'verify_release_anchor'), \
             patch.object(native_pe_m11, '_load', side_effect=[ledger, {'sources': {}}, {}]), \
             patch.object(native_pe_m11, 'runtime_snapshot', return_value={}):
            with self.assertRaisesRegex(AssertionError, 'maintained evidence is stale'):
                native_pe_m11.audit_document(Path('/root'), Path('/root/bundle'), Path('/root/matrix'), Path('/root/index'))

    def test_the_independent_recompute_reports_an_open_denominator_incomplete(self):
        # The audit's second opinion: an all-unreviewed denominator is open and
        # never complete, regardless of gate state.
        rows = _rows('unreviewed', 'unreviewed')
        verified_gates = {name: {'status': 'verified', 'evidence': ['x'],
                                 'scope_fingerprint': 'anything'} for name in REQUIRED_GATES}
        status = completion(rows, [], verified_gates)
        self.assertFalse(status['complete'])
        self.assertEqual(2, status['open_contracts'])

    def test_tool_requires_bundle_matrix_and_index(self):
        # The audit is anchored to a same-build bundle, the release matrix and
        # the source index; it is not a free-floating recomputation.
        import inspect
        signature = inspect.signature(native_pe_m11.seal)
        self.assertEqual(['root', 'bundle', 'matrix_path', 'index_path', 'check'],
                         list(signature.parameters))


if __name__ == '__main__':
    unittest.main()
