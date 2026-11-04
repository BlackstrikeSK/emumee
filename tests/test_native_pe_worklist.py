"""Regression controls for evidence-preserving native migration accounting."""
import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[1] / 'tools/native_pe_worklist.py'
SPEC = importlib.util.spec_from_file_location('native_pe_worklist', SOURCE)
worklist = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(worklist)


class NativePeWorklistTests(unittest.TestCase):
    def test_interrupted_atomic_publication_preserves_existing_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'ledger.json'
            path.write_text('old-evidence', encoding='utf-8')
            with patch.object(worklist.os, 'replace', side_effect=OSError('synthetic interruption')):
                with self.assertRaises(OSError):
                    worklist.atomic_write(path, 'new-evidence')
            self.assertEqual(path.read_text(), 'old-evidence')
            self.assertEqual(list(path.parent.glob('*.tmp')), [])

    def row(self, architecture='x64', kind='function'):
        return {
            'module': 'synthetic', 'export': 'Probe', 'architecture': architecture,
            'kind': kind, 'source_fingerprint': 'original',
            'semantic_status': 'unreviewed', 'submitted_route': 'unreviewed',
            'behavioral_evidence': [],
        }

    def closed(self, architecture='x64', kind='function'):
        row = self.row(architecture, kind)
        row.update(semantic_status='verified_model', submitted_route='verified',
                   behavioral_evidence=[{
                       'id': 'synthetic-control', 'architecture': architecture,
                       'source_fingerprint': row['source_fingerprint'],
                       'oracle': 'independent-properties', 'baseline': 'frozen-synthetic',
                       'tests': ['positive-control'], 'limits': {'instructions': 100},
                       'negative_controls': ['bad-pointer'],
                   }])
        return row

    def gates(self, rows):
        scope = worklist.fingerprint(sorted(row['source_fingerprint'] for row in rows))
        return {name: {'status': 'verified', 'evidence': ['synthetic-proof'],
                       'scope_fingerprint': scope} for name in worklist.REQUIRED_GATES}

    def test_unchanged_regeneration_preserves_closure_and_history(self):
        old = self.closed()
        rows, drift = worklist.merge_contracts([self.row()], [old])
        self.assertEqual(rows[0]['behavioral_evidence'], old['behavioral_evidence'])
        self.assertEqual(rows[0]['semantic_status'], 'verified_model')
        self.assertFalse(drift['added'] or drift['removed'])

    def test_changed_dependency_invalidates_closure_but_preserves_evidence_in_history(self):
        fresh = self.row()
        fresh['source_fingerprint'] = 'changed-shared-state'
        rows, _ = worklist.merge_contracts([fresh], [self.closed()])
        self.assertEqual(rows[0]['semantic_status'], 'stale')
        self.assertEqual(rows[0]['submitted_route'], 'unreviewed')
        self.assertEqual(rows[0]['behavioral_evidence'], [])
        self.assertEqual(rows[0]['history'][0]['behavioral_evidence'][0]['id'], 'synthetic-control')

    def test_inventory_addition_and_removal_require_review(self):
        for fresh in ([], [self.row(), self.row('x86')]):
            with self.assertRaisesRegex(ValueError, 'Inventory drift'):
                worklist.merge_contracts(fresh, [self.row()])
        rows, drift = worklist.merge_contracts([], [self.closed()], allow_inventory_change=True)
        self.assertEqual(rows, [])
        self.assertEqual(len(drift['retired_contracts']), 1)

    def test_architectures_and_data_are_independent_contracts(self):
        rows, _ = worklist.merge_contracts([
            self.row(), self.row('x86'), self.row(kind='data'),
        ])
        self.assertEqual(len(rows), 3)
        rows[0] = self.closed()
        self.assertEqual(worklist.completion(rows, [], self.gates(rows))['open_contracts'], 2)

    def test_duplicate_identity_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'Duplicate contract'):
            worklist.merge_contracts([self.row(), self.row()])

    def test_closure_requires_matching_evidence(self):
        for field in ('tests', 'limits', 'negative_controls', 'oracle', 'baseline'):
            row = self.closed()
            del row['behavioral_evidence'][0][field]
            with self.assertRaisesRegex(ValueError, 'requires'):
                worklist.validate_evidence(row)
        for field, value in (('architecture', 'x86'), ('source_fingerprint', 'stale')):
            row = self.closed()
            row['behavioral_evidence'][0][field] = value
            with self.assertRaisesRegex(ValueError, 'differs'):
                worklist.validate_evidence(row)

    def test_no_completion_from_bindings_or_missing_route(self):
        for row in (self.row(), self.closed()):
            row['submitted_route'] = 'unreviewed'
            self.assertFalse(worklist.completion([row], [], self.gates([row]))['complete'])
        row = self.closed()
        row['status'] = 'missing_binding'
        self.assertFalse(worklist.completion([row], [], self.gates([row]))['complete'])

    def test_applicable_contract_cannot_waive_submitted_reachability(self):
        row = self.closed()
        row['submitted_route'] = 'not_applicable_with_proof'
        with self.assertRaisesRegex(ValueError, 'cannot waive'):
            worklist.validate_evidence(row)

    def test_no_completion_with_empty_scope_unresolved_or_incomplete_gates(self):
        rows = [self.closed()]
        self.assertFalse(worklist.completion([], [], self.gates([]))['complete'])
        self.assertFalse(worklist.completion(rows, ['dynamic-site'], self.gates(rows))['complete'])
        self.assertFalse(worklist.completion(rows, [], {})['complete'])
        for name in worklist.REQUIRED_GATES:
            gates = self.gates(rows)
            del gates[name]
            self.assertFalse(worklist.completion(rows, [], gates)['complete'])
            gates = self.gates(rows)
            gates[name]['scope_fingerprint'] = 'old'
            self.assertFalse(worklist.completion(rows, [], gates)['complete'])
        self.assertTrue(worklist.completion(rows, [], self.gates(rows))['complete'])

    def test_intentional_change_requires_explicit_acceptance(self):
        row = self.closed()
        row['semantic_status'] = 'verified_intentional_change'
        with self.assertRaisesRegex(ValueError, 'accepted deviation'):
            worklist.validate_evidence(row)
        row['accepted_deviation'] = 'reviewed synthetic expectation'
        worklist.validate_evidence(row)

    def test_merge_does_not_mutate_prior_history(self):
        old = self.closed()
        snapshot = copy.deepcopy(old)
        fresh = self.row()
        fresh['source_fingerprint'] = 'changed'
        worklist.merge_contracts([fresh], [old])
        self.assertEqual(old, snapshot)

    def test_unreviewed_row_does_not_acquire_fictitious_stale_evidence(self):
        fresh = self.row()
        fresh['source_fingerprint'] = 'changed'
        rows, _ = worklist.merge_contracts([fresh], [self.row()])
        self.assertEqual(rows[0]['semantic_status'], 'unreviewed')
        self.assertEqual(rows[0]['history'], [])

    def test_maintained_evidence_restores_closure_after_clone_without_local_ledger(self):
        rows, _ = worklist.merge_contracts([self.row()])
        worklist.apply_evidence(rows, {'schema': 1, 'entries': [self.closed()]})
        self.assertEqual(rows[0]['semantic_status'], 'verified_model')
        self.assertTrue(rows[0]['behavioral_evidence'])

    def test_maintained_evidence_rejects_orphans_duplicates_and_unknown_gates(self):
        for document in (
            {'schema': 1, 'entries': [self.closed('x86')]},
            {'schema': 1, 'entries': [self.closed(), self.closed()]},
            {'schema': 1, 'entries': [], 'required_gates': {'imaginary': {}}},
        ):
            rows, _ = worklist.merge_contracts([self.row()])
            with self.assertRaises(ValueError):
                worklist.apply_evidence(rows, document)

    def test_stale_maintained_evidence_is_archived_not_requalified(self):
        fresh = self.row()
        fresh['source_fingerprint'] = 'changed'
        rows, _ = worklist.merge_contracts([fresh])
        document = {'schema': 1, 'entries': [self.closed()]}
        worklist.apply_evidence(rows, document)
        worklist.apply_evidence(rows, document)
        self.assertEqual(rows[0]['semantic_status'], 'stale')
        self.assertEqual(len(rows[0]['history']), 1)
        self.assertFalse(rows[0]['behavioral_evidence'])


if __name__ == '__main__':
    unittest.main()
