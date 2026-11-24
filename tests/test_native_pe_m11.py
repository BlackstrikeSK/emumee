"""Coverage controls for the M11 closure audit; no guest execution."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import native_pe_m11
from native_pe_m11 import falsely_closed_count
from native_pe_worklist import REQUIRED_GATES, completion


def _rows(*statuses):
    return [{'module': 'm', 'export': f'E{i}', 'kind': 'function', 'architecture': 'x64',
             'semantic_status': s, 'submitted_route': 'unreviewed',
             'status': 'unverified_binding', 'source_fingerprint': f'fp{i}',
             'history': [], 'behavioral_evidence': []}
            for i, s in enumerate(statuses)]


class M11ClosureAuditTests(unittest.TestCase):
    def test_closure_audit_is_the_gate_m11_owns(self):
        self.assertIn('closure_audit', REQUIRED_GATES)

    def test_an_all_open_denominator_credits_nothing(self):
        rows = _rows('unreviewed', 'unreviewed', 'unreviewed')
        self.assertEqual(0, falsely_closed_count(rows))

    def test_a_closed_status_is_counted_as_credited(self):
        # If any contract claimed a closed status, the honesty invariant would
        # flag it; the audit asserts this count is zero for the real denominator.
        rows = _rows('unreviewed', 'verified_model', 'not_applicable_with_proof')
        self.assertEqual(2, falsely_closed_count(rows))

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
