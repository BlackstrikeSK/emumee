import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))

from native_pe_semantic_winstrings import check_diagnostics, controls, identity, reference


class WindowsStringSemanticProofTests(unittest.TestCase):
    def test_every_frozen_alias_and_width_has_contained_controls(self):
        frozen, _ = reference()
        contained = list(controls(frozen).values())
        self.assertEqual({identity(case) for case in contained}, {tuple(key) for key in frozen['contracts']})
        self.assertEqual(len(frozen['cases']) - len(contained), 42)
        self.assertTrue(all(case['protection'] != 2 for case in contained))

    def test_diagnostics_distinguish_null_source_from_non_ascii_and_empty_report(self):
        frozen, diagnostics = reference()
        null = next(case for case in frozen['cases']
                    if case['export'] == '_wcslwr' and case['label'] == 'null-0')
        expected = diagnostics[identity(null), null['label']]
        self.assertEqual(expected, ['Case mapping: inaccessible string'])
        check_diagnostics({'string_api_unsupported': expected}, expected)
        with self.assertRaisesRegex(AssertionError, 'String diagnostic differs'):
            check_diagnostics({'string_api_unsupported': ['Case mapping: non-ASCII mapping unavailable']}, expected)
        with self.assertRaisesRegex(AssertionError, 'String diagnostic differs'):
            check_diagnostics({'string_api_unsupported': expected}, [])
