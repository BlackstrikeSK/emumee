from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))

from native_pe_semantic_heap_checks import identity, legacy_map_size, reference


class HeapChecksSemanticTests(unittest.TestCase):
    def test_frozen_mapping_adds_padding_even_to_aligned_subpage_requests(self):
        self.assertEqual([legacy_map_size(size) for size in (33, 48, 4096, 4097)],
                         [48, 64, 4096, 8192])

    def test_expected_differences_are_limited_to_ownership_and_size(self):
        cases = reference().values()
        self.assertEqual(len({identity(case) for case in cases}), 8)
        self.assertEqual(len(cases), 24)
        for case in cases:
            by_label = {row['label']: row for row in case['vectors']}
            differences = {label for label, row in by_label.items() if row['legacy'] != row['expected']}
            invalid = 0 if case['export'] == 'HeapValidate' else (1 << (8 * case['width'])) - 1
            with self.subTest(contract=identity(case), size=case['size']):
                self.assertEqual(by_label['no-access']['legacy'], invalid)
                self.assertEqual(by_label['read-only']['expected'], by_label['live']['expected'])
                self.assertEqual(by_label['freed']['expected'], invalid)
                if case['export'] == 'HeapValidate':
                    self.assertEqual(differences, {'wrong-heap'})
                else:
                    self.assertEqual(differences, {'live', 'live-no-serialize', 'null-heap',
                                                   'wrong-heap', 'read-only', 'restored'})
