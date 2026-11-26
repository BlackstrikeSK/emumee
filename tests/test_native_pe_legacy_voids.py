"""Frozen void bodies and original call-return bookkeeping are independent."""
import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import native_pe_legacy_voids as voids


class LegacyVoidOracleTests(unittest.TestCase):
    def test_original_call_return_distinguishes_void_from_zero_on_both_architectures(self):
        observed=voids.return_observations()['cases']
        self.assertEqual(54,len(observed))
        for case in observed:
            register='eax' if case['architecture']=='x86' else 'rax'
            if case['handler_return'] is None:
                self.assertEqual(case['seed'],case['registers'][register])
                self.assertFalse(any(r==register for r,_ in case['writes']))
            else:
                self.assertEqual(case['handler_return'],case['registers'][register])
                self.assertTrue(any(r==register for r,_ in case['writes']))

    def test_review_has_eighteen_contracts_without_loading_the_legacy_runtime(self):
        with patch.dict(sys.modules,{'speakeasy':None,'speakeasy.binemu':None}):
            reviewed=voids.review()
        self.assertEqual(18,len(reviewed['contracts']))
        self.assertEqual({'x86','x64'},{r['architecture'] for r in reviewed['contracts']})
        self.assertTrue(all(len(r['call_names'])==3 for r in reviewed['contracts']))

    def test_fabricated_argument_count_and_unreviewed_dependencies_are_refused(self):
        manifest=copy.deepcopy(voids.load(voids.MANIFEST))
        manifest['entries'][0]['argc']+=1
        with self.assertRaises(AssertionError): voids.review(manifest)
        manifest=copy.deepcopy(voids.load(voids.MANIFEST))
        manifest['sources']['../unreviewed.py']='0'*64
        with self.assertRaises(AssertionError): voids.review(manifest)


if __name__=='__main__': unittest.main()
