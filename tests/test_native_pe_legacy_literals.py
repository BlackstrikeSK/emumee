"""Independent AST/alias evidence for reviewed return-only legacy handlers."""
import copy
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import native_pe_legacy_literals as literals


class LegacyLiteralOracleTests(unittest.TestCase):
    def test_review_covers_every_contract_without_importing_the_legacy_engine(self):
        with patch.dict(sys.modules, {'speakeasy': None, 'speakeasy.common': None}):
            result = literals.review()
        self.assertEqual(156, len(result['contracts']))
        self.assertEqual({'x86', 'x64'}, {r['architecture'] for r in result['contracts']})
        self.assertEqual(78, len({(r['module'], r['export']) for r in result['contracts']}))

    def test_a_fabricated_value_or_argument_count_cannot_certify_itself(self):
        for field in ('value', 'argc'):
            manifest = copy.deepcopy(literals.load(literals.MANIFEST))
            manifest['entries'][0][field] += 1
            with self.assertRaises(AssertionError, msg=field):
                literals.review(manifest)

    def test_unknown_sources_and_ordinal_claims_are_refused(self):
        manifest = copy.deepcopy(literals.load(literals.MANIFEST))
        manifest['sources']['../unreviewed.py'] = '0' * 64
        with self.assertRaises(AssertionError):
            literals.review(manifest)
        manifest = copy.deepcopy(literals.load(literals.MANIFEST))
        manifest['entries'][0]['export'] = '#2'
        with self.assertRaisesRegex(AssertionError, 'Ordinal'):
            literals.review(manifest)

    def test_original_width_alias_rule_does_not_invent_unknown_or_ntdll_exports(self):
        factory, _ = literals.normalizer_factory()
        instance = factory()
        instance.api = SimpleNamespace(get_export_func_handler=lambda module, name:
            (module, ('BitBlt', 9)) if name == 'BitBlt' and module == 'gdi32' else (None, None))
        self.assertEqual(('gdi32', ('BitBlt', 9)), instance.normalize_import_miss('gdi32', 'BitBltW'))
        self.assertEqual((None, None), instance.normalize_import_miss('gdi32', 'UnknownW'))
        self.assertEqual((None, None), instance.normalize_import_miss('ntdll', 'BitBltW'))


if __name__ == '__main__':
    unittest.main()
