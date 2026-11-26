"""Independent frozen string reference integrity and pointer-discriminant controls."""
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import native_pe_winstrings_reference as reference


class WindowsStringReferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = reference.observe()

    def test_source_reproduction_matches_the_checked_in_observations(self):
        path = ROOT / 'rust/emumee-engine/src/api/winstrings_semantic_reference.json'
        self.assertEqual(json.loads(path.read_bytes()), self.document)
        self.assertEqual(json.loads(json.dumps(self.document)), self.document)
        self.assertEqual(len(self.document['contracts']), 42)
        self.assertEqual(len(self.document['cases']), 1004)

    def test_case_identities_are_unique_and_cover_every_claimed_contract(self):
        cases = self.document['cases']
        identities = [(c['module'], c['export'], c['width'], c['label']) for c in cases]
        self.assertEqual(len(identities), len(set(identities)))
        contracts = {(c['module'], c['export'], 'function', 'x64' if c['width'] == 8 else 'x86') for c in cases}
        self.assertEqual(contracts, {tuple(c) for c in self.document['contracts']})

    def test_char_upper_has_distinct_scalar_and_real_buffer_controls(self):
        cases = [c for c in self.document['cases'] if c['export'] == 'CharUpperW' and c['module'] == 'user32']
        for width in (4, 8):
            selected = [c for c in cases if c['width'] == width]
            self.assertTrue(any(c['label'].startswith('scalar-') and c['arguments'][0] <= 0xffff for c in selected))
            self.assertTrue(any(c['label'].startswith('vector-') and c['arguments'][0] == reference.BASE
                                and not c['unsupported'] for c in selected))

    def test_null_trim_target_is_not_an_unsupported_operation(self):
        cases = [c for c in self.document['cases'] if c['export'] == 'StrTrimW' and c['label'] == 'null-0']
        self.assertEqual({c['width'] for c in cases}, {4, 8})
        for case in cases:
            self.assertEqual(case['result'], 0)
            self.assertFalse(case['unsupported'])
            self.assertEqual(case['last_error'], 0x12345678)

    def test_api_set_nested_pointer_and_permission_controls_are_explicit(self):
        for case in self.document['cases']:
            if case['export'] != 'ApiSetQueryApiSetPresence':
                continue
            header = next(p for p in case['patches'] if p['address'] == reference.BASE + 0x1000)
            offset = 8 if case['width'] == 8 else 4
            pointer = int.from_bytes(bytes.fromhex(header['hex'])[offset:offset + case['width']], 'little')
            self.assertEqual(pointer, reference.BASE)
        for contract in self.document['contracts']:
            module, export, _, architecture = contract
            width = 8 if architecture == 'x64' else 4
            protections = {c['protection'] for c in self.document['cases']
                           if (c['module'], c['export'], c['width']) == (module, export, width)}
            self.assertEqual(protections, {0, 1, 2, 3})


if __name__ == '__main__':
    unittest.main()
