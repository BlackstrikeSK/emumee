"""Independent semantic replay controls, including tampered observations."""
import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import native_pe_semantic_strlen as semantic


class SemanticStrlenTests(unittest.TestCase):
    def test_requalification_uses_a_distinct_immutable_proof_path(self):
        root = Path('/qualification')
        with patch.object(semantic, 'runtime_snapshot', return_value={'source': 'one'}):
            first = semantic.proof_path(root)
        with patch.object(semantic, 'runtime_snapshot', return_value={'source': 'two'}):
            second = semantic.proof_path(root)
        self.assertNotEqual(first, second)
        self.assertEqual(root, first.parent)

    def observation(self):
        name = 'X64-semantic-lstrlenA-001'
        oracle = semantic.oracle_for(name)
        return name, {'result': {'execution': {
            'error': None, 'guest_entry_return': 1,
            'api_events': [dict(api='kernel32.lstrlenA', arguments=[0x26000000],
                result=oracle['result'], last_error=oracle['last_error'], pending=False, error=None)],
            'artifacts': [dict(size=0x10000, sha256=oracle['memory_sha256'],
                observations=[dict(kind='guest_file', guest_path='c:\\guest\\strlen-memory.bin')])],
        }}}

    def test_every_architecture_export_and_oracle_case_is_required(self):
        self.assertEqual(12, len(semantic.required_cases()))
        for name in semantic.required_cases():
            oracle = semantic.oracle_for(name)
            self.assertFalse(oracle['unsupported'])

    def test_valid_observation_matches_independent_frozen_oracle(self):
        name, value = self.observation()
        with patch.object(semantic, 'binding', return_value=value):
            actual = semantic.observations(Path('/qualification'), Path('/fixtures') / name)
        self.assertEqual(2, actual['result'])
        self.assertEqual(0x12345678, actual['last_error'])

    def test_wrong_return_error_argument_or_memory_hash_is_rejected(self):
        name, valid = self.observation()
        for mutation in ('result', 'last_error', 'arguments', 'arena', 'pending'):
            value = copy.deepcopy(valid)
            execution = value['result']['execution']
            if mutation == 'arena':
                execution['artifacts'][0]['sha256'] = '0' * 64
            elif mutation == 'arguments':
                execution['api_events'][0]['arguments'] = [0]
            elif mutation == 'pending':
                execution['api_events'][0]['pending'] = True
            else:
                execution['api_events'][0][mutation] += 1
            with patch.object(semantic, 'binding', return_value=value):
                with self.assertRaises(AssertionError, msg=mutation):
                    semantic.observations(Path('/qualification'), Path('/fixtures') / name)


if __name__ == '__main__':
    unittest.main()
