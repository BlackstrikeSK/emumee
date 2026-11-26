"""Literal qualifier coverage and independent observation negative controls."""
import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import native_pe_semantic_literals as semantic


class SemanticLiteralTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.expected = semantic.controls()

    def test_all_architectures_groups_argument_classes_and_dynamic_aliases_are_required(self):
        self.assertEqual(146, len(self.expected))
        self.assertIn('X86-semantic-literal-dynamic', self.expected)
        self.assertIn('X64-semantic-literal-dynamic', self.expected)
        self.assertTrue(any(n.endswith('-Arena') for n in self.expected))
        self.assertTrue(any(n.endswith('-Poison') for n in self.expected))

    def observation(self):
        name = 'X64-semantic-literal-gdi32-000-Arena'
        expected = self.expected[name]
        events = [dict(api=e['module'] + '.' + n, effect='frozen_legacy_placeholder',
                       result=e['oracle_value'], arguments=[0x26000000] * e['argc'],
                       last_error=0x12345678, pending=False, error=None)
                  for e in expected for n in e['call_names']]
        return name, expected, {'result': {'execution': dict(error=None, guest_entry_return=1,
            api_events_omitted=0, api_events=events, artifacts=[dict(size=65536, sha256=semantic.ARENA_HASH,
                observations=[dict(kind='guest_file', guest_path='c:\\guest\\literal-memory.bin')])])}}

    def test_frozen_body_results_and_full_arena_match(self):
        name, expected, manifest = self.observation()
        with patch.object(semantic, 'binding', return_value=manifest):
            result = semantic.observations(Path('/root'), Path('/fixtures') / name, expected)
        self.assertEqual(semantic.ARENA_HASH, result['arena_sha256'])

    def test_wrong_result_argument_effect_or_memory_is_refused(self):
        name, expected, good = self.observation()
        for mutation in ('return', 'argument', 'effect', 'arena'):
            manifest = copy.deepcopy(good)
            execution = manifest['result']['execution']
            if mutation == 'arena': execution['artifacts'][0]['sha256'] = '0' * 64
            elif mutation == 'effect': execution['api_events'][0]['effect'] = None
            elif mutation == 'argument': execution['api_events'][0]['arguments'] = []
            else: execution['api_events'][0]['result'] += 1
            with patch.object(semantic, 'binding', return_value=manifest):
                with self.assertRaises(AssertionError, msg=mutation):
                    semantic.observations(Path('/root'), Path('/fixtures') / name, expected)


if __name__ == '__main__':
    unittest.main()
