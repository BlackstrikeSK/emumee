"""Void replay cannot turn null results into success scalars or skip canaries."""
import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import native_pe_semantic_voids as semantic


class SemanticVoidTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.expected=semantic.controls()

    def test_both_architectures_argument_classes_and_dynamic_calls_are_required(self):
        self.assertEqual(26,len(self.expected))
        self.assertIn('X64-semantic-void-dynamic',self.expected)
        self.assertIn('X86-semantic-void-dynamic',self.expected)

    def observation(self):
        name='X64-semantic-void-kernel32-000-Arena';expected=self.expected[name]
        events=[dict(api=e['module']+'.'+n,effect='frozen_legacy_placeholder',result=None,
            arguments=[0x26000000]*e['argc'],last_error=0x12345678,pending=False,error=None)
            for e in expected for n in e['call_names']]
        execution=dict(error=None,guest_entry_return=1,api_events_omitted=0,api_events=events,
            artifacts=[dict(size=65536,sha256=semantic.ARENA_HASH,
                observations=[dict(kind='guest_file',guest_path='c:\\guest\\void-memory.bin')])])
        return name,expected,dict(result=dict(execution=execution))

    def test_valid_void_observations_match(self):
        name,expected,manifest=self.observation()
        with patch.object(semantic,'binding',return_value=manifest):
            result=semantic.observations(Path('/root'),Path('/fixtures')/name,expected)
        self.assertTrue(all(c['result'] is None for c in result['calls']))

    def test_scalar_zero_wrong_arguments_error_memory_or_guest_assertion_are_rejected(self):
        name,expected,good=self.observation()
        for mutation in ('zero','argument','error','arena','guest'):
            manifest=copy.deepcopy(good);e=manifest['result']['execution']
            if mutation=='zero': e['api_events'][0]['result']=0
            elif mutation=='argument': e['api_events'][0]['arguments']=[]
            elif mutation=='error': e['api_events'][0]['last_error']=0
            elif mutation=='arena': e['artifacts'][0]['sha256']='0'*64
            else: e['guest_entry_return']=0
            with patch.object(semantic,'binding',return_value=manifest):
                with self.assertRaises(AssertionError,msg=mutation):
                    semantic.observations(Path('/root'),Path('/fixtures')/name,expected)


if __name__=='__main__': unittest.main()
