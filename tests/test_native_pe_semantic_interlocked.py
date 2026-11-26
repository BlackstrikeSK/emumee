"""The contained checker must reject incorrect returns, memory and error routes."""
import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import native_pe_semantic_interlocked as semantic


class SemanticInterlockedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.controls=semantic.controls()

    def test_all_normal_error_and_dynamic_controls_are_required(self):
        self.assertEqual(133,len(self.controls))
        self.assertEqual(40,sum(s['kind']=='error' for s in self.controls.values()))
        self.assertEqual(2,sum(s['kind']=='dynamic' for s in self.controls.values()))

    def observation(self):
        name='X64-semantic-interlocked-InterlockedCompareExchange-000';spec=self.controls[name]
        events=[dict(api='kernel32.'+c['export']+suffix,arguments=c['arguments'],result=c['result'],
                     last_error=0x12345678,pending=False,error=None) for c in spec['cases'] for suffix in ('','A','W')]
        execution=dict(api_events_omitted=0,api_events=events,error=None,guest_entry_return=1,
            artifacts=[dict(size=65536,sha256=spec['cases'][-1]['arena_sha256'],
                observations=[dict(kind='guest_file',guest_path='c:\\guest\\interlocked-memory.bin')])])
        return name,spec,dict(result=dict(execution=execution))

    def test_valid_observation_uses_frozen_full_arena(self):
        name,spec,value=self.observation()
        with patch.object(semantic,'binding',return_value=value):
            self.assertEqual(spec['cases'][-1]['arena_sha256'],semantic.observations(Path('/root'),Path(name),spec)['arena_sha256'])

    def test_wrong_return_argument_memory_or_completion_is_rejected(self):
        name,spec,good=self.observation()
        for mutation in ('return','argument','memory','completion'):
            value=copy.deepcopy(good);e=value['result']['execution']
            if mutation=='return':e['api_events'][0]['result']+=1
            elif mutation=='argument':e['api_events'][0]['arguments']=[]
            elif mutation=='memory':e['artifacts'][0]['sha256']='0'*64
            else:e['guest_entry_return']=0
            with patch.object(semantic,'binding',return_value=value):
                with self.assertRaises(AssertionError,msg=mutation):semantic.observations(Path('/root'),Path(name),spec)


if __name__=='__main__':unittest.main()
