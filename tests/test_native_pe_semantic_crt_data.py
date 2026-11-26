"""Accepted data behavior still needs identity, lifetime and actual NX evidence."""
import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import native_pe_semantic_crt_data as semantic


class SemanticCrtDataTests(unittest.TestCase):
    def test_frozen_reference_establishes_a_real_departure(self):
        oracle,decision=semantic.reference()
        self.assertEqual(4,len(oracle['contracts']))
        self.assertEqual('Keep documented Rust improvements (Recommended)',decision['decision'])
        for case in oracle['cases']:
            self.assertNotEqual(case['imported_cell'],case['first_accessor_cell'])
            self.assertNotEqual(case['first_accessor_cell'],case['second_accessor_cell'])

    def test_unaccepted_policy_is_rejected(self):
        original=semantic.load
        def load(path):
            value=original(path)
            if path==semantic.DECISION:value['decision']='unreviewed'
            return value
        with patch.object(semantic,'load',side_effect=load),self.assertRaisesRegex(AssertionError,'accepted'):
            semantic.reference()

    def observation(self,kind='Alias'):
        address=0x76000000
        execution=dict(crt_startup=dict(msvcrt_command_line=dict(address=address,size=4096)),
            api_events_omitted=0,error=None,guest_entry_return=1,completion_reason='returned',
            api_events=[dict(api='msvcrt.__p__acmdln',result=address,pending=False,error=None) for _ in range(3)])
        return Path(f'X64-m5-crt-data-{kind}-20000'),dict(result=dict(execution=execution))

    def test_mutable_identity_cannot_be_replaced_by_fresh_accessor_cells(self):
        fixture,good=self.observation()
        with patch.object(semantic,'binding',return_value=good):semantic.observations(Path('/root'),fixture)
        bad=copy.deepcopy(good);bad['result']['execution']['api_events'][-1]['result']+=4096
        with patch.object(semantic,'binding',return_value=bad),self.assertRaises(AssertionError):semantic.observations(Path('/root'),fixture)

    def test_execution_fault_must_be_at_the_actual_data_address(self):
        fixture,value=self.observation('Nx');e=value['result']['execution']
        e.update(error='execution denied',guest_entry_return=None,native_memory_fault=dict(access='read',address=0x76000000))
        with patch.object(semantic,'binding',return_value=value),self.assertRaises(AssertionError):semantic.observations(Path('/root'),fixture)
        e['native_memory_fault']['access']='execute'
        with patch.object(semantic,'binding',return_value=value):semantic.observations(Path('/root'),fixture)


if __name__=='__main__':unittest.main()
