"""Frozen arithmetic quirks must not silently become host-width operations."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import native_pe_interlocked_reference as reference


class InterlockedReferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.document=reference.observe()

    def find(self,name,old,tail):
        return next(c for c in self.document['cases'] if c['architecture']=='x64' and c['export']==name
                    and c['old']==old and c['arguments'][1:]==tail and 'synthetic_access' not in c)

    def test_complete_reference_requires_no_legacy_imports(self):
        with patch.dict(sys.modules,{'speakeasy':None,'speakeasy.common':None}):
            document=reference.observe()
        self.assertEqual(378,len(document['cases']));self.assertEqual(10,len(document['contracts']))
        self.assertEqual({'x86','x64'},{c['architecture'] for c in document['cases']})

    def test_wrap_add_compare_and_conversion_have_distinct_frozen_rules(self):
        self.assertEqual(0,self.find('InterlockedIncrement',0xffffffff,[])['new'])
        self.assertEqual(0xffffffff,self.find('InterlockedDecrement',0,[])['new'])
        self.assertEqual(1,self.find('InterlockedExchangeAdd',1,[0x100000000])['new'])
        miss=self.find('InterlockedCompareExchange',0xffffffff,[1,0xffffffffffffffff])
        self.assertEqual(0xffffffff,miss['new']);self.assertIsNone(miss['error'])
        overflow=self.find('InterlockedExchange',1,[0x100000000])
        self.assertEqual('OverflowError',overflow['error']);self.assertEqual(1,overflow['new'])

    def test_denial_controls_preserve_memory_and_last_error(self):
        controls=[c for c in self.document['cases'] if 'synthetic_access' in c]
        self.assertEqual(20,len(controls))
        self.assertTrue(all(c['error']=='MemoryError' and c['old']==c['new'] and c['last_error']==0x12345678 for c in controls))


if __name__=='__main__':unittest.main()
