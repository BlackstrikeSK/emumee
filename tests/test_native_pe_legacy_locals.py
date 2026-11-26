"""Only proved local assignments may become frozen scalar placeholders."""
import ast
import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import native_pe_legacy_locals as locals_oracle


class LegacyLocalConstantTests(unittest.TestCase):
    def function(self, body):
        return ast.parse('def handler(self, emu, argv, ctx=None):\n'+
                         '\n'.join('    '+line for line in body.splitlines())).body[0]

    def test_live_thirty_six_contracts_are_proved_without_legacy_imports(self):
        with patch.dict(sys.modules,{'speakeasy':None,'speakeasy.common':None}):
            result=locals_oracle.review()
        self.assertEqual(36,len(result['contracts']))
        self.assertEqual({'x86','x64'},{r['architecture'] for r in result['contracts']})

    def test_memory_calls_attributes_argument_mutations_branches_and_early_returns_are_refused(self):
        for body in (
            'x, = argv\nrv = 1\nself.mem_write(x, b"x")\nreturn rv',
            'x, = argv\nrv = self.mem_read(x, 4)\nreturn rv',
            'self.result = 1\nreturn 1',
            'argv[0] = 1\nreturn 1',
            'argv = 1\nreturn 1',
            'x, = argv\nrv = 1\nif x:\n    rv = 2\nreturn rv',
            'return 1\nrv = 2\nreturn rv',
            'x, = argv\nreturn x',
        ):
            with self.assertRaises(AssertionError,msg=body):
                locals_oracle.constant_result(self.function(body),1)

    def test_constant_result_cannot_hide_an_argument_unpack_arity_failure(self):
        function=self.function('x, = argv\nrv = True\nreturn rv')
        self.assertEqual(1,locals_oracle.constant_result(function,1))
        with self.assertRaises(AssertionError): locals_oracle.constant_result(function,2)

    def test_manifest_cannot_fabricate_the_return_count_or_source_set(self):
        for field in ('value','argc'):
            manifest=copy.deepcopy(locals_oracle.load(locals_oracle.MANIFEST))
            manifest['entries'][0][field]+=1
            with self.assertRaises(AssertionError,msg=field): locals_oracle.review(manifest)
        manifest=copy.deepcopy(locals_oracle.load(locals_oracle.MANIFEST))
        manifest['sources']['../unreviewed.py']='0'*64
        with self.assertRaises(AssertionError): locals_oracle.review(manifest)


if __name__=='__main__': unittest.main()
