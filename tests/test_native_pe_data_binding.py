"""Typed CRT data bindings cannot be mistaken for callable routines."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from native_api_parity_ledger import binding_for


class TypedDataBindingTests(unittest.TestCase):
    def test_typed_noncallable_data_is_bound_independently_of_routines(self):
        entry = dict(binding_kind='data', callable=False, dispatch='data_model')
        dispatch = {('msvcrt', '_acmdln', 'x64'): entry}
        self.assertEqual(entry, binding_for(dispatch, 'msvcrt', '_acmdln', 'data', 'x64'))
        self.assertIsNone(binding_for(dispatch, 'msvcrt', '_acmdln', 'function', 'x64'))
        self.assertIsNone(binding_for(dispatch, 'msvcrt', '_acmdln', 'data', 'x86'))

    def test_a_function_or_unmodeled_routine_does_not_establish_a_data_model(self):
        for entry in [dict(dispatch='model'), dict(binding_kind='data', dispatch='model', callable=False),
                      dict(binding_kind='data', dispatch='data_model', callable=True)]:
            self.assertIsNone(binding_for({('m', 'x', 'x86'): entry}, 'm', 'x', 'data', 'x86'))

    def test_existing_function_metadata_without_kind_remains_compatible(self):
        entry = dict(dispatch='model')
        self.assertEqual(entry, binding_for({('m', 'x', 'x86'): entry}, 'm', 'x', 'function', 'x86'))


if __name__ == '__main__':
    unittest.main()
