"""Static parity accounting must fail visibly when registrations cannot resolve."""
import importlib.util
from pathlib import Path
import tempfile
import textwrap
import unittest

SOURCE = Path(__file__).resolve().parents[1] / 'tools/inventory_native_api.py'
SPEC = importlib.util.spec_from_file_location('native_api_inventory', SOURCE)
inventory = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(inventory)

class NativeApiInventoryTests(unittest.TestCase):
    def test_absent_or_empty_baseline_never_silently_reduces_inventory(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            with self.assertRaisesRegex(ValueError, 'missing or empty'):
                inventory.baseline_sources(root)
            baseline = root / '.venv/Lib/site-packages/speakeasy/winenv/api/usermode'
            baseline.mkdir(parents=True)
            with self.assertRaisesRegex(ValueError, 'missing or empty'):
                inventory.baseline_sources(root)
            (baseline / 'synthetic.py').write_text('', encoding='utf-8')
            self.assertEqual(len(inventory.baseline_sources(root)), 1)

    def scan(self, source, extension=False):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            path = root / 'synthetic.py'
            path.write_text(textwrap.dedent(source), encoding='utf-8')
            result = inventory.Inventory(root)
            (result.extension if extension else result.speakeasy)(path)
            return result

    def test_literal_stub_classification_never_accepts_delegation_or_mutation(self):
        result = self.scan('''
            class Handler:
                name = 'synthetic'
                @apihook('Literal', argc=1)
                def literal(self):
                    return 0
                @apihook('Delegated', argc=1)
                def delegated(self):
                    return self.model()
                @apihook('Mutation', argc=1)
                def mutation(self):
                    self.state = 1
                    return 0
                @impdata('Global')
                def data(self):
                    return self.allocate()
        ''')
        rows = {r['export']:r for r in result.entries}
        self.assertTrue(rows['Literal']['literal_return_only'])
        self.assertFalse(rows['Delegated']['literal_return_only'])
        self.assertFalse(rows['Mutation']['literal_return_only'])
        self.assertEqual(rows['Global']['kind'], 'data')
        self.assertFalse(result.unresolved)

    def test_registration_loops_preserve_each_alias_and_calling_convention(self):
        result = self.scan('''
            def install(self, emu):
                for module in ('first', 'second'):
                    for suffix in ('A', 'W'):
                        emu.add_api_hook(self.handler, module, 'Probe'+suffix,
                                         argc=2, call_conv=arch.CALL_CONV_CDECL)
        ''', extension=True)
        self.assertEqual({(r['module'],r['export'],r['argc'],r['convention']) for r in result.entries},
                         {(m,'Probe'+s,2,'cdecl') for m in ('first','second') for s in ('A','W')})
        self.assertFalse(result.unresolved)

    def test_dynamic_registration_is_an_explicit_gap_and_source_is_not_executed(self):
        result = self.scan('''
            raise RuntimeError('AST inventory must not execute this module')
            def install(self, emu, runtime_module):
                emu.add_api_hook(self.handler, runtime_module, 'Probe', argc=1)
        ''', extension=True)
        self.assertFalse(result.entries)
        self.assertEqual(len(result.unresolved),1)
        self.assertIn('runtime_module',result.unresolved[0]['reason'])
        self.assertEqual(len(result.sources),1)

if __name__ == '__main__':
    unittest.main()
