"""Source-only registration controls: no legacy import or callback execution."""
import ast
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import native_pe_registration as registration
from inventory_native_api import Inventory, Symbol, Unknown
from native_pe_worklist import fingerprint, registration_dependencies
from native_pe_validation import source_snapshot


class RegistrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.review = registration.Review(self.root)

    def handler(self, export='Probe', module='example', **extra):
        return dict(id='baseline', module=module, export=export, argc=7, convention='cdecl', **extra)

    def tables(self, handler=None):
        handler = handler or self.handler()
        return {handler['module']: {'function': {handler['export']: handler}, 'data': {}}}

    def hook(self, sequence=0, module='example', export='probe', **extra):
        return dict(sequence=sequence, module=module, export=export, argc=3, convention=None, **extra)

    def query(self, tables, hooks, export='Probe', module='example', kind='function'):
        return registration.disposition(tables, hooks, (module, export, kind, 'x86'))

    def walk(self, source, environment=None, strict=False):
        tree = ast.parse(source)
        functions = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
        methods = functions
        environment = {**{name: Symbol(name) for name in functions}, **(environment or {})}
        hooks = []
        self.review.walk(tree.body, environment, 'synthetic.py', functions, methods, hooks, {}, strict=strict)
        return hooks

    def test_supported_hooks_all_run_and_original_is_baseline(self):
        hooks = [self.hook(0), self.hook(1)]
        row = self.query(self.tables(), hooks)
        self.assertEqual([0, 1], row['invoked_hooks'])
        self.assertEqual('baseline', row['original_target'])
        self.assertEqual(1, row['return_hook'])
        self.assertEqual(7, row['argc'])
        self.assertEqual('cdecl', row['convention'])

    def test_unsupported_hook_uses_only_last_abi_and_no_original(self):
        row = self.query({}, [self.hook(0), self.hook(1)])
        self.assertEqual([1], row['invoked_hooks'])
        self.assertIsNone(row['original_target'])
        self.assertEqual(3, row['argc'])
        self.assertEqual('stdcall', row['convention'])
        self.assertEqual('last_hook_only', row['disposition'])

    def test_no_registration_does_not_claim_signature_semantics(self):
        row = self.query({}, [])
        self.assertEqual('no_registered_handler_or_hook', row['disposition'])
        self.assertFalse(row['invoked_hooks'])

    def test_exact_api_bucket_precedes_earlier_wildcard(self):
        hooks = [self.hook(0, export='pro*'), self.hook(1)]
        self.assertEqual([1, 0], [hook['sequence'] for hook in registration.matching_hooks(hooks, 'EXAMPLE', 'Probe')])

    def test_exact_module_bucket_precedes_earlier_wildcard(self):
        hooks = [self.hook(0, module='exam*'), self.hook(1)]
        self.assertEqual([1, 0], [hook['sequence'] for hook in registration.matching_hooks(hooks, 'example', 'probe')])

    def test_bucket_insertion_order_preserves_all_matching_hooks(self):
        hooks = [self.hook(0, export='p*'), self.hook(1, export='pr*'), self.hook(2, export='p*')]
        self.assertEqual([0, 2, 1], [hook['sequence'] for hook in registration.matching_hooks(hooks, 'example', 'probe')])

    def test_hook_patterns_include_decorated_question_marks_and_brackets(self):
        hooks = [self.hook(0, export='??3'), self.hook(1, export='[px]*')]
        self.assertEqual([0], [hook['sequence'] for hook in registration.matching_hooks(hooks, 'example', '??3')])
        self.assertEqual([1], [hook['sequence'] for hook in registration.matching_hooks(hooks, 'example', 'probe')])

    def test_ordinal_uses_named_baseline_hook_lookup(self):
        handler = self.handler('Init', ordinal=17)
        tables = self.tables(handler)
        tables['example']['function']['ordinal_17'] = handler
        row = self.query(tables, [self.hook(0, export='ordinal_17'), self.hook(1, export='init')], '#17')
        self.assertEqual('Init', row['hook_lookup_export'])
        self.assertEqual([1], row['invoked_hooks'])

    def test_unsupported_ordinal_keeps_ordinal_hook_lookup(self):
        row = self.query({}, [self.hook(0, export='ordinal_17')], '#17')
        self.assertEqual([0], row['invoked_hooks'])
        self.assertEqual('ordinal_17', row['hook_lookup_export'])

    def test_function_case_sensitive_but_hook_case_insensitive(self):
        row = self.query(self.tables(), [self.hook()], 'probe')
        self.assertEqual('last_hook_only', row['disposition'])

    def test_data_table_separate_from_functions_and_hooks(self):
        tables = self.tables()
        tables['example']['data']['Data'] = dict(id='data')
        row = self.query(tables, [self.hook(export='data')], 'Data', kind='data')
        self.assertEqual('registered_data_handler', row['disposition'])
        self.assertFalse(row['hooks'])
        self.assertEqual('no_data_handler', self.query(tables, [], 'data', kind='data')['disposition'])

    def test_generic_aw_lookup_uses_original_hook_name(self):
        tables = self.tables()
        row = self.query(tables, [self.hook(0), self.hook(1, export='probew')], 'ProbeW')
        self.assertEqual('normalized_import_miss', row['resolution'])
        self.assertEqual([1], row['invoked_hooks'])

    def test_crt_and_socket_module_aliases(self):
        for module, normalized in (('ucrtbase', 'msvcrt'), ('VCRUNTIME140', 'msvcrt'),
                                   ('api-ms-win-crt-string-l1-1-0', 'msvcrt'), ('wsock32', 'ws2_32'),
                                   ('winsock', 'ws2_32'), ('api-ms-win-core-example', 'kernel32')):
            with self.subTest(module=module):
                row = self.query(self.tables(self.handler(module=normalized)), [], module=module)
                self.assertEqual(normalized, row['baseline_module'])
        self.assertEqual('custom', registration.normalized_module('custom'))

    def test_alias_does_not_redirect_hook_module(self):
        row = self.query(self.tables(self.handler(module='msvcrt')), [self.hook(module='msvcrt')], module='ucrtbase')
        self.assertFalse(row['hooks'])

    def test_ntdll_kernel_nt_zw_fallback(self):
        tables = self.tables(self.handler('ZwProbe', module='ntoskrnl'))
        row = self.query(tables, [self.hook(module='ntdll', export='ntprobe')], 'NtProbe', 'ntdll')
        self.assertEqual('ntoskrnl', row['baseline_module'])
        self.assertEqual([0], row['invoked_hooks'])
        self.assertEqual('ntdll_kernel_fallback', row['resolution'])

    def test_literal_callbacks_are_never_executed(self):
        hooks = self.walk("emulator.add_api_hook(lambda emu, name, original, params: 1 / 0, 'example', 'Probe')")
        self.assertEqual(1, len(hooks))
        information = self.review.callbacks[hooks[0]['callback']]
        self.assertEqual('does_not_reference_original', information['disposition'])

    def test_original_delegation_calls_forwarding_and_guards_recorded(self):
        node = ast.parse('def callback(self, emu, name, original, params):\n if original:\n  forward(original, params)\n  return original(params)\n return 0').body[0]
        information = registration.callback_info(node, 'synthetic.py', True)
        self.assertEqual(['original(params)'], information['original_calls'])
        self.assertEqual(['forward(original, params)'], information['original_forwarding'])
        self.assertEqual(['original'], information['original_guards'])

    def test_literal_loops_preserve_registration_order(self):
        hooks = self.walk("for module in ('first', 'second'):\n for suffix in ('A', 'W'):\n  emulator.add_api_hook(lambda *args: None, module, 'Probe' + suffix, argc=1)")
        self.assertEqual([('first', 'probea'), ('first', 'probew'), ('second', 'probea'), ('second', 'probew')],
                         [(row['module'], row['export']) for row in hooks])

    def test_architecture_guard_selects_only_true_branch(self):
        source = "if info.architecture == 'x64':\n emulator.add_api_hook(lambda *args: None, 'example', 'Probe64')\nelse:\n emulator.add_api_hook(lambda *args: None, 'example', 'Probe32')"
        for architecture, export in (('x64', 'probe64'), ('x86', 'probe32')):
            with self.subTest(architecture=architecture):
                hooks = self.walk(source, {'info.architecture': architecture})
                self.assertEqual([export], [row['export'] for row in hooks])
                self.assertEqual(architecture == 'x64', hooks[0]['guards'][0]['value'])

    def test_pointer_size_guards(self):
        source = "if emulator.get_ptr_size() == 8:\n emulator.add_api_hook(lambda *args: None, 'example', 'Probe')"
        self.assertEqual(1, len(self.walk(source, {'pointer_size': 8})))
        self.assertEqual([], self.walk(source, {'pointer_size': 4}))

    def test_unknown_guard_never_becomes_truthy_symbol(self):
        for predicate in ('self.enabled', 'not self.enabled', 'self.enabled == True', 'self.enabled and True'):
            with self.subTest(predicate=predicate), self.assertRaises((Unknown, ValueError)):
                self.walk(f"if {predicate}:\n emulator.add_api_hook(lambda *args: None, 'example', 'Probe')")

    def test_unknown_early_return_guard_refuses_later_registration(self):
        with self.assertRaises((Unknown, ValueError)):
            self.walk("if not self.enabled:\n return\nemulator.add_api_hook(lambda *args: None, 'example', 'Probe')", strict=True)

    def test_resolved_return_stops_registration_scope(self):
        with self.assertRaises(registration.RegistrationReturn):
            self.walk("return\nemulator.add_api_hook(lambda *args: None, 'example', 'Probe')", strict=True)

    def test_nonselected_return_does_not_stop_scope(self):
        hooks = self.walk("if False:\n return\nemulator.add_api_hook(lambda *args: None, 'example', 'Probe')", strict=True)
        self.assertEqual(1, len(hooks))

    def test_unresolved_loop_and_unbounded_loop_refuse(self):
        for loop in ('dynamic_names', 'range(5000)'):
            with self.subTest(loop=loop), self.assertRaises((Unknown, ValueError)):
                self.walk(f"for name in {loop}:\n emulator.add_api_hook(lambda *args: None, 'example', name)")

    def test_unreviewed_exception_nested_and_while_registrations_refuse(self):
        for source in ("try:\n pass\nexcept Exception:\n emulator.add_api_hook(lambda *args: None, 'example', 'Probe')",
                       "def callback():\n emulator.add_api_hook(lambda *args: None, 'example', 'Probe')",
                       "while True:\n emulator.add_api_hook(lambda *args: None, 'example', 'Probe')"):
            with self.subTest(source=source), self.assertRaisesRegex(ValueError, 'review'):
                self.walk(source)

    def test_unknown_callback_install_and_keywords_refuse(self):
        for source in ("emulator.add_api_hook(missing_callback, 'example', 'Probe')", 'unknown.install(emulator)',
                       "emulator.add_api_hook(lambda *args: None, 'example', 'Probe', unknown=1)"):
            with self.subTest(source=source), self.assertRaises((Unknown, ValueError)):
                self.walk(source)

    def test_source_top_level_and_constructor_are_not_executed(self):
        path = self.root / 'source.py'
        path.write_text("raise RuntimeError('must not execute')\nclass Example:\n def __init__(self):\n  raise RuntimeError('must not execute')\n")
        tree = self.review.read('source.py')
        information = registration.constructor_info(tree.body[1].body[0], 'source.py')
        self.assertEqual('source_reviewed_not_executed', information['disposition'])

    def baseline_fixture(self, body):
        path = self.root / 'baseline.py'
        path.write_text(body)
        inventory = Inventory(self.root)
        inventory.speakeasy(path)
        return registration.baseline_tables(self.review, {'entries': inventory.entries})

    def test_python_method_duplicates_shadow_before_dir_registration(self):
        tables, declarations, _ = self.baseline_fixture("class Example(api.ApiHandler):\n name = 'example'\n @apihook('Old')\n def same(self): return 1\n @apihook('New')\n def same(self): return 2\n")
        self.assertNotIn('Old', tables['example']['function'])
        self.assertIn('New', tables['example']['function'])
        self.assertEqual('python_method_shadowed', declarations[0]['disposition'])

    def test_stacked_decorators_use_outermost_metadata_not_all_aliases(self):
        tables, declarations, _ = self.baseline_fixture("class Example(api.ApiHandler):\n name = 'example'\n @apihook('Outer')\n @apihook('Inner')\n def handler(self): return 1\n")
        self.assertEqual(['Outer'], list(tables['example']['function']))
        self.assertEqual(1, sum(row['disposition'] == 'decorator_metadata_shadowed' for row in declarations))

    def test_export_slot_collision_uses_sorted_method_order_not_source_order(self):
        tables, declarations, _ = self.baseline_fixture("class Example(api.ApiHandler):\n name = 'example'\n @apihook('Same')\n def zebra(self): return 1\n @apihook('Same')\n def alpha(self): return 2\n")
        self.assertEqual('zebra', tables['example']['function']['Same']['method'])
        self.assertEqual(1, sum(row['disposition'] == 'export_slot_overwritten_in_dir_order' for row in declarations))

    def test_data_metadata_and_ordinal_aliases(self):
        tables, _, _ = self.baseline_fixture("class Example(api.ApiHandler):\n name = 'example'\n @apihook('Named', ordinal=29)\n def function(self): return 0\n @impdata('Data')\n def data(self): return 0\n")
        self.assertIs(tables['example']['function']['Named'], tables['example']['function']['ordinal_29'])
        self.assertIn('Data', tables['example']['data'])

    def test_constructor_guards_and_state_are_retained_not_evaluated(self):
        node = ast.parse("def __init__(self, persona):\n self.enabled = persona['enabled']\n if self.enabled:\n  self.funcs = {}\n").body[0]
        information = registration.constructor_info(node, 'synthetic.py')
        self.assertEqual(['self.enabled'], information['guards'])
        self.assertIn("self.enabled = persona['enabled']", information['state_assignments'])

    def test_report_payload_summary_and_current_source_binding(self):
        current = dict(schema=1, scope=registration.SCOPE, review_complete=True, payload={'source': 'current'})
        current['review_fingerprint'] = fingerprint(current['payload'])
        registration.verify_report(copy.deepcopy(current), current)
        for key, replacement in (('schema', 2), ('scope', 'runtime qualified'), ('review_complete', 1),
                                  ('payload', {}), ('review_fingerprint', 'forged')):
            previous = copy.deepcopy(current)
            previous[key] = replacement
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'corrupt or stale'):
                registration.verify_report(previous, current)

    def test_policy_dependencies_are_source_indexed_and_cannot_escape(self):
        policy = self.root / registration.POLICY
        policy.parent.mkdir(parents=True)
        dependency = self.root / 'dependency.py'
        dependency.write_text('source')
        policy.write_text(json.dumps({'schema': 1, 'reviewed_sources': {'dependency.py': 'expected'}}))
        with patch('native_pe_validation.subprocess.run', return_value=subprocess.CompletedProcess([], 0, stdout=b'')):
            snapshot = source_snapshot(self.root)
        self.assertIn('dependency.py', snapshot)
        self.assertIn(registration.POLICY, snapshot)
        for relative in ('../outside.py', 'C:/outside.py', 'outside\\file.py'):
            policy.write_text(json.dumps({'schema': 1, 'reviewed_sources': {relative: 'expected'}}))
            with self.subTest(relative=relative), self.assertRaises(ValueError):
                registration_dependencies(self.root)

    def test_cli_refuses_overwrite_and_outside_output(self):
        for destination in (self.root / 'report.json', ROOT / 'output'):
            result = subprocess.run([sys.executable, str(ROOT / 'tools/native_pe_registration.py'),
                                     'audit', '--output', str(destination)], capture_output=True, text=True)
            self.assertEqual(2, result.returncode)
            self.assertIn('new --output', result.stderr)


class LiveRegistrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = registration.collect(ROOT)

    def test_exact_frozen_contract_and_hook_coverage(self):
        payload = self.report['payload']
        self.assertEqual(2590, len(payload['contracts']))
        self.assertEqual(2590, len(payload['module_load_contracts']))
        self.assertEqual(806, len(payload['baseline_declarations']))
        for architecture in ('x86', 'x64'):
            self.assertEqual(24, len(payload['architectures'][architecture]['installations']))
            self.assertEqual(514, len(payload['architectures'][architecture]['hooks']))

    def test_bridges_preserve_literal_placeholders_and_ordinal(self):
        rows = self.report['payload']['native_bridges']
        self.assertEqual(6, len(rows))
        self.assertTrue(all(row['baseline_literal_return_only'] and row['baseline_literal_result'] == 0 for row in rows))
        self.assertTrue(any(row['export'] == '#29' for row in rows))

    def test_post_load_table_patch_changes_dispatch_path(self):
        payload = self.report['payload']
        before = next(row for row in payload['module_load_contracts'] if row['export'] == 'LdrUnloadDll' and row['architecture'] == 'x86')
        after = next(row for row in payload['contracts'] if row['export'] == 'LdrUnloadDll' and row['architecture'] == 'x86')
        self.assertEqual('last_hook_only', before['disposition'])
        self.assertEqual('baseline_with_hooks', after['disposition'])
        self.assertTrue(payload['conditional_table_patch']['applied'])

    def test_x64_decoration_is_not_an_architecture_guard(self):
        for architecture in ('x86', 'x64'):
            hooks = self.report['payload']['architectures'][architecture]['hooks']
            self.assertEqual(1, sum(row['declared_export'] == '??3@YAXPEAX@Z' for row in hooks))

    def test_invented_double_width_names_stay_in_denominator_without_coverage(self):
        rows = [row for row in self.report['payload']['contracts'] if row['disposition'] == 'no_registered_handler_or_hook']
        self.assertEqual(16, len(rows))
        self.assertTrue(all(row['module'] == 'psapi' and row['export'].endswith(('AA', 'AW', 'WA', 'WW')) for row in rows))

    def test_reviewed_source_drift_refuses_even_with_unchanged_inventory(self):
        original = registration.Review.read
        relative = '.venv/Lib/site-packages/speakeasy/binemu.py'
        def changed(review, source):
            tree = original(review, source)
            if source == relative:
                review.sources[source] = '0' * 64
            return tree
        with patch.object(registration.Review, 'read', changed):
            with self.assertRaisesRegex(ValueError, 'source drift'):
                registration.collect(ROOT)

    def test_post_parse_source_and_runtime_drift_refuse(self):
        original = registration.Review.extensions
        def changed(review, architecture):
            hooks = original(review, architecture)
            if architecture == 'x64':
                review.sources['src/emumee/native.py'] = '0' * 64
            return hooks
        with patch.object(registration.Review, 'extensions', changed):
            with self.assertRaisesRegex(ValueError, 'changed after parsing'):
                registration.collect(ROOT)
        with patch.object(registration, 'runtime_snapshot', side_effect=[{}, {'source': 'changed'}]):
            with self.assertRaisesRegex(ValueError, 'Source changed during'):
                registration.collect(ROOT)


if __name__ == '__main__':
    unittest.main()
