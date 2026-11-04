"""Exact native partition controls, including the real frozen denominator."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import native_pe_batches as batching
import native_pe_status as status
from native_pe_worklist import contract_key, fingerprint, validate_batch_graph


class NativePeBatchTests(unittest.TestCase):
    def inventory(self):
        return {'schema': 1, 'sources': {}, 'unresolved': [], 'entries': [
            {'module': 'kernel32', 'export': 'Probe*', 'kind': 'function', 'ordinal': 7},
            {'module': 'kernel32', 'export': 'ProbeA', 'kind': 'function'},
            {'module': 'kernel32', 'export': 'VirtualAlloc', 'kind': 'function'},
            {'module': 'msvcrt', 'export': '_acmdln', 'kind': 'data'},
            {'module': 'msvcrt', 'export': 'printf', 'kind': 'function'},
            {'module': 'mscoree', 'export': '_CorExeMain', 'kind': 'function'},
            {'module': 'msi32', 'export': 'MsiProbe', 'kind': 'function'},
        ]}

    def rows(self, inventory):
        return [dict(zip(('module', 'export', 'kind', 'architecture'), key),
                     semantic_status='unreviewed', submitted_route='unreviewed',
                     source_fingerprint='synthetic', behavioral_evidence=[])
                for key in batching.inventory_contracts(inventory)]

    def worklist(self):
        return {'batches': [
            {'id': 'M0-effective-baseline', 'status': 'closed', 'depends_on': []},
            {'id': 'M4-user-scheduling', 'status': 'closed', 'depends_on': []},
            {'id': 'M5-M7-model-families', 'status': 'pending', 'depends_on': ['M4-user-scheduling']},
            {'id': 'M8-M11-qualification', 'status': 'pending', 'depends_on': ['M5-M7-model-families']},
        ]}

    def close(self, row):
        row.update(status='unverified_binding', semantic_status='verified_model', submitted_route='verified')
        row['behavioral_evidence'] = [{
            'id': 'synthetic-only', 'architecture': row['architecture'],
            'source_fingerprint': row['source_fingerprint'],
            'oracle': 'synthetic-properties', 'baseline': 'synthetic',
            'tests': ['positive'], 'negative_controls': ['negative'],
            'limits': {'instructions': 10},
        }]

    def test_real_frozen_partition_is_exact_canonical_and_acyclic(self):
        inventory = json.loads((ROOT / 'rust/api-parity/legacy-inventory.json').read_text())
        document = json.loads((ROOT / 'docs/native-pe/api-batches.json').read_text())
        rows = self.rows(inventory)
        assigned = batching.validate_partition(document, rows, fingerprint(inventory), inventory)
        self.assertEqual(len(assigned), 2590)
        self.assertEqual(len(document['batches']), 151)
        self.assertEqual(document, batching.partition(inventory))
        worklist = json.loads((ROOT / 'docs/native-pe/worklist.json').read_text())
        for batch in worklist['batches']:
            batch['status'] = 'pending'
            batch['blocker'] = None
        expanded = batching.expand_worklist(worklist, document, rows)
        self.assertTrue(validate_batch_graph(expanded))
        self.assertEqual({batch['id'] for batch in status.ready_batches(expanded)},
                         {'M0-effective-baseline', 'M1-closure-accounting'})
        next(batch for batch in expanded['batches'] if batch['id'] == 'M1-closure-accounting')['status'] = 'closed'
        self.assertEqual({batch['id'] for batch in status.ready_batches(expanded)}, {'M0-effective-baseline'})
        self.assertTrue(all(len(batch['contracts']) <= 32 for batch in document['batches']))

    def test_architectures_aliases_ordinals_and_overlapping_declarations_stay_together(self):
        inventory = self.inventory()
        document = batching.partition(inventory, max_contracts=8)
        assigned = batching.validate_partition(document, self.rows(inventory), fingerprint(inventory), inventory)
        group = {assigned[('kernel32', name, 'function', architecture)]
                 for name in ('ProbeA', 'ProbeW', '#7') for architecture in ('x86', 'x64')}
        self.assertEqual(len(group), 1)
        self.assertEqual(len(assigned), len(batching.inventory_contracts(inventory)))

    def test_batch_membership_is_stable_under_declaration_order_and_duplicates(self):
        inventory = self.inventory()
        baseline = batching.partition(inventory)['batches']
        inventory['entries'].reverse()
        self.assertEqual(batching.partition(inventory)['batches'], baseline)
        inventory['entries'].append(dict(inventory['entries'][0]))
        self.assertEqual(batching.partition(inventory)['batches'], baseline)

    def test_alias_component_cannot_be_split_to_meet_a_quota(self):
        with self.assertRaisesRegex(ValueError, 'Alias/architecture group'):
            batching.partition(self.inventory(), max_contracts=2)
        for bound in (True, 0, 1, 129, '32'):
            with self.assertRaises(ValueError):
                batching.partition(self.inventory(), max_contracts=bound)

    def test_data_batches_require_direct_memory_contracts_not_function_dispatch(self):
        document = batching.partition(self.inventory())
        data = [batch for batch in document['batches'] if batch['kind'] == 'data']
        self.assertEqual(len(data), 1)
        controls = ' '.join(data[0]['guest_controls']).lower()
        for obligation in ('address', 'size', 'alignment', 'mutability', 'aliases', 'lifetime'):
            self.assertIn(obligation, controls)
        self.assertEqual({member[3] for member in data[0]['contracts']}, {'x86', 'x64'})
        self.assertIn('out-of-bounds', ' '.join(data[0]['negative_controls']))

    def test_native_facing_clr_and_msi_are_explicit_not_scope_exclusions(self):
        document = batching.partition(self.inventory())
        bridges = [batch for batch in document['batches'] if batch['family'] == 'native-bridges']
        self.assertEqual({batch['module'] for batch in bridges}, {'mscoree', 'msi32'})
        self.assertTrue(all('M0-effective-baseline' in batch['depends_on'] for batch in bridges))

    def test_semantic_policy_separates_shared_state_not_only_dll_names(self):
        for module, export, family in (
            ('kernel32', 'VirtualAlloc', 'allocation'),
            ('kernel32', 'GetLastError', 'process'),
            ('kernel32', 'RaiseException', 'exceptions'),
            ('kernel32', 'GetSystemTimeAsFileTime', 'time'),
            ('kernel32', 'GetEnvironmentStringsW', 'environment'),
            ('kernel32', 'FindResourceExW', 'resources'),
            ('kernel32', 'ReadFile', 'filesystem'),
            ('ntdll', 'NtWaitForSingleObject', 'synchronization'),
            ('advapi32', 'RegOpenKeyExW', 'registry'),
            ('advapi32', 'CryptAcquireContextA', 'crypto'),
            ('msvcrt', 'malloc', 'allocation'),
            ('msvcrt', 'printf', 'crt-format'),
            ('msvcrt', 'fopen', 'crt-stdio'),
            ('msvcrt', 'sqrt', 'crt-math'),
        ):
            with self.subTest(module=module, export=export):
                self.assertEqual(batching.family_for(module, [export]), family)
        with self.assertRaisesRegex(ValueError, 'Unreviewed module'):
            batching.family_for('new-unreviewed-dll', ['Probe'])

    def test_missing_orphan_duplicate_malformed_and_wrong_architecture_rows_fail(self):
        inventory = self.inventory()
        baseline = batching.partition(inventory)
        for operation in ('missing', 'orphan', 'duplicate', 'malformed', 'architecture', 'kind'):
            document = copy.deepcopy(baseline)
            batch = document['batches'][0]
            if operation == 'missing':
                batch['contracts'].pop()
            elif operation == 'orphan':
                batch['contracts'].append(['kernel32', 'NotInBaseline', 'function', 'x64'])
            elif operation == 'duplicate':
                batch['contracts'].append(batch['contracts'][0])
            elif operation == 'malformed':
                batch['contracts'][0] = ['kernel32']
            elif operation == 'architecture':
                batch['contracts'][0][3] = 'arm64'
            else:
                batch['contracts'][0][2] = 'data'
            with self.subTest(operation=operation), self.assertRaises(ValueError):
                batching.validate_partition(document, self.rows(inventory), fingerprint(inventory), inventory)

    def test_unreviewed_policy_controls_identity_and_dependencies_cannot_drift(self):
        inventory = self.inventory()
        baseline = batching.partition(inventory)
        for field in ('depends_on', 'shared_state', 'oracle', 'guest_controls', 'negative_controls', 'next_action', 'exit_tests'):
            document = copy.deepcopy(baseline)
            del document['batches'][0][field]
            with self.subTest(field=field), self.assertRaises(ValueError):
                batching.validate_partition(document, self.rows(inventory), fingerprint(inventory), inventory)
        for field, value in (('shared_state', 'invented'), ('depends_on', ['imaginary']),
                             ('oracle', 'self-certifying fixture'), ('id', 'unbound-id')):
            document = copy.deepcopy(baseline)
            document['batches'][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                batching.validate_partition(document, self.rows(inventory), fingerprint(inventory), inventory)
        with self.assertRaisesRegex(ValueError, 'fingerprint differs'):
            batching.validate_partition(baseline, self.rows(inventory), 'changed')

    def test_batch_progress_is_computed_from_every_member_not_manual_flags(self):
        inventory = self.inventory()
        document = batching.partition(inventory)
        rows = self.rows(inventory)
        worklist = self.worklist()
        expanded = batching.expand_worklist(worklist, document, rows)
        qualification = next(batch for batch in expanded['batches'] if batch['id'] == 'M8-M11-qualification')
        self.assertEqual(set(qualification['depends_on']), {batch['id'] for batch in document['batches']})
        self.assertNotIn('M5-M7-model-families', {batch['id'] for batch in expanded['batches']})
        for row in rows:
            self.close(row)
        expanded = batching.expand_worklist(worklist, document, rows)
        self.assertTrue(all(batch['status'] == 'closed' for batch in expanded['batches'] if batch['id'].startswith('api:')))
        rows[0]['semantic_status'] = 'stale'
        expanded = batching.expand_worklist(worklist, document, rows)
        target = next(batch for batch in expanded['batches'] if list(contract_key(rows[0])) in batch.get('contracts', []))
        self.assertEqual(target['status'], 'pending')
        self.assertNotIn('M8-M11-qualification', {batch['id'] for batch in status.ready_batches(expanded)})

    def test_unproved_or_missing_binding_member_cannot_close_a_batch(self):
        inventory = self.inventory()
        document = batching.partition(inventory)
        rows = self.rows(inventory)
        for row in rows:
            self.close(row)
        rows[0]['behavioral_evidence'] = []
        with self.assertRaisesRegex(ValueError, 'requires behavioral evidence'):
            batching.expand_worklist(self.worklist(), document, rows)
        self.close(rows[0])
        rows[0]['status'] = 'missing_binding'
        expanded = batching.expand_worklist(self.worklist(), document, rows)
        self.assertTrue(any(batch['status'] == 'pending' for batch in expanded['batches'] if batch['id'].startswith('api:')))

    def test_blockers_and_graph_errors_remain_actionable(self):
        inventory = self.inventory()
        document = batching.partition(inventory)
        rows = self.rows(inventory)
        rows[0].update(semantic_status='blocked', blocker='synthetic missing observation')
        expanded = batching.expand_worklist(self.worklist(), document, rows)
        blocked = [batch for batch in expanded['batches'] if batch['status'] == 'blocked']
        self.assertEqual(len(blocked), 1)
        self.assertEqual(blocked[0]['blocker'], ['synthetic missing observation'])
        for dependencies in (['absent'], ['M0-effective-baseline'],
                             ['M4-user-scheduling', 'M4-user-scheduling'], 'not-a-list'):
            worklist = self.worklist()
            worklist['batches'][0]['depends_on'] = dependencies
            with self.assertRaises(ValueError):
                validate_batch_graph(batching.expand_worklist(worklist, document, rows))

    def test_frozen_cli_requires_review_and_never_rewrites_failed_check(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory_path = root / 'inventory.json'
            output = root / 'partition.json'
            inventory = self.inventory()
            inventory_path.write_text(json.dumps(inventory), encoding='utf-8')
            command = [sys.executable, str(ROOT / 'tools/native_pe_batches.py'),
                       '--inventory', str(inventory_path), '--output', str(output)]

            def run(*arguments, success=True):
                result = subprocess.run([*command, *arguments], capture_output=True, text=True)
                self.assertEqual(result.returncode == 0, success, result.stderr)

            run('--check', success=False)
            self.assertFalse(output.exists())
            run()
            original = output.read_bytes()
            run('--check')
            self.assertEqual(output.read_bytes(), original)
            inventory['entries'].append({'module': 'kernel32', 'export': 'NewProbe', 'kind': 'function'})
            inventory_path.write_text(json.dumps(inventory), encoding='utf-8')
            run(success=False)
            self.assertEqual(output.read_bytes(), original)
            run('--refresh', '--check', success=False)
            self.assertEqual(output.read_bytes(), original)
            run('--refresh')
            self.assertNotEqual(output.read_bytes(), original)
            run('--check')


if __name__ == '__main__':
    unittest.main()
