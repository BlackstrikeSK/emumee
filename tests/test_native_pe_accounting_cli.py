"""Exercise the actual static audit, ledger regeneration and status entrypoints."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import native_pe_status as status
import audit_native_surface as surface
import native_pe_batches as batching


class NativePeAccountingCliTests(unittest.TestCase):
    def test_audit_is_static_and_retains_nested_hook_sites_without_claiming_activation(self):
        result = surface.audit_source('''
raise RuntimeError("never execute this module")
def run_native(data, guest_env=None):
    bridge.install(se)
    if data:
        se.add_api_hook(handler, "kernel32", "Probe")
    report["events"] = []
    return {"engine": "synthetic", "errors": []}
''')
        self.assertEqual(result['runner_parameters'], ['data', 'guest_env'])
        self.assertEqual(len(result['install_call_sites']), 1)
        self.assertEqual(len(result['hook_call_sites']), 1)
        self.assertEqual(result['summary_keys'], ['engine', 'errors'])
        self.assertEqual(result['effective_registration_review'], 'unreviewed')

    def test_dependency_graph_rejects_unknown_duplicate_and_cyclic_batches(self):
        for batches in (
            [{'id': 'a', 'depends_on': ['missing'], 'status': 'pending'}],
            [{'id': 'a', 'depends_on': [], 'status': 'pending'}] * 2,
            [{'id': 'a', 'depends_on': ['b'], 'status': 'pending'},
             {'id': 'b', 'depends_on': ['a'], 'status': 'pending'}],
        ):
            with self.assertRaises(ValueError):
                status.ready_batches({'batches': batches})
        batches = [
            {'id': 'done', 'depends_on': [], 'status': 'closed'},
            {'id': 'next', 'depends_on': ['done'], 'status': 'pending'},
            {'id': 'later', 'depends_on': ['next'], 'status': 'pending'},
        ]
        self.assertEqual([batch['id'] for batch in status.ready_batches({'batches': batches})], ['next'])

    def test_ledger_cli_preserves_closure_and_retires_reviewed_inventory_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory = root / 'inventory.json'
            dispatch = root / 'dispatch.json'
            output = root / 'ledger.json'
            partition_path = root / 'batches.json'
            relative = 'tools/inventory_native_api.py'
            legacy = {
                'scope': 'synthetic-control', 'unresolved': [],
                'sources': {relative: hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()},
                'entries': [{'module': 'kernel32', 'export': 'Probe', 'kind': 'function'}],
            }
            bindings = {'entries': [
                {'module': 'kernel32', 'export': 'Probe', 'architecture': architecture,
                 'dispatch': 'synthetic-model'} for architecture in ('x86', 'x64')
            ]}
            inventory.write_text(json.dumps(legacy), encoding='utf-8')
            dispatch.write_text(json.dumps(bindings), encoding='utf-8')
            partition_path.write_text(json.dumps(batching.partition(legacy)), encoding='utf-8')
            command = [sys.executable, str(ROOT / 'tools/native_api_parity_ledger.py'),
                       '--inventory', str(inventory), '--dispatch', str(dispatch),
                       '--partition', str(partition_path), '--output', str(output)]

            def run(*extra, success=True):
                result = subprocess.run([*command, *extra], capture_output=True, text=True)
                self.assertEqual(result.returncode == 0, success, result.stderr)
                return result

            run()
            ledger = json.loads(output.read_text())
            self.assertEqual(len(ledger['entries']), 2)
            self.assertFalse(ledger['complete'])
            status_command = [sys.executable, str(ROOT / 'tools/native_pe_status.py'),
                              '--ledger', str(output), '--partition', str(partition_path)]
            original_partition = partition_path.read_bytes()
            corrupt_partition = json.loads(original_partition)
            corrupt_partition['batches'] = []
            partition_path.write_text(json.dumps(corrupt_partition), encoding='utf-8')
            before = output.read_bytes()
            run(success=False)
            self.assertEqual(output.read_bytes(), before)
            refused = subprocess.run(status_command, capture_output=True, text=True)
            self.assertNotEqual(refused.returncode, 0)
            self.assertNotIn('Traceback', refused.stderr)
            partition_path.write_bytes(original_partition)
            old_ledger = dict(ledger)
            del old_ledger['partition_fingerprint']
            output.write_text(json.dumps(old_ledger), encoding='utf-8')
            refused = subprocess.run(status_command, capture_output=True, text=True)
            self.assertNotEqual(refused.returncode, 0)
            self.assertIn('regenerate', refused.stderr)
            self.assertNotIn('Traceback', refused.stderr)
            output.write_bytes(before)
            closed = ledger['entries'][0]
            closed.update(semantic_status='verified_model', submitted_route='verified')
            closed['behavioral_evidence'] = [{
                'id': 'synthetic-only', 'architecture': closed['architecture'],
                'source_fingerprint': closed['source_fingerprint'],
                'oracle': 'synthetic', 'baseline': 'synthetic', 'tests': ['positive'],
                'negative_controls': ['negative'], 'limits': {'instructions': 10},
            }]
            ledger['required_gates']['source_regression'] = {
                'status': 'verified', 'scope_fingerprint': ledger['scope_fingerprint'],
                'evidence': ['synthetic-only'],
            }
            output.write_text(json.dumps(ledger), encoding='utf-8')
            run()
            regenerated = json.loads(output.read_text())
            self.assertEqual(regenerated['entries'][0]['behavioral_evidence'], closed['behavioral_evidence'])
            self.assertFalse(regenerated['complete'])
            regenerated['runtime_source_hashes']['Cargo.toml'] = 'old'
            output.write_text(json.dumps(regenerated), encoding='utf-8')
            result = subprocess.run([
                sys.executable, str(ROOT / 'tools/native_pe_status.py'), '--ledger', str(output),
                '--partition', str(partition_path),
            ], capture_output=True, text=True, check=True)
            observed = json.loads(result.stdout)
            self.assertIn('Cargo.toml', observed['changed_sources'])
            self.assertEqual(observed['newly_stale_contracts'], 1)
            self.assertFalse(observed['complete'])
            bindings['entries'][0]['dispatch'] = 'changed-model'
            dispatch.write_text(json.dumps(bindings), encoding='utf-8')
            run()
            regenerated = json.loads(output.read_text())
            self.assertEqual(regenerated['entries'][0]['semantic_status'], 'stale')
            self.assertEqual(regenerated['required_gates']['source_regression']['status'], 'stale')
            self.assertTrue(regenerated['required_gates']['source_regression']['history'])
            before = output.read_bytes()
            legacy['entries'] = []
            inventory.write_text(json.dumps(legacy), encoding='utf-8')
            partition_path.write_text(json.dumps(batching.partition(legacy)), encoding='utf-8')
            run(success=False)
            self.assertEqual(output.read_bytes(), before)
            run('--allow-inventory-change')
            retired = json.loads(output.read_text())
            self.assertEqual(len(retired['inventory_history'][0]['retired_contracts']), 2)
            self.assertFalse(retired['complete'])

    def test_ledger_refuses_changed_frozen_source_before_writing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory = root / 'inventory.json'
            dispatch = root / 'dispatch.json'
            output = root / 'ledger.json'
            inventory.write_text(json.dumps({'sources': {'Cargo.toml': 'wrong'}, 'entries': []}), encoding='utf-8')
            dispatch.write_text('{"entries": []}', encoding='utf-8')
            result = subprocess.run([
                sys.executable, str(ROOT / 'tools/native_api_parity_ledger.py'),
                '--inventory', str(inventory), '--dispatch', str(dispatch), '--output', str(output),
            ], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('Frozen legacy source missing or changed', result.stderr)
            self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
