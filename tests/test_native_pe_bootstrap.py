import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import native_pe_m3 as bootstrap


class BootstrapEvidenceTests(unittest.TestCase):
    def execution(self, architecture='X64'):
        base = 0x10000000
        return dict(user_bootstrap=dict(process_id=1024, thread_id=1, mapped_bytes=bootstrap.SIZE,
            image_base=0x400000 if architecture == 'X86' else 0x140000000,
            stack_limit=0x70000000, stack_base=0x70100000, teb=base, peb=base + 0x2000,
            process_parameters=base + 0x3000, environment=base + 0x25000, command_line=base + 0x200000),
            instruction_count=200, max_instructions=500000, error=None, guest_entry_return=1,
            completion_reason='entry_return', api_events=[dict(thread_id=1)])

    def test_exact_matrix_and_success_controls(self):
        cases = list(bootstrap.cases())
        self.assertEqual(len(cases), 34)
        self.assertEqual(len(set(cases)), 34)
        self.assertEqual(sum(kind in ('Protect', 'Free') for _, _, kind, _ in cases), 16)
        for architecture in ('X86', 'X64'):
            bootstrap.check_bootstrap(self.execution(architecture), architecture, 'Basic')

    def test_report_identity_mapping_pointer_and_horizon_forgery_refused(self):
        for key in self.execution()['user_bootstrap']:
            execution = self.execution()
            execution['user_bootstrap'][key] = 0
            with self.assertRaises(AssertionError, msg=key):
                bootstrap.check_bootstrap(execution, 'X64', 'Basic')
        for key, value in [('instruction_count', 500001), ('max_instructions', 500001), ('guest_entry_return', 0),
                           ('error', 'fault'), ('completion_reason', 'timeout'),
                           ('api_events', [dict(thread_id=2)])]:
            execution = self.execution()
            execution[key] = value
            with self.assertRaises(AssertionError, msg=key):
                bootstrap.check_bootstrap(execution, 'X64', 'Basic')

    def test_owned_memory_refusal_cannot_be_replaced_by_return_or_generic_fault(self):
        for kind in ('Protect', 'Free'):
            execution = self.execution()
            with self.assertRaises(AssertionError):
                bootstrap.check_bootstrap(execution, 'X64', kind)
            execution.update(error='Mapping change overlaps owned user bootstrap', guest_entry_return=None,
                             completion_reason='fault')
            bootstrap.check_bootstrap(execution, 'X64', kind)
            execution['error'] = 'unrelated fault'
            with self.assertRaises(AssertionError):
                bootstrap.check_bootstrap(execution, 'X64', kind)

    def test_reference_is_bound_to_definition_bytes_and_exact_offsets(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            bootstrap.reference(path)
            document = json.loads((path / 'bootstrap-reference.json').read_bytes())
        bootstrap.verify_reference(document)
        mutated = copy.deepcopy(document)
        mutated['definitions_sha256'] = '0' * 64
        with self.assertRaises(AssertionError):
            bootstrap.verify_reference(mutated)
        mutated = copy.deepcopy(document)
        mutated['layouts']['8']['TEB']['LastErrorValue'] += 4
        with self.assertRaises(AssertionError):
            bootstrap.verify_reference(mutated)
        mutated = copy.deepcopy(document)
        mutated['parameter_sizes']['8'] += 8
        with self.assertRaises(AssertionError):
            bootstrap.verify_reference(mutated)
