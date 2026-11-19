import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import native_pe_m4 as m4


class M4QualificationTests(unittest.TestCase):
    def execution(self):
        return dict(architecture='x86', completion_reason='entry_return', guest_entry_return=1,
                    error=None, instruction_count=100, max_instructions=1000,
                    api_events=[dict(api='kernel32.WaitForSingleObject', result=0, pending=False)],
                    user_threads=dict(current=1, pending=0, threads=[]))

    def test_matrix_requires_both_architectures_and_owned_exception_controls(self):
        names = m4.required_cases()
        self.assertEqual(111, len(names))
        self.assertEqual(21, len(m4.required_eh4_cases()))
        self.assertEqual(40, len(m4.required_process_cases()))
        self.assertIn('X86-m4-actual-Deadlock', names)
        self.assertIn('X64-m4-notification-attach-detach-waits', names)
        self.assertIn('X86-m4-x86-seh-chain-2', names)
        self.assertIn('X64-m4-runtime-function-table-2', names)

    def test_projection_ignores_wall_measurements_but_not_guest_effects(self):
        expected = self.execution()
        actual = copy.deepcopy(expected)
        actual.update(engine_seconds=20, instructions_per_second=5)
        m4.check_execution(actual, expected, dict(max_instructions=1000), 'x86')
        mutations = (
            ('guest_entry_return', 0), ('instruction_count', 101), ('max_instructions', 999),
            ('architecture', 'x64'), ('error', 'fault'), ('completion_reason', 'error'),
            ('process_exit_code', 73), ('native_exceptions', dict(exceptions_raised=2)),
            ('user_threads', dict(current=2, pending=1)), ('user_processes', dict(active=2)),
            ('api_events', [dict(api='kernel32.WaitForSingleObject', result=0x102, pending=False)]),
        )
        for field, value in mutations:
            candidate = copy.deepcopy(actual)
            candidate[field] = value
            with self.assertRaises(AssertionError, msg=field):
                m4.check_execution(candidate, expected, dict(max_instructions=1000), 'x86')

    def test_successful_terminal_reports_cannot_retain_pending_api_events(self):
        for completion in ('entry_return', 'process_exit'):
            execution = self.execution()
            execution['completion_reason'] = completion
            execution['api_events'][0]['pending'] = True
            with self.assertRaises(AssertionError):
                m4.check_execution(execution, execution, dict(max_instructions=1000), 'x86')

    def test_success_cannot_be_its_own_pending_or_failed_oracle(self):
        for field, value in (
            ('guest_entry_return', 0), ('error', 'fault'),
            ('api_events', [dict(api='kernel32.Sleep', result=0, pending=True)]),
        ):
            candidate = self.execution()
            candidate[field] = value
            with self.assertRaises(AssertionError, msg=field):
                m4.check_execution(candidate, candidate, dict(max_instructions=1000), 'x86')

    def test_budget_and_error_observations_are_not_success(self):
        budget = self.execution()
        budget.update(completion_reason='instruction_budget', guest_entry_return=None, instruction_count=1000)
        m4.check_execution(budget, budget, dict(max_instructions=1000), 'x86')
        budget['instruction_count'] -= 1
        with self.assertRaises(AssertionError):
            m4.check_execution(budget, budget, dict(max_instructions=1000), 'x86')
        failed = self.execution()
        failed.update(completion_reason='error', guest_entry_return=None, error='User thread deadlock')
        m4.check_execution(failed, failed, dict(max_instructions=1000), 'x86')
        failed['error'] = None
        with self.assertRaises(AssertionError):
            m4.check_execution(failed, failed, dict(max_instructions=1000), 'x86')

    def test_incomplete_fixture_sets_cannot_seal_without_process_and_eh4(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixtures = root / 'fixtures-final'
            fixtures.mkdir()
            for name in m4.required_cases():
                (fixtures / name).mkdir()
            with self.assertRaisesRegex(AssertionError, 'EH4'):
                m4.cases(root)
            for name in m4.required_eh4_cases():
                (fixtures / name).mkdir()
            with self.assertRaisesRegex(AssertionError, 'process'):
                m4.cases(root)
            for name in m4.required_process_cases():
                (fixtures / name).mkdir()
            with self.assertRaisesRegex(AssertionError, 'source-tested'):
                m4.cases(root)
            for fixture in fixtures.iterdir():
                (fixture / 'source-execution.json').write_text(json.dumps(self.execution()))
            self.assertEqual(172, len(m4.cases(root)))
            (fixtures / 'X86-m4-dispatcher/source-execution.json').unlink()
            with self.assertRaisesRegex(AssertionError, 'source-tested'):
                m4.cases(root)


if __name__ == '__main__':
    unittest.main()
