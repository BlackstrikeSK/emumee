"""M3 evidence-forgery controls; synthetic reports are not guest execution proof."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import native_pe_m3_lifecycle as lifecycle


class LifecycleEvidenceTests(unittest.TestCase):
    def execution(self, family='provider', kind='', filename='bootstrap.exe'):
        case = ('X64', family, kind, filename)
        reason, value = lifecycle.expected(case)
        budget = 512 if family == 'process' or kind == 'Budget' else 500000
        return case, dict(architecture='x64', completion_reason=reason, guest_entry_return=value,
            max_instructions=budget, instruction_count=budget if reason == 'instruction_budget' else 200,
            error=None, api_events=[],
            user_bootstrap=dict(process_id=1024, thread_id=1, teb=0x100000, peb=0x102000,
                image_base=0x140000000, stack_limit=0x70000000, stack_base=0x70100000),
            user_loader=dict(entries=[dict(name=name) for name in (filename, 'ntdll.dll', 'kernel32.dll', 'kernelbase.dll')],
                tls_bytes=0, threads={}))

    def test_matrix_is_exact_unique_and_balanced(self):
        cases = list(lifecycle.cases())
        self.assertEqual(70, len(cases))
        self.assertEqual(70, len({lifecycle.label(case) for case in cases}))
        self.assertEqual(35, sum(case[0] == 'X86' for case in cases))
        self.assertEqual(35, sum(case[0] == 'X64' for case in cases))

    def test_identity_missing_loader_and_budget_forgery_refuse(self):
        case, execution = self.execution()
        lifecycle.check_execution(execution, case)
        for key, value in [('user_loader', None), ('guest_entry_return', 42), ('instruction_count', 500001),
                           ('completion_reason', 'process_exit'), ('error', 'unrelated failure')]:
            candidate = copy.deepcopy(execution)
            candidate[key] = value
            with self.assertRaises(AssertionError, msg=key):
                lifecycle.check_execution(candidate, case)
        for key in execution['user_bootstrap']:
            candidate = copy.deepcopy(execution)
            candidate['user_bootstrap'][key] = 0
            with self.assertRaises(AssertionError, msg=key):
                lifecycle.check_execution(candidate, case)
        candidate = copy.deepcopy(execution)
        candidate['user_loader']['entries'][1:3] = reversed(candidate['user_loader']['entries'][1:3])
        with self.assertRaises(AssertionError):
            lifecycle.check_execution(candidate, case)

    def test_callback_interruption_cannot_claim_live_or_missing_unwind(self):
        case, execution = self.execution('callback', 'Budget', 'callbacks.exe')
        execution['crt_startup'] = dict(initializer_pending=False, suspended_initializers=0,
            interrupted_initializers=[{}, {}])
        lifecycle.check_execution(execution, case)
        for key, value in [('initializer_pending', True), ('suspended_initializers', 1),
                           ('interrupted_initializers', [{}])]:
            candidate = copy.deepcopy(execution)
            candidate['crt_startup'][key] = value
            with self.assertRaises(AssertionError, msg=key):
                lifecycle.check_execution(candidate, case)
        execution['instruction_count'] -= 1
        with self.assertRaises(AssertionError):
            lifecycle.check_execution(execution, case)

    def test_forced_process_exit_cannot_run_detach_or_keep_live_tls(self):
        case, execution = self.execution('process', 'true-true', 'exit.exe')
        execution['process_exit_code'] = 73
        execution['user_lifecycle'] = dict(forced=True, complete=True, events=[])
        lifecycle.check_execution(execution, case)
        for key, value in [('forced', False), ('complete', False), ('complete', None),
                           ('events', [dict(reason=0, returned=True)])]:
            candidate = copy.deepcopy(execution)
            candidate['user_lifecycle'][key] = value
            with self.assertRaises(AssertionError, msg=key):
                lifecycle.check_execution(candidate, case)
        execution['user_loader']['tls_bytes'] = 1
        with self.assertRaises(AssertionError):
            lifecycle.check_execution(execution, case)

    def test_tls_quota_refusal_requires_cleanup_and_real_thread_notifications(self):
        case, execution = self.execution('tls-quota', '', 'quota.exe')
        execution['user_loader'].update(tls_bytes=17 * 1024**2,
            threads={'1': dict(blocks={str(index): index for index in range(17)})})
        execution['user_threads'] = dict(current=1, pending=0,
            threads=[dict(backing_released=True, handle_closed=True, exit_code=42) for _ in range(2)])
        execution['api_events'] = [dict(api='kernel32.CreateThread', result=0, last_error=8, pending=False)]
        execution['user_lifecycle'] = dict(events=[dict(thread=thread, reason=reason, returned=True)
            for thread in (2, 3) for reason in (2, 3) for _ in range(33)])
        lifecycle.check_execution(execution, case)
        candidates = []
        candidate = copy.deepcopy(execution)
        candidate['user_threads']['threads'][0]['backing_released'] = False
        candidates.append(candidate)
        candidate = copy.deepcopy(execution)
        candidate['api_events'][0]['last_error'] = 87
        candidates.append(candidate)
        candidate = copy.deepcopy(execution)
        candidate['user_lifecycle']['events'].pop()
        candidates.append(candidate)
        for candidate in candidates:
            with self.assertRaises(AssertionError):
                lifecycle.check_execution(candidate, case)


if __name__ == '__main__':
    unittest.main()
