"""Submitted-script confinement, authenticated partial traces, and dashboard evidence."""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from emumee.dashboard import create_app
from emumee.powershell import project_trace, run_script, save_script_run
from emumee.powershell_capture import docker, verified_events
from tests import test_powershell_exec_observer as observer_tests

ROOT = Path(__file__).resolve().parents[1]


class PowerShellTests(unittest.TestCase):
    def test_partial_trace_requires_authentication_and_order_but_not_terminal_record(self):
        events = [{'event': 'observer_ready', 'sequence': 1},
                  {'event': 'native_process_exit', 'pid': 5, 'exit_code': 13, 'sequence': 2}]
        signed = observer_tests.ExecObserverTests().signed(events)
        self.assertEqual(verified_events(signed, b'k' * 32, require_finished=False), events)
        with self.assertRaises(ValueError):
            verified_events(signed, b'k' * 32)
        with self.assertRaises(ValueError):
            verified_events(signed.replace(b'13', b'12'), b'k' * 32, require_finished=False)
        with self.assertRaises(ValueError):
            verified_events(b'', b'k' * 32, require_finished=False)

    def test_malformed_engine_record_does_not_destroy_native_or_console_evidence(self):
        events = [{'event': 'native_exec_attempt', 'pid': 5, 'sequence': 2,
                   'path_hex': b'/bin/echo'.hex(), 'argv_hex': [b'/bin/echo'.hex(), b'value'.hex()]},
                  {'event': 'native_exec_committed', 'pid': 5, 'sequence': 3},
                  {'event': 'guest_engine_record', 'pid': 5, 'sequence': 4, 'data_hex': b'garbage'.hex()},
                  {'event': 'native_console_write', 'fd': 1, 'data_hex': 'café'.encode().hex(), 'truncated': False},
                  {'event': 'native_console_write', 'fd': 2, 'data_hex': b'error'.hex(), 'truncated': True},
                  {'event': 'native_syscall_denied', 'syscall_number': 41}]
        commands, network, console, errors = project_trace(events)
        self.assertEqual(commands[0]['native_arguments'], ['value'])
        self.assertEqual(len(errors), 1)
        self.assertIn('sequence 4', errors[0])
        self.assertEqual(console['stdout'], 'café')
        self.assertEqual(console['stderr'], 'error')
        self.assertTrue(console['stderr_truncated'])
        self.assertFalse(network[0]['network_used'])

    def test_supplied_script_limits_are_checked_before_docker(self):
        with tempfile.TemporaryDirectory() as directory:
            sample = Path(directory) / 'input.ps1'
            for data, timeout in ((b'x', 0), (b'x', 301), (b'x', True), (b'', 5), (b'x' * (1024 * 1024 + 1), 5)):
                sample.write_bytes(data)
                with self.subTest(size=len(data), timeout=timeout), patch('emumee.powershell.docker') as mocked:
                    with self.assertRaises(ValueError):
                        run_script(sample, Path('missing-observer'), Path('missing-engine'), timeout=timeout)
                    mocked.assert_not_called()


@unittest.skipUnless(os.environ.get('EMUMEE_POWERSHELL_INTEGRATION') == '1', 'requires built observer, engine, and Docker Desktop Linux')
class PowerShellContainerTests(unittest.TestCase):
    observer = ROOT / 'output/powershell-exec-observer/observer'
    engine = ROOT / 'output/powershell-instrumented-engine/System.Management.Automation.dll'

    def execute(self, source, timeout=30):
        with tempfile.TemporaryDirectory() as directory:
            sample = Path(directory) / 'input.ps1'
            sample.write_text(source, encoding='utf-8')
            report = run_script(sample, self.observer, self.engine, timeout=timeout)
        self.assertEqual(docker('ps', '-aq', '--filter', 'name=emumee-powershell-').strip(), '')
        return report

    def test_evaluated_values_unicode_native_bytes_console_and_dashboard(self):
        report = self.execute((ROOT / 'examples/powershell-capture.ps1').read_text(encoding='utf-8'))
        self.assertEqual(report['errors'], [])
        self.assertEqual(report['guest_exit_code'], 0)
        self.assertTrue(report['observer_trace_complete'])
        self.assertTrue(all(report['configuration_checks'].values()))
        commands = report['command_events']
        self.assertTrue(any(c['command'] == 'Write-Output' and c['bound_parameters'].get('InputObject') == ['evaluated-value'] for c in commands))
        self.assertTrue(any(c['command'] == 'Invoke-CaptureFixture' and c['phase'] == 'process_record_bound' and c['bound_parameters'].get('Value') == 'pipeline-value' for c in commands))
        self.assertTrue(any(c.get('native_arguments') == ['space value', 'quote"value', '', 'café-✓'] for c in commands))
        self.assertTrue(any(e['event'] == 'network_denied' and e['syscall_number'] == 41 for e in report['network_events']))
        self.assertIn('evaluated-value', report['console_output']['stdout'])
        self.assertIn('network-socket-denied', report['console_output']['stdout'])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = save_script_run(report, root)
            html = create_app(root).test_client().get(f'/runs/{run.name}').get_data(as_text=True)
            for text in ('evaluated-value', 'pipeline-value', 'café 日本語 😀', 'kernel_exec_committed', 'Command capture is incomplete'):
                self.assertIn(text, html)
            self.assertNotIn(r'\u00e9', html)
            summary = json.loads((run / 'summary.json').read_text(encoding='utf-8'))
            self.assertFalse(summary['run_manifest']['probe_only'])
            self.assertEqual(summary['sample']['kind'], 'powershell')

    def test_timeout_preserves_observed_commands_and_console_and_removes_container(self):
        report = self.execute("Write-Output 'before-timeout'; [Threading.Thread]::Sleep(60000)", timeout=8)
        self.assertTrue(report['timeout_reached'])
        self.assertFalse(report['observer_trace_complete'])
        self.assertIsNone(report['guest_exit_code'])
        self.assertTrue(any(c['bound_parameters'].get('InputObject') == ['before-timeout'] for c in report['command_events']))
        self.assertIn('before-timeout', report['console_output']['stdout'])
        self.assertTrue(any('timeout' in error for error in report['errors']))

    def test_nonzero_exit_retains_both_console_streams(self):
        report = self.execute("Write-Output 'before-exit'; [Console]::Error.WriteLine('error-marker'); exit 13")
        self.assertTrue(report['observer_trace_complete'])
        self.assertEqual(report['guest_exit_code'], 13)
        self.assertIn('before-exit', report['console_output']['stdout'])
        self.assertIn('error-marker', report['console_output']['stderr'])
        self.assertTrue(any('code 13' in error for error in report['errors']))

    def test_no_host_files_environment_or_docker_socket_and_readonly_root(self):
        with tempfile.TemporaryDirectory() as directory:
            host_marker = Path(directory) / 'host-only-marker.txt'
            host_marker.write_text('host-secret', encoding='utf-8')
            source = r'''
$ErrorActionPreference = 'Stop'
if ([IO.File]::Exists('HOST_MARKER') -or [IO.File]::Exists('/var/run/docker.sock')) { throw 'Host access' }
if ($env:EMUMEE_HOST_SENTINEL) { throw 'Inherited host environment' }
try { [IO.File]::WriteAllText('/usr/emumee-write-probe', 'bad'); throw 'Writable root' }
catch [System.Management.Automation.MethodInvocationException] { Write-Output 'readonly-root' }
try { $s = [IO.File]::OpenRead('/proc/1/mem'); $s.Dispose(); throw 'Observer readable' }
catch [System.Management.Automation.MethodInvocationException] { Write-Output 'observer-memory-denied' }
& '/usr/bin/id' '-u'
Write-Output 'host-paths-absent'
'''.replace('HOST_MARKER', str(host_marker).replace("'", "''"))
            with patch.dict(os.environ, {'EMUMEE_HOST_SENTINEL': 'host-only'}):
                report = self.execute(source)
            self.assertEqual(host_marker.read_text(encoding='utf-8'), 'host-secret')
        self.assertEqual(report['errors'], [])
        for value in ('readonly-root', 'observer-memory-denied', '65534', 'host-paths-absent'):
            self.assertIn(value, report['console_output']['stdout'])

    def test_malformed_guest_engine_payload_is_rejected_and_trace_continues(self):
        report = self.execute('''
Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; public static class InvalidCaptureFixture { [DllImport("libc")] public static extern long write(int fd, byte[] data, UIntPtr count); }'
[void][InvalidCaptureFixture]::write(198, [Text.Encoding]::UTF8.GetBytes('garbage'), [UIntPtr]7)
& '/bin/echo' 'after-invalid-native'
Write-Output 'after-invalid-record'
''')
        self.assertTrue(report['observer_trace_complete'])
        self.assertTrue(any('Rejected malformed engine record' in error for error in report['errors']))
        self.assertTrue(any(c.get('native_arguments') == ['after-invalid-native'] for c in report['command_events']))
        self.assertTrue(any(c['bound_parameters'].get('InputObject') == ['after-invalid-record'] for c in report['command_events']))

    def test_console_budget_and_host_trace_budget_are_bounded(self):
        report = self.execute("[Console]::Write(('x' * 100000)); Write-Output 'end'")
        self.assertLessEqual(len(report['console_output']['stdout'].encode('utf-8')), 65536)
        self.assertTrue(report['console_output']['stdout_truncated'])
        with patch('emumee.powershell.MAX_TRACE', 2048):
            report = self.execute("Write-Output 'bounded-trace'; [Threading.Thread]::Sleep(60000)")
        self.assertTrue(any('observer_output_limit' in error for error in report['errors']))
        self.assertFalse(report['observer_trace_complete'])


if __name__ == '__main__':
    unittest.main()
