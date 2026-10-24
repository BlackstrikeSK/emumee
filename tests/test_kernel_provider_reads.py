"""Native provider-read evidence must preserve execution and memory counters."""

import json
import struct
import tempfile
import unittest
from contextlib import nullcontext
from pathlib import Path
from unittest.mock import patch

from emumee.driver import run_driver
from emumee.kernel_provider_reads import KernelProviderReads
from emumee.pe import inspect_pe
from emumee.persona import load_persona
from tests.test_kernel_objects import call_driver


def provider_read_probe(machine, burst=False, second=False):
    wide = machine == 0x8664
    base, width = (0x140000000, 8) if wide else (0x400000, 4)
    load = lambda rva: (b'\x48\xa1' if wide else b'\xa1') + (base + rva).to_bytes(width, 'little')
    store = lambda rva: (b'\x48\xa3' if wide else b'\xa3') + (base + rva).to_bytes(width, 'little')
    first = load(0x2900) + store(0x2380)
    code = load(0x2390)
    code += (b'\x48\xba' if wide else b'\xba') + (base + 0x2600).to_bytes(width, 'little')
    code += b'\xb9' + struct.pack('<I', 600 if burst else 1)
    code += bytes.fromhex('0fb618ffc975f9')  # native provider-byte read; dec ECX; repeat
    if second:
        code += b'\xb9' + struct.pack('<I', 600)
        code += bytes.fromhex('0fb618ffc975f9')
    code += bytes.fromhex('89d8') + store(0x23C0)
    return call_driver(machine, ['KeGetCurrentIrql', 'RtlPcToFileHeader'],
        [('raw', first), (1, [('load', 0x2380), base + 0x2390], None), ('raw', code)],
        b'\x31\xc0', [(0x2600, b'MissingDiagnosticRoutine\0')])


def verify_provider_reads(report, burst=False):
    capture = report['kernel_provider_reads']
    assert capture['capture_errors'] == capture['watch_errors'] == 0, capture
    assert capture['total_reads'] == (600 if burst else 1), capture['total_reads']
    assert capture['reads_by_provider'] == {'ntoskrnl': capture['total_reads']}
    assert len(capture['first_pc_observations']) == 1
    assert len(capture['tail']) == (256 if burst else 1)
    assert capture['omitted_reads'] == (343 if burst else 0)
    observations = capture['first_pc_observations'] + capture['tail']
    for item in observations:
        assert item['rva'] == '0x0' and item['size'] == 1
        assert item['prefix_at_read'] == '4d'
        registers = item['registers_before']
        assert int(registers.get('eax', registers.get('rax')), 0) == int(item['address'], 0)
        assert item['register_pointer_prefixes']['rdx' if 'rax' in registers else 'edx']['prefix'].startswith(
            b'MissingDiagnosticRoutine\0'.hex())
        assert item['stack_prefix'] and len(bytes.fromhex(item['stack_prefix'])) <= 128


class KernelProviderReadTests(unittest.TestCase):
    def test_periodic_snapshots_keep_exact_read_counts_last_metadata_and_guest_time(self):
        original=KernelProviderReads.__init__
        def sampled(instance,kernel,**kwargs):
            kwargs.update(sample_interval=64,sample_ranges=())
            original(instance,kernel,**kwargs)
        for machine in (0x14c,0x8664):
            with self.subTest(machine=machine):
                _,_,baseline=self.run_probe(machine,True)
                with patch.object(KernelProviderReads,'__init__',sampled):
                    result,report,observed=self.run_probe(machine,True)
                self.assertEqual(result['errors'],[]);self.assertEqual(observed,baseline)
                capture=report['kernel_provider_reads'];self.assertEqual(capture['total_reads'],600)
                self.assertEqual(capture['capture_errors'],0);self.assertEqual(capture['sampled_out_reads'],590)
                self.assertEqual(capture['latest_pc_observations'][0]['sequence'],576)
                self.assertEqual(capture['last_observed_per_pc'][0]['sequence'],600)

    def test_latest_context_survives_another_pc_evicting_global_tail(self):
        for machine in (0x14C, 0x8664):
            observations = []
            for enabled in (False, True):
                with self.subTest(machine=machine, enabled=enabled), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    payload = provider_read_probe(machine, True, True)
                    with patch.object(KernelProviderReads, 'install') if not enabled else nullcontext():
                        result = run_driver(payload, inspect_pe(payload, 'latest-context.sys'), load_persona(None), root, 10, 10000)
                    report = json.loads((root/'engine-report.json').read_text())
                    self.assertEqual(result['errors'], [])
                    observations.append({'instructions': result['instruction_count'], 'return': result['guest_entry_return'],
                        'tsc': report['virtual_tsc'], 'uptime': report['virtual_uptime_ms'],
                        'memory': [r['memory'] for r in report['entry_points']],
                        'artifacts': [(a['source'], a['sha256']) for a in result['artifacts']]})
                    if enabled:
                        capture = report['kernel_provider_reads']
                        self.assertEqual(capture['total_reads'], 1200)
                        self.assertEqual(capture['capture_errors'], 0)
                        self.assertEqual([v['sequence'] for v in capture['latest_pc_observations']], [600, 1200])
                        self.assertEqual(capture['omitted_reads'], 941)
                        self.assertNotIn(600, [v['sequence'] for v in capture['tail']])
            self.assertEqual(observations[0], observations[1])

    def run_probe(self, machine, burst=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = provider_read_probe(machine, burst)
            result = run_driver(data, inspect_pe(data, 'provider-reads.sys'), load_persona(None), root, 5, 3000)
            report = json.loads((root / 'engine-report.json').read_text())
            observation = {'instructions': result['instruction_count'], 'return': result['guest_entry_return'],
                'virtual_tsc': report['virtual_tsc'], 'virtual_uptime_ms': report['virtual_uptime_ms'],
                'memory': [run['memory'] for run in report['entry_points']],
                'artifacts': [(item['source'], item['sha256']) for item in result['artifacts']]}
            return result, report, observation

    def test_passive_read_evidence_preserves_native_results_and_time(self):
        for machine in (0x14C, 0x8664):
            for burst in (False, True):
                with self.subTest(machine=machine, burst=burst):
                    with patch.object(KernelProviderReads, 'install'):
                        _, baseline, before = self.run_probe(machine, burst)
                    result, report, after = self.run_probe(machine, burst)
                    self.assertEqual(result['errors'], [])
                    self.assertEqual(result['guest_entry_return'], 0)
                    self.assertEqual(after, before)
                    self.assertEqual(baseline['kernel_provider_reads']['total_reads'], 0)
                    verify_provider_reads(report, burst)

    def test_zero_capture_limits_are_explicit_and_preserve_guest_execution(self):
        original = KernelProviderReads.__init__
        def limited(instance, kernel, **kwargs):
            original(instance, kernel, first_limit=0, tail_limit=0, **kwargs)
        for machine in (0x14C, 0x8664):
            with self.subTest(machine=machine), patch.object(KernelProviderReads, '__init__', limited):
                result, report, _ = self.run_probe(machine, True)
                capture = report['kernel_provider_reads']
                self.assertEqual(result['errors'], [])
                self.assertEqual(result['guest_entry_return'], 0)
                self.assertEqual(capture['total_reads'], 600)
                self.assertEqual(capture['omitted_reads'], 600)
                self.assertEqual(capture['capture_errors'], 0)
                self.assertEqual(capture['first_pc_observations'], [])
                self.assertEqual(capture['tail'], [])

    def test_module_query_read_context_preserves_native_results(self):
        from tests.test_kernel_system_information import system_information_probe
        for machine in (0x14C, 0x8664):
            for mode in ('standard', 'extended'):
                with self.subTest(machine=machine, mode=mode):
                    results = []
                    for enabled in (False, True):
                        with tempfile.TemporaryDirectory() as directory:
                            root = Path(directory)
                            payload = system_information_probe(machine, mode)
                            if enabled:
                                result = run_driver(payload, inspect_pe(payload, 'query-reads.sys'), load_persona(None), root, 5, 3000)
                            else:
                                with patch.object(KernelProviderReads, 'watch_region', return_value=False):
                                    result = run_driver(payload, inspect_pe(payload, 'query-reads.sys'), load_persona(None), root, 5, 3000)
                            report = json.loads((root / 'engine-report.json').read_text())
                            self.assertEqual(result['errors'], [])
                            self.assertEqual(result['guest_entry_return'], 0)
                            results.append({'instructions': result['instruction_count'],
                                'memory': [entry['memory'] for entry in report['entry_points']],
                                'virtual_tsc': report['virtual_tsc'], 'virtual_uptime_ms': report['virtual_uptime_ms'],
                                'artifacts': [(item['source'], item['sha256']) for item in result['artifacts']]})
                            capture = report['kernel_system_information']['native_buffer_reads']
                            if enabled:
                                verify_query_read_context(report, mode)
                            else:
                                self.assertEqual(capture['total_reads'], 0)
                    self.assertEqual(results[0], results[1])


def verify_query_read_context(report, mode):
    capture = report['kernel_system_information']['native_buffer_reads']
    assert capture['capture_errors'] == capture['watch_errors'] == 0
    assert capture['total_reads'] > 0
    assert capture['omitted_watched_regions'] == 0
    assert capture['stack_prefix_limit'] == 1024
    expected = 'class11_query' if mode == 'standard' else 'class77_query'
    assert all(item['name'].startswith(expected) for item in capture['watched_regions'])
    assert capture['watched_regions']
    observations = capture['first_pc_observations'] + capture['tail']
    assert observations and len(observations) <= 512
    for item in observations:
        assert item['provider'].startswith(expected)
        assert item['prefix_at_read'] is not None and item['registers_before']
        assert item['stack_prefix'] is not None and len(bytes.fromhex(item['stack_prefix'])) <= 1024
