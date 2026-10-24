"""Verify kernel memory helpers and native REP accounting in AppContainer."""
import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tests.test_kernel_memory import memory_probe, repeat_probe
from emumee.reports import valid_summary, verify_artifact_manifest


def verify(root, worker):
    root.mkdir(parents=True, exist_ok=False)
    findings = []
    names = ('RtlMoveMemory', 'RtlCopyMemory', 'RtlFillMemory', 'RtlZeroMemory', 'memcpy', 'memmove', 'memset')
    for machine, architecture in ((0x14C, 'x86'), (0x8664, 'x64')):
        cases = [(name, mode) for name in names for mode in ('success', 'readonly', 'boundary', 'empty', 'large')]
        cases += [(name, mode) for name in ('RtlMoveMemory', 'memmove') for mode in ('overlap', 'unreadable')]
        cases += [('repeat', 'complete'), ('repeat', 'limited')]
        for api, mode in cases:
            name = architecture + '-' + api + '-' + mode
            payload = repeat_probe(machine) if api == 'repeat' else memory_probe(machine, api, mode)
            sample = root / (name + '.sys')
            sample.write_bytes(payload)
            budget = 64 if mode == 'limited' else 2000
            process = subprocess.run([str(worker), 'run', str(sample), '--output', str(root / name),
                '--offline-replay', '--timeout', '5', '--max-instructions', str(budget)],
                text=True, capture_output=True, timeout=60)
            result = json.loads(process.stdout)
            run = Path(result['report']).parent
            summary = json.loads((run / 'summary.json').read_text())
            raw = (run / 'engine-report.json').read_bytes()
            report = json.loads(raw)
            partial = mode in ('readonly', 'boundary', 'large', 'unreadable', 'limited')
            expected = (None if partial else 0 if mode == 'empty' or api in ('repeat', 'RtlZeroMemory') else
                int.from_bytes(b'abab', 'little') if mode == 'overlap' else
                0xFFFFFFFF if api in ('memset', 'RtlFillMemory') else int.from_bytes(b'abcd', 'little'))
            assert process.returncode == int(partial), (name, process.stderr, result)
            assert summary['status'] == ('partial' if partial else 'completed'), (name, result)
            assert summary['guest_entry_return'] == expected, (name, result)
            assert valid_summary(summary) and verify_artifact_manifest(run, summary['artifacts'], summary['artifact_groups']), name
            assert summary['engine_report_sha256'] == hashlib.sha256(raw).hexdigest(), name
            assert (run / 'input.pe').read_bytes() == payload and summary['sample']['sha256'] == hashlib.sha256(payload).hexdigest(), name
            assert all(summary['worker_containment'].get(key) is True for key in
                       ('app_container', 'job_object', 'child_process_blocked')), name
            assert summary['network_broker_complete'] and not summary['network_attempts'], name
            assert json.loads((run / 'network-broker.json').read_text()) == [{'event': 'broker_closed'}], name
            assert not summary['api_coverage']['signature_only_calls'], name
            if partial:
                assert summary['errors'], name
                if mode != 'limited': assert summary['driver_image_changes']['changed_pages'] == 0, name
                if mode == 'large': assert any('byte limit' in error for error in summary['errors']), name
                elif mode == 'unreadable': assert any('not readable' in error for error in summary['errors']), name
                elif mode != 'limited': assert any('not writable' in error for error in summary['errors']), name
            else:
                assert not summary['errors'], (name, summary['errors'])
            if mode == 'overlap' or api == 'repeat':
                item = next(item for item in summary['artifacts'] if item['source'] == 'modified_driver_image:0x2000')
                image = (run / 'artifacts' / item['file']).read_bytes()
                if mode == 'overlap': assert image[0x300:0x308] == b'ababcdgh', name
                else:
                    assert not any(edge['from'] == edge['to'] for edge in report['control_flow_tail']), name
                    assert report['instruction_repetitions']['charged_to_instruction_budget'], name
                    copied = image[0x400:0x480]
                    if mode == 'limited':
                        assert summary['instruction_limit_reached'] and summary['instruction_count'] == 64, name
                        prefix = copied.index(0xCC)
                        assert 0 < prefix < 128 and copied == bytes(range(prefix)) + b'\xcc' * (128 - prefix), name
                    else:
                        assert copied == bytes(range(128)), name
                        assert report['instruction_repetitions']['consecutive_rep_movsb_iterations'] == 512, name
            findings.append({'case': name, 'verified': True, 'report': str(run / 'summary.json')})
            print(name + ': native bytes, permissions, accounting and trace integrity verified', flush=True)
    (root / 'verification.json').write_text(json.dumps(findings, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('destination', type=Path)
    parser.add_argument('--worker', type=Path, default=ROOT / 'dist/Emumee/Emumee.exe')
    args = parser.parse_args()
    verify(args.destination.resolve(), args.worker.resolve())
