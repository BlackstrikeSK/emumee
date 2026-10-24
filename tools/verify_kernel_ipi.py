"""Verify requested IPI callbacks and processor state inside AppContainer."""
import argparse
import hashlib
import json
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tests.test_kernel_ipi import ipi_probe
from emumee.reports import valid_summary, verify_artifact_manifest


def verify(root, worker):
    root.mkdir(parents=True, exist_ok=False)
    findings = []
    cases = [('basic', 1), ('basic', 4), ('basic', 12), ('wide', 4), ('background', 4),
             ('barrier', 4), ('repeat', 4)]
    cases += [(name, 4) for name in ('fault', 'budget', 'invalid', 'nested', 'terminate', 'irql')]
    for machine, architecture in ((0x14C, 'x86'), (0x8664, 'x64')):
        width = 8 if machine == 0x8664 else 4
        # The CLI permits at most 32 cores x 2 threads. An x86 broadcast can
        # reject that valid 64-processor persona; x64 cannot receive >64 here.
        architecture_cases = cases + ([('group-limit', 64)] if width == 4 else [])
        for mode, logical in architecture_cases:
            name = f'{architecture}-{mode}-{logical}'
            payload = ipi_probe(machine, mode, logical)
            sample = root / (name + '.sys')
            sample.write_bytes(payload)
            persona = root / (name + '-persona.json')
            persona.write_text(json.dumps({'cpu': {'cores': 32 if mode == 'group-limit' else logical,
                                                   'threads_per_core': 2 if mode == 'group-limit' else 1}}))
            process = subprocess.run([str(worker), 'run', str(sample), '--persona', str(persona),
                '--output', str(root / name), '--offline-replay', '--timeout', '5', '--max-instructions',
                '50' if mode == 'budget' else '20000'], text=True, capture_output=True, timeout=60)
            assert process.returncode in (0, 1), (name, process.stdout, process.stderr)
            result = json.loads(process.stdout)
            run = Path(result['report']).parent
            summary = json.loads((run / 'summary.json').read_text())
            raw = (run / 'engine-report.json').read_bytes()
            report = json.loads(raw)
            partial = mode in ('fault', 'budget', 'invalid', 'nested', 'terminate', 'irql', 'group-limit')
            assert process.returncode == int(partial) and summary['status'] == ('partial' if partial else 'completed'), (name, result)
            assert summary['guest_entry_return'] == (None if partial else 0x1234), (name, result)
            assert valid_summary(summary) and verify_artifact_manifest(run, summary['artifacts'], summary['artifact_groups']), name
            assert summary['engine_report_sha256'] == hashlib.sha256(raw).hexdigest(), name
            assert summary['sample']['sha256'] == hashlib.sha256(payload).hexdigest() and (run / 'input.pe').read_bytes() == payload, name
            assert all(summary['worker_containment'].get(key) is True for key in
                       ('app_container', 'job_object', 'child_process_blocked')), name
            assert summary['network_broker_complete'] and not summary['network_attempts'], name
            assert json.loads((run / 'network-broker.json').read_text()) == [{'event': 'broker_closed'}], name
            assert not summary['api_coverage']['signature_only_calls'], name
            groups = report['kernel_ipi']['broadcasts']
            if partial:
                assert summary['errors'] and all(not group['completed'] for group in groups), name
                if mode in ('invalid', 'group-limit'): assert not groups, name
                if mode == 'budget': assert summary['instruction_count'] == 50 and summary['instruction_limit_reached'], name
                if mode == 'irql': assert any('expected IPI_LEVEL' in error for error in summary['errors']), name
                if mode == 'terminate': assert any('PASSIVE_LEVEL' in error for error in summary['errors']), name
            else:
                assert not summary['errors'] and len(groups) == (2 if mode == 'repeat' else 1), (name, summary['errors'])
                assert all(group['completed'] and len(group['callbacks']) == logical for group in groups), name
                assert all(row['started'] and row['instruction_count'] > 0 for group in groups for row in group['callbacks']), name
                item = next(item for item in summary['artifacts'] if item['source'] == 'modified_driver_image:0x2000')
                image = (run / 'artifacts' / item['file']).read_bytes()
                threads, stacks = set(), set()
                for number in range(logical):
                    offset = 0xA00 + number * 64
                    assert struct.unpack_from('<6I', image, offset) == (number, 14 if width == 8 else 29, number, number, number, number), name
                    assert image[offset + 40:offset + 44] == bytes([0, 0, number, 0]), name
                    assert struct.unpack_from('<I', image, offset + 44)[0] == number, name
                    if width == 4: assert struct.unpack_from('<I', image, offset + 48)[0] == 1 << number, name
                    cr0, msw, cr4 = struct.unpack_from('<3I', image, offset + 52)
                    assert cr0 == msw == 0x80050033 and cr4 & 0x20, name
                    assert struct.unpack_from('<I', image, offset + (48 if width == 8 else 28))[0] == 0, name
                    threads.add(int.from_bytes(image[offset + 24:offset + 24 + width], 'little'))
                    stacks.add(int.from_bytes(image[offset + 32:offset + 32 + width], 'little'))
                    if mode == 'repeat': assert image[offset:offset + 48] == image[offset + 0x200:offset + 0x230], name
                assert len(threads) == len(stacks) == logical, name
                assert image[0xF08:0xF18] == (bytes(width) + b'\xcc' * (8 - width)) * 2, name
                assert int.from_bytes(image[0xF18:0xF18 + width], 'little') == (0x1122334455667788 if width == 8 else 0xAABBCCDD), name
                expected = 0x1234567800001234 if mode == 'wide' and width == 8 else 0x1234
                assert int.from_bytes(image[0xF00:0xF00 + width], 'little') == int(groups[0]['results']['0'], 0) == expected, name
                if mode == 'background': assert report['kernel_scheduling']['threads'][0]['state'] == 'done', name
            findings.append({'case': name, 'verified': True, 'report': str(run / 'summary.json')})
            print(name + ': actual callbacks, CPU identity, IRQL, caller restoration and isolation verified', flush=True)
    (root / 'verification.json').write_text(json.dumps(findings, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('destination', type=Path)
    parser.add_argument('--worker', type=Path, default=ROOT / 'dist/Emumee/Emumee.exe')
    arguments = parser.parse_args()
    verify(arguments.destination.resolve(), arguments.worker.resolve())
