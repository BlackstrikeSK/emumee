"""Verify native kernel CPU state and syscall entry boundaries in AppContainer."""
import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tests.test_kernel_cpu import cpu_probe
from emumee.cpu import VirtualCPU
from emumee.persona import load_persona
from emumee.reports import valid_summary, verify_artifact_manifest


def verify(root, worker):
    root.mkdir(parents=True, exist_ok=False)
    cases = [(machine, architecture, mode) for machine, architecture in ((0x14C, 'x86'), (0x8664, 'x64')) for mode in ('boot', 'cpuid', 'thread-flags', 'suffix-immediate', 'sysenter', 'sysret', 'sysexit')]
    cases += [(0x8664, 'x64', mode) for mode in ('syscall', 'syscall-rex', 'syscall-segment', 'syscall-default', 'syscall-disabled', 'syscall-bad-target', 'syscall-bad-selector')]
    cases += [(0x14C, 'x86', 'syscall-disabled')]
    cases += [(0x14C, 'x86', 'iret'), (0x8664, 'x64', 'iret'), (0x8664, 'x64', 'iret-null-ss')]
    rows = []
    for machine, architecture, mode in cases:
        name = f'{architecture}-{mode}'
        payload = cpu_probe(machine, mode)
        sample = root / (name + '.sys')
        sample.write_bytes(payload)
        process = subprocess.run([str(worker), 'run', str(sample), '--output', str(root / name), '--offline-replay',
                                  '--timeout', '5', '--max-instructions', '1000'], text=True, capture_output=True, timeout=60)
        assert process.returncode in (0, 1), (name, process.stdout, process.stderr)
        outcome = json.loads(process.stdout)
        run = Path(outcome['report']).parent
        summary = json.loads((run / 'summary.json').read_text())
        raw = (run / 'engine-report.json').read_bytes()
        report = json.loads(raw)
        partial = mode in ('sysenter', 'sysret', 'sysexit', 'syscall-default', 'syscall-disabled', 'syscall-bad-target', 'syscall-bad-selector')
        assert process.returncode == int(partial) and summary['status'] == ('partial' if partial else 'completed'), (name, outcome)
        assert summary['guest_entry_return'] == (None if partial else 0x1234 if mode == 'thread-flags' else 0), name
        assert valid_summary(summary) and verify_artifact_manifest(run, summary['artifacts'], summary['artifact_groups']), name
        assert (run / 'input.pe').read_bytes() == payload and summary['sample']['sha256'] == hashlib.sha256(payload).hexdigest(), name
        assert summary['worker_containment'] and summary['network_broker_complete'], name
        assert json.loads((run / 'network-broker.json').read_text()) == [{'event': 'broker_closed'}], name
        assert summary['engine_report_sha256'] == hashlib.sha256(raw).hexdigest(), name
        assert not summary['api_coverage']['signature_only_calls'], name
        item = next((item for item in summary['artifacts'] if item['source'] == 'modified_driver_image:0x2000'), None)
        data = (run / 'artifacts' / item['file']).read_bytes() if item else b''
        width = 8 if machine == 0x8664 else 4
        value = lambda offset: int.from_bytes(data[offset:offset + width], 'little')
        if partial:
            expected = ('unsupported_kernel_syscall_dispatch' if mode == 'syscall-default' else
                        'unsupported_kernel_syscall_state' if mode in ('syscall-bad-target', 'syscall-bad-selector') else
                        'unsupported_kernel_instruction')
            assert report['entry_points'][0]['error']['type'] == expected, name
            assert data[0x3D0:0x3D4] != bytes.fromhex('5a000000'), name
        elif mode == 'boot':
            assert value(0x380) == value(0x388) == 0x80050033 and value(0x390) & 0x20 and value(0x398) & 0x800, name
            assert value(0x3A0) == 0x80040033, name
            assert value(0x3B0) & 0x200, name
        elif mode == 'cpuid':
            assert tuple(value(offset) for offset in (0x380, 0x388, 0x390, 0x398)) == VirtualCPU(load_persona(None)).leaf(1, 0), name
        elif mode == 'thread-flags':
            assert value(0x360) == value(0x378) == 0x200, name
        elif mode == 'suffix-immediate':
            assert value(0x3A0) == 0x050F0000, name
        elif mode.startswith('iret'):
            assert value(0x380) == value(0x3C0) and value(0x3D0) == 0x5A, name
            assert value(0x3B8) == (0 if mode == 'iret-null-ss' else 0x18 if width == 8 else 0x10), name
        else:
            assert value(0x3A0) == 0x1234 and 0x140001000 <= value(0x3A8) < 0x140001100, name
            assert value(0x3B0) & 0x600 == 0x600 and value(0x3B8) & 0x600 == 0, name
            assert value(0x380) == value(0x3C0) and value(0x3D0) == 0x5A, name
        rows.append({'case': name, 'verified': True, 'report': str(run / 'summary.json')})
        print(f'{name}: native CPU state, guest control flow, fault boundary and isolation verified', flush=True)
    (root / 'verification.json').write_text(json.dumps(rows, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('destination', type=Path)
    parser.add_argument('--worker', type=Path, default=ROOT / 'dist/Emumee/Emumee.exe')
    args = parser.parse_args()
    verify(args.destination.resolve(), args.worker.resolve())
