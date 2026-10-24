"""Verify object-type identities, references and native thread joins in the worker."""

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tests.test_kernel_references import reference_probe, reference_bytes
from emumee.reports import valid_summary, verify_artifact_manifest


def verify(root, worker):
    root.mkdir(parents=True, exist_ok=False)
    findings = []
    success_modes = ("join", "return", "many-any", "many-all", "null-type", "kernel-mismatch")
    status_modes = {"invalid-handle": (0x320, 0xC0000008), "handle-mismatch": (0x320, 0xC0000024),
                    "user-mismatch": (0x330, 0xC0000024)}
    partial_modes = ("user-access", "readonly-output", "released-wait", "released-reference", "opaque-read", "opaque-exec")
    for machine, architecture in ((0x14C, "x86"), (0x8664, "x64")):
        width = 8 if machine == 0x8664 else 4
        for mode in (*success_modes, *status_modes, *partial_modes):
            name = f'{architecture}-{mode}'
            case = root / name
            case.mkdir()
            payload = reference_probe(machine, mode)
            sample = case / 'references.sys'
            sample.write_bytes(payload)
            process = subprocess.run([str(worker), 'run', str(sample), '--output', str(case / 'runs'),
                '--offline-replay', '--timeout', '5', '--max-instructions', '5000'],
                text=True, capture_output=True, timeout=60)
            assert process.returncode in (0, 1), (name, process.stdout, process.stderr)
            outcome = json.loads(process.stdout)
            run = Path(outcome['report']).parent
            summary = json.loads((run / 'summary.json').read_text())
            raw = (run / 'engine-report.json').read_bytes()
            report = json.loads(raw)
            partial = mode in partial_modes
            assert process.returncode == int(partial) and summary['status'] == ('partial' if partial else 'completed'), name
            assert summary['guest_entry_return'] == (None if partial else 0), name
            assert valid_summary(summary) and verify_artifact_manifest(run, summary['artifacts'], summary['artifact_groups']), name
            assert summary['sample']['sha256'] == hashlib.sha256(payload).hexdigest() and (run / 'input.pe').read_bytes() == payload, name
            assert summary['engine_report_sha256'] == hashlib.sha256(raw).hexdigest(), name
            assert all(summary['worker_containment'][key] for key in ('app_container', 'job_object', 'child_process_blocked')), name
            assert summary['network_broker_complete'] and json.loads((run / 'network-broker.json').read_text()) == [{'event': 'broker_closed'}], name
            data = reference_bytes(summary, run)
            references = report['kernel_object_references']
            assert int.from_bytes(data[0x300:0x300 + width], 'little') == int(references['types']['Thread']['identity'], 0), name
            if partial:
                assert data[0x3F8:0x3FC] != b'DONE' and report['entry_points'][0]['error'], name
                if mode.startswith('opaque-'):
                    error = report['entry_points'][0]['error']
                    assert error['type'] == ('invalid_execute' if mode == 'opaque-exec' else 'invalid_protect_read'), name
                    assert error['address'] == references['types']['Thread']['identity'], name
            else:
                assert summary['errors'] == [] and data[0x370:0x374] == b'EXIT' and data[0x3F8:0x3FC] == b'DONE', name
                assert report['kernel_scheduling']['open_thread_handles'] == 0 and report['kernel_scheduling']['threads'][0]['state'] == 'done', name
                assert int.from_bytes(data[0x328:0x32C], 'little') == 0x102, name
                assert int.from_bytes(data[0x338:0x33C], 'little') == int.from_bytes(data[0x340:0x344], 'little') == 0, name
                assert int.from_bytes(data[0x350:0x354], 'little') == 1, name
                assert references['events'][-1]['references_after'] == 0, name
                if mode in status_modes:
                    offset, expected = status_modes[mode]
                    assert int.from_bytes(data[offset:offset + 4], 'little') == expected, name
                else:
                    assert int.from_bytes(data[0x320:0x324], 'little') == int.from_bytes(data[0x330:0x334], 'little') == 0, name
            findings.append({'case': name, 'verified': True, 'report': str(run / 'summary.json')})
            print(f'{name}: native references, object lifetime, join/signal behavior and isolation verified', flush=True)
    (root / 'verification.json').write_text(json.dumps(findings, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('destination', type=Path)
    parser.add_argument('--worker', type=Path, default=ROOT / 'dist/Emumee/Emumee.exe')
    args = parser.parse_args()
    verify(args.destination.resolve(), args.worker.resolve())
