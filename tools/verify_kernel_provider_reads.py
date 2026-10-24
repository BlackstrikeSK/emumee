"""Verify passive provider-read diagnostics using isolated harmless drivers."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tests.test_kernel_provider_reads import provider_read_probe, verify_provider_reads, verify_query_read_context
from tests.test_kernel_system_information import system_information_probe
from emumee.reports import valid_summary, verify_artifact_manifest
from emumee.worker_build import verify_receipt


def verify(root, worker):
    root.mkdir(parents=True, exist_ok=False)
    receipt = verify_receipt(worker, source_root=ROOT)
    findings = []
    for machine, arch in ((0x14C, 'x86'), (0x8664, 'x64')):
        for mode in ('single-read', 'bounded-burst', 'standard', 'extended'):
            burst = mode == 'bounded-burst'
            query = mode in ('standard', 'extended')
            name = f'{arch}-{mode}'
            case = root / name
            case.mkdir()
            payload = system_information_probe(machine, mode) if query else provider_read_probe(machine, burst)
            sample = case / 'provider-read.sys'
            sample.write_bytes(payload)
            process = subprocess.run([str(worker), 'run', str(sample), '--output', str(case / 'runs'),
                '--offline-replay', '--timeout', '5', '--max-instructions', '3000'],
                text=True, capture_output=True, timeout=60)
            assert process.returncode == 0, (name, process.stdout, process.stderr)
            result = json.loads(process.stdout)
            run = Path(result['report']).parent
            summary = json.loads((run / 'summary.json').read_text())
            raw = (run / 'engine-report.json').read_bytes()
            report = json.loads(raw)
            assert summary['status'] == 'completed' and summary['guest_entry_return'] == 0 and not summary['errors']
            assert valid_summary(summary) and verify_artifact_manifest(run, summary['artifacts'], summary['artifact_groups'])
            assert summary['run_manifest']['worker_bundle_sha256'] == receipt['worker_sha256']
            assert summary['sample']['sha256'] == hashlib.sha256(payload).hexdigest()
            assert (run / 'input.pe').read_bytes() == payload
            assert summary['engine_report_sha256'] == hashlib.sha256(raw).hexdigest()
            assert all(summary['worker_containment'][key] for key in ('app_container', 'job_object', 'child_process_blocked'))
            assert summary['network_broker_complete'] and not summary['network_attempts']
            assert json.loads((run / 'network-broker.json').read_text()) == [{'event': 'broker_closed'}]
            if query:
                verify_query_read_context(report, mode)
            else:
                verify_provider_reads(report, burst)
            findings.append({'case': name, 'verified': True, 'report': str(run / 'summary.json')})
            print(f'{name}: native provider bytes, context, bounds, evidence and isolation verified', flush=True)
    (root / 'verification.json').write_text(json.dumps(findings, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('destination', type=Path)
    parser.add_argument('--worker', type=Path, required=True)
    args = parser.parse_args()
    verify(args.destination.resolve(), args.worker.resolve())
