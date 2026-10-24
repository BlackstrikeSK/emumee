"""Prove isolated native provider metadata discovery and fail-closed calls."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tests.test_kernel_providers import provider_metadata_probe, verify_provider_metadata
from emumee.reports import valid_summary, verify_artifact_manifest
from emumee.worker_build import verify_receipt


def verify(root, worker):
    root.mkdir(parents=True, exist_ok=False)
    receipt = verify_receipt(worker, source_root=ROOT)
    findings = []
    for machine, arch in ((0x14C, 'x86'), (0x8664, 'x64')):
        for provider in ('ci', 'cng'):
            for mode in ('read', 'call', 'write'):
                name = f'{arch}-{provider}-{mode}'
                case = root / name
                case.mkdir()
                data = provider_metadata_probe(machine, provider, mode)
                sample = case / 'provider-metadata.sys'
                sample.write_bytes(data)
                process = subprocess.run([str(worker), 'run', str(sample), '--output', str(case / 'runs'),
                    '--offline-replay', '--timeout', '5', '--max-instructions', '3000'],
                    text=True, capture_output=True, timeout=60)
                assert process.returncode == (0 if mode == 'read' else 1), (name, process.stdout, process.stderr)
                outcome = json.loads(process.stdout)
                run = Path(outcome['report']).parent
                summary = json.loads((run / 'summary.json').read_text())
                raw = (run / 'engine-report.json').read_bytes()
                report = json.loads(raw)
                assert valid_summary(summary) and verify_artifact_manifest(run, summary['artifacts'], summary['artifact_groups'])
                assert summary['sample']['sha256'] == hashlib.sha256(data).hexdigest()
                assert (run / 'input.pe').read_bytes() == data
                assert summary['run_manifest']['worker_bundle_sha256'] == receipt['worker_sha256']
                assert summary['engine_report_sha256'] == hashlib.sha256(raw).hexdigest()
                assert summary['status'] == ('completed' if mode == 'read' else 'partial')
                assert all(summary['worker_containment'][key] for key in ('app_container', 'job_object', 'child_process_blocked'))
                assert summary['network_broker_complete'] and not summary['network_attempts']
                assert json.loads((run / 'network-broker.json').read_text()) == [{'event': 'broker_closed'}]
                verify_provider_metadata(summary, report, run, machine, provider, mode)
                findings.append({'case': name, 'verified': True, 'report': str(run / 'summary.json')})
                print(f'{name}: native metadata discovery, read-only/NX boundary, no fabricated provider result and isolation verified', flush=True)
    (root / 'verification.json').write_text(json.dumps(findings, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('destination', type=Path)
    parser.add_argument('--worker', type=Path, required=True)
    args = parser.parse_args()
    verify(args.destination.resolve(), args.worker.resolve())
