"""Verify opaque private HAL symbol metadata and bounded partial failures offline."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from tests.test_kernel_opaque_data import opaque_probe,verify_opaque,MODES
from emumee.reports import valid_summary,verify_artifact_manifest
from emumee.worker_build import verify_receipt


def verify(root,worker):
    root.mkdir(parents=True,exist_ok=False)
    receipt=verify_receipt(worker,source_root=ROOT)
    findings=[]
    for machine,arch in ((0x14C,'x86'),(0x8664,'x64')):
        for mode in MODES:
            name=f'{arch}-{mode}'
            case=root/name
            case.mkdir()
            payload=opaque_probe(machine,mode)
            sample=case/'opaque-data.sys'
            sample.write_bytes(payload)
            proc=subprocess.run([str(worker),'run',str(sample),'--output',str(case/'runs'),
                '--offline-replay','--timeout','10','--max-instructions','10000'],
                text=True,capture_output=True,timeout=60)
            assert proc.returncode==(0 if mode in ('lookup','missing','valid') else 1),(name,proc.stdout,proc.stderr)
            run=Path(json.loads(proc.stdout)['report']).parent
            summary=json.loads((run/'summary.json').read_text())
            raw=(run/'engine-report.json').read_bytes()
            report=json.loads(raw)
            assert valid_summary(summary) and verify_artifact_manifest(run,summary['artifacts'],summary['artifact_groups'])
            assert summary['sample']['sha256']==hashlib.sha256(payload).hexdigest()
            assert (run/'input.pe').read_bytes()==payload
            assert summary['run_manifest']['worker_bundle_sha256']==receipt['worker_sha256']
            assert summary['engine_report_sha256']==hashlib.sha256(raw).hexdigest()
            assert summary['status']==('completed' if mode in ('lookup','missing','valid') else 'partial')
            assert all(summary['worker_containment'][key] for key in ('app_container','job_object','child_process_blocked'))
            assert summary['network_broker_complete'] and not summary['network_attempts']
            assert json.loads((run/'network-broker.json').read_text())==[{'event':'broker_closed'}]
            verify_opaque(summary,report,run,machine,mode)
            findings.append({'case':name,'verified':True,'report':str(run/'summary.json')})
            print(f'{name}: native metadata address agreement, unmodeled private-field/API traps and isolation verified',flush=True)
    (root/'verification.json').write_text(json.dumps(findings,indent=2))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('destination',type=Path)
    parser.add_argument('--worker',type=Path,required=True)
    args=parser.parse_args()
    verify(args.destination.resolve(),args.worker.resolve())
