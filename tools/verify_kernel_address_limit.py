"""Verify native address-limit data reads and protection inside the offline worker."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from tests.test_kernel_address_limit import address_limit_probe, verify_address_limit
from emumee.reports import valid_summary, verify_artifact_manifest
from emumee.persona import load_persona
from emumee.worker_build import verify_receipt


def verify(root,worker):
    root.mkdir(parents=True,exist_ok=False)
    receipt=verify_receipt(worker,source_root=ROOT)
    findings=[]
    for machine,arch in ((0x14C,'x86'),(0x8664,'x64')):
        for mode,build in (('read',22631),('read',22000),('write',22631),('call',22631)):
            name=f'{arch}-{mode}-{build}'
            case=root/name
            case.mkdir()
            payload=address_limit_probe(machine,mode)
            sample=case/'address-limit.sys'
            sample.write_bytes(payload)
            persona=load_persona(None)
            persona['windows_build']=build
            profile=case/'persona.json'
            profile.write_text(json.dumps(persona))
            proc=subprocess.run([str(worker),'run',str(sample),'--output',str(case/'runs'),
                '--persona',str(profile),'--offline-replay','--timeout','5','--max-instructions','2000'],
                text=True,capture_output=True,timeout=60)
            assert proc.returncode==(0 if mode=='read' else 1),(name,proc.stdout,proc.stderr)
            run=Path(json.loads(proc.stdout)['report']).parent
            summary=json.loads((run/'summary.json').read_text())
            raw=(run/'engine-report.json').read_bytes()
            report=json.loads(raw)
            assert valid_summary(summary) and verify_artifact_manifest(run,summary['artifacts'],summary['artifact_groups'])
            assert summary['sample']['sha256']==hashlib.sha256(payload).hexdigest()
            assert (run/'input.pe').read_bytes()==payload
            assert summary['run_manifest']['worker_bundle_sha256']==receipt['worker_sha256']
            assert summary['engine_report_sha256']==hashlib.sha256(raw).hexdigest()
            assert summary['status']==('completed' if mode=='read' else 'partial')
            assert all(summary['worker_containment'][key] for key in ('app_container','job_object','child_process_blocked'))
            assert summary['network_broker_complete'] and not summary['network_attempts']
            assert json.loads((run/'network-broker.json').read_text())==[{'event':'broker_closed'}]
            verify_address_limit(summary,report,run,machine,mode,build)
            findings.append({'case':name,'verified':True,'report':str(run/'summary.json')})
            print(f'{name}: native data/lookup agreement and read-only/NX boundary verified',flush=True)
    (root/'verification.json').write_text(json.dumps(findings,indent=2))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('destination',type=Path)
    parser.add_argument('--worker',type=Path,required=True)
    args=parser.parse_args()
    verify(args.destination.resolve(),args.worker.resolve())
