"""Verify native file object-type identity semantics and bounded partial failures offline."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from tests.test_kernel_file_type import file_type_probe,verify_file_type,MODES,EXPORTS
from emumee.reports import valid_summary,verify_artifact_manifest
from emumee.worker_build import verify_receipt


def verify(root,worker,exports=None,modes=None):
    root.mkdir(parents=True,exist_ok=False)
    receipt=verify_receipt(worker,source_root=ROOT)
    findings=[]
    selected=list(EXPORTS) if exports is None else exports
    assert selected and len(set(selected))==len(selected) and all(name in EXPORTS for name in selected)
    selected_modes=MODES if modes is None else modes
    assert selected_modes and len(set(selected_modes))==len(selected_modes) and all(mode in MODES for mode in selected_modes)
    cases=((export_name,machine,arch,mode) for export_name in selected for machine,arch in ((0x14C,'x86'),(0x8664,'x64')) for mode in selected_modes if mode!='handle-mismatch' or export_name=='IoFileObjectType')
    for export_name,machine,arch,mode in cases:
        name=f'{export_name}-{arch}-{mode}'
        case=root/name
        case.mkdir()
        payload=file_type_probe(machine,mode,export_name)
        sample=case/'file-type.sys'
        sample.write_bytes(payload)
        proc=subprocess.run([str(worker),'run',str(sample),'--output',str(case/'runs'),
            '--offline-replay','--timeout','10','--max-instructions','10000'],
            text=True,capture_output=True,timeout=60)
        assert proc.returncode==(0 if mode in ('read','missing','handle-mismatch') else 1),(name,proc.stdout,proc.stderr)
        run=Path(json.loads(proc.stdout)['report']).parent
        summary=json.loads((run/'summary.json').read_text())
        raw=(run/'engine-report.json').read_bytes()
        report=json.loads(raw)
        assert valid_summary(summary) and verify_artifact_manifest(run,summary['artifacts'],summary['artifact_groups'])
        assert summary['sample']['sha256']==hashlib.sha256(payload).hexdigest()
        assert (run/'input.pe').read_bytes()==payload
        assert summary['run_manifest']['worker_bundle_sha256']==receipt['worker_sha256']
        assert summary['engine_report_sha256']==hashlib.sha256(raw).hexdigest()
        assert summary['status']==('completed' if mode in ('read','missing','handle-mismatch') else 'partial')
        assert all(summary['worker_containment'][key] for key in ('app_container','job_object','child_process_blocked'))
        assert summary['network_broker_complete'] and not summary['network_attempts']
        assert json.loads((run/'network-broker.json').read_text())==[{'event':'broker_closed'}]
        verify_file_type(summary,report,run,machine,mode,export_name)
        findings.append({'case':name,'verified':True,'report':str(run/'summary.json')})
        print(f'{name}: native File type/import/EAT agreement, opaque rights, reference mismatch and isolation verified',flush=True)
    (root/'verification.json').write_text(json.dumps(findings,indent=2))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('destination',type=Path)
    parser.add_argument('--worker',type=Path,required=True)
    parser.add_argument('--exports',help='Comma-separated subset of the type-export matrix')
    parser.add_argument('--modes',help='Comma-separated subset of fixture modes')
    args=parser.parse_args()
    verify(args.destination.resolve(),args.worker.resolve(),args.exports.split(',') if args.exports else None,args.modes.split(',') if args.modes else None)
