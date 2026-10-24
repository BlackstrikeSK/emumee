"""Verify named callback object contracts inside the frozen offline worker."""
import argparse,hashlib,json,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from tests.test_kernel_named_callbacks import named_callback_probe,verify_named_callbacks,MODES,PARTIAL,EXPORTS
from tests.test_kernel_process import process_probe
from tests.test_kernel_system_information import image_range
from emumee.reports import valid_summary,verify_artifact_manifest
from emumee.worker_build import verify_receipt


def verify(root,worker,architecture):
    root.mkdir(parents=True,exist_ok=False)
    receipt=verify_receipt(worker,source_root=ROOT);findings=[]
    for machine,arch in ((0x14c,'x86'),(0x8664,'x64')):
        if architecture not in ('all',arch):continue
        cases=[(m,named_callback_probe(machine,m),m in PARTIAL) for m in MODES]
        cases += [('lookup-'+name,process_probe(machine,'lookup',name,read_data=False),False) for name in EXPORTS]
        for mode,payload,partial in cases:
            name=arch+'-'+mode;case=root/name;case.mkdir()
            sample=case/'named-callback.sys';sample.write_bytes(payload)
            proc=subprocess.run([str(worker),'run',str(sample),'--output',str(case/'runs'),
                '--offline-replay','--timeout','10','--max-instructions','10000'],
                capture_output=True,text=True,timeout=60)
            assert proc.returncode==(1 if partial else 0),(name,proc.stdout,proc.stderr)
            run=Path(json.loads(proc.stdout)['report']).parent
            summary=json.loads((run/'summary.json').read_text());raw=(run/'engine-report.json').read_bytes()
            report=json.loads(raw)
            assert valid_summary(summary) and verify_artifact_manifest(run,summary['artifacts'],summary['artifact_groups'])
            assert summary['sample']['sha256']==hashlib.sha256(payload).hexdigest()
            assert (run/'input.pe').read_bytes()==payload
            assert summary['run_manifest']['worker_bundle_sha256']==receipt['worker_sha256']
            assert summary['engine_report_sha256']==hashlib.sha256(raw).hexdigest()
            assert summary['status']==('partial' if partial else 'completed')
            assert all(summary['worker_containment'][k] for k in ('app_container','job_object','child_process_blocked'))
            assert summary['network_broker_complete'] and not summary['network_attempts']
            assert json.loads((run/'network-broker.json').read_text())==[{'event':'broker_closed'}]
            if mode.startswith('lookup-'):
                data=image_range(summary,run,0x2300,0x100);width=8 if machine==0x8664 else 4
                values=[int.from_bytes(data[n:n+width],'little') for n in (0x10,0x20,0x50)]
                assert values[0] and len(set(values))==1 and not summary['errors'] and summary['guest_entry_return']==0
                assert not report['kernel_named_callbacks']['objects']
            else:
                verify_named_callbacks(summary,report,run,machine,mode)
            findings.append(dict(case=name,verified=True,report=str(run/'summary.json')))
            print(name+': native callback contract, references, unsupported paths and isolation verified',flush=True)
    (root/'verification.json').write_text(json.dumps(findings,indent=2)+'\n')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('destination',type=Path);parser.add_argument('--worker',type=Path,required=True)
    parser.add_argument('--arch',choices=('all','x86','x64'),default='all')
    args=parser.parse_args();verify(args.destination.resolve(),args.worker.resolve(),args.arch)
