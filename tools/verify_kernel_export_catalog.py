"""Validate export-name metadata and explicit unsupported operations offline."""
import argparse,hashlib,json,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT))
from tests.test_kernel_export_catalog import catalog_probe,verify_catalog,MODES,NEGATIVE
from tests.test_kernel_process import process_probe,verify_process
from emumee.reports import valid_summary,verify_artifact_manifest
from emumee.worker_build import verify_receipt


def verify(root,worker,skip_cases=()):
    root.mkdir(parents=True,exist_ok=False);receipt=verify_receipt(worker,source_root=ROOT)
    cases=[(mode,catalog_probe(mode),mode in NEGATIVE,0x8664,None) for mode in MODES]
    for label,machine,build in [('disabled-x86',0x14c,None),('disabled-22000',0x8664,22000),('disabled-22621',0x8664,22621)]:
        cases.append((label,process_probe(machine),False,machine,build))
    findings=[]
    for mode,payload,partial,machine,build in cases:
        if mode in skip_cases:continue
        case=root/mode;case.mkdir();sample=case/'catalog.sys';sample.write_bytes(payload)
        command=[str(worker),'run',str(sample),'--output',str(case/'runs'),'--offline-replay',
                 '--timeout','10','--max-instructions','20000']
        if build is not None:
            persona=case/'persona.json';persona.write_text(json.dumps({'windows_build':build}))
            command+=['--persona',str(persona)]
        proc=subprocess.run(command,capture_output=True,text=True,timeout=60)
        assert proc.returncode==(1 if partial else 0),(mode,proc.stdout,proc.stderr)
        run=Path(json.loads(proc.stdout)['report']).parent;summary=json.loads((run/'summary.json').read_text())
        raw=(run/'engine-report.json').read_bytes();report=json.loads(raw)
        assert valid_summary(summary) and verify_artifact_manifest(run,summary['artifacts'],summary['artifact_groups'])
        assert summary['sample']['sha256']==hashlib.sha256(payload).hexdigest() and (run/'input.pe').read_bytes()==payload
        assert summary['run_manifest']['worker_bundle_sha256']==receipt['worker_sha256']
        assert summary['engine_report_sha256']==hashlib.sha256(raw).hexdigest()
        assert summary['status']==('partial' if partial else 'completed')
        assert all(summary['worker_containment'][k] for k in ('app_container','job_object','child_process_blocked'))
        assert summary['network_broker_complete'] and not summary['network_attempts']
        assert json.loads((run/'network-broker.json').read_text())==[{'event':'broker_closed'}]
        if mode.startswith('disabled-'):
            verify_process(summary,report,run,machine,'read');state=report['kernel_export_catalog']
            assert not state['enabled'] and state['metadata_only_added']==0 and state['address'] is None
        else:
            verify_catalog(summary,report,run,mode)
        findings.append(dict(case=mode,verified=True,report=str(run/'summary.json')))
        print(mode+': native metadata lookup, operation traps, compatibility and isolation verified',flush=True)
    (root/'verification.json').write_text(json.dumps(findings,indent=2)+'\n')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('destination',type=Path)
    parser.add_argument('--worker',type=Path,required=True)
    parser.add_argument('--skip-cases',nargs='*',default=());args=parser.parse_args()
    verify(args.destination.resolve(),args.worker.resolve(),args.skip_cases)
