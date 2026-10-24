"""Check guest-empty history and private byte guards in the offline worker."""
import argparse,hashlib,json,subprocess,sys
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tools')]
import emumee.driver as driver
from emumee.pe import inspect_pe
from emumee.persona import load_persona
from emumee.kernel_code_reference import KNOWN_REFERENCE_SHA256
from emumee.worker_build import verify_receipt
from emumee.reports import valid_summary,verify_artifact_manifest
from benchmark_driver_hooks import observations
from tests.test_kernel_unloaded_history import MODES,NEGATIVE,history_probe,verify_history,history_reference
from tests.test_kernel_process import process_probe

def verify(root,worker,reference):
    root.mkdir(parents=True,exist_ok=False);receipt=verify_receipt(worker,source_root=ROOT)
    ref=reference.read_bytes();assert hashlib.sha256(ref).hexdigest()==KNOWN_REFERENCE_SHA256
    cases=[(mode,history_probe(mode),ref,mode in NEGATIVE) for mode in MODES]
    cases.append(('unbound',history_probe('pointer'),history_reference(),True))
    for name in ('ZwUnloadDriver','MmUnloadSystemImage'):
        cases.append((name,process_probe(0x8664,'call',name,read_data=False),ref,True))
    rows=[]
    for mode,payload,ref,partial in cases:
        case=root/mode;case.mkdir();sample=case/'history.sys';sample.write_bytes(payload)
        data=case/'reference.pe';data.write_bytes(ref)
        proc=subprocess.run([str(worker),'run',str(sample),'--offline-replay','--output',str(case/'runs'),
            '--timeout','30','--max-instructions','20000','--kernel-code-reference',str(data)],text=True,capture_output=True,timeout=120)
        (case/'stdout.txt').write_text(proc.stdout);(case/'stderr.txt').write_text(proc.stderr)
        assert proc.returncode==int(partial),(mode,proc.stdout,proc.stderr)
        run=Path(json.loads(proc.stdout)['report']).parent;s=json.loads((run/'summary.json').read_text());e=json.loads((run/'engine-report.json').read_text())
        assert valid_summary(s) and verify_artifact_manifest(run,s['artifacts'],s['artifact_groups'])
        assert all(s['worker_containment'][key] for key in ('app_container','job_object','child_process_blocked'))
        assert s['network_broker_complete'] and not s['network_attempts']
        assert s['run_manifest']['worker_bundle_sha256']==receipt['worker_sha256']
        assert e['driver_tracing']['backend']=='native_direct' and not e['driver_tracing']['callback_error']
        assert e['driver_tracing']['source_sha256']==receipt['driver_native_assets']['driver_trace']['source_sha256']
        if mode=='unbound':
            assert not e['kernel_code_reference']['guest_unload_history']['enabled'] and s['guest_entry_return'] is None
        elif mode in ('ZwUnloadDriver','MmUnloadSystemImage'):
            assert s['guest_entry_return'] is None and s['errors']
            error=next(r['error'] for r in e['entry_points'] if r.get('error'))
            assert error['api_name']=='ntoskrnl.'+mode
            assert e['kernel_code_reference']['guest_unload_history']['recorded_image_unloads']==0
        else:verify_history(s,e,run,mode)
        source=case/'python';source.mkdir()
        with patch.object(driver,'create_native_trace',lambda _:None):
            baseline=driver.run_driver(payload,inspect_pe(payload,'history.sys'),load_persona(None),source,30,20000,kernel_code_reference=ref)
        assert observations(s,e)==observations(baseline,json.loads((source/'engine-report.json').read_text()))
        row={'case':mode,'verified':True,'report':str(run/'summary.json'),'observations_equal':True};rows.append(row);print(json.dumps(row),flush=True)
    assert len(rows)==13
    (root/'verification.json').write_text(json.dumps(rows,indent=2)+'\n')

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('destination',type=Path)
    parser.add_argument('--worker',type=Path,required=True);parser.add_argument('--reference',type=Path,required=True)
    args=parser.parse_args();verify(args.destination.resolve(),args.worker.resolve(),args.reference.resolve())
