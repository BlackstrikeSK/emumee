"""Verify static code inspection and refusals in the packaged offline worker."""
import argparse,hashlib,json,struct,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tools')]
from emumee.driver import run_driver
from emumee.pe import inspect_pe
from emumee.persona import load_persona
from emumee.kernel_code_reference import KNOWN_REFERENCE_SHA256
from emumee.worker_build import verify_receipt
from emumee.reports import valid_summary,verify_artifact_manifest
from inspect_driver_run import inspect
from benchmark_driver_hooks import observations
from tests.test_kernel_code_reference import (generated_reference,reference_probe,verify_reference,MODES,
    exported_reference,exported_reference_probe,verify_exported_reference)
from tests.test_kernel_system_information import image_range
from tests.fixtures.build_driver import build_driver
from tests.fixtures.build_native import build


def verify(root,worker,authenticated_reference=None,skip_cases=()):
    assert set(skip_cases)<=set(MODES)
    root.mkdir(parents=True,exist_ok=False);receipt=verify_receipt(worker,source_root=ROOT);rows=[]
    def launch(name,payload,reference,extra=()):
        case=root/name;case.mkdir();sample=case/'reference-probe.sys';sample.write_bytes(payload)
        args=[str(worker),'run',str(sample),'--output',str(case/'runs'),'--offline-replay','--timeout','30','--max-instructions','20000']
        if reference is not None:
            path=case/'reference.pe';path.write_bytes(reference);args+=['--kernel-code-reference',str(path)]
        process=subprocess.run([*args,*extra],text=True,capture_output=True,timeout=120)
        (case/'stdout.txt').write_text(process.stdout);(case/'stderr.txt').write_text(process.stderr)
        return case,process
    def reports(case,process):
        run=Path(json.loads(process.stdout)['report']).parent;s=json.loads((run/'summary.json').read_text());e=json.loads((run/'engine-report.json').read_text())
        assert valid_summary(s) and verify_artifact_manifest(run,s['artifacts'],s['artifact_groups'])
        assert all(s['worker_containment'][k] for k in ('app_container','job_object','child_process_blocked'))
        assert s['network_broker_complete'] and not s['network_attempts']
        assert s['run_manifest']['worker_bundle_sha256']==receipt['worker_sha256']
        assert e['driver_tracing']['backend']=='native_direct' and not e['driver_tracing']['callback_error']
        assert e['driver_tracing']['source_sha256']==receipt['driver_native_assets']['driver_trace']['source_sha256']
        inspection=inspect(run,case/'reference-probe.sys');assert inspection['report_integrity_verified']
        return run,s,e
    for mode in MODES:
        if mode in skip_cases:continue
        payload=reference_probe(mode);ref=generated_reference();case,process=launch(mode,payload,ref)
        assert process.returncode==(1 if mode in ('call','write','private-read','api-write') else 0),(mode,process.stdout,process.stderr)
        run,s,e=reports(case,process);verify_reference(s,e,run,mode)
        source=case/'source';source.mkdir();baseline=run_driver(payload,inspect_pe(payload,'reference-probe.sys'),load_persona(None),source,30,20000,kernel_code_reference=ref)
        assert observations(s,e)==observations(baseline,json.loads((source/'engine-report.json').read_text()))
        row={'case':mode,'verified':True,'report':str(run/'summary.json'),'observations_equal':True};rows.append(row);print(json.dumps(row),flush=True)
    for mode in ('lookup','read','api-read','call','write','data'):
        payload=exported_reference_probe(mode);ref=exported_reference()
        case,process=launch('export-'+mode,payload,ref)
        assert process.returncode==(1 if mode in ('call','write') else 0),(mode,process.stdout,process.stderr)
        run,s,e=reports(case,process);verify_exported_reference(s,e,run,mode)
        source=case/'source';source.mkdir()
        baseline=run_driver(payload,inspect_pe(payload,'reference-probe.sys'),load_persona(None),source,30,20000,kernel_code_reference=ref)
        assert observations(s,e)==observations(baseline,json.loads((source/'engine-report.json').read_text()))
        row={'case':'export-'+mode,'verified':True,'report':str(run/'summary.json'),'observations_equal':True}
        rows.append(row);print(json.dumps(row),flush=True)
    ref=bytearray(generated_reference());struct.pack_into('<I',ref,0x98+56,0x1047000)
    case,process=launch('large-reservation',reference_probe('read'),bytes(ref));assert process.returncode==0,(process.stdout,process.stderr)
    run,s,e=reports(case,process);verify_reference(s,e,run,'read')
    assert e['kernel_code_reference']['source_image_size']==0x1047000
    assert int(e['kernel_export_catalog']['address'],0)>=0xfffff80201047000
    rows.append({'case':'large-reservation','verified':True,'report':str(run/'summary.json')});print('large-reservation: correct provider separation verified',flush=True)
    case,process=launch('default-no-reference',reference_probe('read'),None);assert process.returncode==1,(process.stdout,process.stderr)
    run,s,e=reports(case,process);assert e['kernel_code_reference'] is None and s['guest_entry_return'] is None
    rows.append({'case':'default-no-reference','verified':True,'report':str(run/'summary.json')})
    if authenticated_reference is not None:
        ref=authenticated_reference.read_bytes();assert hashlib.sha256(ref).hexdigest()==KNOWN_REFERENCE_SHA256
        import pefile
        pe=pefile.PE(data=ref,fast_load=True)
        for mode in ('read','call'):
            payload=reference_probe(mode,code_rva=0x200000,call_rva=0x85e330)
            case,process=launch('authenticated-'+mode,payload,ref)
            assert process.returncode==(0 if mode=='read' else 1),(process.stdout,process.stderr)
            run,s,e=reports(case,process);state=e['kernel_code_reference']
            assert state['sha256']==KNOWN_REFERENCE_SHA256 and state['execution_allowed'] is False
            assert state['provenance']=='pinned_authenticated_Microsoft_reference'
            if mode=='read':assert image_range(s,run,0x23c0,8)==pe.get_data(0x200000,8)
            else:
                error=next(r['error'] for r in e['entry_points'] if r.get('error'))
                assert error['type']=='unsupported_private_kernel_api' and error['api_name']=='ntoskrnl.MmAllocateIndependentPages'
                assert state['denials'][-1]['access']=='execute' and s['guest_entry_return'] is None
            row={'case':'authenticated-'+mode,'verified':True,'report':str(run/'summary.json')};rows.append(row);print(json.dumps(row),flush=True)
        from tests.test_kernel_process import process_probe
        pe.parse_data_directories(directories=[0])
        exported=next(symbol for symbol in pe.DIRECTORY_ENTRY_EXPORT.symbols if symbol.name==b'PsSetContextThread')
        for mode in ('read','call','write'):
            payload=process_probe(0x8664,mode if mode!='read' else 'lookup','PsSetContextThread',read_data=mode=='read')
            case,process=launch('authenticated-export-'+mode,payload,ref)
            assert process.returncode==(0 if mode=='read' else 1),(mode,process.stdout,process.stderr)
            run,s,e=reports(case,process);data=image_range(s,run,0x2300,0x100)
            pointer=lambda offset:int.from_bytes(data[offset:offset+8],'little')
            assert pointer(0x10)==pointer(0x20)==pointer(0x50)==0xfffff80200000000+exported.address
            if mode=='read':
                assert not s['errors'] and s['guest_entry_return']==0
                assert data[0x18:0x20]==data[0x28:0x30]==data[0x58:0x60]==pe.get_data(exported.address,8)
            else:
                assert s['errors'] and s['guest_entry_return'] is None
                error=next(r['error'] for r in e['entry_points'] if r.get('error'))
                assert error['api_name']=='ntoskrnl.PsSetContextThread'
                assert e['kernel_code_reference']['denials'][-1]['access']==('execute' if mode=='call' else 'write')
            assert not any(0xfffff80200000000+exported.address<=int(item['pc'],0)<0xfffff80200000000+exported.address+16 for item in e['instruction_tail'])
            row={'case':'authenticated-export-'+mode,'verified':True,'report':str(run/'summary.json')}
            rows.append(row);print(json.dumps(row),flush=True)
    negatives=[('x86-driver',build_driver(0x14c),generated_reference(),()),
        ('user-mode',build(0x8664),generated_reference(),()),
        ('x86-reference',reference_probe('read'),build(0x14c),()),
        ('bad-reference',reference_probe('read'),b'not a PE',()),
        ('missing-reference',reference_probe('read'),None,('--kernel-code-reference',str(root/'missing.pe'))),
        ('oversize-reference',reference_probe('read'),bytes(32*1024*1024+1),())]
    persona=root/'wrong-profile.json';persona.write_text(json.dumps({'windows_build':22000}))
    negatives.append(('wrong-profile',reference_probe('read'),generated_reference(),('--persona',str(persona))))
    for name,payload,ref,extra in negatives:
        case,process=launch(name,payload,ref,extra)
        assert process.returncode==2 and not list((case/'runs').glob('*/summary.json')),(name,process.stdout,process.stderr)
        row={'case':name,'verified':True,'guest_execution_prevented':True,'exit_code':2,'report':None};rows.append(row);print(json.dumps(row),flush=True)
    assert len(rows)==(28 if authenticated_reference else 23)-len(set(skip_cases))
    (root/'verification.json').write_text(json.dumps(rows,indent=2)+'\n')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('destination',type=Path);parser.add_argument('--worker',type=Path,required=True);parser.add_argument('--authenticated-reference',type=Path)
    parser.add_argument('--skip-cases',nargs='*',default=())
    args=parser.parse_args();verify(args.destination.resolve(),args.worker.resolve(),args.authenticated_reference.resolve() if args.authenticated_reference else None,args.skip_cases)
