"""Verify passive diagnostics and native cache invalidation in the offline worker."""
import argparse,copy,hashlib,json,subprocess,sys
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1];sys.path[:0]=[str(ROOT),str(ROOT/'tools')]
import emumee.driver as driver
from emumee.pe import inspect_pe
from emumee.persona import load_persona
from emumee.reports import valid_summary,verify_artifact_manifest
from emumee.worker_build import verify_receipt
from tests.test_kernel_runtime import legacy_format_probe
from tests.test_kernel_provider_reads import provider_read_probe
from tests.test_driver_native_cache import changing_code_fixture,multiple_code_sections_fixture,idle_scheduler_fixture
from benchmark_driver_hooks import observations


def verify(root,worker):
    root.mkdir(parents=True,exist_ok=False);receipt=verify_receipt(worker,source_root=ROOT);rows=[]
    cases=[]
    for machine,arch in ((0x14c,'x86'),(0x8664,'x64')):
        cases.extend((f'{arch}-format-{capacity}',legacy_format_probe(machine,capacity),'format',capacity) for capacity in (64,19,3))
        cases.append((f'{arch}-latest-context',provider_read_probe(machine,True,True),'latest',None))
        cases.extend((f'{arch}-changed-code-{eviction}',changing_code_fixture(machine,eviction),'code',eviction) for eviction in (False,True))
        cases.extend((f'{arch}-cached-access-{budget}',multiple_code_sections_fixture(machine),'access',budget) for budget in (64,100000))
        cases.extend((f'{arch}-idle-scheduler-{budget}',idle_scheduler_fixture(machine),'idle',budget) for budget in (32,512,10000,100000))
    for name,payload,kind,option in cases:
        case=root/name;case.mkdir();source=case/'source';source.mkdir();sample=case/'fixture.sys';sample.write_bytes(payload)
        budget=option if kind in ('access','idle') else 10000
        partial=(kind=='access' and budget==64) or (kind=='idle' and budget<100000)
        persona=load_persona(None)
        if kind=='idle':persona['cpu']['cores']=4;persona['cpu']['threads_per_core']=1
        with patch.object(driver,'create_native_trace',lambda _:None):
            baseline=driver.run_driver(payload,inspect_pe(payload,'fixture.sys'),copy.deepcopy(persona),source,30,budget)
        assert baseline['instruction_limit_reached'] if partial else not baseline['errors']
        expected=observations(baseline,json.loads((source/'engine-report.json').read_text()))
        command=[str(worker),'run',str(sample),'--output',str(case/'runs'),'--offline-replay','--timeout','30','--max-instructions',str(budget)]
        if kind=='idle':
            config=case/'persona.json';config.write_text(json.dumps({'cpu':persona['cpu']}));command+=['--persona',str(config)]
        process=subprocess.run(command,text=True,capture_output=True,timeout=90)
        (case/'stdout.txt').write_text(process.stdout);(case/'stderr.txt').write_text(process.stderr)
        assert process.returncode==int(partial),(name,process.stdout,process.stderr)
        run=Path(json.loads(process.stdout)['report']).parent;summary=json.loads((run/'summary.json').read_text());raw=(run/'engine-report.json').read_bytes();report=json.loads(raw)
        assert valid_summary(summary) and verify_artifact_manifest(run,summary['artifacts'],summary['artifact_groups'])
        assert summary['sample']['sha256']==hashlib.sha256(payload).hexdigest()
        assert summary['engine_report_sha256']==hashlib.sha256(raw).hexdigest()
        assert summary['run_manifest']['worker_bundle_sha256']==receipt['worker_sha256']
        assert all(summary['worker_containment'][k] for k in ('app_container','job_object','child_process_blocked'))
        assert summary['network_broker_complete'] and not summary['network_attempts']
        assert report['driver_tracing']['backend']=='native_direct' and not report['driver_tracing']['callback_error']
        assert report['driver_tracing']['source_sha256']==receipt['driver_native_assets']['driver_trace']['source_sha256']
        assert observations(summary,report)==expected,(name,'native observations differ')
        if kind=='idle':
            source_report=json.loads((source/'engine-report.json').read_text())
            assert report['kernel_scheduling']==source_report['kernel_scheduling'] and report['kernel_ipi']==source_report['kernel_ipi']
        if kind=='format':
            state=report['kernel_formatting'];record=state['observations'][0]
            assert not state['capture_errors'] and record['text']=='-464 4294967338 emu'[:option]
            assert record['truncated']==(option<19)
        elif kind=='latest':
            state=report['kernel_provider_reads']
            assert not state['capture_errors'] and state['total_reads']==1200
            assert [r['sequence'] for r in state['latest_pc_observations']]==[600,1200]
            assert state['omitted_reads']==941
        elif kind=='code':assert report['driver_image_changes']['executed_after_write_pages']
        elif partial:assert summary['instruction_limit_reached'] and summary['instruction_count']==budget
        else:assert report['driver_tracing']['fast_instructions']>10000
        row={'case':name,'verified':True,'report':str(run/'summary.json'),'observations_equal':True};rows.append(row);print(json.dumps(row),flush=True)
    (root/'verification.json').write_text(json.dumps(rows,indent=2)+'\n')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('destination',type=Path);parser.add_argument('--worker',type=Path,required=True)
    args=parser.parse_args();verify(args.destination.resolve(),args.worker.resolve())
