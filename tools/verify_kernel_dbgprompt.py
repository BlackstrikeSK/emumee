"""Qualify no-input DbgPrompt using harmless drivers in the offline worker."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'tools')]
import emumee.driver as driver
from emumee.pe import inspect_pe
from emumee.persona import load_persona
from emumee.kernel_code_reference import KNOWN_REFERENCE_SHA256
from emumee.reports import valid_summary,verify_artifact_manifest
from emumee.worker_build import verify_receipt
from benchmark_driver_hooks import observations
from tests.test_kernel_dbgprompt import (MODES,REFERENCE_MODES,NEGATIVE,
    prompt_probe,prompt_reference,verify_prompt)
from tests.test_kernel_code_reference import CODE_RVA


def verify(root,worker,authenticated_reference):
    root.mkdir(parents=True,exist_ok=False)
    receipt=verify_receipt(worker,source_root=ROOT)
    cases=[(f'{machine:x}-{mode}',machine,mode,None,CODE_RVA+0x180)
           for machine in (0x14c,0x8664) for mode in MODES]
    cases.extend((mode,0x8664,mode,prompt_reference(),CODE_RVA+0x180) for mode in REFERENCE_MODES)
    ref=authenticated_reference.read_bytes()
    assert hashlib.sha256(ref).hexdigest()==KNOWN_REFERENCE_SHA256
    cases.extend(('authenticated-'+mode,0x8664,mode,ref,0x5a5520) for mode in REFERENCE_MODES)
    rows=[]
    for name,machine,mode,reference,rva in cases:
        case=root/name;case.mkdir()
        payload=prompt_probe(machine,mode,rva)
        sample=case/'prompt.sys';sample.write_bytes(payload)
        args=[str(worker),'run',str(sample),'--offline-replay','--timeout','30',
              '--max-instructions','20000','--output',str(case/'runs')]
        if reference is not None:
            data=case/'reference.pe';data.write_bytes(reference)
            args+=['--kernel-code-reference',str(data)]
        process=subprocess.run(args,text=True,capture_output=True,timeout=120)
        (case/'stdout.txt').write_text(process.stdout);(case/'stderr.txt').write_text(process.stderr)
        assert process.returncode==int(mode in NEGATIVE),(name,process.stdout,process.stderr)
        run=Path(json.loads(process.stdout)['report']).parent
        summary=json.loads((run/'summary.json').read_text())
        raw=(run/'engine-report.json').read_bytes();report=json.loads(raw)
        assert valid_summary(summary) and verify_artifact_manifest(run,summary['artifacts'],summary['artifact_groups'])
        assert summary['sample']['sha256']==hashlib.sha256(payload).hexdigest()
        assert (run/'input.pe').read_bytes()==payload
        assert summary['engine_report_sha256']==hashlib.sha256(raw).hexdigest()
        assert summary['run_manifest']['worker_bundle_sha256']==receipt['worker_sha256']
        assert all(summary['worker_containment'][key] for key in ('app_container','job_object','child_process_blocked'))
        assert summary['network_broker_complete'] and not summary['network_attempts']
        assert json.loads((run/'network-broker.json').read_text())==[{'event':'broker_closed'}]
        trace=report['driver_tracing']
        assert trace['backend']=='native_direct' and not trace['callback_error']
        assert trace['source_sha256']==receipt['driver_native_assets']['driver_trace']['source_sha256']
        verify_prompt(summary,report,run,machine,mode,rva)
        source=case/'python';source.mkdir()
        with patch.object(driver,'create_native_trace',lambda _:None):
            baseline=driver.run_driver(payload,inspect_pe(payload,'prompt.sys'),load_persona(None),source,30,20000,kernel_code_reference=reference)
        baseline_report=json.loads((source/'engine-report.json').read_text())
        assert observations(summary,report)==observations(baseline,baseline_report)
        assert report['kernel_debugger_state']==baseline_report['kernel_debugger_state']
        row={'case':name,'verified':True,'report':str(run/'summary.json'),'observations_equal':True}
        rows.append(row);print(json.dumps(row),flush=True)
    assert len(rows)==28
    (root/'verification.json').write_text(json.dumps(rows,indent=2)+'\n')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('destination',type=Path)
    parser.add_argument('--worker',type=Path,required=True)
    parser.add_argument('--authenticated-reference',type=Path,required=True)
    args=parser.parse_args()
    verify(args.destination.resolve(),args.worker.resolve(),args.authenticated_reference.resolve())
