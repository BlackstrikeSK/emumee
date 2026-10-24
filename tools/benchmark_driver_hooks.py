"""Alternating harmless scan benchmark against receipt-bound build37 source."""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import statistics
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT)); sys.path.insert(0,str(ROOT/'tools'))
from profile_driver_scan import scan_fixture
from emumee.driver import run_driver
from emumee.pe import inspect_pe
from emumee.persona import load_persona


def reference():
    receipt=json.loads((ROOT/'output/driver-real-bundle-37/worker-build.json').read_text())
    modules={}
    for name,path,source in (('cache','reference_instruction_cache_37.py','src/emumee/instruction_cache.py'),
                             ('driver','reference_driver_37.py','src/emumee/driver.py')):
        target=ROOT/'output'/path
        assert hashlib.sha256(target.read_bytes()).hexdigest()==receipt['source_files'][source]
        spec=importlib.util.spec_from_file_location('emumee._benchmark_reference_'+name,target)
        module=importlib.util.module_from_spec(spec); sys.modules[spec.name]=module; spec.loader.exec_module(module)
        modules[name]=module
    modules['driver'].InstructionCache=modules['cache'].InstructionCache
    return modules['driver'].run_driver


def observations(result,report):
    return {'instruction_count':result['instruction_count'],'guest_entry_return':result['guest_entry_return'],
        'virtual_uptime_ms':report['virtual_uptime_ms'],'virtual_tsc':report['virtual_tsc'],
        'memory':[r['memory'] for r in report['entry_points']],
        'control_flow_tail':report['control_flow_tail'],'instruction_tail':report['instruction_tail'],
        'context_observations':report['context_observations'],
        'artifacts':sorted((r['source'],r['sha256']) for r in result['artifacts'])}


def main():
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument('output',type=Path)
    parser.add_argument('--rounds',type=int,default=3); parser.add_argument('--iterations',type=int,default=2000)
    args=parser.parse_args(); root=args.output.resolve(); root.mkdir(parents=True,exist_ok=False)
    funcs={'reference':reference(),'optimized':run_driver}; payload=scan_fixture(args.iterations)
    info=inspect_pe(payload,'generated-scan.sys'); persona=load_persona(None); timings=[]; expected=None; backend=None
    for round_index in range(args.rounds):
        for name in (('reference','optimized') if round_index%2==0 else ('optimized','reference')):
            case=root/f'{round_index}-{name}'; case.mkdir()
            begin=time.perf_counter(); result=funcs[name](payload,info,copy.deepcopy(persona),case,120,20_000_000)
            elapsed=time.perf_counter()-begin
            assert result['guest_entry_return']==0 and not result['errors'],result['errors']
            report=json.loads((case/'engine-report.json').read_text()); observed=observations(result,report)
            if name=='optimized': backend=report.get('driver_tracing',{'backend':'python'})
            if expected is None: expected=observed
            assert observed==expected,f'{name}: guest observations changed'
            row={'round':round_index,'mode':name,'seconds':elapsed,'instruction_count':result['instruction_count']}
            timings.append(row); print(json.dumps(row),flush=True)
    medians={name:statistics.median(r['seconds'] for r in timings if r['mode']==name) for name in funcs}
    outcome={'verified_observations_equal':True,'timings':timings,'median_seconds':medians,
        'speedup':medians['reference']/medians['optimized'],'optimized_backend':backend,
        'scope':'Generated native scalar scan only; no claim of real-driver speedup until measured in the isolated worker'}
    (root/'verification.json').write_text(json.dumps(outcome,indent=2)); print(json.dumps(outcome),flush=True)


if __name__=='__main__': main()
