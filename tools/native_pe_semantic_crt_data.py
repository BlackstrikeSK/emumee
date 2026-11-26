"""Qualify the accepted process-owned CRT data-cell behavior independently."""
import argparse
import json
from pathlib import Path
import subprocess

from native_pe_crt_data_reference import observe, SOURCE
from native_pe_m4 import verify
from native_pe_m6 import build_gate
from native_pe_semantic_strlen import load, record
from native_pe_staging_seal import binding
from native_pe_semantic_proofs import contract_identities as proof_contracts
from native_pe_worklist import atomic_write, fingerprint, runtime_snapshot, validate_evidence

ROOT=Path(__file__).resolve().parents[1]
CORPUS=ROOT/'rust/emumee-engine/src/api/crt_data_semantic_reference.json'
DECISION=ROOT/'docs/native-pe/behavior-decisions.json'
DECISION_TEXT=ROOT/'docs/native-pe/behavior-decisions.md'
OUTPUT='semantic-crt-data'
KINDS=('Alias','Thread','Long','Parent','Release','Protect','Free','Nx')
TESTS=[
 'crt_data_tests::m5_crt_data_import_accessor_lookup_and_thread_mutations_share_real_guest_storage',
 'crt_data_tests::m5_crt_data_cannot_be_freed_reprotected_or_executed_by_guest_apis',
 'crt_data_tests::m5_crt_data_budget_stops_preserve_only_executed_mutations',
 'api::abi_tests::inventory_distinguishes_mutable_crt_data_from_a_callable_accessor',
]


def reference():
    document=observe();assert load(CORPUS)==document,'CRT reference changed'
    decision=load(DECISION)
    assert decision['decision']=='Keep documented Rust improvements (Recommended)', 'No accepted behavior decision'
    assert decision['date']=='2026-11-24' and 'shared' in decision['scope']
    return document,decision


def cases(root):
    selected=[root/'fixtures-final'/f'{arch}-m5-crt-data-{kind}-20000' for arch in ('X86','X64') for kind in KINDS]
    assert all(p.is_dir() for p in selected),'Missing CRT ownership controls'
    return selected


def source_tests(index):
    run,=[r for r in load(index)['runs'] if r['suite']=='rust-tests'];assert run['exit_code']==0
    text=(ROOT/run['log']).read_text(encoding='utf-8')
    for name in TESTS:assert f'test {name} ... ok' in text,name


def observations(root,fixture):
    execution=binding(root/OUTPUT/fixture.name,fixture/'sample.exe')['result']['execution']
    kind=fixture.name.split('-')[-2];storage=execution['crt_startup']['msvcrt_command_line']
    assert storage['address']%4096==0 and storage['size']==(8192 if kind=='Long' else 4096)
    assert execution['api_events_omitted']==0
    if kind in ('Alias','Thread','Long','Parent'):
        assert execution['error'] is None and execution['guest_entry_return']==1
        events=[e for e in execution['api_events'] if e['api']=='msvcrt.__p__acmdln']
        assert len(events)==(4 if kind in ('Thread','Parent') else 3)
        assert all(e['result']==storage['address'] and not e['pending'] and e['error'] is None for e in events)
        if kind=='Thread':assert len({e['thread_id'] for e in events})==2
        if kind=='Parent':
            assert {e['process_id'] for e in events}=={1024,1025}
            child,=[p for p in execution['user_processes'] if p['id']==1025]
            assert child['failure'] is None and child['exit_code']==42 and child['backing_released']
    else:
        assert execution['error'] and execution['guest_entry_return'] is None
        if kind=='Nx':
            fault=execution['native_memory_fault'];assert fault['access']=='execute' and fault['address']==storage['address']
        else:
            expected='no owned allocation' if kind=='Free' else 'CRT startup-owned'
            assert expected in execution['error']
    return dict(case=fixture.name,storage=storage,completion=execution['completion_reason'])


def run(root,index):
    build_gate(root,index);source_tests(index);reference();output=root/OUTPUT;output.mkdir()
    for fixture in cases(root):
        limits=load(fixture/'limits.json')
        command=[str(root/'bundle/emumee-rs.exe'),'run',str(fixture/'sample.exe'),'--output',str(output/fixture.name),
            '--inputs',str(fixture/'inputs.json'),'--max-instructions',str(limits['max_instructions']),
            '--timeout-us',str(limits['timeout_us']),'--',*load(fixture/'arguments.json')]
        result=subprocess.run(command,capture_output=True,timeout=120)
        (output/f'{fixture.name}.stdout').write_bytes(result.stdout);(output/f'{fixture.name}.stderr').write_bytes(result.stderr)
        assert result.returncode==(0 if fixture.name.split('-')[-2] in ('Alias','Thread','Long','Parent') else 1),(fixture.name,result.returncode,result.stderr)
        verify(root,fixture,output_directory=OUTPUT);observations(root,fixture)
        print(f'{fixture.name} independently verified',flush=True)


def proof_path(root):return root/f'qualified-semantic-crt-data-{fingerprint(runtime_snapshot(ROOT))}.json'


def seal(root,index,*,check=False):
    build_gate(root,index);source_tests(index);oracle,decision=reference();selected=cases(root);observed=[]
    for fixture in selected:
        verify(root,fixture,output_directory=OUTPUT);observed.append(observations(root,fixture))
    paths={CORPUS,ROOT/SOURCE,DECISION,DECISION_TEXT}
    for directory in (root/'bundle',root/OUTPUT,*selected):paths.update(p for p in directory.rglob('*') if p.is_file())
    document=dict(schema=1,profile='emumee.native-semantic.crt-data.v1',runtime_fingerprint=fingerprint(runtime_snapshot(ROOT)),
        source_tree_sha256=load(root/'bundle/rust-worker-build.json')['source_tree_sha256'],
        contract_identities=proof_contracts(oracle['contracts']),
        oracle=oracle,accepted_decision=decision,tests=TESTS,controls=observed,artifacts=[record(p) for p in sorted(paths)])
    document['fingerprint']=fingerprint(document);path=proof_path(root)
    if check:assert load(path)==document,'CRT data proof differs'
    else:
        assert not path.exists(),'Preserve sealed evidence';atomic_write(path,json.dumps(document,indent=2)+'\n')
    print(json.dumps(dict(contracts=4,controls=len(observed),fingerprint=document['fingerprint'])))


def publish_evidence(root,index,ledger_path,*,collect_only=False):
    seal(root,index,check=True);ledger=load(ledger_path);assert ledger['runtime_source_hashes']==runtime_snapshot(ROOT)
    oracle,decision=reference();selected={(r['module'],r['export'],r['kind'],r['architecture']) for r in oracle['contracts']};claims=[];proof=record(proof_path(root))
    for row in ledger['entries']:
        if tuple(row[k] for k in ('module','export','kind','architecture')) not in selected:continue
        binding=row['rust_dispatch'];assert binding['return_type']=='pointer'
        if row['kind']=='data':
            assert binding['dispatch']=='data_model' and binding['callable'] is False
            assert binding['data_layout']==dict(cell_bytes=4 if row['architecture']=='x86' else 8,alignment=4 if row['architecture']=='x86' else 8,mutable=True,executable=False,lifetime='process')
        else:assert binding['dispatch']=='model' and binding['callable'] is True
        claim={k:row[k] for k in ('module','export','kind','architecture','source_fingerprint')}
        claim.update(semantic_status='verified_intentional_change',submitted_route='verified',
            accepted_deviation=dict(decision=decision['decision'],date=decision['date'],policy=record(DECISION),
                change='Retain one mutable process-owned CRT cell instead of fresh accessor allocations; preserve tested sharing, child isolation, ownership and NX controls'),
            behavioral_evidence=[dict(id=f'accepted-crt-cell-{row["kind"]}-{row["architecture"]}-v1',architecture=row['architecture'],source_fingerprint=row['source_fingerprint'],
                oracle='Pinned frozen callback observations establish the departure; accepted independent identity/ownership/isolation properties and actual guest assertions establish the retained behavior',
                baseline=record(CORPUS),limits=dict(pointer_bytes=4 if row['architecture']=='x86' else 8,long_argument_bytes=5000),
                tests=[*TESTS,*[p.name for p in cases(root) if p.name.startswith(row['architecture'].upper())]],
                negative_controls=['Free rejected','Reprotect rejected','CPU execution denied','Budget prefixes do not invent completion','Independent child storage'],
                artifacts=[proof,record(CORPUS),record(DECISION),record(DECISION_TEXT)])])
        validate_evidence(claim);claims.append(claim)
    assert len(claims)==4
    if collect_only:return claims
    path=ROOT/'docs/native-pe/evidence.json';maintained=load(path)
    maintained['entries']=[r for r in maintained['entries'] if tuple(r[k] for k in ('module','export','kind','architecture')) not in selected]+claims
    atomic_write(path,json.dumps(maintained,indent=2)+'\n')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--root',required=True,type=Path);parser.add_argument('--source-index',required=True,type=Path)
    action=parser.add_mutually_exclusive_group();action.add_argument('--seal',action='store_true');action.add_argument('--check',action='store_true');action.add_argument('--record-evidence',type=Path)
    args=parser.parse_args();root,index=args.root.resolve(),args.source_index.resolve()
    if args.record_evidence:publish_evidence(root,index,args.record_evidence.resolve())
    elif args.seal or args.check:seal(root,index,check=args.check)
    else:run(root,index)
