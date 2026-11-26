"""Qualify frozen interlocked transitions through the contained user worker."""
from __future__ import annotations
import argparse
from collections import defaultdict
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace

from native_pe_interlocked_reference import observe, NAMES, SOURCE
from native_pe_legacy_literals import normalizer_factory, NORMALIZER
from native_pe_m4 import verify
from native_pe_m6 import build_gate
from native_pe_semantic_strlen import load, record
from native_pe_staging_seal import binding
from native_pe_semantic_proofs import contract_identities as proof_contracts
from native_pe_worklist import atomic_write, fingerprint, runtime_snapshot, validate_evidence

ROOT=Path(__file__).resolve().parents[1]
CORPUS=ROOT/'rust/emumee-engine/src/api/interlocked_reference.json'
OUTPUT='semantic-interlocked-replay-02'
TESTS=[
 'api::user_interlocked::tests::frozen_interlocked_vectors_match_returns_memory_and_error_preservation',
 'api::user_interlocked::tests::interlocked_lookup_is_finite_and_cannot_grant_kernel_authority',
 'semantic_interlocked_tests::interlocked_submitted_vectors_preserve_results_errors_full_memory_and_width_aliases',
 'semantic_interlocked_tests::interlocked_submitted_overflow_and_denied_memory_never_return_success',
 'semantic_interlocked_tests::interlocked_dynamic_exports_execute_without_static_target_imports',
]


def reference():
    document=observe()
    assert load(CORPUS)==document, 'Frozen interlocked observations changed'
    factory,digest=normalizer_factory()
    for name in NAMES:
        normalizer=factory()
        normalizer.api=SimpleNamespace(get_export_func_handler=lambda dll,export:
            (dll,name) if dll=='kernel32' and export==name else (None,None))
        for suffix in ('A','W'):
            assert normalizer.normalize_import_miss('kernel32',name+suffix)==('kernel32',name)
    return document,digest


def controls(document=None):
    document=document or reference()[0]
    groups=defaultdict(list);result={}
    for index,case in enumerate(document['cases']):
        arch=case['architecture'].upper();export=case['export']
        if case['error'] is None:groups[arch,export].append(case)
        else:result[f'{arch}-semantic-interlocked-error-{export}-{index:03}']=dict(kind='error',cases=[case])
    for (arch,export),cases in sorted(groups.items()):
        for group,start in enumerate(range(0,len(cases),4)):
            result[f'{arch}-semantic-interlocked-{export}-{group:03}']=dict(kind='normal',cases=cases[start:start+4])
    for arch in ('x86','x64'):
        selected=[]
        for name in NAMES:
            selected.append(next(c for c in document['cases'] if c['architecture']==arch and c['export']==name
                and c['error'] is None and c['old']==0xffffffff
                and (len(c['arguments'])==1 or c['arguments'][1]==1)
                and (len(c['arguments'])<3 or c['arguments'][2]==0xffffffff)))
        result[f'{arch.upper()}-semantic-interlocked-dynamic']=dict(kind='dynamic',cases=selected)
    assert len(result)==133
    return result


def fixtures(root,expected):
    selected=sorted(p for p in (root/'fixtures-final').iterdir() if p.is_dir() and '-semantic-interlocked-' in p.name)
    assert {p.name for p in selected}==set(expected), 'Interlocked controls differ'
    return selected


def source_tests(index):
    run,=[r for r in load(index)['runs'] if r['suite']=='rust-tests']
    assert run['exit_code']==0
    text=(ROOT/run['log']).read_text(encoding='utf-8')
    for name in TESTS:assert f'test {name} ... ok' in text, name


def observations(root,fixture,spec):
    execution=binding(root/OUTPUT/fixture.name,fixture/'sample.exe')['result']['execution']
    assert execution['api_events_omitted']==0
    events=[e for e in execution['api_events'] if e['api'].startswith('kernel32.Interlocked')]
    expected=[('kernel32.'+c['export']+suffix,c) for c in spec['cases']
              for suffix in (('',) if spec['kind']=='error' else ('','A','W'))]
    assert [e['api'] for e in events]==[name for name,_ in expected]
    for event,(_,case) in zip(events,expected):
        assert event['arguments']==case['arguments'] and event['last_error']==0x12345678
        assert not event['pending']
        if spec['kind']=='error':
            assert event['error'] and event['result'] is None
            if case['error']=='OverflowError':assert 'integer conversion' in event['error']
            else:
                protect,=[e for e in execution['api_events'] if e['api']=='kernel32.VirtualProtect']
                value=1 if not case['synthetic_access']['readable'] else 2
                assert protect['arguments'][:3]==[0x26000000,65536,value] and protect['result']==1
        else:assert event['error'] is None and event['result']==case['result']
    if spec['kind']=='error':
        assert execution['error'] and execution['guest_entry_return'] is None
        return dict(case=fixture.name,error_category=spec['cases'][0]['error'])
    assert execution['error'] is None and execution['guest_entry_return']==1
    arena,=[a for a in execution['artifacts'] if any(o['kind']=='guest_file' and
        o['guest_path'].lower().endswith('interlocked-memory.bin') for o in a['observations'])]
    assert arena['size']==65536 and arena['sha256']==spec['cases'][-1]['arena_sha256']
    return dict(case=fixture.name,calls=len(events),arena_sha256=arena['sha256'])


def run(root,index):
    build_gate(root,index);source_tests(index)
    expected=controls();output=root/OUTPUT;output.mkdir()
    for fixture in fixtures(root,expected):
        limits=load(fixture/'limits.json')
        command=[str(root/'bundle/emumee-rs.exe'),'run',str(fixture/'sample.exe'),'--output',str(output/fixture.name),
            '--inputs',str(fixture/'inputs.json'),'--max-instructions',str(limits['max_instructions']),
            '--timeout-us',str(limits['timeout_us'])]
        result=subprocess.run(command,capture_output=True,timeout=120)
        (output/f'{fixture.name}.stdout').write_bytes(result.stdout);(output/f'{fixture.name}.stderr').write_bytes(result.stderr)
        assert result.returncode==(1 if expected[fixture.name]['kind']=='error' else 0),(fixture.name,result.returncode,result.stderr)
        verify(root,fixture,output_directory=OUTPUT);observations(root,fixture,expected[fixture.name])
        print(f'{fixture.name} independently verified',flush=True)


def proof_path(root):return root/f'qualified-semantic-interlocked-{fingerprint(runtime_snapshot(ROOT))}.json'


def seal(root,index,*,check=False):
    build_gate(root,index);source_tests(index)
    oracle,normalizer_hash=reference();expected=controls(oracle);selected=fixtures(root,expected);observed=[]
    for fixture in selected:
        verify(root,fixture,output_directory=OUTPUT);observed.append(observations(root,fixture,expected[fixture.name]))
    paths={CORPUS,ROOT/SOURCE,ROOT/NORMALIZER}
    for directory in (root/'bundle',root/OUTPUT,*selected):paths.update(p for p in directory.rglob('*') if p.is_file())
    document=dict(schema=1,profile='emumee.native-semantic.interlocked.v1',runtime_fingerprint=fingerprint(runtime_snapshot(ROOT)),
        source_tree_sha256=load(root/'bundle/rust-worker-build.json')['source_tree_sha256'],
        contract_identities=proof_contracts(oracle['contracts']),
        oracle=oracle,normalizer_sha256=normalizer_hash,tests=TESTS,controls=observed,artifacts=[record(p) for p in sorted(paths)])
    document['fingerprint']=fingerprint(document);path=proof_path(root)
    if check:assert load(path)==document,'Interlocked proof differs'
    else:
        assert not path.exists(),'Preserve sealed evidence';atomic_write(path,json.dumps(document,indent=2)+'\n')
    print(json.dumps(dict(contracts=10,controls=len(observed),fingerprint=document['fingerprint'])))


def publish_evidence(root,index,ledger_path,*,collect_only=False):
    seal(root,index,check=True);ledger=load(ledger_path)
    assert ledger['runtime_source_hashes']==runtime_snapshot(ROOT)
    oracle,_=reference();selected={(r['module'],r['export'],r['kind'],r['architecture']) for r in oracle['contracts']}
    expected=controls(oracle);claims=[];proof=record(proof_path(root))
    for row in ledger['entries']:
        if tuple(row[k] for k in ('module','export','kind','architecture')) not in selected:continue
        assert row['rust_dispatch']['dispatch']=='model' and row['rust_dispatch']['return_type']=='u32'
        related=[n for n,s in expected.items() if any(c['export']==row['export'] and c['architecture']==row['architecture'] for c in s['cases'])]
        claim={k:row[k] for k in ('module','export','kind','architecture','source_fingerprint')}
        claim.update(semantic_status='verified_model',submitted_route='verified',behavioral_evidence=[dict(
            id=f'frozen-{row["export"]}-{row["architecture"]}-v1',architecture=row['architecture'],source_fingerprint=row['source_fingerprint'],
            oracle='Extracted frozen interlocked bodies over synthetic memory; scalar/complete-memory transitions and explicit conversion failures; synthetic memory faults do not assert exact legacy exception formatting',
            baseline=record(CORPUS),limits=dict(arena_bytes=65536,integer_bits=32,native_argument_bits=32 if row['architecture']=='x86' else 64),
            tests=[*TESTS,*related],negative_controls=['Overflow without write','Full-width comparison miss','Read/write denial','Unknown name','Kernel authority denial'],
            artifacts=[proof,record(CORPUS),record(ROOT/SOURCE),record(ROOT/NORMALIZER)])])
        validate_evidence(claim);claims.append(claim)
    assert len(claims)==10
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
