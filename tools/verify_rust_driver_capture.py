"""Sequential frozen Driver128 generated controls; never takes a sample path.

Large payload hashing is chunked. Read-only negative mutations use the8KiB case.
Requires already-completed recovery gates from the exact same frozen bundle.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

MIB=1024*1024
def require(ok,why):
    if not ok:raise AssertionError(why)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def digest_file(path,offset=0,length=None):
    value=hashlib.sha256()
    with path.open('rb')as f:
        f.seek(offset)
        while length is None or length:
            raw=f.read(MIB if length is None else min(MIB,length))
            if not raw:require(length in(None,0),'Short generated range');break
            value.update(raw)
            if length is not None:length-=len(raw)
    return value.hexdigest()
def read(path):return json.loads(path.read_bytes())
def write(path,value):path.write_text(json.dumps(value,indent=2)+'\n',encoding='utf-8')
def snapshot(root):
    return {str(p.relative_to(root)):{'size':p.stat().st_size,'sha256':digest_file(p),'links':p.stat().st_nlink}
            for p in sorted(root.rglob('*'))if p.is_file()}
def call(command,base,timeout=210):
    write(Path(str(base)+'.command.json'),[str(x)for x in command])
    result=subprocess.run([str(x)for x in command],capture_output=True,timeout=timeout,check=False)
    Path(str(base)+'.stdout.bin').write_bytes(result.stdout);Path(str(base)+'.stderr.bin').write_bytes(result.stderr)
    write(Path(str(base)+'.exit.json'),{'exit_code':result.returncode});return result
def state(summary):return summary.get('summary',summary)

def verify_payloads(run,summary,case):
    records=summary['artifacts'];total=0;hashes=set()
    for record in records:
        digest=record['sha256'];size=record['size'];filename=record['filename']
        require(filename==digest+'.bin'and len(digest)==64,'Non-full content-addressed filename')
        require(digest not in hashes and 0<size<=128*MIB,'Duplicate/oversized retained payload');hashes.add(digest);total+=size
        path=run/'artifacts'/filename
        require(path.stat().st_size==size and path.stat().st_nlink==1 and digest_file(path)==digest,'Actual payload size/full hash differs')
        projection=record['projection'];require(projection['size']==size and projection['sha256']==digest,'Projection payload binding differs')
        cursor=0
        for chunk in projection['chunks']:
            require(chunk['offset']==cursor and chunk['size']==min(8*MIB,size-cursor),'Chunk coverage differs')
            require(digest_file(path,cursor,chunk['size'])==chunk['sha256'],'Actual8MiB chunk digest differs');cursor+=chunk['size']
        require(cursor==size,'Incomplete chunk coverage')
        for chunk in projection['range_hashes']:
            require(digest_file(path,chunk['offset'],chunk['size'])==chunk['sha256'],'Actual reconstruction range hash differs')
        for observation in record['observations']:
            context=observation.get('context',{})
            if observation['kind']=='memory_snapshot'and context.get('layout')=='mapped_image':require(context['reconstruction']=='none','Snapshot mislabeled reconstructed')
            if observation['kind']=='carved_image'and context.get('source_layout')=='mapped_image':
                source=next(r for r in records if r['sha256']==context['source_snapshot_sha256'])
                require(any(o['kind']=='memory_snapshot'for o in source['observations']),'Reconstruction lacks retained snapshot')
                source_path=run/'artifacts'/source['filename'];cursor=0
                require(context['structural_only']and context['no_fixups']and context['image_size']==source['size']and context['raw_end']==size,'Reconstruction provenance differs')
                for segment in context['reconstruction_segments']:
                    require(segment['destination']==cursor and segment['size']>0,'Reconstruction has gaps/overlaps')
                    require(digest_file(source_path,segment['source'],segment['size'])==digest_file(path,cursor,segment['size']),'Reconstruction differs from snapshot bytes');cursor+=segment['size']
                require(cursor==size,'Reconstruction does not cover the entire output')
    require(total<=256*MIB,'Retained total exceeded')
    sizes=sorted(r['size']for r in records)
    expected={
        'small-raw':[8192],'raw32-plus':[32*MIB+4096],'raw64':[64*MIB],'raw128':[128*MIB],
        'mapped64':[32*MIB+512,64*MIB],'mapped128':[64*MIB+512,128*MIB],
        'mapped256-total':[128*MIB,128*MIB],'dedupe128':[128*MIB],
        'total256-overflow':[128*MIB,128*MIB],'scan-overflow':[],'single-overflow':[],'driver-entry64':[]}
    require(sizes==expected[case],case+': retained exact sizes differ')
    if case=='dedupe128':require(len(records[0]['observations'])==2,'Owned aliases duplicated data/lost provenance')
    if case in('total256-overflow','scan-overflow','single-overflow'):
        require(summary['omissions']['omitted_observations']>0 and summary['omissions']['omitted_bytes']>0,'Bound refusal silently dropped evidence')
    if case.startswith('mapped'):
        require(sum(o['kind']=='carved_image'for r in records for o in r['observations'])==1,'Mapped output lost carved identity')
        require(sum(o['kind']=='memory_snapshot'for r in records for o in r['observations'])==1,'Mapped output lost snapshot identity')
    return dict(payloads=len(records),bytes=total,sizes=sizes)

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--bundle',type=Path,required=True);parser.add_argument('--output-root',type=Path,required=True);parser.add_argument('--recovery-root',type=Path,required=True);args=parser.parse_args()
    repo=next(p for p in Path(__file__).resolve().parents if(p/'tools/check_residual_appcontainer.ps1').is_file())
    reference_raw=(repo/'rust/emumee-core/tests/data/driver_capture_reference.json').read_bytes()
    require(sha(reference_raw)=='d887b337285924203e17d426993726e52d891ac41aa17a1739196750d674a66e','Generated reference corpus drifted')
    reference={r['case']:r for r in json.loads(reference_raw)['cases']};require(len(reference)==12,'Missing generated recipe references')
    bundle=args.bundle.resolve(strict=True);root=args.output_root.resolve();recovery=args.recovery_root.resolve(strict=True)
    require(not root.exists(),'Use a fresh Driver128 evidence root');require(root!=bundle and bundle not in root.parents and root not in bundle.parents,'Evidence must be outside frozen bundle')
    receipt=read(bundle/'rust-worker-build.json');gates=read(recovery/'verification.json')
    require(isinstance(gates,list)and len(gates)==2 and all(g['verified']and g['broker_journal_unchanged']and g['original_bundle_dacl_restored']and g['old_run_unqualified']and g['owned_processes_remaining']==0 for g in gates),'Completed recovery controls required')
    recovered=read(recovery/'next-controller-crash/manifest.json');require(all(recovered[k]==receipt[k]for k in('source_tree_sha256','controller_sha256','worker_sha256')),'Recovery gates belong to another build')
    exe=bundle/'emumee-rs.exe';require(exe.is_file(),'Frozen controller missing');root.mkdir(parents=True)
    ps=shutil.which('pwsh')or shutil.which('powershell');require(ps is not None,'Existing Windows lifecycle controls require PowerShell')
    acl_script=root/'read-owned-acl.ps1';acl_script.write_text("param([string]$Path)\n$ErrorActionPreference='Stop'\n(Get-Acl -LiteralPath $Path).Sddl\n",encoding='ascii')
    def acl():
        result=subprocess.run([ps,'-NoProfile','-NonInteractive','-File',str(acl_script),str(bundle)],capture_output=True,check=False)
        require(result.returncode==0,'Cannot read bundle DACL');return result.stdout
    baseline_acl=acl();before=snapshot(bundle);write(root/'bundle-before.json',before)
    records=[];status=dict(schema=1,count=0,expected_count=36,verified=False,records=records,scope='Closed sequential generated Driver128 capture/report controls only; no sample execution or unpacking claim')
    write(root/'verification.json',status)
    cases=('small-raw','raw32-plus','raw64','raw128','mapped64','mapped128','mapped256-total','dedupe128','total256-overflow','scan-overflow','single-overflow','driver-entry64')
    faults=('crash-before-checkpoint','crash-after-checkpoint','timeout-after-checkpoint','tamper-payload','tamper-provenance','tamper-engine','profile-downgrade','tamper-request','tamper-input','unknown-request-field','foreign-owned-fixture')
    try:
        for case,fault in [(c,'none')for c in cases]+[('small-raw',f)for f in faults]:
            name=case+'-'+fault;run=root/name
            result=call([exe,'driver-capture-fixture',case,run,'--fault',fault],root/name)
            summary=read(run/'summary.json');manifest=read(run/'manifest.json');stop=read(run/'worker-stop.json');witness=read(run/'worker-containment.json')
            refusal={'tamper-request':'Driver128 request hash changed','tamper-input':'Driver128 fixed input hash/size changed','unknown-request-field':'Driver fixture schema/enum','foreign-owned-fixture':'Driver fixture fixed recipe/profile binding'}.get(fault)
            bad=refusal is not None or fault in('crash-before-checkpoint','tamper-payload','tamper-provenance','tamper-engine','profile-downgrade')
            expected='failed'if bad or fault=='crash-after-checkpoint'else'timeout'if fault=='timeout-after-checkpoint'else'completed'if case=='driver-entry64'else'partial'
            require(result.returncode==(0 if expected=='completed'else 1)and state(summary)['status']==expected and manifest['status']==expected,name+': status/exit differs')
            require(manifest['summary_sha256']==digest_file(run/'summary.json')and manifest['cleanup']=='restored'and stop['cleanup']=='restored'and acl()==baseline_acl,name+': document/lifecycle binding differs')
            require(all(manifest[k]==receipt[k]for k in('source_tree_sha256','controller_sha256','worker_sha256','unicorn_sha256')),name+': frozen source/binary receipt differs')
            require(witness['app_container']and witness['job_object']and witness['child_process_blocked']and witness['network_capabilities']==0,name+': containment missing')
            job=read(run/'driver-job-profile.json');require(job['profile']=='driver_capture_2048_v1'and job['process_memory_bytes']==2048*MIB and 0<job['peak_process_memory_bytes']<=2048*MIB,name+': actual sealed job peak missing')
            require(manifest['output_limits']==dict(max_bytes=1024*MIB,max_entries=10064,max_directories=8,max_depth=4)and manifest['physical_reserved_bytes']==840*MIB,name+': physical input/report/capture/IPC/journal budget differs')
            inspected=call([exe,'inspect-driver-capture',run],root/(name+'-inspect'))
            detail={}
            if bad:
                require(summary['schema']=='emumee.driver_capture_failure.v1'and summary['artifacts']==[]and not manifest['qualified']and inspected.returncode!=0,name+': corrupt/uncheckpointed evidence exposed')
            else:
                require(summary['schema']=='emumee.driver_capture.v1'and summary['profile']=='driver128_v1'and inspected.returncode==0,name+': strict Driver128 reader failed')
                require(state(summary)['guest_trace_complete']is False and state(summary)['network_broker_complete']is False,name+': unearned trace/broker claim')
                require(summary['binding']==manifest['binding']and summary['binding']['request_sha256']==digest_file(run/'request.json')and summary['binding']['input_sha256']==digest_file(run/'input.bin')and summary['binding']['containment_sha256']==digest_file(run/'worker-containment.json'),name+': request/input/witness binding differs')
                detail=verify_payloads(run,summary,case)
                ref=reference[case];require(summary['binding']['input_bytes']==ref['input_size']and summary['binding']['input_sha256']==ref['input_sha256'],name+': independent generated input reference differs')
                actual=sorted((r['size'],r['sha256'])for r in summary['artifacts']);expected_payloads=sorted((r['size'],r['sha256'])for r in ref['payloads']);require(actual==expected_payloads,name+': independent generated full payload reference differs')
                require(manifest['qualified']==(fault=='none'),name+': crash/timeout was qualified')
                require(state(summary)['checkpoint_recovered']==(fault!='none'),name+': checkpoint recovery classification differs')
                if case=='driver-entry64':require(state(summary)['guest_entry_return']==17 and state(summary)['instruction_count']>0,name+': actual DriverEntry return missing')
                else:require(state(summary)['instruction_count']==0 and state(summary)['guest_entry_return']is None,name+': static capture invented execution')
            if refusal is not None:
                require(stop['worker']['reason']=='exited'and stop['worker']['exit_code']==2 and refusal in(run/'worker-error.txt').read_text(encoding='utf-8'),name+': exact refusal not exercised')
                require(not any((run/p).exists()for p in('worker-ready.json','worker-summary.json','artifacts','artifact-checkpoint.json','driver-result.json')),name+': refused input reached capture/reporting')
                require(manifest['expected_refusal']==refusal and manifest['staged_request_sha256']==digest_file(run/'request.json')and manifest['staged_input_sha256']==digest_file(run/'input.bin'),name+': refusal forensic bindings differ')
                if fault=='tamper-request':require(manifest['request_sha256']!=manifest['staged_request_sha256'],name+': request hash control unchanged')
                else:require(manifest['request_sha256']==manifest['staged_request_sha256'],name+': decoder/input control corrupted request transport')
                if fault in('tamper-input','foreign-owned-fixture'):require(manifest['input_sha256']!=manifest['staged_input_sha256'],name+': input control unchanged')
            legacy=call([exe,'inspect-report',run,'--verify-artifacts'],root/(name+'-legacy-inspect'));require(legacy.returncode!=0,name+': separate profile silently admitted by legacy reader')
            if fault in('crash-before-checkpoint','crash-after-checkpoint'):require(stop['worker']['exit_code']==23,name+': crash control not exercised')
            if fault=='timeout-after-checkpoint':require(stop['worker']['reason']=='timeout',name+': timeout control not exercised')
            records.append(dict(kind='contained',name=name,verified=True,status=expected,exit_code=result.returncode,peak_process_memory_bytes=job['peak_process_memory_bytes'],summary_sha256=digest_file(run/'summary.json'),**detail))
            status['count']=len(records);write(root/'verification.json',status)
        good=root/'small-raw-none'
        mutations=('missing-engine','engine-hash','network-hash','manifest-provenance','projection-preview','payload-hash','filename-traversal','hardlink-payload','directory-payload','junction-artifacts','oversized-payload','unknown-profile','oversized-metadata')
        for mutation in mutations:
            target=root/('reader-'+mutation);shutil.copytree(good,target);summary=read(target/'summary.json');payload=target/'artifacts'/summary['artifacts'][0]['filename']
            require(payload.parent==target/'artifacts'and payload.stat().st_size==8192,'Only owned small fixture can be mutated')
            if mutation=='missing-engine':(target/'engine-report.json').rename(target/'engine-report.saved')
            elif mutation=='engine-hash':(target/'engine-report.json').write_bytes((target/'engine-report.json').read_bytes()+b' ')
            elif mutation=='network-hash':(target/'network-broker.json').write_bytes((target/'network-broker.json').read_bytes()+b' ')
            elif mutation=='manifest-provenance':
                value=read(target/'artifacts/manifest.json');value['payloads'][0]['observations'][0]['source']='forged';write(target/'artifacts/manifest.json',value)
            elif mutation=='projection-preview':summary['artifacts'][0]['projection']['preview']='forged';write(target/'summary.json',summary)
            elif mutation=='payload-hash':
                with payload.open('r+b')as f:f.seek(512);f.write(b'FAIL')
            elif mutation=='filename-traversal':summary['artifacts'][0]['filename']='../owned-sentinel.bin';write(target/'summary.json',summary);(target/'owned-sentinel.bin').write_bytes(b'owned-only')
            elif mutation=='hardlink-payload':os.link(payload,target/'owned-extra-link.bin')
            elif mutation=='directory-payload':payload.rename(target/'payload.saved');payload.mkdir()
            elif mutation=='junction-artifacts':
                original=target/'artifacts.saved';(target/'artifacts').rename(original)
                link_path=Path(os.path.abspath(target/'artifacts'));case_path=Path(os.path.abspath(target));owned_root=Path(os.path.abspath(root))
                require(case_path.parent==owned_root and link_path.parent==case_path and original.parent==case_path,'Owned junction path escaped fresh case/root')
                require(not any(c in str(link_path)+str(original)for c in '[]*?'),'Junction fixture paths must avoid provider wildcard characters')
                script=root/'create-owned-junction.ps1'
                script.write_text("param([string]$Link,[string]$Target)\n$ErrorActionPreference='Stop'\nNew-Item -ItemType Junction -Path $Link -Target $Target | Out-Null\n",encoding='ascii')
                link=call([ps,'-NoProfile','-NonInteractive','-File',script,link_path,original],root/'reader-junction-create')
                require(link.returncode==0 and link_path.is_junction(),'Owned directory junction setup failed')
                require(link_path.resolve(strict=True)==original.resolve(strict=True),'Owned junction target mismatch')
                junction_target_snapshot=snapshot(original)
                write(target/'owned-junction-evidence.json',dict(link=str(link_path),target=str(original),reparse_tag=link_path.lstat().st_reparse_tag,target_files=junction_target_snapshot,removed=False))
            elif mutation=='oversized-payload':summary['artifacts'][0]['size']=128*MIB+1;write(target/'summary.json',summary)
            elif mutation=='unknown-profile':summary['profile']='driver1024_v1';write(target/'summary.json',summary)
            elif mutation=='oversized-metadata':summary['artifacts'][0]['observations'][0]['source']='x'*(MIB+1);write(target/'summary.json',summary)
            try:
                proc=call([exe,'inspect-driver-capture',target],root/('reader-'+mutation+'-inspect'));require(proc.returncode!=0,mutation+': malformed/unsafe report passed')
            finally:
                if mutation=='junction-artifacts':
                    link_path=Path(os.path.abspath(target/'artifacts'));case_path=Path(os.path.abspath(target));owned_root=Path(os.path.abspath(root))
                    require(case_path.parent==owned_root and link_path.parent==case_path and original.parent==case_path,'Junction cleanup path escaped owned case/root')
                    require(link_path.is_junction()and link_path.resolve(strict=True)==original.resolve(strict=True)and link_path.lstat().st_reparse_tag==0xA0000003,'Junction cleanup refused changed link/target')
                    os.rmdir(link_path) # Nonrecursive Windows junction removal; never visits target.
                    require(not link_path.exists()and original.is_dir()and snapshot(original)==junction_target_snapshot,'Junction cleanup altered target evidence')
                    evidence=read(target/'owned-junction-evidence.json');evidence['removed']=True;write(target/'owned-junction-evidence.json',evidence)
            records.append(dict(kind='reader',name=mutation,exit_code=proc.returncode,verified=True));status['count']=len(records);write(root/'verification.json',status)
        repeat=call([exe,'recover-bundle'],root/'repeat-recovery');require(repeat.returncode==0,'Recovery command failed');recovered=json.loads(repeat.stdout)
        require(not recovered['recovered']and recovered['profiles']==0 and recovered['jobs']==0 and recovered['grants']==0,'Closed driver role left cleanup resources')
        residual_script=root/'check-owned-residual.ps1';residual_script.write_text("param([string]$Bundle,[string]$Run,[string]$Tool)\n$ErrorActionPreference='Stop'\n& $Tool -Roots @($Bundle,$Run) -WorkerRoots @($Bundle)\nif($LASTEXITCODE -ne 0){exit 1}\n",encoding='ascii')
        residual=call([ps,'-NoProfile','-NonInteractive','-File',residual_script,bundle,root,repo/'tools/check_residual_appcontainer.ps1'],root/'residual-check')
        require(residual.returncode==0 and acl()==baseline_acl,'Owned resource residue or bundle DACL changed')
        after=snapshot(bundle);write(root/'bundle-after.json',after);require(before==after,'Frozen bundle bytes/links changed')
        require(len(records)==status['expected_count'],'Missing Driver128 controls')
        status.update(verified=True,cleanup_plan_idempotent=True,exact_bundle_dacl_restored=True,residual_check_passed=True,large_controls_sequential=True,controller_peak_memory_measured=False)
        write(root/'verification.json',status);print(json.dumps({'verified':True,'count':len(records),'output_root':str(root)}))
    except BaseException as error:
        status['error']=str(error);write(root/'verification.json',status);raise

if __name__=='__main__':main()
