"""Sequential executed Driver128 captures, only compiler-owned fixed cases.

Requires this exact frozen build's completed36 foundation and recovery controls.
The independent corpus contains expected bytes, never execution evidence.
"""
import argparse,hashlib,json,os,shutil,subprocess,sys
from pathlib import Path

REPO=next(p for p in Path(__file__).resolve().parents if(p/'tools/check_residual_appcontainer.ps1').is_file())
sys.path.insert(0,str(REPO/'tools'))
from verify_rust_driver_capture import require,sha,digest_file,read,write,snapshot,call,state
M=1024*1024
def payloads(run,summary,reference):
 actual=sorted((r['size'],r['sha256'])for r in summary['artifacts']);expected=sorted((r['size'],r['sha256'])for r in reference['payloads']);require(actual==expected,'Independent actual capture/reconstruction SHA differs')
 for record in summary['artifacts']:
  path=run/'artifacts'/record['filename'];require(record['filename']==record['sha256']+'.bin'and path.stat().st_size==record['size']and path.stat().st_nlink==1 and digest_file(path)==record['sha256'],'Actual owned payload hash/size differs')
  cursor=0
  for chunk in record['projection']['chunks']:
   require(chunk['offset']==cursor and chunk['size']==min(8*M,record['size']-cursor)and digest_file(path,cursor,chunk['size'])==chunk['sha256'],'Pinned chunk coverage/hash differs');cursor+=chunk['size']
  require(cursor==record['size'],'Incomplete payload chunk coverage')
  for chunk in record['projection']['range_hashes']:require(digest_file(path,chunk['offset'],chunk['size'])==chunk['sha256'],'Actual marker/reconstruction range hash differs')
  for observation in record['observations']:
   context=observation.get('context',{})
   if observation['kind']=='memory_snapshot':
    require(context.get('reconstruction','none')=='none','Snapshot labeled reconstructed')
    if reference['capture_complete']:
     require(record['sha256']==reference['post_image_sha256'],'Captured root snapshot differs from executed expected image')
     with path.open('rb')as file:
      for marker in reference['markers']:file.seek(marker['rva']);require(file.read(1)==bytes([marker['expected']]),'Actual near/final-page guest mutation absent')
   if observation['kind']=='carved_image':
    require(context['source_layout']=='mapped_image'and context['structural_only']and context['no_fixups'],'Reconstruction provenance changed')
    source=next(r for r in summary['artifacts']if r['sha256']==context['source_snapshot_sha256']);source_path=run/'artifacts'/source['filename'];cursor=0
    for segment in context['reconstruction_segments']:
     require(segment['destination']==cursor and segment['size']>0 and digest_file(source_path,segment['source'],segment['size'])==digest_file(path,cursor,segment['size']),'Entire raw reconstruction not bound to actual snapshot');cursor+=segment['size']
    require(cursor==record['size'],'Incomplete reconstruction coverage')
    with path.open('rb')as file:file.seek(1040);require(file.read(1)==b'\xa7','Guest near mutation missing from raw reconstruction')

def rebind_engine(target,mutate):
 engine=read(target/'engine-report.json');mutate(engine);write(target/'engine-report.json',engine)
 summary=read(target/'summary.json');summary['engine_sha256']=digest_file(target/'engine-report.json');summary['engine_bytes']=(target/'engine-report.json').stat().st_size;write(target/'summary.json',summary)

def main():
 p=argparse.ArgumentParser();p.add_argument('--bundle',type=Path,required=True);p.add_argument('--output-root',type=Path,required=True);p.add_argument('--recovery-root',type=Path,required=True);p.add_argument('--foundation-root',type=Path,required=True);args=p.parse_args()
 bundle=args.bundle.resolve(strict=True);root=args.output_root.resolve();foundation=args.foundation_root.resolve(strict=True);recovery=args.recovery_root.resolve(strict=True)
 require(not root.exists()and root!=bundle and root not in bundle.parents and bundle not in root.parents,'Use fresh evidence outside the frozen bundle');receipt=read(bundle/'rust-worker-build.json')
 foundation_gate=read(foundation/'verification.json');require(foundation_gate['verified']and foundation_gate['count']==36,'Completed36 Driver128 foundation controls required')
 for manifest in(read(foundation/'small-raw-none/manifest.json'),read(recovery/'next-controller-crash/manifest.json')):require(all(manifest[k]==receipt[k]for k in('source_tree_sha256','controller_sha256','worker_sha256')),'Prerequisite gates belong to another frozen build')
 gates=read(recovery/'verification.json');require(isinstance(gates,list)and len(gates)==2 and all(g['verified']and g['broker_journal_unchanged']and g['original_bundle_dacl_restored']and g['old_run_unqualified']and g['owned_processes_remaining']==0 for g in gates),'Completed exact controller recovery controls required')
 raw_reference=(REPO/'rust/emumee-core/tests/data/driver_runtime_reference.json').read_bytes();require(sha(raw_reference)=='d6bf26fa2a07224fb0470571c305abbf628c8d5c3bd87dc3b864598efb369141','Runtime reference corpus changed');references={r['case']:r for r in json.loads(raw_reference)['cases']};require(len(references)==9,'Missing runtime references')
 root.mkdir(parents=True);exe=bundle/'emumee-rs.exe';ps=shutil.which('pwsh')or shutil.which('powershell');require(ps is not None,'PowerShell lifecycle tools unavailable')
 acl_script=root/'read-owned-acl.ps1';acl_script.write_text("param([string]$Path)\n$ErrorActionPreference='Stop'\n(Get-Acl -LiteralPath $Path).Sddl\n",encoding='ascii')
 def acl():
  value=subprocess.run([ps,'-NoProfile','-NonInteractive','-File',str(acl_script),str(bundle)],capture_output=True,check=False);require(value.returncode==0,'DACL read failed');return value.stdout
 baseline_acl=acl();before=snapshot(bundle);write(root/'bundle-before.json',before)
 records=[];status=dict(schema=1,count=0,expected_count=23,verified=False,records=records,scope='Sequential executed compiler-owned Driver128 capture controls; no arbitrary input or unpacking claim');write(root/'verification.json',status)
 faults=('crash-before-checkpoint','crash-after-checkpoint','timeout-after-checkpoint','tamper-payload','tamper-provenance','tamper-engine','profile-downgrade')
 try:
  for case,fault in[(c,'none')for c in references]+[('runtime-tiny',f)for f in faults]:
   reference=references[case];name=case+'-'+fault;run=root/name;proc=call([exe,'driver-capture-fixture',case,run,'--fault',fault],root/name)
   summary=read(run/'summary.json');manifest=read(run/'manifest.json');stopped=read(run/'worker-stop.json');job=read(run/'driver-job-profile.json');containment=read(run/'worker-containment.json')
   corrupt=fault in('crash-before-checkpoint','tamper-payload','tamper-provenance','tamper-engine','profile-downgrade');expected='failed'if corrupt or fault=='crash-after-checkpoint'else'timeout'if fault=='timeout-after-checkpoint'else reference['status']
   require(proc.returncode==(0 if expected=='completed'else 1)and manifest['status']==expected and state(summary)['status']==expected,name+': status/exit differs')
   require(manifest['summary_sha256']==digest_file(run/'summary.json')and manifest['cleanup']=='restored'and stopped['cleanup']=='restored'and acl()==baseline_acl,name+': binding/cleanup differs')
   require(all(manifest[k]==receipt[k]for k in('source_tree_sha256','controller_sha256','worker_sha256','unicorn_sha256')),name+': frozen receipt differs')
   require(containment['app_container']and containment['job_object']and containment['child_process_blocked']and containment['network_capabilities']==0,name+': containment absent')
   require(job['process_memory_bytes']==2048*M and 0<job['peak_process_memory_bytes']<=2048*M and manifest['output_limits']['max_bytes']==1024*M,name+': actual sealed job peak/output budget differs')
   inspected=call([exe,'inspect-driver-capture',run],root/(name+'-inspect'))
   if corrupt:require(summary['schema']=='emumee.driver_capture_failure.v1'and summary['artifacts']==[]and not manifest['qualified']and inspected.returncode!=0,name+': unverified capture exposed')
   else:
    require(inspected.returncode==0 and summary['schema']=='emumee.driver_capture.v1',name+': strict Driver reader failed')
    engine=read(run/'engine-report.json')['execution'];capture=engine['capture_runtime'];require(engine['artifacts']==read(run/'engine-report.json')['catalog']and engine['capture_summary']==summary['omissions'],name+': ordinary engine/catalog authority differs')
    require(engine['completion_reason']=='entry_return'and engine['guest_entry_return']==17 and engine['instruction_count']>0,name+': actual guest return/instruction evidence absent')
    require(capture['input_sha256']==reference['input_sha256']==summary['binding']['input_sha256']==digest_file(run/'input.bin')and capture['initial_image_sha256']==reference['initial_image_sha256']and capture['post_image_sha256']==reference['post_image_sha256'],name+': input/initial/post image distinctions differ')
    require(capture['image_bytes']==reference['image_bytes']==engine['image_load']['size']and capture['image_base']==engine['image_load']['base']and capture['boundary_instructions']==engine['instruction_count']and capture['boundary_pc']==engine['final_pc'],name+': actual selected image/settled boundary differs')
    require(capture['selected_read_complete']==reference['selected_read_complete']and capture['capture_complete']==reference['capture_complete'],name+': complete capture synthesized')
    ledger=capture['ledger'];require(ledger['read_bytes']<=ledger['read_reserved_bytes']<=capture['read_limit']<=192*M and ledger['scan_bytes']<=capture['scan_limit']<=128*M and ledger['carving_work_bytes']<=capture['work_limit']<=1024*M,name+': aggregate read/scan/work overdraw')
    for actual,marker in zip(capture['markers'],reference['markers']):require(all(actual[k]==marker[k]for k in('rva','initial','expected'))and actual['observed']==(marker['expected']if reference['selected_read_complete']else None),name+': actual guest marker evidence differs')
    require(len(capture['markers'])==len(reference['markers']),name+': marker count differs');payloads(run,summary,reference)
    if reference['capture_complete']:require(capture['initial_image_sha256']!=capture['post_image_sha256']and not capture['omissions'],name+': no actual mutation/complete ledger')
    else:require(capture['omissions']and summary['omissions']['omitted_observations']>0 and state(summary)['status']=='partial',name+': capture failure promoted or omitted silently')
    require(manifest['qualified']==(fault=='none')and state(summary)['checkpoint_recovered']==(fault!='none'),name+': checkpoint recovery promoted completion')
    require(state(summary)['guest_trace_complete']is False and state(summary)['network_broker_complete']is False,name+': unearned broker/trace coverage')
   legacy=call([exe,'inspect-report',run,'--verify-artifacts'],root/(name+'-legacy-inspect'));require(legacy.returncode!=0,name+': legacy reader silently widened')
   if fault in('crash-before-checkpoint','crash-after-checkpoint'):require(stopped['worker']['exit_code']==23,name+': actual crash missing')
   if fault=='timeout-after-checkpoint':require(stopped['worker']['reason']=='timeout',name+': actual watchdog timeout missing')
   records.append(dict(kind='executed',name=name,status=expected,exit_code=proc.returncode,peak_process_memory_bytes=job['peak_process_memory_bytes'],verified=True));status['count']=len(records);write(root/'verification.json',status)
  good=root/'runtime-tiny-none'
  mutations=('execution-catalog','read-ledger','scan-ledger','work-ledger','marker-claim','initial-image-claim','marker-projection')
  for mutation in mutations:
   target=root/('reader-'+mutation);shutil.copytree(good,target)
   if mutation=='execution-catalog':rebind_engine(target,lambda e:e['execution'].__setitem__('artifacts',[]))
   elif mutation in('read-ledger','scan-ledger','work-ledger'):
    field,limit={'read-ledger':('read_reserved_bytes',192*M),'scan-ledger':('scan_bytes',128*M),'work-ledger':('carving_work_bytes',1024*M)}[mutation];rebind_engine(target,lambda e:e['execution']['capture_runtime']['ledger'].__setitem__(field,limit+1))
   elif mutation=='marker-claim':
    def alter(e):e['execution']['capture_runtime']['markers'][0].update(expected=0x11,observed=0x11)
    rebind_engine(target,alter)
   elif mutation=='initial-image-claim':rebind_engine(target,lambda e:e['execution']['capture_runtime'].__setitem__('initial_image_sha256','0'*64))
   elif mutation=='marker-projection':
    summary=read(target/'summary.json');manifest=read(target/'artifacts/manifest.json')
    for records_value in(summary['artifacts'],manifest['payloads']):
     snapshot_record=next(r for r in records_value if r['size']==16384);marker=next(c for c in snapshot_record['projection']['range_hashes']if c['offset']==0x2010 and c['size']==1);marker['sha256']='0'*64
    write(target/'artifacts/manifest.json',manifest);write(target/'artifact-checkpoint.json',manifest);summary['manifest_sha256']=digest_file(target/'artifacts/manifest.json');summary['checkpoint_sha256']=digest_file(target/'artifact-checkpoint.json');write(target/'summary.json',summary)
   proc=call([exe,'inspect-driver-capture',target],root/('reader-'+mutation+'-inspect'));require(proc.returncode!=0,mutation+': coordinated semantic tamper passed')
   records.append(dict(kind='reader',name=mutation,exit_code=proc.returncode,verified=True));status['count']=len(records);write(root/'verification.json',status)
  repeat=call([exe,'recover-bundle'],root/'repeat-recovery');require(repeat.returncode==0,'Recovery idempotence command failed');recovered=json.loads(repeat.stdout);require(not recovered['recovered']and recovered['profiles']==0 and recovered['jobs']==0 and recovered['grants']==0,'Runtime controls left owned lifecycle resources')
  cleanup=root/'check-owned-residual.ps1';cleanup.write_text("param([string]$Bundle,[string]$Run,[string]$Tool)\n$ErrorActionPreference='Stop'\n& $Tool -Roots @($Bundle,$Run) -WorkerRoots @($Bundle)\nif($LASTEXITCODE -ne 0){exit 1}\n",encoding='ascii');residue=call([ps,'-NoProfile','-NonInteractive','-File',cleanup,bundle,root,REPO/'tools/check_residual_appcontainer.ps1'],root/'residual-check');require(residue.returncode==0 and acl()==baseline_acl,'Owned resource residue or DACL drift')
  after=snapshot(bundle);write(root/'bundle-after.json',after);require(before==after,'Frozen bundle changed');require(len(records)==23,'Missing executed capture controls');status.update(verified=True,large_controls_sequential=True,exact_bundle_dacl_restored=True,residual_check_passed=True,cleanup_plan_idempotent=True,controller_peak_memory_measured=False);write(root/'verification.json',status);print(json.dumps(dict(verified=True,count=len(records),output_root=str(root))))
 except BaseException as error:status['error']=str(error);write(root/'verification.json',status);raise
if __name__=='__main__':main()
