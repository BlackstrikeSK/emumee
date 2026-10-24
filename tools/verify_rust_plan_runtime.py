"""Frozen closed plan installation proof. No external sample execution.

Runs fixed compiler-owned cases only; inspects generated evidence mutations
without rerunning a worker. Requires same-build recovery controls first.
"""
import argparse, hashlib, json, os, shutil, subprocess, sys
from pathlib import Path
REPO=next(p for p in Path(__file__).resolve().parents if(p/'tools/check_residual_appcontainer.ps1').is_file())
sys.path.insert(0,str(REPO/'tools'))
from verify_rust_analysis_reports import require,read,write,snapshot,call

def main():
 p=argparse.ArgumentParser();p.add_argument('--bundle',type=Path,required=True);p.add_argument('--output-root',type=Path,required=True);p.add_argument('--recovery-root',type=Path,required=True);a=p.parse_args()
 bundle=a.bundle.resolve(strict=True);root=a.output_root.resolve();recovery=a.recovery_root.resolve(strict=True)
 require(not root.exists() and root!=bundle and root not in bundle.parents and bundle not in root.parents,'Fresh evidence outside frozen bundle required')
 receipt=read(bundle/'rust-worker-build.json');gates=read(recovery/'verification.json');old=read(recovery/'next-controller-crash/manifest.json')
 require(isinstance(gates,list)and len(gates)==2 and all(g['verified']and g['broker_journal_unchanged']and g['original_bundle_dacl_restored']and g['old_run_unqualified']and g['owned_processes_remaining']==0 for g in gates),'Same-build recovery gates required')
 require(all(old[k]==receipt[k]for k in('source_tree_sha256','controller_sha256','worker_sha256')),'Recovery source/package identity differs')
 root.mkdir();exe=bundle/'emumee-rs.exe';ps=shutil.which('pwsh')or shutil.which('powershell');require(ps,'PowerShell required')
 acl_script=root/'read-owned-acl.ps1';acl_script.write_text("param([string]$Path)\n$ErrorActionPreference='Stop'\n(Get-Acl -LiteralPath $Path).Sddl\n",encoding='ascii')
 def acl():
  r=subprocess.run([ps,'-NoProfile','-NonInteractive','-File',str(acl_script),str(bundle)],capture_output=True,check=False);require(r.returncode==0,'DACL read failed');return r.stdout
 before=snapshot(bundle);baseline_acl=acl();write(root/'bundle-before.json',before)
 reference_raw=(REPO/'rust/emumee-core/tests/data/plan_runtime_reference.json').read_bytes();require(hashlib.sha256(reference_raw).hexdigest()=='6b034f87f7e18e7b34976e5124ae11cbf34a45467283f37e89f587400f0afe25','Closed plan reference metadata changed');references={r['case']:r for r in json.loads(reference_raw)['cases']}
 records=[];status=dict(schema=1,verified=False,count=0,expected_count=32,records=records,scope='Actual staged compiler-owned plan inputs; no general run or full-tool parity claim');write(root/'verification.json',status)
 def record(value):records.append(value);status['count']=len(records);write(root/'verification.json',status)
 try:
  for arch in('x86','x64'):
   for case in('native-a','native-b','native-replay','native-deny','kernel17','kernel19','static-msi'):
    name=arch+'-'+case;run=root/name;r=call([exe,'plan-fixture',case,run,arch],root/name,timeout=120)
    require(r.returncode==0,name+': closed role failed');v=read(run/'plan-verification.json');require(v['verified']and v['broker_complete'],name+': missing parent authority')
    summary=read(run/'summary.json');require(summary['status']==references[case]['expected_status'] and v['guest_entry_return']==references[case]['guest_entry_return'],name+': independent status/guest return differs')
    require(summary['network_broker_complete']and summary['network_coverage']=='parent_verified_closed_offline_broker',name+': absent verified journal coverage')
    install=read(run/'worker/plan-result.json')['installation'];require('private_slot_uninspected_commitment'in install['inventory_authority'],name+': worker fabricated private inventory inspection')
    broker_ready=read(run/'broker/broker-ready.json');require(broker_ready['target_read_denied'] and broker_ready['persona_read_denied'] and broker_ready['cleanup_plan_read_denied'],name+': broker read worker-owned target/persona or cleanup intent')
    require(install['physical_reservation']['total_reserved_output_bytes']<=install['physical_reservation']['output_limit_bytes'],name+': physical copies unbudgeted')
    require(v['broker_attempts']==int(case in('native-replay','native-deny')),name+': actual journal attempt count differs')
    probe=call([exe,'inspect-plan-proof',run],root/(name+'-inspect'));require(probe.returncode==0,name+': read-only proof failed')
    # Unreferenced files remain uninspected; inspector neither mutates nor runs.
    legacy=call([exe,'inspect-report',run,'--verify-artifacts'],root/(name+'-legacy-reader'));require(legacy.returncode==0,name+': standard report reader failed')
    record(dict(kind='executed',name=name,exit_code=r.returncode,verified=True))
  require(read(root/'x64-native-a/summary.json')['guest_entry_return']!=read(root/'x64-native-b/summary.json')['guest_entry_return'],'Different supplied configuration/mounts produced default fixture result')
  mutations=('target-bytes','plan-bytes','persona-bytes','private-fixture','request-field','broker-deadline','worker-installation','worker-engine','broker-isolation','parent-network','parent-completion','journal-tail','journal-start','hardlink-persona','directory-persona','artifact-payload','artifact-provenance')
  for mutation in mutations:
   source=root/('x64-static-msi'if mutation.startswith('artifact-')else'x64-native-a');target=root/('reader-'+mutation);shutil.copytree(source,target)
   if mutation=='target-bytes':
    f=target/'control/inputs/0000.bin';b=bytearray(f.read_bytes());b[0x200]^=1;f.write_bytes(b)
   elif mutation in('plan-bytes','persona-bytes','private-fixture'):
    f=target/{'plan-bytes':'control/plan.json','persona-bytes':'control/persona.json','private-fixture':'private/http-fixtures.json'}[mutation];f.write_bytes(f.read_bytes()+b' ')
   elif mutation=='request-field':v=read(target/'control/request.json');v['executable']=True;write(target/'control/request.json',v)
   elif mutation=='broker-deadline':v=read(target/'control/config.json');v['deadline_ms']+=1;write(target/'control/config.json',v)
   elif mutation=='worker-installation':v=read(target/'broker-session.json');v['worker_result']['installation']['inventory_authority']='parent_actual_full_inventory';write(target/'broker-session.json',v)
   elif mutation=='worker-engine':f=target/'worker/engine-report.json';f.write_bytes(f.read_bytes()+b' ')
   elif mutation=='broker-isolation':v=read(target/'broker/broker-ready.json');v['target_read_denied']=False;write(target/'broker/broker-ready.json',v)
   elif mutation=='parent-network':f=target/'network-broker.json';f.write_bytes(f.read_bytes()+b' ')
   elif mutation=='parent-completion':v=read(target/'summary.json');v['guest_entry_return']=123;write(target/'summary.json',v)
   elif mutation=='journal-tail':f=target/'private/network-broker.journal';f.write_bytes(f.read_bytes()+b'{"event":')
   elif mutation=='journal-start':f=target/'private/network-broker.journal';f.write_bytes(f.read_bytes().replace(b'closed_plan_broker',b'changed_plan_broker',1))
   elif mutation=='hardlink-persona':os.link(target/'control/persona.json',target/'owned-persona-link.bin')
   elif mutation=='directory-persona':f=target/'control/persona.json';f.rename(target/'persona.saved');f.mkdir()
   elif mutation=='artifact-payload':
    summary=read(target/'summary.json');f=target/'artifacts'/summary['artifacts'][0]['file'];b=bytearray(f.read_bytes());b[0]^=1;f.write_bytes(b)
   elif mutation=='artifact-provenance':v=read(target/'worker/artifacts/manifest.json');v[0]['source']='forged';write(target/'worker/artifacts/manifest.json',v)
   baseline=snapshot(target);r=call([exe,'inspect-plan-proof',target],root/('reader-'+mutation+'-inspect'));require(r.returncode!=0,mutation+': unsafe/changed proof accepted');require(snapshot(target)==baseline,mutation+': read-only inspector changed evidence')
   record(dict(kind='reader',name=mutation,exit_code=r.returncode,verified=True))
  gated=call([exe,'run','compiler-owned-unused.sys'],root/'general-gate');require(gated.returncode!=0 and b'disabled'in gated.stderr,'General run gate opened');record(dict(kind='gate',name='general-run-disabled',verified=True))
  recovered=call([exe,'recover-bundle'],root/'repeat-recovery');require(recovered.returncode==0,'Idempotent recovery failed');v=json.loads(recovered.stdout);require(not v['recovered']and all(v[k]==0 for k in('profiles','jobs','grants')),'Closed plan left lifecycle resources')
  cleanup=root/'check-owned-residual.ps1';cleanup.write_text("param([string]$Bundle,[string]$Run,[string]$Tool)\n$ErrorActionPreference='Stop'\n& $Tool -Roots @($Bundle,$Run) -WorkerRoots @($Bundle)\nif($LASTEXITCODE -ne 0){exit 1}\n",encoding='ascii')
  r=call([ps,'-NoProfile','-NonInteractive','-File',cleanup,bundle,root,REPO/'tools/check_residual_appcontainer.ps1'],root/'residual-check');require(r.returncode==0 and acl()==baseline_acl,'Residual worker/profile/grant or bundle DACL drift')
  after=snapshot(bundle);write(root/'bundle-after.json',after);require(after==before,'Frozen bundle mutated');require(len(records)==32,'Missing closed-plan controls');status.update(verified=True,cleanup_idempotent=True,bundle_unchanged=True,residual_check_passed=True);write(root/'verification.json',status);print(json.dumps({'verified':True,'count':len(records),'output_root':str(root)}))
 except BaseException as e:status['error']=str(e);write(root/'verification.json',status);raise
if __name__=='__main__':main()
