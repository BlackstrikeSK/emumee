"""Frozen contained generated analysis/report lifecycle controls.

Requires this bundle's already-completed recovery gates; does not rerun them.
No real sample paths, guest host-process execution or network destinations.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess


def sha(raw):return hashlib.sha256(raw).hexdigest()
def write(path,value):path.write_text(json.dumps(value,indent=2)+'\n',encoding='utf-8')
def read(path):return json.loads(path.read_bytes())
def require(ok,why):
    if not ok:raise AssertionError(why)
def snapshot(root):
    return {str(p.relative_to(root)):{'size':p.stat().st_size,'sha256':sha(p.read_bytes()),'links':p.stat().st_nlink}
            for p in sorted(root.rglob('*'))if p.is_file()}
def call(command,base,timeout=180):
    write(Path(str(base)+'.command.json'),[str(x)for x in command])
    result=subprocess.run([str(x)for x in command],capture_output=True,timeout=timeout,check=False)
    Path(str(base)+'.stdout.bin').write_bytes(result.stdout);Path(str(base)+'.stderr.bin').write_bytes(result.stderr)
    write(Path(str(base)+'.exit.json'),{'exit_code':result.returncode});return result


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--bundle',type=Path,required=True)
    parser.add_argument('--output-root',type=Path,required=True)
    parser.add_argument('--recovery-root',type=Path,required=True)
    args=parser.parse_args()
    repo=Path(__file__).resolve().parents[1]
    # The staged location is deeper; installed tools location is canonical.
    if not (repo/'tools').is_dir():repo=next(p for p in Path(__file__).resolve().parents if(p/'tools/check_residual_appcontainer.ps1').is_file())
    bundle=args.bundle.resolve(strict=True);root=args.output_root.resolve();recovery=args.recovery_root.resolve(strict=True)
    require(not root.exists(),'Use a fresh analysis/report verification root')
    require(root!=bundle and bundle not in root.parents and root not in bundle.parents,'Evidence must be outside frozen bundle')
    receipt=read(bundle/'rust-worker-build.json');gates=read(recovery/'verification.json')
    require(isinstance(gates,list)and len(gates)==2 and all(g['verified']and g['broker_journal_unchanged']and g['original_bundle_dacl_restored']and g['old_run_unqualified']and g['owned_processes_remaining']==0 for g in gates),'Completed controller recovery gates required')
    recovery_manifest=read(recovery/'next-controller-crash/manifest.json')
    require(all(recovery_manifest[k]==receipt[k]for k in ('source_tree_sha256','controller_sha256','worker_sha256')),'Recovery gates belong to another build')
    exe=bundle/'emumee-rs.exe';require(exe.is_file(),'Frozen controller missing');root.mkdir(parents=True)
    ps=shutil.which('pwsh')or shutil.which('powershell');require(ps is not None,'PowerShell required for existing DACL/residual controls')
    acl_script=root/'read-owned-acl.ps1';acl_script.write_text("param([string]$Path)\n$ErrorActionPreference='Stop'\n(Get-Acl -LiteralPath $Path).Sddl\n",encoding='ascii')
    def acl():
        value=subprocess.run([ps,'-NoProfile','-NonInteractive','-File',str(acl_script),str(bundle)],capture_output=True,check=False)
        require(value.returncode==0,'Bundle ACL read failed');return value.stdout
    baseline_acl=acl();before=snapshot(bundle);write(root/'bundle-before.json',before)
    records=[];status=dict(schema=1,expected_count=48,count=0,verified=False,records=records,controller_recovery_gates=2,
                          scope='Closed owned generated native/managed/static report lifecycle only')
    write(root/'verification.json',status)
    cases=[('native-return','completed',None),('native-capture','completed',b'RUST'),('managed-return','completed',None),
           ('managed-capture','completed',b'RUST'),('managed-partial','partial',b'RUST'),('managed-budget','partial',b'RUST'),
           ('managed-error','partial',None),('static-msi','partial',b'MSCF\0\xff'),('malformed-msi','partial',None)]
    controls=[dict(case=c,status=s,payload=p,fault='none')for c,s,p in cases]
    controls += [dict(case='managed-capture',status='timeout'if f=='timeout-after-checkpoint'else'failed',payload=b'RUST',fault=f)
                 for f in ('timeout-after-checkpoint','crash-after-checkpoint','tamper-engine','tamper-manifest','tamper-payload','tamper-provenance')]
    controls += [dict(case=c,status='failed',payload=None,fault='none',request_tamper=True)
                 for c in ('tamper-request','tamper-input','unknown-request-field','foreign-owned-fixture')]
    try:
        for arch in ('x86','x64'):
            for control in controls:
                name=arch+'-'+control['case']+'-'+control['fault'];run=root/name
                proc=call([exe,'analysis-fixture',control['case'],run,'--arch',arch,'--fault',control['fault']],root/name)
                summary=read(run/'summary.json');manifest=read(run/'manifest.json');stop=read(run/'worker-stop.json')
                require(proc.returncode==(0 if control['status']=='completed'else 1),name+': exit/status differs')
                require(summary['status']==control['status'] and manifest['status']==control['status'],name+': completion classification differs')
                require(manifest['summary_sha256']==sha((run/'summary.json').read_bytes()),name+': final summary binding differs')
                require(stop['cleanup']=='restored'and manifest['cleanup']=='restored'and acl()==baseline_acl,name+': exact bundle DACL/lifecycle cleanup differs')
                witness=read(run/'worker-containment.json')
                require(witness['app_container']and witness['job_object']and witness['child_process_blocked']and witness['network_capabilities']==0,name+': containment missing')
                require(summary['guest_trace_complete']is False and summary['network_broker_complete']is False,name+': unearned full trace/broker claim')
                require(manifest['output_limits']['max_bytes']>255*1024*1024 and manifest['output_limits']['max_entries']==10064,name+': role output budget omitted report/input/payload/checkpoint bytes')
                bad_integrity=control.get('request_tamper')or control['fault'].startswith('tamper-')
                if bad_integrity:
                    require(not manifest['qualified']and summary['controller_integrity']=='failed'and summary['artifact_integrity']=='failed'
                            and summary['artifacts']==[]and summary['artifact_groups']==[],name+': integrity failure exposed worker payloads')
                    inspected=call([exe,'inspect-report',run,'--verify-artifacts'],root/(name+'-inspect'))
                    require(inspected.returncode!=0,name+': corrupted report passed strict reader')
                else:
                    require(summary['controller_integrity']=='verified',name+': report not verified')
                    require(summary['run_manifest']['report_profile']=='legacy_v1',name+': profile silently widened')
                    expected=control['payload'];groups=summary['artifact_groups']
                    require(len(groups)==int(expected is not None),name+': actual capture count differs')
                    if expected is not None:
                        digest=sha(expected);filename=digest[:20]+'.bin'
                        require(groups[0]['sha256']==digest and groups[0]['file']==filename and groups[0]['size']==len(expected)
                                and(run/'artifacts'/filename).read_bytes()==expected,name+': actual payload/hash/name differs')
                        for item in summary['artifacts']:
                            origin=item['context']['_emumee_typed_origin']
                            require(item['sha256']==digest and item['file']==filename and origin['catalog_filename']==digest+'.bin'
                                    and origin['kind']==('container_stream'if control['case']=='static-msi'else'guest_file'),name+': typed/fullhash provenance lost')
                    inspected=call([exe,'inspect-report',run,'--verify-artifacts'],root/(name+'-inspect'))
                    require(inspected.returncode==0,name+': valid bound report failed inspector')
                    if control['fault']in ('timeout-after-checkpoint','crash-after-checkpoint'):
                        require(summary['artifact_checkpoint_recovered']is True and not manifest['qualified'],name+': checkpoint recovery claimed completion')
                    else:require(manifest['qualified']is True,name+': completed report lifecycle unqualified')
                if control.get('request_tamper'):
                    require(stop['worker']['exit_code']==2 and not(run/'worker-summary.json').exists()and not(run/'artifacts').exists(),name+': rejected input reached execution')
                if control['fault']=='timeout-after-checkpoint':require(stop['worker']['reason']=='timeout',name+': watchdog timeout not exercised')
                if control['fault']=='crash-after-checkpoint':require(stop['worker']['exit_code']==23,name+': worker crash not exercised')
                records.append(dict(kind='contained',name=name,arch=arch,exit_code=proc.returncode,status=summary['status'],summary_sha256=sha((run/'summary.json').read_bytes()),files=snapshot(run),verified=True))
                status['count']=len(records);write(root/'verification.json',status)
        good=root/'x64-managed-capture-none'
        for mutation in ('missing-engine','engine-hash','network-hash','manifest-provenance','group-preview','payload-hash','filename-traversal','hardlink-payload','directory-payload','oversized-metadata'):
            target=root/('reader-'+mutation);shutil.copytree(good,target)
            summary=read(target/'summary.json');file=summary['artifacts'][0]['file'];payload=target/'artifacts'/file
            require(payload.parent==target/'artifacts'and file==sha(b'RUST')[:20]+'.bin','Unexpected owned fixture filename')
            if mutation=='missing-engine':(target/'engine-report.json').rename(target/'engine-report.saved')
            elif mutation=='engine-hash':(target/'engine-report.json').write_bytes((target/'engine-report.json').read_bytes()+b' ')
            elif mutation=='network-hash':(target/'network-broker.json').write_bytes((target/'network-broker.json').read_bytes()+b' ')
            elif mutation=='manifest-provenance':
                value=read(target/'artifacts/manifest.json');value[0]['source']='forged';write(target/'artifacts/manifest.json',value)
            elif mutation=='group-preview':summary['artifact_groups'][0]['preview']='forged';write(target/'summary.json',summary)
            elif mutation=='payload-hash':payload.write_bytes(b'FAIL')
            elif mutation=='filename-traversal':
                summary['artifacts'][0]['file']='../owned-sentinel.bin';summary['artifact_groups'][0]['file']='../owned-sentinel.bin'
                write(target/'summary.json',summary);write(target/'artifacts/manifest.json',summary['artifacts']);(target/'owned-sentinel.bin').write_bytes(b'owned-only')
            elif mutation=='hardlink-payload':os.link(payload,target/'owned-extra-link.bin')
            elif mutation=='directory-payload':payload.rename(target/'payload.saved');payload.mkdir()
            elif mutation=='oversized-metadata':summary['artifacts'][0]['size']=33554433;write(target/'summary.json',summary)
            proc=call([exe,'inspect-report',target,'--verify-artifacts'],root/('reader-'+mutation+'-inspect'))
            require(proc.returncode!=0,mutation+': malformed/unsafe report passed')
            records.append(dict(kind='reader',name=mutation,exit_code=proc.returncode,files=snapshot(target),verified=True));status['count']=len(records);write(root/'verification.json',status)
        repeat=call([exe,'recover-bundle'],root/'repeat-recovery');require(repeat.returncode==0,'Recovery idempotence command failed')
        recovered=json.loads(repeat.stdout);require(not recovered['recovered']and recovered['profiles']==0 and recovered['jobs']==0 and recovered['grants']==0,'Closed analysis left cleanup journal resources')
        cleanup_script=root/'check-owned-residual.ps1'
        cleanup_script.write_text("param([string]$Bundle,[string]$Run,[string]$Tool)\n$ErrorActionPreference='Stop'\n& $Tool -Roots @($Bundle,$Run) -WorkerRoots @($Bundle)\nif($LASTEXITCODE -ne 0){exit 1}\n",encoding='ascii')
        residue=call([ps,'-NoProfile','-NonInteractive','-File',cleanup_script,bundle,root,repo/'tools/check_residual_appcontainer.ps1'],root/'residual-check')
        require(residue.returncode==0 and acl()==baseline_acl,'Owned AppContainer/profile/process residue or DACL drift')
        after=snapshot(bundle);write(root/'bundle-after.json',after);require(before==after,'Frozen bundle bytes/links changed')
        require(len(records)==48,'Missing controls');status.update(verified=True,cleanup_plan_idempotent=True,exact_bundle_dacl_restored=True,residual_check_passed=True)
        write(root/'verification.json',status);print(json.dumps({'verified':True,'count':len(records),'output_root':str(root)}))
    except BaseException as error:
        status['error']=str(error);write(root/'verification.json',status);raise


if __name__=='__main__':main()
