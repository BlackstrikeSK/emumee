"""Closed native/kernel settled-root indicator controls, generated inputs only.
Requires same-build recovery and ordinary analysis receipts. Fresh evidence only.
Never admits a supplied image, custom regex or periodic/general run option.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess

REPO=next(p for p in Path(__file__).resolve().parents if (p/'tools/check_residual_appcontainer.ps1').is_file())
CORPUS_SHA='5e1eb09804fdebe82911250fe317938cac1bde23ef568f4b52fd0c702edd31b3'
SOURCE='memory:closed_settled_root'

def require(ok,why):
    if not ok:raise AssertionError(why)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def write(path,value):path.write_text(json.dumps(value,indent=2)+'\n',encoding='utf-8',newline='\n')
def strict(raw):
    def pairs(items):
        result={}
        for key,value in items:
            require(key not in result,'Duplicate JSON key: '+key);result[key]=value
        return result
    def constant(value):raise ValueError('Nonfinite JSON: '+value)
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=constant)
def regular(path,limit=64*1024*1024):
    for part in reversed([path.parent,*path.parent.parents]):
        info=part.lstat();require(stat.S_ISDIR(info.st_mode) and not getattr(info,'st_file_attributes',0)&0x400,'Directory boundary: '+str(part))
    info=path.lstat();require(stat.S_ISREG(info.st_mode) and info.st_nlink==1 and not getattr(info,'st_file_attributes',0)&0x400,'File boundary: '+str(path))
    require(info.st_size<=limit,'File byte limit');raw=path.read_bytes();require(len(raw)==info.st_size,'Changed file size');return raw
def read(path):return strict(regular(path))
def snapshot(root):
    result={};total=0
    for path in sorted(root.rglob('*')):
        info=path.lstat();require(not getattr(info,'st_file_attributes',0)&0x400 and not path.is_symlink(),'Reparse evidence')
        if stat.S_ISDIR(info.st_mode):continue
        value=regular(path);total+=len(value);require(total<=128*1024*1024 and len(result)<4096,'Evidence tree bound')
        result[path.relative_to(root).as_posix()]=dict(size=len(value),sha256=sha(value))
    return result
def call(command,prefix,timeout=210):
    for suffix in ('.command.json','.exit.json','.stdout.bin','.stderr.bin'):
        require(not os.path.lexists(str(prefix)+suffix),'Preserve existing command evidence')
    write(Path(str(prefix)+'.command.json'),[str(value) for value in command])
    try:result=subprocess.run([str(value) for value in command],capture_output=True,timeout=timeout,check=False)
    except subprocess.TimeoutExpired as error:
        Path(str(prefix)+'.stdout.bin').write_bytes(error.stdout or b'');Path(str(prefix)+'.stderr.bin').write_bytes(error.stderr or b'')
        write(Path(str(prefix)+'.exit.json'),dict(exit_code=None,timeout=True));raise
    Path(str(prefix)+'.stdout.bin').write_bytes(result.stdout);Path(str(prefix)+'.stderr.bin').write_bytes(result.stderr)
    write(Path(str(prefix)+'.exit.json'),dict(exit_code=result.returncode,timeout=False));return result

def main():
    parser=argparse.ArgumentParser()
    for name in ('bundle','output-root','recovery-root','analysis-root'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();bundle=args.bundle.resolve(strict=True);root=args.output_root.absolute()
    require(not os.path.lexists(root) and bundle not in root.parents and root not in bundle.parents,'Fresh evidence outside bundle required')
    receipt=read(bundle/'rust-worker-build.json');recovery=args.recovery_root.resolve(strict=True);analysis=args.analysis_root.resolve(strict=True)
    recovered=read(recovery/'verification.json');old=read(recovery/'next-controller-crash/manifest.json')
    require(isinstance(recovered,list) and len(recovered)==2 and all(
        row['verified'] is True and row['original_bundle_dacl_restored'] is True and row['broker_journal_unchanged'] is True
        and row['old_run_unqualified'] is True and row['owned_processes_remaining']==0 for row in recovered),'Completed recovery gates required')
    require(all(old[key]==receipt[key] for key in ('source_tree_sha256','controller_sha256','worker_sha256')),'Recovery package mismatch')
    prior=read(analysis/'verification.json');require(prior['verified'] is True and prior['count']==48,'Completed48 analysis controls required')
    raw=regular(REPO/'rust/emumee-core/tests/data/native_indicators_reference.json',256*1024)
    require(sha(raw)==CORPUS_SHA,'Pinned harmless corpus changed');rows=strict(raw)['cases'];require(len(rows)==24,'Corpus count')
    root.mkdir();exe=bundle/'emumee-rs.exe';powershell=shutil.which('pwsh') or shutil.which('powershell');require(powershell,'PowerShell required')
    acl_script=root/'owned-acl.ps1';acl_script.write_text("param([string]$Path)\n$ErrorActionPreference='Stop'\n(Get-Acl -LiteralPath $Path).Sddl\n",encoding='ascii')
    def acl():
        r=subprocess.run([powershell,'-NoProfile','-NonInteractive','-File',str(acl_script),str(bundle)],capture_output=True,check=False)
        require(r.returncode==0,'ACL read failed');return r.stdout
    original_acl=acl();(root/'bundle-before.sddl.bin').write_bytes(original_acl)
    before=snapshot(bundle);write(root/'bundle-before.json',before)
    records=[];status=dict(schema=1,verified=False,count=0,expected_count=47,records=records,
        source_tree_sha256=receipt['source_tree_sha256'],scope='Actual closed native/kernel settled root only; no managed/regex/periodic/full-live-memory/general/unpacking claim')
    def record(name,kind,**extra):
        records.append(dict(name=name,kind=kind,verified=True,**extra));status['count']=len(records);write(root/'verification.json',status)
    try:
        for architecture in ('x86','x64'):
            old_root=analysis/(architecture+'-native-return-none');manifest=read(old_root/'manifest.json')
            require(all(manifest[key]==receipt[key] for key in ('source_tree_sha256','controller_sha256','worker_sha256')),'Ordinary analysis package mismatch')
            original=snapshot(old_root);summary=read(old_root/'summary.json');engine=read(old_root/'engine-report.json')['execution']
            require(all(field not in value for value in (summary,engine) for field in ('memory_strings','memory_string_sources')),'Old role acquired an indicator extension')
            inspected=call([exe,'inspect-report',old_root,'--verify-artifacts'],root/(architecture+'-old-inspect'))
            require(inspected.returncode==0 and snapshot(old_root)==original,'Read-only old-role inspection changed/failed')
            record(architecture+'-old-role','retained-readonly')
        for row in rows:
            name=row['architecture']+'-'+row['analysis_case'];run=root/name
            result=call([exe,'analysis-fixture',row['analysis_case'],run,'--arch',row['architecture']],root/name)
            require(result.returncode==0,name+': fixed fixture did not complete')
            manifest=read(run/'manifest.json');summary=read(run/'summary.json');execution=read(run/'engine-report.json')['execution']
            source=execution['memory_string_sources'];capture=execution['memory_strings'];input_bytes=regular(run/'input.bin',65536)
            require(manifest['qualified'] is True and summary['controller_integrity']=='verified'
                and summary['status']=='completed' and execution['completion_reason']=='entry_return'
                and execution['guest_entry_return']==17 and execution['error'] is None,name+': real guest status changed')
            require(sha(input_bytes)==row['input_sha256'] and len(input_bytes)==row['input_size'],name+': actual staged input not fixed recipe')
            require(capture==row['expected'] and summary['memory_strings']==capture
                and summary['memory_string_sources']==source,name+': complete legacy observation or summary binding mismatch')
            canonical=json.dumps(capture,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()
            require(source['capture_sha256']==sha(canonical) and source['input_sha256']==sha(input_bytes)
                and source['initial_image_sha256']==row['initial_image_sha256'],name+': actual input/initial/capture hash binding changed')
            require(source['version']=='emumee.settled-root-indicators.v1' and source['source']==SOURCE
                and source['all_guest_memory_complete'] is False and source['initial_patches_absent'] is True
                and source['coverage']==row['coverage'] and source['omissions']==row['omissions'],name+': selected-source scope inflated')
            require(all(source[key]==row[key] for key in ('read_limit','scan_limit','read_bytes','selected_bytes','retained_snapshot')),
                name+': selected READ/scan/retention ledger changed')
            observed=row['read_bytes']>0
            require(source['settled_image_sha256']==(row['golden_settled_sha256'] if observed else None)
                and source['runtime_patches_verified'] is observed,name+': settled root hash/actual runtime writes missing')
            require(source['boundary_instructions']==execution['instruction_count']>0
                and source['boundary_pc']==execution['final_pc'],name+': boundary evidence changed')
            require(summary['execution_mode']==('kernel' if row['case'].startswith('kernel') else 'user'),name+': wrong execution mode')
            old_manifest=read(analysis/(row['architecture']+'-native-return-none')/'manifest.json')
            require(manifest['output_limits']['max_bytes']==old_manifest['output_limits']['max_bytes']+16*1024*1024,
                name+': additional physical report-copy reservation omitted')
            require(len(summary['artifacts'])==int(row['retained_snapshot']),name+': capture-none/retention payload count differs')
            if row['retained_snapshot']:
                item=summary['artifacts'][0];payload=regular(run/'artifacts'/item['file'],12288)
                require(len(payload)==12288 and sha(payload)==row['golden_settled_sha256'] and item['source']==SOURCE,
                    name+': retained actual root differs from independently generated golden')
            for marker in (b'http://settled.example/', 'https://wide.example/'.encode('utf-16le')):
                require(marker not in input_bytes,name+': indicator was present contiguously in raw input')
            before_read=snapshot(run);checked=call([exe,'inspect-report',run,'--verify-artifacts'],root/(name+'-inspect'))
            require(checked.returncode==0 and snapshot(run)==before_read,name+': bound read-only inspector failed/mutated evidence')
            witness=read(run/'worker-containment.json');stop=read(run/'worker-stop.json')
            require(witness['app_container'] is True and witness['job_object'] is True and witness['child_process_blocked'] is True
                and witness['network_capabilities']==0 and stop['cleanup']=='restored' and acl()==original_acl,name+': containment/cleanup drift')
            record(name,'executed-closed-root',matches=len(capture['matches']),read_bytes=source['read_bytes'])
        for architecture in ('x86','x64'):
            source=root/(architecture+'-native-indicators-none')
            for mutation in ('summary-value','summary-scope','missing-summary-extension','engine-value-rebound',
                    'engine-ledger-rebound','engine-source-rebound','unknown-source-field-rebound','stripped-extension-rebound','unbound-engine'):
                name=architecture+'-reader-'+mutation;target=root/name;snapshot(source);shutil.copytree(source,target)
                summary=read(target/'summary.json');engine=read(target/'engine-report.json')
                if mutation=='summary-value':summary['memory_strings']['matches'][0]['value']='203.0.113.1'
                elif mutation=='summary-scope':summary['memory_string_sources']['all_guest_memory_complete']=True
                elif mutation=='missing-summary-extension':
                    summary.pop('memory_strings');summary.pop('memory_string_sources')
                elif mutation=='unbound-engine':
                    for key in ('engine_report','engine_report_sha256','engine_report_size'):summary.pop(key,None)
                    summary['run_manifest'].pop('engine_report_integrity',None)
                else:
                    execution=engine['execution']
                    if mutation=='stripped-extension-rebound':
                        execution.pop('memory_strings');execution.pop('memory_string_sources')
                        summary.pop('memory_strings');summary.pop('memory_string_sources')
                    elif mutation=='engine-value-rebound':execution['memory_strings']['matches'][0]['value']='203.0.113.1'
                    elif mutation=='engine-ledger-rebound':execution['memory_string_sources']['read_bytes']=0
                    elif mutation=='engine-source-rebound':execution['memory_string_sources']['source']='memory:forged'
                    else:execution['memory_string_sources']['unknown']=True
                    raw=(json.dumps(engine,separators=(',',':'))+'\n').encode();(target/'engine-report.json').write_bytes(raw)
                    summary['engine_report_sha256']=sha(raw);summary['engine_report_size']=len(raw)
                    # Make the two copies agree: the typed receipt validator must
                    # still reject corruption after the raw hash is rebound.
                    if mutation!='stripped-extension-rebound':
                        summary['memory_strings']=execution['memory_strings'];summary['memory_string_sources']=execution['memory_string_sources']
                write(target/'summary.json',summary);before_read=snapshot(target)
                refused=call([exe,'inspect-report',target,'--verify-artifacts'],root/(name+'-inspect'))
                require(refused.returncode!=0 and snapshot(target)==before_read,name+': forged authority accepted/mutated')
                record(name,'reader-refusal',exit_code=refused.returncode)
        for name,command,reason in [
            ('custom',[exe,'analysis-fixture','native-indicators-custom',root/'denied-custom'],'Unknown closed analysis case'),
            ('periodic',[exe,'analysis-fixture','kernel-indicators',root/'denied-periodic','--checkpoint','100'],'Unknown generated analysis option'),
            ('general',[exe,'run','compiler-owned-unused.sys'],'disabled')]:
            refused=call(command,root/('gate-'+name));require(refused.returncode!=0 and reason.encode() in refused.stderr,name+': gate changed')
            require(not os.path.lexists(root/('denied-'+name)),name+': refused option created a run')
            record('gate-'+name,'gate')
        residual=root/'residual.ps1'
        residual.write_text("param([string]$Bundle,[string]$Run,[string]$Tool)\n$ErrorActionPreference='Stop'\n& $Tool -Roots @($Bundle,$Run) -WorkerRoots @($Bundle)\nif($LASTEXITCODE -ne 0){exit 1}\n",encoding='ascii')
        checked=call([powershell,'-NoProfile','-NonInteractive','-File',residual,bundle,root,REPO/'tools/check_residual_appcontainer.ps1'],root/'residual')
        require(checked.returncode==0 and acl()==original_acl and snapshot(bundle)==before,'Residual resources/package/DACL changed')
        require(len(records)==47,'Control count differs');status.update(verified=True,bundle_unchanged=True,original_sddl_restored=True,residual_check_passed=True)
        write(root/'verification.json',status);print(json.dumps(dict(verified=True,count=len(records),output_root=str(root))))
    except BaseException as error:
        status['error']=str(error);write(root/'verification.json',status);raise

if __name__=='__main__':main()
