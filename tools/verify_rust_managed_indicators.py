"""Contained generated IL event observations; no supplied assembly/CLR/JIT.
Reuses bounded evidence helpers and the existing analysis worker lifecycle.
"""
import argparse,json,os,shutil,subprocess,sys
from pathlib import Path
REPO=next(p for p in Path(__file__).resolve().parents if (p/'tools/check_residual_appcontainer.ps1').is_file())
sys.path.insert(0,str(REPO/'tools'))
from verify_rust_native_indicators import require,sha,write,read,regular,snapshot,call,strict
CORPUS_SHA='5a44ce7fbd1fe04e9deb8b2f498af8b731a3272ecf1fba63b5630f2b6e3769d1'
def canonical(value):return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()
def main():
    parser=argparse.ArgumentParser()
    for name in ('bundle','output-root','recovery-root','analysis-root'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();bundle=args.bundle.resolve(strict=True);root=args.output_root.absolute()
    recovery=args.recovery_root.resolve(strict=True);analysis=args.analysis_root.resolve(strict=True)
    # Canonicalize an existing parent before writing any evidence. A fresh
    # output path below a symlinked parent can otherwise alias a frozen root.
    root_real=root.parent.resolve(strict=True)/root.name
    require(not os.path.lexists(root) and all(
        root_real!=frozen and frozen not in root_real.parents and root_real not in frozen.parents
        for frozen in (bundle,recovery,analysis)),
        'Fresh evidence outside bundle and completed control roots required')
    receipt=read(bundle/'rust-worker-build.json');gates=read(recovery/'verification.json');next_manifest=read(recovery/'next-controller-crash/manifest.json')
    require(isinstance(gates,list) and len(gates)==2 and all(g['verified'] is True and g['original_bundle_dacl_restored'] is True
        and g['old_run_unqualified'] is True and g['broker_journal_unchanged'] is True and g['owned_processes_remaining']==0 for g in gates),'Recovery2 required')
    require(all(next_manifest[key]==receipt[key] for key in ('source_tree_sha256','controller_sha256','worker_sha256')),'Recovery source/package mismatch')
    ordinary=read(analysis/'verification.json');require(ordinary['verified'] is True and ordinary['count']==48,'Completed48 analysis controls required')
    raw=regular(REPO/'rust/emumee-core/tests/data/managed_indicators_reference.json',128*1024)
    require(sha(raw)==CORPUS_SHA,'Pinned pure event corpus changed');rows=strict(raw)['cases'];require(len(rows)==6,'Corpus count')
    root.mkdir();exe=bundle/'emumee-rs.exe';ps=shutil.which('pwsh') or shutil.which('powershell');require(ps,'PowerShell required')
    acl_script=root/'owned-acl.ps1';acl_script.write_text("param([string]$Path)\n$ErrorActionPreference='Stop'\n(Get-Acl -LiteralPath $Path).Sddl\n",encoding='ascii')
    def acl():
        result=subprocess.run([ps,'-NoProfile','-NonInteractive','-File',str(acl_script),str(bundle)],capture_output=True,check=False)
        require(result.returncode==0,'DACL read failed');return result.stdout
    original_acl=acl();(root/'bundle-before.sddl.bin').write_bytes(original_acl)
    before=snapshot(bundle);write(root/'bundle-before.json',before)
    records=[];status=dict(schema=1,verified=False,count=0,expected_count=37,records=records,
        source_tree_sha256=receipt['source_tree_sha256'],scope='Actual closed IL UTF16 string events only; no custom regex/periodic/host CLR/general/full-managed/unpacking claim')
    def record(name,kind,**extra):
        records.append(dict(name=name,kind=kind,verified=True,**extra));status['count']=len(records);write(root/'verification.json',status)
    try:
        for arch in ('x86','x64'):
            old_root=analysis/(arch+'-managed-return-none');old_manifest=read(old_root/'manifest.json')
            require(all(old_manifest[key]==receipt[key] for key in ('source_tree_sha256','controller_sha256','worker_sha256')),'Ordinary analysis source/package mismatch')
            old_before=snapshot(old_root);old=read(old_root/'summary.json');old_execution=read(old_root/'engine-report.json')['execution']
            require(all(field not in value for value in (old,old_execution) for field in ('memory_strings','memory_string_sources')),'Old managed role acquired capture')
            checked=call([exe,'inspect-report',old_root,'--verify-artifacts'],root/(arch+'-old-inspect'))
            require(checked.returncode==0 and snapshot(old_root)==old_before,'Retained old-role inspector changed/failed')
            record(arch+'-old-managed-role','retained-readonly')
            enabled=None
            for row in rows:
                name=arch+'-'+row['analysis_case'];run=root/name
                result=call([exe,'analysis-fixture',row['analysis_case'],run,'--arch',arch],root/name)
                require(result.returncode==(0 if row['status']=='completed' else 1),name+': CLI status differs')
                summary=read(run/'summary.json');manifest=read(run/'manifest.json');execution=read(run/'engine-report.json')['execution']
                capture=execution['memory_strings'];source=execution['memory_string_sources'];input_bytes=regular(run/'input.bin',65536)
                require(summary['controller_integrity']=='verified' and manifest['qualified'] is True
                    and summary['status']==row['status'] and execution['completion_reason']==row['completion_reason']
                    and execution['guest_entry_return']==row['guest_entry_return'],name+': guest stop/return/integrity changed')
                require((execution['error'] is not None)==(row['case']=='framework-failure'),name+': capture refusal altered guest error')
                require(source['version']=='emumee.managed-string-events.v1'
                    and source['all_managed_strings_complete'] is False and source['all_guest_memory_complete'] is False
                    and source['enabled']==(row['case']!='disabled'),name+': broader coverage claimed')
                require(source['input_sha256']==sha(input_bytes) and read(run/'request.json')['input_sha256']==sha(input_bytes)
                    and source['capture_sha256']==sha(canonical(capture)),name+': immutable input/capture hash changed')
                require(summary['memory_strings']==capture and summary['memory_string_sources']==source
                    and capture==row['expected'] and source['events']==row['events'],name+': actual legacy event observations/order/ref identity changed')
                require(all(source[key]==row[key] for key in ('source_utf16_bytes_observed','omitted_sources'))
                    and source['events_seen']==len(row['events']) and source['events_omitted']==0
                    and source['max_source_utf16_bytes']==1024*1024,name+': observer source budget changed')
                require(execution['instruction_count']==row['instruction_count'] and execution['final_offset']==row['final_offset']
                    and execution['managed_calls']==row['managed_calls'] and source['boundary_instructions']==execution['instruction_count']
                    and source['boundary_method']==execution['final_method'] and source['boundary_offset']==execution['final_offset'],name+': real instruction/transition boundary changed')
                require(execution['framework']['attempts']==row['framework_attempts']
                    and execution['framework']['completed_calls']==row['framework_completed'],name+': framework success fabricated')
                heap=execution['heap'];require([s['utf16_preview'] for s in heap['strings']]==row['heap_utf16']
                    and heap['string_objects']==len(row['heap_utf16']) and all(not s['preview_truncated'] for s in heap['strings'])
                    and heap['utf16_units']==sum(len(s) for s in row['heap_utf16']),name+': actual UTF16/identity/physical unit quota changed')
                require(summary['artifacts']==[] and summary['artifact_groups']==[] and execution['artifacts']==[],name+': string observations invented payloads')
                require(manifest['output_limits']['max_bytes']==old_manifest['output_limits']['max_bytes']+16*1024*1024,name+': physical report reservation omitted')
                if row['case']=='events':enabled=execution
                if row['case']=='disabled':require(execution['heap']==enabled['heap'] and execution['framework']==enabled['framework'],name+': disabled capture changed actual guest objects/calls')
                if row['case']=='budget':
                    require('http://managed.example/'.encode('utf-16le') in input_bytes
                        and not any(item['format']=='url' for item in capture['matches']),name+': unexecuted raw literal was scanned')
                if row['case']=='surrogate':require(heap['strings'][0]['utf16_preview'][-1]==0xd800 and execution['error'] is None,name+': surrogate replaced/raised fake guest exception')
                original=snapshot(run);checked=call([exe,'inspect-report',run,'--verify-artifacts'],root/(name+'-inspect'))
                require(checked.returncode==0 and snapshot(run)==original,name+': readonly typed binding failed/changed evidence')
                containment=read(run/'worker-containment.json');stop=read(run/'worker-stop.json')
                require(containment['app_container'] is True and containment['job_object'] is True and containment['child_process_blocked'] is True
                    and containment['network_capabilities']==0 and stop['cleanup']=='restored' and acl()==original_acl,name+': containment/cleanup/DACL differs')
                record(name,'executed-closed-il',matches=len(capture['matches']),events=len(source['events']))
            for mutation in ('summary-value','alias-rebound','token-rebound','event-boundary-rebound','utf16-preview-rebound',
                    'observer-ledger-rebound','logical-offset-rebound','stripped-extension-rebound','profile-rebound','unknown-event-rebound'):
                name=arch+'-reader-'+mutation;source=root/(arch+'-managed-indicators');target=root/name
                snapshot(source);shutil.copytree(source,target)
                summary=read(target/'summary.json');engine=read(target/'engine-report.json');execution=engine['execution']
                if mutation=='summary-value':summary['memory_strings']['matches'][0]['value']='203.0.113.1'
                else:
                    event_receipt=execution['memory_string_sources']
                    if mutation=='alias-rebound':event_receipt['events'][5]['reference']=4
                    elif mutation=='token-rebound':event_receipt['events'][0]['token']=0x70000011
                    elif mutation=='event-boundary-rebound':event_receipt['events'][4]['instruction_count']=2
                    elif mutation=='utf16-preview-rebound':execution['heap']['strings'][0]['utf16_preview'][0]=0xfffd
                    elif mutation=='observer-ledger-rebound':event_receipt['source_utf16_bytes_observed']=0
                    elif mutation=='logical-offset-rebound':
                        execution['memory_strings']['matches'][0]['offset']=0
                        event_receipt['capture_sha256']=sha(canonical(execution['memory_strings']))
                    elif mutation=='stripped-extension-rebound':
                        execution.pop('memory_strings');execution.pop('memory_string_sources')
                        summary.pop('memory_strings');summary.pop('memory_string_sources')
                    elif mutation=='profile-rebound':
                        summary['run_manifest']['memory_string_profile']='arbitrary-managed'
                        engine['run_manifest']=summary['run_manifest']
                    else:event_receipt['events'][0]['unknown']=True
                    raw=(json.dumps(engine,separators=(',',':'))+'\n').encode();(target/'engine-report.json').write_bytes(raw)
                    summary['engine_report_sha256']=sha(raw);summary['engine_report_size']=len(raw)
                    if mutation!='stripped-extension-rebound':
                        summary['memory_strings']=execution['memory_strings'];summary['memory_string_sources']=execution['memory_string_sources']
                write(target/'summary.json',summary);original=snapshot(target)
                refused=call([exe,'inspect-report',target,'--verify-artifacts'],root/(name+'-inspect'))
                require(refused.returncode!=0 and snapshot(target)==original,name+': rebound typed authority accepted/changed')
                record(name,'reader-refusal',exit_code=refused.returncode)
        for name,command,reason in [
            ('custom',[exe,'analysis-fixture','managed-indicators-custom',root/'denied-custom'],'Unknown closed analysis case'),
            ('periodic',[exe,'analysis-fixture','managed-indicators',root/'denied-periodic','--checkpoint','100'],'Unknown generated analysis option'),
            ('general',[exe,'run','compiler-owned-unused.exe'],'disabled')]:
            denied=call(command,root/('gate-'+name));require(denied.returncode!=0 and reason.encode() in denied.stderr,name+': gate changed')
            require(not os.path.lexists(root/('denied-'+name)),name+': rejected gate created a run');record('gate-'+name,'gate')
        residual=root/'residual.ps1';residual.write_text("param([string]$Bundle,[string]$Run,[string]$Tool)\n$ErrorActionPreference='Stop'\n& $Tool -Roots @($Bundle,$Run) -WorkerRoots @($Bundle)\nif($LASTEXITCODE -ne 0){exit 1}\n",encoding='ascii')
        checked=call([ps,'-NoProfile','-NonInteractive','-File',residual,bundle,root,REPO/'tools/check_residual_appcontainer.ps1'],root/'residual')
        require(checked.returncode==0 and snapshot(bundle)==before and acl()==original_acl,'Residual/package/original DACL changed')
        require(len(records)==37,'Control count differs');status.update(verified=True,bundle_unchanged=True,original_sddl_restored=True,residual_check_passed=True)
        write(root/'verification.json',status);print(json.dumps(dict(verified=True,count=len(records),output_root=str(root))))
    except BaseException as error:status['error']=str(error);write(root/'verification.json',status);raise
if __name__=='__main__':main()
