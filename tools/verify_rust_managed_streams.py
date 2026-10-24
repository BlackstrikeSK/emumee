"""Frozen-bundle, contained owned-CIL MemoryStream controls only.

Constructor metadata controls deliberately declare no unused Class locals and
must reach explicit newobj rejection. Separate source controls prove declared
Class locals fail entry preflight; this verifier never fabricates their trace.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def sha(raw):return hashlib.sha256(raw).hexdigest()
def write(path,value):path.write_text(json.dumps(value,indent=2)+'\n',encoding='utf-8')
def require(ok,message):
    if not ok:raise AssertionError(message)
def snapshot(root):
    return {str(p.relative_to(root)):{'size':p.stat().st_size,'sha256':sha(p.read_bytes())}
            for p in sorted(root.rglob('*')) if p.is_file()}
def preview(e,index):return [v['value'] for v in e['arrays']['evidence'][index]['preview']]


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--bundle',required=True,type=Path)
    parser.add_argument('--output-root',required=True,type=Path)
    args=parser.parse_args()
    bundle=args.bundle.resolve(strict=True);root=args.output_root.resolve()
    require(not root.exists(),'Use a fresh evidence root')
    require(root!=bundle and bundle not in root.parents and root not in bundle.parents,'Keep evidence outside bundle')
    exe=bundle/'emumee-rs.exe';require(exe.is_file(),'Frozen controller missing')
    root.mkdir(parents=True);before=snapshot(bundle);write(root/'bundle-before.json',before)
    positive=[
        ('owned',82,1,1),('file',17,1,1),('borrowed-write',81,1,1),('borrowed-read',81,1,1),
        ('can-write',0,1,1),('to-array-copy',65,1,2),('close',3,1,2),('sparse',6,1,1),
        ('empty-write',0,1,1),('shrink',0,1,2),('seek',67,1,1),('read',66,1,2),
        ('copy',67,2,2),('identity',0,2,0),('alias',1,1,0),('object-local',82,1,1),
        ('base-local',82,1,1),('object-class-local',82,1,1),('object-array',82,1,2),
        ('object-array-kinds',65,1,2),('static-call',82,1,1),
    ]
    cases=[dict(case=c,value=v,objects=o,arrays=a)for c,v,o,a in positive]
    negatives=[
        ('read-only','NotSupportedException',1,1),('fixed','fixed MemoryStream capacity',1,1),
        ('closed-read','ObjectDisposedException',1,1),('closed-can','ObjectDisposedException',1,1),
        ('self-copy','same stream',1,1),('null-buffer','ArgumentNullException',0,0),
        ('bad-flag','writable flag',0,1),('bad-capacity','ArgumentOutOfRangeException',0,0),
        ('bad-signature','method/signature',0,0),('bad-assembly','assembly/type',0,0),
        ('bad-version','assembly/type',0,0),('bad-namespace','namespace',0,0),
        ('bad-owner','MemberRef owner',0,0),('bad-scope','AssemblyRef',0,0),
        ('constructor-call','require newobj',1,0),('constructor-stack','max_stack',0,0),
        ('null-receiver','NullReferenceException',0,0),('exposure','method/signature',1,0),
        ('unknown-class','Class identity',1,0),('object-bad-value','store value type mismatch',0,1),
        ('to-array-limit','array element limit',1,0),
    ]
    cases += [dict(case=c,error=error,objects=o,arrays=a)for c,error,o,a in negatives]
    cases += [dict(case='quota',error='MemoryStream object limit',objects=4096,arrays=0,budget=100000,
                   instructions=12289,calls=4096,attempts=4097,owned=0),
              dict(case='owned-quota',error='owned capacity limit',objects=2,arrays=0,
                   instructions=8,calls=2,attempts=3,owned=67108864)]
    require(len(cases)==44,'Missing generated baseline kinds')
    for case,name,budget,objects,arrays,length,position in [
        ('owned','owned-before-write',3,1,0,0,0),('owned','owned-after-write',4,1,0,1,1),
        ('borrowed-write','borrow-before-newobj',4,0,1,None,None),
        ('borrowed-write','borrow-after-newobj',5,1,1,3,0),
        ('borrowed-write','borrow-before-write',6,1,1,3,0),
        ('borrowed-write','borrow-after-write',7,1,1,3,1),
        ('file','file-before-capture',6,1,1,1,1),('file','file-after-capture',7,1,1,1,1),
    ]:
        cases.append(dict(case=case,name=name,partial=True,budget=budget,objects=objects,arrays=arrays,
                          length=length,position=position))
    records=[];status=dict(schema=1,scope='closed generated MemoryStream/newobj models; no host CLR or sample execution',
                          expected_count=104,count=0,verified=False,records=records)
    write(root/'verification.json',status)
    try:
        for arch in ('x86','x64'):
            for case in cases:
                name=arch+'-'+case.get('name',case['case']);run=root/name;kind='managed-stream-'+case['case'];budget=case.get('budget',1000)
                command=[str(exe),'fixture','--arch',arch,'--kind',kind,'--iterations','17','--max-instructions',str(budget),'--isolated-output',str(run)]
                write(root/(name+'.command.json'),command)
                proc=subprocess.run(command,capture_output=True,timeout=90,check=False)
                (root/(name+'.stdout.bin')).write_bytes(proc.stdout);(root/(name+'.stderr.bin')).write_bytes(proc.stderr)
                write(root/(name+'.exit.json'),{'exit_code':proc.returncode})
                result=json.loads((run/'fixture-result.json').read_bytes());e=result['execution'];f=e['framework'];contain=result['containment']
                require(contain['app_container'] and contain['job_object'] and contain['child_process_blocked'] and contain['network_capabilities']==0,name+': containment differs')
                require(e['backend']=='rust/managed-il' and e['architecture']==arch and 'No host CLR' in e['scope'],name+': backend/scope differs')
                if case.get('partial'):
                    require(proc.returncode==1 and e['completion_reason']=='instruction_budget' and e['instruction_count']==budget
                            and e['managed_return'] is None and e['guest_entry_return'] is None,name+': false partial return')
                elif case.get('error'):
                    require(proc.returncode==1 and e['completion_reason']=='error' and case['error'] in (e['error'] or '')
                            and e['managed_return'] is None and e['guest_entry_return'] is None,name+': explicit negative failure differs')
                    if case['case'] not in ('unknown-class','object-bad-value'):
                        require(f['attempts']==f['completed_calls']+1,name+': failed framework call miscounted')
                else:
                    require(proc.returncode==0 and e['completion_reason']=='entry_return'
                            and e['managed_return']=={'kind':'i32','value':case['value']}
                            and e['guest_entry_return']==case['value'],name+': actual IL return differs')
                    require(f['attempts']==f['completed_calls'],name+': successful framework accounting differs')
                if 'instructions' in case:require(e['instruction_count']==case['instructions'],name+': instruction count differs')
                for key,actual in [('calls',f['completed_calls']),('attempts',f['attempts'])]:
                    if key in case:require(actual==case[key],name+': '+key+' differs')
                s=f.get('streams',{'objects':0,'owned_capacity':0,'evidence':[]})
                require(s['objects']==case['objects'] and e['arrays']['objects']==case['arrays'],name+': failed constructor allocated identity or wrong array count')
                if 'owned' in case:require(s['owned_capacity']==case['owned'],name+': owned capacity differs')
                require(s['owned_capacity']<=67108864 and s['objects']<=4096 and len(s['evidence'])<=64,name+': stream bounds exceeded')
                for item in s['evidence']:
                    require(item['length']<=33554432 and item['position']<=33554432 and item['capacity']<=33554432,name+': stream extent exceeded')
                if case.get('partial') and case['length'] is not None:
                    require(s['evidence'][0]['length']==case['length'] and s['evidence'][0]['position']==case['position'],name+': partial side effect crossed instruction budget')
                require(len(f['events'])<=128 and len(f['events'])+f['omitted_events']==f['attempts']
                        and sum(f['counts'].values())==f['completed_calls'],name+': framework evidence count bound differs')
                require(sum(e['opcode_counts'].values())==e['instruction_count'] and len(e['instruction_tail'])<=128,name+': instruction count bound differs')
                require(not f['console_output']['utf16'],name+': unexpected guest console')
                capture=case['case']=='file' and (not case.get('partial') or budget>=7)
                require(len(e['artifacts'])==int(capture),name+': raw stream memory mislabeled as capture')
                if capture:
                    artifact=e['artifacts'][0];digest=sha(b'R')
                    require(artifact['sha256']==digest and artifact['filename']==digest+'.bin' and artifact['size']==1
                            and (run/'artifacts'/artifact['filename']).read_bytes()==b'R',name+': captured bytes/hash differ')
                    require(len(artifact['observations'])==2 and {o['source']for o in artifact['observations']}==
                            {'managed_write_all_bytes','managed_virtual_file_at_stop'} and
                            all(o['kind']=='guest_file' and o['guest_path']=='c:\\stream.bin'for o in artifact['observations']),name+': capture origin differs')
                if not case.get('partial'):
                    c=case['case']
                    if c in ('borrowed-write','borrowed-read'):require(preview(e,0)==[81,66,67],name+': original array alias differs')
                    if c in ('read-only','fixed','self-copy'):require(preview(e,0)==[65,66,67],name+': failed write changed bytes')
                    if c=='to-array-copy':require(preview(e,0)==[65,66,67] and preview(e,1)==[81,66,67],name+': ToArray aliases backing')
                    if c=='shrink':require(preview(e,0)==[65,0,0] and preview(e,1)==[65,0,0],name+': re-exposed bytes not zeroed')
                    if c=='sparse':require(preview(e,0)==[0,0,0,0,0,82],name+': sparse write bytes differ')
                    if c=='read':require(preview(e,1)==[0,65,66],name+': guest read destination differs')
                    if c=='empty-write':require(s['evidence'][0]['length']==0 and s['evidence'][0]['position']==5,name+': retained zero-count behavior changed')
                    if c in ('close','closed-read','closed-can'):require(s['evidence'][0]['closed'],name+': Dispose lost identity/state')
                    if c=='copy':require([v['position']for v in s['evidence']]==[3,3],name+': CopyTo positions differ')
                    if c=='object-array-kinds':
                        require(e['arrays']['evidence'][0]['preview']==[
                            {'kind':'string_ref','value':1},{'kind':'array_ref','value':{'reference':2,'element':'u1'}},
                            {'kind':'object_ref','value':{'reference':1,'kind':'memory_stream'}}],name+': Object[] lost actual typed references')
                    if c=='object-bad-value':require(e['arrays']['evidence'][0]['preview']==[{'kind':'null'}] and e['arrays']['element_writes']==0,name+': numeric reference was fabricated')
                    if c=='static-call':require(e['managed_calls']==1 and e['max_call_depth']==2,name+': resolved-class static call differs')
                records.append(dict(name=name,arch=arch,kind=kind,exit_code=proc.returncode,completion=e['completion_reason'],
                                    instructions=e['instruction_count'],result_sha256=sha((run/'fixture-result.json').read_bytes()),files=snapshot(run),verified=True))
                status['count']=len(records);write(root/'verification.json',status)
        after=snapshot(bundle);write(root/'bundle-after.json',after);require(before==after,'Frozen bundle changed')
        require(len(records)==104,'Missing verification controls');status['verified']=True;write(root/'verification.json',status)
        print(json.dumps({'verified':True,'count':len(records),'output_root':str(root)}))
    except BaseException as error:
        status['error']=str(error);write(root/'verification.json',status);raise


if __name__=='__main__':main()
