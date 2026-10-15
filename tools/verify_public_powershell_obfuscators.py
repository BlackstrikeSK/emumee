"""Test public obfuscators on benign fixtures; generate and execute only in offline guests."""

import argparse
import base64
import hashlib
import io
import json
import subprocess
import sys
import uuid
import zipfile
from pathlib import Path, PurePosixPath

from emumee.powershell import run_script, save_script_run
from emumee.powershell_capture import docker
from tools.powershell_obfuscation_cases import PRELUDE, TEXT, ITEMS, decode, invoke
from tools.verify_powershell_obfuscation import check

ROOT = Path(__file__).resolve().parents[1]
UPSTREAM = {
    'Invoke-Obfuscation': ('https://github.com/danielbohannon/Invoke-Obfuscation', 'f20e7f843edd0a3a7716736e9eddfa423395dd26'),
    'Obfell': ('https://github.com/Jael-G/Obfell', '7467840b9ba28d51a8ae16e1d7472a2065369b9a'),
}
MODES = ['token-command', 'token-string', 'token-all', 'ascii', 'hex', 'bxor', 'compress', 'layered', 'bxor-long']

GENERATE_PS = r'''
$ErrorActionPreference='Stop'
Get-ChildItem '/work/repos/Invoke-Obfuscation/Out-*.ps1' | ForEach-Object { . $_.FullName }
$specs=[IO.File]::ReadAllText('/work/specs.json') | ConvertFrom-Json
foreach($spec in $specs) {
    if($spec.tool -ne 'Invoke-Obfuscation'){continue}
    $null=Get-Random -SetSeed $spec.seed
    $block=[ScriptBlock]::Create($spec.input)
    $result=switch($spec.mode) {
        'token-command' { Out-ObfuscatedTokenCommand -ScriptBlock $block -TokenTypeToObfuscate Command -ObfuscationLevel 2 }
        'token-string' { Out-ObfuscatedTokenCommand -ScriptBlock $block -TokenTypeToObfuscate String -ObfuscationLevel 2 }
        'token-all' { Out-ObfuscatedTokenCommand -ScriptBlock $block }
        'ascii' { Out-EncodedAsciiCommand -ScriptBlock $block -PassThru }
        'hex' { Out-EncodedHexCommand -ScriptBlock $block -PassThru }
        'bxor' { Out-EncodedBXORCommand -ScriptBlock $block -PassThru }
        'bxor-long' { Out-EncodedBXORCommand -ScriptBlock $block -PassThru }
        'compress' { Out-CompressedCommand -ScriptBlock $block -PassThru }
        'layered' {
            $first=Out-ObfuscatedTokenCommand -ScriptBlock $block
            $second=Out-CompressedCommand -ScriptBlock ([ScriptBlock]::Create([string]$first)) -PassThru
            Out-EncodedBXORCommand -ScriptBlock ([ScriptBlock]::Create([string]$second)) -PassThru
        }
    }
    [IO.File]::WriteAllText(('/work/'+$spec.name+'.ps1'),[string]$result)
}
'''

GENERATE_PY = r'''
import base64, importlib.util, json, pathlib, random, subprocess
root=pathlib.Path('/work')
specs=json.loads((root/'specs.json').read_text())
prelude=(root/'prelude.ps1').read_text()
reference=(root/'reference.ps1').read_text()
with (root/'generation.log').open('wb') as log:
    p=subprocess.run(['pwsh','-NoLogo','-NoProfile','-NonInteractive','-File','/work/generate.ps1'],stdout=log,stderr=log,timeout=180)
if p.returncode:
    raise RuntimeError((root/'generation.log').read_text(errors='replace')[-6000:])
spec=importlib.util.spec_from_file_location('upstream_obfell','/work/repos/Obfell/obfell.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
results=[]
for item in specs:
    name=item['name']; path=root/(name+'.ps1')
    if item['tool']=='Obfell':
        random.seed(item['seed'])
        source=root/'obfell-input.ps1';source.write_text(item['input'])
        ob=module.ScriptObfuscator(str(source),item['arrays'],24,item['operations'])
        assert ob.load_file();ob.generate_arrays();ob.generate_obfuscated_powershell_script()
        path.write_bytes((root/'output.ps1').read_bytes())
    content=path.read_text()
    assert 0 < len(content.encode()) <= 1024*1024
    ref=root/'reference-input.ps1';ref.write_text(reference+content)
    p=subprocess.run(['pwsh','-NoLogo','-NoProfile','-NonInteractive','-File',str(ref)],capture_output=True,timeout=25)
    results.append({'name':name,'source_b64':base64.b64encode((prelude+content).encode()).decode(),
        'reference_exit_code':p.returncode,'reference_stdout':p.stdout.decode(errors='replace')[-16000:],
        'reference_stderr':p.stderr.decode(errors='replace')[-4000:]})
print(json.dumps({'generated':results,'generation_log':(root/'generation.log').read_text(errors='replace')[-4000:]}))
'''

BOOTSTRAP = r'''
import io,pathlib,subprocess,sys,zipfile
data=sys.stdin.buffer.read(8*1024*1024+1)
assert len(data)<=8*1024*1024
with zipfile.ZipFile(io.BytesIO(data)) as archive:
    for name in archive.namelist():
        path=pathlib.PurePosixPath(name)
        assert not path.is_absolute() and '..' not in path.parts
    archive.extractall('/work')
subprocess.run(['/opt/emumee-python/bin/python','-I','/work/generate.py'],check=True,timeout=240)
'''


def specifications():
    specs = []
    for index, mode in enumerate(MODES):
        specs.append({'name': 'invoke-' + mode, 'tool':'Invoke-Obfuscation', 'mode':mode, 'seed':517+index})
    for index, (arrays, operations) in enumerate(((2,1),(6,5),(20,10))):
        specs.append({'name':f'obfell-{arrays}-arrays-{operations}-operations', 'tool':'Obfell',
                      'arrays':arrays, 'operations':operations, 'seed':822+index})
    for spec in specs:
        spec['input'] = invoke(spec['name'], text=decode(TEXT), items='@(' + ','.join('('+decode(v)+')' for v in ITEMS) + ')')
        if spec.get('mode')=='bxor-long':
            spec['seed']=522
            spec['input']="$null='"+('A'*1000)+"';"+spec['input']
    return specs


def generate(repos, specs):
    archive = io.BytesIO()
    provenance = {}
    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED) as bundle:
        for name, (url, commit) in UPSTREAM.items():
            repo = repos / name
            actual = subprocess.check_output(['git','-C',str(repo),'rev-parse','HEAD'],text=True).strip()
            dirty = subprocess.check_output(['git','-C',str(repo),'status','--porcelain'],text=True).strip()
            if actual != commit or dirty:
                raise ValueError(f'{name}: clean pinned revision required: {commit}')
            provenance[name] = {'url':url,'commit':actual}
            tracked = subprocess.check_output(['git','-C',str(repo),'ls-files','-z']).decode().split('\0')
            for relative in filter(None, tracked):
                path=repo/relative
                if path.is_symlink() or not path.resolve().is_relative_to(repo.resolve()):
                    raise ValueError('Unsafe upstream file link')
                if path.suffix.lower() == '.ps1' or name == 'Obfell' and path.name == 'obfell.py':
                    bundle.writestr(f'repos/{name}/{relative}',path.read_bytes())
        reference = PRELUDE.replace("[Console]::WriteLine('PROBE=' + $Case)",
            "[Console]::WriteLine('REFERENCE='+(@{Case=$Case;Text=$Text;Items=$Items;Count=$Count;Enabled=[bool]$Enabled}|ConvertTo-Json -Compress -Depth 8))")
        for name, content in {'specs.json':json.dumps(specs), 'prelude.ps1':PRELUDE,
                              'reference.ps1':reference,'generate.ps1':GENERATE_PS,'generate.py':GENERATE_PY}.items():
            bundle.writestr(name,content.encode('utf-8'))
    image=json.loads((ROOT/'output/powershell-guest-tools/build.json').read_text())['image_id']
    name='emumee-obfuscator-'+uuid.uuid4().hex
    created=False
    try:
        docker('create','--name',name,'--interactive','--pull=never','--network=none','--read-only',
               '--cap-drop=ALL','--security-opt=no-new-privileges=true','--user=65534:65534',
               '--pids-limit=64','--memory=512m','--memory-swap=512m','--cpus=1','--log-driver=none',
               '--tmpfs=/work:rw,nosuid,nodev,noexec,size=16m,mode=1777','--workdir=/work',
               '--env=HOME=/work','--env=POWERSHELL_TELEMETRY_OPTOUT=1',
               image,'/opt/emumee-python/bin/python','-I','-c',BOOTSTRAP)
        created=True
        info=json.loads(docker('inspect',name))[0]
        assert info['HostConfig']['NetworkMode']=='none' and info['HostConfig']['ReadonlyRootfs']
        assert not info['HostConfig'].get('Binds') and all(m['Type']=='tmpfs' for m in info.get('Mounts',[]))
        assert info['Config']['User']=='65534:65534' and info['HostConfig']['CapDrop']==['ALL']
        assert info['HostConfig']['SecurityOpt']==['no-new-privileges=true']
        assert info['HostConfig']['Memory']==512*1024*1024 and info['HostConfig']['MemorySwap']==512*1024*1024
        assert info['HostConfig']['PidsLimit']==64 and info['HostConfig']['NanoCpus']==1000000000
        p=subprocess.run(['docker','start','--attach','--interactive',name],input=archive.getvalue(),capture_output=True,timeout=270)
        if p.returncode:
            raise RuntimeError(p.stderr.decode(errors='replace')[-6000:])
        envelope=json.loads(p.stdout)
        return envelope, provenance
    finally:
        if created:
            docker('rm','--force',name)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repos',type=Path,default=ROOT/'output/public-obfuscators/repos')
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--replay',type=Path,help='Reuse a saved generation.json, including its stock-runtime evidence')
    parser.add_argument('--case',action='append',dest='selected')
    args=parser.parse_args()
    output=args.output.resolve();output.mkdir(parents=True,exist_ok=False)
    specs=specifications()
    if args.selected:
        specs=[spec for spec in specs if spec['name'] in args.selected]
        if set(args.selected)!={spec['name'] for spec in specs}:
            parser.error('Unknown case name')
    if args.replay:
        saved=json.loads(args.replay.read_text(encoding='utf-8'))
        provenance=saved['provenance']
        generated={**saved,'generated':[item for item in saved['generated'] if item['name'] in {s['name'] for s in specs}]}
        if {item['name'] for item in generated['generated']}!={spec['name'] for spec in specs}:
            raise ValueError('Replay does not contain all requested cases')
    else:
        generated,provenance=generate(args.repos.resolve(),specs)
    (output/'generation.json').write_text(json.dumps({'provenance':provenance,**generated},ensure_ascii=False,indent=2),encoding='utf-8')
    by_name={spec['name']:spec for spec in specs}
    results=[]
    for item in generated['generated']:
        name=item['name'];spec=by_name[name]
        expected={'Case':name,'Text':TEXT,'Items':ITEMS,'Count':42,'Enabled':True}
        references=[json.loads(line[len('REFERENCE='):]) for line in item['reference_stdout'].splitlines() if line.startswith('REFERENCE=')]
        reference_ok=item['reference_exit_code']==0 and references==[expected]
        source=base64.b64decode(item['source_b64'],validate=True)
        if not 0<len(source)<=1024*1024:
            raise ValueError('Generated script exceeds bounds')
        path=output/(name+'.ps1');path.write_bytes(source)
        result={'case':name,'tool':spec['tool'],'settings':spec,'reference_passed':reference_ok,
                'source_sha256':hashlib.sha256(source).hexdigest(),'source_bytes':len(source),
                'reference_stderr':item['reference_stderr']}
        report=run_script(path,ROOT/'output/powershell-exec-observer/observer',
            ROOT/'output/powershell-instrumented-engine/System.Management.Automation.dll',
            guest_tools_build=ROOT/'output/powershell-guest-tools/build.json',timeout=120)
        run=save_script_run(report,ROOT/'output/powershell-dashboard-probe')
        failures,matches=check(report,{'name':name,'expected':expected},run)
        runtime_parity=report['observer_trace_complete'] and report['guest_exit_code']==item['reference_exit_code']
        result.update(passed=reference_ok and not failures,failures=failures,run=str(run),matching_invocations=len(matches),
                      reference_exit_code=item['reference_exit_code'],runtime_parity=runtime_parity,
                      classification=('runtime_divergence' if not runtime_parity else 'upstream_incompatible' if not reference_ok else 'capture_failure' if failures else 'verified'),
                      execution_errors=report['errors'],guest_exit_code=report['guest_exit_code'],
                      stderr=report['console_output']['stderr'])
        results.append(result)
        (output/'progress.json').write_text(json.dumps(results,ensure_ascii=False,indent=2),encoding='utf-8')
        print(json.dumps({key:result[key] for key in ('case','reference_passed','passed','failures') }),flush=True)
    passed=all(item['passed'] for item in results)
    (output/'verification.json').write_text(json.dumps({'passed':passed,'provenance':provenance,'cases':results,
        'verified_cases':sum(item['passed'] for item in results),
        'upstream_incompatible':sum(item['classification']=='upstream_incompatible' for item in results)},ensure_ascii=False,indent=2),encoding='utf-8')
    sys.exit(0 if passed else 1)


if __name__=='__main__':
    main()
