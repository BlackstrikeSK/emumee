"""Verify generated enumeration children through the packaged AppContainer CLI."""

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

from emumee.enumeration_programs import enumeration_programs
from emumee.guest_programs import hostname_exe
from emumee.persona import load_persona
from emumee.reports import read_verified_engine_report
from emumee.worker_build import verify_receipt
from tests.fixtures.build_native import build_host_winexec_probe
from tests.test_powershell_guest_tools import COMMANDS

ROOT = Path(__file__).resolve().parents[1]


def parent_image(machine: int, command: str) -> bytes:
    image = bytearray(build_host_winexec_probe(machine, 'unused-marker'))
    encoded = command.encode('ascii') + b'\0'
    if len(encoded) > 0x200:
        raise ValueError('Guest command exceeds fixture bounds')
    image[0x700:0x900] = b'\0' * 0x200
    image[0x700:0x700 + len(encoded)] = encoded
    return bytes(image)


def analyze(runner, sample, output, persona_path=None):
    command = [*runner, 'run', str(sample), '--output', str(output), '--timeout', '20',
               '--max-instructions', '500000', '--offline-replay']
    if persona_path:
        command.extend(['--persona', str(persona_path)])
    completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=75)
    try:
        envelope = json.loads(completed.stdout)
        report_path = Path(envelope['report'])
        summary = json.loads(report_path.read_text(encoding='utf-8'))
    except (ValueError, KeyError) as error:
        raise AssertionError(f'CLI did not return a report: {completed.stdout} {completed.stderr}') from error
    if completed.returncode or summary['status'] != 'completed' or summary['errors']:
        raise AssertionError(f'Packaged analysis failed: {summary}')
    if summary['run_manifest']['network_mode'] != 'offline_replay':
        raise AssertionError('Enumeration package gate must have no live network broker')
    if not all(summary['worker_containment'].get(k) for k in ('app_container','job_object','child_process_blocked')):
        raise AssertionError('Worker containment was not verified')
    raw = read_verified_engine_report(report_path.parent, summary)
    if raw is None:
        raise AssertionError('Engine report integrity verification failed')
    return summary, json.loads(raw), report_path.parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists():
        raise ValueError('Choose a fresh package gate output directory')
    output.mkdir(parents=True)
    worker = ROOT/'dist/Emumee/Emumee.exe'
    receipt = verify_receipt(worker, ROOT)
    config = {'hostname':'PACKAGE-ENUM-61','user_name':'Casey','user_is_admin':True,'domain':'corp.example',
              'device_registration':{'domain_joined':True},'clock_utc':'2026-10-14T12:00:00Z',
              'network_adapter':{'ipv4':'192.0.2.61','gateway':'192.0.2.1','dns_servers':['192.0.2.53']}}
    persona_path = output/'persona.json'
    persona_path.write_text(json.dumps(config),encoding='utf-8')
    persona = load_persona(persona_path)
    # The source CLI must use a compatible worker, including binary persona files.
    sample=output/'source-cli-ping-x64.exe'
    sample.write_bytes(parent_image(0x8664,'ping.exe -n 1 localhost'))
    summary,engine,run=analyze([sys.executable,'-m','emumee'],sample,output/'source-cli')
    if 'Reply from 127.0.0.1' not in summary['console_output']['stdout']:
        raise AssertionError('Source CLI did not execute its guest ping child')
    findings=[{'interface':'source-cli','program':'ping.exe','architecture':'x64','report':str(run/'summary.json')}]
    for arch,machine in (('x86',0x14c),('x64',0x8664)):
        images={'hostname.exe':hostname_exe(arch=='x64'), **enumeration_programs(arch=='x64',persona)}
        if set(images) != set(COMMANDS):
            raise AssertionError('Packaged gate inventory differs from bundled utilities')
        for index,(name,arguments) in enumerate(COMMANDS.items(),1):
            command=subprocess.list2cmdline([name,*arguments])
            sample=output/f'{arch}-{name}'
            sample.write_bytes(parent_image(machine,command))
            summary,engine,run=analyze([str(worker)],sample,output/'runs',persona_path)
            creates=[e for e in engine['virtual_process_events'] if e['event']=='virtual_process_create' and e.get('success')]
            if len(creates)!=1 or creates[0]['application'].casefold()!=name:
                raise AssertionError(f'{arch}/{name}: guest child was not created from the requested image')
            child=creates[0]['pid']
            exits=[e for e in engine['virtual_process_events'] if e['event']=='virtual_process_exit' and e.get('pid')==child]
            if len(exits)!=1 or exits[0]['exit_code']!=0:
                raise AssertionError(f'{arch}/{name}: guest child did not exit successfully: {exits}')
            payload=(run/'persona-programs'/name).read_bytes()
            expected=hashlib.sha256(images[name]).hexdigest()
            if hashlib.sha256(payload).hexdigest()!=expected:
                raise AssertionError(f'{arch}/{name}: generated child bytes differ from persona image')
            text=summary['console_output']['stdout']
            if not text:
                raise AssertionError(f'{arch}/{name}: supported read command has no output')
            if any(e.get('network_used') for e in engine.get('network_events',[])):
                raise AssertionError(f'{arch}/{name}: unexpected network use')
            if name=='whoami.exe' and 'PACKAGE-ENUM-61\\Casey' not in text:
                raise AssertionError('Packaged whoami did not confirm persona')
            if name=='ipconfig.exe' and '192.0.2.61' not in text:
                raise AssertionError('Packaged ipconfig did not confirm adapter')
            if name=='hostname.exe' and text.strip()!='PACKAGE-ENUM-61':
                raise AssertionError('Packaged hostname did not confirm persona')
            if name=='ping.exe' and not any(e['event']=='guest_icmp_echo' and e.get('status')==0 for e in engine['network_events']):
                raise AssertionError('Packaged ping did not use offline ICMP')
            findings.append({'interface':'packaged-cli','program':name,'arguments':arguments,'architecture':arch,
                             'child_exit_code':0,'guest_pe_sha256':expected,'report':str(run/'summary.json')})
            (output/'progress.json').write_text(json.dumps({'passed':findings},indent=2),encoding='utf-8')
            print(f'{arch} {index}/{len(COMMANDS)} {name}: guest child exit 0, persona bytes verified',flush=True)
    result={'passed':True,'cases':len(findings),'worker_sha256':receipt['worker_sha256'],
            'source_tree_sha256':receipt['source_tree_sha256'],'guest_native_assets':receipt['guest_native_assets'],
            'findings':findings}
    (output/'verification.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps({'passed':True,'cases':len(findings),'report':str(output/'verification.json')}))


if __name__=='__main__':
    main()
