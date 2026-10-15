"""Verify readable .NET method identities and passed values inside confined PowerShell."""

import argparse
import html
import json
from pathlib import Path

from emumee.dashboard import create_app
from emumee.powershell import run_script, save_script_run
from tools.powershell_method_cases import cases

ROOT=Path(__file__).resolve().parents[1]


def verify(report,case,run):
    failures=[]
    matches=[]
    for expected in case['expected']:
        found=[]
        for command in report['command_events']:
            if command.get('command_type')!='DotNetMethod': continue
            if command.get('method_name')!=expected['method_name']: continue
            if command.get('phase')!=expected.get('phase','method_arguments_bound'): continue
            if 'declaring_type' in expected and command.get('declaring_type')!=expected['declaring_type']: continue
            if [arg['value'] for arg in command.get('method_arguments',[])]!=expected['values']: continue
            if 'generic_arguments' in expected and command.get('generic_arguments')!=expected['generic_arguments']: continue
            if 'supplied_argument_count' in expected and command.get('supplied_argument_count')!=expected['supplied_argument_count']: continue
            if 'delegate_target' in expected and expected['delegate_target'] not in command.get('delegate_targets',[]): continue
            found.append(command)
        if not found: failures.append('Missing method/value match: '+json.dumps(expected,ensure_ascii=False))
        else: matches.extend(found)
    if report['errors']: failures.append('Run errors: '+repr(report['errors']))
    if report['guest_exit_code']!=0: failures.append('PowerShell exit differs from zero')
    if not report['observer_trace_complete']: failures.append('Observer lifecycle incomplete')
    if not all(report['configuration_checks'].values()): failures.append('Confinement configuration failed')
    if 'CASE-DONE='+case['name'] not in report['console_output']['stdout']: failures.append('Case did not finish')
    if any(event.get('network_used') is not False for event in report['network_events']): failures.append('Unexpected network use')
    client=create_app(run.parent).test_client()
    for command in matches:
        page=(command['sequence']-1)//100+1
        response=client.get(f'/runs/{run.name}?commands_page={page}')
        markup=response.get_data(as_text=True)
        panel=markup.split(f'id="command-{command["sequence"]}"',1)[-1].split('</article>',1)[0]
        display=html.unescape(panel)
        if response.status_code!=200 or 'Resolved .NET method' not in display: failures.append('Dashboard method panel missing')
        if command['method_signature'] not in display: failures.append('Dashboard missing method signature')
        for argument in command['method_arguments']:
            value=argument['value']
            if isinstance(value,str) and value and json.dumps(value,ensure_ascii=False) not in display:
                failures.append('Dashboard missing readable method value')
    return failures,matches


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--case',action='append',dest='selected')
    args=parser.parse_args()
    selected=[case for case in cases() if not args.selected or case['name'] in args.selected]
    if not selected or args.selected and set(args.selected)!={case['name'] for case in selected}: parser.error('Unknown case')
    output=args.output.resolve();output.mkdir(parents=True,exist_ok=False)
    results=[]
    for case in selected:
        source=output/(case['name']+'.ps1');source.write_text(case['source'],encoding='utf-8',newline='\n')
        report=run_script(source,ROOT/'output/powershell-exec-observer/observer',
            ROOT/'output/powershell-instrumented-engine/System.Management.Automation.dll',
            guest_tools_build=ROOT/'output/powershell-guest-tools/build.json',timeout=120)
        run=save_script_run(report,ROOT/'output/powershell-dashboard-probe')
        failures,matches=verify(report,case,run)
        result={'case':case['name'],'passed':not failures,'failures':failures,'run':str(run),
                'engine_sha256':report['instrumented_engine_build']['assembly_sha256'],
                'matched_methods':[{'signature':c['method_signature'],'arguments':c['method_arguments'],
                    'sequence':c['sequence'],'phase':c['phase']} for c in matches],
                'console':report['console_output']}
        results.append(result)
        (output/'progress.json').write_text(json.dumps(results,ensure_ascii=False,indent=2),encoding='utf-8')
        print(json.dumps({k:result[k] for k in ('case','passed','failures','run')}),flush=True)
    passed=all(item['passed'] for item in results)
    (output/'verification.json').write_text(json.dumps({'passed':passed,'cases':results},ensure_ascii=False,indent=2),encoding='utf-8')
    raise SystemExit(0 if passed else 1)


if __name__=='__main__': main()
