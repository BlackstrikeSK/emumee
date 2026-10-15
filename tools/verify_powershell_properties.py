"""Check actual property identities, values, and dashboard rows in offline Docker."""

import argparse
import html
import json
from pathlib import Path

from emumee.dashboard import create_app
from emumee.powershell import run_script, save_script_run
from tools.powershell_property_cases import cases

ROOT=Path(__file__).resolve().parents[1]


def verify(report,case,run):
    failures=[]; matches=[]
    commands=report['command_events']
    for expected in case['expected']:
        found=[c for c in commands if c.get('command_type')=='DotNetProperty' and all(c.get(k)==v for k,v in expected.items())]
        if not found: failures.append('Missing property/value match: '+json.dumps(expected,ensure_ascii=False))
        matches.extend(found)
    if report['errors'] or report['guest_exit_code']!=0: failures.append('Run failure: '+repr(report['errors']))
    if not report['observer_trace_complete'] or not all(report['configuration_checks'].values()): failures.append('Incomplete trace or confinement evidence')
    if 'CASE-DONE='+case['name'] not in report['console_output']['stdout']: failures.append('Case did not finish')
    if any(e.get('network_used') is not False for e in report['network_events']): failures.append('Unexpected network use')
    client=create_app(run.parent).test_client()
    for c in matches:
        starts=[s for s in commands if s.get('engine_sequence')==c['access_id'] and s.get('guest_pid')==c.get('guest_pid') and s.get('command_type')=='DotNetProperty' and s.get('access_status')=='started']
        if len(starts)!=1: failures.append('Property access start correlation missing')
        page=(c['sequence']-1)//100+1
        response=client.get(f'/runs/{run.name}?commands_page={page}')
        markup=response.get_data(as_text=True)
        panel=markup.split(f'id="command-{c["sequence"]}"',1)[-1].split('</article>',1)[0]
        rendered=html.unescape(panel)
        if response.status_code!=200 or 'Resolved .NET property' not in rendered or c['declaring_type']+'::'+c['property_name'] not in rendered:
            failures.append('Dashboard property identity missing')
        if c['value_available'] and json.dumps(c['property_value'],ensure_ascii=False,indent=2) not in rendered:
            failures.append('Dashboard readable property value missing')
        if not c['value_available'] and 'no returned value' not in rendered: failures.append('Dashboard missing unavailable-result distinction')
    return failures,matches


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--case',action='append',dest='selected')
    parser.add_argument('--instrumented-engine',type=Path,default=ROOT/'output/powershell-instrumented-engine/System.Management.Automation.dll')
    args=parser.parse_args()
    selected=[c for c in cases() if not args.selected or c['name'] in args.selected]
    if not selected or args.selected and set(args.selected)!={c['name'] for c in selected}: parser.error('Unknown case')
    output=args.output.resolve(); output.mkdir(parents=True,exist_ok=False)
    results=[]
    for case in selected:
        source=output/(case['name']+'.ps1'); source.write_text(case['source'],encoding='utf-8',newline='\n')
        report=run_script(source,ROOT/'output/powershell-exec-observer/observer',args.instrumented_engine,
            guest_tools_build=ROOT/'output/powershell-guest-tools/build.json',timeout=120)
        run=save_script_run(report,ROOT/'output/powershell-dashboard-probe')
        failures,matches=verify(report,case,run)
        result={'case':case['name'],'passed':not failures,'failures':failures,'run':str(run),
                'engine_sha256':report['instrumented_engine_build']['assembly_sha256'],'matched_properties':matches,'console':report['console_output']}
        results.append(result)
        (output/'progress.json').write_text(json.dumps(results,ensure_ascii=False,indent=2),encoding='utf-8')
        print(json.dumps({k:result[k] for k in ('case','passed','failures','run')}),flush=True)
    passed=all(c['passed'] for c in results)
    (output/'verification.json').write_text(json.dumps({'passed':passed,'cases':results},ensure_ascii=False,indent=2),encoding='utf-8')
    raise SystemExit(0 if passed else 1)


if __name__=='__main__': main()
