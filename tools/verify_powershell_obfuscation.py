"""Run benign obfuscated fixtures inside the confined guest and verify final bindings."""

import argparse
import hashlib
import html
import json
from pathlib import Path

from emumee.dashboard import create_app
from emumee.powershell import run_script, save_script_run
from tools.powershell_obfuscation_cases import cases

ROOT = Path(__file__).resolve().parents[1]


def check(report, case, run):
    failures = []

    def require(condition, message):
        if not condition:
            failures.append(message)

    require(report['errors'] == [], 'Run errors: ' + repr(report['errors']))
    require(report['guest_exit_code'] == 0, 'PowerShell did not exit successfully')
    require(report['observer_trace_complete'], 'Native observer lifecycle incomplete')
    require(all(report['configuration_checks'].values()), 'Confinement setting failed')
    require(all(event.get('network_used') is False for event in report['network_events']), 'Unexpected network use')
    commands = report['command_events']
    expected_command = case.get('command', 'Invoke-ReadableProbe')
    matches = [c for c in commands if c['command'] == expected_command and
               c.get('phase') == 'process_record_bound' and c.get('bound_parameters') == case['expected']]
    require(bool(matches), 'Missing exact final typed parameter values at process_record_bound')
    if case['name'] == 'long-derived-source-line':
        require(any(c.get('source_line_truncated') and c.get('source_line_length', 0) > 65536 and
                    len(c.get('source_line', '')) <= 1024 for c in matches), 'Missing bounded source preview metadata')
    if case.get('require_network_denial'):
        require(any(e['event'] == 'network_denied' and e['sequence'] > c['observer_sequence']
                    for e in report['network_events'] for c in matches), 'Missing denial after evaluated web request')
    require('PROBE=' + case['name'] in report['console_output']['stdout'], 'Reporting function did not run')
    if case.get('native_arguments') is not None:
        require(any(c.get('capture') == 'external_linux_ptrace' and c.get('command') == 'echo' and
                    c.get('native_arguments') == case['native_arguments'] for c in commands),
                'Missing exact kernel-confirmed native argument array')
    if case.get('utility'):
        expected = case['utility']
        require(any(c.get('capture') == 'guest_windows_emulation' and c['command'] == expected['command'] and
                    c['unbound_arguments'] == expected['arguments'] and c['persona_matches_baseline']
                    for c in commands), 'Missing decoded persona utility arguments')
    if case.get('forbidden_case'):
        require(not any(c.get('bound_parameters', {}).get('Case') == case['forbidden_case'] for c in commands),
                'Unexecuted decoy incorrectly reported as invoked')
    if case.get('forbidden_output'):
        require(case['forbidden_output'] not in report['console_output']['stdout'], 'Snapshot invoked a custom getter')
    client = create_app(run.parent).test_client()
    pages = []
    for page in range(1, max(1, (len(commands) + 99) // 100) + 1):
        response = client.get(f'/runs/{run.name}?commands_page={page}')
        require(response.status_code == 200, 'Dashboard page unavailable')
        markup = response.get_data(as_text=True)
        section = markup.split('id="commands"', 1)[-1].split('id="coverage"', 1)[0]
        pages.append(html.unescape(section))
    rendered = '\n'.join(pages)
    for value in (expected_command, case['name'], 'readable café 日本語 😀', 'space value'):
        require(value in rendered, 'Dashboard missing readable value: ' + value)
    require(r'\u00e9' not in rendered and r'\ud83d' not in rendered, 'Dashboard escaped Unicode values')
    return failures, matches


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--case', action='append', dest='selected')
    args = parser.parse_args()
    selected = [case for case in cases() if not args.selected or case['name'] in args.selected]
    if not selected or args.selected and set(args.selected) - {case['name'] for case in selected}:
        parser.error('Unknown case name')
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    results = []
    for case in selected:
        source = output / (case['name'] + '.ps1')
        source.write_text(case['source'], encoding='utf-8', newline='\n')
        report = run_script(source, ROOT / 'output/powershell-exec-observer/observer',
                            ROOT / 'output/powershell-instrumented-engine/System.Management.Automation.dll',
                            guest_tools_build=ROOT / 'output/powershell-guest-tools/build.json', timeout=120)
        run = save_script_run(report, ROOT / 'output/powershell-dashboard-probe')
        failures, matches = check(report, case, run)
        result = {'case': case['name'], 'passed': not failures, 'failures': failures,
                  'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(), 'run': str(run),
                  'expected_parameters': case['expected'], 'matching_invocations': len(matches),
                  'commands': len(report['command_events']), 'console': report['console_output']}
        results.append(result)
        (output / 'progress.json').write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding='utf-8')
        print(json.dumps({'case': case['name'], 'passed': result['passed'], 'failures': failures, 'run': str(run)}), flush=True)
    passed = all(result['passed'] for result in results)
    (output / 'verification.json').write_text(json.dumps({'passed': passed, 'cases': results}, ensure_ascii=False, indent=2), encoding='utf-8')
    raise SystemExit(0 if passed else 1)


if __name__ == '__main__':
    main()
