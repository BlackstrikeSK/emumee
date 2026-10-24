"""Compare frozen Rust bundles using owned IL fixtures in offline workers."""
import argparse
import json
from pathlib import Path
import statistics
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', action='append', required=True)
    parser.add_argument('--output-root', type=Path, required=True)
    parser.add_argument('--trials', type=int, default=5)
    args = parser.parse_args()
    if not 3 <= args.trials <= 20:
        parser.error('Use 3 to 20 trials.')
    bundles = [Path(p).resolve(strict=True) for p in args.bundle]
    if len({b.name for b in bundles}) != len(bundles):
        parser.error('Bundle names must be distinct.')
    root = args.output_root.resolve()
    root.mkdir(exist_ok=False)
    records = []
    for arch in ('x86', 'x64'):
        for trial in range(1, args.trials + 1):
            order = bundles if trial % 2 else list(reversed(bundles))
            for bundle in order:
                run = root / f'{arch}-{bundle.name}-{trial}'
                with run.with_suffix('.console.log').open('wb') as console:
                    result = subprocess.run([
                        str(bundle / 'emumee-rs.exe'), 'fixture', '--arch', arch,
                        '--kind', 'managed-loop', '--iterations', '1000000',
                        '--max-instructions', '5000000', '--isolated-output', str(run),
                    ], stdout=console, stderr=subprocess.STDOUT, timeout=60, check=False)
                report = json.loads((run / 'fixture-result.json').read_text(encoding='utf-8-sig'))
                execution = report['execution']
                containment = report['containment']
                assert result.returncode == 0, str(run)
                assert all(containment[k] for k in ('app_container', 'job_object', 'child_process_blocked'))
                assert containment['network_capabilities'] == 0
                assert execution['backend'] == 'rust/managed-il'
                assert execution['completion_reason'] == 'entry_return'
                assert execution['instruction_count'] == 4000004
                assert execution['guest_entry_return'] == 1000000
                assert execution['managed_return'] == {'kind': 'i32', 'value': 1000000}
                records.append(dict(arch=arch, bundle=str(bundle), trial=trial,
                                    engine_seconds=execution['engine_seconds'],
                                    instructions=execution['instruction_count'],
                                    return_value=execution['guest_entry_return'], run=str(run)))
    medians = [dict(arch=arch, bundle=str(bundle), engine_seconds=statistics.median(
        r['engine_seconds'] for r in records if r['arch'] == arch and r['bundle'] == str(bundle)))
        for arch in ('x86', 'x64') for bundle in bundles]
    evidence = dict(scope='Alternating packaged offline generated IL loops; verified matching results and counts. No Python or real-driver comparison.',
                    samples=records, medians=medians)
    (root / 'benchmark.json').write_text(json.dumps(evidence, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(medians, indent=2))


if __name__ == '__main__':
    main()
