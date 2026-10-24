"""Contained owned-CIL Convert controls; never accepts a sample/assembly path.

Run only against a frozen, verified bundle. Each run is preserved under a fresh
root, including exit code, console bytes, hashes and incremental verification.
This verifies a modeled decoding family, not broad CLI or unpacking parity.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def sha(data):
    return hashlib.sha256(data).hexdigest()


def snapshot(root):
    return {str(p.relative_to(root)): {'size': p.stat().st_size, 'sha256': sha(p.read_bytes())}
            for p in sorted(root.rglob('*')) if p.is_file()}


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--bundle', required=True, type=Path)
    parser.add_argument('--output-root', required=True, type=Path)
    args = parser.parse_args()
    bundle = args.bundle.resolve(strict=True)
    exe = bundle / 'emumee-rs.exe'
    require(exe.is_file(), 'Frozen controller is missing')
    root = args.output_root.resolve()
    require(not root.exists(), 'Use a fresh output root')
    require(root != bundle and bundle not in root.parents and root not in bundle.parents,
            'Keep evidence outside bundle')
    root.mkdir(parents=True)
    before = snapshot(bundle)
    write(root / 'bundle-before.json', before)
    records = []
    success = [
        ('bytes', 5, 5, 1, 1, 5, 1), ('whitespace', 5, 5, 1, 1, 5, 1),
        ('empty', 0, 5, 1, 1, 0, 1), ('trailing-bits', 1, 5, 1, 1, 1, 1),
        ('writable', 82, 9, 1, 1, 5, 1), ('identity', 0, 6, 2, 2, 10, 1),
        ('round-trip', 1, 6, 3, 1, 5, 2), ('encode-empty', 1, 6, 3, 1, 0, 2),
        ('file', 17, 6, 2, 1, 5, 2), ('large-encode', 17, 6, 1, 1, 1048576, 1),
    ]
    cases = [dict(case=c, value=v, instructions=i, calls=f, arrays=a, storage=b, strings=s)
             for c, v, i, f, a, b, s in success]
    for case, error, instructions, arrays in [
        ('malformed', 'FormatException', 2, 0), ('padding', 'FormatException', 2, 0),
        ('unicode', 'FormatException', 2, 0), ('surrogate', 'FormatException', 2, 0),
        ('null', 'ArgumentNullException', 2, 0), ('null-bytes', 'ArgumentNullException', 2, 0),
        ('bad-argument', 'argument type mismatch', 2, 0),
        ('wrong-array', 'argument type mismatch', 3, 1),
        ('bad-signature', 'method/signature', 2, 0), ('bad-assembly', 'assembly/type', 2, 0),
        ('bad-version', 'assembly/type', 2, 0), ('bad-namespace', 'namespace', 2, 0),
        ('bad-owner', 'MemberRef owner', 2, 0), ('bad-scope', 'AssemblyRef', 2, 0),
        ('static-virtual', 'static framework method', 2, 0),
    ]:
        cases.append(dict(case=case, error=error, instructions=instructions, arrays=arrays, calls=0, attempts=1))
    cases += [
        dict(case='quota', error='array object limit', instructions=16386, budget=100000,
             arrays=4096, storage=0, strings=1, calls=4096, attempts=4097),
        dict(case='heap-quota', error='string object limit', instructions=262148, budget=400000,
             arrays=1, storage=0, strings=65536, units=0, calls=65536, attempts=65537),
        dict(case='decode-limit', error='array element limit', instructions=156,
             arrays=0, storage=0, strings=20, units=4194300, calls=19, attempts=20),
        dict(case='bytes', name='decode-before-call', budget=1, partial=True, calls=0, arrays=0),
        dict(case='bytes', name='decode-before-return', budget=4, partial=True, calls=1, arrays=1),
        dict(case='file', name='file-before-write', budget=3, partial=True, calls=1, arrays=1),
        dict(case='file', name='file-before-return', budget=5, partial=True, calls=2, arrays=1),
    ]
    expected_count = 2 * len(cases)
    status = dict(schema=1, scope='owned CIL Convert models; no host CLR or sample execution',
                  expected_count=expected_count, count=0, verified=False, records=records)
    write(root / 'verification.json', status)
    try:
        for arch in ('x86', 'x64'):
            for case in cases:
                name = arch + '-' + case.get('name', case['case'])
                run = root / name
                kind = 'managed-convert-' + case['case']
                budget = case.get('budget', 1000)
                command = [str(exe), 'fixture', '--arch', arch, '--kind', kind,
                           '--iterations', '17', '--max-instructions', str(budget),
                           '--isolated-output', str(run)]
                write(root / (name + '.command.json'), command)
                proc = subprocess.run(command, capture_output=True, timeout=90, check=False)
                (root / (name + '.stdout.bin')).write_bytes(proc.stdout)
                (root / (name + '.stderr.bin')).write_bytes(proc.stderr)
                write(root / (name + '.exit.json'), {'exit_code': proc.returncode})
                result = json.loads((run / 'fixture-result.json').read_bytes())
                e = result['execution']
                f = e['framework']
                contain = result['containment']
                require(contain['app_container'] and contain['job_object'] and contain['child_process_blocked']
                        and contain['network_capabilities'] == 0, name + ': containment failed')
                require(e['backend'] == 'rust/managed-il' and e['architecture'] == arch
                        and 'No host CLR' in e['scope'], name + ': backend/scope changed')
                if case.get('partial'):
                    require(proc.returncode == 1 and e['completion_reason'] == 'instruction_budget'
                            and e['instruction_count'] == budget and e['managed_return'] is None
                            and e['guest_entry_return'] is None, name + ': false return on budget')
                elif case.get('error'):
                    require(proc.returncode == 1 and e['completion_reason'] == 'error'
                            and case['error'] in (e['error'] or '') and e['managed_return'] is None
                            and e['guest_entry_return'] is None, name + ': error not explicit')
                else:
                    require(proc.returncode == 0 and e['completion_reason'] == 'entry_return'
                            and e['managed_return'] == {'kind': 'i32', 'value': case['value']}
                            and e['guest_entry_return'] == case['value'], name + ': actual IL result differs')
                if 'instructions' in case:
                    require(e['instruction_count'] == case['instructions'], name + ': instruction count differs')
                for expected, actual in [('arrays', e['arrays']['objects']), ('storage', e['arrays']['storage_bytes']),
                                         ('strings', e['heap']['string_objects']), ('units', e['heap']['utf16_units']),
                                         ('calls', f['completed_calls'])]:
                    if expected in case:
                        require(actual == case[expected], name + ': ' + expected + ' differs')
                require(f['attempts'] == case.get('attempts', case['calls']), name + ': attempts differ')
                require(len(f['events']) <= 128 and len(f['events']) + f['omitted_events'] == f['attempts']
                        and sum(f['counts'].values()) == f['completed_calls'], name + ': framework count bound differs')
                require(sum(e['opcode_counts'].values()) == e['instruction_count']
                        and len(e['instruction_tail']) <= 128, name + ': instruction trace bound differs')
                require(not f['console_output']['utf16'], name + ': unexpected guest console output')
                artifacts = e['artifacts']
                capture = case['case'] == 'file' and not (case.get('partial') and budget < 4)
                require(len(artifacts) == int(capture), name + ': unexpected evidence capture')
                if capture:
                    payload = bytes([0, 255, 128, 77, 90])
                    digest = sha(payload)
                    artifact = artifacts[0]
                    require(artifact['sha256'] == digest and artifact['filename'] == digest + '.bin'
                            and artifact['size'] == 5 and len(artifact['observations']) == 2,
                            name + ': binary capture metadata differs')
                    require((run / 'artifacts' / artifact['filename']).read_bytes() == payload,
                            name + ': binary capture bytes differ')
                    require({o['source'] for o in artifact['observations']} ==
                            {'managed_write_all_bytes', 'managed_virtual_file_at_stop'}
                            and all(o['kind'] == 'guest_file' and o['guest_path'] == 'c:\\convert.bin'
                                    for o in artifact['observations']), name + ': capture provenance differs')
                if case['case'] in ('bytes', 'whitespace', 'writable') and not case.get('partial'):
                    expected = [82 if case['case'] == 'writable' else 0, 255, 128, 77, 90]
                    require([v['value'] for v in e['arrays']['evidence'][0]['preview']] == expected,
                            name + ': actual guest byte[] contents differ')
                if case['case'] == 'writable':
                    require(e['arrays']['element_reads'] == 1 and e['arrays']['element_writes'] == 1,
                            name + ': decoded array not writable through actual CIL')
                if case['case'] == 'identity':
                    values = [event['result']['value']['reference'] for event in f['events']]
                    require(values == [1, 2], name + ': decoded arrays alias unexpectedly')
                if case['case'] == 'large-encode':
                    require(e['heap']['utf16_units'] == 1398104 and e['heap']['strings'][0]['utf16_preview'] == [65]*64,
                            name + ': bounded large encoding differs')
                record = dict(name=name, kind=kind, arch=arch, exit_code=proc.returncode,
                              completion=e['completion_reason'], instructions=e['instruction_count'],
                              result_sha256=sha((run / 'fixture-result.json').read_bytes()),
                              files=snapshot(run), verified=True)
                records.append(record)
                status['count'] = len(records)
                write(root / 'verification.json', status)
        after = snapshot(bundle)
        write(root / 'bundle-after.json', after)
        require(before == after, 'Frozen bundle changed during verification')
        require(len(records) == expected_count, 'Missing controls')
        status['verified'] = True
        write(root / 'verification.json', status)
        print(json.dumps({'verified': True, 'count': len(records), 'output_root': str(root)}))
    except BaseException as error:
        status['error'] = str(error)
        write(root / 'verification.json', status)
        raise


if __name__ == '__main__':
    main()
