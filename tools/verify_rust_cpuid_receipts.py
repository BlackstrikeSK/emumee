"""Verify passive CPUID receipts using closed and submitted generated callers."""
import argparse
import json
from pathlib import Path
import struct
import subprocess

from verify_rust_kernel_loader import build_driver, check, load, sha

SUCCESS = 0x43504931
VENDOR = [0x16, 0x756E6547, 0x6C65746E, 0x49656E69]


def fixture(kind):
    image = bytearray(build_driver(0x8664))
    code, failures = bytearray(b'\x53'), []

    def query(leaf, subleaf):
        code.extend(b'\xb8' + struct.pack('<I', leaf) + b'\xb9' + struct.pack('<I', subleaf) + b'\x0f\xa2')

    def compare(register, value):
        code.extend(bytes([0x81, 0xF8 + register]) + struct.pack('<I', value) + b'\x0f\x85')
        failures.append(len(code)); code.extend(bytes(4))

    if kind == 'cap':
        code.extend(b'\x41\xb9\x41\x00\x00\x00')  # mov r9d,65
        loop = len(code)
        code.extend(b'\x31\xc0\x31\xc9\x0f\xa2\x41\xff\xc9')
        code.extend(b'\x75' + struct.pack('b', loop - len(code) - 2))
    elif kind == 'budget':
        code.extend(b'\x31\xc0\x31\xc9\x0f\xa2')  # CPUID is instruction4
    else:
        query(0, 0)
        for register, value in zip((0, 3, 1, 2), VENDOR):
            compare(register, value)
        query(0xB, 1)
        for register, value in zip((0, 3, 1, 2), (4, 12, 0x201, 0)):
            compare(register, value)
        query(0x16, 0)
        for register, value in zip((0, 3, 1, 2), (2900, 4300, 100, 0)):
            compare(register, value)
    code.extend(b'\xb8' + struct.pack('<I', SUCCESS) + b'\x5b\xc3')
    failed = len(code)
    code.extend(b'\xb8\x0d\x00\x00\xc0\x5b\xc3')
    for offset in failures:
        struct.pack_into('<i', code, offset, failed - offset - 4)
    check(len(code) <= 512, 'Generated CPUID caller exceeds text')
    image[0x200:0x400] = code + bytes(512 - len(code))
    return image


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--resume', action='store_true')
    args = parser.parse_args()
    bundle, root = args.bundle.resolve(), args.root.resolve()
    check(not root.exists() or args.resume, 'Preserve prior controls; fresh root or --resume required')
    root.mkdir(exist_ok=args.resume)
    build = load(bundle / 'rust-worker-build.json')
    for file, key in [('emumee-rs.exe', 'controller_sha256'), ('emumee-worker.exe', 'worker_sha256'), ('unicorn.dll', 'unicorn_sha256')]:
        check(sha(bundle / file) == build[key], 'Frozen binary differs')
    records = []
    for name, arch, kind in [('identity-x86', 'x86', None), ('identity-x64', 'x64', None), ('submitted', 'x64', 'read'), ('cap', 'x64', 'cap'), ('budget', 'x64', 'budget')]:
        run = root / name
        if kind:
            source = root / f'{name}.sys'
            generated = fixture(kind)
            if source.exists():
                check(source.read_bytes() == generated, 'Saved generated input changed')
            else:
                source.write_bytes(generated)
            command = [str(bundle / 'emumee-rs.exe'), 'submitted-driver', str(source), str(run), '--service', 'CpuControl', '--max-instructions', '4' if kind == 'budget' else '10000', '--timeout-us', '30000000']
        else:
            command = [str(bundle / 'emumee-rs.exe'), 'fixture', '--arch', arch, '--kind', 'cpu-identity', '--max-instructions', '10000', '--isolated-output', str(run)]
        if run.exists():
            check(args.resume, 'Existing run requires --resume')
        else:
            with (root / f'{name}.console.log').open('wb') as out:
                process = subprocess.run(command, stdout=out, stderr=subprocess.STDOUT)
            check(process.returncode == 0, 'Generated CPUID control failed to process')
        if kind:
            manifest, result, report = [load(run / p) for p in ('controller-manifest.json', 'worker-result.json', 'engine-report.json')]
            check(manifest['status'] == 'verified' and manifest['guest_status'] == result['status'] == 'processed', 'Submitted verification/status differs')
            check(manifest['worker_result_sha256'] == sha(run / 'worker-result.json') and result['engine_report_sha256'] == sha(run / 'engine-report.json'), 'Submitted result/report binding differs')
            for binding in (manifest, result['binding'], report['binding']):
                check(binding['request_sha256'] == sha(run / 'request.json') and binding['input_sha256'] == sha(source) == sha(run / 'input.sys') and binding['source_tree_sha256'] == build['source_tree_sha256'], 'Submitted input/request/build binding differs')
                check(binding['containment_sha256'] == sha(run / 'worker-containment.json'), 'Submitted witness binding differs')
            witness = load(run / 'worker-containment.json')
            job = load(run / 'driver-job-profile.json')
            check(job['active_process_limit'] == 1 and job['process_memory_bytes'] == 2147483648 and job['network_capabilities'] == 0, 'Submitted job limits differ')
            check(all(load(run / p)['cleanup'] == 'restored' for p in ('driver-job-profile.json', 'worker-stop.json')), 'Submitted cleanup differs')
            check(not manifest['unpacking_confirmed'], 'Generated control mislabeled unpacked')
            e = report['execution']
        else:
            manifest, result = load(run / 'manifest.json'), load(run / 'fixture-result.json')
            check(manifest['request_sha256'] == result['request_sha256'] == sha(run / 'request.json') and manifest['result_sha256'] == sha(run / 'fixture-result.json') and manifest['result'] == result, 'Closed fixture binding differs')
            witness = result['containment']
            e = result['execution']
        for key in ('source_tree_sha256', 'controller_sha256', 'worker_sha256', 'unicorn_sha256'):
            check(manifest[key] == build[key], 'Control used another frozen build')
        check(manifest['cleanup'] == load(run / 'worker-exit.json')['cleanup'] == 'restored' and load(run / 'worker-exit.json')['exit_code'] == 0, 'Worker cleanup/exit differs')
        check(witness['app_container'] and witness['job_object'] and witness['child_process_blocked'] and witness['network_capabilities'] == 0 and e['network']['calls'] == 0, 'Offline containment differs')
        if kind == 'budget':
            check(e['completion_reason'] == 'instruction_budget' and e['instruction_count'] == 4 and e['guest_entry_return'] is None and e['error'] is None, 'Budget prefix invented completion')
        else:
            check(e['completion_reason'] == 'entry_return' and e['guest_entry_return'] == (SUCCESS if kind else 1) and e['error'] is None, 'Actual guest CPUID output assertions failed')
        receipt = e['cpu']['cpuid_receipts']
        count = 65 if kind == 'cap' else 1 if kind == 'budget' else 3 if kind else 5
        check(e['cpu']['cpuid'] == receipt['completed_calls'] == count and receipt['limit'] == 64 and receipt['omitted_calls'] == max(count - 64, 0), 'Completed CPUID count/cap differs')
        rows = receipt['observations']
        check(len(rows) == min(count, 64), 'Receipt count differs')
        expected = [(0, 0), (0xB, 1), (0x16, 0)] if kind == 'read' else [(0, 0)] * min(count, 64) if kind else [(0, 0), (1, 0), (0xB, 1), (0x16, 0), (0x40000000, 0)]
        check([(x['function'], x['subleaf']) for x in rows] == expected, 'Actual CPUID inputs differ')
        for row in rows:
            check(row['processor'] == 0 and row['architecture'] == arch and row['pc'] > 0 and 0 < row['instruction_count'] <= e['instruction_count'], 'CPUID context/position differs')
            if row['function'] == 0:
                check(row['outputs'] == VENDOR, 'Vendor outputs differ')
            elif row['function'] == 0xB:
                check(row['outputs'] == [4, 12, 0x201, 0], 'Topology outputs differ')
            elif row['function'] == 0x16:
                check(row['outputs'] == [2900, 4300, 100, 0], 'Frequency outputs differ')
            elif row['function'] == 1:
                check(row['outputs'][0] == 0xA0653 and row['outputs'][1] == 12 << 16 | 8 << 8, 'Signature/count outputs differ')
            else:
                check(row['outputs'] == [0, 0, 0, 0], 'Unsupported leaf outputs differ')
        records.append({'case': name, 'verified': True, 'source_tree_sha256': build['source_tree_sha256'], 'run': str(run), 'completed_calls': count, 'recorded_calls': len(rows), 'omitted_calls': receipt['omitted_calls'], 'cleanup': 'restored', 'unpacking_confirmed': False})
        (root / 'verification.json').write_text(json.dumps(records, indent=2) + '\n')
    print('Verified 5 harmless CPUID receipt controls; modeled outputs remain unchanged.')


if __name__ == '__main__':
    main()
