"""Compare the frozen heap checks with contained guest heap ownership and liveness."""
import argparse
import ast
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace

from native_pe_m6 import build_gate
from native_pe_semantic_strlen import load, record
from native_pe_semantic_winstrings import template_paths, templates
from native_pe_staging_seal import binding
from native_pe_winstrings_guest import Probe
from native_pe_worklist import atomic_write, contract_key, fingerprint, runtime_snapshot, validate_evidence


ROOT = Path(__file__).resolve().parents[1]
SOURCE = 'src/emumee/heap_checks.py'
MAPPING = '.venv/Lib/site-packages/speakeasy/memmgr.py'
MAPPING_HASH = '785e5edeceb3167098740d94de16da7183670394cbcfdacb6932e6ea0570bfd8'
DECISION = ROOT / 'docs/native-pe/behavior-decisions.json'
REVIEW = ROOT / 'docs/native-pe/heap-checks-qualification.md'
BUDGET, TIMEOUT_US, LAST_ERROR = 10000, 30000000, 0x12345678
OUTPUT = 'semantic-heap-checks'
PROFILE = 'emumee.native-semantic.heap-checks.v1'
EXPORTS = {
    'kernel32': 'HeapValidate',
    'kernelbase': 'HeapValidate',
    'api-ms-win-core-heap-l1-1-0': 'HeapValidate',
    'ntdll': 'RtlSizeHeap',
}
HELPERS = (
    'GetProcessHeap', 'HeapCreate', 'HeapAlloc', 'HeapFree', 'HeapDestroy',
    'VirtualProtect', 'SetLastError', 'GetLastError',
)
SIZES = (33, 48, 4097)
VECTORS = (
    ('live', 'process', 0, 'block'),
    ('live-no-serialize', 'process', 1, 'block'),
    ('whole-heap', 'process', 0, 'null'),
    ('null-heap', 'null', 0, 'block'),
    ('wrong-heap', 'other', 0, 'block'),
    ('other-whole-heap', 'other', 0, 'null'),
    ('unknown-heap', 'unknown', 0, 'block'),
    ('unknown-flags', 'process', 2, 'block'),
    ('interior', 'process', 0, 'interior'),
    ('image', 'process', 0, 'image'),
    ('read-only', 'process', 0, 'block'),
    ('no-access', 'process', 0, 'block'),
    ('restored', 'process', 0, 'block'),
    ('freed', 'process', 0, 'block'),
)


def legacy_handler(inventory):
    raw = (ROOT / SOURCE).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == inventory['sources'][SOURCE]
    assert hashlib.sha256((ROOT / MAPPING).read_bytes()).hexdigest() == MAPPING_HASH
    cls, = [node for node in ast.parse(raw).body
            if isinstance(node, ast.ClassDef) and node.name == 'GuestHeapChecks']
    cls.body = [node for node in cls.body if isinstance(node, ast.FunctionDef)
                and node.name in ('__init__', 'validate', 'size')]
    namespace = {}
    exec(compile(ast.Module(body=[cls], type_ignores=[]), SOURCE, 'exec'), namespace)
    return namespace['GuestHeapChecks']


def legacy_map_size(size):
    # Frozen MemoryManager.mem_map uses 16-byte slots below a page, otherwise
    # get_valid_ranges rounds the mapped extent to complete pages.
    if 0 < size < 4096:
        return size + 16 - size % 16
    return ((size + 4095) // 4096) * 4096


def identity(case):
    return case['module'], case['export'], 'function', case['architecture']


def reference():
    inventory = load(ROOT / 'rust/api-parity/legacy-inventory.json')
    factory = legacy_handler(inventory)
    declarations = {(row['module'], row['export']) for row in inventory['entries']
                    if row['source'] == SOURCE and row['kind'] == 'function'}
    assert declarations == set(EXPORTS.items())
    result = {}
    for width, architecture in ((4, 'x86'), (8, 'x64')):
        invalid = (1 << (8 * width)) - 1
        for module, export in EXPORTS.items():
            for size in SIZES:
                handler = factory()
                heap_ids = dict(process=0x5000, other=0x5008, null=0, unknown=0x5010)
                pointers = dict(block=0x10000, interior=0x10001, image=0x20000, null=0)
                heap = SimpleNamespace(heaps={heap_ids['process'], heap_ids['other']})
                known_block = SimpleNamespace(base=pointers['block'], size=legacy_map_size(size),
                                              tag='api.heap.HeapAlloc', free=False)
                image = SimpleNamespace(base=pointers['image'], size=4096, tag='pe.fixture', free=False)
                emu = SimpleNamespace(
                    api=SimpleNamespace(load_api_handler=lambda _: heap),
                    get_mem_maps=lambda: (known_block, image),
                    get_ptr_size=lambda: width, last_error=LAST_ERROR,
                )
                vectors = []
                for label, handle, flags, pointer in VECTORS:
                    handler.read_guard = lambda *args: label != 'no-access'
                    known_block.free = label == 'freed'
                    callback = handler.validate if export == 'HeapValidate' else handler.size
                    baseline = callback(emu, f'{module}.{export}', None,
                                        [heap_ids[handle], flags, pointers[pointer]])
                    assert emu.last_error == LAST_ERROR
                    expected = baseline
                    if label == 'wrong-heap':
                        expected = 0 if export == 'HeapValidate' else invalid
                    elif export == 'RtlSizeHeap' and baseline != invalid:
                        expected = size
                    vectors.append(dict(label=label, heap=handle, flags=flags, pointer=pointer,
                                        legacy=baseline, expected=expected))
                name = f'{architecture}-{module}-{export}-{size}'
                result[name] = dict(module=module, export=export, width=width,
                                    architecture=architecture, size=size, vectors=vectors)
    assert len(result) == 24
    return result


def program(case, template):
    probe = Probe(case, template, helpers=HELPERS)
    process, other, block, interior, image, old_protect = (
        probe.base + offset for offset in range(0x3400, 0x3430, 8)
    )
    pointers = dict(block=(block,), interior=(interior,), image=image, null=0)
    handles = dict(process=(process,), other=(other,), null=0, unknown=0x5010)
    probe.call(0, [])
    probe.save(process)
    probe.call(1, [0, 0, 0])
    probe.save(other)
    probe.call(2, [(process,), 0, case['size']])
    # Store the base and its interior byte without altering any heap content.
    probe.save(block)
    probe.code += b'\x48\xff\xc0' if probe.wide else b'\x40'
    probe.save(interior)
    protections = {'read-only': 2, 'no-access': 1, 'restored': 4}
    for row in case['vectors']:
        label = row['label']
        if label in protections:
            probe.call(5, [(block,), case['size'], protections[label], old_protect])
            probe.expect(1)
        if label == 'freed':
            probe.call(3, [(process,), 0, (block,)])
            probe.expect(1)
        probe.call(6, [LAST_ERROR])
        probe.call(len(HELPERS), [handles[row['heap']], row['flags'], pointers[row['pointer']]])
        probe.expect(row['expected'], pointer=case['export'] == 'RtlSizeHeap')
        probe.call(7, [])
        probe.expect(LAST_ERROR)
    probe.call(4, [(other,)])
    probe.expect(1)
    return probe.finish()


def check_case(directory, case, header, receipt):
    assert load(directory / 'specification.json') == case
    sample = directory / 'sample.exe'
    assert sample.read_bytes() == program(case, header)
    output = directory / 'run'
    manifest = binding(output, sample)
    assert manifest['bundle_receipt'] == receipt
    assert manifest['source_tree_sha256'] == receipt['source_tree_sha256']
    request = manifest['result']['input_receipt']
    assert request['max_instructions'] == BUDGET and request['timeout_us'] == TIMEOUT_US
    assert request['module_name'] == sample.name and not request['staged'] and not request['arguments']
    execution = manifest['result']['execution']
    assert execution['architecture'] == case['architecture'] and execution['api_events_omitted'] == 0
    assert execution['configuration']['initialized'] and not execution['configuration']['generated_only']
    assert execution['error'] is None and execution['completion_reason'] == 'entry_return'
    assert execution['guest_entry_return'] == 1 and 0 < execution['instruction_count'] <= BUDGET

    events = execution['api_events']

    def event(name):
        match, = [row for row in events if row['api'] == f'kernel32.{name}']
        assert not match['pending'] and match['error'] is None
        return match

    process = event('GetProcessHeap')['result']
    other = event('HeapCreate')['result']
    alloc = event('HeapAlloc')
    base = 0x140000000 if case['width'] == 8 else 0x400000
    block = alloc['result']
    assert process and other and block and process != other
    assert alloc['arguments'] == [process, 0, case['size']]
    assert event('HeapFree')['arguments'] == [process, 0, block]
    assert event('HeapDestroy')['arguments'] == [other]
    protections = [row for row in events if row['api'] == 'kernel32.VirtualProtect']
    assert [row['arguments'][:3] for row in protections] == [
        [block, case['size'], protection] for protection in (2, 1, 4)
    ]
    assert all(row['result'] == 1 and row['error'] is None and not row['pending'] for row in protections)
    handles = dict(process=process, other=other, null=0, unknown=0x5010)
    pointers = dict(block=block, interior=block + 1, image=base + 0x3420, null=0)
    target = f'{case["module"]}.{case["export"]}'
    calls = [row for row in events if row['api'] == target]
    for row, expected in zip(calls, case['vectors'], strict=True):
        assert row['arguments'] == [handles[expected['heap']], expected['flags'], pointers[expected['pointer']]]
        assert row['result'] == expected['expected'] and row['last_error'] == LAST_ERROR, (directory.name, expected, row)
        assert row['error'] is None and not row['pending']
    job = load(output / 'general-job-profile.json')
    assert job['profile'] == 'submitted_user_1024_v1' and job['cleanup'] == 'restored'
    assert job['active_process_limit'] == 1 and job['network_capabilities'] == 0
    assert 0 < job['peak_process_memory_bytes'] <= job['process_memory_bytes'] == 1024**3
    stop = load(output / 'worker-stop.json')
    assert stop['cleanup'] == 'restored' and stop['worker']['reason'] == 'exited' and stop['worker']['exit_code'] == 0
    return dict(case=directory.name, identity=list(identity(case)), vectors=case['vectors'])


def run(root, index):
    build_gate(root, index)
    expected = reference()
    headers = templates(root)
    receipt = load(root / 'bundle/rust-worker-build.json')
    output = root / OUTPUT
    output.mkdir()
    for name, case in expected.items():
        directory = output / name
        directory.mkdir()
        sample = directory / 'sample.exe'
        sample.write_bytes(program(case, headers[case['width']]))
        atomic_write(directory / 'specification.json', json.dumps(case, indent=2) + '\n')
        result = subprocess.run(
            [str(root / 'bundle/emumee-rs.exe'), 'run', str(sample), '--output', str(directory / 'run'),
             '--max-instructions', str(BUDGET), '--timeout-us', str(TIMEOUT_US)],
            capture_output=True, timeout=120,
        )
        (directory / 'stdout').write_bytes(result.stdout)
        (directory / 'stderr').write_bytes(result.stderr)
        assert result.returncode == 0, (name, result.stderr)
        check_case(directory, case, headers[case['width']], receipt)
        print(f'{name} verified', flush=True)


def proof_path(root):
    return root / f'qualified-semantic-heap-checks-{fingerprint(runtime_snapshot(ROOT))}.json'


def seal(root, index, *, check=False):
    build_gate(root, index)
    expected = reference()
    headers = templates(root)
    receipt = load(root / 'bundle/rust-worker-build.json')
    output = root / OUTPUT
    assert {path.name for path in output.iterdir() if path.is_dir()} == set(expected)
    observed = [check_case(output / name, case, headers[case['width']], receipt)
                for name, case in expected.items()]
    identities = sorted({identity(case) for case in expected.values()})
    paths = {ROOT / SOURCE, ROOT / MAPPING, DECISION, REVIEW, *template_paths(root).values()}
    for directory in (root / 'bundle', output):
        paths.update(path for path in directory.rglob('*') if path.is_file())
    document = dict(schema=1, profile=PROFILE, runtime_fingerprint=fingerprint(runtime_snapshot(ROOT)),
                    source_tree_sha256=receipt['source_tree_sha256'],
                    contract_identities=[list(key) for key in identities], controls=observed,
                    artifacts=[record(path) for path in sorted(paths)])
    document['fingerprint'] = fingerprint(document)
    path = proof_path(root)
    if check:
        assert load(path) == document, 'Heap check proof differs'
    else:
        assert not path.exists(), 'Preserve sealed evidence'
        atomic_write(path, json.dumps(document, indent=2) + '\n')
    print(json.dumps(dict(contracts=len(identities), controls=len(observed), fingerprint=document['fingerprint'])))


def publish_evidence(root, index, ledger_path, *, collect_only=False):
    assert collect_only, 'Publish heap checks through the atomic family publisher'
    seal(root, index, check=True)
    ledger = load(ledger_path)
    assert ledger['runtime_source_hashes'] == runtime_snapshot(ROOT)
    policy = load(DECISION)
    groups = defaultdict(list)
    for name, case in reference().items():
        groups[identity(case)].append(name)
    claims = []
    artifacts = [record(path) for path in (proof_path(root), ROOT / SOURCE, ROOT / MAPPING, REVIEW, DECISION)]
    for row in ledger['entries']:
        key = contract_key(row)
        if key not in groups:
            continue
        dispatch = row['rust_dispatch']
        assert dispatch['dispatch'] == 'model' and dispatch['callable'] is True
        assert dispatch['argc'] == 3 and dispatch['convention'] == 'stdcall'
        validate = row['export'] == 'HeapValidate'
        assert dispatch['return_type'] == ('u32' if validate else 'pointer')
        change = 'Reject pointers belonging to another known heap.'
        if not validate:
            change += ' Report requested block size instead of the legacy rounded mapping size.'
        claim = {field: row[field] for field in ('module', 'export', 'kind', 'architecture', 'source_fingerprint')}
        claim.update(
            semantic_status='verified_intentional_change', submitted_route='verified',
            accepted_deviation=dict(decision=policy['decision'], date=policy['date'],
                                    policy=record(DECISION), change=change),
            behavioral_evidence=[dict(
                id=f'heap-check-{row["module"]}-{row["export"]}-{row["architecture"]}-v1',
                architecture=row['architecture'], source_fingerprint=row['source_fingerprint'],
                oracle='Pinned frozen callbacks, legacy mapping extents and reviewed Rust ownership and requested-size behavior',
                baseline=record(ROOT / SOURCE), limits=dict(max_instructions=BUDGET, max_bytes=max(SIZES)),
                tests=groups[key], negative_controls=['Wrong heap', 'Invalid flags', 'Interior pointer',
                                                      'Inaccessible mapping', 'Released block'],
                artifacts=artifacts,
            )],
        )
        validate_evidence(claim)
        claims.append(claim)
    assert {contract_key(claim) for claim in claims} == set(groups) and len(claims) == len(groups) == 8
    return claims


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', required=True, type=Path)
    parser.add_argument('--source-index', required=True, type=Path)
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument('--seal', action='store_true')
    actions.add_argument('--check', action='store_true')
    options = parser.parse_args()
    root, index = options.root.resolve(), options.source_index.resolve()
    if options.seal or options.check:
        seal(root, index, check=options.check)
    else:
        run(root, index)
