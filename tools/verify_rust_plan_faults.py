"""Exclusive packaged closed-plan fault controls; generated recipes only.

Requires this build's completed base plan controls. Each worker fault is fixed by
compiled enum/request recipe. No real input paths, private-fixture disclosure,
network destinations or general sample admission. Controller-crash cases must run
exclusively so another controller cannot consume the abandoned cleanup intent.
"""
import argparse
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

REPO = next(p for p in Path(__file__).resolve().parents
            if (p / 'tools/check_residual_appcontainer.ps1').is_file())
sys.path.insert(0, str(REPO / 'tools'))
from verify_rust_analysis_reports import require, write, snapshot


def digest(path):
    return hashlib.sha256(regular_bytes(path)).hexdigest()


def strict_json(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, 'Duplicate JSON key in retained evidence: ' + key)
            value[key] = item
        return value
    def constant(value):
        raise ValueError('Nonfinite JSON value in retained evidence: ' + value)
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def regular_bytes(path, bound=128 * 1024 * 1024):
    ordinary_directory_chain(path.parent)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            and not getattr(info, 'st_file_attributes', 0) & 0x400,
            'Retained evidence must be an ordinary single-link file: ' + str(path))
    require(info.st_size <= bound, 'Retained evidence byte bound: ' + str(path))
    raw = path.read_bytes()
    require(len(raw) == info.st_size, 'Retained evidence changed while reading: ' + str(path))
    return raw


def read(path):
    return strict_json(regular_bytes(path))


def present(path):
    # exists() follows links: a dangling reparse sidecar is still a boundary,
    # never an absent output that may be replaced by a new command receipt.
    return os.path.lexists(path)


def ordinary_directory_chain(path):
    for part in reversed([path, *path.parents]):
        info = part.lstat()
        require(stat.S_ISDIR(info.st_mode)
                and not getattr(info, 'st_file_attributes', 0) & 0x400,
                'Evidence directory ancestor is a reparse/type boundary: ' + str(part))


def inherited_acl_authority(recovery_root, receipt):
    """Read preserved controller assertions; does not recreate an original SDDL."""
    ordinary_directory_chain(recovery_root)
    names = ('verification.json', 'next-controller-crash/manifest.json',
             'controller-crash-repeat.json', 'controller-partial-recovery.json',
             'controller-partial-repeat.json')
    raw = {name: regular_bytes(recovery_root / name, 32 * 1024 * 1024) for name in names}
    gates = strict_json(raw['verification.json'])
    manifest = strict_json(raw['next-controller-crash/manifest.json'])
    require(all(manifest[k] == receipt[k] for k in
                ('source_tree_sha256', 'controller_sha256', 'worker_sha256')),
            'Inherited ACL recovery assertions belong to another frozen package')
    require(manifest['cleanup'] == 'restored' and manifest['result']['execution']['guest_entry_return'] == 10,
            'Inherited recovery successor lacks actual guest execution/cleanup authority')
    require(isinstance(gates, list) and len(gates) == 2
            and [g['case'] for g in gates] == ['controller-crash', 'controller-partial'],
            'Both historical controller-recovery assertions required')
    for gate in gates:
        require(all(gate.get(k) is True for k in
                    ('verified', 'original_bundle_dacl_restored', 'broker_journal_unchanged',
                     'worker_cleanup_plan_read_denied', 'broker_cleanup_plan_read_denied',
                     'old_run_unqualified')) and type(gate['owned_processes_remaining']) is int
                and gate['owned_processes_remaining'] == 0,
                'Historical controller recovery did not prove restoration/cleanup')
        actual = gate['recovery']
        require(actual.get('recovered') is True and actual.get('already_complete') is False
                and all(type(actual[k]) is int and actual[k] == n
                        for k, n in (('profiles', 2), ('jobs', 2), ('grants', 12)))
                and actual.get('partial_tail') is (gate['case'] == 'controller-partial'),
                'Historical controller-recovery authority/counts differ')
        if gate['case'] == 'controller-crash':
            require(actual == manifest['controller_recovery'], 'Historical successor recovery differs')
        else:
            require(actual == strict_json(raw['controller-partial-recovery.json']),
                    'Historical torn-intent recovery receipt differs')
        repeat = strict_json(raw[gate['case'] + '-repeat.json'])
        require(repeat.get('recovered') is False
                and all(type(repeat[k]) is int and repeat[k] == 0
                        for k in ('profiles', 'jobs', 'grants')),
                'Historical recovery was not idempotent')
    return dict(schema='inherited_controller_acl_assertions.v1',
                historical_original_sddl_available=False,
                historical_comparison='Original verifier assertion only; original SDDL bytes were not persisted',
                recovery_root=str(recovery_root),
                package_binding={k: receipt[k] for k in
                    ('source_tree_sha256', 'controller_sha256', 'worker_sha256')},
                receipts={name: dict(size=len(value), sha256=hashlib.sha256(value).hexdigest())
                          for name, value in raw.items()})


def retained_call(root, name, command):
    """Completed command receipt only; partial receipts are terminal, not retries."""
    prefix = root / name
    suffixes = ('.command.json', '.exit.json', '.stdout.bin', '.stderr.bin')
    paths = [Path(str(prefix) + suffix) for suffix in suffixes]
    found = [present(p) for p in paths]
    if not any(found):
        return None
    require(all(found), name + ': incomplete retained command receipt; no relaunch permitted')
    require(strict_json(regular_bytes(paths[0], 64 * 1024)) == [str(x) for x in command],
            name + ': retained command/path/role differs')
    exit_info = strict_json(regular_bytes(paths[1], 4096))
    require(set(exit_info) == {'exit_code', 'timeout'}
            and exit_info['timeout'] is False and type(exit_info['exit_code']) is int,
            name + ': incomplete/timed-out command is terminal; no relaunch permitted')
    return subprocess.CompletedProcess([str(x) for x in command], exit_info['exit_code'],
                                       regular_bytes(paths[2]), regular_bytes(paths[3]))


def tree_identity(root):
    """Bounded owned tree identity including empty directories, without reparse traversal."""
    files, directories, pending = {}, [], [root]
    total = 0
    while pending:
        directory = pending.pop()
        info = directory.lstat()
        require(stat.S_ISDIR(info.st_mode) and not getattr(info, 'st_file_attributes', 0) & 0x400,
                'Owned evidence directory is a reparse/type boundary: ' + str(directory))
        for path in directory.iterdir():
            relative = path.relative_to(root).as_posix()
            info = path.lstat()
            require(not getattr(info, 'st_file_attributes', 0) & 0x400,
                    'Owned evidence reparse boundary: ' + str(path))
            if stat.S_ISDIR(info.st_mode):
                directories.append(relative); pending.append(path)
            else:
                require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
                        'Owned evidence is not an ordinary single-link file: ' + str(path))
                total += info.st_size
                require(total <= 1536 * 1024 * 1024 and info.st_size <= 128 * 1024 * 1024,
                        'Owned evidence exceeds compiled bounds')
                h = hashlib.sha256()
                with path.open('rb') as stream:
                    for block in iter(lambda: stream.read(65536), b''): h.update(block)
                files[relative] = dict(size=info.st_size, sha256=h.hexdigest())
            require(len(files) + len(directories) <= 22000, 'Owned evidence entry bound')
    return dict(files=files, directories=sorted(directories))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--output-root', type=Path, required=True)
    parser.add_argument('--plan-root', type=Path, required=True)
    parser.add_argument('--recovery-root', type=Path,
                        help='Required for legacy resume with no persisted original SDDL')
    parser.add_argument('--resume', action='store_true',
                        help='Reverify complete retained phases; never relaunch an existing run')
    args = parser.parse_args()
    bundle = args.bundle.resolve(strict=True)
    root = args.output_root.absolute()
    base = args.plan_root.resolve(strict=True)
    require(root != bundle and root not in bundle.parents and bundle not in root.parents,
            'Evidence outside bundle required')
    ordinary_directory_chain(root if args.resume else root.parent)
    require(root.is_dir() if args.resume else not present(root),
            'Resume requires an existing evidence root; ordinary mode requires a fresh root')
    receipt = read(bundle / 'rust-worker-build.json')
    gates = read(base / 'verification.json')
    base_manifest = read(base / 'x64-native-a/manifest.json')
    require(gates['verified'] and gates['count'] == 32,
            'Completed base plan installation controls required')
    require(all(base_manifest[k] == receipt[k] for k in
                ('source_tree_sha256', 'controller_sha256', 'worker_sha256')),
            'Base controls belong to another source/package')
    corpus_raw = (REPO / 'rust/emumee-core/tests/data/plan_fault_reference.json').read_bytes()
    require(hashlib.sha256(corpus_raw).hexdigest() == '908d50bbd78a24921fa37b8a5b62e25588429054c33e8bbc555bb0e448f9708a', 'Fixed fault metadata corpus changed')
    prior_status = None
    if args.resume:
        prior_status = strict_json(regular_bytes(root / 'verification.json', 1024 * 1024))
        require(prior_status['schema'] == 1 and prior_status['verified'] is False
                and prior_status['expected_count'] == 32
                and prior_status['source_tree_sha256'] == receipt['source_tree_sha256']
                and prior_status['count'] == len(prior_status['records']),
                'Resume state is complete, inconsistent or from another build')
        expected_names = []
        for architecture in ('x86', 'x64'):
            expected_names += [architecture + '-' + fault for fault in
                ('crash-after-checkpoint', 'timeout-after-checkpoint', 'broker-death',
                 'broker-partial', 'reconfigure', 'guest-timeout', 'output-directories',
                 'controller-exit', 'controller-partial')]
        expected_names += ['checkpoint-engine', 'checkpoint-payload', 'checkpoint-provenance',
                          'checkpoint-receipt', 'checkpoint-lifecycle', 'checkpoint-final-completed',
                          'broker-journal-tail', 'broker-journal-start',
                          'broker-isolation-witness', 'broker-session-closed',
                          'broker-evidence-completed', 'request-fault', 'missing-quota-evidence',
                          'general-run-disabled']
        require([r['name'] for r in prior_status['records']] == expected_names[:prior_status['count']]
                and all(r['verified'] is True for r in prior_status['records']),
                'Resume records are not a verified, ordered control prefix')
        missing_run = False
        for name in expected_names[:18]:
            architecture, fault = name.split('-', 1)
            command = [bundle / 'emumee-rs.exe', 'plan-fault', fault, root / name, architecture]
            saved = retained_call(root, name, command)
            exists = present(root / name)
            require(not exists or saved is not None,
                    name + ': an existing run lacks a complete receipt; terminal before any relaunch')
            if saved is not None:
                require(exists and not missing_run,
                        name + ': retained runs are not a complete sequential prefix')
                require(saved.returncode == (27 if fault.startswith('controller-') else 0),
                        name + ': previously failed launch is terminal, not retried')
                tree_identity(root / name)
            else:
                missing_run = True
            if fault == 'controller-exit':
                next_name = name + '-next'
                next_root = root / (name + '-next-native-b')
                next_command = [bundle / 'emumee-rs.exe', 'plan-fixture', 'native-b', next_root, architecture]
                next_saved = retained_call(root, next_name, next_command)
                require(not present(next_root) or next_saved is not None,
                        name + ': partial recovery launch is terminal, not relaunched')
                require(saved is None or next_saved is not None,
                        name + ': retained controller lacks a completed recovery successor; terminal')
                if next_saved is not None:
                    require(saved is not None and present(next_root) and next_saved.returncode == 0,
                            name + ': recovery launch receipt is failed or orphaned')
                    tree_identity(next_root)
            elif fault == 'controller-partial' and saved is not None:
                recovered = retained_call(root, name + '-recover', [bundle / 'emumee-rs.exe', 'recover-bundle'])
                require(recovered is not None and recovered.returncode == 0,
                        name + ': retained controller lacks completed torn-intent recovery; terminal')
        # Keep all prior reports/command sidecars and the original state bytes.
        audit = next((root / ('resume-' + str(i).zfill(4)) for i in range(1, 1000)
                      if not present(root / ('resume-' + str(i).zfill(4)))), None)
        require(audit is not None, 'Resume audit generation bound')
        audit.mkdir()
        (audit / 'prior-verification.json').write_bytes(regular_bytes(root / 'verification.json'))
        write(audit / 'retained-evidence-before.json', tree_identity(root))
    else:
        root.mkdir()
        audit = root
    exe = bundle / 'emumee-rs.exe'
    powershell = shutil.which('pwsh') or shutil.which('powershell')
    require(powershell, 'PowerShell required for owned ACL/process/residual checks')
    acl_script = audit / 'owned-acl.ps1'
    acl_script.write_text("param([string]$Path)\n$ErrorActionPreference='Stop'\n(Get-Acl -LiteralPath $Path).Sddl\n", encoding='ascii')
    pid_script = audit / 'owned-pids.ps1'
    pid_script.write_text("param([string]$Worker,[string]$Ids)\n$ErrorActionPreference='Stop'\n$owned=@($Ids.Split(',')|ForEach-Object{[uint32]$_})\n$remaining=@(Get-CimInstance Win32_Process|Where-Object{$_.ProcessId -in $owned -and $_.ExecutablePath -eq $Worker})\nWrite-Output $remaining.Count\n", encoding='ascii')
    records = []
    status = dict(schema=1, verified=False, count=0, expected_count=32,
                  records=records, source_tree_sha256=receipt['source_tree_sha256'],
                  scope='Fixed generated plan fault/recovery proof; no general run/full-tool/unpacking claim')
    pending_recovery = False
    reused_calls = []

    def call(command, name, timeout=100):
        role = str(command[1]) if len(command) > 1 else ''
        readonly = role not in ('plan-fault', 'plan-fixture', 'recover-bundle')
        if args.resume and not readonly:
            saved = retained_call(root, name, command)
            if saved is not None:
                reused_calls.append(name)
                return saved
            if role in ('plan-fault', 'plan-fixture'):
                require(not present(Path(command[3])),
                        name + ': run exists without a complete command receipt; terminal, no relaunch')
        prefix = (audit if args.resume and readonly else root) / name
        require(not any(present(Path(str(prefix) + suffix)) for suffix in
                        ('.command.json', '.exit.json', '.stdout.bin', '.stderr.bin')),
                name + ': refusing to overwrite prior command evidence')
        write(Path(str(prefix) + '.command.json'), [str(x) for x in command])
        try:
            result = subprocess.run([str(x) for x in command], capture_output=True,
                                    timeout=timeout, check=False)
        except subprocess.TimeoutExpired as error:
            Path(str(prefix) + '.stdout.bin').write_bytes(error.stdout or b'')
            Path(str(prefix) + '.stderr.bin').write_bytes(error.stderr or b'')
            write(Path(str(prefix) + '.exit.json'), dict(exit_code=None, timeout=True))
            raise
        Path(str(prefix) + '.stdout.bin').write_bytes(result.stdout)
        Path(str(prefix) + '.stderr.bin').write_bytes(result.stderr)
        write(Path(str(prefix) + '.exit.json'), dict(exit_code=result.returncode, timeout=False))
        return result

    def acl():
        result = subprocess.run([powershell, '-NoProfile', '-NonInteractive', '-File',
                                 str(acl_script), str(bundle)], capture_output=True, check=False)
        require(result.returncode == 0, 'DACL read failed')
        return result.stdout

    def record(value):
        if prior_status is not None:
            old = next((r for r in prior_status['records'] if r['name'] == value['name']), None)
            if old is not None:
                value['resume_readonly_reverified'] = True
                require(all(value.get(k) == v for k, v in old.items()),
                        value['name'] + ': prior verified authority changed during resume')
        records.append(value)
        status['count'] = len(records)
        status['reused_command_phases'] = reused_calls
        write(root / 'verification.json', status)

    def assert_dead(run, name):
        ready = read(run / 'controller-ready.json')
        result = call([powershell, '-NoProfile', '-NonInteractive', '-File', pid_script,
                       bundle / 'emumee-worker.exe',
                       str(ready['worker_pid']) + ',' + str(ready['broker_pid'])], name)
        require(result.returncode == 0 and int(result.stdout.strip()) == 0,
                'Owned children survived controller recovery')

    def apply_mutation(target, mutation):
        if mutation == 'checkpoint-engine':
            f = target / 'worker/engine-report.json'; f.write_bytes(f.read_bytes() + b' ')
        elif mutation == 'checkpoint-payload':
            summary = read(target / 'worker/worker-summary.json')
            f = target / 'worker/artifacts' / summary['artifacts'][0]['file']
            f.write_bytes(b'FAKE')
        elif mutation == 'checkpoint-provenance':
            f = target / 'worker/artifacts/manifest.json'; value = read(f)
            value[0]['source'] = 'forged'; write(f, value)
        elif mutation == 'checkpoint-receipt':
            f = target / 'worker/plan-checkpoint.json'; value = read(f)
            value['engine_sha256'] = '0' * 64; write(f, value)
        elif mutation == 'checkpoint-lifecycle':
            f = target / 'broker-session.json'; value = read(f)
            value.update(reason='exited', worker_exit=0, boundary_qualified=True)
            write(f, value)
        elif mutation == 'checkpoint-final-completed':
            f = target / 'summary.json'; value = read(f)
            value.update(status='completed', artifact_checkpoint_recovered=False)
            write(f, value)
        elif mutation == 'broker-journal-tail':
            f = target / 'private/network-broker.journal'; f.write_bytes(f.read_bytes() + b'changed')
        elif mutation == 'broker-journal-start':
            f = target / 'private/network-broker.journal'
            f.write_bytes(f.read_bytes().replace(b'closed_plan_broker', b'changed_plan_broker', 1))
        elif mutation == 'broker-isolation-witness':
            f = target / 'broker/broker-ready.json'; value = read(f)
            value['persona_read_denied'] = False; write(f, value)
        elif mutation == 'broker-session-closed':
            f = target / 'broker-session.json'; value = read(f)
            value['journal']['closed'] = True; write(f, value)
        elif mutation == 'broker-evidence-completed':
            f = target / 'plan-fault-evidence.json'; value = read(f)
            value.update(analysis_completed=True, status='completed', instruction_count=0)
            write(f, value)
        elif mutation == 'request-fault':
            f = target / 'control/request.json'; value = read(f)
            value['fault'] = 'user-hook'; write(f, value)
        else:
            # These are copied, compiler-owned empty directories only. Preserve
            # every original evidence directory/file; do not follow any link.
            for d in (target / 'worker').glob('owned-dir-*'):
                require(d.parent == target / 'worker' and d.is_dir()
                        and not d.is_symlink() and not list(d.iterdir()),
                        'Only owned copied empty quota directories may be removed')
                d.rmdir()

    initial_bundle = snapshot(bundle)
    initial_acl = acl()
    if args.resume:
        require(initial_bundle == strict_json(regular_bytes(root / 'bundle-before.json', 1024 * 1024)),
                'Frozen package differs from original pre-run snapshot')
        historical_acl = root / 'bundle-before.sddl.bin'
        if present(historical_acl):
            require(regular_bytes(historical_acl, 65536) == initial_acl,
                    'Resume bundle ACL differs from the persisted original SDDL')
            status['acl_baseline_authority'] = 'original_run_persisted_sddl'
        else:
            # Old verifier versions retained exact-restore assertions in their
            # completed records but omitted the baseline bytes. Do not pretend
            # that an original byte receipt exists; retain the inherited scope.
            require(prior_status['count'] >= 7 and args.recovery_root is not None,
                    'Legacy resume requires seven original cleanup controls and --recovery-root')
            authority = inherited_acl_authority(args.recovery_root.absolute(), receipt)
            for name, binding in authority['receipts'].items():
                original = args.recovery_root.absolute() / name
                value = regular_bytes(original, 32 * 1024 * 1024)
                require(len(value) == binding['size']
                        and hashlib.sha256(value).hexdigest() == binding['sha256'],
                        'Inherited recovery receipt changed during audit preservation')
                target = audit / 'inherited-recovery' / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(value)
            write(audit / 'inherited-acl-authority.json', authority)
            status['acl_baseline_authority'] = authority['schema']
            status['historical_original_sddl_available'] = False
            status['inherited_acl_authority_sha256'] = digest(audit / 'inherited-acl-authority.json')
        (audit / 'resume-start.sddl.bin').write_bytes(initial_acl)
        write(audit / 'bundle-rechecked.json', initial_bundle)
        status['resume'] = dict(prior_count=prior_status['count'], audit=str(audit),
                               original_evidence_preserved=True, no_existing_run_relaunched=True)
    else:
        write(root / 'bundle-before.json', initial_bundle)
        (root / 'bundle-before.sddl.bin').write_bytes(initial_acl)
        status['acl_baseline_authority'] = 'original_run_persisted_sddl'
    write(root / 'verification.json', status)
    try:
        for arch in ('x86', 'x64'):
            for fault in ('crash-after-checkpoint', 'timeout-after-checkpoint',
                          'broker-death', 'broker-partial', 'reconfigure',
                          'guest-timeout', 'output-directories'):
                name = arch + '-' + fault
                run = root / name
                result = call([exe, 'plan-fault', fault, run, arch], name)
                require(result.returncode == 0, name + ': expected fixed fault did not qualify')
                proof = read(run / 'plan-fault-verification.json')
                require(strict_json(result.stdout) == proof,
                        name + ': retained launch stdout does not bind actual delivered proof')
                session = read(run / 'broker-session.json')
                broker_ready = read(run / 'broker/broker-ready.json')
                require(broker_ready['target_read_denied'] and broker_ready['persona_read_denied']
                        and broker_ready['cleanup_plan_read_denied'],
                        name + ': broker access to worker target/persona or cleanup intent')
                require(proof['verified'] and proof['analysis_completed'] is False
                        and session['qualified'] is False and session['cleanup'] == 'restored',
                        name + ': fault promoted completion or cleanup missing')
                journal_before = digest(run / 'private/network-broker.journal')
                if fault.endswith('after-checkpoint'):
                    expected = 'timeout' if fault.startswith('timeout') else 'failed'
                    summary = read(run / 'summary.json')
                    draft = read(run / 'worker/worker-summary.json')
                    require(summary['status'] == expected and draft['status'] == 'completed'
                            and summary['artifact_checkpoint_recovered'] is True
                            and proof['checkpoint_recovered'] is True,
                            name + ': failed lifecycle promoted draft completion')
                    require(not (run / 'worker/plan-result.json').exists()
                            and (run / 'worker/plan-checkpoint.json').is_file(),
                            name + ': final receipt exists after checkpoint failure')
                    require(summary['guest_entry_return'] == int.from_bytes(b'RUST', 'little')
                            and summary['instruction_count'] > 0,
                            name + ': actual settled guest evidence lost')
                    require(len(summary['artifacts']) == 1, name + ': checkpoint payload count')
                    artifact = summary['artifacts'][0]
                    require((run / 'artifacts' / artifact['file']).read_bytes() == b'RUST'
                            and artifact['sha256'] == hashlib.sha256(b'RUST').hexdigest()
                            and artifact['source'] == 'configured_file_changed_at_stop'
                            and artifact['guest_path'].lower() ==
                            r'C:\Users\Alex\Downloads\fault-checkpoint.bin'.lower(),
                            name + ': actual checkpoint full hash/source/path differs')
                    require(proof['broker_complete'] is True and session['journal']['closed'],
                            name + ': already-closed real broker lost independent authority')
                    standard = call([exe, 'inspect-report', run, '--verify-artifacts'], name + '-report')
                    require(standard.returncode == 0, name + ': recovered report invalid')
                elif fault in ('guest-timeout', 'reconfigure'):
                    summary = read(run / 'summary.json')
                    engine = read(run / 'engine-report.json')['execution']
                    require(summary['status'] == ('timeout' if fault == 'guest-timeout' else 'partial')
                            and engine['guest_entry_return'] is None,
                            name + ': guest stop promoted completion')
                    if fault == 'guest-timeout':
                        require(engine['completion_reason'] == 'timeout'
                                and 0 < engine['instruction_count'] < 1000000000,
                                name + ': actual timeout not observed')
                    else:
                        guard = engine['closed_plan_fault']
                        require(engine['instruction_count'] == 1 and guard['refused']
                                and guard['configuration_unchanged']
                                and guard['before'] == guard['after'] == engine['configuration'],
                                name + ': real publication guard not exercised atomically')
                else:
                    evidence = read(run / 'plan-fault-evidence.json')
                    require(evidence == proof and evidence['status'] == 'failed'
                            and evidence['guest_entry_return'] is None
                            and evidence['instruction_count'] is None
                            and evidence['instruction_count_available'] is False
                            and evidence['broker_complete'] is False,
                            name + ': unknown guest execution was fabricated')
                    require(not (run / 'summary.json').exists()
                            and not (run / 'worker/worker-summary.json').exists(),
                            name + ': pre-checkpoint failure acquired a summary')
                    require(evidence['journal_sha256'] == journal_before,
                            name + ': parent failed to bind actual private journal')
                    if fault.startswith('broker-'):
                        require(evidence['broker_attempts'] == 1
                                and (evidence['journal_unrecovered_bytes'] > 0)
                                == (fault == 'broker-partial'), name + ': partial broker authority differs')
                    else:
                        require('output exceeds directories limit' in session['reason']
                                and evidence['broker_attempts'] == 0,
                                name + ': selected real output watchdog did not fire')
                before = snapshot(run)
                inspect = call([exe, 'inspect-plan-fault', run], name + '-inspect')
                require(inspect.returncode == 0 and snapshot(run) == before
                        and digest(run / 'private/network-broker.journal') == journal_before,
                        name + ': read-only fault inspection failed/mutated journal')
                ordinary = call([exe, 'inspect-plan-proof', run], name + '-not-normal-proof')
                require(ordinary.returncode != 0 and b'Normal/fault role identity changed' in ordinary.stderr,
                        name + ': expected ordinary/fault role refusal missing')
                require(acl() == initial_acl, name + ': bundle ACL was not restored exactly')
                record(dict(kind='executed-fixed-fault', name=name, verified=True,
                            journal_sha256=journal_before, analysis_completed=False))

            for fault in ('controller-exit', 'controller-partial'):
                name = arch + '-' + fault
                run = root / name
                result = call([exe, 'plan-fault', fault, run, arch], name)
                require(result.returncode == 27, name + ': fixed controller hard exit not reached')
                pending_recovery = name not in reused_calls
                worker = read(run / 'worker/worker-ready.json')
                server = read(run / 'broker/broker-ready.json')
                require(worker['cleanup_plan_read_denied'] and worker['private_fixture_denied']
                        and worker['private_journal_denied'] and server['cleanup_plan_read_denied']
                        and server['target_read_denied'] and server['persona_read_denied'],
                        name + ': contained role could inspect private authority')
                journal_before = digest(run / 'private/network-broker.journal')
                if fault == 'controller-exit':
                    next_run = root / (name + '-next-native-b')
                    result = call([exe, 'plan-fixture', 'native-b', next_run, arch], name + '-next')
                    require(result.returncode == 0
                            and read(next_run / 'summary.json')['guest_entry_return'] == 625565019,
                            name + ': next actual staged guest did not execute after automatic recovery')
                    require(strict_json(result.stdout) == read(next_run / 'plan-verification.json'),
                            name + ': retained next-run stdout/proof differs')
                    if args.resume:
                        inspected_next = call([exe, 'inspect-plan-proof', next_run], name + '-next-proof')
                        require(inspected_next.returncode == 0
                                and strict_json(inspected_next.stdout) == read(next_run / 'plan-verification.json'),
                                name + ': actual retained recovery launch failed independent read-only verification')
                    recovery = read(next_run / 'broker-session.json')['controller_recovery']
                else:
                    result = call([exe, 'recover-bundle'], name + '-recover')
                    require(result.returncode == 0, name + ': explicit torn-intent recovery failed')
                    recovery = strict_json(result.stdout)
                require(recovery['recovered'] and recovery['profiles'] == 2
                        and recovery['jobs'] == 2 and recovery['grants'] == 15
                        and recovery['partial_tail'] == (fault == 'controller-partial'),
                        name + ': persisted recovery authority/counts differ')
                pending_recovery = False
                inspected = call([exe, 'inspect-broker-journal', run / 'private/network-broker.journal'], name + '-journal')
                require(inspected.returncode == 1 and inspected.stderr == b'',
                        name + ': unclosed journal must return1 with strict recovered JSON and no stderr')
                actual_journal = strict_json(inspected.stdout)
                if args.resume:
                    previous_journal = retained_call(root, name + '-journal',
                        [exe, 'inspect-broker-journal', run / 'private/network-broker.journal'])
                    if previous_journal is not None:
                        require(previous_journal.returncode == 1 and previous_journal.stderr == b''
                                and strict_json(previous_journal.stdout) == actual_journal,
                                name + ': retained pre-resume journal authority changed')
                request = read(run / 'control/request.json')
                config = read(run / 'control/config.json')
                require(actual_journal['source_sha256'] == journal_before
                        and actual_journal['closed'] is False
                        and actual_journal['stop_reason'] == 'missing_close_marker'
                        and actual_journal['source_bytes'] == (run / 'private/network-broker.journal').stat().st_size
                        and actual_journal['valid_bytes'] == actual_journal['source_bytes']
                        and actual_journal['valid_prefix_sha256'] == journal_before
                        and actual_journal['unrecovered_bytes'] == 0
                        and len(actual_journal['events']) == 1
                        and actual_journal['events'][0] == dict(
                            event='broker_started', mode='offline_replay', role='closed_plan_broker',
                            config_sha256=digest(run / 'control/config.json'),
                            request_sha256=digest(run / 'control/request.json'),
                            plan_sha256=request['plan_sha256'], fixture_sha256=request['fixture_sha256'])
                        and config['request_sha256'] == digest(run / 'control/request.json'),
                        name + ': recovered journal invented guest work or changed exact plan/request binding')
                require(acl() == initial_acl and digest(run / 'private/network-broker.journal') == journal_before,
                        name + ': recovery altered journal or original DACL')
                require(not any((run / f).exists() for f in
                                ('summary.json', 'manifest.json', 'plan-fault-verification.json',
                                 'worker/plan-result.json', 'worker/worker-summary.json')),
                        name + ': abandoned analysis was promoted by cleanup')
                assert_dead(run, name + '-owned-pids')
                repeated = call([exe, 'recover-bundle'], name + '-repeat')
                repeated_value = strict_json(repeated.stdout)
                require(repeated.returncode == 0 and not repeated_value['recovered']
                        and all(repeated_value[k] == 0 for k in ('profiles', 'jobs', 'grants')),
                        name + ': completed recovery intent replayed')
                record(dict(kind='controller-recovery', name=name, verified=True,
                            journal_sha256=journal_before, analysis_completed=False,
                            recovery=recovery, owned_processes_remaining=0))

        mutations = ('checkpoint-engine', 'checkpoint-payload', 'checkpoint-provenance',
                     'checkpoint-receipt', 'checkpoint-lifecycle', 'checkpoint-final-completed',
                     'broker-journal-tail', 'broker-journal-start',
                     'broker-isolation-witness', 'broker-session-closed',
                     'broker-evidence-completed', 'request-fault', 'missing-quota-evidence')
        for mutation in mutations:
            case = ('x64-crash-after-checkpoint' if mutation.startswith('checkpoint-')
                    else 'x64-output-directories' if mutation == 'missing-quota-evidence'
                    else 'x64-broker-partial')
            target = root / ('reader-' + mutation)
            source = root / case
            tree_identity(source)
            if present(target):
                require(args.resume, mutation + ': reader evidence already exists')
                expected = audit / ('expected-' + mutation)
                shutil.copytree(source, expected)
                apply_mutation(expected, mutation)
                require(tree_identity(target) == tree_identity(expected),
                        mutation + ': retained reader phase is partial or changed; terminal, no remutation')
            else:
                require(not any(present(Path(str(root / ('reader-' + mutation + '-inspect')) + suffix))
                                for suffix in ('.command.json', '.exit.json', '.stdout.bin', '.stderr.bin')),
                        mutation + ': reader directory missing behind retained command evidence')
                shutil.copytree(source, target)
                apply_mutation(target, mutation)
            before = snapshot(target)
            result = call([exe, 'inspect-plan-fault', target], 'reader-' + mutation + '-inspect')
            require(result.returncode != 0 and snapshot(target) == before,
                    mutation + ': altered fault authority accepted or inspector mutated evidence')
            record(dict(kind='reader-refusal', name=mutation, verified=True,
                        exit_code=result.returncode))

        result = call([exe, 'run', 'compiler-owned-unused.sys'], 'general-gate')
        require(result.returncode != 0 and b'disabled' in result.stderr,
                'General execution gate opened')
        record(dict(kind='gate', name='general-run-disabled', verified=True))
        final_recovery = call([exe, 'recover-bundle'], 'final-recovery')
        recovered = strict_json(final_recovery.stdout)
        require(final_recovery.returncode == 0 and not recovered['recovered']
                and all(recovered[k] == 0 for k in ('profiles', 'jobs', 'grants')),
                'Fixed fault controls left lifecycle resources')
        residual = audit / 'owned-residual.ps1'
        residual.write_text("param([string]$Bundle,[string]$Run,[string]$Tool)\n$ErrorActionPreference='Stop'\n& $Tool -Roots @($Bundle,$Run) -WorkerRoots @($Bundle)\nif($LASTEXITCODE -ne 0){exit 1}\n", encoding='ascii')
        result = call([powershell, '-NoProfile', '-NonInteractive', '-File', residual,
                       bundle, root, REPO / 'tools/check_residual_appcontainer.ps1'], 'residual')
        require(result.returncode == 0 and acl() == initial_acl,
                'Residual worker/profile/grant or bundle ACL drift')
        final_bundle = snapshot(bundle)
        if present(root / 'bundle-after.json'):
            require(args.resume and strict_json(regular_bytes(root / 'bundle-after.json')) == final_bundle, 'Original final bundle snapshot changed')
        else:
            write(root / 'bundle-after.json', final_bundle)
        require(final_bundle == initial_bundle and len(records) == 32,
                'Frozen package mutated or fault controls incomplete')
        status.update(verified=True, cleanup_idempotent=True, bundle_unchanged=True,
                      residual_check_passed=True, controller_recovery_cases=4)
        write(root / 'verification.json', status)
        print(json.dumps(dict(verified=True, count=len(records), output_root=str(root))))
    except BaseException as error:
        status['error'] = str(error)
        write(root / 'verification.json', status)
        if pending_recovery:
            # Recovery only cleans the owned persisted lifecycle. It never labels
            # the interrupted analysis complete or edits its private journal.
            try:
                result = call([exe, 'recover-bundle'], 'failed-control-owned-recovery')
                status['failure_cleanup_exit_code'] = result.returncode
            except BaseException as cleanup_error:
                status['failure_cleanup_error'] = str(cleanup_error)
            write(root / 'verification.json', status)
        raise


if __name__ == '__main__':
    main()
