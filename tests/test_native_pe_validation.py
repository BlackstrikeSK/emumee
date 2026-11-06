"""Source impact and evidence-index regressions; never run a submitted sample."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import native_pe_validation as validation


POLICY = validation.load_policy(ROOT)
ENVIRONMENT = {'python_executable': sys.executable, 'tools': {'rustc': 'synthetic'},
               'test_environment': {'RUST_TEST_THREADS': '1', 'CARGO_BUILD_JOBS': '1'}}


class NativePeValidationTests(unittest.TestCase):
    def test_rust_commands_and_recorded_environment_both_compile_serially(self):
        with patch.object(validation.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, stdout='tool')):
            environment = validation.environment_snapshot()
        self.assertEqual(environment['test_environment']['CARGO_BUILD_JOBS'], '1')
        commands = validation.suite_commands(ROOT, sources={})
        for suite in ('rust-tests', 'rust-lint'):
            command = commands[suite]
            self.assertEqual(command[command.index('-Jobs') + 1], '1')

    def sources(self, *names):
        return {name: 'a' * 64 for name in names}

    def baseline(self, sources):
        return {'source_hashes': sources, 'full_baseline': True,
                'environment': copy.deepcopy(ENVIRONMENT), 'policy_fingerprint': validation.fingerprint(POLICY),
                'index_fingerprint': 'b' * 64}

    def test_initial_missing_and_selected_only_baselines_require_full_suites(self):
        sources = self.sources('rust/emumee-engine/src/lib.rs')
        self.assertEqual(validation.make_plan(sources, ENVIRONMENT, POLICY)['selected_suites'], list(validation.SUITES))
        baseline = self.baseline(sources)
        baseline['full_baseline'] = False
        self.assertEqual(validation.make_plan(sources, ENVIRONMENT, POLICY, baseline)['selected_suites'], list(validation.SUITES))

    def test_unchanged_baseline_selects_nothing_and_explicit_full_overrides(self):
        sources = self.sources('Cargo.toml')
        baseline = self.baseline(sources)
        self.assertEqual(validation.make_plan(sources, ENVIRONMENT, POLICY, baseline)['selected_suites'], [])
        self.assertEqual(validation.make_plan(sources, ENVIRONMENT, POLICY, baseline, full=True)['selected_suites'], list(validation.SUITES))

    def test_changes_additions_deletions_and_unknown_dependencies_select_full(self):
        for relative in ('Cargo.lock', 'rust/emumee-engine/src/user.rs', 'tools/build_rust.ps1',
                         'tools/native_pe_staging.py', 'tools/native_pe_staging_seal.py', 'tools/native_pe_m2.py', 'tests/test_native_pe_staging.py',
                         '.venv/Lib/site-packages/speakeasy/handler.py', 'new-unclassified.fixture'):
            original = self.sources(relative)
            changed = {relative: 'c' * 64}
            for previous, current in ((original, changed), ({}, original), (original, {}), (original, {relative: None})):
                plan = validation.make_plan(current, ENVIRONMENT, POLICY, self.baseline(previous))
                self.assertEqual(plan['selected_suites'], list(validation.SUITES), relative)
                self.assertIn(relative, plan['changed_sources'])

    def test_accounting_and_documentation_have_explicit_safe_selection(self):
        for relative, expected in (
            ('tools/native_pe_status.py', ['partition', 'accounting', 'inventory', 'syntax', 'whitespace']),
            ('tests/test_native_pe_batches.py', ['partition', 'accounting', 'inventory', 'syntax', 'whitespace']),
            ('docs/native-pe/evidence.json', ['partition', 'accounting', 'inventory', 'syntax', 'whitespace']),
            ('docs/native-pe/resume.md', ['whitespace']),
        ):
            plan = validation.make_plan(self.sources(relative), ENVIRONMENT, POLICY, self.baseline({}))
            self.assertEqual(plan['selected_suites'], expected)

    def test_selector_policy_and_toolchain_changes_force_full(self):
        for relative in ('tools/native_pe_validation.py', 'tests/test_native_pe_validation.py', validation.POLICY):
            self.assertEqual(validation.make_plan(self.sources(relative), ENVIRONMENT, POLICY,
                             self.baseline({}))['selected_suites'], list(validation.SUITES))
        baseline = self.baseline({})
        for field, value in (('environment', {}), ('policy_fingerprint', 'changed')):
            changed = {**baseline, field: value}
            self.assertEqual(validation.make_plan({}, ENVIRONMENT, POLICY, changed)['selected_suites'], list(validation.SUITES))

    def test_paths_reject_traversal_absolute_drives_and_escaped_links(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative in ('../outside', '/outside', 'C:/outside', 'some\\path', ''):
                with self.assertRaises(ValueError):
                    validation.local_path(root, relative)
            with patch.object(Path, 'resolve', autospec=True,
                              side_effect=lambda path: root.parent if path.name == 'inside' else path):
                with self.assertRaises(ValueError):
                    validation.local_path(root, 'inside')

    def test_source_snapshot_retains_missing_files_and_hashes_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'source.rs').write_bytes(b'original')
            snapshot = validation.source_snapshot(root, ['source.rs', 'deleted.rs'])
            self.assertIsNone(snapshot['deleted.rs'])
            self.assertEqual(snapshot['source.rs'], validation.file_record(root, 'source.rs')['sha256'])
            (root / 'source.rs').write_bytes(b'changed')
            self.assertNotEqual(snapshot, validation.source_snapshot(root, ['source.rs', 'deleted.rs']))

    def test_snapshot_includes_frozen_dependencies_and_new_git_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory = root / 'rust/api-parity/legacy-inventory.json'
            inventory.parent.mkdir(parents=True)
            inventory.write_text(json.dumps({'sources': {'legacy.py': 'old'}}))
            (root / 'legacy.py').write_text('never execute')
            (root / 'new.rs').write_text('new source')
            result = subprocess.CompletedProcess([], 0, stdout=b'new.rs\0removed.rs\0')
            with patch.object(validation.subprocess, 'run', return_value=result):
                snapshot = validation.source_snapshot(root)
            self.assertEqual(set(snapshot), {'legacy.py', 'new.rs', 'removed.rs'})

    def run_fixture(self, root, selected=None, return_code=0, failure=None, drift=False, references=(), artifact_drift=False, environment_drift=False):
        selected = selected or list(validation.SUITES)
        sources = self.sources('source.rs')
        commands = {suite: [sys.executable, '-c', 'pass'] for suite in validation.SUITES}
        selection = {'selected_suites': selected, 'changed_sources': [], 'fallback': 'synthetic'}

        def execute(command, **kwargs):
            kwargs['stdout'].write('synthetic log, not runtime evidence\n')
            self.assertEqual(kwargs['env']['RUST_TEST_THREADS'], '1')
            self.assertIn('timeout', kwargs)
            if artifact_drift:
                (root / references[0]).write_text('changed reference during execution')
            if failure:
                raise failure
            return subprocess.CompletedProcess(command, return_code)

        with patch.object(validation, 'suite_commands', return_value=commands), \
                patch.object(validation, 'source_snapshot', return_value={} if drift else sources), \
                patch.object(validation, 'environment_snapshot', return_value={} if environment_drift else ENVIRONMENT), \
                patch.object(validation, 'run_command', side_effect=execute):
            document = validation.execute_plan(root, root / 'output/run', selection, sources,
                                               ENVIRONMENT, POLICY, artifacts=references)
            validation.verify_index(root, document, POLICY)
        return document, commands

    def test_full_run_indexes_commands_sources_timings_and_reference_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'reference.json').write_text('{}')
            document, commands = self.run_fixture(root, references=['reference.json'])
            self.assertTrue(document['full_baseline'])
            self.assertEqual(document['status'], 'passed')
            self.assertEqual(len(document['runs']), len(validation.SUITES))
            self.assertEqual(document['artifacts'][0]['role'], 'reference-only')
            self.assertTrue(all(run['seconds'] >= 0 for run in document['runs']))
            self.assertEqual(json.loads((root / 'output/run/index.json').read_text()), document)

    def test_partial_run_does_not_claim_full_baseline(self):
        with tempfile.TemporaryDirectory() as directory:
            document, commands = self.run_fixture(Path(directory), selected=['accounting'])
            self.assertFalse(document['full_baseline'])

    def test_changed_missing_and_duplicate_artifacts_are_refused(self):
        for mode in ('changed', 'missing', 'duplicate'):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                document, commands = self.run_fixture(root)
                path = root / document['artifacts'][0]['path']
                if mode == 'changed':
                    path.write_text('tampered')
                elif mode == 'missing':
                    path.unlink()
                else:
                    document['artifacts'].append(document['artifacts'][0])
                    validation.save_index(root / 'output/run/index.json', document)
                with patch.object(validation, 'suite_commands', return_value=commands), self.assertRaises((ValueError, OSError)):
                    validation.verify_index(root, document, POLICY)

    def test_receipt_corruption_and_fictitious_success_are_refused(self):
        mutations = (
            lambda document: document.update(index_fingerprint='tampered'),
            lambda document: document.update(source_fingerprint='tampered'),
            lambda document: document['runs'][0].update(exit_code=1),
            lambda document: document['runs'][0].update(command=['echo', 'fake success']),
            lambda document: document['runs'][0].update(seconds=-1),
            lambda document: document['runs'].pop(),
            lambda document: document.update(full_baseline=False),
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original, commands = self.run_fixture(root)
            for mutate in mutations:
                document = copy.deepcopy(original)
                mutate(document)
                if document['index_fingerprint'] != 'tampered':
                    validation.save_index(root / 'output/run/index.json', document)
                with patch.object(validation, 'suite_commands', return_value=commands), self.assertRaises(ValueError):
                    validation.verify_index(root, document, POLICY)

    def test_failures_timeouts_interruptions_and_source_drift_leave_failed_receipts(self):
        for options in ({'return_code': 3}, {'failure': subprocess.TimeoutExpired('synthetic', 1)},
                        {'failure': KeyboardInterrupt()}, {'failure': OSError('missing executable')},
                        {'drift': True}, {'environment_drift': True}):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                with self.assertRaises((ValueError, subprocess.TimeoutExpired, KeyboardInterrupt, OSError)):
                    self.run_fixture(root, **options)
                document = json.loads((root / 'output/run/index.json').read_text())
                self.assertEqual(document['status'], 'failed-or-interrupted')
                self.assertFalse(document['full_baseline'])
                with self.assertRaises(ValueError):
                    validation.verify_index(root, document, POLICY)

    def test_reference_mutation_during_execution_cannot_publish_success(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'reference.json').write_text('original')
            with self.assertRaisesRegex(ValueError, 'Artifact changed'):
                self.run_fixture(root, references=['reference.json'], artifact_drift=True)
            document = json.loads((root / 'output/run/index.json').read_text())
            self.assertEqual(document['status'], 'failed-or-interrupted')

    def test_environment_hashes_sensitive_build_values_and_detects_path_changes(self):
        result = subprocess.CompletedProcess([], 0, stdout='synthetic version')
        with patch.object(validation.subprocess, 'run', return_value=result), \
                patch.dict(validation.os.environ, {'CARGO_REGISTRIES_PRIVATE_TOKEN': 'synthetic-secret', 'PATH': 'original'}, clear=True):
            original = validation.environment_snapshot()
            validation.os.environ['PATH'] = 'changed'
            changed = validation.environment_snapshot()
        self.assertNotEqual(original, changed)
        self.assertNotIn('synthetic-secret', json.dumps(original))
        self.assertNotIn('original', json.dumps(original['build_environment_hashes']))

    def test_malformed_policy_and_index_shapes_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / validation.POLICY
            path.parent.mkdir(parents=True)
            for document in ([], {**POLICY, 'rules': ['not-a-rule']}, {**POLICY, 'unknown_change': 'none'}):
                path.write_text(json.dumps(document))
                with self.assertRaises(ValueError):
                    validation.load_policy(root)
            document, commands = self.run_fixture(root)
            document['source_hashes'] = []
            validation.save_index(root / 'output/run/index.json', document)
            with self.assertRaises(ValueError):
                validation.verify_index(root, document, POLICY)

    def test_output_cannot_escape_overwrite_or_publish_empty_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'output/existing').mkdir(parents=True)
            for output, suites in ((root / 'output/existing', ['accounting']), (root / 'source', ['accounting']),
                                   (root / 'output/empty', []), (root.parent / 'outside', ['accounting'])):
                with self.assertRaises(ValueError):
                    validation.execute_plan(root, output, {'selected_suites': suites}, {}, ENVIRONMENT, POLICY)

    def test_command_timeout_terminates_the_tree_and_reaps_the_process(self):
        process = unittest.mock.Mock(pid=12345)
        process.wait.side_effect = [subprocess.TimeoutExpired('synthetic', 1), 0]
        process.poll.return_value = None
        with patch.object(validation.subprocess, 'Popen', return_value=process), \
                patch.object(validation.subprocess, 'run') as terminate, \
                patch.object(validation.os, 'killpg', create=True) as kill_group:
            with self.assertRaises(subprocess.TimeoutExpired):
                validation.run_command(['synthetic'], cwd=ROOT, stdout=None, stderr=None, env={}, timeout=1)
            if validation.os.name == 'nt':
                self.assertEqual(terminate.call_args.args[0], ['taskkill', '/PID', '12345', '/T', '/F'])
            else:
                kill_group.assert_called_once()
            process.kill.assert_called_once()
            self.assertEqual(process.wait.call_count, 2)

    def test_real_harmless_command_and_timeout_leave_no_running_parent(self):
        original_popen = validation.subprocess.Popen
        processes = []

        def spawn(*args, **kwargs):
            process = original_popen(*args, **kwargs)
            processes.append(process)
            return process

        with tempfile.TemporaryDirectory() as directory:
            with (Path(directory) / 'command.log').open('w') as log, \
                    patch.object(validation.subprocess, 'Popen', side_effect=spawn):
                result = validation.run_command([sys.executable, '-c', 'print("harmless validation probe")'],
                                                cwd=ROOT, stdout=log, stderr=subprocess.STDOUT,
                                                env=None, timeout=10)
                self.assertEqual(result.returncode, 0)
                with self.assertRaises(subprocess.TimeoutExpired):
                    validation.run_command([sys.executable, '-c', 'import time; time.sleep(30)'],
                                           cwd=ROOT, stdout=log, stderr=subprocess.STDOUT,
                                           env=None, timeout=0.2)
            self.assertTrue(all(process.poll() is not None for process in processes))

    def test_cli_refuses_corrupt_index_and_reports_safe_initial_plan(self):
        command = [sys.executable, str(ROOT / 'tools/native_pe_validation.py')]
        result = subprocess.run([*command, 'plan'], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        plan = json.loads(result.stdout)
        self.assertEqual(plan['selected_suites'], list(validation.SUITES))
        self.assertLessEqual(len(plan['changed_sources_preview']), 20)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'index.json'
            path.write_text('{}')
            result = subprocess.run([*command, 'check', '--index', str(path)], cwd=ROOT, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('fingerprint', result.stderr)
            self.assertNotIn('Traceback', result.stderr)


if __name__ == '__main__':
    unittest.main()
