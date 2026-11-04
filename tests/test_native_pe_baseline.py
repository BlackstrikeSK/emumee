"""Static dependency verification controls; synthetic inputs never execute packages."""
import base64
import copy
from contextlib import redirect_stdout
import csv
import hashlib
import importlib.machinery
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import native_pe_baseline as baseline


class BaselineTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.venv = self.root / 'venv'
        self.site = self.venv / 'Lib/site-packages'
        self.site.mkdir(parents=True)
        self.dist = self.site / 'example-1.0.dist-info'
        self.dist.mkdir()
        (self.dist / 'METADATA').write_text('Name: example\nVersion: 1.0\nRequires-Python: >=3.10\n')
        (self.site / 'example.py').write_bytes(b'not executed\n')
        self.write_record()

    def write_record(self, extra=()):
        rows = []
        for path in (self.site / 'example.py', self.dist / 'METADATA'):
            raw = path.read_bytes()
            encoded = base64.urlsafe_b64encode(hashlib.sha256(raw).digest()).decode().rstrip('=')
            rows.append((path.relative_to(self.site).as_posix(), f'sha256={encoded}', str(len(raw))))
        rows += [('example-1.0.dist-info/RECORD', '', ''), *extra]
        with (self.dist / 'RECORD').open('w', newline='') as stream:
            csv.writer(stream).writerows(rows)

    def record_issues(self):
        report = baseline.audit_records(self.venv)
        return report['issues'] + [issue for row in report['distributions'] for issue in row['issues']]

    def archive(self, members=None):
        archive = self.root / 'example-1.0.crate'
        source = self.root / 'source'
        source.mkdir(exist_ok=True)
        (source / 'lib.rs').write_bytes(b'pub fn example() {}')
        with tarfile.open(archive, 'w:gz') as bundle:
            for name, raw, kind in members or [('example-1.0/lib.rs', b'pub fn example() {}', tarfile.REGTYPE)]:
                member = tarfile.TarInfo(name)
                member.type = kind
                member.linkname = '../outside'
                member.size = len(raw) if kind == tarfile.REGTYPE else 0
                bundle.addfile(member, io.BytesIO(raw) if kind == tarfile.REGTYPE else None)
        return archive, source, baseline.digest_file(archive)['sha256']

    def archive_report(self, archive, source, checksum):
        return baseline.audit_archive(archive, source, 'example', '1.0', checksum)

    def requirements(self, rows, version='3.13.6'):
        return baseline.audit_requirements(rows, version)

    def distribution(self, name='example', version='1.0', requirements=(), **extra):
        return dict(directory=f'{name}.dist-info', name=name, version=version, requirements=list(requirements), **extra)

    def test_valid_record_hashes_and_metadata(self):
        report = baseline.audit_records(self.venv)
        self.assertEqual([], self.record_issues())
        self.assertEqual(2, report['distributions'][0]['hashed_files'])
        self.assertEqual('example', report['distributions'][0]['name'])

    def test_record_changed_bytes(self):
        (self.site / 'example.py').write_bytes(b'bad executed\n')
        self.assertTrue(self.record_issues())

    def test_record_missing_file(self):
        (self.site / 'example.py').unlink()
        self.assertTrue(any('Missing installed file' in issue for issue in self.record_issues()))

    def test_record_wrong_size(self):
        record = self.dist / 'RECORD'
        rows = list(csv.reader(io.StringIO(record.read_text())))
        rows[0][2] = '999'
        with record.open('w', newline='') as stream:
            csv.writer(stream).writerows(rows)
        self.assertTrue(any('size differs' in issue for issue in self.record_issues()))

    def test_record_missing_metadata(self):
        (self.dist / 'METADATA').unlink()
        self.assertTrue(self.record_issues())

    def test_record_empty_scope(self):
        other = self.root / 'empty'
        other.mkdir()
        self.assertTrue(baseline.audit_records(other)['issues'])

    def test_record_unrecorded_source(self):
        (self.site / 'surprise.py').write_text('not executed')
        self.assertTrue(any('Unrecorded' in issue for issue in self.record_issues()))
        cache = self.site / '__pycache__'
        cache.mkdir()
        (cache / 'surprise.py').write_text('not a bytecode cache')
        self.assertTrue(any('__pycache__/surprise.py' in issue for issue in self.record_issues()))

    def test_record_unhashed_source_refused(self):
        (self.site / 'other.py').write_text('not executed')
        self.write_record([('other.py', '', '')])
        self.assertTrue(any('Unhashed non-cache' in issue for issue in self.record_issues()))

    def test_record_unhashed_cache_allowed(self):
        (self.site / 'cache.pyc').write_bytes(b'not executed')
        self.write_record([('cache.pyc', '', '')])
        self.assertEqual([], self.record_issues())

    def test_record_duplicate_path(self):
        self.write_record([('example.py', '', '')])
        self.assertTrue(any('Duplicate' in issue for issue in self.record_issues()))

    def test_record_malformed_hash_and_rows(self):
        for row in [('new',), ('other', 'sha256=!!!', ''), ('other', 'md5=AAAA', '')]:
            with self.subTest(row=row):
                (self.site / 'other').write_text('content')
                self.write_record([row])
                self.assertTrue(self.record_issues())

    def test_record_escape_paths(self):
        for relative in ('../../../../outside', '/outside', 'C:/outside', '..\\outside'):
            with self.subTest(relative=relative), self.assertRaises(ValueError):
                baseline.record_path(self.site, self.venv, relative)
        self.assertEqual(self.site / '../../Scripts/example.exe',
                         baseline.record_path(self.site, self.venv, '../../Scripts/example.exe'))

    def test_metadata_symlink_escape_refused(self):
        metadata = self.dist / 'METADATA'
        outside = self.root / 'outside'
        original = Path.resolve
        with patch.object(Path, 'resolve', lambda path: outside if path == metadata else original(path)):
            with self.assertRaisesRegex(ValueError, 'escapes'):
                baseline.audit_records(self.venv)

    def test_real_directory_link_escape_refused(self):
        outside = self.root / 'outside-directory'
        outside.mkdir()
        link = self.site / 'outside.dist-info'
        if sys.platform == 'win32':
            import _winapi
            _winapi.CreateJunction(str(outside), str(link))
        else:
            link.symlink_to(outside, target_is_directory=True)
        self.addCleanup(link.unlink if sys.platform != 'win32' else link.rmdir)
        with self.assertRaisesRegex(ValueError, 'escapes'):
            baseline.audit_records(self.venv)

    def test_active_and_inactive_requirement_markers(self):
        rows = [self.distribution(requirements=('missing; extra == "dev"', 'missing; python_version < "3.0"'))]
        report = self.requirements(rows)
        self.assertFalse(report['issues'])
        self.assertTrue(all(not edge['active'] for edge in report['edges']))

    def test_missing_dependency_and_wrong_version(self):
        for rows in ([self.distribution(requirements=('missing>=1',))],
                     [self.distribution(requirements=('target>=2',)), self.distribution('target')]):
            with self.subTest(rows=rows):
                self.assertTrue(self.requirements(rows)['issues'])

    def test_extras_propagate_to_fixed_point(self):
        rows = [self.distribution('target', requirements=('missing; extra == "feature"',)),
                self.distribution(requirements=('target[feature]',))]
        self.assertTrue(any('missing' in issue for issue in self.requirements(rows)['issues']))

    def test_requirement_identity_version_python_and_url_failures(self):
        for rows in ([self.distribution(version='invalid')],
                     [self.distribution(), self.distribution('EXAMPLE')],
                     [self.distribution(requires_python='<3')],
                     [self.distribution(requirements=('target @ https://example.invalid/target',))],
                     [self.distribution(requirements=('invalid $$$',))]):
            with self.subTest(rows=rows):
                self.assertTrue(self.requirements(rows)['issues'])

    def test_untrusted_requirement_parser_refused(self):
        specification = importlib.machinery.ModuleSpec('pip', None, origin=str(self.root / 'pip.py'))
        with patch.object(baseline.importlib.util, 'find_spec', return_value=specification):
            with self.assertRaisesRegex(ValueError, 'trusted system pip'):
                baseline.requirement_tools()

    def test_valid_archive_and_generated_metadata(self):
        archive, source, checksum = self.archive()
        (source / '.cargo-ok').write_text('generated')
        self.assertFalse(self.archive_report(archive, source, checksum)['issues'])

    def test_archive_checksum_corruption(self):
        archive, source, checksum = self.archive()
        archive.write_bytes(archive.read_bytes() + b'tamper')
        self.assertTrue(self.archive_report(archive, source, checksum)['issues'])

    def test_archive_source_corruption_and_missing_file(self):
        archive, source, checksum = self.archive()
        (source / 'lib.rs').write_bytes(b'changed')
        self.assertTrue(self.archive_report(archive, source, checksum)['issues'])
        (source / 'lib.rs').unlink()
        self.assertTrue(self.archive_report(archive, source, checksum)['issues'])

    def test_missing_archive_or_source(self):
        self.assertTrue(self.archive_report(self.root / 'missing', self.root / 'missing', '0' * 64)['issues'])

    def test_archive_unrecorded_source(self):
        archive, source, checksum = self.archive()
        (source / 'surprise.rs').write_bytes(b'not executed')
        self.assertTrue(self.archive_report(archive, source, checksum)['issues'])

    def test_archive_traversal_links_special_duplicates_and_empty(self):
        for members in ([('example-1.0/../outside', b'', tarfile.REGTYPE)],
                        [('/example-1.0/outside', b'', tarfile.REGTYPE)],
                        [('example-1.0/link', b'', tarfile.SYMTYPE)],
                        [('example-1.0/link', b'', tarfile.LNKTYPE)],
                        [('example-1.0/device', b'', tarfile.CHRTYPE)],
                        [('example-1.0/lib.rs', b'', tarfile.REGTYPE)] * 2,
                        [('example-1.0', b'', tarfile.DIRTYPE)]):
            with self.subTest(members=members):
                self.assertTrue(self.archive_report(*self.archive(members))['issues'])

    def test_archive_selected_source_escape_refused(self):
        archive, source, checksum = self.archive()
        outside = self.root / 'outside'
        original = Path.resolve
        with patch.object(Path, 'resolve', lambda path: outside if path == source / 'lib.rs' else original(path)):
            self.assertTrue(self.archive_report(archive, source, checksum)['issues'])

    def test_cargo_missing_unlocked_and_duplicate_identities(self):
        row = dict(name='example', version='1.0', manifest_path=str(self.root / 'Cargo.toml'))
        locked = dict(name='example', version='1.0')
        for lock, metadata in (({'package': [locked]}, {'packages': []}),
                               ({'package': []}, {'packages': [row]}),
                               ({'package': [locked]}, {'packages': [row, row]}),
                               ({'package': [locked, locked]}, {'packages': [row]})):
            with self.subTest(metadata=metadata):
                self.assertTrue(baseline.audit_cargo(lock, metadata, self.root, self.root)['issues'])

    def test_cargo_workspace_manifest_escape(self):
        row = dict(name='example', version='1.0', manifest_path=str(self.root.parent / 'Cargo.toml'))
        with self.assertRaisesRegex(ValueError, 'escapes'):
            baseline.audit_cargo({'package': [dict(name='example', version='1.0')]},
                                 {'packages': [row]}, self.root, self.root)

    def test_cargo_locked_registry_resolution(self):
        archive, source, checksum = self.archive()
        selected = self.root / 'registry/src/bucket/example-1.0'
        selected.mkdir(parents=True)
        (selected / 'lib.rs').write_bytes((source / 'lib.rs').read_bytes())
        cache = self.root / 'registry/cache/bucket'
        cache.mkdir(parents=True)
        (cache / archive.name).write_bytes(archive.read_bytes())
        package = dict(name='example', version='1.0', checksum=checksum,
                       source='registry+https://github.com/rust-lang/crates.io-index')
        metadata = {'packages': [dict(package, manifest_path=str(selected / 'Cargo.toml'))]}
        report = baseline.audit_cargo({'package': [package]}, metadata, self.root, self.root)
        self.assertFalse(report['issues'])
        self.assertFalse(report['packages'][0]['issues'])

    def test_packaging_probe_requires_actual_capabilities(self):
        capabilities = dict(powershell_major=5, path_get_full_path=True,
                            sha256_create=True, ordinal_sort=True, utf8_no_bom=True)
        probe = dict(exit_code=0, stdout=json.dumps(capabilities), stderr='')
        with patch.object(baseline, 'capture', return_value=probe) as capture:
            report = baseline.packaging_shell_probe(self.root, 'pwsh')
        self.assertTrue(report['supported'])
        self.assertEqual(capabilities, report['capabilities'])
        command = capture.call_args.args[0]
        self.assertEqual(['pwsh', '-NoProfile', '-NonInteractive', '-Command'], command[:4])
        self.assertNotIn('package_rust.ps1', command[-1])

    def test_packaging_probe_refuses_each_missing_capability(self):
        for missing in ('path_get_full_path', 'sha256_create', 'ordinal_sort', 'utf8_no_bom'):
            capabilities = dict(powershell_major=5, path_get_full_path=True,
                                sha256_create=True, ordinal_sort=True, utf8_no_bom=True)
            capabilities[missing] = False
            with self.subTest(missing=missing), patch.object(baseline, 'capture', return_value=dict(
                    exit_code=0, stdout=json.dumps(capabilities), stderr='')):
                report = baseline.packaging_shell_probe(self.root, 'pwsh')
                self.assertFalse(report['supported'])
                self.assertEqual([f'Packaging shell lacks {missing}'], report['issues'])

    def test_packaging_probe_refuses_missing_shell_without_execution(self):
        with patch.object(baseline, 'capture') as capture:
            report = baseline.packaging_shell_probe(self.root, None)
        capture.assert_not_called()
        self.assertFalse(report['supported'])
        self.assertIsNone(report['capabilities'])

    def test_packaging_probe_refuses_failed_process(self):
        with patch.object(baseline, 'capture', return_value=dict(exit_code=1, stdout='{}', stderr='failed')):
            report = baseline.packaging_shell_probe(self.root, 'pwsh')
        self.assertFalse(report['supported'])
        self.assertIsNone(report['capabilities'])
        self.assertEqual('failed', report['probe']['stderr'])

    def test_packaging_probe_refuses_unavailable_process(self):
        for error in (FileNotFoundError('missing'), subprocess.TimeoutExpired('probe', 120)):
            with self.subTest(error=type(error).__name__), patch.object(baseline, 'capture', side_effect=error):
                report = baseline.packaging_shell_probe(self.root, 'pwsh')
                self.assertFalse(report['supported'])

    def test_packaging_probe_refuses_malformed_or_forged_output(self):
        valid = dict(powershell_major=5, path_get_full_path=True,
                     sha256_create=True, ordinal_sort=True, utf8_no_bom=True)
        for output in ('not json', 'null', '[]', '{}', json.dumps(dict(valid, powershell_major=True)),
                       json.dumps(dict(valid, powershell_major=0)), json.dumps(dict(valid, sha256_create=1)),
                       json.dumps(dict(valid, extra=True))):
            with self.subTest(output=output), patch.object(baseline, 'capture', return_value=dict(
                    exit_code=0, stdout=output, stderr='')):
                report = baseline.packaging_shell_probe(self.root, 'pwsh')
                self.assertFalse(report['supported'])
                self.assertIsNone(report['capabilities'])

    def test_missing_toolchain_is_classified(self):
        with patch.object(baseline, 'environment_snapshot', side_effect=FileNotFoundError('cargo')), \
                patch.object(baseline.shutil, 'which', return_value=None):
            report = baseline.audit_toolchain(self.root)
        self.assertTrue(any(row['dependency'] == 'cargo' for row in report['missing_dependencies']))
        self.assertTrue(any(row['scope'] == 'packaging' for row in report['missing_dependencies']))

    def test_report_rejects_corruption_staleness_and_forged_claims(self):
        current = dict(schema=1, payload={'source': 'current'}, scope='static', integrity_verified=True,
                       issues=[], source_build_prerequisites_present=True, packaging_prerequisites_present=False)
        current['dependency_fingerprint'] = baseline.fingerprint(current['payload'])
        baseline.verify_report(copy.deepcopy(current), current)
        for key, value in (('schema', 2), ('payload', {}), ('dependency_fingerprint', 'bad'),
                           ('integrity_verified', False), ('packaging_prerequisites_present', True),
                           ('integrity_verified', 1), ('issues', ['forged'])):
            previous = copy.deepcopy(current)
            previous[key] = value
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, 'corrupt or stale'):
                baseline.verify_report(previous, current)

    def test_cli_refuses_outside_output_and_overwrite_before_audit(self):
        for output in (self.root / 'outside.json', ROOT / 'output'):
            result = subprocess.run([sys.executable, str(ROOT / 'tools/native_pe_baseline.py'),
                                     'audit', '--output', str(output)], capture_output=True, text=True)
            self.assertEqual(2, result.returncode)
            self.assertIn('new --output', result.stderr)

    def test_collection_missing_cargo_and_venv_configuration(self):
        inventory = self.root / 'rust/api-parity/legacy-inventory.json'
        inventory.parent.mkdir(parents=True)
        inventory.write_text('{"sources": {}}')
        toolchain = {'files': {}, 'missing_dependencies': [{'scope': 'source-build', 'dependency': 'cargo'}]}
        with patch.object(baseline, 'runtime_snapshot', return_value={}), \
                patch.object(baseline, 'audit_toolchain', return_value=toolchain), \
                patch.dict(baseline.os.environ, {'RUSTC_WRAPPER': '', 'RUSTC_WORKSPACE_WRAPPER': ''}), \
                patch.object(baseline, 'capture') as capture:
            report = baseline.collect(self.root, self.venv, self.root)
        capture.assert_not_called()
        self.assertFalse(report['integrity_verified'])
        self.assertFalse(report['source_build_prerequisites_present'])
        self.assertTrue(any('requirements' in issue for issue in report['issues']))

    def test_collection_refuses_rustc_wrappers(self):
        inventory = self.root / 'rust/api-parity/legacy-inventory.json'
        inventory.parent.mkdir(parents=True)
        inventory.write_text('{"sources": {}}')
        with patch.object(baseline, 'runtime_snapshot', return_value={}), \
                patch.object(baseline, 'audit_toolchain', return_value={}), \
                patch.dict(baseline.os.environ, {'RUSTC_WRAPPER': 'unreviewed.exe'}), \
                patch.object(baseline, 'capture') as capture:
            with self.assertRaisesRegex(ValueError, 'wrappers'):
                baseline.collect(self.root, self.venv, self.root)
        capture.assert_not_called()

    def test_collection_failed_metadata_and_source_drift(self):
        inventory = self.root / 'rust/api-parity/legacy-inventory.json'
        inventory.parent.mkdir(parents=True)
        inventory.write_text('{"sources": {}}')
        (self.venv / 'pyvenv.cfg').write_text('version = 3.13.6\n')
        toolchain = {'files': {'cargo': {'path': 'trusted-cargo'}}, 'missing_dependencies': []}
        with patch.object(baseline, 'runtime_snapshot', side_effect=[{'source': 'before'}, {'source': 'after'}]), \
                patch.object(baseline, 'audit_toolchain', return_value=toolchain), \
                patch.dict(baseline.os.environ, {'RUSTC_WRAPPER': '', 'RUSTC_WORKSPACE_WRAPPER': ''}), \
                patch.object(baseline, 'capture', return_value={'exit_code': 1, 'stdout': '', 'stderr': 'offline failure'}):
            report = baseline.collect(self.root, self.venv, self.root)
        self.assertFalse(report['integrity_verified'])
        self.assertIn('Offline Cargo metadata probe failed', report['issues'])
        self.assertIn('Repository source changed during dependency audit', report['issues'])
        self.assertIsNotNone(report['payload']['venv_configuration'])

    def test_cli_report_roundtrip_and_tamper(self):
        report = dict(schema=1, scope='static', integrity_verified=True, issues=[], seconds=0,
                      source_build_prerequisites_present=True, packaging_prerequisites_present=False,
                      payload={'legacy': {'sources': {}}, 'python_records': {'distributions': []},
                               'cargo': {'packages': []}, 'toolchain': {'missing_dependencies': []}})
        report['dependency_fingerprint'] = baseline.fingerprint(report['payload'])
        with tempfile.TemporaryDirectory(dir=ROOT / 'output') as directory:
            destination = Path(directory) / 'report.json'
            with patch.object(baseline, 'collect', return_value=report), redirect_stdout(io.StringIO()):
                with patch.object(sys, 'argv', ['audit', 'audit', '--output', str(destination)]):
                    self.assertEqual(0, baseline.main())
                with patch.object(sys, 'argv', ['audit', 'check', '--report', str(destination)]):
                    self.assertEqual(0, baseline.main())
                corrupted = json.loads(destination.read_text())
                corrupted['integrity_verified'] = False
                destination.write_text(json.dumps(corrupted))
                with patch.object(sys, 'argv', ['audit', 'check', '--report', str(destination)]), \
                        patch.object(baseline.argparse.ArgumentParser, 'error', side_effect=ValueError) as parse_error:
                    with self.assertRaises(ValueError):
                        baseline.main()
                    self.assertIn('corrupt or stale', parse_error.call_args.args[0])


if __name__ == '__main__':
    unittest.main()
