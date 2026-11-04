"""Audit native development dependencies without importing or executing legacy code."""
from __future__ import annotations

import argparse
import base64
import configparser
import csv
from email.parser import Parser
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib

from native_pe_validation import environment_snapshot, run_command
from native_pe_worklist import atomic_write, fingerprint, runtime_snapshot


def digest_file(path, algorithm='sha256'):
    digest = hashlib.new(algorithm)
    size = 0
    with path.open('rb') as stream:
        before = os.fstat(stream.fileno())
        while chunk := stream.read(1024 * 1024):
            size += len(chunk)
            digest.update(chunk)
        after = os.fstat(stream.fileno())
    if (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
        raise ValueError(f'Dependency changed while hashing: {path}')
    return {'sha256' if algorithm == 'sha256' else algorithm: digest.hexdigest(), 'size': size}


def contained(root, path):
    if not path.resolve().is_relative_to(root.resolve()):
        raise ValueError(f'Dependency path escapes allowed root: {path}')
    return path


def record_path(site, venv, relative):
    if not relative or '\\' in relative or ':' in relative or PurePosixPath(relative).is_absolute():
        raise ValueError('Invalid installed RECORD path')
    return contained(venv, site / relative)


def audit_records(venv):
    site = contained(venv, venv / 'Lib/site-packages')
    distributions = []
    owned = set()
    issues = []
    for directory in sorted(site.glob('*.dist-info')):
        contained(venv, directory)
        record = contained(venv, directory / 'RECORD')
        metadata = contained(venv, directory / 'METADATA')
        row = {'directory': directory.name, 'issues': [], 'hashed_files': 0, 'unhashed_files': []}
        distributions.append(row)
        if not record.is_file() or not metadata.is_file():
            row['issues'].append('Missing RECORD or METADATA')
            continue
        row['record'] = digest_file(record)
        row['metadata'] = digest_file(metadata)
        message = Parser().parsestr(metadata.read_text(encoding='utf-8'))
        row.update(name=message.get('Name'), version=message.get('Version'),
                   requires_python=message.get('Requires-Python'), requirements=message.get_all('Requires-Dist', []))
        observed = {}
        with record.open(encoding='utf-8', newline='') as stream:
            for entry in csv.reader(stream):
                try:
                    if len(entry) != 3:
                        raise ValueError('Malformed RECORD row')
                    relative, expected_hash, expected_size = entry
                    path = record_path(site, venv, relative)
                    identity = path.resolve().as_posix()
                    if identity in observed:
                        raise ValueError(f'Duplicate RECORD path: {relative}')
                    owned.add(path.resolve())
                    if not path.is_file():
                        observed[identity] = None
                        raise ValueError(f'Missing installed file: {relative}')
                    actual = digest_file(path)
                    observed[identity] = actual
                    if expected_size and (not expected_size.isdecimal() or int(expected_size) != actual['size']):
                        raise ValueError(f'Installed size differs: {relative}')
                    if not expected_hash:
                        row['unhashed_files'].append(relative)
                        if path != record and path.suffix != '.pyc':
                            raise ValueError(f'Unhashed non-cache installed file: {relative}')
                        continue
                    algorithm, encoded = expected_hash.split('=', 1)
                    if algorithm not in ('sha256', 'sha384', 'sha512'):
                        raise ValueError(f'Unsupported RECORD hash: {algorithm}')
                    expected = base64.b64decode(encoded + '=' * (-len(encoded) % 4), altchars=b'-_', validate=True).hex()
                    actual_digest = actual['sha256'] if algorithm == 'sha256' else digest_file(path, algorithm)[algorithm]
                    if expected != actual_digest:
                        raise ValueError(f'Installed hash differs: {relative}')
                    row['hashed_files'] += 1
                except (ValueError, OSError) as error:
                    row['issues'].append(str(error))
        row['files_fingerprint'] = fingerprint(observed)
    if not distributions:
        issues.append('No installed distribution metadata; dependency scope cannot be empty')
    for path in sorted(site.rglob('*')):
        if path.is_file() and path.suffix != '.pyc':
            contained(venv, path)
            if path.resolve() not in owned:
                issues.append(f'Unrecorded installed file: {path.relative_to(site).as_posix()}')
    return {'scope': 'Installed RECORD self-consistency, not independent package authenticity',
            'distributions': distributions, 'issues': issues}


def requirement_tools():
    specification = importlib.util.find_spec('pip')
    if specification is None or not Path(specification.origin).resolve().is_relative_to(Path(sys.base_prefix).resolve()):
        raise ValueError('Requirement parsing requires trusted system pip, outside the legacy environment')
    from pip._vendor.packaging.markers import default_environment
    from pip._vendor.packaging.requirements import Requirement
    from pip._vendor.packaging.specifiers import SpecifierSet
    from pip._vendor.packaging.utils import canonicalize_name
    from pip._vendor.packaging.version import Version
    parser_root = Path(specification.origin).parent / '_vendor/packaging'
    parser_hashes = {path.relative_to(parser_root).as_posix(): digest_file(path)['sha256']
                     for path in sorted(parser_root.rglob('*.py'))}
    return Requirement, SpecifierSet, Version, canonicalize_name, default_environment(), fingerprint(parser_hashes)


def audit_requirements(distributions, python_version):
    Requirement, SpecifierSet, Version, canonicalize, environment, parser_fingerprint = requirement_tools()
    environment.update(python_version='.'.join(python_version.split('.')[:2]), python_full_version=python_version)
    installed = {}
    issues = []
    edges = []
    extras = {}
    for row in distributions:
        try:
            if not row.get('name') or not row.get('version'):
                raise ValueError(f'Missing distribution identity: {row["directory"]}')
            name = canonicalize(row['name'])
            if name in installed:
                raise ValueError(f'Duplicate installed distribution: {name}')
            Version(row['version'])
            if row.get('requires_python') and not SpecifierSet(row['requires_python']).contains(Version(python_version)):
                issues.append(f'Python version does not satisfy {name}: {row["requires_python"]}')
            installed[name] = row
            extras[name] = {''}
        except ValueError as error:
            issues.append(str(error))
    pending = list(installed)
    visited = set()
    while pending:
        parent = pending.pop(0)
        for extra in sorted(extras[parent]):
            if (parent, extra) in visited:
                continue
            visited.add((parent, extra))
            for text in installed[parent].get('requirements', []):
                try:
                    requirement = Requirement(text)
                    active = requirement.marker is None or requirement.marker.evaluate({**environment, 'extra': extra})
                    edge = {'parent': parent, 'extra': extra, 'requirement': text, 'active': active}
                    edges.append(edge)
                    if not active:
                        continue
                    target = canonicalize(requirement.name)
                    if requirement.url:
                        raise ValueError(f'Unverified direct-URL requirement: {parent}: {text}')
                    if target not in installed:
                        raise ValueError(f'Missing required distribution: {parent}: {text}')
                    if not requirement.specifier.contains(Version(installed[target]['version'])):
                        raise ValueError(f'Installed version does not satisfy {parent}: {text}')
                    added = set(requirement.extras) - extras[target]
                    if added:
                        extras[target].update(added)
                        pending.append(target)
                except ValueError as error:
                    issues.append(str(error))
    return {'python_version': python_version, 'marker_environment': environment,
            'parser_fingerprint': parser_fingerprint, 'edges': edges, 'issues': sorted(set(issues))}


def audit_archive(archive, source, name, version, checksum):
    result = {'name': name, 'version': version, 'archive': str(archive), 'source': str(source), 'issues': []}
    if not archive.is_file() or not source.is_dir():
        result['issues'].append('Missing locked archive or selected unpacked source')
        return result
    result['archive_bytes'] = digest_file(archive)
    if result['archive_bytes']['sha256'] != checksum:
        result['issues'].append('Cached archive differs from Cargo.lock checksum')
        return result
    observed = {}
    expected = set()
    prefix = f'{name}-{version}'
    try:
        with tarfile.open(archive, mode='r:gz') as bundle:
            for member in bundle:
                parts = PurePosixPath(member.name).parts
                if (not parts or parts[0] != prefix or '..' in parts or '\\' in member.name
                        or ':' in member.name or PurePosixPath(member.name).is_absolute()):
                    raise ValueError('Unsafe crate archive member path')
                if member.isdir():
                    continue
                if not member.isfile() or len(parts) < 2:
                    raise ValueError('Unsupported link/special crate archive member')
                relative = PurePosixPath(*parts[1:]).as_posix()
                if relative in expected:
                    raise ValueError('Duplicate crate archive member')
                expected.add(relative)
                extracted = contained(source, source / relative)
                with bundle.extractfile(member) as stream:
                    digest = hashlib.sha256()
                    while chunk := stream.read(1024 * 1024):
                        digest.update(chunk)
                actual = digest_file(extracted) if extracted.is_file() else None
                observed[relative] = actual
                if actual is None or actual['sha256'] != digest.hexdigest() or actual['size'] != member.size:
                    result['issues'].append(f'Unpacked source differs from locked archive: {relative}')
        if not expected:
            raise ValueError('Empty crate archive cannot verify dependencies')
        for path in sorted(source.rglob('*')):
            if path.is_file():
                contained(source, path)
                relative = path.relative_to(source).as_posix()
                if relative not in expected and relative not in ('.cargo-ok', '.cargo-checksum.json'):
                    result['issues'].append(f'Unrecorded unpacked source: {relative}')
    except (ValueError, OSError, tarfile.TarError) as error:
        result['issues'].append(str(error))
    result.update(files=len(expected), source_fingerprint=fingerprint(observed))
    return result


def audit_cargo(lock, metadata, cargo_home, root):
    selected = {}
    rows = []
    issues = []
    for row in metadata['packages']:
        identity = (row['name'], row['version'], row.get('source'))
        if identity in selected:
            issues.append(f'Duplicate offline metadata dependency: {identity}')
        selected[identity] = row
    locked = set()
    for package in lock['package']:
        identity = (package['name'], package['version'], package.get('source'))
        if identity in locked:
            issues.append(f'Duplicate locked dependency: {identity}')
        locked.add(identity)
        resolved = selected.get(identity)
        if resolved is None:
            issues.append(f'Locked dependency absent from offline metadata: {identity}')
            continue
        source = Path(resolved['manifest_path']).parent
        if 'source' not in package:
            contained(root, source)
            continue
        if package['source'] != 'registry+https://github.com/rust-lang/crates.io-index':
            issues.append(f'Unreviewed non-crates.io dependency: {identity}')
            continue
        contained(cargo_home / 'registry/src', source)
        archive = cargo_home / 'registry/cache' / source.parent.name / f'{package["name"]}-{package["version"]}.crate'
        contained(cargo_home / 'registry/cache', archive)
        rows.append(audit_archive(archive, source, package['name'], package['version'], package['checksum']))
    if not rows:
        issues.append('No registry dependencies were verified')
    unexpected = set(selected) - {(row['name'], row['version'], row.get('source')) for row in lock['package']}
    if unexpected:
        issues.append(f'Offline metadata adds unlocked dependencies: {sorted(unexpected, key=str)}')
    return {'packages': rows, 'issues': issues, 'metadata_fingerprint': fingerprint(metadata)}


def capture(command, root):
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        result = run_command(command, cwd=root, stdout=stdout, stderr=stderr, env=os.environ.copy(), timeout=120)
        stdout.seek(0)
        stderr.seek(0)
        return {'command': command, 'exit_code': result.returncode,
                'stdout': stdout.read().decode('utf-8', errors='replace'),
                'stderr': stderr.read().decode('utf-8', errors='replace')}


def packaging_shell_probe(root, shell):
    capabilities = None
    probe = None
    issues = []
    if shell is None:
        issues.append('No PowerShell executable is available for the packaging capability probe')
    else:
        script = """$ErrorActionPreference='Stop';
        $hasher=[Security.Cryptography.SHA256]::Create();
        try {$hash=[BitConverter]::ToString($hasher.ComputeHash([byte[]]@())).Replace('-','').ToLowerInvariant()}
        finally {$hasher.Dispose()};
        $names=[string[]]@('b','a'); [Array]::Sort($names,[StringComparer]::Ordinal);
        [ordered]@{
            powershell_major=$PSVersionTable.PSVersion.Major;
            path_get_full_path=[IO.Path]::IsPathRooted([IO.Path]::GetFullPath('.'));
            sha256_create=($hash -eq 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
            ordinal_sort=($names[0] -eq 'a' -and $names[1] -eq 'b');
            utf8_no_bom=([Text.UTF8Encoding]::new($false).GetPreamble().Length -eq 0)
        } | ConvertTo-Json -Compress"""
        try:
            probe = capture([str(shell), '-NoProfile', '-NonInteractive', '-Command', script], root)
            if probe['exit_code'] != 0:
                raise ValueError('PowerShell packaging capability probe failed')
            capabilities = json.loads(probe['stdout'])
            required = ('path_get_full_path', 'sha256_create', 'ordinal_sort', 'utf8_no_bom')
            if (not isinstance(capabilities, dict)
                    or set(capabilities) != {'powershell_major', *required}
                    or type(capabilities['powershell_major']) is not int
                    or capabilities['powershell_major'] < 1
                    or any(type(capabilities[key]) is not bool for key in required)):
                raise ValueError('Malformed PowerShell packaging capability probe')
            issues.extend(f'Packaging shell lacks {key}' for key in required if not capabilities[key])
        except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError) as error:
            capabilities = None
            issues.append(str(error))
    return {'shell': str(shell) if shell else None, 'probe': probe, 'capabilities': capabilities,
            'supported': not issues, 'issues': issues}


def audit_toolchain(root):
    tools = {}
    missing = []
    try:
        environment = environment_snapshot()
    except (OSError, subprocess.SubprocessError) as error:
        environment = {'probe_error': str(error)}
        missing.append({'scope': 'source-build', 'dependency': 'Development-tool environment probe failed'})
    local_ninja = root / 'output/rust-toolchain/ninja/bin/ninja.exe'
    for name in ('cargo', 'rustc', 'powershell', 'cmake', 'ninja'):
        found = str(local_ninja) if name == 'ninja' and local_ninja.is_file() else shutil.which(name)
        if found is None:
            missing.append({'scope': 'source-build', 'dependency': name})
            continue
        path = Path(found).resolve()
        tools[name] = {'path': str(path), **digest_file(path)}
        if name in ('cmake', 'ninja'):
            try:
                tools[name]['probe'] = capture([str(path), '--version'], root)
            except (OSError, subprocess.SubprocessError) as error:
                tools[name]['probe'] = {'exit_code': None, 'error': str(error)}
            if tools[name]['probe']['exit_code'] != 0:
                missing.append({'scope': 'source-build', 'dependency': f'{name} version probe failed'})
    paths = {'python': Path(sys.executable),
             'libclang': Path(os.environ.get('LIBCLANG_PATH', root / 'output/rust-toolchain/libclang/clang/native'))}
    if paths['libclang'].is_dir():
        paths['libclang'] /= 'libclang.dll'
    vc_root = Path(os.environ.get('ProgramFiles(x86)', 'C:/Program Files (x86)')) / 'Microsoft Visual Studio/2022/BuildTools/VC/Tools/MSVC'
    versions = sorted(vc_root.glob('*'), reverse=True)
    if versions:
        paths['msvc'] = versions[0] / 'bin/Hostx64/x64/cl.exe'
        paths['msvc-headers'] = versions[0] / 'include/vcruntime.h'
    else:
        missing.append({'scope': 'source-build', 'dependency': 'MSVC BuildTools'})
    sdk_root = Path(os.environ.get('ProgramFiles(x86)', 'C:/Program Files (x86)')) / 'Windows Kits/10/Include'
    sdks = sorted(sdk_root.glob('10.*'), reverse=True)
    if sdks:
        for component, header in (('ucrt', 'stdio.h'), ('shared', 'ntdef.h'), ('um', 'Windows.h')):
            paths[f'sdk-{component}'] = sdks[0] / component / header
    else:
        missing.append({'scope': 'source-build', 'dependency': 'Windows SDK headers'})
    for name, path in paths.items():
        if not path.is_file():
            missing.append({'scope': 'source-build', 'dependency': name, 'path': str(path)})
        else:
            tools[name] = {'path': str(path.resolve()), **digest_file(path)}
    modern_shell = shutil.which('pwsh')
    if modern_shell is not None:
        tools['pwsh'] = {'path': modern_shell, **digest_file(Path(modern_shell))}
    packaging = packaging_shell_probe(root, modern_shell or shutil.which('powershell'))
    missing.extend({'scope': 'packaging', 'dependency': issue} for issue in packaging['issues'])
    return {'environment': environment, 'files': tools, 'missing_dependencies': missing,
            'packaging_shell': packaging}


def collect(root, venv, cargo_home):
    start = time.monotonic()
    initial_sources = runtime_snapshot(root)
    inventory = json.loads((root / 'rust/api-parity/legacy-inventory.json').read_text(encoding='utf-8-sig'))
    legacy = {'sources': {}, 'issues': []}
    for relative, expected in inventory['sources'].items():
        path = contained(root, root / relative)
        actual = digest_file(path)['sha256'] if path.is_file() else None
        legacy['sources'][relative] = actual
        if actual != expected:
            legacy['issues'].append(f'Frozen source missing or changed: {relative}')
    if not legacy['sources']:
        legacy['issues'].append('Frozen legacy source scope is empty')
    records = audit_records(venv)
    configuration = configparser.ConfigParser(interpolation=None)
    try:
        configuration.read_string('[venv]\n' + contained(venv, venv / 'pyvenv.cfg').read_text(encoding='utf-8'))
        requirements = audit_requirements(records['distributions'], configuration['venv']['version'])
    except (ValueError, KeyError, OSError, configparser.Error) as error:
        requirements = {'issues': [f'Cannot verify installed Python requirements: {error}']}
    toolchain = audit_toolchain(root)
    if any(os.environ.get(name) for name in ('RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER')):
        raise ValueError('Review configured rustc wrappers before any offline metadata probe')
    if 'cargo' in toolchain['files']:
        metadata_probe = capture([toolchain['files']['cargo']['path'], 'metadata', '--locked', '--offline', '--format-version', '1'], root)
    else:
        metadata_probe = {'exit_code': None, 'stdout': '', 'stderr': 'Cargo is missing; offline resolution not attempted'}
    if metadata_probe['exit_code'] != 0:
        cargo = {'packages': [], 'issues': ['Offline Cargo metadata probe failed']}
    else:
        cargo = audit_cargo(tomllib.loads((root / 'Cargo.lock').read_text()),
                            json.loads(metadata_probe['stdout']), cargo_home, root)
    configuration_path = venv / 'pyvenv.cfg'
    payload = {'source_hashes': runtime_snapshot(root), 'legacy': legacy, 'python_records': records,
               'venv_configuration': digest_file(contained(venv, configuration_path)) if configuration_path.is_file() else None,
               'python_requirements': requirements, 'toolchain': toolchain, 'cargo': cargo,
               'cargo_metadata_probe': metadata_probe}
    all_issues = [*legacy['issues'], *records['issues'], *requirements['issues'], *cargo['issues']]
    all_issues += [issue for row in records['distributions'] for issue in row['issues']]
    all_issues += [issue for row in cargo['packages'] for issue in row['issues']]
    if initial_sources != payload['source_hashes']:
        all_issues.append('Repository source changed during dependency audit')
    return {'schema': 1, 'scope': 'Static dependency integrity and trusted development-tool probes only; no security recovery or package/runtime qualification',
            'integrity_verified': not all_issues, 'issues': all_issues, 'payload': payload,
            'source_build_prerequisites_present': not any(row['scope'] == 'source-build' for row in toolchain['missing_dependencies']),
            'packaging_prerequisites_present': not any(row['scope'] == 'packaging' for row in toolchain['missing_dependencies']),
            'dependency_fingerprint': fingerprint(payload), 'seconds': round(time.monotonic() - start, 6)}


def verify_report(previous, current):
    if (not isinstance(previous, dict) or previous.get('schema') != 1
            or any(type(previous.get(key)) is not bool for key in (
                'integrity_verified', 'source_build_prerequisites_present', 'packaging_prerequisites_present'))
            or previous.get('dependency_fingerprint') != fingerprint(previous.get('payload'))
            or previous['dependency_fingerprint'] != current['dependency_fingerprint']
            or any(previous.get(key) != current[key] for key in (
                'scope', 'integrity_verified', 'issues', 'source_build_prerequisites_present',
                'packaging_prerequisites_present'))):
        raise ValueError('Baseline report is corrupt or stale for current source/dependencies/toolchain')


def main():
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('audit', 'check'))
    parser.add_argument('--output', type=Path)
    parser.add_argument('--report', type=Path)
    parser.add_argument('--venv', type=Path, default=root / '.venv')
    parser.add_argument('--cargo-home', type=Path, default=Path(os.environ.get('CARGO_HOME', Path.home() / '.cargo')))
    args = parser.parse_args()
    try:
        if args.action == 'audit' and (args.output is None or args.output.exists()
                or not args.output.resolve().is_relative_to((root / 'output').resolve())):
            raise ValueError('audit requires a new --output report inside repository output/')
        if args.action == 'check' and args.report is None:
            raise ValueError('check requires --report')
        report = collect(root, args.venv.resolve(), args.cargo_home.resolve())
        if args.action == 'audit':
            atomic_write(args.output, json.dumps(report, indent=2) + '\n')
        else:
            previous = json.loads(args.report.read_text(encoding='utf-8-sig'))
            verify_report(previous, report)
        summary = {'integrity_verified': report['integrity_verified'], 'issues': report['issues'],
                   'source_build_prerequisites_present': report['source_build_prerequisites_present'],
                   'packaging_prerequisites_present': report['packaging_prerequisites_present'],
                   'legacy_sources': len(report['payload']['legacy']['sources']),
                   'python_distributions': len(report['payload']['python_records']['distributions']),
                   'cargo_packages': len(report['payload']['cargo']['packages']),
                   'missing_dependencies': report['payload']['toolchain']['missing_dependencies'],
                   'dependency_fingerprint': report['dependency_fingerprint'], 'seconds': report['seconds']}
        print(json.dumps(summary, indent=2))
        return 0 if report['integrity_verified'] else 1
    except (ValueError, KeyError, TypeError, OSError, csv.Error, tarfile.TarError, configparser.Error,
            subprocess.SubprocessError) as error:
        parser.error(str(error))


if __name__ == '__main__':
    sys.exit(main())
