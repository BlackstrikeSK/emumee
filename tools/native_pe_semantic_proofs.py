"""Check semantic proof identity, exact release bytes and transitive artifacts."""
from __future__ import annotations

import hashlib
import importlib
import json
from pathlib import Path, PurePosixPath

from native_pe_worklist import CLOSED_STATES, contract_key, fingerprint, validate_evidence

CHECKERS = {
    'emumee.native-semantic.legacy-literals.v1': 'native_pe_semantic_literals',
    'emumee.native-semantic.lstrlen.v1': 'native_pe_semantic_strlen',
    'emumee.native-semantic.legacy-voids.v1': 'native_pe_semantic_voids',
    'emumee.native-semantic.legacy-local-constants.v1': 'native_pe_semantic_locals',
    'emumee.native-semantic.interlocked.v1': 'native_pe_semantic_interlocked',
    'emumee.native-semantic.crt-data.v1': 'native_pe_semantic_crt_data',
    'emumee.native-semantic.winstrings.v1': 'native_pe_semantic_winstrings',
    'emumee.native-semantic.heap-checks.v1': 'native_pe_semantic_heap_checks',
}


def contract_identities(rows):
    """Use JSON arrays, so sealed documents compare identically after loading."""
    keys = [contract_key({**row, 'kind': row.get('kind', 'function')}) for row in rows]
    assert len(keys) == len(set(keys)), 'Duplicate semantic proof contract'
    return [list(key) for key in sorted(keys)]


def verify_artifacts(entries, root, *, bundle=None, runtime_fingerprint=None, source_index=None):
    root = Path(root).resolve()
    strict = bundle is not None
    receipt = json.loads((Path(bundle) / 'rust-worker-build.json').read_bytes()) if strict else None
    expected_files = {name: hashlib.sha256((Path(bundle) / name).read_bytes()).hexdigest()
                      for name in ('emumee-rs.exe', 'emumee-worker.exe', 'unicorn.dll')} if strict else {}
    checked = {}
    active = set()
    verified = set()

    def walk(record, depth=0):
        assert depth <= 16, 'Semantic proof nesting exceeds bound'
        relative = record['path']
        assert isinstance(relative, str) and relative and '\\' not in relative and ':' not in relative
        assert not PurePosixPath(relative).is_absolute() and '..' not in PurePosixPath(relative).parts
        path = root / relative
        assert path.resolve().is_relative_to(root), 'Evidence artifact escapes repository'
        identity = relative, record['size'], record['sha256']
        assert identity not in active, 'Cyclic semantic proof'
        if identity in checked:
            return checked[identity]
        assert path.is_file() and path.stat().st_size == record['size'], 'Missing/resized semantic artifact'
        raw = path.read_bytes()
        assert hashlib.sha256(raw).hexdigest() == record['sha256'], 'Semantic artifact hash mismatch'
        active.add(identity)
        payload = None
        if path.suffix == '.json':
            try:
                payload = json.loads(raw)
            except (ValueError, UnicodeError):
                pass
        proofs = []
        if isinstance(payload, dict) and str(payload.get('profile', '')).startswith('emumee.native-semantic.'):
            assert payload['profile'] in CHECKERS, 'Unknown semantic proof profile'
            assert payload.get('fingerprint') == fingerprint({k:v for k,v in payload.items() if k != 'fingerprint'}), 'Semantic proof fingerprint mismatch'
            artifacts = payload.get('artifacts')
            assert isinstance(artifacts, list) and artifacts, 'Semantic proof lacks raw artifacts'
            for child in artifacts:
                proofs.extend(walk(child, depth + 1))
            if strict:
                assert payload.get('runtime_fingerprint') == runtime_fingerprint, 'Semantic proof runtime is stale'
                assert payload.get('source_tree_sha256') == receipt['source_tree_sha256'], 'Semantic proof source build differs'
                identities = payload.get('contract_identities')
                assert isinstance(identities, list) and identities, 'Semantic proof lacks contract identities'
                keys = [tuple(key) for key in identities]
                assert len(keys) == len(set(keys)), 'Duplicate semantic proof contract'
                for key in keys:
                    assert len(key) == 4
                    contract_key(dict(zip(('module','export','kind','architecture'), key)))
                binaries = [r for r in artifacts if PurePosixPath(r['path']).parent.name == 'bundle'
                            and PurePosixPath(r['path']).name in expected_files]
                assert len(binaries) == 3 and {PurePosixPath(r['path']).name for r in binaries} == set(expected_files), 'Semantic proof lacks exact bundle bytes'
                for binary in binaries:
                    assert binary['sha256'] == expected_files[PurePosixPath(binary['path']).name], 'Semantic proof uses another release binary'
                if source_index is not None and identity not in verified:
                    checker = importlib.import_module(CHECKERS[payload['profile']])
                    assert checker.proof_path(path.parent).resolve() == path.resolve(), 'Semantic proof filename differs from its checker'
                    checker.seal(path.parent, Path(source_index).resolve(), check=True)
                    verified.add(identity)
            proofs.append(payload)
        active.remove(identity)
        checked[identity] = proofs
        return proofs

    for row in entries:
        if row['semantic_status'] not in CLOSED_STATES:
            continue
        validate_evidence(row)
        supported = False
        for evidence in row['behavioral_evidence']:
            artifacts = evidence.get('artifacts')
            assert isinstance(artifacts, list) and artifacts, 'Closed evidence needs bound artifacts'
            for record in artifacts:
                for proof in walk(record):
                    if list(contract_key(row)) in proof.get('contract_identities', []):
                        supported = True
        if strict:
            assert supported, 'Closed contract is absent from its semantic proof'
    return len(checked)
