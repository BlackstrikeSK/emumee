"""Publish independently checked semantic families in one atomic update.

Every family's proof is checked before maintained evidence changes, so a later
family cannot be checked against a source index invalidated by an earlier write.
"""
from __future__ import annotations

import argparse
import importlib
import json
from pathlib import Path

from native_pe_worklist import CLOSED_STATES, atomic_write, contract_key, validate_evidence

ROOT = Path(__file__).resolve().parents[1]
FAMILIES = ('literals', 'strlen', 'voids', 'locals', 'interlocked', 'crt_data', 'winstrings', 'heap_checks')


def publish(root, index, ledger, *, qualifiers=None, evidence_path=None):
    qualifiers = qualifiers if qualifiers is not None else [
        importlib.import_module(f'native_pe_semantic_{family}') for family in FAMILIES]
    claims = []
    identities = set()
    for qualifier in qualifiers:
        family = qualifier.publish_evidence(root, index, ledger, collect_only=True)
        assert family, 'A selected qualifier published no contracts'
        for claim in family:
            assert claim['semantic_status'] in CLOSED_STATES and claim['submitted_route'] == 'verified'
            validate_evidence(claim)
            key = contract_key(claim)
            assert key not in identities, 'Overlapping semantic family claims'
            identities.add(key)
            claims.append(claim)
    assert claims, 'No semantic claims to publish'
    path = evidence_path or ROOT / 'docs/native-pe/evidence.json'
    maintained = json.loads(path.read_bytes())
    prior_keys = [contract_key(row) for row in maintained['entries']]
    assert len(prior_keys) == len(set(prior_keys)), 'Duplicate maintained evidence'
    maintained['entries'] = [row for row in maintained['entries']
                             if contract_key(row) not in identities] + claims
    atomic_write(path, json.dumps(maintained, indent=2) + '\n')
    print(f'Published {len(claims)} independently checked contracts atomically.')
    return len(claims)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', required=True, type=Path)
    parser.add_argument('--source-index', required=True, type=Path)
    parser.add_argument('--ledger', required=True, type=Path)
    args = parser.parse_args()
    publish(args.root.resolve(), args.source_index.resolve(), args.ledger.resolve())
