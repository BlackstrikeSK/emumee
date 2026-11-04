"""Cheap read-only status for native PE contracts and dependency-ready batches."""
import argparse
import json
from pathlib import Path

from native_pe_batches import expand_worklist, validate_partition
from native_pe_worklist import changed_sources, completion, fingerprint, runtime_snapshot, validate_batch_graph


def ready_batches(worklist):
    batches = validate_batch_graph(worklist)
    return [batch for batch in batches.values()
            if batch['status'] in ('pending', 'in_progress') and not batch.get('blocker')
            and all(batches[dependency]['status'] == 'closed'
                    for dependency in batch['depends_on'])]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ledger', type=Path, required=True)
    parser.add_argument('--evidence', type=Path,
                        default=Path(__file__).resolve().parents[1] / 'docs/native-pe/evidence.json')
    parser.add_argument('--partition', type=Path,
                        default=Path(__file__).resolve().parents[1] / 'docs/native-pe/api-batches.json')
    parser.add_argument('--worklist', type=Path,
                        default=Path(__file__).resolve().parents[1] / 'docs/native-pe/worklist.json')
    args = parser.parse_args()
    ledger = json.loads(args.ledger.read_text(encoding='utf-8-sig'))
    if any(field not in ledger for field in ('inventory_fingerprint', 'partition_fingerprint')):
        parser.error('Ledger predates exact partition accounting; regenerate it with native_api_parity_ledger.py')
    worklist = json.loads(args.worklist.read_text(encoding='utf-8-sig'))
    root = Path(__file__).resolve().parents[1]
    changed = changed_sources(root, ledger['source_hashes'])
    current = runtime_snapshot(root)
    expected = ledger['runtime_source_hashes']
    maintained = json.loads(args.evidence.read_text(encoding='utf-8-sig'))
    evidence_changed = fingerprint(maintained) != ledger['maintained_evidence_fingerprint']
    partition_document = json.loads(args.partition.read_text(encoding='utf-8-sig'))
    try:
        validate_partition(partition_document, ledger['entries'], ledger['inventory_fingerprint'])
    except ValueError as error:
        parser.error(str(error))
    partition_changed = fingerprint(partition_document) != ledger['partition_fingerprint']
    changed += [name for name in sorted(set(current) | set(expected))
                if current.get(name) != expected.get(name)]
    stale = 0
    if changed:
        for row in ledger['entries']:
            if row['semantic_status'] not in ('unreviewed', 'missing', 'blocked', 'stale'):
                stale += 1
                row['semantic_status'] = 'stale'
                row['submitted_route'] = 'unreviewed'
    status = completion(ledger['entries'], ledger['inventory_unresolved'], ledger['required_gates'])
    worklist = expand_worklist(worklist, partition_document, ledger['entries'])
    status['complete'] = status['complete'] and not changed and not evidence_changed and not partition_changed and all(batch['status'] == 'closed' for batch in worklist['batches'])
    status['changed_sources'] = changed
    status['maintained_evidence_changed'] = evidence_changed
    status['partition_changed'] = partition_changed
    status['api_batches'] = len(partition_document['batches'])
    status['newly_stale_contracts'] = stale
    status['ready_batches'] = [{'id': batch['id'], 'next_action': batch['next_action']}
                               for batch in ready_batches(worklist)]
    status['blocked_batches'] = [batch['id'] for batch in worklist['batches'] if batch.get('blocker')]
    print(json.dumps(status, indent=2))


if __name__ == '__main__':
    main()
