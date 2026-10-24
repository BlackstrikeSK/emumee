"""Compare owned HTTP documents with the legacy parser; no network execution."""
import argparse
import copy
import importlib.util
import json
import subprocess
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('--bundle', required=True)
parser.add_argument('--output-root', required=True)
args = parser.parse_args()
root = Path(args.output_root).resolve()
root.mkdir(exist_ok=False)
exe = Path(args.bundle).resolve() / 'emumee-rs.exe'
spec = importlib.util.spec_from_file_location('legacy_http_fixtures', Path(__file__).resolve().parents[1] / 'src/emumee/networkfixtures.py')
legacy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(legacy)
base = {'version': 1, 'rules': [{'request': {'method': 'POST', 'url': 'https://fixture.invalid:443/a%2fb?q=One', 'chunked': True, 'headers': [['X-Straße', 'One'], ['Content-Type', 'binary']], 'body_base64': 'AP8QgA=='}, 'response': {'status': 206, 'reason': 'Partial', 'version': 'HTTP/1.0', 'headers': [['Set-Cookie', 'one'], ['Set-Cookie', 'two']], 'body_utf8': 'Rúst\0'}}]}
cases = [('binary-unicode-headers', base)]
for name, part, field, value in [
    ('empty-request', 'request', 'body_base64', ''),
    ('empty-response', 'response', 'body_utf8', ''),
    ('headers-object', 'request', 'headers', {'X-Test': 'Exact'}),
    ('response-object', 'response', 'headers', {'Z-Last': 'one', 'A-First': 'two'}),
    ('ipv6', 'request', 'url', 'http://[::1]:8080/a'),
    ('unicode-url', 'request', 'url', 'https://fixture.invalid/ž?q=One'),
    ('bad-body-bits', 'request', 'body_base64', 'AP8QgB=='),
    ('body-whitespace', 'request', 'body_base64', 'AP8Q gA=='),
    ('missing-padding', 'request', 'body_base64', 'AP8QgA'),
    ('duplicate-header', 'request', 'headers', [['Straße', 'a'], ['STRASSE', 'b']]),
    ('header-injection', 'response', 'headers', [['x', 'a\r\nb']]),
    ('bad-status-bool', 'response', 'status', True),
    ('bad-status-float', 'response', 'status', 200.0),
    ('bad-status-range', 'response', 'status', 1000),
    ('bad-version', 'response', 'version', 'HTTP/2'),
    ('bad-chunked', 'request', 'chunked', 1),
    ('bad-method', 'request', 'method', 'post'),
    ('bad-port', 'request', 'url', 'http://fixture.invalid:65536/'),
    ('empty-port', 'request', 'url', 'http://fixture.invalid:/'),
    ('bad-scheme', 'request', 'url', 'file:///x'),
    ('header-size', 'response', 'headers', [['x', 'a' * 16384]]),
]:
    document = copy.deepcopy(base)
    document['rules'][0][part][field] = value
    cases.append((name, document))
for name, count in [('empty-rules', 0), ('duplicate-rules', 2), ('too-many-rules', 33)]:
    cases.append((name, {'version': 1, 'rules': [copy.deepcopy(base['rules'][0]) for _ in range(count)]}))
both = copy.deepcopy(base)
both['rules'][0]['request']['body_utf8'] = ''
cases.append(('two-bodies', both))
ordered = copy.deepcopy(base)
ordered['rules'][0]['response']['headers'] = {'Z-Last': 'one', 'A-First': 'two'}
cases.append(('duplicate-object-header', json.dumps(ordered, ensure_ascii=False).replace('"Z-Last": "one"', '"Z-Last": "old", "Z-Last": "one"').encode('utf-8')))
many = copy.deepcopy(base)
many['rules'] = []
for index in range(32):
    rule = copy.deepcopy(base['rules'][0])
    rule['request']['url'] += '&rule=' + str(index)
    many['rules'].append(rule)
cases.append(('max-distinct-rules', many))
records = []
for name, document in cases:
    raw = document if isinstance(document, bytes) else json.dumps(document, ensure_ascii=False).encode('utf-8')
    source = root / (name + '.json')
    source.write_bytes(raw)
    try:
        expected = json.loads(legacy.public_fixture_document(legacy.parse_network_fixtures(raw)))
    except ValueError:
        expected = None
    result = subprocess.run([str(exe), 'inspect-network-fixtures', str(source), '--normalized'], capture_output=True, check=False)
    (root / (name + '.stdout.txt')).write_bytes(result.stdout)
    (root / (name + '.stderr.txt')).write_bytes(result.stderr)
    if expected is None:
        assert result.returncode == 2, (name, result.returncode, result.stderr)
    else:
        assert result.returncode == 0, (name, result.stderr)
        assert json.loads(result.stdout) == expected, name
    assert source.read_bytes() == raw, name
    records.append({'case': name, 'accepted': expected is not None, 'exit': result.returncode, 'normalized_matches_python': expected is not None, 'source_unchanged': True, 'verified': True})
(root / 'verification.json').write_text(json.dumps(records, indent=2) + '\n')
print(f'Verified {len(records)} owned HTTP schema controls against the legacy parser, without networking.')
