"""Observe frozen lstrlen handlers through four AST-extracted methods and fake memory.

No Speakeasy imports, PE loading, guest instructions or native exports run here.
The legacy source hash must match the frozen inventory before any method runs.
"""
from __future__ import annotations

import argparse
import ast
import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
SOURCE = 'src/emumee/winstrings.py'
METHODS = {'__init__', '_access', '_read', '_length'}
BASE, SIZE, LIMIT = 0x1000, 0x10000, 32767


def handler():
    source = (ROOT / SOURCE).read_bytes()
    baseline = json.loads((ROOT / 'rust/api-parity/legacy-inventory.json').read_bytes())
    assert hashlib.sha256(source).hexdigest() == baseline['sources'][SOURCE], 'Frozen handler changed'
    tree = ast.parse(source)
    cls, = [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'GuestStrings']
    cls = copy.deepcopy(cls)
    cls.body = [n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name in METHODS]
    assert {n.name for n in cls.body} == METHODS
    namespace = {'common': SimpleNamespace(PERM_MEM_READ=1), 'MAX_CHARS': LIMIT}
    exec(compile(ast.Module(body=[cls], type_ignores=[]), SOURCE, 'exec'), namespace)
    return namespace['GuestStrings'], hashlib.sha256(source).hexdigest()


class Memory:
    def __init__(self, readable=True):
        self.memory = bytearray(SIZE)
        self.readable = readable
        self.last_error = 0x12345678

    def get_address_map(self, address):
        if BASE <= address < BASE + SIZE:
            return SimpleNamespace(base=BASE, size=SIZE, free=False, prot=int(self.readable))
        return None

    def mem_read(self, address, size):
        assert BASE <= address and address + size <= BASE + SIZE
        return bytes(self.memory[address - BASE:address - BASE + size])


def specifications(wide, bits):
    unit = b'A\0' if wide else b'A'
    cases = [dict(label='null', address=0, patches=[]),
             dict(label='unmapped', address=BASE + SIZE, patches=[]),
             dict(label='overflow', address=(1 << bits) - 1, patches=[]),
             dict(label='unreadable', address=BASE, patches=[], readable=False)]
    def add(label, data, repeat=1, address=BASE):
        cases.append(dict(label=label, address=address,
                          patches=[dict(address=address, hex=data.hex(), repeat=repeat)]))
    if wide:
        for value in [0, 1, 0x7f, 0x80, 0xff, 0x7ff, 0x800, 0xd7ff,
                      0xd800, 0xdbff, 0xdc00, 0xdfff, 0xe000, 0xffff]:
            add(f'unit-{value:04x}', value.to_bytes(2, 'little'))
        add('surrogate-pair', bytes.fromhex('3dd800de'))
        add('reversed-surrogates', bytes.fromhex('00de3dd8'))
        add('odd-address', b'A\0', address=BASE + 1)
        add('boundary-half-unit', b'A', address=BASE + SIZE - 1)
        add('embedded-null', b'A\0\0\0B\0')
    else:
        for value in range(256):
            add(f'byte-{value:02x}', bytes([value]))
        add('embedded-null', b'A\0B')
    for length in [LIMIT - 1, LIMIT, LIMIT + 1]:
        add(f'length-{length}', unit, repeat=length)
    return cases


def observe():
    factory, source_hash = handler()
    cases = []
    for width in [4, 8]:
        for wide in [False, True]:
            export = 'lstrlenW' if wide else 'lstrlenA'
            for spec in specifications(wide, width * 8):
                memory = Memory(spec.get('readable', True))
                for patch in spec['patches']:
                    data = bytes.fromhex(patch['hex']) * patch['repeat']
                    offset = patch['address'] - BASE
                    assert 0 <= offset <= SIZE and len(data) <= SIZE - offset
                    memory.memory[offset:offset + len(data)] = data
                before = bytes(memory.memory)
                result = factory()._length(memory, export, None, [spec['address']])
                assert before == memory.memory, 'Read-only handler modified synthetic memory'
                cases.append(dict(module='kernel32', export=export, width=width, **spec,
                                  result=result, last_error=memory.last_error,
                                  memory_sha256=hashlib.sha256(memory.memory).hexdigest()))
    return dict(schema=1, reference_sha256=source_hash,
                oracle='Four frozen AST methods over bounded synthetic memory; no external imports',
                cases=cases)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=ROOT / 'rust/emumee-engine/src/api/lstrlen_semantic_reference.json')
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    document = observe()
    if args.check:
        assert json.loads(args.output.read_bytes()) == document, 'Semantic reference drift'
    else:
        assert not args.output.exists(), 'Preserve existing observations; use --check'
        args.output.write_text(json.dumps(document, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(dict(cases=len(document['cases']), reference_sha256=document['reference_sha256'])))
