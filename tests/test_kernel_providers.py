"""Native metadata discovery must never invent provider function execution."""

import json
import struct
import tempfile
import unittest
from pathlib import Path

from emumee.driver import run_driver
from emumee.pe import inspect_pe
from emumee.persona import load_persona
from tests.test_kernel_objects import call_driver
from tests.test_kernel_system_information import image_range


def provider_metadata_probe(machine, provider='ci', mode='read'):
    wide = machine == 0x8664
    base, width = (0x140000000, 8) if wide else (0x400000, 4)
    rex = b'\x48' if wide else b''
    load = lambda rva: (b'\x48\xa1' if wide else b'\xa1') + (base + rva).to_bytes(width, 'little')
    store = lambda rva: (b'\x48\xa3' if wide else b'\xa3') + (base + rva).to_bytes(width, 'little')
    code = bytearray(load(0x2310) + rex + b'\x89\xc2')
    labels, jumps = {}, []
    def branch(opcode, label):
        opcode = b'\x0f\x84' if opcode == b'\x74' else b'\xe9'
        code.extend(opcode + bytes(4))
        jumps.append((len(code) - 4, label))
    labels['loop'] = len(code)
    code.extend(bytes.fromhex('66833a00'))
    branch(b'\x74', 'missing')
    code.extend(bytes.fromhex('0fb74a') + bytes([0x2E if wide else 0x1E]))
    code.extend(rex + bytes.fromhex('8d740a') + bytes([0x30 if wide else 0x20]))
    code.extend(b'\x66\x81\x3e' + (b'ci' if provider == 'ci' else b'cn'))
    branch(b'\x74', 'found')
    code.extend(bytes.fromhex('0fb70a') + rex + bytes.fromhex('01ca'))
    branch(b'\xeb', 'loop')
    labels['missing'] = len(code)
    code.extend(b'\xb8' + struct.pack('<I', 0xC000007A))
    branch(b'\xeb', 'end')
    labels['found'] = len(code)
    code.extend(rex + bytes.fromhex('8b42') + bytes([0x18 if wide else 0x0C]) + store(0x2320))
    code.extend(bytes.fromhex('0fb70889c8') + store(0x2328) + load(0x2320))
    code.extend(bytes.fromhex('8b483c'))
    code.extend(bytes.fromhex('8b8c08') + struct.pack('<I', 0x88 if wide else 0x78))
    code.extend(rex + bytes.fromhex('8d0c08'))
    code.extend(bytes.fromhex('8b5120') + rex + bytes.fromhex('8d14108b12') + rex + bytes.fromhex('8d1410'))
    code.extend(rex + bytes.fromhex('89d0') + store(0x2330) + load(0x2320))
    code.extend(bytes.fromhex('8b511c') + rex + bytes.fromhex('8d14108b12') + rex + bytes.fromhex('8d1410'))
    code.extend(rex + bytes.fromhex('89d0') + store(0x2340))
    if mode == 'call':
        code.extend(bytes.fromhex('ffd0'))
    elif mode == 'write':
        code.extend(load(0x2320) + b'\xc7\x00NOPE')
    else:
        code.extend(bytes.fromhex('0fb600') + store(0x2348))
    code.extend(b'\xb8DONE' + store(0x23F8) + b'\x31\xc0')
    labels['end'] = len(code)
    for offset, label in jumps:
        code[offset:offset + 4] = struct.pack('<i', labels[label] - offset - 4)
    return call_driver(machine, ['ZwQuerySystemInformation', 'ExAllocatePoolWithTag'],
        [(0, [77, 0, 0, base + 0x2300], 0x2380),
         (1, [0, ('load', 0x2300), 0x50524F56], 0x2310),
         (0, [77, ('load', 0x2310), ('load', 0x2300), 0], 0x2388), ('raw', bytes(code))])


def verify_provider_metadata(result, report, root, machine, provider, mode):
    width = 8 if machine == 0x8664 else 4
    data = image_range(result, root, 0x2300, 0x100)
    value = lambda offset: int.from_bytes(data[offset:offset + width], 'little')
    metadata = report['kernel_provider_metadata']
    assert {item['name'] for item in metadata} == {'ci.dll', 'cng.sys'}
    item = next(item for item in metadata if item['name'] == ('ci.dll' if provider == 'ci' else 'cng.sys'))
    assert item['permissions'] == 'r--' and not item['executable']
    assert value(0x20) == int(item['base'], 0) and value(0x28) == 0x5A4D
    assert value(0x40) == int(item['named_exports'][0]['address'], 0)
    assert item['named_exports'][0]['name'] == ('CiCheckSignedFile' if provider == 'ci' else 'BCryptAddContextFunctionProvider')
    assert item['named_exports'][0]['ordinal'] == (4 if provider == 'ci' else 1)
    mappings = [row for entry in report['entry_points'] for row in entry['memory']['layout']
                if int(row['address'], 0) == int(item['base'], 0)]
    assert mappings and all(row['prot'] == 'r--' for row in mappings)
    if mode == 'read':
        assert result['guest_entry_return'] == 0 and result['errors'] == []
        assert value(0x48) == 0xCC and data[0xF8:0xFC] == b'DONE'
    else:
        assert result['guest_entry_return'] is None and result['errors']
        error = report['entry_points'][0]['error']
        assert error['type'] == ('invalid_execute' if mode == 'call' else 'invalid_protect_write')
        assert int(error['address'], 0) == value(0x40 if mode == 'call' else 0x20)
        assert data[0xF8:0xFC] != b'DONE'
    assert not any(event.get('api_name', '').startswith(('ci.', 'cng.'))
                   for entry in report['entry_points'] for event in entry['events'])


class KernelProviderMetadataTests(unittest.TestCase):
    def check_mode(self, mode):
        for machine in (0x14C, 0x8664):
            for provider in ('ci', 'cng'):
                with self.subTest(machine=machine, provider=provider), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    payload = provider_metadata_probe(machine, provider, mode)
                    result = run_driver(payload, inspect_pe(payload, 'provider-metadata.sys'), load_persona(None), root, 5, 3000)
                    report = json.loads((root / 'engine-report.json').read_text())
                    verify_provider_metadata(result, report, root, machine, provider, mode)

    def test_native_module_and_export_metadata_discovery(self):
        self.check_mode('read')

    def test_native_provider_calls_stop_without_fabricating_results(self):
        self.check_mode('call')

    def test_native_provider_writes_stop_without_following_marker(self):
        self.check_mode('write')
