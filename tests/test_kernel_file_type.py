"""Native file object-type identity, export coherence and rejected misuse."""
import json
import tempfile
import unittest
from pathlib import Path
from emumee.driver import run_driver
from emumee.pe import inspect_pe
from emumee.persona import load_persona
from tests.test_kernel_process import process_probe
from tests.test_kernel_references import reference_probe, reference_bytes
from tests.test_kernel_system_information import image_range

MODES = ('read', 'missing', 'write', 'call', 'identity-read', 'identity-call', 'handle-mismatch')
EXPORTS = {'IoFileObjectType':'File', 'IoDriverObjectType':'Driver',
           'PsThreadType':'Thread', 'PsProcessType':'Process',
           'MmSectionObjectType':'Section', 'ExEventObjectType':'Event',
           'ExSemaphoreObjectType':'Semaphore', 'SeTokenObjectType':'Token',
           'TmEnlistmentObjectType':'TmEnlistment',
           'TmResourceManagerObjectType':'TmResourceManager',
           'TmTransactionManagerObjectType':'TmTransactionManager',
           'TmTransactionObjectType':'TmTransaction'}


def file_type_probe(machine, mode, export_name='IoFileObjectType'):
    if mode == 'handle-mismatch':
        return reference_probe(machine, mode, 'IoFileObjectType')
    return process_probe(machine, mode, export_name)


def verify_file_type(result, report, root, machine, mode, export_name='IoFileObjectType'):
    width = 8 if machine == 0x8664 else 4
    refs = report['kernel_object_references']
    assert set(refs['types']) == set(EXPORTS.values())
    assert len({v['identity'] for v in refs['types'].values()}) == len(EXPORTS)
    assert len({v['storage'] for v in refs['types'].values()}) == len(EXPORTS)
    entry = refs['types'][EXPORTS[export_name]]
    storage, identity = int(entry['storage'],0), int(entry['identity'],0)
    assert storage != identity and identity >= (0xffff800000000000 if width == 8 else 0x80000000)
    if mode == 'handle-mismatch':
        data = reference_bytes(result,root)
        assert result['guest_entry_return'] == 0 and not result['errors']
        assert int.from_bytes(data[0x308:0x308+width],'little') == identity
        assert int.from_bytes(data[0x320:0x324],'little') == 0xc0000024
        assert refs['events'][-1]['references_after'] == 0 and data[0x3f8:0x3fc] == b'DONE'
        return
    data = image_range(result,root,0x2300,0x100)
    value = lambda n:int.from_bytes(data[n:n+width],'little')
    assert value(0x10) == value(0x20) == storage
    assert value(0x18) == value(0x28) == identity
    assert value(0x30) != identity and value(0x38) == 4 and value(0x40) == 0
    assert len(refs['events']) == 2 and all(v['object'] == hex(value(0x30)) for v in refs['events'])
    assert refs['events'][0]['references_after'] == refs['events'][1]['references_after']+1
    if mode == 'missing':
        assert value(0x50) == 0
    else:
        assert value(0x50) == storage and value(0x58) == identity
    segments = [segment for run in report['entry_points'] for module in run['memory']['modules']
                for segment in module['segments'] if int(segment['address'],0) <= storage <
                int(segment['address'],0)+int(segment['size'],0)]
    assert segments and all(v['prot'] == 'r--' for v in segments)
    if mode in ('read','missing'):
        assert result['guest_entry_return'] == 0 and not result['errors'] and data[0xf8:0xfc] == b'DONE'
    else:
        assert result['guest_entry_return'] is None and result['errors'] and data[0xf8:0xfc] == b'COLD'
        error = report['entry_points'][0]['error']
        expected = {'write':'invalid_protect_write','call':'invalid_execute',
                    'identity-read':'invalid_protect_read','identity-call':'invalid_execute'}[mode]
        assert error['type'] == expected
        assert int(error['address'],0) == (identity if mode.startswith('identity-') else storage)


class KernelFileTypeTests(unittest.TestCase):
    def probe(self,mode):
        for export_name in (('IoFileObjectType',) if mode=='handle-mismatch' else EXPORTS):
            for machine in (0x14c,0x8664):
                with self.subTest(machine=machine,mode=mode,export=export_name), tempfile.TemporaryDirectory() as d:
                    root = Path(d)
                    payload = file_type_probe(machine,mode,export_name)
                    result = run_driver(payload,inspect_pe(payload,'file-type.sys'),load_persona(None),root,5,10000)
                    verify_file_type(result,json.loads((root/'engine-report.json').read_text()),root,machine,mode,export_name)
    def test_import_dynamic_and_binary_lookup_share_type_identity(self):self.probe('read')
    def test_missing_binary_export_stays_absent(self):self.probe('missing')
    def test_export_write_stops_before_marker(self):self.probe('write')
    def test_export_execute_stops_before_marker(self):self.probe('call')
    def test_opaque_identity_read_stops_before_marker(self):self.probe('identity-read')
    def test_opaque_identity_execute_stops_before_marker(self):self.probe('identity-call')
    def test_file_type_rejects_thread_handle_without_losing_reference(self):self.probe('handle-mismatch')
