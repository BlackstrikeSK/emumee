"""Guest-empty unload history exposes only the two verified storage fields."""
import hashlib,json,struct,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from emumee import driver,kernel_code_reference
from emumee.pe import inspect_pe
from emumee.persona import load_persona
from tests.test_kernel_code_reference import generated_reference,reference_probe
from tests.test_kernel_system_information import image_range

POINTER_RVA=0xc13098
INDEX_RVA=0xc13090
MODES=('pointer','index','neighbor','padding','cross','write','call','api-read','api-neighbor','api-write')
NEGATIVE=set(MODES)-{'pointer','index','api-read'}

def history_reference():
    data=bytearray(generated_reference());struct.pack_into('<I',data,0x98+56,0xc14000)
    return bytes(data)

def history_probe(mode):
    selected=('call' if mode=='call' else 'write' if mode=='write' else
        'api-write' if mode=='api-write' else 'api-read' if mode in ('api-read','api-neighbor') else 'read')
    rva=(INDEX_RVA if mode=='index' else POINTER_RVA+8 if mode in ('neighbor','api-neighbor') else
        INDEX_RVA+4 if mode in ('padding','cross') else POINTER_RVA)
    payload=bytearray(reference_probe(selected,code_rva=rva,call_rva=rva))
    if mode in ('index','padding'):
        before=bytes(payload);after=before.replace(bytes.fromhex('488b00'),bytes.fromhex('8b0090'),1)
        assert before!=after;payload=bytearray(after)
    if mode=='api-read':payload[0xa00:0xa08]=bytes(8)
    return bytes(payload)

def verify_history(result,report,root,mode):
    reference=report['kernel_code_reference'];state=reference['guest_unload_history']
    assert state['enabled'] and state['recorded_image_unloads']==0
    assert {f['name']:f['value'] for f in state['fields']}=={'MmUnloadedDrivers':0,'MmLastUnloadedDriver':0}
    assert reference['execution_allowed'] is False
    data=image_range(result,root,0x2300,0x100)
    if mode in NEGATIVE:
        assert result['errors'] and result['guest_entry_return'] is None and data[0xf8:0xfc]==b'COLD'
        assert reference['denials']
        error=next(run['error'] for run in report['entry_points'] if run.get('error'))
        if mode in ('neighbor','padding','cross','api-neighbor'):
            assert reference['denials'][-1]['access']=='read'
    else:
        assert not result['errors'] and result['guest_entry_return']==0 and data[0xf8:0xfc]==b'DONE'
        assert int.from_bytes(data[0xc0:0xc8],'little')==(8 if mode=='api-read' else 0)
        if mode in ('pointer','index'):assert state['native_reads']>0
    assert not any(0xfffff80200000000+INDEX_RVA<=int(row['pc'],0)<0xfffff80200000000+POINTER_RVA+8
        for row in report['instruction_tail'])

class KernelUnloadedHistoryTests(unittest.TestCase):
    def test_driver_unload_callback_does_not_invent_an_image_unload_record(self):
        from tests.fixtures.build_driver import build_driver
        reference=history_reference();digest=hashlib.sha256(reference).hexdigest()
        layout=kernel_code_reference.KNOWN_GUEST_DATA_LAYOUTS[kernel_code_reference.KNOWN_REFERENCE_SHA256]
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);payload=build_driver(0x8664)
            with patch.dict(kernel_code_reference.KNOWN_GUEST_DATA_LAYOUTS,{digest:layout}):
                result=driver.run_driver(payload,inspect_pe(payload,'unload-callback.sys'),load_persona(None),root,20,20000,
                    kernel_code_reference=reference,unload=True)
            report=json.loads((root/'engine-report.json').read_text())
            self.assertTrue(result['driver']['unload_completed']);self.assertEqual(result['errors'],[])
            history=report['kernel_code_reference']['guest_unload_history']
            self.assertEqual(history['recorded_image_unloads'],0)
            self.assertTrue(all(field['value']==0 for field in history['fields']))
    def test_empty_session_fields_and_byte_guards_match_python_and_native(self):
        from tools.benchmark_driver_hooks import observations
        reference=history_reference();digest=hashlib.sha256(reference).hexdigest()
        layout=kernel_code_reference.KNOWN_GUEST_DATA_LAYOUTS[kernel_code_reference.KNOWN_REFERENCE_SHA256]
        for mode in MODES:
            rows=[]
            for native in (False,True):
                with self.subTest(mode=mode,native=native),tempfile.TemporaryDirectory() as directory:
                    root=Path(directory);payload=history_probe(mode)
                    factory=driver.create_native_trace if native else lambda _:None
                    # A declared generated layout tests the byte guards. Its
                    # provenance remains unverified; production binds only the
                    # actual reference digest and matching PDB field addresses.
                    with patch.dict(kernel_code_reference.KNOWN_GUEST_DATA_LAYOUTS,{digest:layout}),patch.object(driver,'create_native_trace',factory):
                        result=driver.run_driver(payload,inspect_pe(payload,'history.sys'),load_persona(None),root,20,20000,
                            kernel_code_reference=reference)
                    report=json.loads((root/'engine-report.json').read_text());verify_history(result,report,root,mode)
                    self.assertEqual(report['kernel_code_reference']['provenance'],'unverified_user_supplied_PE_data')
                    rows.append(observations(result,report))
            self.assertEqual(rows[0],rows[1],mode)

    def test_unbound_reference_does_not_expose_guest_history(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);payload=history_probe('pointer')
            result=driver.run_driver(payload,inspect_pe(payload,'unbound-history.sys'),load_persona(None),root,20,20000,
                kernel_code_reference=history_reference())
            report=json.loads((root/'engine-report.json').read_text())
            self.assertFalse(report['kernel_code_reference']['guest_unload_history']['enabled'])
            self.assertIsNone(result['guest_entry_return']);self.assertTrue(result['errors'])
