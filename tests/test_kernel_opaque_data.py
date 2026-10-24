"""Private HAL symbol metadata is discoverable; contents remain unimplemented."""
import json,struct,tempfile,unittest
from pathlib import Path
from emumee.driver import run_driver
from emumee.pe import inspect_pe
from emumee.persona import load_persona
from tests.test_kernel_process import process_probe
from tests.test_kernel_system_information import image_range

MODES=('lookup','missing','read','offset-read','write','call','api-read','api-write','valid')


def opaque_probe(machine,mode):
    wide=machine==0x8664;base,width=(0x140000000,8) if wide else (0x400000,4)
    rex=b'\x48' if wide else b''
    load=lambda rva:rex+b'\xa1'+(base+rva).to_bytes(width,'little')
    operations=[];writes=[]
    if mode in ('read','offset-read'):
        code=load(0x2350)
        if mode=='offset-read':code+=rex+b'\x83\xc0\x10'
        operations.append(('raw',code+rex+b'\x8b\x00'))
    if mode in ('api-read','api-write','valid'):
        api={'api-read':'RtlCompareMemory','api-write':'RtlInitUnicodeString','valid':'MmIsAddressValid'}[mode]
        text=api.encode('utf-16le')
        writes.extend([(0x2a20,struct.pack('<HH',len(text),len(text)+2)+(bytes(4) if wide else b'')+(base+0x2a40).to_bytes(width,'little')),
                       (0x2a40,text+bytes(2)),(0x2b00,'fixture\0'.encode('utf-16le'))])
        operations.append((1,[base+0x2a20],0x2900+7*width))
        args=[('load',0x2350)]
        if mode=='api-read':args += [base+0x23b0,16]
        if mode=='api-write':args += [base+0x2b00]
        operations.append((7,args,0x2370))
    return process_probe(machine,mode,'HalPrivateDispatchTable',read_data=False,
        post_operations=operations,extra_writes=writes)


def verify_opaque(result,report,root,machine,mode):
    width=8 if machine==0x8664 else 4
    data=image_range(result,root,0x2300,0x100);value=lambda n:int.from_bytes(data[n:n+width],'little')
    state=report['kernel_opaque_data'];address=int(state['address'],0)
    assert state['permissions']=='---' and state['layout_version'] is None and state['field_values_exposed'] is False
    assert value(0x10)==value(0x20)==address and value(0x18)==value(0x28)==0
    assert value(0x50)==(0 if mode=='missing' else address)
    assert value(0x58)==0
    if mode in ('lookup','missing','valid'):
        assert result['guest_entry_return']==0 and not result['errors'] and data[0xf8:0xfc]==b'DONE'
        if mode=='valid':assert value(0x70)==1
    else:
        assert result['guest_entry_return'] is None and result['errors'] and data[0xf8:0xfc]==b'COLD'
        error=report['entry_points'][0]['error']
        if mode.startswith('api-'):
            assert state['api_denials'] and state['api_denials'][-1]['access']==('read' if mode=='api-read' else 'write')
            assert 'Unmodeled kernel data HalPrivateDispatchTable' in error['context_summary']
        else:
            access='read' if mode in ('read','offset-read') else 'write' if mode=='write' else 'execute'
            assert error['type']=='unmodeled_kernel_data_'+access
            assert error['api_name']=='ntoskrnl.HalPrivateDispatchTable'
            assert int(error['address'],0)==address+(16 if mode=='offset-read' else 0)
    segments=[segment for run in report['entry_points'] for module in run['memory']['modules']
        for segment in module['segments'] if int(segment['address'],0)<=address<
        int(segment['address'],0)+int(segment['size'],0)]
    assert segments and all(v['prot']=='---' for v in segments)


class KernelOpaqueDataTests(unittest.TestCase):
    def probe(self,mode):
        for machine in (0x14c,0x8664):
            with self.subTest(machine=machine,mode=mode),tempfile.TemporaryDirectory() as d:
                root=Path(d);payload=opaque_probe(machine,mode)
                result=run_driver(payload,inspect_pe(payload,'opaque-data.sys'),load_persona(None),root,5,10000)
                verify_opaque(result,json.loads((root/'engine-report.json').read_text()),root,machine,mode)
    def test_import_dynamic_and_native_binary_lookup_share_metadata_address(self):self.probe('lookup')
    def test_missing_binary_export_stays_absent(self):self.probe('missing')
    def test_native_read_stops_with_private_field_offset(self):
        self.probe('read');self.probe('offset-read')
    def test_native_write_stops_before_marker(self):self.probe('write')
    def test_native_execute_stops_before_marker(self):self.probe('call')
    def test_api_read_cannot_bypass_unmodeled_memory(self):self.probe('api-read')
    def test_api_write_cannot_bypass_unmodeled_memory(self):self.probe('api-write')
    def test_address_validity_does_not_expose_private_contents(self):self.probe('valid')
