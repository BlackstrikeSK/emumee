"""Authenticated names expose missing operations without fabricated behavior."""
import json,struct,tempfile,unittest
from pathlib import Path
from emumee.driver import run_driver
from emumee.pe import inspect_pe
from emumee.persona import load_persona
from emumee.kernel_export_names_22631 import CODE_EXPORTS,DATA_EXPORTS,SOURCE_SHA256
from tests.test_kernel_process import process_probe,verify_process
from tests.test_kernel_file_type import file_type_probe,verify_file_type
from tests.test_kernel_user_bounds import bounds_probe,verify_bounds
from tests.test_kernel_system_information import image_range

MODES=('lookup-code','lookup-data','missing','call-code','read-code','write-code',
       'read-data','offset-data','write-data','call-data','api-read','api-write',
       'known-code','known-process','known-file-type','known-boundary','distinct')
NEGATIVE={'call-code','read-code','write-code','read-data','offset-data','write-data',
          'call-data','api-read','api-write'}


def catalog_probe(mode):
    machine=0x8664;base=0x140000000
    if mode=='known-process':return process_probe(machine)
    if mode=='known-file-type':return file_type_probe(machine,'read')
    if mode=='known-boundary':return bounds_probe(machine,'read','MmUserProbeAddress')
    name=('ExCreateCallback' if mode=='known-code' else 'IoCreateDriver'
          if mode in ('lookup-code','missing','call-code','read-code','write-code','distinct')
          else 'PsLoadedModuleList')
    native_mode='missing' if mode=='missing' else 'call' if mode in ('call-code','call-data') else 'write' if mode in ('write-code','write-data') else 'lookup'
    load=lambda rva:b'\x48\xa1'+(base+rva).to_bytes(8,'little')
    operations=[];writes=[]
    if mode in ('read-code','read-data','offset-data'):
        operations=[('raw',load(0x2350)+(b'\x48\x83\xc0\x10' if mode=='offset-data' else b'')+b'\x48\x8b\x00')]
    if mode in ('api-read','api-write','distinct'):
        api='RtlCompareMemory' if mode=='api-read' else 'RtlInitUnicodeString' if mode=='api-write' else 'PsLoadedModuleList'
        text=api.encode('utf-16le')
        writes=[(0x2a20,struct.pack('<HH',len(text),len(text)+2)+bytes(4)+(base+0x2a40).to_bytes(8,'little')),
                (0x2a40,text+bytes(2)),(0x2b00,'fixture\0'.encode('utf-16le'))]
        if mode=='distinct':
            operations=[(1,[base+0x2a20],0x2370)]
        else:
            operations=[(1,[base+0x2a20],0x2900+7*8),
                (7,[('load',0x2350),base+(0x23b0 if mode=='api-read' else 0x2b00)]+([8] if mode=='api-read' else []),0x2370)]
    return process_probe(machine,native_mode,name,read_data=False,post_operations=operations,extra_writes=writes)


def verify_catalog(result,report,root,mode):
    state=report['kernel_export_catalog']
    assert state['enabled'] and state['source_image_sha256']=='4b954aae4b18a231b2254c0989b1b6bcc55741a8ef90a350f036d09cd480cc99'
    assert state['named_reference_exports']==3257 and state['reference_code_symbols']==3180 and state['reference_data_symbols']==77
    address=int(state['address'],0);end=address+state['size']
    assert state['permissions']=='---' and state['size']==state['metadata_only_added']*4096
    assert state['code_metadata_added']>2000 and state['data_metadata_added']>10
    assert end<=0xfffff80201000000
    segments=[s for run in report['entry_points'] for m in run['memory']['modules'] for s in m['segments']
              if int(s['address'],0)<=address<int(s['address'],0)+int(s['size'],0)]
    assert segments and all(s['prot']=='---' for s in segments)
    if mode in ('known-process','known-file-type','known-boundary'):
        if mode=='known-process':verify_process(result,report,root,0x8664,'read')
        elif mode=='known-file-type':verify_file_type(result,report,root,0x8664,'read')
        else:verify_bounds(result,report,root,0x8664,'read','MmUserProbeAddress',22631)
        assert not state['denials'];return
    data=image_range(result,root,0x2300,0x100)
    ptr=lambda n:int.from_bytes(data[n:n+8],'little')
    assert ptr(0x10)==ptr(0x20) and ptr(0x10)!=0
    assert ptr(0x50)==(0 if mode=='missing' else ptr(0x10))
    if mode=='known-code':
        assert not address<=ptr(0x10)<end
    else:
        assert address<=ptr(0x10)<end and not ptr(0x10)&4095
    if mode in NEGATIVE:
        assert result['guest_entry_return'] is None and result['errors'] and data[0xf8:0xfc]==b'COLD'
        item=state['denials'][-1];error=report['entry_points'][0]['error']
        code=mode.endswith('code')
        name='IoCreateDriver' if code else 'PsLoadedModuleList'
        assert item['name']==name and item['kind']==('code' if code else 'data')
        if mode.startswith('api-'):
            assert name in error['context_summary']
            assert item['access']==('read' if mode=='api-read' else 'write')
        else:
            offset=16 if mode=='offset-data' else 0
            access='execute' if mode.startswith('call-') else 'write' if mode.startswith('write-') else 'read'
            expected='unsupported_kernel_api' if code and access=='execute' else ('unmodeled_kernel_function_' if code else 'unmodeled_kernel_data_')+access
            assert error['type']==expected and error['api_name']=='ntoskrnl.'+name
            assert int(error['address'],0)==ptr(0x10)+offset and item['offset']==offset
    else:
        assert result['guest_entry_return']==0 and not result['errors'] and data[0xf8:0xfc]==b'DONE'
        assert not state['denials']
        if mode=='distinct':
            assert ptr(0x70) and ptr(0x70)!=ptr(0x10) and address<=ptr(0x70)<end and not ptr(0x70)&4095


class KernelExportCatalogTests(unittest.TestCase):
    def probe(self,*modes):
        for mode in modes:
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as d:
                root=Path(d);payload=catalog_probe(mode)
                result=run_driver(payload,inspect_pe(payload,'catalog.sys'),load_persona(None),root,10,20000)
                verify_catalog(result,json.loads((root/'engine-report.json').read_text()),root,mode)
    def test_pinned_classified_names_have_no_duplicates(self):
        self.assertEqual(len(CODE_EXPORTS),3180);self.assertEqual(len(DATA_EXPORTS),77)
        self.assertEqual(len(set(CODE_EXPORTS+DATA_EXPORTS)),3257)
        self.assertIn('IoCreateDriver',CODE_EXPORTS);self.assertIn('PsLoadedModuleList',DATA_EXPORTS)
        self.assertEqual(SOURCE_SHA256,'4b954aae4b18a231b2254c0989b1b6bcc55741a8ef90a350f036d09cd480cc99')
    def test_import_dynamic_and_native_lookup_agree(self):self.probe('lookup-code','lookup-data','missing')
    def test_unknown_function_call_stops_with_its_name(self):self.probe('call-code')
    def test_function_byte_reads_and_writes_are_unmodeled(self):self.probe('read-code','write-code')
    def test_data_reads_writes_offsets_and_calls_are_unmodeled(self):self.probe('read-data','offset-data','write-data','call-data')
    def test_api_memory_helpers_cannot_bypass_data_guard(self):self.probe('api-read','api-write')
    def test_known_api_retains_its_implemented_address(self):self.probe('known-code')
    def test_existing_system_process_identity_is_preserved(self):self.probe('known-process')
    def test_existing_object_types_are_preserved(self):self.probe('known-file-type')
    def test_existing_address_boundary_is_preserved(self):self.probe('known-boundary')
    def test_metadata_symbols_have_distinct_protected_pages(self):self.probe('distinct')
    def test_x86_and_other_build_profiles_do_not_use_this_catalog(self):
        for machine,build in ((0x14c,22631),(0x8664,22000),(0x8664,7601)):
            with self.subTest(machine=machine,build=build),tempfile.TemporaryDirectory() as d:
                root=Path(d);payload=process_probe(machine);persona=load_persona(None);persona['windows_build']=build
                result=run_driver(payload,inspect_pe(payload,'catalog-disabled.sys'),persona,root,10,20000)
                report=json.loads((root/'engine-report.json').read_text());verify_process(result,report,root,machine,'read')
                state=report['kernel_export_catalog']
                assert not state['enabled'] and state['metadata_only_added']==0 and state['address'] is None
