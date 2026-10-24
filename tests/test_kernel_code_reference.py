"""Generated references are inspection data, never kernel instructions/state."""
import copy,hashlib,json,struct,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from emumee.driver import run_driver
from emumee.pe import inspect_pe,InvalidSample
from emumee.persona import load_persona
from tests.fixtures.build_native import build
from tests.fixtures.build_driver import build_driver
from tests.test_kernel_objects import call_driver
from tests.test_kernel_system_information import image_range

CODE_RVA=0x40000
DATA_RVA=0x80000
MODES=('read','scan','relocation','call','write','private-read','api-read','api-write')
NEGATIVE={'call','write','private-read','api-write'}


def generated_reference():
    data=bytearray(build(0x8664));opt=0x98;sh=opt+0xf0;dd=opt+112
    struct.pack_into('<I',data,opt+16,0)
    struct.pack_into('<I',data,opt+20,CODE_RVA)
    struct.pack_into('<I',data,opt+56,DATA_RVA+4096)
    data[dd:dd+16*8]=bytes(16*8)
    struct.pack_into('<I',data,sh+12,CODE_RVA)
    struct.pack_into('<I',data,sh+8,0x200)
    struct.pack_into('<I',data,sh+52,DATA_RVA)
    data[0x200:0x400]=b'\xcc'*0x200
    data[0x200:0x208]=b'GENDCODE'
    data[0x220:0x228]=b'MATCHREF'
    data[0x380:0x386]=bytes.fromhex('b82a000000c3')
    struct.pack_into('<Q',data,0x300,0x140000000+DATA_RVA)
    data[0x400:0x420]=b'UNMODELED_PRIVATE_REFERENCE_DATA'
    struct.pack_into('<II',data,dd+5*8,DATA_RVA+0x100,12)
    struct.pack_into('<IIHH',data,0x500,CODE_RVA,12,(10<<12)|0x100,0)
    return bytes(data)


def exported_reference():
    """Harmless named code and data exports, with the same relocation fixture."""
    data=bytearray(generated_reference())
    struct.pack_into('<II',data,0x98+112,DATA_RVA+0x40,0xb0)
    struct.pack_into('<IIHHIIIIIII',data,0x440,0,0,0,0,0,1,4,4,
        DATA_RVA+0x70,DATA_RVA+0x80,DATA_RVA+0x90)
    struct.pack_into('<IIII',data,0x470,CODE_RVA+0x180,CODE_RVA+0x10,DATA_RVA,CODE_RVA+0x20)
    offset=0x498
    for index,name in enumerate(('IoCreateDriver','KeGetCurrentIrql','PsLoadedModuleList','PsSetContextThread')):
        struct.pack_into('<I',data,0x480+4*index,DATA_RVA+offset-0x400)
        struct.pack_into('<H',data,0x490+2*index,index)
        raw=name.encode()+b'\0';data[offset:offset+len(raw)]=raw;offset+=len(raw)
    assert offset<=0x4f0
    return bytes(data)


def exported_reference_probe(mode):
    from tests.test_kernel_process import process_probe
    base=0x140000000
    load=lambda rva:b'\x48\xa1'+struct.pack('<Q',base+rva)
    if mode=='read':post=[('raw',load(0x2350)+b'\x48\x8b\x00'+b'\x48\xa3'+struct.pack('<Q',base+0x2370))]
    elif mode=='api-read':post=[(1,[base+0x2a20],0x2900+7*8),(7,[('load',0x2350),base+0x2b00,6],0x2370)]
    else:post=[]
    return process_probe(0x8664,mode if mode in ('call','write') else 'lookup',
        'PsLoadedModuleList' if mode=='data' else 'IoCreateDriver',read_data=False,
        post_operations=post,extra_writes=[(0x2b00,bytes.fromhex('b82a000000c3')),
            (0x2a20,struct.pack('<HH',32,34)+bytes(4)+struct.pack('<Q',base+0x2a40)),
            (0x2a40,'RtlCompareMemory\0'.encode('utf-16le'))])


def verify_exported_reference(result,report,root,mode):
    state=report['kernel_code_reference'];catalog=report['kernel_export_catalog']
    data=image_range(result,root,0x2300,0x100)
    pointer=lambda offset:int.from_bytes(data[offset:offset+8],'little')
    assert state['file_backed_named_code_exports']==3 and catalog['reference_code_exports']==2
    assert state['execution_allowed'] is False and state['permissions']=='r--'
    assert pointer(0x10)==pointer(0x20)==pointer(0x50)
    if mode=='data':
        assert int(catalog['address'],0)<=pointer(0x50)<int(catalog['address'],0)+catalog['size']
    else:assert pointer(0x50)==0xfffff80200000000+CODE_RVA+0x180
    if mode in ('call','write'):
        assert result['errors'] and result['guest_entry_return'] is None and data[0xf8:0xfc]==b'COLD'
        error=next(run['error'] for run in report['entry_points'] if run.get('error'))
        assert error['api_name']=='ntoskrnl.IoCreateDriver'
        if mode=='call':assert error['type']=='unsupported_kernel_api'
        assert state['denials'][-1]['access']==('execute' if mode=='call' else 'write')
    else:
        assert not result['errors'] and result['guest_entry_return']==0 and data[0xf8:0xfc]==b'DONE'
        if mode=='read':assert data[0x70:0x78]==bytes.fromhex('b82a000000c3cccc')
        if mode=='api-read':assert pointer(0x70)==6
    assert not any(0xfffff80200000000+CODE_RVA<=int(row['pc'],0)<0xfffff80200000000+CODE_RVA+0x200
        for row in report['instruction_tail'])


def reference_probe(mode, *, code_rva=CODE_RVA, data_rva=DATA_RVA, call_rva=None):
    base=0x140000000
    load=lambda rva:b'\x48\xa1'+struct.pack('<Q',base+rva)
    store=lambda rva:b'\x48\xa3'+struct.pack('<Q',base+rva)
    code=load(0x2390)+b'\x48\x05'+struct.pack('<I',
        data_rva if mode=='private-read' else call_rva if mode=='call' and call_rva is not None else
        code_rva+(0x100 if mode=='relocation' else 0x180 if mode=='call' else 0))
    operations=[('raw',load(0x2900)+store(0x2380)),(1,[('load',0x2380),base+0x2390],None)]
    if mode in ('read','relocation','private-read'):
        code+=b'\x48\x8b\x00'+store(0x23c0)
    elif mode=='call':code+=b'\xff\xd0'+store(0x23c0)
    elif mode=='write':code+=b'\xc7\x00\x00\x00\x00\x00'
    elif mode=='scan':
        code+=b'\x48\xbbMATCHREF\xb9\x00\x01\x00\x00'
        # cmp [rax],rbx; je found; inc rax; loop
        code+=bytes.fromhex('483918740548ffc0e2f6')+store(0x23c0)
    elif mode in ('api-read','api-write'):
        code+=store(0x2398)
    operations.append(('raw',code))
    if mode=='api-read':operations.append((3,[('load',0x2398),base+0x2600,8],0x23c0))
    elif mode=='api-write':operations.append((2,[('load',0x2398),base+0x2620],0x23c0))
    operations.append(('raw',b'\x48\xb8'+struct.pack('<Q',base+0x23f8)+b'\xc7\x00DONE'))
    return call_driver(0x8664,['KeGetCurrentIrql','RtlPcToFileHeader','RtlInitUnicodeString','RtlCompareMemory'],operations,
        b'\x31\xc0',[(0x23f8,b'COLD'),(0x2600,b'GENDCODE'),(0x2620,'fixture\0'.encode('utf-16le'))])


def verify_reference(result,report,root,mode):
    reference=report['kernel_code_reference'];assert reference['enabled'] and reference['execution_allowed'] is False
    assert reference['provenance']=='unverified_user_supplied_PE_data' and reference['relocations']==1
    assert reference['permissions']=='r--' and reference['other_reference_data']=='---'
    assert reference['base']=='0xfffff80200000000'
    data=image_range(result,root,0x2300,0x100);value=int.from_bytes(data[0xc0:0xc8],'little')
    if mode in NEGATIVE:
        assert result['guest_entry_return'] is None and result['errors'] and data[0xf8:0xfc]==b'COLD'
        assert reference['denials']
        assert reference['denials'][-1]['access']==('execute' if mode=='call' else 'read' if mode=='private-read' else 'write')
    else:
        assert result['guest_entry_return']==0 and not result['errors'] and data[0xf8:0xfc]==b'DONE'
        expected={'read':int.from_bytes(b'GENDCODE','little'),'scan':0xfffff80200000000+CODE_RVA+0x20,
            'relocation':0xfffff80200000000+DATA_RVA,'api-read':8}[mode]
        assert value==expected,(mode,hex(value),hex(expected))
        assert not reference['denials']
    # No code callback may enter the reference code range, including a failed call.
    assert not any(0xfffff80200000000+CODE_RVA<=int(row['pc'],0)<0xfffff80200000000+CODE_RVA+0x200
        for row in report['instruction_tail'])
    catalog=report['kernel_export_catalog'];assert int(catalog['address'],0)>=0xfffff80200000000+DATA_RVA+4096
    assert int(catalog['address'],0)+catalog['size']<0xfffff80202000000


class KernelCodeReferenceTests(unittest.TestCase):
    def test_export_inspection_native_and_python_observations_match(self):
        from tools.benchmark_driver_hooks import observations
        from emumee import driver
        for mode in ('read','api-read','call','write','data'):
            rows=[]
            for native in (False,True):
                with self.subTest(mode=mode,native=native),tempfile.TemporaryDirectory() as directory:
                    root=Path(directory);payload=exported_reference_probe(mode)
                    factory=driver.create_native_trace if native else lambda _:None
                    with patch.object(driver,'create_native_trace',factory):
                        result=run_driver(payload,inspect_pe(payload,'export-view.sys'),load_persona(None),root,10,20000,
                            kernel_code_reference=exported_reference())
                    report=json.loads((root/'engine-report.json').read_text())
                    verify_exported_reference(result,report,root,mode)
                    rows.append(observations(result,report))
            self.assertEqual(rows[0],rows[1],mode)
    def test_reference_exports_do_not_override_modeled_apis_or_expose_data(self):
        from tests.test_kernel_export_catalog import catalog_probe,verify_catalog
        for mode in ('read-data','write-data','call-data','api-read','api-write'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);payload=catalog_probe(mode)
                result=run_driver(payload,inspect_pe(payload,'export-data.sys'),load_persona(None),root,10,20000,
                    kernel_code_reference=exported_reference())
                verify_catalog(result,json.loads((root/'engine-report.json').read_text()),root,mode)
        # Every reference probe calls the modeled KeGetCurrentIrql before
        # inspecting code. An exported reference byte at its RVA must not
        # replace that implementation or become executable.
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);payload=reference_probe('read')
            result=run_driver(payload,inspect_pe(payload,'modeled-export.sys'),load_persona(None),root,10,20000,
                kernel_code_reference=exported_reference())
            verify_reference(result,json.loads((root/'engine-report.json').read_text()),root,'read')

    def test_oversized_reference_export_table_is_rejected_before_guest(self):
        ref=bytearray(exported_reference());struct.pack_into('<I',ref,0x440+20,16385)
        payload=reference_probe('read')
        with tempfile.TemporaryDirectory() as directory,self.assertRaises(InvalidSample):
            run_driver(payload,inspect_pe(payload,'bad-exports.sys'),load_persona(None),Path(directory),10,20000,
                kernel_code_reference=bytes(ref))
    def test_unimplemented_code_export_inspection_uses_reference_rvas_without_execution(self):
        for mode in ('lookup','read','api-read','call','write','data'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);payload=exported_reference_probe(mode)
                result=run_driver(payload,inspect_pe(payload,'export-view.sys'),load_persona(None),root,10,20000,
                    kernel_code_reference=exported_reference())
                verify_exported_reference(result,json.loads((root/'engine-report.json').read_text()),root,mode)
    def test_large_reference_reservation_keeps_catalog_below_next_provider(self):
        ref=bytearray(generated_reference());struct.pack_into('<I',ref,0x98+56,0x1047000)
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);payload=reference_probe('read')
            result=run_driver(payload,inspect_pe(payload,'reference-probe.sys'),load_persona(None),root,10,20000,kernel_code_reference=bytes(ref))
            report=json.loads((root/'engine-report.json').read_text());verify_reference(result,report,root,'read')
            self.assertEqual(report['kernel_code_reference']['source_image_size'],0x1047000)
            self.assertGreaterEqual(int(report['kernel_export_catalog']['address'],0),0xfffff80201047000)

    def test_guest_api_cannot_change_reference_protections(self):
        from emumee.driver import DriverEmulator
        from emumee.persona import make_speakeasy_config
        from emumee import kernel_providers
        persona=load_persona(None);cfg=make_speakeasy_config(persona,'reference-probe.sys',10,20000);kernel_providers.configure(cfg)
        for i,definition in enumerate(cfg['modules']['system_modules']):definition['base_addr']=hex(0xfffff80200000000+i*0x2000000)
        with DriverEmulator(cfg,persona=persona,kernel_code_reference=generated_reference()) as se:
            se.load_module(data=reference_probe('read'),filename='reference-probe.sys');kernel=se.emu;ref=kernel.kernel_code_reference
            kernel.guest_api_depth=1
            try:
                with self.assertRaises(ValueError):kernel.mem_protect(ref.base+CODE_RVA,4096,7)
            finally:kernel.guest_api_depth=0
            permissions=next(p for start,end,p in kernel.emu_eng.emu.mem_regions() if start<=ref.base+CODE_RVA<=end)
            self.assertEqual(permissions,1);self.assertEqual(ref.denials[-1]['access'],'protection_change')

    def test_worker_routes_a_hash_bound_generated_reference_as_data(self):
        from emumee.worker import execute
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);payload=reference_probe('read');ref=generated_reference()
            (root/'input.pe').write_bytes(payload);(root/'kernel-code-reference.pe').write_bytes(ref)
            request={'sample_name':'reference-probe.sys','persona':load_persona(None),'dlls':[],
                'timeout':10,'max_instructions':20000,'input_sha256':hashlib.sha256(payload).hexdigest(),
                'companions_sha256':{},'bundle_files_sha256':{},'kernel_code_reference_sha256':hashlib.sha256(ref).hexdigest()}
            raw=json.dumps(request).encode();(root/'request.json').write_bytes(raw)
            with patch('emumee.worker.verify_worker_containment',return_value={}):
                summary=execute(root,hashlib.sha256(raw).hexdigest())
            self.assertEqual(summary['status'],'completed')
            report=json.loads((root/'engine-report.json').read_text());verify_reference(summary,report,root,'read')

    def test_sampled_snapshots_preserve_code_discovery_and_virtual_time(self):
        from tools.benchmark_driver_hooks import observations
        from emumee.kernel_provider_reads import KernelProviderReads
        rows=[]
        payload=reference_probe('scan')
        for enabled in (False,True):
            with tempfile.TemporaryDirectory() as directory:
                root=Path(directory)
                if enabled:
                    result=run_driver(payload,inspect_pe(payload,'reference-probe.sys'),load_persona(None),root,10,20000,kernel_code_reference=generated_reference())
                else:
                    with patch.object(KernelProviderReads,'install'):
                        result=run_driver(payload,inspect_pe(payload,'reference-probe.sys'),load_persona(None),root,10,20000,kernel_code_reference=generated_reference())
                report=json.loads((root/'engine-report.json').read_text());verify_reference(result,report,root,'scan')
                rows.append(observations(result,report))
                if enabled:
                    state=report['kernel_provider_reads'];self.assertEqual(state['capture_errors'],0)
                    self.assertGreater(state['sampled_out_reads'],0)
                    self.assertTrue(any(v['address']==hex(0xfffff80200000000+CODE_RVA+0x20) for v in state['last_observed_per_pc']))
        self.assertEqual(rows[0],rows[1])

    def test_worker_reference_binding_rejects_changed_missing_unbound_and_wrong_profile(self):
        from emumee.worker import execute
        for mode in ('changed','missing','unbound','digest','profile','architecture','user-mode'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);payload=(build(0x8664) if mode=='user-mode' else
                    build_driver(0x14c) if mode=='architecture' else reference_probe('read'))
                ref=generated_reference();persona=load_persona(None)
                if mode=='profile':persona['windows_build']=22000
                (root/'input.pe').write_bytes(payload)
                if mode!='missing':(root/'kernel-code-reference.pe').write_bytes(ref+b'changed' if mode=='changed' else ref)
                request={'sample_name':'probe.sys','persona':persona,'dlls':[],'timeout':10,'max_instructions':20000,
                    'input_sha256':hashlib.sha256(payload).hexdigest(),'companions_sha256':{},'bundle_files_sha256':{},
                    'kernel_code_reference_sha256':None if mode=='unbound' else 'bad' if mode=='digest' else hashlib.sha256(ref).hexdigest()}
                raw=json.dumps(request).encode();(root/'request.json').write_bytes(raw)
                with patch('emumee.worker.verify_worker_containment',return_value={}),patch('emumee.worker.run_driver',side_effect=AssertionError('Guest started before reference preflight')):
                    with self.assertRaises(InvalidSample):execute(root,hashlib.sha256(raw).hexdigest())
                self.assertFalse((root/'engine-report.json').exists())

    def test_parent_verifies_the_staged_reference_against_its_manifest(self):
        from emumee.cli import _staged_input_errors
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);payload=reference_probe('read');ref=generated_reference();request=b'{}'
            for name,data in [('request.json',request),('input.pe',payload),('kernel-code-reference.pe',ref)]:
                (root/name).write_bytes(data)
            manifest={'request_sha256':hashlib.sha256(request).hexdigest(),
                'execution_target':{'sha256':hashlib.sha256(payload).hexdigest()},'companions':[],
                'kernel_code_reference':{'sha256':hashlib.sha256(ref).hexdigest()}}
            self.assertEqual(_staged_input_errors(root,manifest),[])
            (root/'kernel-code-reference.pe').write_bytes(ref+b'changed')
            self.assertEqual(_staged_input_errors(root,manifest),['Staged execution input changed or is unsafe: kernel-code-reference.pe'])

    def test_generated_code_discovery_relocation_and_read_api(self):self.probe('read','scan','relocation','api-read')
    def test_reference_writes_execution_and_private_data_stop(self):self.probe('call','write','private-read','api-write')
    def probe(self,*modes):
        for mode in modes:
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);payload=reference_probe(mode)
                result=run_driver(payload,inspect_pe(payload,'reference-probe.sys'),load_persona(None),root,10,20000,kernel_code_reference=generated_reference())
                report=json.loads((root/'engine-report.json').read_text());verify_reference(result,report,root,mode)
    def test_reference_is_opt_in(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);payload=reference_probe('read')
            result=run_driver(payload,inspect_pe(payload,'no-reference.sys'),load_persona(None),root,10,20000)
            report=json.loads((root/'engine-report.json').read_text());self.assertIsNone(report['kernel_code_reference'])
            self.assertTrue(result['errors']);self.assertIsNone(result['guest_entry_return'])
    def test_bad_architecture_profile_and_reference_are_rejected(self):
        payload=reference_probe('read');info=inspect_pe(payload,'reference-probe.sys')
        for ref,persona in ((b'invalid',load_persona(None)),(build(0x14c),load_persona(None)),
                (generated_reference(),{**load_persona(None),'windows_build':22000})):
            with self.subTest(reference=len(ref),build=persona['windows_build']),tempfile.TemporaryDirectory() as directory:
                with self.assertRaises((InvalidSample,ValueError)):
                    run_driver(payload,info,persona,Path(directory),10,20000,kernel_code_reference=ref)
