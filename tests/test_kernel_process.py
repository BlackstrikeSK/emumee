"""Native import/dynamic/EAT coherence of the guest's initial System process."""
import json,struct,tempfile,unittest
from pathlib import Path
from emumee.driver import run_driver
from emumee.pe import inspect_pe
from emumee.persona import load_persona
from tests.test_kernel_objects import call_driver
from tests.test_kernel_system_information import image_range


def process_probe(machine,mode='read',export_name='PsInitialSystemProcess',read_data=True,post_operations=(),extra_writes=()):
    wide=machine==0x8664
    base,width=(0x140000000,8) if wide else (0x400000,4)
    rex=b'\x48' if wide else b''
    load=lambda rva:rex+b'\xa1'+(base+rva).to_bytes(width,'little')
    store=lambda rva:rex+b'\xa3'+(base+rva).to_bytes(width,'little')
    name=export_name;text=name.encode('utf-16le')
    writes=[(0x2720,struct.pack('<HH',len(text),len(text)+2)+(bytes(4) if wide else b'')+(base+0x2780).to_bytes(width,'little')),(0x2780,text+bytes(2))]
    names=[name,'MmGetSystemRoutineAddress','RtlPcToFileHeader','IoGetCurrentProcess','PsGetCurrentProcessId','ObReferenceObjectByPointer','ObfDereferenceObject']
    operations=[('raw',b'\xb8COLD'+store(0x23f8)),
        ('raw',load(0x2900)+store(0x2310)+(rex+b'\x8b\x00'+store(0x2318) if read_data else b'')),
        (1,[base+0x2720],0x2320),('raw',load(0x2320)+rex+b'\x8b\x00'+store(0x2328) if read_data else b''),
        (3,[],0x2330),(4,[],0x2338),
        (2,[('load',0x2900+3*width),base+0x2300],0x2300)]
    targets=(name+'EmumeeMissing' if mode=='missing' else name,)
    for index,target in enumerate(targets):
        text=target.encode()+b'\0';target_rva=0x26c0;writes.append((target_rva,text))
        code=bytearray(load(0x2300)+rex+b'\x89\xc3')
        code.extend(bytes.fromhex('8b533c')+rex+b'\x01\xda'+bytes.fromhex('8b92')+struct.pack('<I',0x88 if wide else 0x78)+rex+b'\x01\xda')
        code.extend(bytes.fromhex('8b6a1831c0'))
        labels,jumps={},[]
        def branch(op,label):
            op={b'\x0f\x83':b'\x73',b'\x0f\x84':b'\x74',b'\x0f\x82':b'\x72',b'\xe9':b'\xeb'}[op]
            code.extend(op+bytes(1)); jumps.append((len(code)-1,label))
        labels['loop']=len(code)
        code.extend(bytes.fromhex('39e8'))
        branch(bytes.fromhex('0f83'),'missing')
        code.extend(bytes.fromhex('89c101e9d1e9'))
        # Save midpoint through an absolute pointer without clobbering low/high.
        code.extend((b'\x49\xbb'+struct.pack('<Q',base+0x2700)+b'\x41\x89\x0b') if wide else b'\x89\x0d'+struct.pack('<I',base+0x2700))
        code.extend(bytes.fromhex('8b7a20')+rex+b'\x01\xdf'+bytes.fromhex('8b3c8f')+rex+b'\x01\xdf')
        code.extend((b'\x48\xbe' if wide else b'\xbe')+(base+target_rva).to_bytes(width,'little'))
        code.extend(b'\xb9'+struct.pack('<I',len(text))+bytes.fromhex('fcf3a6'))
        branch(bytes.fromhex('0f84'),'found')
        branch(bytes.fromhex('0f82'),'smaller')
        code.extend((b'\x41\x8b\x03') if wide else b'\xa1'+struct.pack('<I',base+0x2700))
        code.extend(bytes.fromhex('83c001'))
        branch(b'\xe9','loop')
        labels['smaller']=len(code)
        code.extend((b'\x41\x8b\x2b') if wide else b'\x8b\x2d'+struct.pack('<I',base+0x2700))
        branch(b'\xe9','loop')
        labels['missing']=len(code)
        code.extend(bytes.fromhex('31c0'))
        branch(b'\xe9','save')
        labels['found']=len(code)
        code.extend((b'\x41\x8b\x0b') if wide else b'\x8b\x0d'+struct.pack('<I',base+0x2700))
        code.extend(bytes.fromhex('8b7a24')+rex+b'\x01\xdf'+bytes.fromhex('0fb73c4f8b721c')+rex+b'\x01\xde'+bytes.fromhex('8b04be')+rex+b'\x01\xd8')
        labels['save']=len(code)
        code.extend(store(0x2350+index*0x10))
        if mode!='missing' and read_data:
            code.extend(rex+bytes.fromhex('8b00')+store(0x2358+index*0x10))
        for offset,label in jumps:
            code[offset:offset+1]=struct.pack('<b',labels[label]-offset-1)
        operations.append(('raw',bytes(code)))
    operations.append((5,[('load',0x2330),0,('load',0x2318),0],0x2340))
    if wide:operations.append((6,[('load',0x2330)],0x2348))
    else:operations.append(('raw',load(0x2330)+b'\x89\xc1\xff\x15'+(base+0x2900+6*width).to_bytes(width,'little')+store(0x2348)))
    if mode in ('write','call'):
        operations.append(('raw',load(0x2350)+(rex+b'\xc7\x00'+bytes(4) if mode=='write' else b'\xff\xd0')))
    if mode in ('identity-read','identity-call'):
        operations.append(('raw',load(0x2358)+(rex+b'\x8b\x00' if mode=='identity-read' else b'\xff\xd0')))
    operations.extend(post_operations)
    operations.append(('raw',b'\xb8DONE'+store(0x23f8)+b'\x31\xc0'))
    return call_driver(machine,names,operations,writes=writes+list(extra_writes))


def verify_process(result,report,root,machine,mode):
    width=8 if machine==0x8664 else 4
    data=image_range(result,root,0x2300,0x100);value=lambda n:int.from_bytes(data[n:n+width],'little')
    state=report['kernel_initial_system_process'];storage=int(state['address'],0);body=int(state['process'],0)
    assert state['pid']==4 and state['type']=='PEPROCESS' and state['permissions']=='r--'
    assert value(0x10)==value(0x20)==storage and storage!=body
    assert value(0x18)==value(0x28)==value(0x30)==body and value(0x38)==4
    assert value(0x40)==0
    events=report['kernel_object_references']['events'];assert len(events)==2
    assert all(v['object']==hex(body) and v['kind']=='EPROCESS' for v in events)
    assert events[0]['references_after']==events[1]['references_after']+1 and events[1]['references_after']>0
    if mode=='missing':assert value(0x50)==0
    else:assert value(0x50)==storage and value(0x58)==body
    segments=[segment for run in report['entry_points'] for module in run['memory']['modules'] for segment in module['segments'] if int(segment['address'],0)<=storage<int(segment['address'],0)+int(segment['size'],0)]
    assert segments and all(v['prot']=='r--' for v in segments)
    if mode in ('read','missing'):
        assert result['guest_entry_return']==0 and not result['errors'] and data[0xf8:0xfc]==b'DONE'
    else:
        assert result['guest_entry_return'] is None and result['errors'] and data[0xf8:0xfc]==b'COLD'
        error=report['entry_points'][0]['error'];assert error['type']==('invalid_protect_write' if mode=='write' else 'invalid_execute') and int(error['address'],0)==storage


class KernelProcessTests(unittest.TestCase):
    def probe(self,mode):
        for machine in (0x14c,0x8664):
            with self.subTest(machine=machine,mode=mode),tempfile.TemporaryDirectory() as d:
                root=Path(d);payload=process_probe(machine,mode)
                result=run_driver(payload,inspect_pe(payload,'system-process.sys'),load_persona(None),root,5,10000)
                verify_process(result,json.loads((root/'engine-report.json').read_text()),root,machine,mode)
    def test_import_dynamic_and_native_binary_lookup_share_existing_system_object(self):self.probe('read')
    def test_absent_binary_export_stays_absent(self):self.probe('missing')
    def test_global_pointer_write_stops_before_marker(self):self.probe('write')
    def test_global_pointer_execution_stops_before_marker(self):self.probe('call')
