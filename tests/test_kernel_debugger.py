"""Native PE binary lookup of guest debugger BOOLEAN data, imports and NX."""
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


def debugger_probe(machine,mode='read'):
    wide=machine==0x8664
    base,width=(0x140000000,8) if wide else (0x400000,4)
    rex=b'\x48' if wide else b''
    load=lambda rva:rex+b'\xa1'+(base+rva).to_bytes(width,'little')
    store=lambda rva:rex+b'\xa3'+(base+rva).to_bytes(width,'little')
    operations=[('raw',b'\xb8COLD'+store(0x23F8))]
    writes=[]
    for index,name in enumerate(('KdDebuggerNotPresent','KdDebuggerEnabled')):
        text=name.encode('utf-16le')
        descriptor=0x2600+index*0x20
        pointer=0x2640+index*0x40
        writes.extend([(descriptor,struct.pack('<HH',len(text),len(text)+2)+(bytes(4) if wide else b'')+(base+pointer).to_bytes(width,'little')),
                       (pointer,text+bytes(2))])
        operations.append(('raw',load(0x2900+index*width)+store(0x2310+index*0x10)+bytes.fromhex('0fb600')+store(0x2318+index*0x10)))
        operations.append((2,[base+descriptor],0x2330+index*0x10))
    operations.append((3,[('load',0x2900+3*width),base+0x2300],0x2300))
    if mode=='entered':
        text='KdEnteredDebugger'.encode('utf-16le')
        writes.extend([(0x2720,struct.pack('<HH',len(text),len(text)+2)+(bytes(4) if wide else b'')+(base+0x2740).to_bytes(width,'little')),(0x2740,text+bytes(2))])
        operations.append(('raw',load(0x2900+4*width)+store(0x2370)+bytes.fromhex('0fb600')+store(0x2378)))
        operations.append((2,[base+0x2720],0x2380))
    targets=('KdDebuggerNotPresent','KdDebuggerEnabled') if mode=='read' else ('KdDebuggerEmumeeMissing',) if mode=='missing' else ('KdEnteredDebugger',) if mode=='entered' else ('KdDebuggerNotPresent',)
    for index,target in enumerate(targets):
        text=target.encode()+b'\0'
        target_rva=0x26C0+index*0x20
        writes.append((target_rva,text))
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
        if mode!='missing':
            code.extend(bytes.fromhex('0fb600')+store(0x2358+index*0x10))
        for offset,label in jumps:
            code[offset:offset+1]=struct.pack('<b',labels[label]-offset-1)
        operations.append(('raw',bytes(code)))
    if mode in ('write','call'):
        operations.append(('raw',load(0x2350)+(b'\xc6\x00\0' if mode=='write' else b'\xff\xd0')))
    operations.append(('raw',b'\xb8DONE'+store(0x23F8)+b'\x31\xc0'))
    names=['KdDebuggerNotPresent','KdDebuggerEnabled','MmGetSystemRoutineAddress','RtlPcToFileHeader']
    if mode=='entered': names.append('KdEnteredDebugger')
    payload=call_driver(machine,names,operations,writes=writes)
    if mode=='entered':
        # The shared fixture's fifth import-name slot overlaps the first
        # UNICODE_STRING. Relocate that name before loading this extra import.
        payload=bytearray(payload)
        for table in (0x2800,0x2900):
            struct.pack_into('<Q' if wide else '<I',payload,table-0x1C00+4*width,0x2780)
        name=b'\0\0KdEnteredDebugger\0'
        payload[0x2780-0x1C00:0x2780-0x1C00+len(name)]=name
        payload=bytes(payload)
    return payload


def verify_debugger(result,report,root,machine,mode):
    width=8 if machine==0x8664 else 4
    data=image_range(result,root,0x2300,0x100)
    value=lambda offset:int.from_bytes(data[offset:offset+width],'little')
    state=report['kernel_debugger_state']
    assert state['enabled'] is False and state['not_present'] is True
    for index,name in enumerate(('KdDebuggerNotPresent','KdDebuggerEnabled')):
        assert value(0x10+index*0x10)==value(0x30+index*0x10)==int(state['exports'][name]['address'],0)
        assert value(0x18+index*0x10)==(1-index)
        if mode not in ('missing','entered') and (index==0 or mode=='read'):
            assert value(0x50+index*0x10)==value(0x10+index*0x10) and value(0x58+index*0x10)==1-index
        rows=[row for run in report['entry_points'] for module in run['memory'].get('modules',[]) for row in module['segments']
              if int(row['address'],0)<=value(0x10+index*0x10)<int(row['address'],0)+int(row['size'],0)]
        assert rows and all(row['prot']=='r--' for row in rows)
    if mode=='entered':
        assert state['entered'] is False
        assert value(0x50)==value(0x70)==value(0x80)==int(state['exports']['KdEnteredDebugger']['address'],0)
        assert value(0x58)==value(0x78)==0
    if mode in ('read','missing','entered'):
        assert result['guest_entry_return']==0 and not result['errors'] and data[0xF8:0xFC]==b'DONE'
        if mode=='missing':
            assert value(0x50)==0
    else:
        assert result['guest_entry_return'] is None and result['errors'] and data[0xF8:0xFC]==b'COLD'
        error=report['entry_points'][0]['error']
        assert error['type']==('invalid_protect_write' if mode=='write' else 'invalid_execute')
        assert int(error['address'],0)==value(0x50)


class KernelDebuggerTests(unittest.TestCase):
    def check_mode(self,mode):
        for machine in (0x14C,0x8664):
            with self.subTest(machine=machine,mode=mode),tempfile.TemporaryDirectory() as d:
                root=Path(d); payload=debugger_probe(machine,mode)
                result=run_driver(payload,inspect_pe(payload,'debugger-data.sys'),load_persona(None),root,5,10000)
                verify_debugger(result,json.loads((root/'engine-report.json').read_text()),root,machine,mode)

    def test_native_binary_export_search_agrees_with_imports_and_dynamic_lookup(self): self.check_mode('read')
    def test_missing_export_search_returns_no_match(self): self.check_mode('missing')
    def test_entered_debugger_global_is_a_coherent_false_boolean(self): self.check_mode('entered')
    def test_native_debugger_data_write_stops(self): self.check_mode('write')
    def test_native_debugger_data_execution_stops(self): self.check_mode('call')
