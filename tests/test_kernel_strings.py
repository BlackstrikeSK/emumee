"""Native strcmp ABI, unsigned ordering, short circuit and bounded failure."""
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


def strcmp_probe(machine, mode='ordering'):
    wide=machine==0x8664
    base,width=(0x140000000,8) if wide else (0x400000,4)
    store=lambda rva:(b'\x48\xa3' if wide else b'\xa3')+(base+rva).to_bytes(width,'little')
    operations,writes=[('raw',b'\xb8COLD'+store(0x23F8))],[]
    if mode=='ordering':
        pairs=[(b'same',b'same'),(b'a',b'b'),(b'z',b'a'),(b'\xff',b'\x7f'),
               (b'A',b'a'),(b'ab',b'abc'),(b'',b'x'),(b'a\0after',b'a\0other')]
        args=[]
        for index,(left,right) in enumerate(pairs):
            first,second=0x2400+index*32,0x2410+index*32
            writes.extend([(first,left+b'\0'),(second,right+b'\0')])
            args.append((base+first,base+second))
        writes.append((0x2FFF,b'\0'))
        args.append((base+0x2FFF,base+0x2FFF))
    else:
        writes.append((0x2400,b'valid\0'))
        pointer={'null':0,'unmapped':0x7FFF7000,'limit':base+0x4000}[mode]
        args=[(pointer,pointer if mode in ('null','limit') else base+0x2400)]
    for index,(left,right) in enumerate(args):
        operations.append((0,[left,right],0x2300+index*8))
        if not wide:
            operations.append(('raw',bytes.fromhex('83c408')))  # caller pops cdecl arguments
    operations.append(('raw',b'\xb8DONE'+store(0x23F8)+b'\x31\xc0'))
    payload=bytearray(call_driver(machine,['strcmp'],operations,writes=writes))
    if mode=='limit':
        section=0x98+(0xF0 if wide else 0xE0)+40
        struct.pack_into('<I',payload,section+8,0x23000)
        struct.pack_into('<I',payload,section+16,0x23000)
        struct.pack_into('<I',payload,0x98+56,0x25000)
        payload.extend(bytes(0x23400-len(payload)))
        payload[0x2400:0x12400]=b'A'*65536
    return bytes(payload)


def verify_strcmp(result,report,root,machine,mode):
    data=image_range(result,root,0x2300,0x100)
    if mode=='ordering':
        assert result['guest_entry_return']==0 and not result['errors']
        values=[int.from_bytes(data[index*8:index*8+4],'little',signed=True) for index in range(9)]
        assert [(v>0)-(v<0) for v in values]==[0,-1,1,1,-1,-1,-1,0,0],values
        assert data[0xF8:0xFC]==b'DONE'
        calls=[e for e in report['entry_points'][0]['events'] if e.get('api_name')=='ntoskrnl.strcmp']
        assert len(calls)==9
    else:
        assert result['guest_entry_return'] is None and result['errors']
        assert data[0xF8:0xFC]==b'COLD'
        error=report['entry_points'][0]['error']
        expected='strcmp exceeded the modeled 65536-byte comparison limit' if mode=='limit' else 'strcmp input is not readable guest memory'
        assert error['type']==expected and 'in strcmp' in error['traceback']
        assert ('65536-byte' if mode=='limit' else 'not readable guest memory') in str(result['errors'])
    assert not result['api_coverage']['signature_only_calls']


class KernelStringTests(unittest.TestCase):
    def check_mode(self,mode):
        for machine in (0x14C,0x8664):
            with self.subTest(machine=machine,mode=mode),tempfile.TemporaryDirectory() as d:
                root=Path(d)
                payload=strcmp_probe(machine,mode)
                result=run_driver(payload,inspect_pe(payload,'strings.sys'),load_persona(None),root,10,3000)
                report=json.loads((root/'engine-report.json').read_text())
                verify_strcmp(result,report,root,machine,mode)

    def test_native_ordering_unsigned_bytes_cdecl_and_nul_boundary(self):
        self.check_mode('ordering')

    def test_equal_null_pointers_are_not_assumed_to_be_valid_strings(self):
        self.check_mode('null')

    def test_unmapped_input_stops_before_following_guest_marker(self):
        self.check_mode('unmapped')

    def test_comparison_limit_stops_without_fabricating_equality(self):
        self.check_mode('limit')
