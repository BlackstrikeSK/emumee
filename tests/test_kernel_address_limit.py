"""Native pointer-sized address-limit data and its protection boundary."""
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


def address_limit_probe(machine, mode='read'):
    wide = machine == 0x8664
    base, width = (0x140000000, 8) if wide else (0x400000, 4)
    rex = b'\x48' if wide else b''
    load = lambda rva: rex + b'\xa1' + (base+rva).to_bytes(width,'little')
    store = lambda rva: rex + b'\xa3' + (base+rva).to_bytes(width,'little')
    name = 'MmHighestUserAddress'.encode('utf-16le')
    ustr = struct.pack('<HH',len(name),len(name)+2) + (bytes(4) if wide else b'') + (base+0x2620).to_bytes(width,'little')
    before = load(0x2900) + store(0x2300) + rex + b'\x8b\x00' + store(0x2310)
    after = load(0x2320) + rex + b'\x8b\x00' + store(0x2330)
    if mode == 'write':
        after += load(0x2300) + b'\xc7\x00NOPE'
    elif mode == 'call':
        after += load(0x2300) + b'\xff\xd0'
    after += b'\xb8DONE' + store(0x23F8) + b'\x31\xc0'
    return call_driver(machine,['MmHighestUserAddress','MmGetSystemRoutineAddress'],
        [('raw',before),(1,[base+0x2600],0x2320),('raw',after)],
        writes=[(0x2600,ustr),(0x2620,name+bytes(2))])


def verify_address_limit(result, report, root, machine, mode, build=22631):
    width = 8 if machine == 0x8664 else 4
    data = image_range(result,root,0x2300,0x100)
    value = lambda offset:int.from_bytes(data[offset:offset+width],'little')
    expected = (0x7FFFFFFEFFFF if build >= 9600 else 0x7FFFFFEFFFF) if width==8 else 0x7FFEFFFF
    assert value(0) == value(0x20) and value(0) >= (0xFFFF800000000000 if width==8 else 0x80000000)
    assert value(0x10) == value(0x30) == expected
    rows = [row for entry in report['entry_points'] for module in entry['memory']['modules']
            for row in module['segments'] if int(row['address'],0)<=value(0)<
            int(row['address'],0)+int(row['size'],0)]
    assert rows and all(row['prot']=='r--' for row in rows)
    if mode=='read':
        assert result['guest_entry_return']==0 and not result['errors'] and data[0xF8:0xFC]==b'DONE'
    else:
        assert result['guest_entry_return'] is None and result['errors'] and data[0xF8:0xFC]!=b'DONE'
        error=report['entry_points'][0]['error']
        assert error['type']==('invalid_execute' if mode=='call' else 'invalid_protect_write')
        assert int(error['address'],0)==value(0)


class KernelAddressLimitTests(unittest.TestCase):
    def check_mode(self, mode, build=22631):
        for machine in (0x14C,0x8664):
            with self.subTest(machine=machine,mode=mode,build=build), tempfile.TemporaryDirectory() as d:
                root=Path(d)
                data=address_limit_probe(machine,mode)
                persona=load_persona(None)
                persona['windows_build']=build
                result=run_driver(data,inspect_pe(data,'address-limit.sys'),persona,root,5,2000)
                report=json.loads((root/'engine-report.json').read_text())
                verify_address_limit(result,report,root,machine,mode,build)

    def test_native_import_and_dynamic_lookup_read_the_same_data(self):
        self.check_mode('read')

    def test_legacy_x64_profile_has_an_eight_tb_limit(self):
        self.check_mode('read',7601)

    def test_native_data_write_stops_before_following_marker(self):
        self.check_mode('write')

    def test_native_data_execution_stops_before_following_marker(self):
        self.check_mode('call')
