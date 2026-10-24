"""Native trace slots must observe changed instruction classes and eviction."""
import copy,json,struct,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
import emumee.driver as driver
from emumee.instruction_cache import InstructionCache
from emumee.pe import inspect_pe
from emumee.persona import load_persona
from tests.test_kernel_runtime import runtime_driver
from tools.benchmark_driver_hooks import observations


def changing_code_fixture(machine, eviction=False):
    wide=machine==0x8664;base=0x140000000 if wide else 0x400000
    start=0x1004 if wide else 0x1000
    code=bytearray(b'\xb9'+struct.pack('<I',32))
    def call(target):
        code.extend(b'\xe8'+struct.pack('<i',target-(start+len(code)+5)))
    loop=len(code);call(0x1180)
    if eviction:call(0x2b00)
    code.extend(b'\xff\xc9\x75'+struct.pack('<b',loop-(len(code)+4)))
    if wide:
        code.extend(b'\x66\xc7\x05'+struct.pack('<i',0x1180-(start+len(code)+9))+b'\x0f\x31')
    else:
        code.extend(b'\x66\xc7\x05'+struct.pack('<I',base+0x1180)+b'\x0f\x31')
    call(0x1180)
    if wide:
        code.extend(b'\x89\x05'+struct.pack('<i',0x2400-(start+len(code)+6)))
        code.extend(b'\x89\x15'+struct.pack('<i',0x2404-(start+len(code)+6)))
    else:
        code.extend(b'\xa3'+struct.pack('<I',base+0x2400))
        code.extend(b'\x89\x15'+struct.pack('<I',base+0x2404))
    data=bytearray(runtime_driver(machine,['KeGetCurrentIrql'],[],[(0x2b00,b'\xc3')],tail=bytes(code),zero_return=True))
    data[0x380:0x383]=b'\x90\x90\xc3'
    section=0x98+(0xf0 if wide else 0xe0)
    for offset in (section+36,section+76):struct.pack_into('<I',data,offset,0xe0000020)
    return bytes(data)


def multiple_code_sections_fixture(machine):
    wide=machine==0x8664;start=0x1004 if wide else 0x1000
    code=bytearray(b'\xe8'+struct.pack('<i',0x4000-start-5)+b'\xb9'+struct.pack('<I',5000))
    loop=len(code);code.extend(b'\xff\xc0\xff\xc9\x75'+struct.pack('<b',loop-(len(code)+6)))
    data=bytearray(runtime_driver(machine,['KeGetCurrentIrql'],[],tail=bytes(code),zero_return=True))
    assert len(data)==0x1400
    struct.pack_into('<H',data,0x86,3)
    struct.pack_into('<I',data,0x98+56,0x5000)
    struct.pack_into('<I',data,0x98+4,0x400)
    struct.pack_into('<8sIIIIIIHHI',data,0x98+(0xf0 if wide else 0xe0)+80,b'.text2\0\0',0x200,0x4000,0x200,0x1400,0,0,0,0,0x60000020)
    data.extend(b'\xc3'+bytes(0x1ff))
    return bytes(data)


def idle_scheduler_fixture(machine,iterations=20000):
    from tests import test_kernel_ipi as ipi
    original=ipi.call_driver
    def build(machine,names,operations,tail,writes):
        operations=list(operations)
        before=next(index for index,item in enumerate(operations) if item[0]==6)
        operations.insert(before,('raw',b'\xb9'+struct.pack('<I',iterations)+bytes.fromhex('ffc975fc')))
        return original(machine,names,operations,tail,writes)
    with patch.object(ipi,'call_driver',build):
        return ipi.ipi_probe(machine,'background',4)


class DriverNativeCacheTests(unittest.TestCase):
    def test_idle_scheduler_and_multiple_run_global_budgets_match_python(self):
        factory=driver.create_native_trace
        for machine in (0x14c,0x8664):
            for budget in (32,512,10000,100000):
                payload=idle_scheduler_fixture(machine);rows=[]
                persona=load_persona(None);persona['cpu']['cores']=4;persona['cpu']['threads_per_core']=1
                for native in (False,True):
                    with self.subTest(machine=machine,budget=budget,native=native),tempfile.TemporaryDirectory() as directory:
                        root=Path(directory)
                        with patch.object(driver,'create_native_trace',factory if native else lambda _:None):
                            result=driver.run_driver(payload,inspect_pe(payload,'idle-scheduler.sys'),copy.deepcopy(persona),root,20,budget)
                        report=json.loads((root/'engine-report.json').read_text())
                        if budget<100000:
                            self.assertTrue(result['instruction_limit_reached']);self.assertEqual(result['instruction_count'],budget)
                        else:
                            self.assertEqual(result['errors'],[]);self.assertEqual(result['guest_entry_return'],0x1234)
                            self.assertTrue(report['kernel_ipi']['broadcasts'][0]['completed'])
                            self.assertEqual(report['kernel_scheduling']['threads'][0]['state'],'done')
                            if native:self.assertGreater(report['driver_tracing']['fast_instructions'],40000)
                        rows.append((observations(result,report),report['kernel_scheduling'],report['kernel_ipi'],
                            report['entry_points'],report['instruction_cache']['misses']))
                self.assertEqual(rows[0],rows[1])
    def test_cached_secondary_access_matches_python_and_exact_budget(self):
        factory=driver.create_native_trace
        for machine in (0x14c,0x8664):
            for budget in (64,100000):
                rows=[];payload=multiple_code_sections_fixture(machine)
                for native in (False,True):
                    with self.subTest(machine=machine,budget=budget,native=native),tempfile.TemporaryDirectory() as directory:
                        root=Path(directory)
                        with patch.object(driver,'create_native_trace',factory if native else lambda _:None):
                            result=driver.run_driver(payload,inspect_pe(payload,'multiple-code-sections.sys'),copy.deepcopy(load_persona(None)),root,10,budget)
                        report=json.loads((root/'engine-report.json').read_text())
                        if budget==64:
                            self.assertTrue(result['instruction_limit_reached']);self.assertEqual(result['instruction_count'],64)
                        else:
                            self.assertEqual(result['errors'],[]);self.assertEqual(result['guest_entry_return'],0)
                        if native:
                            trace=report['driver_tracing'];self.assertEqual(trace['backend'],'native_direct');self.assertFalse(trace['callback_error'])
                            if budget!=64:self.assertGreater(trace['fast_instructions'],10000)
                        rows.append((observations(result,report),report['entry_points'],report['instruction_cache']['misses']))
                self.assertEqual(rows[0],rows[1])

    def test_self_modifying_rdtsc_and_eviction_match_python_trace(self):
        for machine in (0x14c,0x8664):
            for eviction in (False,True):
                rows=[]
                payload=changing_code_fixture(machine,eviction)
                factory=driver.create_native_trace
                class Cache(InstructionCache):
                    def __init__(self,read):super().__init__(read,pages=1 if eviction else 256)
                for native in (False,True):
                    with self.subTest(machine=machine,eviction=eviction,native=native),tempfile.TemporaryDirectory() as directory:
                        root=Path(directory)
                        with patch.object(driver,'create_native_trace',factory if native else lambda _:None),patch.object(driver,'InstructionCache',Cache):
                            result=driver.run_driver(payload,inspect_pe(payload,'changing-code.sys'),copy.deepcopy(load_persona(None)),root,10,10000)
                        self.assertEqual(result['errors'],[])
                        self.assertEqual(result['guest_entry_return'],0)
                        report=json.loads((root/'engine-report.json').read_text())
                        self.assertTrue(report['driver_image_changes']['executed_after_write_pages'])
                        if native:self.assertEqual(report['driver_tracing']['backend'],'native_direct')
                        rows.append(observations(result,report))
                self.assertEqual(rows[0],rows[1])
