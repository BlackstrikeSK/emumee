"""Generated calls to the documented no-input guest debugger prompt model."""
import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import emumee.driver as driver
from emumee.pe import inspect_pe
from emumee.persona import load_persona
from tests.test_kernel_code_reference import exported_reference, CODE_RVA
from tests.test_kernel_process import process_probe
from tests.test_kernel_system_information import image_range
from tools.benchmark_driver_hooks import observations

MODES=('normal','empty','zero','boundary','repeat','null-prompt',
       'unterminated','null-response','cross-response','readonly-response','oversize')
REFERENCE_MODES=('reference-normal','reference-call','reference-write')
NEGATIVE={'null-prompt','unterminated','null-response','cross-response',
          'readonly-response','oversize','reference-call','reference-write'}


def prompt_reference():
    original=exported_reference()
    return original.replace(b'IoCreateDriver\0',b'DbgPrompt\0'+bytes(5))


def prompt_probe(machine,mode,reference_rva=CODE_RVA+0x180):
    wide=machine==0x8664
    base,width=(0x140000000,8) if wide else (0x400000,4)
    rex=b'\x48' if wide else b''
    load=lambda rva:rex+b'\xa1'+(base+rva).to_bytes(width,'little')
    store=lambda rva:rex+b'\xa3'+(base+rva).to_bytes(width,'little')
    prompt=0 if mode=='null-prompt' else base+0x2b00
    response=0 if mode in ('zero','null-response') else base+(0x2ff0 if mode=='cross-response' else 0x1000 if mode=='readonly-response' else 0x2d00)
    capacity=0 if mode=='zero' else 512 if mode=='boundary' else 513 if mode=='oversize' else 32
    text=b'\0' if mode=='empty' else b'P'*511+b'\0' if mode=='boundary' else b'P'*512 if mode=='unterminated' else b'Generated prompt?\0'
    post=[('raw',load(0x2350)+store(0x2900+7*width))]
    if mode in ('reference-call','reference-write'):
        assert wide
        address=0xfffff80200000000+reference_rva
        post.append(('raw',b'\x48\xb8'+struct.pack('<Q',address)+(b'\xff\xd0' if mode=='reference-call' else b'\xc6\x00\0')))
    else:
        if mode!='repeat':
            post.append((7,[prompt,response,capacity],0x2370))
        if mode=='repeat':
            # Keep the loop counter in guest memory: Windows APIs may clobber
            # caller-saved registers. Reuse a single machine call sequence.
            from tests.test_kernel_objects import call_driver
            from tests.test_kernel_runtime import runtime_driver
            one=call_driver(machine,['DbgPrompt'],[(0,[prompt,response,capacity],None)])
            start=0x204 if wide else 0x200
            end=one.index(b'\x48\x83\xc4\x78\xc3' if wide else b'\xc2\x08\x00',start)
            body=bytearray(one[start:end])
            # RIP-relative imported call must account for its new position.
            # Use an absolute target slot through RAX/EAX for this loop.
            if wide:
                marker=body.index(b'\xff\x15')
                body[marker:marker+6]=load(0x2900)+b'\xff\xd0'
            loop=(b'\x48\xbe' if wide else b'\xbe')+(base+0x23d0).to_bytes(width,'little')
            loop+=b'\xc7\x06'+struct.pack('<I',65)
            loop+=bytes(body)+b'\xff\x0e'+b'\x75'+struct.pack('<b',-len(body)-4)
            # The small standalone fixture avoids the lookup prelude's 512B
            # section limit. Normal mode separately checks EAT coherence.
            return runtime_driver(machine,['DbgPrompt'],[],
                [(0x2b00,text),(0x2d00,b'R'*512)],
                tail=loop+b'\xb8DONE'+store(0x23f8)+b'\x31\xc0')
    return process_probe(machine,'lookup','DbgPrompt',read_data=False,
        post_operations=post,extra_writes=[(0x2b00,text),(0x2d00,b'R'*512)])


def verify_prompt(result,report,root,machine,mode,reference_rva=CODE_RVA+0x180):
    width=8 if machine==0x8664 else 4
    state=report['kernel_debugger_state']
    capture=state['prompt']
    assert not state['enabled'] and state['not_present'] and not state['entered']
    assert capture['input_policy']=='no_input' and capture['response_writes']==0
    assert image_range(result,root,0x2d00,512)==b'R'*512
    if mode!='repeat':
        data=image_range(result,root,0x2300,0x100)
        pointer=lambda offset:int.from_bytes(data[offset:offset+width],'little')
        assert pointer(0x10)==pointer(0x20)==pointer(0x50)!=0
    if mode in NEGATIVE:
        assert result['guest_entry_return'] is None and result['errors']
        assert capture['calls']==0 and capture['observations']==[]
        if mode.startswith('reference-'):
            assert report['kernel_code_reference']['denials'][-1]['access']==('execute' if mode=='reference-call' else 'write')
        return
    assert result['guest_entry_return']==0 and not result['errors'],result['errors']
    expected=65 if mode=='repeat' else 1
    assert capture['calls']==expected and len(capture['observations'])==min(64,expected)
    assert capture['omitted']==max(0,expected-64)
    for row in capture['observations']:
        assert row['received_characters']==0
        assert row['prompt']==('' if mode=='empty' else 'P'*511 if mode=='boundary' else 'Generated prompt?')
    if mode!='repeat':
        assert pointer(0x70)==0 and data[0xf8:0xfc]==b'DONE'
    if mode in REFERENCE_MODES:
        ref=report['kernel_code_reference'];start=int(ref['base'],0)
        assert ref['execution_allowed'] is False
        assert pointer(0x50)!=start+reference_rva
        assert not any(start+reference_rva<=int(row['pc'],0)<start+reference_rva+16 for row in report['instruction_tail'])


class KernelDbgPromptTests(unittest.TestCase):
    def probe(self,modes):
        for machine in (0x14c,0x8664):
            for mode in modes:
                if mode in REFERENCE_MODES and machine!=0x8664:continue
                with self.subTest(machine=machine,mode=mode),tempfile.TemporaryDirectory() as d:
                    expected=None
                    for native in (False,True):
                        root=Path(d)/str(native);root.mkdir()
                        payload=prompt_probe(machine,mode)
                        reference=prompt_reference() if mode in REFERENCE_MODES else None
                        from contextlib import nullcontext
                        with nullcontext() if native else patch.object(driver,'create_native_trace',lambda _:None):
                            result=driver.run_driver(payload,inspect_pe(payload,'prompt.sys'),load_persona(None),root,15,20000,kernel_code_reference=reference)
                        report=json.loads((root/'engine-report.json').read_text())
                        verify_prompt(result,report,root,machine,mode)
                        observed=(observations(result,report),report['kernel_debugger_state'])
                        if expected is None:expected=observed
                        else:self.assertEqual(expected,observed)

    def test_no_input_preserves_response_and_lookup_identity(self):self.probe(('normal','empty','zero','boundary'))
    def test_prompt_capture_is_bounded_without_suppressing_calls(self):self.probe(('repeat',))
    def test_invalid_guest_arguments_stop_instead_of_returning_success(self):self.probe(tuple(mode for mode in MODES if mode in NEGATIVE))
    def test_reference_bytes_remain_nx_and_readonly_with_modeled_prompt(self):self.probe(REFERENCE_MODES)
