"""Native address-boundary globals, exact profile values and protection."""
import json,tempfile,unittest
from pathlib import Path
from emumee.driver import run_driver
from emumee.pe import inspect_pe
from emumee.persona import load_persona
from tests.test_kernel_process import process_probe
from tests.test_kernel_system_information import image_range

EXPORTS=('MmHighestUserAddress','MmUserProbeAddress')
MODES=('read','missing','write','call')


def bounds_probe(machine,mode,name):
    return process_probe(machine,mode,name)


def verify_bounds(result,report,root,machine,mode,name,build):
    width=8 if machine==0x8664 else 4
    data=image_range(result,root,0x2300,0x100)
    value=lambda n:int.from_bytes(data[n:n+width],'little')
    globals=report['kernel_address_boundaries']['globals']
    expected_high=(0x7ffffffeffff if build>=9600 else 0x7fffffeffff) if width==8 else 0x7ffeffff
    expected_probe=(0x7fffffff0000 if build>=9600 else 0x7ffffff0000) if width==8 else 0x7fff0000
    assert int(globals['MmHighestUserAddress']['value'],0)==expected_high
    assert int(globals['MmUserProbeAddress']['value'],0)==expected_probe==expected_high+1
    for entry in globals.values():assert entry['width']==width and entry['permissions']=='r--'
    assert globals['MmHighestUserAddress']['address']!=globals['MmUserProbeAddress']['address']
    storage=int(globals[name]['address'],0);expected=expected_high if name=='MmHighestUserAddress' else expected_probe
    assert value(0x10)==value(0x20)==storage and storage>= (0xffff800000000000 if width==8 else 0x80000000)
    assert value(0x18)==value(0x28)==expected and value(0x38)==4 and value(0x40)==0
    events=report['kernel_object_references']['events']
    assert len(events)==2 and all(v['object']==hex(value(0x30)) for v in events)
    assert events[0]['references_after']==events[1]['references_after']+1
    if mode=='missing':assert value(0x50)==0
    else:assert value(0x50)==storage and value(0x58)==expected
    segments=[segment for run in report['entry_points'] for module in run['memory']['modules']
        for segment in module['segments'] if int(segment['address'],0)<=storage<
        int(segment['address'],0)+int(segment['size'],0)]
    assert segments and all(v['prot']=='r--' for v in segments)
    if mode in ('read','missing'):
        assert result['guest_entry_return']==0 and not result['errors'] and data[0xf8:0xfc]==b'DONE'
    else:
        assert result['guest_entry_return'] is None and result['errors'] and data[0xf8:0xfc]==b'COLD'
        error=report['entry_points'][0]['error']
        assert error['type']==('invalid_execute' if mode=='call' else 'invalid_protect_write')
        assert int(error['address'],0)==storage


class KernelUserBoundsTests(unittest.TestCase):
    def probe(self,mode):
        for machine in (0x14c,0x8664):
            for build in (7601,22631):
                for name in EXPORTS:
                    with self.subTest(machine=machine,mode=mode,build=build,name=name),tempfile.TemporaryDirectory() as d:
                        root=Path(d);payload=bounds_probe(machine,mode,name);persona=load_persona(None);persona['windows_build']=build
                        result=run_driver(payload,inspect_pe(payload,'bounds.sys'),persona,root,5,10000)
                        verify_bounds(result,json.loads((root/'engine-report.json').read_text()),root,machine,mode,name,build)
    def test_import_dynamic_and_binary_lookup_share_exact_profile_boundaries(self):self.probe('read')
    def test_absent_binary_export_stays_absent(self):self.probe('missing')
    def test_readonly_global_write_stops_before_marker(self):self.probe('write')
    def test_nx_global_execution_stops_before_marker(self):self.probe('call')
